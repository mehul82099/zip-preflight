import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from zip_preflight import inspect_archive, main, PreflightError


def make_zip(path, entries):
    """entries: (name, data, kind, compression). kind: file/dir/symlink/special/encrypted."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, *rest in entries:
            kind = rest[0] if rest else "file"
            compression = rest[1] if len(rest) > 1 else zipfile.ZIP_DEFLATED
            info = zipfile.ZipInfo("placeholder")
            # Set after construction: ZipInfo.__init__ rewrites os.sep to "/"
            # on Windows, which would hide backslash-hostile member names.
            info.filename = name
            info.compress_type = compression
            if kind == "dir":
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
            elif kind == "symlink":
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            elif kind == "special":
                info.create_system = 3
                info.external_attr = (stat.S_IFIFO | 0o644) << 16
            elif kind == "encrypted":
                info.flag_bits |= 0x1
            archive.writestr(info, data)



def patch_all_headers(path, sig, offset, patch):
    raw = bytearray(path.read_bytes())
    start = 0
    while True:
        try:
            pos = raw.index(sig, start)
        except ValueError:
            break
        patch(raw, pos + offset)
        start = pos + 4
    path.write_bytes(raw)


def set_encrypted_flag(path):
    """Set the general-purpose encrypted bit in local and central headers."""
    patch_all_headers(path, b"PK\x03\x04", 6, lambda r, p: r.__setitem__(p, r[p] | 0x1))
    patch_all_headers(path, b"PK\x01\x02", 8, lambda r, p: r.__setitem__(p, r[p] | 0x1))


def forge_declared_sizes(path, fake_size):
    """Lie about uncompressed sizes in every header; data and CRC stay real."""
    def put(raw, pos):
        raw[pos:pos + 4] = fake_size.to_bytes(4, "little")
    patch_all_headers(path, b"PK\x03\x04", 22, put)
    patch_all_headers(path, b"PK\x01\x02", 24, put)

def codes(report):
    return [item["code"] for item in report["errors"]]


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample.zip"

    def inspect(self, entries, **options):
        make_zip(self.path, entries)
        return inspect_archive(self.path, **options)


class SafeArchiveTests(Base):
    def test_empty_archive(self):
        self.assertTrue(self.inspect([])["ok"])

    def test_single_file(self):
        self.assertTrue(self.inspect([("hello.txt", b"hi")])["ok"])

    def test_nested_file(self):
        self.assertTrue(self.inspect([("docs/a/b.txt", b"hi")])["ok"])

    def test_explicit_directory(self):
        self.assertTrue(self.inspect([("docs/", b"", "dir"), ("docs/a.txt", b"hi")])["ok"])

    def test_case_distinct_no_collision(self):
        self.assertTrue(self.inspect([("one.txt", b"1"), ("two.txt", b"2")])["ok"])

    def test_unicode_name(self):
        self.assertTrue(self.inspect([("नमस्ते.txt", "hello".encode())])["ok"])

    def test_spaces_inside_name(self):
        self.assertTrue(self.inspect([("my file.txt", b"hi")])["ok"])

    def test_space_before_extension(self):
        self.assertTrue(self.inspect([("name .txt", b"hi")])["ok"])

    def test_plus_and_dash(self):
        self.assertTrue(self.inspect([("a+b-c.txt", b"hi")])["ok"])

    def test_stored(self):
        self.assertTrue(self.inspect([("a.bin", b"123", "file", zipfile.ZIP_STORED)])["ok"])

    def test_bzip2(self):
        self.assertTrue(self.inspect([("a.bin", b"123", "file", zipfile.ZIP_BZIP2)])["ok"])

    def test_lzma(self):
        self.assertTrue(self.inspect([("a.bin", b"123", "file", zipfile.ZIP_LZMA)])["ok"])

    def test_deep_allowed(self):
        self.assertTrue(self.inspect([("/".join(f"d{i}" for i in range(8)) + "/a.txt", b"x")])["ok"])

    def test_payload_verified(self):
        report = self.inspect([("a.txt", b"hello")], verify_payload=True)
        self.assertTrue(report["payload_verified"])
        self.assertEqual(report["summary"]["verified_uncompressed_bytes"], 5)

    def test_payload_large_allowed(self):
        report = self.inspect([("a.bin", b"x" * 200000)], verify_payload=True, max_ratio=0)
        self.assertTrue(report["ok"])

    def test_ratio_disabled(self):
        report = self.inspect([("a.txt", b"x" * 10000)], verify_payload=True, max_ratio=0)
        self.assertTrue(report["ok"])

    def test_default_warning(self):
        self.assertIn("payload_not_verified", [x["code"] for x in self.inspect([("a", b"1")])["warnings"]])

    def test_verify_no_default_warning(self):
        self.assertEqual(self.inspect([("a", b"1")], verify_payload=True)["warnings"], [])


class NamePolicyTests(Base):
    def bad(self, name):
        return self.inspect([(name, b"x")])

    def test_parent_traversal(self):
        self.assertIn("dot_dot_path_component", codes(self.bad("../evil.txt")))

    def test_embedded_traversal(self):
        self.assertIn("dot_dot_path_component", codes(self.bad("safe/../evil.txt")))

    def test_absolute_posix(self):
        self.assertIn("absolute_path", codes(self.bad("/tmp/evil.txt")))

    def test_absolute_unc_slashes(self):
        report = self.bad("//server/share/file.txt")
        self.assertIn("absolute_path", codes(report))

    def test_windows_drive_forward(self):
        self.assertIn("windows_drive_path", codes(self.bad("C:/Windows/file.txt")))

    @unittest.skipIf(os.sep != "/", "CPython zipfile normalizes os.sep in member names on read")
    def test_windows_drive_backslash(self):
        report = self.bad(r"C:\Windows\file.txt")
        self.assertIn("windows_drive_path", codes(report))
        self.assertIn("ambiguous_windows_separator", codes(report))

    def test_unc_backslash(self):
        report = self.bad(r"\\server\share\file.txt")
        self.assertIn("absolute_path", codes(report))

    @unittest.skipIf(os.sep != "/", "CPython zipfile normalizes os.sep in member names on read")
    def test_backslash_inside(self):
        self.assertIn("ambiguous_windows_separator", codes(self.bad(r"dir\file.txt")))

    def test_empty_component(self):
        self.assertIn("empty_path_component", codes(self.bad("dir//file.txt")))

    def test_dot_component(self):
        self.assertIn("dot_path_component", codes(self.bad("dir/./file.txt")))

    def test_root_directory(self):
        self.assertIn("empty_member_name", codes(self.bad("/")))

    def test_repeated_trailing_slash(self):
        self.assertIn("empty_path_component", codes(self.bad("dir//")))

    def test_control_character(self):
        self.assertIn("control_character", codes(self.bad("bad\x01name.txt")))

    def test_delete_character(self):
        self.assertIn("control_character", codes(self.bad("bad\x7fname.txt")))

    def test_colon(self):
        self.assertIn("windows_unsafe_character", codes(self.bad("file:stream.txt")))

    def test_windows_chars(self):
        for char in '<>"|?*':
            with self.subTest(char=char):
                self.assertIn("windows_unsafe_character", codes(self.bad("a" + char + "b.txt")))

    def test_trailing_space(self):
        self.assertIn("windows_trailing_character", codes(self.bad("name ")))

    def test_trailing_dot(self):
        self.assertIn("windows_trailing_character", codes(self.bad("name.")))

    def test_reserved_names(self):
        for name in ("CON.txt", "aux", "NUL", "com1.dat", "LPT9.txt"):
            with self.subTest(name=name):
                self.assertIn("windows_reserved_name", codes(self.bad(name)))

    def test_reserved_case(self):
        self.assertIn("windows_reserved_name", codes(self.bad("cOn.ini")))

    def test_long_component(self):
        self.assertIn("path_component_too_long", codes(self.bad("a" * 256 + ".txt")))

    def test_long_name(self):
        name = "/".join(["a" * 120] * 9) + ".txt"
        self.assertIn("member_name_too_long", codes(self.bad(name)))

    def test_too_deep(self):
        name = "/".join(f"d{i}" for i in range(33)) + "/a.txt"
        self.assertIn("path_too_deep", codes(self.bad(name)))

    def test_custom_depth(self):
        self.assertIn("path_too_deep", codes(self.inspect([("a/b/c.txt", b"x")], max_depth=2)))

    def test_multiple_name_errors(self):
        report = self.bad(r"C:\bad\../x|y.txt")
        self.assertGreaterEqual(len(report["errors"]), 3)


class CollisionAndMetadataTests(Base):
    def test_exact_duplicate(self):
        self.assertIn("duplicate_member", codes(self.inspect([("a.txt", b"1"), ("a.txt", b"2")])))

    def test_case_collision(self):
        self.assertIn("colliding_member_names", codes(self.inspect([("Report.txt", b"1"), ("report.TXT", b"2")])))

    def test_unicode_normalization_collision(self):
        self.assertIn("colliding_member_names", codes(self.inspect([("caf\u00e9.txt", b"1"), ("cafe\u0301.txt", b"2")])))

    def test_casefold_collision(self):
        self.assertIn("colliding_member_names", codes(self.inspect([("stra\u00dfe.txt", b"1"), ("strasse.txt", b"2")])))

    def test_file_directory_conflict(self):
        self.assertIn("file_directory_conflict", codes(self.inspect([("a", b"file"), ("a/b.txt", b"child")])))

    def test_explicit_kind_conflict(self):
        report = self.inspect([("a", b"file"), ("a/", b"", "dir")])
        self.assertIn("file_directory_conflict", codes(report))

    def test_case_kind_conflict(self):
        report = self.inspect([("A", b"file"), ("a/", b"", "dir")])
        self.assertTrue({"colliding_member_names", "file_directory_conflict"} & set(codes(report)))

    def test_nested_conflict(self):
        report = self.inspect([("docs", b"file"), ("docs/a/b.txt", b"child")])
        self.assertIn("file_directory_conflict", codes(report))

    def test_symlink(self):
        self.assertIn("symlink_entry", codes(self.inspect([("link", b"target", "symlink")])))

    def test_special_file(self):
        self.assertIn("special_file_entry", codes(self.inspect([("pipe", b"", "special")])))

    def test_encrypted(self):
        make_zip(self.path, [("secret.txt", b"x")])
        set_encrypted_flag(self.path)
        self.assertIn("encrypted_entry", codes(inspect_archive(self.path)))

    def test_too_many_entries(self):
        report = self.inspect([(f"{i}.txt", b"x") for i in range(3)], max_entries=2)
        self.assertIn("too_many_entries", codes(report))

    def test_member_limit(self):
        report = self.inspect([("big.bin", b"12345")], max_member_bytes=4)
        self.assertIn("member_too_large_declared", codes(report))

    def test_total_limit(self):
        report = self.inspect([("a", b"123"), ("b", b"123")], max_total_bytes=5)
        self.assertIn("total_too_large_declared", codes(report))

    def test_ratio_limit_metadata(self):
        report = self.inspect([("a.txt", b"x" * 1000)], max_ratio=1)
        self.assertIn("declared_compression_ratio_exceeded", codes(report))

    def test_no_payload_read_by_default(self):
        make_zip(self.path, [("a.txt", b"hello")])
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("must not read")):
            self.assertTrue(inspect_archive(self.path)["ok"])


class PayloadTests(Base):
    def test_forged_small_size_fails_crc(self):
        # Declared metadata says 1 byte; the real payload is 5. CPython
        # truncates the read at the declared size, so the CRC check fails.
        make_zip(self.path, [("a.bin", b"12345")])
        forge_declared_sizes(self.path, 1)
        report = inspect_archive(self.path, verify_payload=True,
                                 max_member_bytes=4, max_ratio=0)
        self.assertIn("payload_read_failed", codes(report))

    def test_forged_large_size_mismatch(self):
        # Declared metadata says 100 bytes; the real payload is 5.
        make_zip(self.path, [("a.bin", b"12345")])
        forge_declared_sizes(self.path, 100)
        report = inspect_archive(self.path, verify_payload=True, max_ratio=0)
        self.assertIn("declared_size_mismatch", codes(report))

    def test_ratio_limit_payload(self):
        report = self.inspect([("a.txt", b"x" * 10000)], verify_payload=True, max_ratio=1000)
        self.assertTrue(report["ok"])

    def test_corrupt_crc(self):
        make_zip(self.path, [("a.txt", b"hello", "file", zipfile.ZIP_STORED)])
        raw = bytearray(self.path.read_bytes())
        pos = raw.index(b"hello")
        raw[pos] ^= 1
        self.path.write_bytes(raw)
        report = inspect_archive(self.path, verify_payload=True)
        self.assertIn("payload_read_failed", codes(report))

    def test_directory_payload_skipped(self):
        report = self.inspect([("docs/", b"", "dir")], verify_payload=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["summary"]["verified_uncompressed_bytes"], 0)

    def test_payload_result_deterministic(self):
        entries = [("b.txt", b"2"), ("a.txt", b"1")]
        one = self.inspect(entries, verify_payload=True)
        self.path.unlink()
        two = self.inspect(list(reversed(entries)), verify_payload=True)
        self.assertEqual(one["summary"]["verified_uncompressed_bytes"], two["summary"]["verified_uncompressed_bytes"])


class InputAndCLITests(Base):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.path), *args])
        return code, out.getvalue(), err.getvalue()

    def test_missing_file(self):
        self.assertEqual(self.run_cli()[0], 2)

    def test_invalid_zip(self):
        self.path.write_bytes(b"not a zip")
        self.assertEqual(self.run_cli()[0], 2)

    def test_truncated_zip(self):
        make_zip(self.path, [("a", b"123")])
        raw = self.path.read_bytes()[:-10]
        self.path.write_bytes(raw)
        self.assertEqual(self.run_cli()[0], 2)

    def test_archive_size_limit(self):
        make_zip(self.path, [("a", b"123")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.path), "--max-archive-bytes", "10"]), 1)

    def test_policy_exit_text(self):
        make_zip(self.path, [("../evil", b"x")])
        code, out, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("dot_dot_path_component", out)
        self.assertEqual(err, "")

    def test_json_exit_and_shape(self):
        make_zip(self.path, [("../evil", b"x")])
        code, out, _ = self.run_cli("--format", "json")
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual(report["format_version"], 1)
        self.assertFalse(report["ok"])

    def test_success_text(self):
        make_zip(self.path, [("a", b"x")])
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_verify_cli(self):
        make_zip(self.path, [("a", b"x")])
        self.assertEqual(self.run_cli("--verify-payload")[0], 0)

    def test_input_error_json_safe(self):
        self.path.write_bytes(b"PRIVATE_SENTINEL not zip")
        code, out, err = self.run_cli("--format", "json")
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE_SENTINEL", out + err)

    def test_member_name_included(self):
        make_zip(self.path, [("../named-member", b"x")])
        report = inspect_archive(self.path)
        self.assertEqual(report["errors"][0]["member"], "../named-member")

    def test_no_file_mutation(self):
        make_zip(self.path, [("a", b"x")])
        before = self.path.read_bytes()
        self.run_cli("--verify-payload")
        self.assertEqual(self.path.read_bytes(), before)

    def test_bad_limit(self):
        with self.assertRaises(PreflightError):
            self.inspect([("a", b"x")], max_entries=0)

    def test_bad_ratio(self):
        with self.assertRaises(PreflightError):
            self.inspect([("a", b"x")], max_ratio=-1)

    def test_argparse_bad_limit(self):
        make_zip(self.path, [("a", b"x")])
        with self.assertRaises(SystemExit):
            main([str(self.path), "--max-depth", "0"])


if __name__ == "__main__":
    unittest.main()
