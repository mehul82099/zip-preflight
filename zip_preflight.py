#!/usr/bin/env python3
"""Read-only ZIP preflight checks. No archive payload is written or executed."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import unicodedata
import zipfile

__version__ = "0.1.0"
FORMAT_VERSION = 1
SUPPORTED_COMPRESSION = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
WINDOWS_UNSAFE_CHARS = set('<>:"|?*')
CHUNK_SIZE = 1024 * 1024


class PreflightError(ValueError):
    """Invalid option or unreadable archive. Reports fixed codes only."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _entry(code, member=None, index=None):
    item = {"code": code}
    if member is not None:
        item["member"] = member
    if index is not None:
        item["index"] = index
    return item


def _positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _nonnegative_float(text):
    value = float(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return value


def _fold_component(component):
    # Deliberately conservative. This can reject names some filesystems allow.
    return unicodedata.normalize("NFKC", component).casefold()


def _path_key(parts):
    return "\x00".join(_fold_component(part) for part in parts)


def _check_name(name, max_depth):
    """Return (parts, explicit_directory, name_errors). Never resolves a path."""
    errors = []
    is_dir = name.endswith("/")
    if not name:
        return [], is_dir, [_entry("empty_member_name")]
    if "\x00" in name:
        errors.append(_entry("nul_in_member_name", name))
    if len(name.encode("utf-8", "surrogatepass")) > 1024:
        errors.append(_entry("member_name_too_long", name))
    if name.startswith(("/", "\\")):
        errors.append(_entry("absolute_path", name))
    if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
        errors.append(_entry("windows_drive_path", name))

    body = name[:-1] if is_dir else name
    if not body:
        errors.append(_entry("empty_member_name", name))
        return [], is_dir, errors
    parts = body.split("/")
    if len(parts) > max_depth:
        errors.append(_entry("path_too_deep", name))
    for part in parts:
        if part == "":
            errors.append(_entry("empty_path_component", name))
            continue
        if part == ".":
            errors.append(_entry("dot_path_component", name))
        elif part == "..":
            errors.append(_entry("dot_dot_path_component", name))
        if len(part.encode("utf-8", "surrogatepass")) > 255:
            errors.append(_entry("path_component_too_long", name))
        if "\\" in part:
            errors.append(_entry("ambiguous_windows_separator", name))
        if any(char in WINDOWS_UNSAFE_CHARS for char in part):
            errors.append(_entry("windows_unsafe_character", name))
        if any(ord(char) < 32 or ord(char) == 127 for char in part):
            errors.append(_entry("control_character", name))
        if part.endswith((" ", ".")):
            errors.append(_entry("windows_trailing_character", name))
        if part.split(".", 1)[0].upper() in RESERVED_WINDOWS_NAMES:
            errors.append(_entry("windows_reserved_name", name))
    return parts, is_dir, errors


def _member_kind(info):
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode):
        if stat.S_ISLNK(mode):
            return "symlink"
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            return "special"
    return "directory" if info.is_dir() else "file"


def _metadata_checks(archive_path, limits):
    errors, warnings = [], []
    try:
        archive_size = os.stat(archive_path).st_size
    except OSError:
        raise PreflightError("archive_unreadable") from None
    if archive_size > limits["max_archive_bytes"]:
        errors.append(_entry("archive_too_large"))
        return [], errors, warnings, archive_size
    try:
        archive = zipfile.ZipFile(archive_path, "r")
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile):
        raise PreflightError("invalid_zip") from None

    members = []
    with archive:
        try:
            infos = archive.infolist()
        except (OSError, EOFError, RuntimeError, zipfile.BadZipFile):
            raise PreflightError("invalid_zip") from None
        if len(infos) > limits["max_entries"]:
            errors.append(_entry("too_many_entries"))
        declared_total = 0
        for index, info in enumerate(infos):
            name = info.filename
            kind = _member_kind(info)
            if kind == "symlink":
                errors.append(_entry("symlink_entry", name, index))
            elif kind == "special":
                errors.append(_entry("special_file_entry", name, index))
            if info.flag_bits & 0x1:
                errors.append(_entry("encrypted_entry", name, index))
            if info.compress_type not in SUPPORTED_COMPRESSION:
                errors.append(_entry("unsupported_compression", name, index))
            if info.file_size > limits["max_member_bytes"]:
                errors.append(_entry("member_too_large_declared", name, index))
            declared_total += info.file_size
            parts, explicit_dir, name_errors = _check_name(name, limits["max_depth"])
            errors.extend({**item, "index": index} for item in name_errors)
            members.append({
                "info": info,
                "index": index,
                "name": name,
                "parts": parts,
                "key": _path_key(parts),
                "kind": "directory" if explicit_dir else "file",
                "declared_size": info.file_size,
            })
        if declared_total > limits["max_total_bytes"]:
            errors.append(_entry("total_too_large_declared"))
        ratio = limits["max_ratio"]
        if ratio and archive_size and declared_total > archive_size * ratio:
            errors.append(_entry("declared_compression_ratio_exceeded"))

        exact_names = set()
        folded = {}
        files, directories = set(), set()
        for member in members:
            if not member["parts"]:
                continue
            exact = tuple(member["parts"])
            if exact in exact_names:
                errors.append(_entry("duplicate_member", member["name"], member["index"]))
            exact_names.add(exact)
            key = member["key"]
            if key in folded:
                errors.append(_entry("colliding_member_names", member["name"], member["index"]))
            else:
                folded[key] = member["name"]
            collection = directories if member["kind"] == "directory" else files
            if key in files and member["kind"] == "directory":
                errors.append(_entry("file_directory_conflict", member["name"], member["index"]))
            if key in directories and member["kind"] == "file":
                errors.append(_entry("file_directory_conflict", member["name"], member["index"]))
            collection.add(key)
            for end in range(1, len(member["parts"])):
                if "\x00".join(_fold_component(p) for p in member["parts"][:end]) in files:
                    errors.append(_entry("file_directory_conflict", member["name"], member["index"]))
                    break
    return members, errors, warnings, archive_size


def _verify_payload(archive_path, members, limits, archive_size):
    errors = []
    actual_total = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in members:
                if member["kind"] == "directory":
                    continue
                info = member["info"]
                actual = 0
                try:
                    with archive.open(info, "r") as stream:
                        while True:
                            chunk = stream.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            actual += len(chunk)
                            actual_total += len(chunk)
                            if actual > limits["max_member_bytes"]:
                                errors.append(_entry("member_too_large_actual", member["name"], member["index"]))
                                break
                            if actual_total > limits["max_total_bytes"]:
                                errors.append(_entry("total_too_large_actual", member["name"], member["index"]))
                                break
                            ratio = limits["max_ratio"]
                            if ratio and archive_size and actual_total > archive_size * ratio:
                                errors.append(_entry("actual_compression_ratio_exceeded", member["name"], member["index"]))
                                break
                except (EOFError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    errors.append(_entry("payload_read_failed", member["name"], member["index"]))
                    continue
                if errors:
                    break
                if actual != info.file_size:
                    errors.append(_entry("declared_size_mismatch", member["name"], member["index"]))
                    break
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile):
        raise PreflightError("invalid_zip") from None
    return errors, actual_total


def inspect_archive(archive_path, *, verify_payload=False, max_entries=1000,
                    max_member_bytes=256 * 1024 * 1024,
                    max_total_bytes=1024 * 1024 * 1024,
                    max_archive_bytes=256 * 1024 * 1024,
                    max_depth=32, max_ratio=100.0):
    """Inspect metadata and optionally bounded payloads. Never extracts files."""
    limits = {
        "max_entries": max_entries,
        "max_member_bytes": max_member_bytes,
        "max_total_bytes": max_total_bytes,
        "max_archive_bytes": max_archive_bytes,
        "max_depth": max_depth,
        "max_ratio": max_ratio,
    }
    for key, value in limits.items():
        if key == "max_ratio":
            if value < 0:
                raise PreflightError("invalid_limit")
        elif value < 1:
            raise PreflightError("invalid_limit")
    members, errors, warnings, archive_size = _metadata_checks(archive_path, limits)
    actual_total = 0
    if not errors and verify_payload:
        payload_errors, actual_total = _verify_payload(archive_path, members, limits, archive_size)
        errors.extend(payload_errors)
    elif not verify_payload:
        warnings.append(_entry("payload_not_verified"))
    files = sum(1 for member in members if member["kind"] == "file")
    directories = len(members) - files
    declared_total = sum(member["declared_size"] for member in members)
    return {
        "format_version": FORMAT_VERSION,
        "ok": not errors,
        "payload_verified": verify_payload and not errors,
        "summary": {
            "entries": len(members),
            "files": files,
            "directories": directories,
            "archive_bytes": archive_size,
            "declared_uncompressed_bytes": declared_total,
            "verified_uncompressed_bytes": actual_total,
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "errors": errors,
        "warnings": warnings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--verify-payload", action="store_true",
                        help="decompress in memory only, bounded, and check CRC/size")
    parser.add_argument("--max-entries", type=_positive_int, default=1000)
    parser.add_argument("--max-member-bytes", type=_positive_int, default=256 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=_positive_int, default=1024 * 1024 * 1024)
    parser.add_argument("--max-archive-bytes", type=_positive_int, default=256 * 1024 * 1024)
    parser.add_argument("--max-depth", type=_positive_int, default=32)
    parser.add_argument("--max-ratio", type=_nonnegative_float, default=100.0,
                        help="0 disables expansion-ratio checks")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(
            args.archive,
            verify_payload=args.verify_payload,
            max_entries=args.max_entries,
            max_member_bytes=args.max_member_bytes,
            max_total_bytes=args.max_total_bytes,
            max_archive_bytes=args.max_archive_bytes,
            max_depth=args.max_depth,
            max_ratio=args.max_ratio,
        )
        code = 0 if report["ok"] else 1
    except (PreflightError, ValueError) as exc:
        code_value = exc.code if isinstance(exc, PreflightError) else "invalid_options"
        report = {
            "format_version": FORMAT_VERSION,
            "ok": False,
            "input_error": {"code": code_value},
        }
        code = 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    elif "input_error" in report:
        print("INPUT ERROR: " + report["input_error"]["code"])
    else:
        print("PASS" if report["ok"] else "FAIL")
        for level in ("errors", "warnings"):
            for item in report[level]:
                location = f": {item['member']}" if "member" in item else ""
                print(f"{level[:-1].upper()}: {item['code']}{location}")
        summary = report["summary"]
        print(f"{summary['entries']} entries, {summary['errors']} error(s), {summary['warnings']} warning(s)")
    return code


if __name__ == "__main__":
    sys.exit(main())
