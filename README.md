# zip-preflight

Read-only preflight checks for ZIP archives you are about to extract with
something else. It answers one question before any file touches disk:
**is this archive's structure safe and unambiguous enough to hand to an
extractor?**

It never extracts files, never writes archive payloads anywhere, and never
executes anything. It is not a malware scanner and does not inspect payload
content for threats; it checks archive *structure and limits* only.

## Why

Real-world failure reports and platform docs show that extraction problems are
usually structural, not malicious payloads:

- **Duplicate entries behave inconsistently.** Two central-directory records
  with the same name confuse extractors; CPython tracks real-world archives
  broken by this ([cpython#117779]). Python's own docs note that repeated
  extraction overwrites existing files without asking ([zipfile docs]).
- **Case-colliding names silently lose files.** On case-insensitive
  filesystems (default Windows and macOS), extracting `Report.txt` and
  `report.TXT` overwrites one with the other ([case-sensitivity report]).
- **Path handling differs per consumer.** Python's `ZipFile.extract()` and
  `extractall()` sanitize absolute paths and `..` components, but
  `zipfile.Path` does not sanitize member names, and non-Python consumers
  apply their own rules ([zipfile docs]). PEP 706 added extraction filters
  for **tar**, not zip ([PEP 706]).
- **Declared metadata can lie.** Uncompressed sizes in the central directory
  are attacker-controlled; the OpenSSF secure-coding guide calls for checking
  paths, links, and expansion limits before extracting untrusted archives
  ([OpenSSF guide]).
- **Windows names are a separate hazard class.** Reserved device names
  (`CON`, `NUL`, `COM1`...), reserved characters, and trailing dots/spaces
  are illegal on Windows regardless of what the archive claims
  ([Microsoft file naming]).

The "Zip Slip" disclosure is the classic path-traversal story ([Snyk]), but
note that Snyk's own analysis found Python's `zipfile.extractall()` was *not*
vulnerable in the form they tested. This tool's value is preflight visibility
across extractors and platforms, not a claim that modern Python extraction is
broadly broken.

## Install

No dependencies beyond the Python 3.9+ standard library. Copy
`zip_preflight.py` into your project or run it in place.

## Usage

```console
$ python3 zip_preflight.py archive.zip
FAIL
ERROR: symlink_entry: bin/sh
ERROR: colliding_member_names: report.TXT
WARNING: payload_not_verified
3 entries, 2 error(s), 1 warning(s)

$ python3 zip_preflight.py archive.zip --verify-payload --format json
```

Exit codes: `0` pass, `1` policy failure, `2` unreadable input or bad options.

Library use:

```python
from zip_preflight import inspect_archive

report = inspect_archive("archive.zip", verify_payload=True)
if not report["ok"]:
    for err in report["errors"]:
        print(err["code"], err.get("member", ""))
```

## What it checks

Name policy (per member):

- absolute paths (`/...`, `\\...`, UNC), drive-letter paths (`C:\...`)
- `..` / `.` / empty path components, paths deeper than `--max-depth`
- backslashes inside names (ambiguous on Windows)
- Windows-reserved device names, reserved characters `<>:"|?*`,
  trailing dots/spaces, control characters
- overlong components (>255 bytes) and names (>1024 bytes)

Structure:

- exact duplicate entries
- case-insensitive and Unicode-normalized (NFKC + casefold) name collisions
- file/directory conflicts, including a file shadowing a parent directory
- symlink and special-file (device, FIFO, socket) entries from Unix mode bits
- encrypted entries and unsupported compression methods

Limits (metadata, always checked):

- entry count, per-member size, total uncompressed size, archive size
- declared compression ratio (`--max-ratio`, `0` disables)

Payload verification (`--verify-payload`, opt-in):

- streams every file through the decompressor **in memory only**, bounded by
  the same limits, and lets `zipfile` verify CRC and declared size for each
  member. No bytes are written to disk.

## Threat model and limitations

- The archive is untrusted input; the machine and user running this tool are
  trusted. Output codes are fixed strings; exception text is never echoed.
- Metadata-only mode (default) trusts declared sizes, which can be forged;
  it warns `payload_not_verified`. Use `--verify-payload` for untrusted
  archives.
- Payload verification relies on CPython's `zipfile`, which truncates
  decompressed reads at the declared size, so a forged *small* declared size
  surfaces as a CRC failure rather than an over-read. Limits are still
  enforced during streaming as defense in depth.
- Unicode and casefold collision folding is deliberately conservative: it can
  flag name pairs some filesystems would accept.
- This is a preflight gate, not an extractor. A passing archive can still be
  unwanted (wrong contents, unwanted file types); a failing archive may be
  extractable by a tool that applies its own sanitization.

## Report shape

JSON mode returns `format_version`, `ok`, `payload_verified`, a `summary`
(counts and byte totals), and `errors` / `warnings` lists of
`{code, member?, index?}` objects. Error codes are stable identifiers meant
for scripting.

## Tests

```console
$ python3 -m unittest -v
```

79 tests build adversarial archives in memory: traversal and Windows-hostile
names, duplicate/case/Unicode collisions, symlink and special-file mode bits,
flipped encryption flags, corrupted CRCs, and forged declared sizes patched
directly into ZIP headers. CI runs the suite on Linux and Windows.

## Sources

- [zipfile docs]: extraction sanitization, `zipfile.Path` caveat, overwrite-on-extract behavior
- [cpython#117779]: duplicate central-directory entries break real archives
- [case-sensitivity report]: `extractall()` overwriting case-colliding names
- [OpenSSF guide]: secure archive extraction (path validation, links, expansion limits)
- [PEP 706]: extraction filters added for tar, not zip
- [Snyk]: Zip Slip disclosure; Python `extractall()` not vulnerable in analyzed form
- [Microsoft file naming]: reserved names/characters, trailing dot/space rules
- [APPNOTE]: ZIP format specification (flags, compression methods, external attributes)

[zipfile docs]: https://docs.python.org/3/library/zipfile.html
[cpython#117779]: https://github.com/python/cpython/issues/117779
[case-sensitivity report]: https://stackoverflow.com/questions/79382088/python-zipfile-extractall-is-not-being-case-sensitive
[OpenSSF guide]: https://best.openssf.org/Secure-Coding-Guide-for-Python/04_neutralization/pyscg-0012/
[PEP 706]: https://peps.python.org/pep-0706/
[Snyk]: https://snyk.io/blog/behind-the-disclosure-the-zip-slip-vulnerability/
[Microsoft file naming]: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
[APPNOTE]: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

## License

MIT (see LICENSE).
