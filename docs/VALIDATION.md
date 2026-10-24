# Validation

Validated on Windows 10 x64 with the Windows 10.0.26100 SDK and Visual Studio C++ tools:

- Release build with MSVC 14.44.35207, `/W4 /WX` and static C++ runtime.
- The same offline suites with MSVC 14.44.35207 AddressSanitizer and its matching runtime.
- **12,080** assertions: HTML attribute/content escaping, script-shaped names, registry DWORD/string/multi-string parsing, invalid UTF-16, missing terminators, data after terminators, 2,000 bounded malformed-value cases, 10,000 escaping stress cases, JSON schema round-trip, access-denied versus device-problem interpretation, and bounded local-path syntax including UNC/device paths, aliases, streams and reserved names.
- Binary inspection read an owned temporary file containing `abc`, verified its known SHA-256 and missing embedded signature, and rejected a real local directory junction to that fixture before hashing. Optional file/directory symbolic-link cases were skipped because the existing account/OS configuration did not permit creating them. No permissions or security settings were changed. These tests do not attempt hostile concurrent filesystem mutations or network-share access.
- Offline JSON and HTML exports.
- Earlier-build read-only host snapshot, before the stricter binary-path policy: **249** present PnP nodes and **107** associated services in **820 ms**, no initial enumeration error. Optional Code Integrity query succeeded and respected the 64-event cap. Default exports contained no instance IDs or raw event XML. A final path-hardened read-only snapshot again found 249 nodes and 107 associated services, with 106 driver-service binary hash records available, no initial enumeration error and a 570 ms observed collection duration. Raw identifiers remained excluded. These separate local observations are not a controlled before/after benchmark.
- Native offline preview rendered and closed normally. CLI preserves existing report files and rejects invalid arguments.

The observed 820 ms is a single local support-snapshot duration, not a performance guarantee. Cached certificate state, devices, file sizes, permissions and Windows policy affect collection time. Some service or signature observations may legitimately be inaccessible or indeterminate.

No driver was installed, modified, activated, disabled or started for these tests. No real input was captured or generated. No security settings were changed. There has been no HLK/certification test or hardware compatibility qualification; the application intentionally issues no such verdict.

Local build logs, test logs, the private host snapshot and executable hashes are kept under ignored `obj/`. The public screenshot and example export use synthetic data only.
