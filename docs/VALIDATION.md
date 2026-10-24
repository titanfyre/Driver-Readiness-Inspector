# Validation

Validated on Windows 10 x64 with the Windows 10.0.26100 SDK and Visual Studio C++ tools:

- Release build with `/W4 /WX` and static C++ runtime.
- The same offline suites with MSVC AddressSanitizer.
- **12,029** model assertions: HTML attribute/content escaping, script-shaped names, registry DWORD/string/multi-string parsing, invalid UTF-16, missing terminators, data after terminators, 2,000 bounded malformed-value cases, 10,000 escaping stress cases, JSON schema round-trip, and access-denied versus device-problem interpretation.
- Offline JSON and HTML exports.
- Real read-only host snapshot: **249** present PnP nodes and **107** associated services in **820 ms**, no initial enumeration error. Optional Code Integrity query succeeded and respected the 64-event cap. Default exports contained no instance IDs or raw event XML.
- Native offline preview rendered and closed normally. CLI preserves existing report files and rejects invalid arguments.

The observed 820 ms is a single local support-snapshot duration, not a performance guarantee. Cached certificate state, devices, file sizes, permissions and Windows policy affect collection time. Some service or signature observations may legitimately be inaccessible or indeterminate.

No driver was installed, modified, activated, disabled or started for these tests. No real input was captured or generated. No security settings were changed. There has been no HLK/certification test or hardware compatibility qualification; the application intentionally issues no such verdict.

Local build logs, test logs, the private host snapshot and executable hashes are kept under ignored `obj/`. The public screenshot and example export use synthetic data only.
