# Reading a report

Each observation contains a `status`, `value`, numeric `error` and explanatory `detail`. Missing information stays `null`; it is never silently converted into a success or failure verdict.

| Status | Meaning |
|---|---|
| `known` | The indicated Windows API/registry value was read successfully |
| `access_denied` | The account or Windows policy did not allow the read |
| `not_present` | The queried key, value or property was absent |
| `unavailable` | The API failed; inspect its recorded error and detail |
| `malformed` / `unsupported_type` | A returned registry value did not have the expected bounded layout/type |
| `unknown_value` | Windows returned an unrecognized value; no state was inferred |
| `not_requested` | Optional evidence collection was disabled |
| `not_inspected` / `not_applicable` | The binary or service is outside the documented inspection scope |
| `not_tested` | A functional or certification test was not performed |

Most errors are Windows error numbers. Configuration Manager and NT queries explicitly label their respective result/NTSTATUS domains. Never interpret an unrelated API error as the device's PnP problem code.

## Common situations

**PnP code 0, stopped filter service:** these are separate observations. Code 0 says Windows reports no problem for this node. Some drivers start on demand or serve a parent node. A stopped service alone is not proof of an installation failure.

**No service property:** this can be normal for a software child node. It does not prove there is no functional parent or class driver.

**PnP code 28:** Windows reports that drivers are not installed for the selected node. Identify the matching device and vendor package. The utility never installs or selects a package automatically.

**PnP code 52:** Windows cannot verify the required driver's digital signature. Review the actual package and relevant Code Integrity events. The utility's cached embedded-signature check cannot substitute for Windows' package/catalog and kernel-policy decision.

**Missing embedded signature:** a driver may be signed by its package catalog. This program does not search catalogs or verify that a file belongs to an installed package. Its exact result is `no_embedded_signature`, not “unsigned,” “blocked,” or “unsafe.”

**Cached trust not established:** the machine may lack cached certificates/revocation information; the file may be untrusted or malformed; or another trust condition may apply. The numeric WinVerifyTrust status is retained. The tool does not disable checks or fetch certificates.

**HVCI configured but not running:** configuration is separate from runtime enforcement. Neither observation proves that a particular driver is compatible. A missing Secure Boot registry value does not mean Secure Boot is disabled. Actual compatibility requires the appropriate test environment and driver testing.

**Recent Code Integrity event:** this may refer to historical or unrelated software. Default reports retain event ID, level, provider and time while omitting the payload. Explicit sensitive export retains bounded raw XML, which may contain private paths. An event is supporting evidence; temporal proximity alone does not establish causation.

## Boundaries

- Present PnP nodes only; at most 512 nodes and 128 associated unique service names.
- Filter names are device/class registry configuration, not a verified live stack order. Stale metadata can exist.
- Local resolved fixed-drive kernel/filesystem-driver binaries only; no process-memory or arbitrary path scanner. Unknown paths and user-mode service binaries are skipped.
- Binary hashes inspect at most 128 MiB. Running code may differ from a file replaced on disk. Files and services can change during collection.
- At most 64 Code Integrity events from the previous seven days; individual render buffers are limited to 64 KiB. Partial, inaccessible or truncated data is explicit.
- Reports are support evidence, not security scans, certification, hardware validation, performance measurements or guarantees of successful loading.
- Closing the window cancels after the current Windows read returns. Background work is joined before the application exits.

Microsoft references: [Device Manager problem codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-manager-error-messages), [driver signing options](https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings), [memory integrity testing](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/driver-compatibility-with-device-guard), [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).
