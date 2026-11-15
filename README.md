# Wearden Windows agent

Native Go agent for Windows 10, Windows 11 and Windows Server 2022. It uses the standard library, the local shared `github.com/Wearden/proto/wire` contract, and `golang.org/x/sys/windows/svc` for Windows service hosting. It never launches PowerShell, secedit, auditpol, a shell, arbitrary remediation commands, or downloaded code.

The native catalog preserves all 100 control IDs in each legacy Windows benchmark. **98 controls have native implementations; 2 require manual review and report `error`. This is not full benchmark parity.** Implemented providers use registry, NetAPI account policy, LSA user rights, advanced audit policy, Service Control Manager, and fixed read-only WMI queries. These counts describe implementations, not passing checks or verified runtime coverage. Unsupported checks and access/provider errors do not count as passing controls. No build, test, host scan, or runtime validation was performed during this rewrite, as requested.

From the sibling repository parent, use a Go workspace containing `./proto`, `./agent-windows` and other project modules. Go 1.25 or newer is required. The approved Windows platform dependency is `golang.org/x/sys v0.47.0`; no global package/tool installation is needed. After review, build from this repository with:

```powershell
go build -o agent.exe ./cmd/agent
```

Commands intended for an authorized Windows host:

```powershell
.\agent.exe scan --ruleset .\rulesets\windows-11.json --agent-id local-windows
.\agent.exe enroll --server https://wearden.example --identity .\identity.dpapi
.\agent.exe run --identity .\identity.dpapi --spool .\spool --once
.\agent.exe run --identity .\identity.dpapi --spool .\spool
```

For the interactive CLI, set `WEARDEN_ENROLLMENT_TOKEN` securely in the enrollment process environment. The CLI reads it only for enrollment and never prints it. Before the first POST, it exclusively persists a random 32-hex request ID and the full enrollment payload with current-user DPAPI in `<identity>.pending.dpapi`. That record contains no enrollment token. Retrying with the same identity path and exact core origin reuses the original request, including its hostname/version, so a lost receipt or local identity-write failure can recover the same enrollment within core's 24-hour retry window. Pending records remain for explicit operator cleanup. Enrollment binds the core origin and returned agent ID/token into an exclusive current-user DPAPI identity file. Run under the same Windows account that enrolled. Re-enrollment uses a new file after the operator revokes the old identity. The LocalSystem service uses the private bootstrap file described below and never reads the interactive enrollment environment variable.

For deployment, run the reviewed binary from an elevated administrator terminal. The following are operator commands, not commands executed during this implementation:

```powershell
.\agent.exe service install --server https://wearden.example --confirm
.\agent.exe service start
.\agent.exe service stop
.\agent.exe service uninstall --confirm
```

Install defaults to read-only operation. To authorize the existing ten native remediation controls locally at installation, use:

```powershell
.\agent.exe service install --server https://wearden.example --allow-remediation --confirm
```

`allow_remediation` is persisted only in the SYSTEM/Administrators-private service config and defaults to false. Core assignments and network tasks cannot enable it. Foreground daemon mode likewise requires local `run --allow-remediation`, plus the LocalSystem identity and all other safeguards. Turning opt-in off does not suppress recovery or delivery of previously durable results; it prevents fetching/executing new tasks. Provisioning the bootstrap file must preserve its Administrators/SYSTEM ownership and private ACL; replacing it with an interactive-user-owned file is refused.

Installation copies the current executable exclusively into the Windows known Program Files folder under `WeardenAgent\agent.exe`. It creates the fixed `WeardenAgent` LocalSystem SCM service, starts automatically at boot, and configures a 30-second restart after an unexpected process crash. The installer leaves the service stopped. Install/uninstall require `--confirm`; start/stop require explicit CLI invocation and administrator SCM access. Existing binaries with different contents, existing SCM records, and untrusted pre-existing directories are not overwritten. Lifecycle commands validate the fixed binary command line/account before controlling a service. Use the same binary architecture for lifecycle operations.

The installer creates SYSTEM/Administrators-owned, private `service.json` and an empty `enrollment-token.txt` under the Windows known ProgramData folder's `WeardenAgent` directory. On a default installation this is `C:\ProgramData\WeardenAgent`. After installation, provision the token into that protected file through an elevated editor or an approved secret-provisioning mechanism, then start the service. Do not put the token on the command line, in service arguments, public machine environment variables, or registry credentials. The service only reads the exact absolute bootstrap path specified in its protected config and refuses any other path. A blank, unsafe or untrusted bootstrap file prevents initial startup.

SCM hosting uses `svc.Run` under LocalSystem. The service validates its protected installed binary and config, enrolls under SYSTEM with an immutable DPAPI pending request, retries transient enrollment failures, and finalizes a SYSTEM DPAPI identity. Subsequent starts use that identity without reading the bootstrap token again. The configured core origin must match the saved identity. Preserve the original private bootstrap token until enrollment succeeds; afterward it may be cleared only through explicit operator cleanup. Private diagnostic errors go to `agent.log` in the same directory, without tokens or raw server response bodies.

Stop and Shutdown cancel enrollment, HTTP and daemon operations; SCM receives StopPending checkpoints until the worker exits. Native calls may delay exit. The stop CLI waits up to 60 seconds, reports a pending transition, and never forcibly terminates the service or its independent helper. An armed recovery helper remains detached and either receives a durable acknowledgment or compensates the unacknowledged apply. Removing the stopped SCM service preserves the installed binary, private config, identity, bootstrap, logs, leases and backups. Upgrades and state cleanup require separate operator review. No service was installed, started or stopped during development.

Standalone `scan` writes the wire report JSON to stdout. `run` enrolls separately, sends heartbeats, fetches its assignment and exact native ruleset, verifies SHA-256 and benchmark/version identity, then submits reports. Foreground periodic mode polls every 60 seconds, scans at the server interval, responds to assigned `scan_id` jobs, and accepts explicitly confirmed typed remediation tasks only with local remediation opt-in. New tasks are not fetched in `--once` mode. Ctrl+C cancels requests and stops the loop. A non-Windows binary exits with an explicit unsupported OS error before networking. Windows build and installation type must match the assigned benchmark.

Typed tasks use `GET /api/agent/v1/tasks` and `POST /api/agent/v1/tasks/{id}/results`. The task can contain only compiled control IDs, `apply` or `rollback`, a local backup-group `run_id`, explicit `confirmed: true`, expiration within 24 hours, and a 30..600 second safety budget. IDs cannot contain paths or Windows reserved device names. No command, writable path or replacement value comes from the network. Task work is sequential with scan/report work under the agent's spool lock. Final task receipts must acknowledge the exact task ID and result revision with HTTP 200.

Writable coverage is **56 controls**: 31 registry controls,7 native local account-policy controls and18 native audit-policy controls, independent of the 98 read-only implementations:

| Writable IDs | Fixed DWORD policy |
| --- | --- |
| WIN-SEC-001 | Require secure attention sequence |
| WIN-SEC-002 | Hide last signed-in username |
| WIN-SEC-006, WIN-SEC-007, WIN-SEC-008 | Restrict anonymous enumeration/Everyone permissions |
| WIN-SEC-009 | Restrict blank-password network sign-in |
| WIN-SEC-010 | Disable shutdown without sign-in |
| WIN-SEC-019 | Restrict printer-driver installation to administrators |
| WIN-DEF-006 | Disable drive autorun |
| WIN-DEF-008 | Enable SmartScreen policy |
| WIN-SEC-003 | Positive inactivity limit at most900seconds; preserve an already compliant tighter limit |
| WIN-SEC-011..014 | Client/server signing and advanced audit-policy precedence |
| WIN-SEC-015..018 | UAC, secure-desktop and elevation policies; EnableLUA requires reboot for effective behavior |
| WIN-SEC-020 | Domain secure-channel sign/seal policy |
| WIN-SMB-001,002,007..009 | Reviewed NTLM/LM and anonymous-session DWORD policies |
| WIN-RDP-001,002,005,006 | NLA, encryption, drive-redirection and password-saving policy |
| WIN-RDP-003,004 | Positive idle/disconnection limits at most900000/60000milliseconds; preserve compliant tighter limits |

An entire mixed batch is rejected before writes if any requested rule is outside the compiled write allowlist. The21 expanded registry controls,7 account-policy controls and18 audit-policy controls require explicit risk confirmation in core in addition to local remediation opt-in. Driver startup (SMB004), LSA protection (DEF009), operator-supplied strings and SCM/WMI remain outside the current write paths. Seven local account-policy scalars use NetUserModalsSet as described below. Only existing HKLM keys with DWORD or absent values are eligible. The agent never creates or deletes registry keys and refuses unexpected existing types. It preserves exact original DWORD bytes/type or value absence, writes the fixed compiled baseline only when needed, flushes and natively rechecks the result. Positive timeout values already below the maximum remain unchanged; zero is treated as disabled and is corrected. These findings attest registry configuration, not effective service activation, authentication compatibility or successful future logins. No service restart or reboot is issued. Rollback restores the named group's exact local snapshot, including deleting a value that did not originally exist. Unexpected external policy changes are refused rather than overwritten.

Native task mutation/restoration requires **LocalSystem enrollment and daemon identity**. Interactive administrator runs remain read-only. Current-user DPAPI under an interactive administrator does not isolate journals from that same user's unelevated processes, so that configuration is refused for mutation. Before any mutation, original backups and the mutation-intent journal are persisted with current-user DPAPI under `spool/tasks`, owned by SYSTEM/administrators with protected inheritable NTFS ACLs. Network paths and filesystem-link traversal are rejected. Encrypted state commits use synced temporary files and write-through Windows rename. Original backup files are exclusive and never overwritten by a later task. Core receives only safe before/after descriptors and `run_id/rule_id` backup locators, never local snapshot contents or filesystem paths.

The journal records each intended write before it occurs. Apply tasks also require a separately running recovery helper before the first mutation. The daemon starts only its own protected installed executable with fixed internal flags, an encrypted scoped lease and a random nonce. PID, nonce and task fingerprint readiness must match, and the child must be running outside every Windows job. The executable and its ancestors must be controlled by SYSTEM, Administrators or TrustedInstaller, with no untrusted write/replacement permissions. User-writable development binaries cannot authorize native apply tasks. No shell, arbitrary executable or network-provided command is accepted.

The helper uses `GetTickCount64` elapsed kernel time, including suspended time, so wall-clock/NTP changes do not extend an armed safety window. It restores prepared local snapshots if core acceptance is not durably acknowledged before expiry. It records failed task result revision 1 while preserving any original revision 0 locally; core can reconcile revision 1 even when it accepted revision 0 but its receipt was lost. Retries within a revision remain unchanged. Parent mutation, helper restoration and HTTP acknowledgment commits share a task-local Windows lock. The parent re-reads the journal under that lock before sending or committing a receipt; a late or wrong-revision receipt cannot disarm recovery.

On daemon restart, any unacknowledged apply is conservatively compensated before networking, coordinated with a live helper by the same lock. This also avoids interpreting an old uptime lease after a reboot. Interrupted batches are never applied again. Explicit rollback tasks retain their local execution/recheck recovery path; lost rollback receipts do not cause hardened settings to be reapplied. A failed restore or unrelated external policy drift reports unverified recovery and blocks further mutations for local manual review. Backups, revision history, leases, readiness records and temporary files remain until explicit operator cleanup.

The helper is detached from the parent's console, starts a separate process group, inherits no handles and requests Windows job breakaway. A job that forbids breakaway, an unavailable helper or a failed readiness handshake causes apply to fail before mutation. This does not protect against explicit termination of the helper, administrative process-tree termination, shutdown or host failure. Synchronous native calls and task-lock holders cannot be forcibly interrupted, so restoration may wait for a blocked native call or lock release. Registry APIs do not provide cross-process compare-and-swap isolation. Windows runtime validation remains outstanding; no helper or remediation was executed during development.

Reports are persisted before submission in `pending-report.json`. Failed submissions retry the exact report ID and payload, including after restart. The file is removed only after an accepted matching receipt. A Windows no-sharing file handle prevents two instances using the same spool and is released automatically after process exit. Interrupted temporary writes remain available for manual review. A permanently rejected or corrupt pending report blocks new scans until the operator resolves it; nothing is silently discarded. Report files contain rule IDs, outcomes and registry target metadata, without raw registry string values. Protect the identity and spool directories with Windows NTFS ACLs for the agent account and administrators; Go file mode bits do not provide a Windows ACL boundary.

The HTTP client requires HTTPS, except literal loopback HTTP IPs for local deployment. It rejects redirects, disables environment proxy inheritance, applies request timeouts and bounded responses, rejects trailing JSON, and validates report receipts. Server errors are logged by status without echoing tokens or response bodies.

Native rule metadata is JSON: `version`, `benchmark_id`, `ruleset_version`, and `rules`. Each rule has `id`, `title`, `severity`, `kind`, and provider-specific `path`, `name`, `match`, `expected`, or an unsupported `reason`. Every ID/provider/path/name tuple must match the compiled reviewed catalog allowlist. A server assignment cannot introduce arbitrary registry targets, WMI queries, namespaces, methods or shell commands. Both complete catalogs and server-selected nonempty subsets are accepted.

Registry paths are relative to HKLM and always use the 64-bit view. Supported scalar comparisons are `equals`, `nonempty`, `numeric_gte`, and `numeric_lte`. The last requires a positive value because zero Windows timers and lockout thresholds disable enforcement. NetAPI ages and lockout periods are compared in seconds. User-right assignments compare SID sets, independent of localization and formatting. Audit subcategories use fixed SDK GUIDs and exact success/failure flags. Service checks query startup configuration and treat only documented service-not-found errors as absent/disabled, matching the source audit's intent; they do not claim the service is currently stopped.

Missing registry data normally returns `error`. Two dedicated controls preserve their explicitly defined source semantics: an absent AlwaysInstallElevated policy value means zero, and an absent/empty NullSessionPipes list means none. Other access/type/provider errors remain `error`. Guest account flags are checked only after confirming built-in RID 501; a missing/localized/renamed English Guest name returns `error` instead of assuming disabled. WMI reads eight allowlisted Defender/SMB scalar properties and nine fixed per-profile firewall properties. It rejects null, missing, ambiguous and timed-out results, uses system-directory DLLs, and frees COM/VARIANT/SAFEARRAY resources on the owning thread. Provider availability, privileges and deployment version can still produce `error` on supported controls.

Firewall checks select Domain, Private or Public instances of `MSFT_NetFirewallProfile` in `ROOT\StandardCimv2`. Enablement, inbound action and blocked-traffic logging use the provider's own `Values`/`ValueMap` qualifiers to decode enumeration labels; no enum numbers are assumed. Missing, inconsistent or unknown/localized enum metadata returns `error`. Public log capacity uses the documented CIM uint64 to Automation BSTR mapping and is compared in KiB. Like the legacy `Get-NetFirewallProfile` audits without `-PolicyStore`, these checks concern the default local persistent configuration. They do not claim to prove effective ActiveStore or domain GPO policy. A deployment requiring effective-policy assurance needs a separately reviewed ActiveStore-aware provider.

Catalogs were translated from the actual sibling YAML audit definitions by `tools/import_catalog.py`. It converts reviewed provider intents into data and also generates the compiled target allowlist. It never executes YAML. It updates this repository's catalog copies and the authoritative sibling `ruleset/native/windows/<platform>/registry.json` files. Regenerate content without scanning a host:

```powershell
python .\tools\import_catalog.py ..\ruleset\windows
```

Coverage is identical across the three catalog files:

| Controls | Native coverage |
| --- | --- |
| Security options | 20/20 registry controls |
| RDP hardening | 6/6 registry controls |
| SMB/NTLM/LSA | 10/10 registry and WMI controls |
| Defender/miscellaneous | 9/9 registry and WMI preference controls |
| Password and lockout policy | 8/10, including Guest account flags |
| User rights assignment | 12/12 LSA controls |
| Firewall profile configuration | 9/9 native WMI property reads |
| Advanced audit policy | 18/18 system audit controls |
| Service configuration | 6/6 SCM controls |

Registry and WMI preference observations describe configured values; they do not prove effective domain policy, firewall enforcement, Defender runtime health or all compliance requirements. Password complexity and reversible-storage policy remain manual because the implemented NetAPI modal-policy metadata does not expose those properties; the agent does not read SAM files, hashes, passwords or credential stores. Offline assignment cache, remaining checks and signed deployment packaging remain work. WMI connection/enumeration calls have native bounded waits, but cancellation cannot interrupt a native call already in progress. Legacy YAML CIS references are draft mappings requiring licensed benchmark review. See [native provider sources](docs/native-providers.md). The existing LICENSE is preserved.

## Native local account-policy remediation

PWD001 and PWD003..008 now use NetUserModalsGet/Set for minimum length, lockout threshold/duration/window, maximum/minimum age and history length. Their compiled baseline is14characters,5attempts,900seconds,900seconds,5184000seconds,86400seconds and24entries, respectively. Stronger already-compliant scalar settings are retained. Backups contain only the selected numeric policy value, never passwords, password hashes, history contents or SAM files. A separate snapshot kind distinguishes native policy values from registry values in the existing DPAPI records.

These actions require local remediation opt-in, LocalSystem, explicit core risk confirmation, trusted executable/state and an independently armed recovery helper. Native version metadata must identify a workstation or non-DC server. Domain controllers and unknown product types are refused before policy backup/writes, because changing domain policy exceeds this local scope. The native setter always receives NULL servername; no remote computer is addressed.

Password fields use single-field levels1001/1002/1003/1005. Windows exposes lockout settings as a three-field level3 group, so each selected field is updated from a fresh read while retaining the other two. The selected value is checked again before that write. The API has no compare-and-swap transaction: do not run concurrent local/GPO policy changes during these tasks. Windows policy constraints can reject a requested combination or ordering; failure invokes restoration of the armed changes and never reports success. Rollback restores only the saved scalar and retains the then-current unselected lockout fields. Complexity and reversible-storage audits remain manual; no credential-file provider was added.

The scanner's advapi32/netapi32 functions now resolve through the existing approved x/sys system-DLL loader. No native API was invoked while implementing this source. Compiler checks passed; tests and live policy operations were not run.

Reviewed primary references: [NetUserModalsSet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset), [USER_MODALS_INFO_3](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_3), [USER_MODALS_INFO_1001](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_1001), [USER_MODALS_INFO_1005](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_1005). Inspected2026-11-15.

System DLL loading in the scanner, encrypted identity, durable-state commit and recovery paths now uses the approved x/sys system-directory loader. WMI loads its fixed COM libraries by an absolute system path with LOAD_LIBRARY_SEARCH_SYSTEM32. No DLL load or native account-policy call was executed during source preparation; Windows amd64 and386 compilation passed. The account-policy role guard uses the documented OSVERSIONINFOEX product-type values, excluding domain controllers and unknown roles: [Microsoft product-type documentation](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw).

## Native audit-policy remediation

AUD001..018 use AuditQuerySystemPolicy/AuditSetSystemPolicy with the same fixed subcategory GUIDs as the native reader. The compiled success/failure bit pairs match all three catalogs. Each original pair is saved in the existing private DPAPI backup/journal under a separate snapshot kind; no event records, account names or Security log contents are read. These actions require LocalSystem, local remediation opt-in, explicit core risk confirmation and an armed independent watchdog.

The native setter interprets zero as UNCHANGED, so restoring an original pair with no enabled event bits uses the explicit NONE operation. Queries normalize NONE/zero to the same success/failure pair. Restore/recheck covers that observable pair, not raw instruction encodings, global legacy-category overrides, per-user audit policy, GPO ownership or actual event delivery. The selected subcategory is checked again before a write; later external drift is refused by the common engine.

SeSecurityPrivilege is enabled only on a temporary self-impersonation token while the current OS thread is locked. An existing impersonation context is refused. AdjustTokenPrivileges is checked for both BOOL failure and ERROR_NOT_ALL_ASSIGNED. The token is closed and the thread reverts before reuse; failed reversion terminates the process according to Windows API guidance so it cannot continue under an unintended token. Any armed task remains recoverable by the separate helper. The normal read-only scan path does not enable this mutation privilege. No process token is modified.

Plans now distinguish registry, password_policy and audit_policy providers internally. Existing registry/account backup tags are unchanged. Core receives safe state descriptions and backup locators, never the private backup objects. No AuditSetSystemPolicy, privilege adjustment, helper or live scan was executed during implementation. Windows amd64/386 and Linux package-tree compilation passed; tests were not run.

Primary sources inspected2026-11-15: [AuditSetSystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditsetsystempolicy), [AUDIT_POLICY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information), [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges), [ImpersonateSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateself), [RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).
