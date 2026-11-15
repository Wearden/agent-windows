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

Install defaults to read-only operation. To authorize the compiled native remediation controls locally at installation, use:

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

Writable coverage is **96 controls**: 35 registry controls (32 DWORD, two notice strings and the anonymous-pipe list), 7 native local account-policy controls, 18 native audit-policy controls, 6 native service controls, 12 native user-right controls 6 native firewall controls and one built-in Guest disabled-flag control and eleven selected WMI scalars, independent of the 98 read-only implementations:

| Writable IDs | Compiled native policy |
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
| WIN-SEC-004,005 | The original baseline notice caption/text as REG_SZ; existing nonempty text is preserved |
| WIN-SMB-010 | Remove NullSessionPipes, preserving an existing empty list |
| WIN-SVC-001..006 | Disable and stop the fixed service; preserve exact startup, delayed-start and stopped/running state for rollback |
| WIN-URA-001..012 | Compiled local LSA right assignments; exact SID membership backup/restore |
| WIN-FW-001..006 | Enable Domain/Private/Public firewall settings and select Block as their default inbound action |

An entire mixed batch is rejected before writes if any requested rule is outside the compiled write allowlist. The21 expanded DWORD controls, three notice/pipe-list controls, 7 account-policy controls, 18 audit-policy controls, six service controls and12 user-right controls require explicit risk confirmation in core in addition to local remediation opt-in. Driver startup (SMB004), LSA protection (DEF009), operator-supplied strings and WMI remain outside the current write paths. Seven local account-policy scalars use NetUserModalsSet as described below. Only existing HKLM keys are eligible. Each compiled target accepts its exact expected type (DWORD, notice REG_SZ or pipe-list REG_MULTI_SZ) or value absence. The agent never creates or deletes registry keys and refuses unexpected existing types. It preserves exact original bytes/type or value absence, writes the fixed compiled baseline only when needed, flushes and natively rechecks the result. Positive timeout values already below the maximum remain unchanged; zero is treated as disabled and is corrected. These findings attest registry configuration, not effective service activation, authentication compatibility or successful future logins. Registry, account and audit actions do not restart services or reboot. The compiled service actions can stop or restore only their named service. Rollback restores the named group's exact local snapshot, including deleting a value that did not originally exist. Unexpected external policy changes are refused rather than overwritten.

Native task mutation/restoration requires **LocalSystem enrollment and daemon identity**. Interactive administrator runs remain read-only. Current-user DPAPI under an interactive administrator does not isolate journals from that same user's unelevated processes, so that configuration is refused for mutation. Before any mutation, original backups and the mutation-intent journal are persisted with current-user DPAPI under `spool/tasks`, owned by SYSTEM/administrators with protected inheritable NTFS ACLs. Network paths and filesystem-link traversal are rejected. Encrypted state commits use synced temporary files and write-through Windows rename. Original backup files are exclusive and never overwritten by a later task. Core receives only safe before/after descriptors and `run_id/rule_id` backup locators, never local snapshot contents or filesystem paths.

The journal records each intended write before it occurs. Apply tasks also require a separately running recovery helper before the first mutation. The daemon starts only its own protected installed executable with fixed internal flags, an encrypted scoped lease and a random nonce. PID, nonce and task fingerprint readiness must match, and the child must be running outside every Windows job. The executable and its ancestors must be controlled by SYSTEM, Administrators or TrustedInstaller, with no untrusted write/replacement permissions. User-writable development binaries cannot authorize native apply tasks. No shell, arbitrary executable or network-provided command is accepted.

The helper uses `GetTickCount64` elapsed kernel time, including suspended time, so wall-clock/NTP changes do not extend an armed safety window. It restores prepared local snapshots if core acceptance is not durably acknowledged before expiry. It records failed task result revision 1 while preserving any original revision 0 locally; core can reconcile revision 1 even when it accepted revision 0 but its receipt was lost. Retries within a revision remain unchanged. Parent mutation, helper restoration and HTTP acknowledgment commits share a task-local Windows lock. The parent re-reads the journal under that lock before sending or committing a receipt; a late or wrong-revision receipt cannot disarm recovery.

On daemon restart, any unacknowledged apply is conservatively compensated before networking, coordinated with a live helper by the same lock. This also avoids interpreting an old uptime lease after a reboot. Interrupted batches are never applied again. Explicit rollback tasks retain their local execution/recheck recovery path; lost rollback receipts do not cause hardened settings to be reapplied. A failed restore or unrelated external policy drift reports unverified recovery and blocks further mutations for local manual review. Backups, revision history, leases, readiness records and temporary files remain until explicit operator cleanup.

The helper is detached from the parent's console, starts a separate process group, inherits no handles and requests Windows job breakaway. A job that forbids breakaway, an unavailable helper or a failed readiness handshake causes apply to fail before mutation. This does not protect against explicit termination of the helper, administrative process-tree termination, shutdown or host failure. Synchronous native calls and task-lock holders cannot be forcibly interrupted, so restoration may wait for a blocked native call or lock release. Registry APIs do not provide cross-process compare-and-swap isolation. Windows runtime validation remains outstanding; no helper or remediation was executed during development.

Reports are persisted before submission in `pending-report.json`. Failed submissions retry the exact report ID and payload, including after restart. The file is removed only after an accepted matching receipt. A Windows no-sharing file handle prevents two instances using the same spool and is released automatically after process exit. Interrupted temporary writes remain available for manual review. A permanently rejected or corrupt pending report blocks new scans until the operator resolves it; nothing is silently discarded. Report files contain rule IDs, outcomes and registry target metadata, without raw registry string values. Protect the identity and spool directories with Windows NTFS ACLs for the agent account and administrators; Go file mode bits do not provide a Windows ACL boundary.

The HTTP client requires HTTPS, except literal loopback HTTP IPs for local deployment. It rejects redirects, disables environment proxy inheritance, applies request timeouts and bounded responses, rejects trailing JSON, and validates report receipts. Server errors are logged by status without echoing tokens or response bodies.

Native rule metadata is JSON: `version`, `benchmark_id`, `ruleset_version`, and `rules`. Each rule has `id`, `title`, `severity`, `kind`, and provider-specific `path`, `name`, `match`, `expected`, or an unsupported `reason`. Every ID/provider/path/name tuple must match the compiled reviewed catalog allowlist. A server assignment cannot introduce arbitrary registry targets, WMI queries, namespaces, methods or shell commands. Both complete catalogs and server-selected nonempty subsets are accepted.

Registry paths are relative to HKLM and always use the 64-bit view. Supported scalar comparisons are `equals`, `nonempty`, `numeric_gte`, and `numeric_lte`. The last requires a positive value because zero Windows timers and lockout thresholds disable enforcement. NetAPI ages and lockout periods are compared in seconds. User-right assignments compare SID sets, independent of localization and formatting. Audit subcategories use fixed SDK GUIDs and exact success/failure flags. Service checks query startup configuration and treat only documented service-not-found errors as absent/disabled, matching the source audit's intent; they do not claim the service is currently stopped.

Missing registry data normally returns `error`. Two dedicated controls preserve their explicitly defined source semantics: an absent AlwaysInstallElevated policy value means zero, and an absent/empty NullSessionPipes list means none. Other access/type/provider errors remain `error`. Guest account discovery derives RID501 from the local SAM SID, resolves its current name and rechecks its exact SID through USER_INFO_23. Localized/renamed names are supported; missing/ambiguous evidence and domain-controller use return `error`. WMI reads eight allowlisted Defender/SMB scalar properties and nine fixed per-profile firewall properties. It rejects null, missing, ambiguous and timed-out results, uses system-directory DLLs, and frees COM/VARIANT/SAFEARRAY resources on the owning thread. Provider availability, privileges and deployment version can still produce `error` on supported controls.

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

## Notice and anonymous-pipe policy restoration

SEC004/005 use the same fixed English notice strings as all three retained baselines. Nonempty well-formed existing REG_SZ text is already compliant and remains unchanged. No request may supply notice text, paths or registry value types. SMB010 removes the fixed NullSessionPipes value; an absent value or well-formed empty list remains compliant. Removal can affect applications relying on anonymous named-pipe access, so core requires explicit risk confirmation.

Before mutation, each exact original value or absence is saved through the existing SYSTEM-only DPAPI engine. Restoration preserves byte order, UTF-16 encoding, list order and type. Strings/lists are bounded to64 KiB; odd byte lengths, invalid surrogate pairs, missing terminators, embedded empty list elements and unexpected types are refused before mutation. Empty MULTI_SZ accepts the documented single empty terminator as well as the conventional double terminator. Text and list contents never appear in change descriptors or core submissions. Only fixed shape descriptions are sent.

The existing independent watchdog, elapsed-time lease, journal validation and drift refusal apply to these targets. Native rechecks establish stored registry state only, not immediate authentication/session behavior or loaded service state. These registry actions do not restart services. The prior DWORD/account/audit backup tags remain unchanged.

Registry type and termination handling was inspected against [Registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) and [RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw). No new dependency was added. Compiler checks do not prove runtime behavior; no tests or native changes were executed.

## Native service policy actions

SVC001..006 use local SCM APIs for Spooler, RemoteRegistry, TlntSvr, SNMP, Fax and simptcp. They require LocalSystem, local remediation opt-in, explicit core risk confirmation and the existing independent recovery helper. Missing services are already compliant and are never installed. Applying the policy disables startup, clears delayed auto-start and stops the selected service. Printing, remote registry and other corresponding functionality can stop, so the operator must select only appropriate lab targets.

The private snapshot records startup type, delayed-start flag and stable stopped/running state. It also retains a SHA256 fingerprint of unmodified basic SCM configuration, including service type, executable, account, dependencies, load group, tag, display name and error control. Only the fingerprint is stored; those strings are neither stored in task journals nor sent to core. A changed fingerprint blocks automatic restoration, preventing rollback from restarting a reconfigured executable. Existing DWORD/account/audit backups retain their formats.

Rollback restores the recorded configuration and stopped/running state through typed SCM calls. A previously disabled but running service is temporarily demand-startable for restoration and is disabled again after starting. Recovery accepts only journaled endpoint-field combinations and that specific temporary manual-start state, with the same configuration fingerprint. This permits compensation after interruption between configuration/runtime changes. Other drift remains a manual-review failure.

Stops never force or stop dependent services. A running service must have inspectable, already running direct dependencies before backup. Before restart, those dependencies are rechecked; stopped/missing dependencies and dependency groups are refused to prevent implicit dependency startup. At most32 dependencies with256 UTF-16 units per name are examined. Drivers, paused/unreviewed runtime states, inaccessible configuration, missing evidence and oversized buffers fail explicitly. Basic configuration buffers are bounded to64 KiB.

Pending start/stop states are observed with a cooperative six-second snapshot budget. Each write sequence uses at most a ten-second cooperative budget, further limited by the task context deadline, with cancellation/deadline checks before native writes. Restoration uses an independent context so expiry does not cancel compensation. Synchronous SCM calls cannot be forcibly interrupted; a blocked native call can delay both the task lock and recovery. Runtime state, process IDs, in-flight jobs and custom service-start arguments are not process-memory backups. Services are restarted with no custom arguments, and their own failure actions or external administrators can still change state. There is no cross-process SCM compare-and-swap transaction.

Implementation references inspected: [ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw), [delayed auto-start](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info), [ControlService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice) and [StartServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew), plus the already approved x/sys native wrappers. No dependency was added. No service/API call, test, helper, scan or application execution was performed during implementation.

## Native user-right policy actions

URA001..012 use local LSA policy APIs, with LocalSystem, local remediation opt-in, explicit core risk confirmation and an independently armed helper. Domain controllers and unknown product types are refused. No secret/private-data access, account-name resolution, credential store, SAM/password file, remote policy handle or network-selected right/SID is used. Only compiled right names and targets can be changed.

Debug, remote shutdown, take ownership, load-driver and backup rights target Administrators only; TCB targets no assignments. Impersonation targets exactly Administrators, Local Service, Network Service and Service, matching the original remediation list. Deny-right controls add Guests while retaining existing denials; network logon adds Administrators while retaining the existing set. Those contains-mode actions intentionally avoid the old shell remediation side effects of removing unrelated denials or granting network logon to additional groups.

Snapshots store canonical sorted binary SID sets under a separate DPAPI snapshot tag, bounded to256 SIDs of at most68 bytes each. Duplicate, malformed, unordered, truncated and trailing data are refused. Names and SID contents are never included in core change descriptors. Two successive enumeration results must agree before backup. Add/remove calls change only one named right for one SID; the remove-all flag is always false. The optional LSA policy account-record creation permission is requested only for writes; this does not create a Windows login account.

Each set difference removes extras before adding missing members, keeping intermediate cardinality within the snapshot bound. Before each individual native call the current set must equal the expected working set, and context cancellation/deadlines are checked. Recovery accepts only subsets of the original/target union that retain every common member. Unexpected outside members or lost common assignments block restoration for manual review. Exact original membership is restored; unrelated rights remain untouched. The sequence is not an LSA transaction and cannot distinguish external edits that happen to equal a planned intermediate state. Native synchronous calls remain unpreemptible. These are stored assignment observations, not group expansion or proof of privileges in existing logon tokens.

Native catalog version4 closes two drift gaps: URA007 compares the exact four-SID impersonation set instead of checking only for Administrators; service audits require disabled startup and stopped state. Original YAML remains unchanged. See the canonical Windows native README for hashes and semantic changes.

Inspected API references: [LsaOpenPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy), [enumeration](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright), [add](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights), [remove](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights), [policy access](https://learn.microsoft.com/en-us/windows/win32/secmgmt/policy-object-access-rights) and [SID layout](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components). The installed Windows SDK10.0.26100.0 NTSecAPI.h declarations and already approved x/sys SID helpers were also inspected. No dependency was added and no native policy operation or test was executed.

## Native local firewall scalar actions

FW001..006 use INetFwPolicy2 directly for the three individual Domain/Private/Public profiles. Local enabled flags are set to true and default inbound action to Block. Each call addresses one profile and one compiled property. No rule, group, excluded interface, outbound policy, logging configuration or firewall reset is modified. These changes can interrupt remote administration and require explicit core risk confirmation, local opt-in, LocalSystem, private DPAPI backups and an independent watchdog. The Linux nftables dependency remains read-only.

Snapshots retain the exact logical getter value under a dedicated scalar tag. They describe the COM API setting, not raw registry-value presence or the full firewall store. Two getter results must agree before backup; expected-value drift is checked again before mutation, and the getter must match after writes/restores. LocalPolicyModifyState must report OK during apply preparation and again before dispatching a write. This check concerns the current profile and is not proof that every inactive profile is free of Group Policy overrides. Rollback/compensation does not require that apply precondition, allowing local settings to be restored if management policy subsequently changes.

Group Policy can make effective behavior differ from local flags. These actions do not override domain policy or attest packet delivery, remote-admin reachability or effective rule exceptions. COM settings do not offer a cross-process compare-and-swap transaction; external changes matching a planned value are indistinguishable. Synchronous COM/RPC calls cannot be forcibly interrupted. Task cancellation/deadline checks precede native setters; recovery uses its independent context. The existing task-result receipt/watchdog logic remains in force. No firewall API or watchdog was executed during development.

The fixed IID/CLSID, IDispatch prefix, scalar method order, profile bits and Boolean/action widths were inspected against installed SDK10.0.26100.0 netfw.h/icftypes.h. Vendor references: [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2), [local enabled flag](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_firewallenabled), [current-profile modify state](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_localpolicymodifystate) and [default inbound setter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-put_defaultinboundaction). No new dependency was added. FW007..009 logging and the other WMI setters remain unfinished; unsupported write IDs are still rejected.

## Built-in Guest account mutation

WIN-PWD-010 uses local NetUserSetInfo level1008 to set only UF_ACCOUNTDISABLE, retaining all other observed flags. The private DPAPI snapshot retains flags and a SID fingerprint, never an account name. Apply and restoration refuse identity or unrelated-flag drift; restoration can re-enable only the exact previously enabled built-in Guest account. No passwords, full-name/comment fields, memberships or other accounts are modified. Native account-name updates do not provide an atomic SID compare-and-swap; privileged concurrent renames/changes require external coordination. Rechecks and synchronous native-call cancellation limits still apply.

Discovery uses [USER_MODALS_INFO_2](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_2) and [USER_INFO_23](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_23). The flags API is [USER_INFO_1008](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1008). These sources were inspected; no account query/write, test or native recovery ran during implementation.

## Installer elevation policy mutation

WIN-DEF-007 sets only the fixed per-machine AlwaysInstallElevated DWORD to zero. A missing value/key is already compliant and remains untouched. The provider never creates policy keys, opens user hives, invokes an installer or changes per-user policy. Existing registry snapshot/recheck/DPAPI recovery restores the exact prior DWORD or value absence; concurrent registry changes are refused where observable. Core requires risk confirmation. [Microsoft policy documentation](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) confirms the elevation policy requires both per-machine and per-user values to be1. This is a policy configuration action, not a claim that every managed installation runs without elevation. No installer/registry operation or test ran.

## Selected WMI policy mutation

Eleven fixed Defender/SMB/firewall logging properties have typed scalar write/restore plans. Instance queries retain native keys; only the selected scalar, CIM/VARIANT type and a relative-instance identity fingerprint enter the private DPAPI snapshot. Missing, null, ambiguous or unreviewed values are refused. Original scalar type/value and identity are rechecked before each write and restored through existing recovery. Core requires risk confirmation.

Defender uses only its compiled static Set method and SMB only SetConfiguration, with the selected typed scalar parameter. Method signatures are obtained from the compiled class, their parameter types are checked, and ReturnValue must report success. No method/class/input name comes from a remote task. The installed Windows Defender and SmbShare CDXML setter declarations were inspected as source, without running cmdlets.

Three logging controls use only the compiled Domain/Public profile and one property at a time. LogBlocked's target must map to True in provider metadata. LogMaxSizeKilobytes is retained as a full uint64 through WMI BSTR transport. MAXUINT64 means NotConfigured, so it never counts as a large compliant log limit; larger explicit compliant limits remain unchanged. The agent never directly reads or writes log files or changes their configured paths; packet filters and rules are outside these handlers.

Logging writes require IWbemContext __PUT_EXTENSIONS, __PUT_EXT_CLIENT_REQUEST, __PUT_EXT_ATOMIC and a one-property __PUT_EXT_PROPERTIES array with WBEM_FLAG_UPDATE_ONLY. Unsupported partial-update providers fail explicitly. There is no whole-instance or shell fallback. Snapshot/recheck is not an atomic compare-and-swap against external changes; synchronous native calls cannot be forcibly interrupted by context cancellation. Selected-property rechecks do not attest effective domain/GPO/tamper policy, successful log production or network reachability.

The installed NetSecurity CDXML declares cim:ModifyInstance for logging. [Microsoft partial-instance update documentation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/updating-part-of-an-instance), [MSFT_NetFirewallProfile types and NotConfigured sentinel](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallprofile), the [WinSDK interface layout](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/WbemCli.h), and [SAFEARRAY pointer semantics](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayputelement) were inspected. No WMI query/write or test ran; provider support remains unexercised.
