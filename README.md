# Dell SARemediation Cleanup

PowerShell utility for detecting and removing **Dell SupportAssist Remediation** (SARemediation) and its
System Repair snapshot data from Windows endpoints. Designed to run from the **ConnectWise Control
(ScreenConnect) command console** by pulling the script directly from GitHub.

## Background

Dell SupportAssist Remediation is part of **SupportAssist OS Recovery Tools**. It creates system repair
snapshots under `ProgramData\Dell\SARemediation\SystemRepair\Snapshots\Backup\`, storing hash-named
`.exe` and `.dll` copies of system files. SentinelOne and other EDR products frequently flag these
snapshots as malware (for example, `Threat Mitigation Report Kill Success` escalations from ConnectWise
SIEM), even though they are legitimate Dell recovery artifacts rather than actual threats.

Example alert path:

```text
\Device\HarddiskVolume3\ProgramData\Dell\SARemediation\SystemRepair\Snapshots\Backup\8F388EF5....exe
```

Clients that do not use Dell SupportAssist or OS Recovery do not need this component installed.

## What it does

- Detects the **Dell SupportAssist Remediation** / **Alienware SupportAssist Remediation** Windows service
- Detects registered **Programs and Features** uninstall entries for SupportAssist Remediation / OS Recovery
- Detects Task Scheduler tasks related to SARemediation or System Repair
- Detects install and data folders under `Program Files`, `Program Files (x86)`, and `ProgramData`
  (including `ProgramData\Dell\SARemediation`)
- Runs vendor uninstallers (registry `UninstallString` / `QuietUninstallString`, or MSI `msiexec /x`) when
  available
- Stops and deletes matched services, removes scheduled tasks, and deletes remaining folders
- Optionally (`-RemoveSupportAssist`) also uninstalls **Dell SupportAssist** itself — the parent application
  that can redeliver SARemediation — and cleans up leftover registry keys
- **Dry-run by default** — reports findings without changing anything until `-Delete` is used

## Why SARemediation keeps coming back

Dell SupportAssist Remediation is typically redelivered by:

1. **Dell SupportAssist** checking for and installing SupportAssist OS Recovery components
2. **Dell Update** or factory preload mechanisms on business laptops

Running without `-RemoveSupportAssist` removes the current remediation install and snapshot data but does
not prevent Dell SupportAssist from reinstalling it later. Use `-RemoveSupportAssist` when clients do not
use SupportAssist at all.

## Safety

- Only targets components matching Dell SupportAssist Remediation / SARemediation naming — does not touch
  unrelated Dell software (BIOS/firmware update tools, Dell Command | Update unless bundled under
  SupportAssist, printer drivers, etc.)
- Does not delete arbitrary `ProgramData\Dell` content — only folders whose names match remediation
  patterns, plus the explicit `SARemediation` data path
- Each action (uninstaller, service, task, folder) is attempted independently and reported separately, so
  a failure in one step does not stop the rest of the cleanup from being reported

## Requirements

- **Windows endpoints only** (PowerShell 5.1+)
- Must run **elevated (as Administrator)** to stop/delete services, run uninstallers, and remove snapshot
  folders. Without elevation the script still reports findings but actions will fail.
- Outbound HTTPS to `raw.githubusercontent.com`

## ScreenConnect command console (Windows)

The SC command tab runs in `cmd` by default with a 10-second timeout. Use hashbang modifiers so
PowerShell runs with enough time and output space.

Replace `monobrau/dell-saremediation-cleanup` if you fork or rename the repository.

Use `ScriptBlock` invocation so `-Delete` binds correctly. Add a cache-buster query string so endpoints
do not run a stale cached copy from GitHub CDN.

### Dry-run (recommended first)

```powershell
#!ps
#timeout=120000
#maxlength=100000
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = 'monobrau/dell-saremediation-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-DellSARemediation.ps1?v=1.0.0"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script))
```

### Delete matched items (remediation only)

```powershell
#!ps
#timeout=120000
#maxlength=100000
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = 'monobrau/dell-saremediation-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-DellSARemediation.ps1?v=1.0.0"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script)) -Delete
```

### Delete remediation and Dell SupportAssist (recommended when unused)

```powershell
#!ps
#timeout=180000
#maxlength=100000
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = 'monobrau/dell-saremediation-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-DellSARemediation.ps1?v=1.0.0"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script)) -Delete -RemoveSupportAssist
```

### Windows fallback (if `#!ps` fails)

```text
#!cmd
#timeout=180000
#maxlength=100000
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = 'https://raw.githubusercontent.com/monobrau/dell-saremediation-cleanup/main/Remove-DellSARemediation.ps1?v=1.0.0'; $script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content; & ([ScriptBlock]::Create($script)) -Delete -RemoveSupportAssist }"
```

Output should begin with `=== Dell SARemediation Removal v1.0.0 ===`.

## Local usage

```powershell
# Report only
.\Remove-DellSARemediation.ps1

# Remove matched remediation items (run elevated)
.\Remove-DellSARemediation.ps1 -Delete

# Skip the vendor uninstaller
.\Remove-DellSARemediation.ps1 -Delete -SkipUninstaller

# Also remove Dell SupportAssist to stop redelivery (recommended when clients do not use it)
.\Remove-DellSARemediation.ps1 -Delete -RemoveSupportAssist
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Delete` | off | Remove/uninstall matched services, tasks, and folders |
| `-SkipUninstaller` | off | Do not run registry uninstall strings or known vendor uninstaller executables |
| `-RemoveSupportAssist` | off | Also uninstall Dell SupportAssist, its services/tasks/folders, and leftover registry keys |

## Example output

```text
=== Dell SARemediation Removal v1.0.0 ===
Mode: DRY-RUN
Running as Administrator: True

Remediation services found: 1
Remediation uninstall entries found: 1
Remediation scheduled tasks found: 1
Remediation install folders found: 1

[Uninstaller] WOULD RUN : Dell SupportAssist Remediation (MsiExec.exe /X{GUID} /quiet)
[Service] WOULD STOP/DELETE : DellSupportAssistRemediationService (Dell SupportAssist Remediation, state Running)
[ScheduledTask] WOULD REMOVE : \Dell\SupportAssist Remediation
[Folder] WOULD REMOVE : C:\ProgramData\Dell\SARemediation

=== Summary ===
Uninstallers would run: 1
Services would remove: 1
Scheduled tasks would remove: 1
Folders would remove: 1
No changes made. Re-run with -Delete to remove matched items.
```

## Troubleshooting

- **Command times out in SC:** Increase `#timeout=` (milliseconds). Snapshot folder deletion can take
  longer on machines with large backup caches — try `180000` or higher.
- **Actions report FAILED:** Confirm the session is elevated (Administrator). ScreenConnect sessions
  running as the logged-in user are not elevated by default.
- **SARemediation reappears after reboot or Dell Update:** Re-run with `-RemoveSupportAssist`. Consider
  blocking Dell SupportAssist deployment via Intune/GPO if it is not needed in the environment.
- **SIEM ticket still open after cleanup:** Resolve or allowlist the SentinelOne threat in the console,
  then close the ConnectWise ticket noting authorized Dell software was removed.
- **`ps: illegal argument`:** The guest is **macOS** (or non-Windows). This script is Windows-only.
- **Output truncated:** Increase `#maxlength=` or run locally and review full output.
- **TLS errors:** The SC one-liner sets TLS 1.2 explicitly; ensure the endpoint can reach GitHub.

## License

MIT — see [LICENSE](LICENSE).
