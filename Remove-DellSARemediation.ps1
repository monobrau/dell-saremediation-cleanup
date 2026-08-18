#Requires -Version 5.1
<#
.SYNOPSIS
    Detects and removes Dell SupportAssist Remediation (SARemediation) and related System Repair snapshot data.

.DESCRIPTION
    Finds the Dell SupportAssist Remediation Windows service, registered uninstall entries, Task Scheduler
    tasks, and install/data folders (including ProgramData\Dell\SARemediation\SystemRepair\Snapshots).
    Runs vendor uninstallers when present, stops and deletes matched services, removes scheduled tasks, and
    cleans up remaining folders. Dry-run by default.

.PARAMETER Delete
    Actually remove/uninstall matched items. Without this switch, only reports findings.

.PARAMETER SkipUninstaller
    Do not attempt to run registry uninstall strings or known vendor uninstaller executables.

.PARAMETER RemoveSupportAssist
    Also detect and uninstall Dell SupportAssist and related components (SupportAssistAgent service,
    SupportAssist install folders). Off by default because it removes more than the remediation
    component (driver/firmware checks, warranty registration). Use when clients do not use SupportAssist
    and you want to prevent redelivery of SARemediation.

.PARAMETER BlockReinstall
    Apply local policies to reduce automatic redelivery: disables Dell Update / Command Update scheduled
    tasks, disables remediation-related services, and (when combined with -Delete) also enables
    -RemoveSupportAssist. Does not block every factory preload path; pair with Intune/GPO app blocklists
    for fleet-wide enforcement when needed.

.PARAMETER BackupsOnly
    Only target System Repair snapshot backup folders under ProgramData\Dell\SARemediation
    (typically ...\SystemRepair\Snapshots\Backup). Does not uninstall SARemediation/SupportAssist,
    stop services, or remove scheduled tasks. Preferred for SentinelOne FP cleanup of hash-named
    backup .exe/.dll copies. Ignores -RemoveSupportAssist / -BlockReinstall when set.
#>
[CmdletBinding()]
param(
    [switch]$Delete,
    [switch]$SkipUninstaller,
    [switch]$RemoveSupportAssist,
    [switch]$BlockReinstall,
    [switch]$BackupsOnly
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.3.0'

if ($env:OS -notlike '*Windows*' -and -not $IsWindows) {
    Write-Output "ERROR: This script supports Windows endpoints only."
    return
}

$RemediationServicePattern = 'saremediation|supportassist.*remediation'
$RemediationDisplayNamePattern = 'SupportAssist\s+(OS\s+Recovery(\s+Tools)?|Remediation)|Alienware\s+SupportAssist\s+Remediation|SARemediation'
$RemediationTaskPattern = 'saremediation|supportassist.*remediation|system\s*repair'
$RemediationFolderNamePattern = 'saremediation|supportassist.*remediation|supportassistosrecovery'

$SupportAssistDisplayNamePattern = '^Dell SupportAssist$|^PC-Doctor for Windows$'
$SupportAssistServicePattern = '^SupportAssistAgent$|^DellSupportAssistManagerService$|^SupportAssistService$'
$SupportAssistTaskPattern = 'supportassist(?!.*remediation)|supportassistagent|dell\s*supportassist'
$SupportAssistFolderNamePattern = '^SupportAssist$|^SupportAssistAgent$|^SupportAssistClient$'
$SupportAssistRegistryKeys = @(
    'HKLM:\SOFTWARE\Dell\SupportAssist',
    'HKLM:\SOFTWARE\WOW6432Node\Dell\SupportAssist'
)
$DeliveryTaskPattern = '(?i)dell.*(command\s*update|supportassist|remediation|client\s*management|update\s*service)|supportassist.*(update|remediation)'
$DeliveryServicePattern = '(?i)supportassist|saremediation|remediation'
$RemediationServiceDisableNames = @(
    'Dell SupportAssist Remediation',
    'Alienware SupportAssist Remediation'
)

if ($BackupsOnly -and ($RemoveSupportAssist -or $BlockReinstall)) {
    Write-Output 'WARNING: -BackupsOnly is set; ignoring -RemoveSupportAssist / -BlockReinstall.'
    $RemoveSupportAssist = $false
    $BlockReinstall = $false
}

if ($BlockReinstall -and $Delete) {
    $RemoveSupportAssist = $true
}

function Get-DellUpdateDeliveryTasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return @()
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -ne 'Disabled' -and (
                $_.TaskName -match $DeliveryTaskPattern -or
                $_.TaskPath -match '\\Dell\\|\\DellInc\\'
            )
        }
}

function Get-DellDeliveryServices {
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.StartMode -ne 'Disabled' -and (
                $_.Name -match $DeliveryServicePattern -or
                $_.DisplayName -match $DeliveryServicePattern -or
                $RemediationServiceDisableNames -contains $_.DisplayName
            )
        }
}

function Invoke-ScheduledTaskDisableAction {
    param(
        [object]$Task,
        [ref]$Stats
    )

    $path = "$($Task.TaskPath)$($Task.TaskName)"

    if (-not $Delete) {
        Write-Result -Type 'ScheduledTask' -Status 'WOULD DISABLE' -Path $path
        $Stats.Value.WouldDisableTasks++
        return
    }

    try {
        Disable-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop
        Write-Result -Type 'ScheduledTask' -Status 'DISABLED' -Path $path
        $Stats.Value.DisabledTasks++
    }
    catch {
        Write-Result -Type 'ScheduledTask' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedTasks++
    }
}

function Invoke-ServiceDisableAction {
    param(
        [object]$Service,
        [ref]$Stats
    )

    $name = $Service.Name

    if (-not $Delete) {
        Write-Result -Type 'Service' -Status 'WOULD DISABLE' -Path $name -Detail ("{0}, start {1}" -f $Service.DisplayName, $Service.StartMode)
        $Stats.Value.WouldDisableServices++
        return
    }

    try {
        if ($Service.State -eq 'Running') {
            Stop-Service -Name $name -Force -ErrorAction Stop
        }

        $scOutput = & sc.exe config $name start= disabled 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Result -Type 'Service' -Status 'DISABLED' -Path $name -Detail $Service.DisplayName
            $Stats.Value.DisabledServices++
        }
        else {
            Write-Result -Type 'Service' -Status 'FAILED' -Path $name -Detail ("sc config exit {0}: {1}" -f $LASTEXITCODE, ($scOutput -join ' '))
            $Stats.Value.FailedServices++
        }
    }
    catch {
        Write-Result -Type 'Service' -Status 'FAILED' -Path $name -Detail $_.Exception.Message
        $Stats.Value.FailedServices++
    }
}

function Write-Result {
    param(
        [string]$Type,
        [string]$Status,
        [string]$Path,
        [string]$Detail = ''
    )

    $line = "[$Type] $Status : $Path"
    if ($Detail) {
        $line += " ($Detail)"
    }

    Write-Output $line
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RemediationServices {
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $RemediationServicePattern -or $_.DisplayName -match $RemediationDisplayNamePattern }
}

function Get-RemediationUninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -match $RemediationDisplayNamePattern }
    }
}

function Get-RemediationScheduledTasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return @()
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match $RemediationTaskPattern -or $_.TaskPath -match '\\Dell\\.*remediation|\\Dell\\.*saremediation' }
}

function Get-DellVendorFolders {
    param([string]$FolderNamePattern)

    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) |
        Where-Object { $_ } | Select-Object -Unique

    $folders = New-Object System.Collections.Generic.List[string]

    foreach ($root in $roots) {
        $dellRoot = Join-Path $root 'Dell'
        if (-not (Test-Path -LiteralPath $dellRoot)) {
            continue
        }

        Get-ChildItem -LiteralPath $dellRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $FolderNamePattern } |
            ForEach-Object { [void]$folders.Add($_.FullName) }
    }

    return $folders
}

function Get-RemediationInstallFolders {
    $folders = New-Object System.Collections.Generic.List[string]

    foreach ($path in @(Get-DellVendorFolders -FolderNamePattern $RemediationFolderNamePattern)) {
        [void]$folders.Add($path)
    }

    $saRoot = Join-Path $env:ProgramData 'Dell\SARemediation'
    if ((Test-Path -LiteralPath $saRoot) -and -not $folders.Contains($saRoot)) {
        [void]$folders.Add($saRoot)
    }

    return $folders
}

function Get-SaRemediationBackupFolders {
    # Only the snapshot Backup folders Dell SARemediation creates (S1 FP path), not the whole product.
    $folders = New-Object System.Collections.Generic.List[string]

    $primary = Join-Path $env:ProgramData 'Dell\SARemediation\SystemRepair\Snapshots\Backup'
    if (Test-Path -LiteralPath $primary) {
        [void]$folders.Add($primary)
    }

    $dellRoot = Join-Path $env:ProgramData 'Dell'
    if (Test-Path -LiteralPath $dellRoot) {
        Get-ChildItem -LiteralPath $dellRoot -Directory -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -eq 'Backup' -and
                $_.Parent -and ($_.Parent.Name -eq 'Snapshots') -and
                ($_.FullName -match '(?i)\\SARemediation\\')
            } |
            ForEach-Object {
                if (-not $folders.Contains($_.FullName)) {
                    [void]$folders.Add($_.FullName)
                }
            }
    }

    return $folders
}

function Get-SupportAssistServices {
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $SupportAssistServicePattern -or $_.DisplayName -match '^Dell SupportAssist' }
}

function Get-SupportAssistUninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -match $SupportAssistDisplayNamePattern }
    }
}

function Get-SupportAssistScheduledTasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return @()
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.TaskName -match $SupportAssistTaskPattern -or $_.TaskPath -match '\\Dell\\SupportAssist') -and
            $_.TaskName -notmatch $RemediationTaskPattern
        }
}

function Get-SupportAssistInstallFolders {
    Get-DellVendorFolders -FolderNamePattern $SupportAssistFolderNamePattern
}

function Get-SupportAssistUninstallerPaths {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique
    $relativePaths = @(
        'Dell\SupportAssist\uninstaller.exe',
        'Dell\SupportAssist\SupportAssistUninstaller.exe',
        'Dell\SupportAssistAgent\SupportAssistAgent.exe'
    )

    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($root in $roots) {
        foreach ($relative in $relativePaths) {
            $exe = Join-Path $root $relative
            if (Test-Path -LiteralPath $exe) {
                [void]$paths.Add($exe)
            }
        }
    }

    return $paths
}

function Get-SupportAssistPresentRegistryKeys {
    $SupportAssistRegistryKeys | Where-Object { Test-Path -LiteralPath $_ }
}

function Stop-RelatedProcesses {
    param([string[]]$NamePatterns)

    foreach ($pattern in $NamePatterns) {
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -match $pattern } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Add-NoRestartFlags {
    param([string]$Arguments)

    $args = if ($null -eq $Arguments) { '' } else { [string]$Arguments }

    # Strip reboot-forcing MSI properties; Dell / nested MSI may otherwise reboot anyway.
    $args = $args -replace '(?i)\s*REBOOT\s*=\s*(Force|Prompt|Suppress)\b', ''
    $args = $args.Trim()

    if ($args -notmatch '(?i)\bREBOOT\s*=\s*ReallySuppress\b') {
        $args = ($args + ' REBOOT=ReallySuppress').Trim()
    }
    if ($args -notmatch '(?i)/norestart\b') {
        $args = ($args + ' /norestart').Trim()
    }

    return $args
}

function Get-SilentUninstallArguments {
    param(
        [string]$Exe,
        [string]$Arguments
    )

    # SupportAssistUninstaller.exe historically used "/arp /S" with NO reboot suppression.
    # That path was observed to reboot endpoints during -RemoveSupportAssist. Always add /norestart.
    if ($Exe -match '(?i)SupportAssist(Uninstaller|Agent|uninstaller)\.exe$') {
        $args = if ([string]::IsNullOrWhiteSpace($Arguments)) { '/arp /S' } else { $Arguments.Trim() }
        if ($args -notmatch '(?i)/arp') {
            $args = ('/arp ' + $args).Trim()
        }
        if ($args -notmatch '(?i)(/S\b|/quiet|/qn|/silent)') {
            $args = ($args + ' /S').Trim()
        }
        return (Add-NoRestartFlags -Arguments $args)
    }

    if ($Exe -match '(?i)msiexec\.exe$') {
        $Arguments = $Arguments -replace '(?i)/I\b', '/X'

        if ($Arguments -notmatch '(?i)/qn|/quiet|/passive') {
            $Arguments = ($Arguments + ' /qn').Trim()
        }

        return (Add-NoRestartFlags -Arguments $Arguments)
    }

    if ($Arguments -notmatch '(?i)/quiet|/qn|/silent|/verysilent|/s\b|/S\b') {
        $Arguments = ($Arguments + ' /quiet').Trim()
    }

    return (Add-NoRestartFlags -Arguments $Arguments)
}

function Invoke-UninstallCommandLine {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        throw 'Empty uninstall command line'
    }

    if ($CommandLine -match '^\s*"(?<exe>[^"]+)"\s*(?<args>.*)$') {
        $exe = $Matches['exe']
        $arguments = $Matches['args']
    }
    elseif ($CommandLine -match '^\s*(?<exe>\S+)\s*(?<args>.*)$') {
        $exe = $Matches['exe']
        $arguments = $Matches['args']
    }
    else {
        throw "Unable to parse uninstall command line: $CommandLine"
    }

    $arguments = Get-SilentUninstallArguments -Exe $exe -Arguments $arguments
    Write-Output ("[Uninstaller] EXEC : {0} {1}" -f $exe, $arguments)

    $proc = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($proc.ExitCode -eq 3010) {
        Write-Output '[Uninstaller] WARN : exit 3010 (reboot requested by installer). Script did not call Restart-Computer; schedule reboot later if needed.'
        return
    }
    if ($proc.ExitCode -ne 0) {
        throw "Uninstaller exited with code $($proc.ExitCode)"
    }
}

function Invoke-UninstallEntryAction {
    param(
        [object]$Entry,
        [string]$ResultType = 'Uninstaller',
        [ref]$Stats
    )

    $displayName = $Entry.DisplayName
    $commandLine = if ($Entry.QuietUninstallString) { $Entry.QuietUninstallString } else { $Entry.UninstallString }

    if (-not $Delete) {
        Write-Result -Type $ResultType -Status 'WOULD RUN' -Path $displayName -Detail $commandLine
        $Stats.Value.WouldRunUninstalls++
        return
    }

    try {
        Stop-RelatedProcesses -NamePatterns @('SupportAssist', 'SARemediation', 'DellSupportAssist')
        Invoke-UninstallCommandLine -CommandLine $commandLine
        Write-Result -Type $ResultType -Status 'RAN' -Path $displayName -Detail $commandLine
        $Stats.Value.RanUninstalls++
    }
    catch {
        Write-Result -Type $ResultType -Status 'FAILED' -Path $displayName -Detail $_.Exception.Message
        $Stats.Value.FailedUninstalls++
    }
}

function Invoke-SupportAssistUninstallerAction {
    param(
        [string]$ExePath,
        [ref]$Stats
    )

    if (-not $Delete) {
        Write-Result -Type 'SupportAssist-Uninstaller' -Status 'WOULD RUN' -Path $ExePath
        $Stats.Value.WouldRunUninstalls++
        return
    }

    try {
        Stop-RelatedProcesses -NamePatterns @('SupportAssist', 'SARemediation', 'DellSupportAssist')
        $arguments = Get-SilentUninstallArguments -Exe $ExePath -Arguments ''
        Write-Output ("[SupportAssist-Uninstaller] EXEC : {0} {1}" -f $ExePath, $arguments)
        $proc = Start-Process -FilePath $ExePath -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        if ($proc.ExitCode -eq 3010) {
            Write-Output '[SupportAssist-Uninstaller] WARN : exit 3010 (reboot requested). Script did not initiate reboot.'
        }
        elseif ($proc.ExitCode -ne 0) {
            throw "Uninstaller exited with code $($proc.ExitCode)"
        }

        Write-Result -Type 'SupportAssist-Uninstaller' -Status 'RAN' -Path $ExePath -Detail $arguments
        $Stats.Value.RanUninstalls++
    }
    catch {
        Write-Result -Type 'SupportAssist-Uninstaller' -Status 'FAILED' -Path $ExePath -Detail $_.Exception.Message
        $Stats.Value.FailedUninstalls++
    }
}

function Invoke-RegistryKeyAction {
    param(
        [string]$Path,
        [ref]$Stats
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'RegistryKey' -Status 'WOULD REMOVE' -Path $Path
        $Stats.Value.WouldRemoveRegistryKeys++
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Result -Type 'RegistryKey' -Status 'REMOVED' -Path $Path
        $Stats.Value.RemovedRegistryKeys++
    }
    catch {
        Write-Result -Type 'RegistryKey' -Status 'FAILED' -Path $Path -Detail $_.Exception.Message
        $Stats.Value.FailedRegistryKeys++
    }
}

function Invoke-ServiceAction {
    param(
        [object]$Service,
        [ref]$Stats
    )

    $name = $Service.Name

    if (-not $Delete) {
        Write-Result -Type 'Service' -Status 'WOULD STOP/DELETE' -Path $name -Detail ("{0}, state {1}" -f $Service.DisplayName, $Service.State)
        $Stats.Value.WouldRemoveServices++
        return
    }

    try {
        if ($Service.State -eq 'Running') {
            Stop-Service -Name $name -Force -ErrorAction Stop
        }

        $scOutput = & sc.exe delete $name 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Result -Type 'Service' -Status 'REMOVED' -Path $name -Detail $Service.DisplayName
            $Stats.Value.RemovedServices++
        }
        else {
            Write-Result -Type 'Service' -Status 'FAILED' -Path $name -Detail ("sc delete exit {0}: {1}" -f $LASTEXITCODE, ($scOutput -join ' '))
            $Stats.Value.FailedServices++
        }
    }
    catch {
        Write-Result -Type 'Service' -Status 'FAILED' -Path $name -Detail $_.Exception.Message
        $Stats.Value.FailedServices++
    }
}

function Invoke-ScheduledTaskAction {
    param(
        [object]$Task,
        [ref]$Stats
    )

    $path = "$($Task.TaskPath)$($Task.TaskName)"

    if (-not $Delete) {
        Write-Result -Type 'ScheduledTask' -Status 'WOULD REMOVE' -Path $path
        $Stats.Value.WouldRemoveTasks++
        return
    }

    try {
        Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false -ErrorAction Stop
        Write-Result -Type 'ScheduledTask' -Status 'REMOVED' -Path $path
        $Stats.Value.RemovedTasks++
    }
    catch {
        Write-Result -Type 'ScheduledTask' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedTasks++
    }
}

function Invoke-FolderAction {
    param(
        [string]$Path,
        [ref]$Stats,
        [switch]$LightProcessStop
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'Folder' -Status 'WOULD REMOVE' -Path $Path
        $Stats.Value.WouldRemoveFolders++
        return
    }

    try {
        if ($LightProcessStop) {
            Stop-RelatedProcesses -NamePatterns @('SARemediation')
        }
        else {
            Stop-RelatedProcesses -NamePatterns @('SupportAssist', 'SARemediation', 'DellSupportAssist')
        }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Result -Type 'Folder' -Status 'REMOVED' -Path $Path
        $Stats.Value.RemovedFolders++
    }
    catch {
        Write-Result -Type 'Folder' -Status 'FAILED' -Path $Path -Detail $_.Exception.Message
        $Stats.Value.FailedFolders++
    }
}

$isAdmin = Test-IsAdministrator
$mode = if ($BackupsOnly) {
    if ($Delete) { 'BACKUPS-ONLY DELETE' } else { 'BACKUPS-ONLY DRY-RUN' }
} elseif ($Delete) {
    'DELETE'
} else {
    'DRY-RUN'
}

Write-Output "=== Dell SARemediation Removal v$ScriptVersion ==="
Write-Output "Mode: $mode"
Write-Output "Running as Administrator: $isAdmin"
Write-Output ''

if (-not $isAdmin) {
    Write-Output 'WARNING: Not running elevated. Service, uninstaller, and folder actions will likely fail. Re-run as Administrator.'
    Write-Output ''
}

if ($BackupsOnly) {
    $backupFolders = @(Get-SaRemediationBackupFolders)
    Write-Output ("SARemediation snapshot backup folders found: {0}" -f $backupFolders.Count)
    Write-Output 'Scope: backup folders only (no service/uninstaller/SupportAssist changes).'
    Write-Output ''

    if ($backupFolders.Count -eq 0) {
        Write-Output 'No SARemediation snapshot Backup folders detected under ProgramData\Dell.'
        return
    }

    $stats = @{
        WouldRemoveFolders = 0
        RemovedFolders     = 0
        FailedFolders      = 0
    }

    foreach ($folder in $backupFolders) {
        Invoke-FolderAction -Path $folder -Stats ([ref]$stats) -LightProcessStop
    }

    Write-Output ''
    Write-Output '=== Summary ==='
    if ($Delete) {
        Write-Output ("Backup folders removed: {0}; failed: {1}" -f $stats.RemovedFolders, $stats.FailedFolders)
    }
    else {
        Write-Output ("Backup folders would remove: {0}" -f $stats.WouldRemoveFolders)
        Write-Output 'No changes made. Re-run with -Delete -BackupsOnly to remove backup folders.'
    }
    return
}

$services = @(Get-RemediationServices)
$uninstallEntries = if ($SkipUninstaller) { @() } else { @(Get-RemediationUninstallEntries) }
$scheduledTasks = @(Get-RemediationScheduledTasks)
$installFolders = @(Get-RemediationInstallFolders)

$supportAssistServices = if ($RemoveSupportAssist) { @(Get-SupportAssistServices) } else { @() }
$supportAssistUninstallEntries = if ($RemoveSupportAssist -and -not $SkipUninstaller) { @(Get-SupportAssistUninstallEntries) } else { @() }
$supportAssistScheduledTasks = if ($RemoveSupportAssist) { @(Get-SupportAssistScheduledTasks) } else { @() }
$supportAssistInstallFolders = if ($RemoveSupportAssist) { @(Get-SupportAssistInstallFolders) } else { @() }
$supportAssistUninstallerPaths = if ($RemoveSupportAssist -and -not $SkipUninstaller) { @(Get-SupportAssistUninstallerPaths) } else { @() }
$supportAssistRegistryKeys = if ($RemoveSupportAssist) { @(Get-SupportAssistPresentRegistryKeys) } else { @() }
$deliveryTasks = if ($BlockReinstall) { @(Get-DellUpdateDeliveryTasks) } else { @() }
$deliveryServices = if ($BlockReinstall) { @(Get-DellDeliveryServices) } else { @() }

Write-Output ("Remediation services found: {0}" -f $services.Count)
Write-Output ("Remediation uninstall entries found: {0}{1}" -f $uninstallEntries.Count, $(if ($SkipUninstaller) { ' (skipped)' } else { '' }))
Write-Output ("Remediation scheduled tasks found: {0}" -f $scheduledTasks.Count)
Write-Output ("Remediation install folders found: {0}" -f $installFolders.Count)
if ($RemoveSupportAssist) {
    Write-Output ("Dell SupportAssist services found: {0}" -f $supportAssistServices.Count)
    Write-Output ("Dell SupportAssist uninstall entries found: {0}" -f $supportAssistUninstallEntries.Count)
    Write-Output ("Dell SupportAssist scheduled tasks found: {0}" -f $supportAssistScheduledTasks.Count)
    Write-Output ("Dell SupportAssist install folders found: {0}" -f $supportAssistInstallFolders.Count)
    Write-Output ("Dell SupportAssist leftover registry keys found: {0}" -f $supportAssistRegistryKeys.Count)
}
if ($BlockReinstall) {
    Write-Output ("Dell update delivery tasks found: {0}" -f $deliveryTasks.Count)
    Write-Output ("Dell delivery services found: {0}" -f $deliveryServices.Count)
    if ($Delete) {
        Write-Output 'BlockReinstall: -RemoveSupportAssist is enabled automatically with -Delete.'
    }
}
Write-Output ''

$nothingFound = $services.Count -eq 0 -and $uninstallEntries.Count -eq 0 -and $scheduledTasks.Count -eq 0 `
    -and $installFolders.Count -eq 0 -and $supportAssistServices.Count -eq 0 `
    -and $supportAssistUninstallEntries.Count -eq 0 -and $supportAssistScheduledTasks.Count -eq 0 `
    -and $supportAssistInstallFolders.Count -eq 0 -and $supportAssistUninstallerPaths.Count -eq 0 `
    -and $supportAssistRegistryKeys.Count -eq 0 -and -not $BlockReinstall

if ($nothingFound) {
    Write-Output 'No Dell SARemediation or SupportAssist Remediation components detected on this system.'
    return
}

$stats = @{
    WouldRunUninstalls        = 0
    RanUninstalls             = 0
    FailedUninstalls          = 0
    WouldRemoveServices       = 0
    RemovedServices           = 0
    FailedServices            = 0
    WouldRemoveTasks          = 0
    RemovedTasks              = 0
    FailedTasks               = 0
    WouldRemoveFolders        = 0
    RemovedFolders            = 0
    FailedFolders             = 0
    WouldRemoveRegistryKeys   = 0
    RemovedRegistryKeys       = 0
    FailedRegistryKeys        = 0
    WouldDisableTasks         = 0
    DisabledTasks             = 0
    WouldDisableServices      = 0
    DisabledServices          = 0
}

foreach ($entry in $uninstallEntries) {
    Invoke-UninstallEntryAction -Entry $entry -Stats ([ref]$stats)
}

foreach ($service in $services) {
    Invoke-ServiceAction -Service $service -Stats ([ref]$stats)
}

foreach ($task in $scheduledTasks) {
    Invoke-ScheduledTaskAction -Task $task -Stats ([ref]$stats)
}

foreach ($folder in $installFolders) {
    Invoke-FolderAction -Path $folder -Stats ([ref]$stats)
}

if ($RemoveSupportAssist) {
    foreach ($entry in $supportAssistUninstallEntries) {
        Invoke-UninstallEntryAction -Entry $entry -ResultType 'SupportAssist-Uninstaller' -Stats ([ref]$stats)
    }

    if ($supportAssistUninstallEntries.Count -eq 0) {
        foreach ($exePath in $supportAssistUninstallerPaths) {
            Invoke-SupportAssistUninstallerAction -ExePath $exePath -Stats ([ref]$stats)
        }
    }

    foreach ($service in $supportAssistServices) {
        Invoke-ServiceAction -Service $service -Stats ([ref]$stats)
    }

    foreach ($task in $supportAssistScheduledTasks) {
        Invoke-ScheduledTaskAction -Task $task -Stats ([ref]$stats)
    }

    foreach ($folder in $supportAssistInstallFolders) {
        Invoke-FolderAction -Path $folder -Stats ([ref]$stats)
    }

    foreach ($key in $supportAssistRegistryKeys) {
        Invoke-RegistryKeyAction -Path $key -Stats ([ref]$stats)
    }
}

if ($BlockReinstall) {
    foreach ($task in $deliveryTasks) {
        Invoke-ScheduledTaskDisableAction -Task $task -Stats ([ref]$stats)
    }

    foreach ($service in $deliveryServices) {
        Invoke-ServiceDisableAction -Service $service -Stats ([ref]$stats)
    }
}

Write-Output ''
Write-Output '=== Summary ==='
if ($Delete) {
    Write-Output ("Uninstallers run: {0}; failed: {1}" -f $stats.RanUninstalls, $stats.FailedUninstalls)
    Write-Output ("Services removed: {0}; failed: {1}" -f $stats.RemovedServices, $stats.FailedServices)
    Write-Output ("Scheduled tasks removed: {0}; failed: {1}" -f $stats.RemovedTasks, $stats.FailedTasks)
    Write-Output ("Folders removed: {0}; failed: {1}" -f $stats.RemovedFolders, $stats.FailedFolders)
    if ($RemoveSupportAssist) {
        Write-Output ("Dell SupportAssist registry keys removed: {0}; failed: {1}" -f $stats.RemovedRegistryKeys, $stats.FailedRegistryKeys)
    }
    if ($BlockReinstall) {
        Write-Output ("Update delivery tasks disabled: {0}; failed: {1}" -f $stats.DisabledTasks, $stats.FailedTasks)
        Write-Output ("Delivery services disabled: {0}; failed: {1}" -f $stats.DisabledServices, $stats.FailedServices)
    }
}
else {
    Write-Output ("Uninstallers would run: {0}" -f $stats.WouldRunUninstalls)
    Write-Output ("Services would remove: {0}" -f $stats.WouldRemoveServices)
    Write-Output ("Scheduled tasks would remove: {0}" -f $stats.WouldRemoveTasks)
    Write-Output ("Folders would remove: {0}" -f $stats.WouldRemoveFolders)
    if ($RemoveSupportAssist) {
        Write-Output ("Dell SupportAssist registry keys would remove: {0}" -f $stats.WouldRemoveRegistryKeys)
    }
    if ($BlockReinstall) {
        Write-Output ("Update delivery tasks would disable: {0}" -f $stats.WouldDisableTasks)
        Write-Output ("Delivery services would disable: {0}" -f $stats.WouldDisableServices)
    }
    Write-Output 'No changes made. Re-run with -Delete to remove matched items.'
}
