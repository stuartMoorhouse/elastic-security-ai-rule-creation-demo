$ErrorActionPreference = "Stop"

# Create the jsmith local account used in the Okta credential stuffing demo.
#
# A startup scheduled task (EntityStoreSeed) runs as SYSTEM and calls LogonUser
# four times with logon type 2 (interactive), emitting Windows Security event
# 4624 for each call. SYSTEM holds SE_TCB_NAME, which is required for type-2
# logons. The task waits for the Elastic Agent to be running before generating
# events, ensuring the System integration is already collecting the Security log.
#
# The entity store transform reads these 4624 events from logs-system.security-*
# and builds a user-host relationship for jsmith — crossing the COUNT >= 4
# accesses_frequently threshold — so the Workflow can look up the correct
# endpoint without a hardcoded agent ID.

$demoPassword = ConvertTo-SecureString "JSmith@Demo2024!" -AsPlainText -Force

if (-not (Get-LocalUser -Name "jsmith" -ErrorAction SilentlyContinue)) {
    New-LocalUser `
        -Name                "jsmith" `
        -Password            $demoPassword `
        -FullName            "John Smith" `
        -Description         "Demo user — Okta credential stuffing scenario" `
        -PasswordNeverExpires
    Add-LocalGroupMember -Group "Users" -Member "jsmith"
    Write-Output "Created local account 'jsmith'."
} else {
    Write-Output "Local account 'jsmith' already exists — skipping creation."
}

# --- EntityStoreSeed scheduled task ------------------------------------------
# Runs as SYSTEM at startup (and immediately on first provision). Waits for the
# Elastic Agent service to reach Running state, waits an additional 90 s for the
# System integration policy to propagate, then calls LogonUser four times.
# A sentinel file prevents repeat runs across reboots once seeding is complete.

$logonScript = @'
$log = "C:\Windows\Temp\entity-store-seed.log"
function Write-Log { param($m); "$([datetime]::UtcNow.ToString('u'))  $m" | Out-File -Append -Encoding utf8 $log }

$sentinel = "C:\Windows\Temp\entity-store-seed.done"
if (Test-Path $sentinel) { Write-Log "Sentinel present — already seeded, exiting."; exit 0 }

Write-Log "EntityStoreSeed: waiting for Elastic Agent service..."
$deadline = (Get-Date).AddMinutes(15)
$agentRunning = $false
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "elastic-agent" -ErrorAction SilentlyContinue }
    if ($svc -and $svc.Status -eq "Running") { $agentRunning = $true; break }
    Start-Sleep -Seconds 10
}
if (-not $agentRunning) {
    Write-Log "ERROR: Elastic Agent never reached Running state within 15 min."
    exit 1
}
Write-Log "Elastic Agent is running. Waiting 90 s for System integration policy to propagate..."
Start-Sleep -Seconds 90

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string u, string d, string p, int t, int prov, out IntPtr tok);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@

Write-Log "Generating 4 interactive logon events for jsmith (type 2 / LOGON_INTERACTIVE)..."
$allOk = $true
for ($i = 1; $i -le 4; $i++) {
    $tok = [IntPtr]::Zero
    if ([WinLogon]::LogonUser("jsmith", ".", "JSmith@Demo2024!", 2, 0, [ref]$tok)) {
        [WinLogon]::CloseHandle($tok)
        Write-Log "Logon $i succeeded — Windows Security event 4624 written."
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "Logon $i FAILED (Win32 error $err)."
        $allOk = $false
    }
    Start-Sleep -Seconds 1
}

if ($allOk) {
    New-Item -Path $sentinel -ItemType File -Force | Out-Null
    Write-Log "All 4 logon events generated. Sentinel written — task will not re-run."
} else {
    Write-Log "One or more logon calls failed — sentinel NOT written; will retry on next startup."
}
'@

$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($logonScript))
$action   = New-ScheduledTaskAction `
    -Execute  "powershell.exe" `
    -Argument "-NonInteractive -NoProfile -EncodedCommand $encoded"
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -MultipleInstances  IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

if (Get-ScheduledTask -TaskName "EntityStoreSeed" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "EntityStoreSeed" -Confirm:$false
}
Register-ScheduledTask `
    -TaskName  "EntityStoreSeed" `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal | Out-Null
Write-Output "Registered EntityStoreSeed scheduled task (SYSTEM, at-startup)."

# Trigger immediately — the VM is already up so the startup trigger won't fire
# until next reboot, but we want the seeding to happen during this provision.
Start-ScheduledTask -TaskName "EntityStoreSeed"
Write-Output "EntityStoreSeed task started — will generate logon events once Elastic Agent is running."
