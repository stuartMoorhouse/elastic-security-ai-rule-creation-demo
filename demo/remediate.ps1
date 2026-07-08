<#
    remediate.ps1

    Remediation script for the BENIGN simulate-lolbin-chain.ps1 telemetry demo
    (authorized Elastic Security webinar demo). Intended to be uploaded to the
    Elastic Defend Script library and executed via a "runscript" response action
    triggered from an alert.

    What it does:
      1. Kills any running process whose command line references the specific
         throwaway demo marker/path created by simulate-lolbin-chain.ps1 (never
         a broad kill of powershell.exe/mshta.exe system-wide).
      2. Removes the specific HKCU Run persistence value created by the demo
         (not the whole Run key).
      3. Collects (prints) the simulation log so runscript output shows exactly
         what the simulation did.
      4. Deletes the throwaway temp files/folder created by the simulation.
      5. Prints a clear final summary.

    Safe to run even if the simulation was never run on this host: every step
    checks for existence first and reports "nothing to clean up" rather than
    erroring.
#>

[CmdletBinding()]
param()

$Marker             = "elastic-lolbin-demo"
$DemoRoot           = Join-Path $env:TEMP $Marker
$LogFile            = Join-Path $env:TEMP "lolbin-sim-log.txt"
$ManifestPath       = Join-Path $env:TEMP "lolbin-sim-manifest.json"
$RegKeyPathPsDrive  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$DefaultRegValueName = "ElasticLolbinDemo"

Write-Output "=== remediate.ps1 starting ==="

# --------------------------------------------------------------------------
# Load the manifest (if present) for the precise reg value name used by this
# run. Falls back to the well-known default if the manifest is missing or
# unreadable, so remediation still works even if the manifest was lost.
# --------------------------------------------------------------------------
$RegValueName = $DefaultRegValueName
if (Test-Path $ManifestPath) {
    try {
        $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
        if ($manifest.RegValueName) {
            $RegValueName = $manifest.RegValueName
        }
        Write-Output "Loaded manifest: $ManifestPath"
    } catch {
        Write-Output "WARNING: manifest present at $ManifestPath but could not be parsed ($($_.Exception.Message)); using default reg value name '$DefaultRegValueName'."
    }
} else {
    Write-Output "No manifest found at $ManifestPath; using default reg value name '$DefaultRegValueName'."
}

$processesKilled = @()
$registryRemoved = $false
$pathsDeleted    = @()
$logCollected    = $false

# --------------------------------------------------------------------------
# 1. Kill matching processes.
# Match only on command lines that reference the specific demo marker path
# (e.g. "...\elastic-lolbin-demo\payload.ps1"), so unrelated powershell.exe /
# mshta.exe / wscript.exe processes on the host are never touched.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 1: Terminating simulated LOLBin chain processes =="
$matchingProcs = @()
try {
    $matchingProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$Marker*" }
} catch {
    Write-Output "WARNING: could not query running processes: $($_.Exception.Message)"
}

if ($matchingProcs.Count -gt 0) {
    foreach ($proc in $matchingProcs) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            $processesKilled += "$($proc.Name) (PID $($proc.ProcessId))"
            Write-Output "Killed $($proc.Name) (PID $($proc.ProcessId)) - CommandLine: $($proc.CommandLine)"
        } catch {
            Write-Output "WARNING: failed to stop PID $($proc.ProcessId) ($($proc.Name)): $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "No running processes matched marker '$Marker' (nothing to kill)."
}

# --------------------------------------------------------------------------
# 2. Remove the specific persistence registry value (not the whole Run key).
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 2: Removing persistence registry value =="
if (Test-Path $RegKeyPathPsDrive) {
    $existingValue = Get-ItemProperty -Path $RegKeyPathPsDrive -Name $RegValueName -ErrorAction SilentlyContinue
    if ($null -ne $existingValue) {
        try {
            Remove-ItemProperty -Path $RegKeyPathPsDrive -Name $RegValueName -Force -ErrorAction Stop
            $registryRemoved = $true
            Write-Output "Removed registry value '$RegValueName' from $RegKeyPathPsDrive."
        } catch {
            Write-Output "WARNING: failed to remove registry value '$RegValueName': $($_.Exception.Message)"
        }
    } else {
        Write-Output "Registry value '$RegValueName' not present under $RegKeyPathPsDrive (nothing to remove)."
    }
} else {
    Write-Output "Registry key $RegKeyPathPsDrive does not exist (nothing to remove)."
}

# --------------------------------------------------------------------------
# 3. Collect (print) the simulation log so runscript output captures it.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 3: Collecting simulation log =="
if (Test-Path $LogFile) {
    Write-Output "----- $LogFile -----"
    Get-Content -Path $LogFile | ForEach-Object { Write-Output $_ }
    Write-Output "----- end of log -----"
    $logCollected = $true
} else {
    Write-Output "No log file found at $LogFile (simulation may not have run on this host)."
}

# --------------------------------------------------------------------------
# 4. Delete throwaway temp files created by the simulation.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 4: Deleting throwaway temp artifacts =="
$pathsToDelete = @($DemoRoot, $LogFile, $ManifestPath)
foreach ($path in $pathsToDelete) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            $pathsDeleted += $path
            Write-Output "Deleted $path"
        } catch {
            Write-Output "WARNING: failed to delete $path: $($_.Exception.Message)"
        }
    } else {
        Write-Output "$path not present (nothing to delete)."
    }
}

# --------------------------------------------------------------------------
# 5. Final summary.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "=== Remediation Summary ==="
Write-Output ("Processes killed:              " + $(if ($processesKilled.Count -gt 0) { $processesKilled -join ", " } else { "none" }))
Write-Output ("Registry persistence removed:  " + $registryRemoved)
Write-Output ("Files/folders deleted:         " + $(if ($pathsDeleted.Count -gt 0) { $pathsDeleted -join ", " } else { "none" }))
Write-Output ("Log collected:                 " + $logCollected)

if ($processesKilled.Count -eq 0 -and -not $registryRemoved -and $pathsDeleted.Count -eq 0 -and -not $logCollected) {
    Write-Output ""
    Write-Output "Nothing to clean up - the simulation does not appear to have run on this host."
}

Write-Output "=== remediate.ps1 complete ==="
