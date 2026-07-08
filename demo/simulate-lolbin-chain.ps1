<#
    simulate-lolbin-chain.ps1

    BENIGN telemetry-generation script for an authorized Elastic Security webinar
    demo. It reproduces the process-tree SHAPE of the Jan 2026 ClickFix / LOLBin /
    Remcos-NetSupport RAT attack chain using ONLY signed, built-in Windows binaries
    that already ship on Windows Server 2022. It downloads and executes nothing
    malicious: the only network call is a single benign GET to a public,
    unauthenticated "what is my IP" endpoint, and every artifact created lives
    under $env:TEMP.

    Process chain reproduced (parent -> child):

        forfiles.exe -> cmd.exe -> mshta.exe -> powershell.exe -> curl.exe
                                                                -> wscript.exe
                                                                -> reg.exe

    MITRE ATT&CK techniques mapped (for detection-engineering reference):

        T1218.005  System Binary Proxy Execution: Mshta
                   -> forfiles.exe launches mshta.exe (Run-dialog-style LOLBin proxy)
        T1059.003  Command and Scripting Interpreter: Windows Command Shell
                   -> forfiles.exe's /c handler always shells out via cmd.exe
        T1059.001  Command and Scripting Interpreter: PowerShell
                   -> mshta.exe's inline script launches powershell.exe
        T1547      Boot or Logon Autostart Execution (T1547.001 Registry Run Keys)
                   -> reg.exe adds a benign HKCU Run value; wscript.exe executes a
                      throwaway .vbs "beacon" script to round out persistence telemetry

    Safe to re-run: every artifact is created under a single throwaway subfolder of
    $env:TEMP and is overwritten/recreated on each run rather than causing failures.

    This script must only ever be run in the isolated demo VM, by the presenter,
    for the purpose of generating telemetry for Elastic Defend / detection rules.
#>

[CmdletBinding()]
param()

# --------------------------------------------------------------------------
# Config / shared marker
# --------------------------------------------------------------------------
# NOTE: "$Marker" is intentionally the literal folder name used everywhere below.
# remediate.ps1 hardcodes the same marker string to precisely identify and clean
# up only the artifacts/processes created by this script.
$Marker         = "elastic-lolbin-demo"
$DemoRoot       = Join-Path $env:TEMP $Marker
$LogFile        = Join-Path $env:TEMP "lolbin-sim-log.txt"
$ManifestPath   = Join-Path $env:TEMP "lolbin-sim-manifest.json"

$PayloadPath    = Join-Path $DemoRoot "payload.ps1"
$HtaPath        = Join-Path $DemoRoot "launcher.hta"
$VbsPath        = Join-Path $DemoRoot "persist.vbs"
$IpOutputPath   = Join-Path $DemoRoot "ip.txt"
$WscriptMarker  = Join-Path $DemoRoot "wscript-marker.txt"
$CompleteMarker = Join-Path $DemoRoot "payload-complete.marker"

$RegKeyPathNative = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
$RegValueName     = "ElasticLolbinDemo"

# --------------------------------------------------------------------------
# Logging helper (shared file also written to by payload.ps1)
# --------------------------------------------------------------------------
function Write-DemoLog {
    param([Parameter(Mandatory)][string]$Message)
    $line = "$(Get-Date -Format o) | simulate-lolbin-chain.ps1 | $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

New-Item -ItemType Directory -Path $DemoRoot -Force | Out-Null
Add-Content -Path $LogFile -Value "==================================================================="
Write-DemoLog "Run starting. Demo root: $DemoRoot"
Write-DemoLog "This is a BENIGN reproduction of the Jan 2026 ClickFix/LOLBin chain for an authorized Elastic Security webinar demo (MITRE T1218.005, T1059.003, T1059.001, T1547)."

# --------------------------------------------------------------------------
# Resolve a short (8.3, space-free) path to $env:TEMP.
#
# Why: the forfiles /c value below is parsed as a raw cmd.exe command line.
# If the interactive user's profile path happens to contain a space (e.g. a
# username with a space in it), an unquoted "mshta.exe <path>" token would be
# split into multiple arguments by cmd.exe. Using the 8.3 short path for the
# %TEMP% segment sidesteps that entire class of quoting problems without
# having to nest quotes inside the forfiles -> cmd -> mshta command chain.
# Everything else in this script uses the normal long path, since it is only
# ever consumed by PowerShell/VBScript, which quote correctly on their own.
# --------------------------------------------------------------------------
$fso = New-Object -ComObject Scripting.FileSystemObject
$ShortTempRoot   = $fso.GetFolder($env:TEMP).ShortPath
$ShortLauncher   = Join-Path (Join-Path $ShortTempRoot $Marker) "launcher.hta"

# --------------------------------------------------------------------------
# Write the mshta launcher (.hta). Its only job is to shell out to
# powershell.exe, mirroring the real ClickFix technique's abuse of
# mshta.exe as a Run-dialog LOLBin proxy (T1218.005).
# --------------------------------------------------------------------------
$htaTemplate = @'
<html>
<head>
<title>elastic-lolbin-demo</title>
<script language="VBScript">
Sub RunPayload()
    Dim shell
    Set shell = CreateObject("WScript.Shell")
    ' Benign demo artifact only - launches the local, self-authored payload
    ' script below. Nothing is downloaded or executed here beyond what this
    ' demo itself created under %TEMP%.
    shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{{PAYLOAD_PATH}}""", 0, False
    window.close
End Sub
RunPayload
</script>
</head>
<body></body>
</html>
'@
$htaContent = $htaTemplate.Replace('{{PAYLOAD_PATH}}', $PayloadPath)
Set-Content -Path $HtaPath -Value $htaContent -Force -Encoding ASCII
Write-DemoLog "Wrote mshta launcher: $HtaPath"

# --------------------------------------------------------------------------
# Write the "payload" powershell script. This is the process that mshta.exe
# spawns; it in turn spawns curl.exe (T1059.001 child) and wscript.exe /
# reg.exe (T1547 persistence telemetry). All benign, all under $DemoRoot.
# --------------------------------------------------------------------------
$payloadTemplate = @'
$Marker         = "{{MARKER}}"
$LogFile        = "{{LOG_FILE}}"
$IpOutputPath   = "{{IP_OUTPUT}}"
$VbsPath        = "{{VBS_PATH}}"
$WscriptMarker  = "{{WSCRIPT_MARKER}}"
$RegKeyPathNative = "{{REG_KEY_NATIVE}}"
$RegValueName   = "{{REG_VALUE_NAME}}"
$CompleteMarker = "{{COMPLETE_MARKER}}"

function Write-DemoLog {
    param([string]$Message)
    $line = "$(Get-Date -Format o) | payload.ps1 | $Message"
    Add-Content -Path $LogFile -Value $line
}

Write-DemoLog "Payload started (PID $PID), spawned by mshta.exe. Benign demo stage (T1218.005 -> T1059.001)."

# --- curl.exe stage: fetch a harmless, public, plaintext, unauthenticated resource ---
Write-DemoLog "Invoking curl.exe to fetch a harmless external resource (T1059.001 child process telemetry)."
& curl.exe -s -m 10 -o $IpOutputPath "https://api.ipify.org"
if ($LASTEXITCODE -eq 0 -and (Test-Path $IpOutputPath)) {
    Write-DemoLog "curl.exe succeeded; response saved to $IpOutputPath."
} else {
    Write-DemoLog "WARNING: curl.exe exited with code $LASTEXITCODE (network may be unavailable). Continuing demo chain regardless, since process-spawn telemetry is the goal."
}

# --- wscript.exe stage: benign throwaway .vbs, simulates a persistence "beacon" ---
Write-DemoLog "Writing throwaway persistence script for wscript.exe (T1547 telemetry)."
$vbsContent = @"
'' Elastic security demo - benign, throwaway script. Safe to delete.
'' Created by simulate-lolbin-chain.ps1 for an authorized webinar demo only.
Dim fso, f
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.OpenTextFile("$WscriptMarker", 2, True)
f.WriteLine "Elastic demo persistence marker executed at " & Now
f.Close
"@
Set-Content -Path $VbsPath -Value $vbsContent -Force
& wscript.exe $VbsPath
Write-DemoLog "Executed wscript.exe against $VbsPath."

# --- reg.exe stage: benign HKCU Run value pointing at the throwaway .vbs (T1547.001) ---
Write-DemoLog "Adding HKCU Run persistence value '$RegValueName' (T1547.001 telemetry; never actually persists anything harmful)."
& reg.exe add $RegKeyPathNative /v $RegValueName /t REG_SZ /d "wscript.exe `"$VbsPath`"" /f | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-DemoLog "reg.exe added Run value successfully."
} else {
    Write-DemoLog "WARNING: reg.exe exited with code $LASTEXITCODE."
}

Write-DemoLog "Payload complete."
Set-Content -Path $CompleteMarker -Value "done" -Force
'@

$payloadContent = $payloadTemplate.
    Replace('{{MARKER}}', $Marker).
    Replace('{{LOG_FILE}}', $LogFile).
    Replace('{{IP_OUTPUT}}', $IpOutputPath).
    Replace('{{VBS_PATH}}', $VbsPath).
    Replace('{{WSCRIPT_MARKER}}', $WscriptMarker).
    Replace('{{REG_KEY_NATIVE}}', $RegKeyPathNative).
    Replace('{{REG_VALUE_NAME}}', $RegValueName).
    Replace('{{COMPLETE_MARKER}}', $CompleteMarker)
Set-Content -Path $PayloadPath -Value $payloadContent -Force
Write-DemoLog "Wrote payload script: $PayloadPath"

# Clear any stale completion marker from a previous run so we can reliably
# detect completion of *this* run.
Remove-Item -Path $CompleteMarker -Force -ErrorAction SilentlyContinue

# --------------------------------------------------------------------------
# Write a manifest describing exactly what this run created, so
# remediate.ps1 can clean up precisely (and the presenter can inspect it).
# --------------------------------------------------------------------------
$manifest = [ordered]@{
    Marker            = $Marker
    CreatedAtUtc      = (Get-Date).ToUniversalTime().ToString("o")
    DemoRoot          = $DemoRoot
    HtaPath           = $HtaPath
    PayloadPath       = $PayloadPath
    VbsPath           = $VbsPath
    IpOutputPath      = $IpOutputPath
    WscriptMarkerPath = $WscriptMarker
    LogFile           = $LogFile
    RegKeyPathNative  = $RegKeyPathNative
    RegValueName      = $RegValueName
}
$manifest | ConvertTo-Json | Set-Content -Path $ManifestPath -Force
Write-DemoLog "Wrote manifest: $ManifestPath"

# --------------------------------------------------------------------------
# Kick off the chain: forfiles.exe -> cmd.exe -> mshta.exe
#
# forfiles' /c handler always executes its command via cmd.exe, which is why
# the real-world ClickFix chain (and this reproduction) shows cmd.exe as the
# intermediate hop between forfiles.exe and mshta.exe.
# --------------------------------------------------------------------------
Write-DemoLog "Invoking forfiles.exe -> cmd.exe -> mshta.exe (T1218.005 LOLBin proxy chain)."
$forfilesArgs = @(
    "/p", "$env:SystemRoot\System32",
    "/m", "notepad.exe",
    "/c", "mshta.exe $ShortLauncher"
)
& forfiles.exe @forfilesArgs
if ($LASTEXITCODE -ne 0) {
    Write-DemoLog "WARNING: forfiles.exe exited with code $LASTEXITCODE."
} else {
    Write-DemoLog "forfiles.exe/mshta.exe stage returned; powershell payload continues asynchronously."
}

# --------------------------------------------------------------------------
# mshta launches powershell.exe asynchronously (fire-and-forget, matching the
# real technique), so poll briefly for the payload's completion marker.
# --------------------------------------------------------------------------
$timeoutAt = (Get-Date).AddSeconds(30)
while (-not (Test-Path $CompleteMarker) -and (Get-Date) -lt $timeoutAt) {
    Start-Sleep -Milliseconds 500
}
if (Test-Path $CompleteMarker) {
    Write-DemoLog "Full chain completed successfully (forfiles -> mshta -> powershell -> curl.exe/wscript.exe/reg.exe)."
} else {
    Write-DemoLog "WARNING: payload completion marker not seen within 30s. Check $LogFile and Fleet/Defend telemetry manually."
}

Write-DemoLog "Run finished. Log: $LogFile | Manifest: $ManifestPath"
Write-Host ""
Write-Host "Done. Tail of $LogFile :"
Get-Content -Path $LogFile -Tail 15
