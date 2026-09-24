Param(
  [string]$ElasticVersion,
  [string]$FleetUrl,
  [string]$EnrollmentToken
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$dest = "C:\ElasticAgent"

$svc = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Output "Elastic Agent already running - skipping install."
} else {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $zip = "$dest\elastic-agent.zip"
    $uri = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ElasticVersion-windows-x86_64.zip"

    Write-Output "Downloading Elastic Agent $ElasticVersion from $uri ..."
    $response = Invoke-WebRequest -Uri $uri -OutFile $zip -UseBasicParsing -PassThru
    if ($response.StatusCode -ne 200) {
        Write-Error "Download failed with HTTP $($response.StatusCode): $uri"
        exit 1
    }
    $zipSize = (Get-Item $zip).Length
    if ($zipSize -lt 10MB) {
        Write-Error "Downloaded file is suspiciously small ($zipSize bytes) - likely a corrupt or partial download: $zip"
        exit 1
    }
    Write-Output "Download complete ($zipSize bytes). Expanding archive..."
    Expand-Archive -Path $zip -DestinationPath $dest -Force

    $agentDir = (Get-ChildItem -Path $dest -Directory -Filter "elastic-agent-*" | Select-Object -First 1).FullName
    Set-Location $agentDir

    Write-Output "Installing Elastic Agent (Fleet URL: $FleetUrl) ..."
    & .\elastic-agent.exe install `
        --url="$FleetUrl" `
        --enrollment-token="$EnrollmentToken" `
        --non-interactive `
        --force
    $installExit = $LASTEXITCODE

    if ($installExit -ne 0) {
        # Give the service a few seconds to start - the CLI can return non-zero
        # even when enrollment succeeds (e.g. after --force reinstall).
        Start-Sleep -Seconds 10
        $svc = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Output "Elastic Agent service is Running (install exited $installExit - treating as success)."
        } else {
            Write-Error "elastic-agent install exited $installExit and service is not Running. Enrollment failed."
            exit 1
        }
    } else {
        Write-Output "Elastic Agent installed and enrolled successfully."
    }
}
