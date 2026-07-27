$ErrorActionPreference = "Stop"

# Create the jsmith local account used in the Okta credential stuffing demo.
#
# Elastic Defend captures the process event below (user.name=jsmith, host.id=<vm>)
# and writes it to the entity store. The entity store then links this endpoint
# record to the Okta user entity for jsmith@example.com, giving the Workflow a
# way to look up which host to remediate on without hardcoding an agent ID.

$demoPassword = ConvertTo-SecureString "JSmith@Demo2024!" -AsPlainText -Force

if (-not (Get-LocalUser -Name "jsmith" -ErrorAction SilentlyContinue)) {
    New-LocalUser `
        -Name        "jsmith" `
        -Password    $demoPassword `
        -FullName    "John Smith" `
        -Description "Demo user — Okta credential stuffing scenario" `
        -PasswordNeverExpires
    Add-LocalGroupMember -Group "Users" -Member "jsmith"
    Write-Output "Created local account 'jsmith'."
} else {
    Write-Output "Local account 'jsmith' already exists — skipping creation."
}

# Spawn a short-lived process as jsmith so Elastic Defend emits a process event
# with user.name=jsmith and host.id, which the entity store picks up to build
# the user-host association needed by the Workflow.
$jsmithCred = New-Object PSCredential "jsmith", $demoPassword
Start-Process -FilePath "cmd.exe" `
              -ArgumentList "/c", "echo entity-store-seed" `
              -Credential $jsmithCred `
              -Wait `
              -NoNewWindow
Write-Output "Simulated jsmith session — entity store will associate jsmith with this host."
