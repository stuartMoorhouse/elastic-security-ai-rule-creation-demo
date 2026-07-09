$ErrorActionPreference = "Stop"

Add-WindowsCapability -Online -Name OpenSSH.Server

Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

# Add-WindowsCapability creates this rule automatically on most builds, but
# ensure it exists (and is enabled) rather than assume it.
if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
