<#
    block-spray-source.ps1

    Runscript response action for the password-spraying detection demo
    (authorized Elastic Security webinar demo). Uploaded to the Elastic
    Defend Script library and triggered via a "runscript" response action
    from the alert, parameterised with the alert's source.ip (and,
    optionally, the alert's targeted-username list).

    What it does:
      1. Adds an inbound-block Windows Firewall rule for the offending
         source IP (replaces it if a rule from a previous take already
         exists, so re-runs don't stack duplicate rules).
      2. Optionally disables the targeted local user accounts, if a
         -TargetedUsers list is supplied and those accounts exist locally.
      3. Prints a summary of what was changed.

    Safe to re-run: step 1 replaces rather than duplicates the firewall
    rule, and step 2 skips accounts that don't exist or are already
    disabled.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceIp,

    [string]$TargetedUsers = ""
)

$RuleName = "Elastic-PasswordSpray-Block-$SourceIp"

Write-Output "=== block-spray-source.ps1 starting ==="
Write-Output "Source IP: $SourceIp"

# --------------------------------------------------------------------------
# 1. Block the source IP at the Windows Firewall.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 1: Blocking source IP at the Windows Firewall =="
$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "Rule '$RuleName' already exists from a previous take; removing before recreating."
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
}

$firewallBlocked = $false
try {
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block `
        -RemoteAddress $SourceIp -Protocol Any -ErrorAction Stop | Out-Null
    $firewallBlocked = $true
    Write-Output "Created inbound block rule '$RuleName' for $SourceIp."
} catch {
    Write-Output "WARNING: failed to create firewall rule: $($_.Exception.Message)"
}

# --------------------------------------------------------------------------
# 2. Optionally disable the targeted local accounts.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 2: Disabling targeted local accounts (if supplied) =="
$disabled = @()
if ([string]::IsNullOrWhiteSpace($TargetedUsers)) {
    Write-Output "No -TargetedUsers supplied; skipping account lockout."
} else {
    $users = $TargetedUsers -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($u in $users) {
        $account = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
        if (-not $account) {
            Write-Output "Local account '$u' not found on this host; skipping."
            continue
        }
        if ($account.Enabled) {
            try {
                Disable-LocalUser -Name $u -ErrorAction Stop
                $disabled += $u
                Write-Output "Disabled local account '$u'."
            } catch {
                Write-Output "WARNING: failed to disable '$u': $($_.Exception.Message)"
            }
        } else {
            Write-Output "Local account '$u' already disabled."
        }
    }
}

# --------------------------------------------------------------------------
# 3. Summary.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "=== Response Summary ==="
Write-Output ("Firewall rule:      " + $(if ($firewallBlocked) { "$RuleName (blocking $SourceIp)" } else { "FAILED to create" }))
Write-Output ("Accounts disabled:  " + $(if ($disabled.Count -gt 0) { $disabled -join ", " } else { "none" }))
Write-Output "=== block-spray-source.ps1 complete ==="
