# Demo commands

## Reset before each take

```bash
./scripts/prepare-and-reset-demo.sh
```

## AI rule creation prompt

In Kibana: Security → Rules → Create new rule → **AI rule creation**.

> Within a 24-hour window, for each Okta actor and client IP: count sign-on failures with reason INVALID_CREDENTIALS, failed MFA challenges including push denials, successful sign-ons, and successful post-compromise actions where the actor is the one performing the action. Post-compromise means group membership add, application assignment, privilege grant, MFA factor enrolment, a change to a policy or policy rule (a modification, not an evaluation), or a profile update — explicitly excluding password changes. Require the post-compromise action to occur after the first successful sign-on.
> Before writing any field names, call the Elasticsearch GET API on logs-okta.system-default/_mapping and use only field paths that exist in the response. Do not use any field name that is not present in the mapping.

## Connect to the VM

```bash
VM_IP=$(jq -r '.vm_public_ip' shared/env.json)
VM_USER=$(jq -r '.vm_admin_username' shared/env.json)
VM_PASS=$(jq -r '.vm_admin_password' shared/env.json)

sshpass -p "$VM_PASS" ssh "$VM_USER@$VM_IP" powershell
```

## Verify remediation on the VM

```powershell
# Firewall rule — shows the attacker IP that was blocked
Get-NetFirewallRule -DisplayName "Elastic-OktaCompromise-Block-*" | ForEach-Object { $_ | Get-NetFirewallAddressFilter | Select-Object @{n='Rule';e={$_.InstanceID}}, RemoteAddress } | Format-Table -AutoSize

# jsmith account — should show Enabled: False
Get-LocalUser -Name jsmith | Select-Object Name, Enabled
```
