# Elastic Security 9.5 Webinar Demo

Self-contained demo of automated detection-to-response: a detection rule fires on Okta credential stuffing telemetry, and a Workflow automatically opens a case, runs a remediation script via Runscript, and closes the case — all without human intervention.

## The threat

**Okta credential stuffing and account takeover** — an attacker uses a list of breached credentials to spray multiple Okta accounts, pushes through MFA, and then takes post-compromise actions (privilege escalation, policy changes) once inside. The detection requires the *full four-stage sequence* to be present for the same `user.name` and `source.ip`: failed logins with `INVALID_CREDENTIALS`, MFA failures, a successful login, and at least one post-compromise action. This is what makes it high-fidelity: a user who forgets their password won't match (no MFA failures, no post-compromise), and an attacker stopped at MFA won't match either.

Demo telemetry is synthetic Okta system log events (`logs-okta.system-default`), seeded via `scripts/seed-okta-attack-data.sh`. One attacker IP completes the full chain against `jsmith@example.com` (fires the rule); two other accounts (`bjones`, `alee`) get failed logins only; one benign IP (`mwilson`) has a single failed login then success (forgot password — correctly silent).

MITRE: T1110.004 (Credential Stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| High-fidelity threat detection | **ES\|QL aggregation rule** detecting the full four-stage Okta credential stuffing chain — fires only when all stages are present for the same user and IP |
| Automated response & case management | **Workflows**, launched from an alert, combining a **Runscript** response action + centralized **Script library** (Elastic Defend, GA 9.4) to block the `source.ip` and disable accounts, with **Cases** action steps to triage and document the incident |

## Setup

Everything is handled by `terraform apply` and `scripts/configure.sh`.

### First-time provisioning

```bash
# 1. Fill in credentials
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# edit terraform/terraform.tfvars — Elastic Cloud API key, Azure credentials, my_ip

# 2. Provision
terraform -chdir=terraform init
terraform -chdir=terraform apply
```

`terraform apply` does all of this in order:
- Creates the Elastic Cloud deployment (Elasticsearch + Kibana)
- Provisions the Azure Windows VM, VNet, NSG, public IP
- Installs and enrolls the Elastic Agent on the VM
- Creates the **case-writer** Agent Builder agent (`terraform/agents/case-writer.json`, ID saved to `state/case-writer-agent-id`) and deploys the **Okta Credential Stuffing Response** workflow to Kibana
- Runs `scripts/configure.sh` — writes `shared/env.json`, creates the endpoint response-actions data stream, installs the Okta Fleet integration, waits for the agent to show healthy in Fleet, uploads `scripts/remediate-okta-compromise.ps1` to the Script library (saving its UUID to `state/script-id`), and updates the deployed Workflow with that UUID so the `script_id` input is pre-filled

### After first provisioning (one-time)

```bash
./scripts/configure.sh
```

`configure.sh` creates the detection rule (saving its UUID to `state/rule-id`). It does **not** attach the workflow: attempts to automate this (injecting the rule ID into the workflow trigger) failed because the workflow engine strips the field, so attaching is a manual step. In Kibana, open the rule, add the **Okta Credential Stuffing Response** workflow as a rule action, and use the IDs from `state/workflow-id` and `state/script-id`. The action is preserved across resets.

### Before each demo take (including the first)

```bash
# 1. Reset — clears alerts, cases, Okta telemetry, previous workflow runs, and the endpoint
./scripts/prepare-and-reset-demo.sh

# 2. When ready to fire the rule, seed the attack data
./scripts/seed-okta-attack-data.sh
```

`prepare-and-reset-demo.sh` clears the previous take's state and ensures the detection rule exists but is disabled. The seed script enables it after loading the data, so it never runs against an empty index and the alert appears within seconds. It does **not** seed new data — that is a separate step so you can attach the workflow to the rule in Kibana between reset and trigger if needed (required on first setup). The rule and its workflow action are preserved across resets.

## Connecting to the VM

The VM enrollment script installs OpenSSH Server, so the simplest way to run response actions or inspect state is SSH from your machine — no RDP client needed. (RDP is also open on 3389 from `my_ip` if you want the GUI.)

Connection details are in `shared/env.json` (written by `configure.sh`):

```bash
VM_IP=$(jq -r '.vm_public_ip' shared/env.json)
VM_USER=$(jq -r '.vm_admin_username' shared/env.json)
VM_PASS=$(jq -r '.vm_admin_password' shared/env.json)
```

SSH in with [`sshpass`](https://formulae.brew.sh/formula/sshpass) (`brew install hudochenkov/sshpass/sshpass`) to avoid copy/paste mangling of the password. Pass `powershell` as the remote command so you land in PowerShell directly rather than cmd.exe:

```bash
sshpass -p "$VM_PASS" ssh "$VM_USER@$VM_IP" powershell
```

RDP instead, if preferred:

```bash
open "rdp://full%20address=s:${VM_IP}&username=s:${VM_USER}"   # macOS, Microsoft Remote Desktop app
```

If SSH or RDP hangs on connect, your public IP has likely changed since the NSG rule was last provisioned (it's auto-detected at `apply` time). Re-run `terraform -chdir=terraform apply` — it only updates the NSG rule — then retry.

## Demo steps

### Step 1: Detect

Navigate to Security → Alerts. The rule fires immediately on the seeded data — show the alert for `jsmith@example.com`. Walk the aggregation fields (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) to show why this user/IP triggered and the others did not.

### Step 2: Respond — show the auto-created case

Open Security → Cases. The Workflow fired when the alert was created and ran these automated steps:

1. The **case-writer** Agent Builder agent (an `ai.agent` step) received the alert and, using its Cases tools, did all of the following:
   - Opened the case with a title, description, severity Critical and MITRE tags.
   - Set the status to **in-progress**, signalling that remediation is underway.
   - Attached the triggering alert.
   - Pinned the attacker IP and compromised account as **observables** (IOCs visible in the case header).
   - Added an **AI analysis comment** summarising the four-stage attack chain.
2. Located the enrolled Windows endpoint via Fleet (first online agent).
3. Ran `remediate-okta-compromise.ps1` via Runscript against that endpoint — blocked `source.ip` at the Windows Firewall and disabled the local account matching the compromised Okta username.
4. Added a remediation summary comment.
5. Closed the case.

Walk the case timeline: created → in-progress → observables → AI analysis → remediation → closed.

#### Verifying the Runscript actually ran

**In Kibana:** Security → Endpoints → Response Actions History. Find the `run-script` entry for the Windows VM and expand it — the script prints a `=== Response Summary ===` block naming the firewall rule created and the account disabled.

**On the VM (belt-and-braces):** SSH in and run two read-only commands:

```powershell
# Show the firewall rule and the specific IP it blocks
Get-NetFirewallRule -DisplayName "Elastic-OktaCompromise-Block-*" | ForEach-Object { $_ | Get-NetFirewallAddressFilter | Select-Object @{n='Rule';e={$_.InstanceID}}, RemoteAddress } | Format-Table -AutoSize

# Show the compromised account is disabled
Get-LocalUser -Name jsmith | Select-Object Name, Enabled
```

The first command shows the exact attacker IP embedded in the rule, proving the dynamic value was passed correctly from the alert. A matching IP and `Enabled: False` on the account confirm the script ran end-to-end.

> **If Response Actions History is empty:** check that the Elastic Agent on the Windows VM is showing as **Online** in Fleet (Security → Fleet → Agents). If the agent is offline or unhealthy, the Runscript action queues but cannot execute.

## Optional: building a richer alert queue

For a more compelling "scale" story, seed additional attack scenarios before the demo:

```bash
./scripts/add-attack-scenario.sh   # adds one new attacker IP against jsmith
./scripts/add-attack-scenario.sh   # add another, and so on
```

Each run picks the next attacker IP from a rotation pool; the victim is always `jsmith@example.com`. Using the same victim matters: the remediation script strips the email domain to get the local Windows account name (`jsmith@example.com` → `jsmith`), and `jsmith` is the only demo account that exists on the VM — a different victim email would cause `Disable-LocalUser` to fail. The Workflow locates the endpoint via Fleet and the Runscript fires regardless of victim identity. Each new scenario triggers the detection rule and the Workflow, which remediates and acknowledges the alert automatically.

**What to show in Kibana:** Security → Alerts → change the **Status** filter to **Acknowledged** (or **All**). You'll see a queue of multiple attackers, each already remediated — demonstrating that the automated response runs consistently across every alert, not just the first one.

The original `jsmith@example.com` alert stays **Open** (it was seeded before the Workflow was attached to the rule), giving you a clean before/after contrast: one unprocessed alert vs. a queue of auto-closed ones.

## Cleanup

`terraform destroy`
