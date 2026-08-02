# Elastic Security 9.4 Webinar Demo

Self-contained demo of AI-assisted detection, identity-to-endpoint correlation via the Entity Store, Runscript response, and Workflow-driven case automation, run against a Windows VM enrolled in Elastic Cloud.

## The threat

**Okta credential stuffing and account takeover** — an attacker uses a list of breached credentials to spray multiple Okta accounts, pushes through MFA, and then takes post-compromise actions (privilege escalation, policy changes) once inside. The detection requires the *full four-stage sequence* to be present for the same `user.name` and `source.ip`: failed logins with `INVALID_CREDENTIALS`, MFA failures, a successful login, and at least one post-compromise action. This is what makes it high-fidelity: a user who forgets their password won't match (no MFA failures, no post-compromise), and an attacker stopped at MFA won't match either.

Demo telemetry is synthetic Okta system log events (`logs-okta.system-default`), seeded via `scripts/seed-okta-attack-data.sh`. One attacker IP completes the full chain against `jsmith@example.com` (fires the rule); two other accounts (`bjones`, `alee`) get failed logins only; one benign IP (`mwilson`) has a single failed login then success (forgot password — correctly silent).

MITRE: T1110.004 (Credential Stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| AI-assisted detection engineering | **AI rule creation** in Agent Builder — describe the threat in natural language, generate/refine an ES\|QL aggregation rule |
| Identity-to-endpoint correlation | **Entity Store** — correlates Okta identities to Windows hosts via interactive logon records (Windows Security event 4624), enabling the Workflow to target the exact endpoint rather than guessing |
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
- Deploys the **Okta Credential Stuffing Response** workflow to Kibana
- Runs `scripts/configure.sh` — writes `shared/env.json`, creates the endpoint response-actions data stream, installs the Okta Fleet integration, waits for the agent to show healthy in Fleet, uploads `scripts/remediate-okta-compromise.ps1` to the Script library (saving its UUID to `state/script-id`), and updates the deployed Workflow with that UUID so the `script_id` input is pre-filled

### Before each demo take (including the first)

```bash
./scripts/prepare-and-reset-demo.sh
```

Seeds fresh Okta attack telemetry with current timestamps, and closes any open alerts and cases from the previous take. Run this before every demo, including the first time after `terraform apply`.

## Connecting to the VM

The VM enrollment script installs OpenSSH Server, so the simplest way to run response actions or inspect state is SSH from your machine — no RDP client needed. (RDP is also open on 3389 from `my_ip` if you want the GUI.)

Grab connection details from Terraform outputs:

```bash
export VM_IP=$(terraform -chdir=terraform output -raw vm_public_ip)
export VM_USER=$(terraform -chdir=terraform output -raw vm_admin_username)
terraform -chdir=terraform output -raw vm_admin_password   # prints the admin password
```

SSH in (enter the password from above when prompted):

```bash
ssh "${VM_USER}@${VM_IP}"
```

If the password is rejected, copy/paste corruption between terminals (e.g. VS Code's integrated terminal wrapping/mangling long special-character strings) is a common culprit — skip the manual copy entirely and feed the password straight from Terraform to `ssh` with [`sshpass`](https://formulae.brew.sh/formula/sshpass) (`brew install hudochenkov/sshpass/sshpass`):

```bash
sshpass -p "$(terraform -chdir=terraform output -raw vm_admin_password)" ssh "${VM_USER}@${VM_IP}"
```

RDP instead, if preferred:

```bash
open "rdp://full%20address=s:${VM_IP}&username=s:${VM_USER}"   # macOS, Microsoft Remote Desktop app
```

If SSH or RDP hangs on connect, your public IP has likely changed since the NSG rule was last provisioned (it's auto-detected at `apply` time). Re-run `terraform -chdir=terraform apply` — it only updates the NSG rule — then retry.

## Demo steps

### Step 1: Author the detection rule (AI rule creation)

In Kibana: Security → Rules → Create new rule → **AI rule creation**.

Paste this prompt:

> *Within a 24-hour window, for each Okta actor and client IP: count sign-on failures with reason INVALID_CREDENTIALS, failed MFA challenges including push denials, successful sign-ons, and successful post-compromise actions where the actor is the one performing the action. Post-compromise means group membership add, application assignment, privilege grant, MFA factor enrolment, a change to a policy or policy rule (a modification, not an evaluation), or a profile update — explicitly excluding password changes. Require the post-compromise action to occur after the first successful sign-on.
 Before writing any field names, call the Elasticsearch GET API on 
   logs-okta.system-default/_mapping and use only field paths that exist in the 
   response. Do not use any field name that is not present in the mapping.

*

Review the generated ES|QL — it should aggregate by `user.name` and `source.ip`, use `MIN(@timestamp)` with per-condition filters to capture the first success and first post-compromise timestamps, and enforce the temporal ordering in the `WHERE` clause. Optionally refine. Review the MITRE mapping. Click **Preview rule results** — `jsmith@example.com` should appear (all four stages); `bjones`, `alee`, and `mwilson` should not.

On the **Actions** tab, before saving: add the Workflow as a rule action — select **Okta Credential Stuffing Response** from the Workflow picker. The `script_id` input is pre-filled automatically by `configure.sh`.

Also on the **Actions** tab, enable **Alert suppression**: suppress by `okta.actor.alternate_id` and `okta.client.ip`, per time period, **1 hour**. This prevents the rule firing a new alert (and triggering the Workflow) on every 5-minute run while the seed data is present in the index. Each unique `(user, attacker IP)` pair still produces exactly one alert — `add-attack-scenario.sh` uses a fresh IP each run, so every new scenario still fires; `prepare-and-reset-demo.sh` wipes the events, resetting suppression.

Click **Apply to creation** and enable the rule.

### Step 2: Detect

Navigate to Security → Alerts. The rule fires immediately on the seeded data — show the alert for `jsmith@example.com`. Walk the aggregation fields (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) to show why this user/IP triggered and the others did not.

The alert tells you the compromised identity and the attacker IP. Ask the audience: *which machine needs remediation?* Okta doesn't know about Windows hosts. That's the gap the Entity Store bridges — see the next section before walking the case.

### The identity-to-endpoint bridge

The alert carries two key facts: the compromised identity (`jsmith@example.com`) and the attacker IP. But Okta has no knowledge of Windows hosts — the alert alone cannot tell you which machine needs remediation.

The Elastic Entity Store answers that question. It runs continuously in the background, correlating identities across data sources. When the Windows System integration collected interactive logon events (Windows Security event 4624), the entity store recorded that `jsmith` last authenticated on `DEMO-VM-01`. Workflow step 6 (`find_user_entity`) queries the entity store v2 index, strips the domain from the Okta actor email to get the local username, and retrieves the associated hostname. Step 6b (`find_agent`) then resolves the Fleet agent ID for that specific host. The remediation script fires against the exact right machine — not the first Windows agent in Fleet, not a hardcoded hostname, but the one the entity store identified as `jsmith`'s endpoint.

### Step 3: Respond — show the auto-created case

Open Security → Cases. The Workflow fired when the alert was created and ran nine automated steps:

1. Opened a case — title, description, severity Critical, MITRE tags.
2. Set status → **in-progress** — signals remediation is underway.
3. Attached the triggering alert to the case.
4. Pinned the attacker IP and compromised account as **observables** (IOCs visible in the case header).
5. Added an **AI analysis comment** (Claude-generated summary of the four-stage attack chain).
6. Queried the **Entity Store** to resolve which Windows host `jsmith` last authenticated on — this is the identity-to-endpoint bridge described above.
7. Looked up the Fleet agent ID for that hostname (step 6b).
8. Ran `remediate-okta-compromise.ps1` via Runscript against that endpoint — blocked `source.ip` at the Windows Firewall and disabled the local account matching the compromised Okta username.
9. Added a remediation summary comment (includes the resolved hostname).
10. Closed the case.

Walk the case timeline: created → in-progress → observables → AI analysis → entity store resolves hostname → remediation → closed. Step 6 is the moment to pause and explain how Elastic knew which endpoint to target — the entity store correlated the Okta identity to the Windows host before the Workflow ever ran.

#### Verifying the Runscript actually ran

**In Kibana:** Security → Endpoints → Response Actions History. Find the `run-script` entry for the Windows VM and expand it — the script prints a `=== Response Summary ===` block naming the firewall rule created and the account disabled.

**On the VM (belt-and-braces):** SSH in and run two read-only commands:

```powershell
# Show the firewall rule and the specific IP it blocks
Get-NetFirewallRule -DisplayName "Elastic-OktaCompromise-Block-*" |
  ForEach-Object { $_ | Get-NetFirewallAddressFilter |
    Select-Object @{n='Rule';e={$_.InstanceID}}, RemoteAddress } |
  Format-Table -AutoSize

# Show the compromised account is disabled
Get-LocalUser -Name jsmith | Select-Object Name, Enabled
```

The first command shows the exact attacker IP embedded in the rule, proving the dynamic value was passed correctly from the alert. A matching IP and `Enabled: False` on the account confirm the script ran end-to-end.

> **If Response Actions History is empty:** check that the Elastic Agent on the Windows VM is showing as **Online** in Fleet (Security → Fleet → Agents). If the agent is offline or unhealthy, the Runscript action queues but cannot execute. The remediation comment in the case will still show the hostname if the Fleet lookup succeeded.

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
