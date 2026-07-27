# Elastic Security 9.4 Webinar Demo

Self-contained demo of AI-assisted detection, Runscript response, and Workflow-driven case automation, run against a Windows VM enrolled in Elastic Cloud.

## The threat

**Okta credential stuffing and account takeover** — an attacker uses a list of breached credentials to spray multiple Okta accounts, pushes through MFA, and then takes post-compromise actions (privilege escalation, policy changes) once inside. The detection requires the *full four-stage sequence* to be present for the same `user.name` and `source.ip`: failed logins with `INVALID_CREDENTIALS`, MFA failures, a successful login, and at least one post-compromise action. This is what makes it high-fidelity: a user who forgets their password won't match (no MFA failures, no post-compromise), and an attacker stopped at MFA won't match either.

Demo telemetry is synthetic Okta system log events (`logs-okta.system-default`), seeded via `scripts/seed-okta-attack-data.sh`. One attacker IP completes the full chain against `jsmith@example.com` (fires the rule); two other accounts (`bjones`, `alee`) get failed logins only; one benign IP (`mwilson`) has a single failed login then success (forgot password — correctly silent).

MITRE: T1110.004 (Credential Stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| AI-assisted detection engineering | **AI rule creation** in Agent Builder — describe the threat in natural language, generate/refine an ES\|QL aggregation rule |
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
- Runs `scripts/configure.sh` — writes `shared/env.json`, creates the endpoint response-actions data stream, installs the Okta Fleet integration, waits for the agent to show healthy in Fleet, and uploads `scripts/remediate-okta-compromise.ps1` to the Script library (saving its UUID to `state/script-id`)

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

> *Find likely Okta account-takeover cases. For each user and source IP, flag the pair when all of these occur: at least 3 failed logins due to invalid credentials, at least one MFA failure, at least one successful login, and at least one post-compromise action — being added to a group or application, being granted account privileges, a sign-on or policy change, or a profile update. Return the user, source IP, a count for each of those four categories, and the first and last timestamps seen, sorted by failed-login count descending.*

Review the generated ES|QL — it uses `COUNT_IF` in a single `STATS` pass, grouped by `user.name` and `source.ip`. Optionally refine. Review the MITRE mapping. Click **Preview rule results** — `jsmith@example.com` should appear (all four stages); `bjones`, `alee`, and `mwilson` should not.

On the **Actions** tab, before saving: add the Workflow as a rule action.

- Select **Okta Credential Stuffing Response** from the Workflow picker
- **`script_id` input:** `cat state/script-id` (uploaded automatically by `configure.sh`)

Click **Apply to creation** and enable the rule.

### Step 2: Detect

Navigate to Security → Alerts. The rule fires immediately on the seeded data — show the alert for `jsmith@example.com`. Walk the aggregation fields (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) to show why this user/IP triggered and the others did not.

### Step 3: Respond — show the auto-created case

Open Security → Cases. The Workflow fired when the alert was created and ran ten automated steps:

1. Opened a case — title, description, severity Critical, MITRE tags.
2. Set status → **in-progress** — signals remediation is underway.
3. Attached the triggering alert to the case.
4. Pinned the attacker IP and compromised account as **observables** (IOCs visible in the case header).
5. Added an **AI analysis comment** (Claude-generated summary of the four-stage attack chain).
6. Queried the **entity store** (`entities-latest-default`) to resolve which host `jsmith` is associated with — the entity store links the Okta user entity (built from Okta log events) to the endpoint user entity (built from Elastic Defend process telemetry on jsmith's Windows workstation).
7. Looked up the **Fleet agent ID** for that host via the Fleet API.
8. Ran `remediate-okta-compromise.ps1` via Runscript against the dynamically resolved endpoint — blocked `source.ip` at the Windows Firewall and disabled the local account matching the compromised Okta username.
9. Added a remediation summary comment (includes the resolved hostname).
10. Closed the case.

Walk the case timeline: created → in-progress → observables → AI analysis → entity resolution → remediation → closed. The pitch: the Workflow doesn't need a hardcoded machine name — the entity store provides the bridge between the Okta identity and the Windows workstation, so the same Workflow works regardless of which user or endpoint is involved.

#### Verifying the Runscript actually ran

**In Kibana:** Security → Endpoints → Response Actions History. Find the `run-script` entry for the Windows VM and expand it — the script prints a `=== Response Summary ===` block naming the firewall rule created and the account disabled.

**On the VM (belt-and-braces):** SSH in and run two read-only commands:

```powershell
# Show the inbound-block firewall rule for the attacker IP
Get-NetFirewallRule -DisplayName "Elastic-OktaCompromise-Block-*" | Select-Object DisplayName, Enabled, Action

# Show the compromised account is disabled
Get-LocalUser -Name jsmith | Select-Object Name, Enabled
```

A matching firewall rule and `Enabled: False` on the account confirm the script ran.

> **If Response Actions History is empty:** the entity store lookup (Step 6) may not have found jsmith's host yet. Check the case's remediation comment — if it says `unknown host`, the entity store hasn't linked jsmith's Okta identity to the Windows endpoint yet. Wait a few minutes for the entity store extraction cycle to run, then re-seed and retry. See [Entity store timing](#entity-store-timing) below.

#### Entity store timing

The entity store runs on a schedule (default: every few minutes). Two sources feed the jsmith entity:

- **Endpoint entity** (user.name + host.id): created from Elastic Defend process telemetry generated when `jsmith` first logged into the Windows VM. This happens automatically during `terraform apply` (the `create-demo-users.ps1` script runs a process as jsmith) and persists indefinitely — no action needed per demo take. Elastic Defend is an EDR agent that captures every process start event on the host, stamping each one with the owning user (`user.name`) and a stable host identifier (`host.id`). The entity store's scheduled extraction reads these process events from the security data view and — when it sees both fields together — creates a user entity record linking jsmith to this specific host. That record is what the Workflow queries in step 6 to find the right endpoint to remediate on, without any hardcoded machine name.
- **Okta user entity** (user.email): created from the seeded Okta log events. This is re-seeded by `prepare-and-reset-demo.sh` and will appear in the entity store within a few minutes of seeding.

For a live demo, seed the Okta data at least **5 minutes before** showing the alert to give the entity store time to extract the Okta user entity and link it to the endpoint entity via entity resolution. Seeding at the start of your setup time (before the narrative begins) is the safest approach.

To verify the entity store has the association before the demo: Security → Entity analytics → search for `jsmith`. The user entity should show both the Okta source and the host association.

## Optional: building a richer alert queue

For a more compelling "scale" story, seed additional attack scenarios before the demo:

```bash
./scripts/add-attack-scenario.sh   # adds one new attacker IP + victim
./scripts/add-attack-scenario.sh   # add another, and so on
```

Each run picks the next IP/victim from a rotation pool. Each new scenario fires the detection rule and triggers the Workflow, which remediates and acknowledges the alert automatically.

**What to show in Kibana:** Security → Alerts → change the **Status** filter to **Acknowledged** (or **All**). You'll see a queue of multiple attackers, each already remediated — demonstrating that the automated response runs consistently across every alert, not just the first one.

The original `jsmith@example.com` alert stays **Open** (it was seeded before the Workflow was attached to the rule), giving you a clean before/after contrast: one unprocessed alert vs. a queue of auto-closed ones.

## Cleanup

`terraform destroy`
