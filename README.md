# Elastic Security 9.4 Webinar Demo

Self-contained demo of AI-assisted detection, Runscript response, and Workflow-driven case automation, run against a Windows VM enrolled in Elastic Cloud.

## The threat

**Password spraying** — a single source IP attempting authentication against many distinct user accounts with only a few tries each (low-and-slow, to avoid per-account lockout). The detection signal is a *high count of distinct usernames from one source IP*, not raw attempt volume — that's the key distinction from brute force, and it's naturally expressed as an aggregation: group by `source.ip`, count distinct `user.name`, count total failures.

Demo telemetry is synthetic authentication-failure events, seeded directly via `demo/create-sample-data.http`: one attacker IP failing against 8 distinct usernames, one benign IP failing against only 2 (to show the threshold correctly not firing).

MITRE: T1110.003 (Brute Force: Password Guessing / Spraying).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| AI-assisted detection engineering | **AI rule creation** in Agent Builder — describe the threat in natural language, generate/refine an ES\|QL aggregation rule |
| Automated response | **Runscript** response action + centralized **Script library** (Elastic Defend, GA 9.4) — blocks the alert's `source.ip` |
| Automated case management | **Workflows** with Cases action steps, launched from an alert |

## Prerequisites

- Infra provisioned (see `CLAUDE.md`): Azure Windows VM + Elastic Cloud, agent enrolled, Elastic Defend installed on the agent policy in detect-only mode (Terraform-managed).
- `demo/block-spray-source.ps1` uploaded to the Script library (*Remediation Action*).

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

RDP instead, if preferred:

```bash
open "rdp://full%20address=s:${VM_IP}&username=s:${VM_USER}"   # macOS, Microsoft Remote Desktop app
```

## Demo steps

1. **Seed data.** Run `./demo/seed-password-spray-data.sh` (reads endpoint/credentials from `shared/env.json`, deletes any previous take's events, then bulk-loads fresh ones with timestamps relative to now) — no VM access needed for this step. `demo/create-sample-data.http` does the same thing request-by-request if you'd rather trigger it from an HTTP client instead. Seeding *before* authoring the rule means the next step's rule preview has live data to validate against, not an empty result set.
2. **Author (AI detection).** Create a rule → **AI rule creation**. Prompt: *"Over authentication logs, detect password spraying: a single source IP that fails authentication against many distinct user accounts. Group by source.ip, count the total failed attempts and the number of distinct usernames targeted, and alert when one IP has failed logins against 5 or more distinct users with at least 10 attempts."* Refine as needed (e.g. exclude a known-good egress range, add a `BUCKET` time window, add the targeted-username list to the alert), review the MITRE mapping. Then click **Preview rule results** — since the data from step 1 is already indexed, this runs the generated query against your live, real data (no sample/sandbox set) and should surface the attacker IP (8 distinct users, 14 failed attempts) while the benign IP (2 distinct users) is correctly absent. This is the moment that proves the AI-generated query actually works, before you commit to enabling it. Once satisfied, **Apply to creation** and enable.
3. **Detect.** Show the alert — the same result seen in the preview now exists as a real alert for the attacker IP, correctly quiet for the benign IP. Walk the aggregation results (`distinct_users`, `failed_attempts`, `targeted_users`) in the alert details.
4. **Respond (Runscript).** From the alert, run `runscript --script="block-spray-source.ps1" --params="SourceIp=<alert source.ip>"`. Show output (firewall rule created) and script provenance in the Script library.
5. **Automate (Workflows).** Show the alert-triggered Workflow: create case → attach alert → AI analysis comment (summarizing the targeted usernames) → run `block-spray-source.ps1` → final summary comment. Open the auto-created case.

## Cleanup

`terraform destroy`
