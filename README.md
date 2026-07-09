# Elastic Security 9.4 Webinar Demo

Self-contained demo of AI-assisted detection, Runscript response, and Workflow-driven case automation, run against a Windows VM enrolled in Elastic Cloud.

## The attack

A **benign** reproduction of the Jan 2026 ClickFix → LOLBin → Remcos/NetSupport RAT chain. No real malware — every step uses signed Windows binaries and writes only to throwaway paths, generating detectable Elastic Defend telemetry.

Kill chain: `forfiles` → `mshta` → `powershell` → `curl.exe` (fetch harmless file) → `wscript` / `reg.exe` persistence.

MITRE: T1218.005 (Mshta), T1059.001 (PowerShell), T1059.003 (cmd), T1547 (persistence).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| AI-assisted detection engineering | **AI rule creation** in Agent Builder — describe the threat in natural language, generate/refine an ES\|QL rule |
| Automated response | **Runscript** response action + centralized **Script library** (Elastic Defend, GA 9.4) |
| Automated case management | **Workflows** with Cases action steps, launched from an alert |

## Prerequisites

- Infra provisioned (see `CLAUDE.md`): Azure Windows VM + Elastic Cloud, agent enrolled, Elastic Defend installed on the agent policy in detect-only mode (Terraform-managed).
- `demo/remediate.ps1` uploaded to the Script library (*Remediation Action*).

## Connecting to the VM

The VM enrollment script installs OpenSSH Server, so the simplest way to copy over and run `simulate-lolbin-chain.ps1` is SSH/SCP from your machine — no RDP client needed. (RDP is also open on 3389 from `my_ip` if you want the GUI, e.g. to watch Elastic Defend or the demo running live.)

Grab connection details from Terraform outputs:

```bash
export VM_IP=$(terraform -chdir=terraform output -raw vm_public_ip)
export VM_USER=$(terraform -chdir=terraform output -raw vm_admin_username)
terraform -chdir=terraform output -raw vm_admin_password   # prints the admin password
```

Copy the simulation script to the VM (lands in the admin user's home directory):

```bash
scp demo/simulate-lolbin-chain.ps1 "${VM_USER}@${VM_IP}:"
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

1. **Author (AI detection).** Create a rule → **AI rule creation**. Prompt: *"Detect a ClickFix-style attack where a command from the Run dialog or mshta spawns PowerShell or curl to download a payload."* Refine, review the MITRE mapping, **Apply to creation**, enable.
2. **Trigger.** Run the simulation on the VM over SSH (no interactive session needed):
   ```bash
   ssh "${VM_USER}@${VM_IP}" powershell -ExecutionPolicy Bypass -File simulate-lolbin-chain.ps1
   ```
3. **Detect.** Show the alert(s) — your AI rule plus the prebuilt *Suspicious Microsoft HTML Application Child Process*. Walk the process tree in the analyzer.
4. **Respond (Runscript).** From the alert, run `runscript --script="remediate.ps1"`. Show output and script provenance in the Script library.
5. **Automate (Workflows).** Show the alert-triggered Workflow: create case → attach alerts → AI analysis comment → isolate host → Slack notify. Open the auto-created case.

## Cleanup

`terraform destroy`
