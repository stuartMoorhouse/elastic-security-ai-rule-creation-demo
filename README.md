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

- Infra provisioned (see `CLAUDE.md`): Azure Windows VM + Elastic Cloud, agent enrolled.
- Elastic Defend installed on the VM (manual — via Kibana Fleet).
- `demo/remediate.ps1` uploaded to the Script library (*Remediation Action*).

## Demo steps

1. **Author (AI detection).** Create a rule → **AI rule creation**. Prompt: *"Detect a ClickFix-style attack where a command from the Run dialog or mshta spawns PowerShell or curl to download a payload."* Refine, review the MITRE mapping, **Apply to creation**, enable.
2. **Trigger.** On the VM, run `demo/simulate-lolbin-chain.ps1`.
3. **Detect.** Show the alert(s) — your AI rule plus the prebuilt *Suspicious Microsoft HTML Application Child Process*. Walk the process tree in the analyzer.
4. **Respond (Runscript).** From the alert, run `runscript --script="remediate.ps1"`. Show output and script provenance in the Script library.
5. **Automate (Workflows).** Show the alert-triggered Workflow: create case → attach alerts → AI analysis comment → isolate host → Slack notify. Open the auto-created case.

## Cleanup

`terraform destroy`
