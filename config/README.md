# config/

Solution-layer config and reference documentation for the webinar demo. Nothing in this directory is a deployable Terraform module, NDJSON rule export, or Workflow definition file — those two artifacts are built manually in Kibana per spec (see below).

## Files

### `fleet-agent-policy-payload.json`

**Consumed automatically.** JSON request body for Fleet's agent policy creation endpoint:

```
POST /api/fleet/agent_policies
```

Read by `terraform/scripts/setup-fleet-policy.sh` (part of the Terraform `null_resource` Fleet-enrollment automation) and sent via `curl` to create the dedicated `elastic-security-webinar-demo-policy` agent policy, with `monitoring_enabled` for logs and metrics. The script then uses the returned policy ID to call `GET /api/fleet/enrollment_api_keys` and `GET /api/fleet/fleet_server_hosts` to obtain an enrollment token and the real Fleet Server URL for the Azure VM's `custom_script_extension`.

### `ai-detection-rule-prompt.md`

**Manual reference doc** for the presenter. Not consumed by any script. Contains the exact natural-language prompt for Kibana's AI rule creation (Agent Builder), the MITRE ATT&CK techniques to verify on the generated rule (T1218.005, T1059.001, T1059.003, T1547), a step-by-step checklist (review ES\|QL → verify MITRE tags → Apply to creation → enable), and the expected process tree to sanity-check the query against.

### `workflow-definition-reference.md`

**Manual reference doc** for the presenter. Not consumed by any script. Describes the alert-triggered Workflow to build by hand in Kibana's Workflows UI: create case → attach alert(s) → AI analysis comment → isolate host → final summary comment. Notes that no external notification integration (e.g. Slack) is included by design. Maps directly to spec Acceptance Criteria #9.

## What this project intentionally does NOT automate

Per `.claude/spec/spec.md` ("Out of scope for Terraform"), two things are deliberately left as manual, live steps in the webinar rather than API-created or Terraform-managed:

1. **The AI/ES\|QL detection rule.** Authoring it live via Kibana's AI rule creation (Agent Builder) is itself the demo content for the "AI-assisted detection engineering" agenda item — scripting or API-creating it in advance would remove the thing being demonstrated.
2. **The alert-triggered Workflow.** Building it live in the Workflows UI demonstrates "automated case management" as a hands-on capability, not just a pre-baked artifact. It also keeps the demo narrative "live" — the presenter shows the tool being used, not a `terraform apply` output.

Both decisions are explicit in the spec (see "Out of scope for Terraform" and the Demo flow section) and are intentional, not omissions. The only genuinely automated piece in this directory is the Fleet agent policy payload, which supports VM enrollment (infrastructure), not detection/response content (demo narrative).
