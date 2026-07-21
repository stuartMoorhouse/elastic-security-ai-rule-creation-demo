# Alert-Triggered Workflow

The Workflow definition is at `terraform/workflows/okta-credential-stuffing.yaml` and is
deployed automatically by `terraform apply` via `terraform/workflows.tf`.

The Workflow ID is written to `state/workflow-id` after a successful deploy. When creating
the AI detection rule (step 2 of the demo), add this Workflow as a rule action using that ID
so it fires on every alert.

## Steps (in order)

1. `cases.createCase` — opens a Critical case with title referencing the compromised user, description summarising the four-stage attack, and MITRE tags (T1110.004, T1078, T1098).
2. `cases.setStatus` → `in-progress` — signals automated remediation is running.
3. `cases.addAlerts` — attaches the triggering alert to the case.
4. `cases.addObservables` — pins `source.ip` as an `ip_address` observable and `user.name` as a `user` observable (IOCs visible in the Cases UI, not just comment text).
5. `cases.addComment` — analysis comment showing the four aggregation counts (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) and the MITRE chain.
6. `kibana.request` → `POST /api/endpoint/action/run_script` — runs `remediate-okta-compromise.ps1` against the enrolled Windows endpoint, parameterised with `SourceIp` and `CompromisedUser` from the alert.
7. `cases.addComment` + `cases.setStatus` → `closed` — records the remediation outcome and closes the case.

## Re-deploying

To force a re-deploy after editing the YAML, run `terraform apply` — the `terraform_data.workflow` resource triggers on the YAML file hash.

## Explicit exclusions

- No external notification integration (Slack, etc.) — the Workflow is self-contained; no external connector credentials required.
- No deduplication gate (`cases.getCasesByAlertId`) — kept simple for the demo; the seeded data fires the rule once per take.
