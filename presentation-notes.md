# Presentation Notes: Elastic Security 9.4 — AI Rule Creation Demo

Okta credential stuffing and account takeover, detected by an AI-generated ES|QL rule,
remediated automatically by a Workflow and Runscript response action.

---

## Contents

1. [The Threat — What Is Happening and Why It Matters](#1-the-threat)
2. [The Data — How Okta Events Look in Elastic](#2-the-data)
3. [The Detection — Building the ES|QL Rule](#3-the-detection)
4. [The Workflow — Automated Response](#4-the-workflow)
5. [The Runscript — Endpoint Remediation](#5-the-runscript)
6. [SA Talking Points — Step by Step](#6-sa-talking-points)
7. [Q&A — Likely Questions from Security Practitioners](#7-qa)

---

## 1. The Threat

### What Is Credential Stuffing?

Credential stuffing is a brute-force variant where attackers use lists of leaked username/password
pairs — sourced from data breaches sold on criminal markets — and replay them at scale against a
target service. Unlike pure brute force, the credentials are real, so success rates are much higher
(typically 0.5-2% of attempts succeed).

Okta is a high-value target because a successful compromise gives the attacker a single sign-on
token that unlocks dozens of downstream applications: corporate email, cloud infrastructure, HR
systems, financial tools.

### The Four-Stage Attack Chain

This demo detects an attack only when all four stages are present for the same actor and source IP.
This is the key to high fidelity: partial activity is noise; the full chain is a confirmed takeover.

```
Stage 1: Credential Stuffing
  The attacker fires the same username repeatedly with different passwords from a breach list.
  Okta logs each failed attempt with outcome = FAILURE, reason = INVALID_CREDENTIALS.
  Three or more failures establishes the stuffing pattern.

Stage 2: MFA Fatigue / Challenge Bypass
  Once the correct password is found, Okta challenges the second factor.
  The attacker either pushes repeated MFA notifications hoping the user approves by mistake,
  or the attacker has already stolen the session token or TOTP seed.
  Okta logs these as user.authentication.auth_via_mfa with outcome FAILURE.

Stage 3: Successful Login
  The attacker passes authentication — either the user accidentally approved the MFA push,
  or the MFA was bypassed via a phishing kit or token theft.
  Okta logs user.session.start with outcome SUCCESS.

Stage 4: Post-Compromise Action
  Within the same session the attacker acts: grants themselves privileges, adds their device
  to an MFA policy, modifies application assignments, or updates profile data.
  These are the actions that cause real damage and distinguish an attacker from a legitimate
  user who forgot their password (who would not take post-compromise actions).
```

### Why the Four-Stage Requirement Matters

A rule that fires on three failed logins alone would page on every user who forgets their password.
Requiring MFA failures eliminates the "I mistyped my password" case. Requiring a successful login
following the failures eliminates attackers who were stopped at MFA. Requiring a post-compromise
action after success eliminates legitimate users who log in after a difficult authentication.

The temporal ordering constraint (`first_post_compromise_timestamp > first_successful_login_timestamp`)
is the final gate: it proves the post-compromise action happened *inside* the attacker's session,
not days earlier when the legitimate user was active.

### MITRE ATT&CK Mapping

| Stage | Tactic | Technique |
|---|---|---|
| Credential stuffing | Credential Access (TA0006) | T1110.004 — Credential Stuffing |
| MFA failure | Credential Access (TA0006) | T1621 — Multi-Factor Authentication Request Generation |
| Successful login | Initial Access (TA0001) | T1078.004 — Valid Accounts: Cloud Accounts |
| Post-compromise | Persistence / Privilege Escalation | T1098.003 — Account Manipulation: Additional Cloud Roles |

---

## 2. The Data

### Where Okta Logs Live in Elastic

The Elastic Okta integration ships system log events into the data stream `logs-okta.system-default`.
The integration's ingest pipeline maps Okta's native fields to ECS (Elastic Common Schema):

| Okta native field | ECS field | What it contains |
|---|---|---|
| `actor.alternateId` | `user.name` | User's email address |
| `client.ipAddress` | `source.ip` | Source IP of the authentication attempt |
| `eventType` | `event.action` | The action that occurred (e.g. `user.session.start`) |
| `outcome.result` | `event.outcome` | `success` or `failure` |
| `outcome.reason` | `okta.outcome.reason` | Failure reason (e.g. `INVALID_CREDENTIALS`) |

Both the ECS fields and some Okta-native fields (`okta.client.ip`, `okta.actor.alternate_id`) are
available in the index — which field the AI-generated rule uses depends on the model's training,
which is why the prompt specifies "Okta actor" and "client IP" rather than ECS names.

### Sample Events — What the Four Stages Look Like

The following shows how a single attack sequence against `jsmith@example.com` from `203.0.113.66`
appears in the index. Timestamps are relative (minutes before detection).

**Stage 1 — Credential stuffing attempt (T-9 minutes):**
```json
{
  "@timestamp": "2026-07-29T09:01:00.000Z",
  "event.action": "user.authentication.usernamepassword",
  "event.outcome": "failure",
  "user.name": "jsmith@example.com",
  "source.ip": "203.0.113.66",
  "okta.outcome.reason": "INVALID_CREDENTIALS",
  "okta.client.ipAddress": "203.0.113.66",
  "okta.actor.alternateId": "jsmith@example.com"
}
```

Two event types are fired per attempt in Okta: `user.session.start` (the session layer) and
`user.authentication.usernamepassword` (the credential layer). Both carry the same outcome and
reason. The demo seeds both so the rule fires regardless of which action the AI uses.

**Stage 2 — MFA challenge failure (T-4 minutes):**
```json
{
  "@timestamp": "2026-07-29T09:06:00.000Z",
  "event.action": "user.authentication.auth_via_mfa",
  "event.outcome": "failure",
  "user.name": "jsmith@example.com",
  "source.ip": "203.0.113.66",
  "okta.outcome.reason": "FACTOR_CHALLENGE_TIMEOUT"
}
```

`FACTOR_CHALLENGE_TIMEOUT` is the reason emitted when a push notification expires without being
approved. `MFA_ENROLL_NOT_ALLOWED` and `FACTOR_ENROLL_PUSH_REJECTED` appear when the attacker
tries to enrol their own device into the MFA policy.

**Stage 3 — Successful authentication (T-2 minutes):**
```json
{
  "@timestamp": "2026-07-29T09:08:00.000Z",
  "event.action": "user.session.start",
  "event.outcome": "success",
  "user.name": "jsmith@example.com",
  "source.ip": "203.0.113.66"
}
```

**Stage 4 — Post-compromise privilege grant (T-1 minute):**
```json
{
  "@timestamp": "2026-07-29T09:09:00.000Z",
  "event.action": "user.account.privilege.grant",
  "event.outcome": "success",
  "user.name": "jsmith@example.com",
  "source.ip": "203.0.113.66"
}
```

The timestamp on Stage 4 (`09:09`) is strictly after Stage 3 (`09:08`). This is deliberate:
the `first_post_ts > first_success_ts` filter in the rule requires it.

### What Does NOT Fire the Rule

The demo also seeds accounts that exercise the false-positive paths:

| Account | Events seeded | Why it stays silent |
|---|---|---|
| `bjones@example.com` | 3 failed logins (INVALID_CREDENTIALS), no MFA, no success | `successful_logins = 0` — fails threshold |
| `alee@example.com` | 2 failed logins, no MFA, no success | `failed_logins < 3` and no success |
| `mwilson@example.com` | 1 failed login, then 1 success (forgot password) | No MFA failures, `failed_logins < 3`, no post-compromise |

Showing these in the ES|QL preview results is a key demo moment: it proves the rule is
discriminating, not noisy.

---

## 3. The Detection

### Why ES|QL Aggregation, Not EQL Sequence

EQL sequences work well for detecting multi-stage attacks within a fixed event count and time window
(e.g. process A spawns process B). They break down for this threat because:

- The number of failed login attempts is variable — stuffing campaigns fire dozens or hundreds of
  attempts; an EQL sequence needs a fixed count.
- The attack spans minutes to hours — EQL sequence windows are limited and don't handle gaps.
- EQL can't express "at least 3 failures" natively without complex `until` clauses.

An ES|QL aggregation rule groups all events within the detection window, computes counts per
(user, IP) pair, and fires once when the thresholds are all satisfied simultaneously. It produces
a single, enriched alert with all four counts as fields — far more useful for triage than four
separate events.

### Building the Query — The Thought Process

An SA can walk through this live as the AI generates it to show how to read and validate ES|QL.

**Step 1 — Source and time window.**
```esql
FROM logs-okta.system-*
| WHERE @timestamp >= NOW() - 24 hours
```
All Okta system log events in the last 24 hours. The wildcard covers `logs-okta.system-default`
and any custom namespace.

**Step 2 — Aggregate per (actor, IP) pair.**
```esql
| STATS
    ...
  BY user.name, source.ip
```
Every metric is computed independently per unique `(user.name, source.ip)` combination. This is
what lets the rule distinguish an attacker spray (many users, one IP) from a user spray (one user,
many IPs — unusual but possible).

**Step 3 — Count each attack stage.**
```esql
    failed_logins = COUNT(*) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "failure"
        AND okta.outcome.reason == "INVALID_CREDENTIALS",

    mfa_failures = COUNT(*) WHERE
        event.action == "user.authentication.auth_via_mfa"
        AND event.outcome == "failure",

    successful_logins = COUNT(*) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "success",

    post_compromise_events = COUNT(*) WHERE
        event.action IN (
            "group.user_membership.add",
            "application.user_membership.add",
            "user.account.privilege.grant",
            "user.mfa.factor.activate",
            "policy.lifecycle.update",
            "policy.rule.update",
            "user.account.update_profile"
        ) AND event.outcome == "success",
```

`COUNT(*) WHERE condition` is ES|QL's aggregation filter syntax. Each counter is independent — one
`STATS` pass computes all of them efficiently. Note that `user.account.reset_password` and
`user.account.update_password` are deliberately excluded from post-compromise: a user resetting
their own password is not an indicator of compromise.

**Step 4 — Capture timestamps for temporal ordering.**
```esql
    first_success_ts = MIN(@timestamp) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "success",

    first_post_ts = MIN(@timestamp) WHERE
        event.action IN ("group.user_membership.add", ..., "user.account.update_profile")
        AND event.outcome == "success"
```

`MIN(@timestamp) WHERE condition` is the same aggregation filter pattern applied to a timestamp
field. It captures the earliest occurrence of each event type, which is what we need to prove
the post-compromise action came *after* the successful login.

**Step 5 — Filter to groups that completed the full chain.**
```esql
| WHERE
    failed_logins >= 3
    AND mfa_failures >= 1
    AND successful_logins >= 1
    AND post_compromise_events >= 1
    AND first_post_ts > first_success_ts
```

This is the alert condition. All five must be true simultaneously. The last condition (`first_post_ts
> first_success_ts`) is the temporal ordering gate — it eliminates any edge case where a
post-compromise event (e.g. a policy change by an admin) happened before the stuffing attempt.

**Step 6 — Shape the output.**
```esql
| KEEP user.name, source.ip, failed_logins, mfa_failures,
       successful_logins, post_compromise_events,
       first_success_ts, first_post_ts
| SORT failed_logins DESC
```

The `KEEP` clause selects what appears as alert fields. All six counters plus the two timestamps
appear in the alert, which is what the Workflow later reads via `event.alerts[0].failed_login_count`.
Sorting by `failed_logins DESC` puts the most aggressive attacker first in the preview.

### Complete Reference Query

```esql
FROM logs-okta.system-*
| WHERE @timestamp >= NOW() - 24 hours
| STATS
    failed_logins          = COUNT(*) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "failure"
        AND okta.outcome.reason == "INVALID_CREDENTIALS",
    mfa_failures           = COUNT(*) WHERE
        event.action == "user.authentication.auth_via_mfa"
        AND event.outcome == "failure",
    successful_logins      = COUNT(*) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "success",
    post_compromise_events = COUNT(*) WHERE
        event.action IN (
            "group.user_membership.add",
            "application.user_membership.add",
            "user.account.privilege.grant",
            "user.mfa.factor.activate",
            "policy.lifecycle.update",
            "policy.rule.update",
            "user.account.update_profile"
        ) AND event.outcome == "success",
    first_success_ts       = MIN(@timestamp) WHERE
        (event.action == "user.session.start"
         OR event.action == "user.authentication.usernamepassword")
        AND event.outcome == "success",
    first_post_ts          = MIN(@timestamp) WHERE
        event.action IN (
            "group.user_membership.add",
            "application.user_membership.add",
            "user.account.privilege.grant",
            "user.mfa.factor.activate",
            "policy.lifecycle.update",
            "policy.rule.update",
            "user.account.update_profile"
        ) AND event.outcome == "success"
  BY user.name, source.ip
| WHERE
    failed_logins          >= 3
    AND mfa_failures        >= 1
    AND successful_logins   >= 1
    AND post_compromise_events >= 1
    AND first_post_ts > first_success_ts
| KEEP
    user.name, source.ip,
    failed_logins, mfa_failures, successful_logins, post_compromise_events,
    first_success_ts, first_post_ts
| SORT failed_logins DESC
```

---

## 4. The Workflow

### Overview

The Workflow is deployed automatically by `terraform apply` and attached to the detection rule
during the demo's live authoring step. It fires once per alert — the full nine-step sequence
runs in under 30 seconds for a fresh environment.

The Workflow uses three step types:
- `cases.*` — native Cases API operations (no HTTP knowledge required)
- `kibana.request` — raw HTTP to any Kibana API endpoint
- `ai.prompt` — sends a prompt to a configured AI connector and returns the response

Variable interpolation uses Liquid template syntax: `{{ expression }}`. Fields from the
triggering alert are available as `event.alerts[0].<field>`. Outputs from previous steps
are available as `steps.<step_name>.output.<field>`.

### Annotated Workflow YAML

```yaml
version: '1'
name: Okta Credential Stuffing Response
enabled: true

triggers:
  - type: alert
  # Fires once for every alert the detection rule creates.
  # In this demo that is one alert per (user, IP) pair that completes all four stages.

inputs:
  - name: script_id
    type: string
    default: "REPLACE_WITH_SCRIPT_LIBRARY_UUID"
    # The UUID of the PowerShell script in the Elastic Defend Script Library.
    # configure.sh substitutes the real UUID into this default at deploy time,
    # so the input is pre-filled when you attach the Workflow to the rule.

steps:

  # ---------------------------------------------------------------------------
  # STEP 1 — Open a case
  # ---------------------------------------------------------------------------
  - name: create_case
    type: cases.createCase
    with:
      owner: securitySolution
      title: "Okta Account Takeover: {{ event.alerts[0].okta.actor.alternate_id | default: 'Unknown User' }}"
      # The | default: filter is Liquid — it produces a fallback if the field is null.
      # The title uses the Okta-native field okta.actor.alternate_id (the email address)
      # rather than the ECS user.name, because that is what the alert carries for Okta events.
      description: |
        Credential stuffing attack detected. The same user and source IP completed the full
        four-stage sequence: failed logins (INVALID_CREDENTIALS) → MFA failures →
        successful login → post-compromise action (privilege grant or policy update).

        **Source IP:** {{ event.alerts[0].okta.client.ip | default: 'Unknown' }}
        **Compromised account:** {{ event.alerts[0].okta.actor.alternate_id | default: 'Unknown' }}

        Automated remediation is underway. See case comments for details.
      severity: critical
      tags:
        - okta
        - credential-stuffing
        - account-takeover
        - T1110.004
        - T1078
        - T1098
        - automated

  # ---------------------------------------------------------------------------
  # STEP 2 — Mark the case in-progress
  # ---------------------------------------------------------------------------
  - name: set_in_progress
    type: cases.setStatus
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      # steps.create_case.output.case.id — every cases.* step exposes its
      # created/modified object under steps.<name>.output.
      status: in-progress
      # Setting in-progress immediately signals to any human analyst watching
      # the Cases queue that automated remediation is already running.

  # ---------------------------------------------------------------------------
  # STEP 3 — Attach the triggering alert to the case
  # ---------------------------------------------------------------------------
  - name: attach_alert
    type: cases.addAlerts
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      alerts:
        - alertId: "{{ event.alerts[0]['_id'] }}"
          index:   "{{ event.alerts[0]['_index'] }}"
          # _id and _index are the Elasticsearch document ID and index name of
          # the alert document. The bracket notation handles the leading underscore.

  # ---------------------------------------------------------------------------
  # STEP 4 — Pin attacker IP and compromised account as observables (IOCs)
  # ---------------------------------------------------------------------------
  - name: add_observables
    type: cases.addObservables
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      observables:
        - typeKey: observable-type-ipv4
          value: "{{ event.alerts[0].okta.client.ip }}"
          description: "Attacker IP — credential stuffing source"
        - typeKey: observable-type-email
          value: "{{ event.alerts[0].okta.actor.alternate_id }}"
          description: "Compromised Okta account"
      # Observables appear in the case header and are searchable across all cases.
      # If the same IP appears in future alerts, all related cases are surfaced automatically.

  # ---------------------------------------------------------------------------
  # STEP 5 — AI-generated analysis comment
  # ---------------------------------------------------------------------------
  - name: ai_analysis
    type: ai.prompt
    connector-id: Anthropic-Claude-Sonnet-4-6
    # The connector must be configured in Kibana > Stack Management > Connectors.
    # Any AI connector can be used here — the connector-id references the name set there.
    with:
      prompt: >-
        You are a security analyst. Analyze the following Okta credential stuffing alert
        and produce a concise case comment for the security team.

        **Alert data:**
        {{ event.alerts | json }}
        # | json is a Liquid filter that serialises the object as JSON.

        **Attack stages detected:**
        - Failed logins (INVALID_CREDENTIALS): {{ event.alerts[0].failed_login_count | default: 'unknown' }}
        - MFA failures: {{ event.alerts[0].mfa_failure_count | default: 'unknown' }}
        - Successful logins: {{ event.alerts[0].successful_login_count | default: 'unknown' }}
        - Post-compromise events: {{ event.alerts[0].post_compromise_count | default: 'unknown' }}

        Include in your analysis:
        1. A summary of the credential stuffing attack and what the four stages indicate.
        2. The compromised account and attacker IP, and what the post-compromise activity suggests.
        3. Severity assessment.
        4. Recommended next steps beyond the automated remediation already underway.

        Format the output as a readable case comment in Markdown. Be concise.

  - name: analysis_comment
    type: cases.addComment
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      comment: "## AI Analysis\n\n{{ steps.ai_analysis.output.content }}"
      # steps.ai_analysis.output.content holds the model's text response.

  # ---------------------------------------------------------------------------
  # STEP 6 — Resolve which endpoint the compromised user is associated with
  #           via the Elastic Entity Store
  # ---------------------------------------------------------------------------
  - name: find_jsmith_entity
    type: kibana.request
    with:
      method: POST
      path: '/api/console/proxy?path=%2F.entities.v2.latest.security_default-00001%2F_search&method=POST'
      body:
        size: 1
        _source:
          - host.name
          - entity.name
        query:
          bool:
            must:
              - term:
                  user.name: "{{ event.alerts[0].okta.actor.alternate_id | split: '@' | first }}"
              - exists:
                  field: host.name
      # The entity store v2 index is auto-initialised by Elastic Security 9.x.
      # It correlates identities across data sources. Here it maps the Okta actor
      # email (jsmith@example.com → jsmith) to the Windows host that user last
      # interactively logged into, populated via Windows Security event 4624.
      #
      # | split: '@' | first is Liquid for "strip the domain from the email address".
      #
      # The response is available as steps.find_jsmith_entity.output.
      # steps.find_jsmith_entity.output.hits.hits[0]._source.host.name is the hostname.

  # ---------------------------------------------------------------------------
  # STEP 6b — Resolve the Fleet agent ID for the host from the entity store
  # ---------------------------------------------------------------------------
  - name: find_agent
    type: kibana.request
    with:
      method: GET
      path: '/api/fleet/agents?perPage=1&kuery=local_metadata.host.hostname%3A%22{{ steps.find_jsmith_entity.output.hits.hits[0]._source.host.name }}%22%20AND%20status%3Aonline'
      # Uses the hostname resolved in step 6 to look up the specific Fleet agent
      # rather than blindly picking the first Windows agent. The hostname is
      # URL-encoded in the kuery parameter (%3A = :, %22 = ").
      #
      # steps.find_agent.output.items[0].id is the agent UUID needed for run_script.

  # ---------------------------------------------------------------------------
  # STEP 7 — Run the remediation script against the resolved endpoint
  # ---------------------------------------------------------------------------
  - name: remediate
    type: kibana.request
    with:
      method: POST
      path: /api/endpoint/action/run_script
      body:
        alert_ids:
          - "{{ event.alerts[0]._id }}"
          # Associates the response action with the triggering alert in
          # Security > Endpoints > Response Actions History.
        agent_type: endpoint
        endpoint_ids:
          - "{{ steps.find_agent.output.items[0].id }}"
          # The Fleet agent UUID from step 6. The Elastic Agent on the VM
          # receives this and queues the script for execution.
        parameters:
          scriptId: "{{ inputs.script_id }}"
          # inputs.script_id resolves to the Script Library UUID that was
          # pre-filled by configure.sh. The agent fetches the script content
          # from the library by UUID — the script itself never travels in this payload.
          scriptInput: "-SourceIP {{ event.alerts[0].okta.client.ip }} -CompromisedUser {{ event.alerts[0].okta.actor.alternate_id }}"
          # scriptInput is passed directly to the PowerShell script as command-line
          # arguments. The script's param() block receives -SourceIP and -CompromisedUser.
        comment: "Triggered by workflow '{{ workflow.name }}'"

  # ---------------------------------------------------------------------------
  # STEP 8 — Remediation summary comment
  # ---------------------------------------------------------------------------
  - name: remediation_comment
    type: cases.addComment
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      comment: |
        ## Automated Remediation Complete

        `remediate-okta-compromise.ps1` ran against `{{ steps.find_jsmith_entity.output.hits.hits[0]._source.host.name | default: 'unknown host' }}`:

        - Blocked `{{ event.alerts[0].okta.client.ip }}` at the Windows Firewall
        - Disabled local account `{{ event.alerts[0].okta.actor.alternate_id | split: '@' | first }}`

        Script output:
        ```
        {{ steps.remediate.output | default: 'No output captured' }}
        ```
        # | split: '@' | first is Liquid for "split on @ and take the first element"
        # — converts jsmith@example.com → jsmith for the comment.

  # ---------------------------------------------------------------------------
  # STEP 9 — Close the case
  # ---------------------------------------------------------------------------
  - name: close_case
    type: cases.setStatus
    with:
      case_id: "{{ steps.create_case.output.case.id }}"
      status: closed
      # A closed case with a full audit trail (created → in-progress → alert attached
      # → observables → AI analysis → remediation comment → closed) is the demo payoff:
      # the entire SOC workflow automated in under 30 seconds.
```

---

## 5. The Runscript

### How the Script Library Works

The Elastic Defend Script Library (GA 9.4) stores scripts centrally in Kibana, encrypted at rest.
Scripts are referenced by UUID — the agent fetches the content from the library at execution time.
The `requiresInput: true` flag on upload signals that the script expects runtime parameters;
the Workflow passes these via `scriptInput` as a CLI argument string.

The script runs inside the Elastic Defend agent process on the endpoint with the agent's privileges
(Local System on Windows). Output is captured and returned to Kibana, where it appears in
Response Actions History and in the case comment.

### Annotated PowerShell Script

```powershell
<#
    remediate-okta-compromise.ps1

    Uploaded to the Elastic Defend Script Library by configure.sh.
    Triggered via run_script response action from the Workflow,
    parameterised with the alert's source.ip and okta.actor.alternate_id.

    In a production environment, add Okta Management API calls here:
      POST /api/v1/users/{userId}/lifecycle/suspend   — suspend the Okta user
      DELETE /api/v1/users/{userId}/sessions          — terminate active sessions
    This provides true Okta-layer remediation, not just Windows-layer containment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceIp,
    # Populated from scriptInput: -SourceIP {{ event.alerts[0].okta.client.ip }}
    # For example: -SourceIP 203.0.113.67

    [string]$CompromisedUser = ""
    # Populated from scriptInput: -CompromisedUser {{ event.alerts[0].okta.actor.alternate_id }}
    # For example: -CompromisedUser jsmith@example.com
    # Optional with empty default — if the field is absent in the alert, the script
    # skips account lockout gracefully rather than failing.
)

$RuleName = "Elastic-OktaCompromise-Block-$SourceIp"
# The firewall rule name embeds the IP. Multiple runs for different attacker IPs
# create separate rules. The same IP on a re-run replaces the existing rule (idempotent).

Write-Output "=== remediate-okta-compromise.ps1 starting ==="
Write-Output "Source IP:        $SourceIp"
Write-Output "Compromised user: $(if ($CompromisedUser) { $CompromisedUser } else { '(none supplied)' })"

# ---------------------------------------------------------------------------
# STEP 1 — Block the attacker's source IP at the Windows Firewall
# ---------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 1: Blocking source IP at the Windows Firewall =="

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    # If a rule for this IP already exists (e.g. from a previous demo take),
    # remove it before recreating so rules don't stack.
    Write-Output "Rule '$RuleName' already exists from a previous take; removing before recreating."
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
}

$firewallBlocked = $false
try {
    New-NetFirewallRule `
        -DisplayName $RuleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $SourceIp `
        -Protocol Any `
        -ErrorAction Stop | Out-Null
    # Direction Inbound blocks the attacker from re-establishing connections
    # from the same IP. In production, also add -Direction Outbound to prevent
    # beaconing back to an attacker-controlled host from the compromised endpoint.
    $firewallBlocked = $true
    Write-Output "Created inbound block rule '$RuleName' for $SourceIp."
} catch {
    Write-Output "WARNING: failed to create firewall rule: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# STEP 2 — Disable the local Windows account for the compromised Okta user
# ---------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 2: Disabling local Windows account for compromised user =="

$accountDisabled = $false
$localUsername = ""

if ([string]::IsNullOrWhiteSpace($CompromisedUser)) {
    Write-Output "No -CompromisedUser supplied; skipping account lockout."
} else {
    $localUsername = ($CompromisedUser -split "@")[0].Trim()
    # jsmith@example.com → jsmith
    # The Okta actor email prefix maps to the local Windows account name in this demo.
    # In production: look up the Windows account via AD/LDAP using the UPN
    # rather than assuming prefix == samAccountName.

    $account = Get-LocalUser -Name $localUsername -ErrorAction SilentlyContinue
    if (-not $account) {
        Write-Output "Local account '$localUsername' not found on this host; skipping."
        # Graceful skip — if the account doesn't exist locally (different naming
        # convention, AD-only account) the script continues rather than failing.
    } elseif (-not $account.Enabled) {
        Write-Output "Local account '$localUsername' is already disabled."
        # Idempotent — re-running against an already-disabled account is a no-op.
    } else {
        try {
            Disable-LocalUser -Name $localUsername -ErrorAction Stop
            # Disable-LocalUser prevents new logons but does not kill active sessions.
            # In production, follow up with: Get-Process -IncludeUserName | Where-Object ...
            # to kill active explorer/rdp sessions, or use logoff /server.
            $accountDisabled = $true
            Write-Output "Disabled local account '$localUsername'."
        } catch {
            Write-Output "WARNING: failed to disable '$localUsername': $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# STEP 3 — Summary (captured by Elastic Agent and returned to Kibana)
# ---------------------------------------------------------------------------
Write-Output ""
Write-Output "=== Response Summary ==="
Write-Output ("Firewall rule:    " + $(if ($firewallBlocked) { "$RuleName (blocking $SourceIp)" } else { "FAILED to create" }))
Write-Output ("Account disabled: " + $(if ($accountDisabled) { $localUsername } elseif ($CompromisedUser) { "$localUsername (not found or already disabled)" } else { "none supplied" }))
Write-Output "=== remediate-okta-compromise.ps1 complete ==="
# Everything written to stdout is captured by the Elastic Agent and returned
# to Kibana, where it appears in:
#   Security > Endpoints > Response Actions History (expand the run_script entry)
#   The case comment added in Workflow step 8 ({{ steps.remediate.output }})
```

### Verifying the Script Ran

**In Kibana:** Security → Endpoints → Response Actions History. Find the `run-script` entry for
the Windows VM and expand it — the `=== Response Summary ===` block is visible in the output.

**On the endpoint (SSH/RDP):**
```powershell
# Show the firewall rule and the exact IP it is blocking
Get-NetFirewallRule -DisplayName "Elastic-OktaCompromise-Block-*" |
  ForEach-Object { $_ | Get-NetFirewallAddressFilter |
    Select-Object @{n='Rule';e={$_.InstanceID}}, RemoteAddress } |
  Format-Table -AutoSize

# Confirm the account is disabled
Get-LocalUser -Name jsmith | Select-Object Name, Enabled
```

---

## 6. SA Talking Points

### Before the Demo

Seed the data first, then open Kibana. The rule fires within 5 minutes of being saved.

```bash
./scripts/prepare-and-reset-demo.sh   # resets alerts, cases, rule, and re-seeds data
```

### Step 1 — AI Rule Creation (Agent Builder)

**What you're showing:** The new AI rule creation experience in Agent Builder. This is not a
rule wizard — it is a generative authoring experience where the analyst describes the threat
in natural language and the AI produces a production-quality ES|QL aggregation rule.

**Talking points:**
- "Detection engineering has historically required deep ES|QL expertise. An analyst who knows
  what they want to detect — the threat behaviour — shouldn't need to know the exact field names
  and aggregation syntax."
- "We're not generating a simple keyword search. This is a multi-stage aggregation rule with
  per-condition counters, temporal ordering, and threshold logic. Exactly what a senior detection
  engineer would write."
- "Notice the Preview Results panel — jsmith fires, bjones doesn't, alee doesn't, mwilson doesn't.
  The rule is discriminating, not noisy. That's what we asked for in the prompt."
- "I can iterate on the prompt if I want to tighten the thresholds or add additional post-compromise
  categories. The AI explains each change it makes."

**Paste this prompt:**
> *Within a 24-hour window, for each Okta actor and client IP: count sign-on failures with reason
> INVALID_CREDENTIALS, failed MFA challenges including push denials, successful sign-ons, and
> successful post-compromise actions where the actor is the one performing the action. Post-compromise
> means group membership add, application assignment, privilege grant, MFA factor enrolment, a change
> to a policy or policy rule (a modification, not an evaluation), or a profile update — explicitly
> excluding password changes. Require the post-compromise action to occur after the first successful
> sign-on.*

**Before saving:** apply both tuning suggestions the AI offers:
- Raise `invalid_creds_count >= 1` to `>= 3`
- Add `AND mfa_failure_count >= 1` to the WHERE clause
- Change the schedule from 24 hours to 5 minutes (for the demo)

**When attaching the Workflow:** select "Okta Credential Stuffing Response" from the Workflow
picker. The `script_id` input is pre-filled — do not change it.

### Step 2 — The Alert Fires

After saving the rule, navigate to Security → Alerts. The jsmith alert should appear within
5 minutes (the rule's schedule). Show the alert card:

- `user.name: jsmith@example.com` — the victim
- `source.ip: 203.0.113.66` — the attacker
- The four counters: `failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`
- The timestamps: `first_success_ts` and `first_post_ts`

"Every field in this alert was computed by the ES|QL rule. The analyst doesn't need to pivot to
Okta to understand what happened — the full attack chain is summarised in a single alert."

### Step 3 — The Case (Workflow)

Navigate to Security → Cases. The Workflow ran automatically when the alert fired. Walk the
case timeline from top to bottom:

1. **Case created** — title includes the victim's email. Severity: Critical.
2. **Status: in-progress** — automated remediation is underway.
3. **Alert attached** — the triggering alert is linked; the analyst can click through.
4. **Observables** — the attacker IP and compromised email appear as IOCs in the case header.
5. **AI Analysis comment** — Claude's summary of the four-stage attack chain and recommended
   next steps.
6. **Automated Remediation Complete comment** — names the host, the blocked IP, and the
   disabled account. The script output is embedded.
7. **Status: closed** — the full lifecycle completed automatically.

"This is nine automated steps in under 30 seconds. A human analyst would have spent 15-20 minutes
doing this manually: opening a ticket, noting the IOCs, pivoting to Fleet, executing a response
action, documenting the outcome, closing the ticket. The Workflow does it all and leaves a complete
audit trail."

---

## 7. Q&A

### Detection and ES|QL

**Q: The AI wrote the query — how do I know it's correct?**

The Preview Results panel is the answer. Before saving, you can see exactly which (user, IP) pairs
satisfy the rule against live data. If the preview shows actors you don't expect, you read the
ES|QL, understand why, and either tighten the thresholds or the action list. The AI generates,
the analyst validates. No different from reviewing a PR.

**Q: Could an attacker avoid this rule by spreading attempts across different IPs?**

Yes — the rule groups by `(user.name, source.ip)` pair. A credential stuffing campaign that rotates
IPs per attempt would not accumulate enough failures at one IP to trigger. In practice, commercial
stuffing tools often use IP-rotating proxies. The counter is: complement this rule with a separate
rule that groups only by `user.name` (ignoring IP) with a higher failure threshold. The two rules
cover different attacker profiles.

**Q: Why ES|QL and not EQL sequences or threshold rules?**

EQL sequences require knowing the exact number of events in order (e.g. A → B → C → D). Stuffing
campaigns fire dozens of attempts — sequences can't express "at least 3 failures." Threshold rules
alert on a single counter (e.g. "more than 5 failed logins") but cannot require multiple
conditions simultaneously. ES|QL aggregation rules compute all four counters in one pass and fire
only when all thresholds are met — that combination is only possible with ES|QL.

**Q: What if the post-compromise event happens days later?**

The 24-hour lookback window handles this: if the post-compromise action lands more than 24 hours
after the last stuffing attempt, the stuffing events age out and the rule doesn't fire. For a more
durable detection, increase the lookback to 72 hours and raise the failure threshold accordingly
to manage false-positive rates. The trade-off is: longer windows catch slow attackers but increase
alert volume on noisy tenants.

**Q: What Okta data does this require? Does it need the Okta integration configured?**

Yes — the Elastic Okta integration ingests Okta system log events via the Okta API and writes
them to `logs-okta.system-default`. The ingest pipeline performs the field mapping that makes
`user.name`, `source.ip`, `event.action`, and `event.outcome` available for the rule to query.
Without the integration, the raw Okta webhook events would arrive with native field names and
the rule's field references would not resolve.

### Workflow and Automation

**Q: How does the Workflow know which endpoint to run the script on?**

It uses the Elastic Entity Store — a built-in feature of Elastic Security 9.x that correlates
identities across data sources. The `find_jsmith_entity` step queries the entity store v2 index
for the Windows host associated with the Okta actor's username (derived by stripping the domain
from the email address). The entity store populates the `host.name` field once the Windows System
integration has collected interactive logon events (Windows Security event 4624) for that user.
A second step (`find_agent`) then looks up the Fleet agent ID for that specific hostname. This
avoids the naive approach of picking the first Windows agent and instead pinpoints the exact
endpoint the identity was active on.

**Q: What if the Windows agent is offline when the Workflow runs?**

The `find_agent` step would return an empty `items` array. `steps.find_agent.output.items[0].id`
would be null, and the `run_script` step would fail. The case is still created with the alert and
observables attached — the AI analysis comment and the case lifecycle (open → in-progress → closed)
still run. Only the Runscript step fails silently. In production, add a conditional step after
`find_agent` to check `items | length > 0` before attempting remediation and add a comment
explaining the endpoint was unreachable.

**Q: Does the AI analysis step require a specific model or connector?**

No. The `ai.prompt` step uses whichever AI connector is configured in Kibana > Stack Management >
Connectors. Any connector works: Anthropic, OpenAI, Azure OpenAI, Gemini, Amazon Bedrock. The
`connector-id` in the YAML references the connector's display name. If the connector is not
configured or unavailable, that step fails and the Workflow continues — the other eight steps
complete normally.

**Q: Can the Workflow be triggered manually, not just by a rule?**

Yes. Workflows can also be triggered manually from a case or an alert via the Actions menu.
The same nine steps run. This is useful for re-running remediation against an alert that was
created before the Workflow was attached to the rule.

### Runscript and Remediation

**Q: This blocks the IP at the Windows Firewall — does that actually stop anything?**

For the demo, it demonstrates the Runscript mechanism end-to-end. For the real-world version of
this attack, the meaningful remediation is suspending the Okta account and terminating active
sessions via the Okta Management API (`POST /api/v1/users/{id}/lifecycle/suspend` and
`DELETE /api/v1/users/{id}/sessions`). The PowerShell script includes these as comments showing
exactly where you would add those calls. The Windows Firewall block is a secondary containment
action for any lateral movement the attacker might attempt from the compromised session.

**Q: How is the script content kept secure? Can an attacker modify it?**

Scripts in the Elastic Defend Script Library are stored encrypted at rest in Elasticsearch.
They are retrieved over the Kibana API using the UUID — only users with the `run_script`
privilege can invoke them. The Elastic Agent verifies the script's integrity before execution.
The Workflow holds the UUID, not the script content, so there is nothing sensitive in the
Workflow definition itself.

**Q: What if the script fails — does it break the Workflow?**

The `remediate` step (`kibana.request` to `run_script`) is an async operation: Kibana queues the
action to the agent and returns immediately. If the agent is online, the script runs and the output
is captured. The Workflow does not wait for the script to complete before writing the remediation
comment — it writes the comment based on the queued action. The actual output appears in
Response Actions History independently. If the agent is offline, the action queues and runs when
the agent reconnects.

**Q: Does this require Elastic Defend (EDR) on the endpoint?**

Yes — `run_script` is a response action specific to the Elastic Defend agent policy. The endpoint
must have Elastic Defend installed and enrolled in a policy that has response actions enabled.
In the demo, this is handled by `configure.sh` via the setup-fleet-policy and Elastic Defend
configuration scripts that run as part of `terraform apply`.

### Licensing and Scale

**Q: What license does this require?**

The full demo uses Elastic Security with an Enterprise subscription:
- AI rule creation (Agent Builder): requires an AI connector configured in Kibana, included in all tiers
- Workflows: generally available from Elastic Security 9.4, requires Platinum or Enterprise
- Script Library and Runscript response action: Elastic Defend GA 9.4, requires Enterprise
- Cases and Observables: available from Essentials tier upward

**Q: Will this scale to a real Okta tenant with thousands of events per day?**

ES|QL aggregation rules are designed for high-cardinality data. The rule groups by `(user.name,
source.ip)` — each unique pair is processed independently. The rule's lookback window and schedule
determine how much data is scanned per run: 24-hour lookback at 5-minute intervals means each run
queries the last 24 hours. For a large tenant (millions of Okta events/day), this is a full-index
scan on every run. Tune the lookback to match your stuffing detection window (typically 1-4 hours
is enough), and use `source.ip` filtering via a threat intelligence lookup to pre-filter known-good
IPs before the aggregation.
