#!/usr/bin/env bash
#
# prepare-and-reset-demo.sh
#
# Resets demo state between takes. Clears alerts, cases, Okta telemetry, and
# previous workflow runs; resets the Windows endpoint; and ensures the detection
# rule exists (disabled). Does NOT seed new Okta data — run seed-okta-attack-data.sh
# separately when you are ready to trigger the rule.
#
# Idempotent: safe to re-run, and safe to run when there is nothing to reset.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not found on PATH."; exit 1; }
}

require_cmd jq
require_cmd curl

HAS_SSHPASS=false
command -v sshpass >/dev/null 2>&1 && HAS_SSHPASS=true

# --------------------------------------------------------------------------
# 0. Load credentials/endpoints from shared/env.json
# --------------------------------------------------------------------------
if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh after 'terraform apply' first."
    exit 1
fi

KIBANA_URL="$(jq -r '.kibana_url // empty' "${ENV_JSON}")"
ELASTICSEARCH_URL="$(jq -r '.elasticsearch_url // empty' "${ENV_JSON}")"
ELASTIC_USERNAME="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
ELASTIC_PASSWORD="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"
DEMO_RESET_PASSWORD="$(jq -r '.demo_reset_password // empty' "${ENV_JSON}")"
INFRA_READY="$(jq -r '.infra_ready // false' "${ENV_JSON}")"
VM_PUBLIC_IP="$(jq -r '.vm_public_ip // empty' "${ENV_JSON}")"
VM_ADMIN_USERNAME="$(jq -r '.vm_admin_username // empty' "${ENV_JSON}")"
VM_ADMIN_PASSWORD="$(jq -r '.vm_admin_password // empty' "${ENV_JSON}")"

if [[ -z "${KIBANA_URL}" || -z "${ELASTIC_USERNAME}" || -z "${ELASTIC_PASSWORD}" || "${INFRA_READY}" != "true" ]]; then
    err "${ENV_JSON} is missing Kibana credentials/endpoint or infra_ready is not true."
    err "Run ./scripts/configure.sh first."
    exit 1
fi

kibana_post() {
    local path="$1" body="$2"
    curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -X POST "${KIBANA_URL%/}${path}" -d "${body}"
}

kibana_patch() {
    local path="$1" body="$2"
    curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -X PATCH "${KIBANA_URL%/}${path}" -d "${body}"
}

kibana_get() {
    local path="$1"
    curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' "${KIBANA_URL%/}${path}"
}

# --------------------------------------------------------------------------
# 0b. Disable the detection rule
#
# The rule stays off until seed-okta-attack-data.sh loads the data and enables
# it, so it never runs against an empty/half-cleared index.
# --------------------------------------------------------------------------
step "Disabling detection rule"

RULE_LOOKUP="$(kibana_get "/api/detection_engine/rules?rule_id=okta-credential-stuffing")"
EXISTING_RULE_UUID="$(jq -r '.id // empty' <<<"${RULE_LOOKUP}" 2>/dev/null || true)"
if [[ -n "${EXISTING_RULE_UUID}" ]]; then
    kibana_post "/api/detection_engine/rules/_bulk_action" \
        "{\"action\":\"disable\",\"ids\":[\"${EXISTING_RULE_UUID}\"]}" >/dev/null
    log "Rule ${EXISTING_RULE_UUID} disabled."
else
    log "Rule not created yet (it will be created disabled below)."
fi

# --------------------------------------------------------------------------
# 1. Delete all alerts from the previous take
#
# Closing alerts is not enough — the ES|QL rule deduplicates by
# (okta.actor.alternate_id, okta.client.ip) and will not create new alerts
# while any prior alert with the same key exists, regardless of status.
# Delete-by-query removes them entirely so the next rule run fires fresh.
# --------------------------------------------------------------------------
step "Deleting alerts from the previous take"

DELETE_RESP="$(curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST "${ELASTICSEARCH_URL%/}/.alerts-security.alerts-default/_delete_by_query?refresh=true&conflicts=proceed" \
    -d '{"query":{"match_all":{}}}')"
DELETED="$(jq -r '.deleted // 0' <<<"${DELETE_RESP}" 2>/dev/null || echo 0)"
if [[ "${DELETED}" -gt 0 ]]; then
    log "Deleted ${DELETED} alert(s)."
else
    log "No alerts to delete (or index empty)."
fi

# --------------------------------------------------------------------------
# 2. List (and close) open cases (Cases API)
# --------------------------------------------------------------------------
step "Reviewing cases created by the previous take"

CASES_RESPONSE="$(kibana_get "/api/cases/_find?status=open&perPage=100")"

if ! jq -e . >/dev/null 2>&1 <<<"${CASES_RESPONSE}"; then
    err "Unexpected response listing open cases: ${CASES_RESPONSE}"
    exit 1
fi

CASE_COUNT="$(jq -r '.cases | length' <<<"${CASES_RESPONSE}" 2>/dev/null || echo 0)"

if [[ "${CASE_COUNT}" -eq 0 ]]; then
    log "No open cases found (nothing to close)."
else
    log "Found ${CASE_COUNT} open case(s):"
    jq -r '.cases[] | "  - \(.id)  \"\(.title)\"  (created: \(.created_at))"' <<<"${CASES_RESPONSE}"

    BULK_BODY="$(jq -c '{cases: [.cases[] | {id: .id, version: .version, status: "closed"}]}' <<<"${CASES_RESPONSE}")"
    UPDATE_RESPONSE="$(kibana_patch "/api/cases" "${BULK_BODY}")"

    if jq -e 'type == "array"' >/dev/null 2>&1 <<<"${UPDATE_RESPONSE}"; then
        log "Closed ${CASE_COUNT} case(s)."
    else
        err "Failed to bulk-close cases; review manually in Kibana Cases UI. Response: ${UPDATE_RESPONSE}"
        log "(Continuing - case listing above is still available for manual review.)"
    fi
fi

# --------------------------------------------------------------------------
# 3. Ensure the detection rule exists
#
# The rule is kept across demo resets (not deleted) so that the workflow
# action attached to it via the Kibana UI is preserved. create-detection-rule.sh
# is idempotent — it skips creation if the rule already exists.
# --------------------------------------------------------------------------
step "Ensuring detection rule exists"

bash "${REPO_ROOT}/scripts/create-detection-rule.sh"

# --------------------------------------------------------------------------
# 4. Reset the Windows endpoint: remove firewall block rule, re-enable jsmith
# --------------------------------------------------------------------------
step "Resetting Windows endpoint (firewall rule + jsmith account)"

MANUAL_RESET_HINT=(
    "  Remove-NetFirewallRule -DisplayName \"Elastic-OktaCompromise-Block-*\" -ErrorAction SilentlyContinue"
    "  Enable-LocalUser -Name jsmith -ErrorAction SilentlyContinue"
)

if [[ -z "${VM_PUBLIC_IP}" || -z "${VM_ADMIN_USERNAME}" || -z "${VM_ADMIN_PASSWORD}" ]]; then
    log "VM credentials not found in env.json — skipping endpoint reset."
elif [[ "${HAS_SSHPASS}" != "true" ]]; then
    log "sshpass not found — skipping automated endpoint reset."
    log "To reset manually, SSH into ${VM_PUBLIC_IP} and run:"
    printf '%s\n' "${MANUAL_RESET_HINT[@]}"
else
    # Pass the two PowerShell commands as a semicolon-joined one-liner to avoid
    # multi-line quoting issues across the SSH boundary. The wildcard pattern
    # Elastic-OktaCompromise-Block-* has no spaces so it needs no quotes in PS.
    PS_CMD='Remove-NetFirewallRule -DisplayName Elastic-OktaCompromise-Block-* -ErrorAction SilentlyContinue; Enable-LocalUser -Name jsmith -ErrorAction SilentlyContinue; Write-Output endpoint-reset-ok'

    SSH_OUT="$(SSHPASS="${VM_ADMIN_PASSWORD}" sshpass -e ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o BatchMode=no \
        "${VM_ADMIN_USERNAME}@${VM_PUBLIC_IP}" \
        "powershell.exe -NoProfile -NonInteractive -Command \"${PS_CMD}\"" 2>&1)" \
        && SSH_OK=true || SSH_OK=false

    if [[ "${SSH_OK}" == "true" ]] && grep -q "endpoint-reset-ok" <<<"${SSH_OUT}"; then
        log "Firewall block rule removed and jsmith account re-enabled."
    else
        log "Warning: endpoint reset via SSH failed or produced unexpected output."
        log "Output: ${SSH_OUT}"
        log "To reset manually, SSH into ${VM_PUBLIC_IP} and run:"
        printf '%s\n' "${MANUAL_RESET_HINT[@]}"
    fi
fi

# --------------------------------------------------------------------------
# 5. Clear Okta demo telemetry
#
# Remove previous take's events so stale data doesn't re-fire the rule
# before the next seed. Targets only the known demo IPs.
# --------------------------------------------------------------------------
step "Clearing Okta demo telemetry"

DEMO_IPS='["203.0.113.66","203.0.113.67","203.0.113.68","203.0.113.69","203.0.113.70","203.0.113.71","198.51.100.20"]'
OKTA_DELETE_RESP="$(curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST "${ELASTICSEARCH_URL%/}/logs-okta.system-default/_delete_by_query?refresh=true&conflicts=proceed" \
    -d "{\"query\":{\"bool\":{\"filter\":[{\"terms\":{\"source.ip\":${DEMO_IPS}}}]}}}")"
OKTA_DELETED="$(jq -r '.deleted // 0' <<<"${OKTA_DELETE_RESP}" 2>/dev/null || echo 0)"
if [[ "${OKTA_DELETED}" -gt 0 ]]; then
    log "Deleted ${OKTA_DELETED} Okta demo event(s)."
else
    log "No Okta demo events to delete."
fi

# --------------------------------------------------------------------------
# 6. Delete previous workflow runs
#
# The Kibana Workflows API has no delete endpoint for executions, so we
# write directly to the backing Elasticsearch indices. We collect finished
# execution IDs, delete their step-level records first, then the parent
# execution documents. In-flight runs (running/pending/waiting) are left intact.
# --------------------------------------------------------------------------
step "Deleting previous workflow run history"

# .workflows-executions is a restricted index — even the elastic superuser
# cannot delete from it without allow_restricted_indices: true. configure.sh
# creates demo_reset_user with that privilege; we use it here.
if [[ -z "${DEMO_RESET_PASSWORD}" ]]; then
    log "Warning: demo_reset_password not in env.json — run configure.sh to provision demo_reset_user."
    log "Skipping workflow run cleanup."
else
    RESET_CREDS="demo_reset_user:${DEMO_RESET_PASSWORD}"

    # Collect all finished execution IDs (up to 1000).
    EXEC_LIST_RESP="$(curl -s -u "${RESET_CREDS}" \
        -H 'Content-Type: application/json' \
        -X POST "${ELASTICSEARCH_URL%/}/.workflows-executions/_search" \
        -d '{"size":1000,"_source":["id"],"query":{"bool":{"must_not":[{"terms":{"status":["running","pending","waiting"]}}]}}}')"
    EXEC_IDS="$(jq -r '[.hits.hits[]._source.id] | @json' <<<"${EXEC_LIST_RESP}" 2>/dev/null || echo '[]')"
    EXEC_COUNT="$(jq -r 'length' <<<"${EXEC_IDS}")"

    if [[ "${EXEC_COUNT}" -eq 0 ]]; then
        log "No previous workflow runs found (nothing to delete)."
    else
        log "Found ${EXEC_COUNT} previous run(s); deleting..."

        # Delete step executions for those runs.
        STEPS_RESP="$(curl -s -u "${RESET_CREDS}" \
            -H 'Content-Type: application/json' \
            -X POST "${ELASTICSEARCH_URL%/}/.workflows-step-executions/_delete_by_query?refresh=true&conflicts=proceed" \
            -d "{\"query\":{\"terms\":{\"executionId\":${EXEC_IDS}}}}")"
        STEPS_DELETED="$(jq -r '.deleted // 0' <<<"${STEPS_RESP}" 2>/dev/null || echo 0)"

        # Delete the parent execution records.
        EXEC_RESP="$(curl -s -u "${RESET_CREDS}" \
            -H 'Content-Type: application/json' \
            -X POST "${ELASTICSEARCH_URL%/}/.workflows-executions/_delete_by_query?refresh=true&conflicts=proceed" \
            -d "{\"query\":{\"terms\":{\"id\":${EXEC_IDS}}}}")"
        EXEC_DELETED="$(jq -r '.deleted // 0' <<<"${EXEC_RESP}" 2>/dev/null || echo 0)"

        log "Deleted ${EXEC_DELETED} execution(s) and ${STEPS_DELETED} step record(s)."
    fi
fi

step "Reset complete"

cat <<EOF

  Alerts, cases, and Okta telemetry have been reset; the detection rule is
  disabled until the seed script enables it.
  The Windows endpoint firewall rule and jsmith account have been restored.
  Previous workflow runs have been removed from the execution history.

  When ready to trigger the demo:
    ./scripts/seed-okta-attack-data.sh

EOF

log "prepare-and-reset-demo.sh completed successfully."
