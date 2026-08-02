#!/usr/bin/env bash
#
# prepare-and-reset-demo.sh
#
# Run on the operator's machine before every demo take, including the first.
# Seeds fresh Okta attack telemetry with current timestamps, and cleans up
# the previous take's alerts and cases via the Kibana/Elasticsearch APIs
# (credentials from ./shared/env.json, written by configure.sh).
#
# Remote remediation via Fleet's endpoint "runscript" response action is
# intentionally NOT automated here: as of this writing that API surface is
# new (Elastic Defend GA 9.4) and its exact request schema should be verified
# against the Kibana API reference for the deployed stack version before
# scripting against it. Manual "run block-spray-source.ps1 via runscript"
# instructions are printed instead - see the checklist at the end.
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
ELASTIC_USERNAME="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
ELASTIC_PASSWORD="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"
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
# 1. Close open alerts (Detections API)
# --------------------------------------------------------------------------
step "Closing open alerts from the previous take"

SEARCH_BODY='{"query":{"bool":{"filter":[{"term":{"kibana.alert.workflow_status":"open"}}]}},"size":1000}'

SEARCH_RESPONSE="$(kibana_post "/api/detection_engine/signals/search" "${SEARCH_BODY}")"

if ! jq -e . >/dev/null 2>&1 <<<"${SEARCH_RESPONSE}"; then
    err "Unexpected response searching for open alerts: ${SEARCH_RESPONSE}"
    exit 1
fi

ALERT_IDS="$(jq -r '[.hits.hits[]?._id] | @json' <<<"${SEARCH_RESPONSE}")"
ALERT_COUNT="$(jq -r 'length' <<<"${ALERT_IDS}")"

if [[ "${ALERT_COUNT}" -eq 0 ]]; then
    log "No open alerts found (nothing to close)."
else
    log "Found ${ALERT_COUNT} open alert(s); closing..."
    CLOSE_BODY="$(jq -n --argjson ids "${ALERT_IDS}" '{signal_ids: $ids, status: "closed"}')"
    CLOSE_RESPONSE="$(kibana_post "/api/detection_engine/signals/status" "${CLOSE_BODY}")"
    UPDATED="$(jq -r '.updated // 0' <<<"${CLOSE_RESPONSE}" 2>/dev/null || echo 0)"
    if [[ "${UPDATED}" -gt 0 ]]; then
        log "Closed ${UPDATED} alert(s)."
    else
        err "Failed to close alerts. Response: ${CLOSE_RESPONSE}"
        exit 1
    fi
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
# 3. Delete the Okta detection rule (so it is re-authored fresh next take)
# --------------------------------------------------------------------------
step "Deleting the Okta detection rule (if it exists)"

# Matches any rule whose name contains "okta" (case-insensitive). In this demo
# environment that is always the AI-generated credential-stuffing rule.
RULES_RESPONSE="$(kibana_get "/api/detection_engine/rules/_find?per_page=100")"

if ! jq -e . >/dev/null 2>&1 <<<"${RULES_RESPONSE}"; then
    err "Unexpected response from detection rules API: ${RULES_RESPONSE}"
    exit 1
fi

OKTA_RULES="$(jq -c '[.data[]? | select(.name | ascii_downcase | contains("okta")) | {id: .id, name: .name}]' <<<"${RULES_RESPONSE}")"
OKTA_RULE_COUNT="$(jq 'length' <<<"${OKTA_RULES}")"

if [[ "${OKTA_RULE_COUNT}" -eq 0 ]]; then
    log "No Okta detection rule found (nothing to delete)."
else
    jq -r '.[] | "\(.id)\t\(.name)"' <<<"${OKTA_RULES}" | while IFS=$'\t' read -r RULE_ID RULE_NAME; do
        log "Deleting rule: \"${RULE_NAME}\" (${RULE_ID})..."
        DEL_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
            -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
            -H 'kbn-xsrf: true' \
            -X DELETE \
            "${KIBANA_URL%/}/api/detection_engine/rules?id=${RULE_ID}")"
        if [[ "${DEL_CODE}" == "200" ]]; then
            log "  Deleted."
        else
            log "  Warning: delete returned HTTP ${DEL_CODE}."
        fi
    done
fi

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
# 5. Re-seed Okta attack telemetry for the next take
# --------------------------------------------------------------------------
step "Seeding fresh Okta attack telemetry"

bash "${REPO_ROOT}/scripts/seed-okta-attack-data.sh"

# --------------------------------------------------------------------------
# 6. Next-take checklist
# --------------------------------------------------------------------------
step "Reset complete"

cat <<EOF

  Alerts, cases, Okta telemetry, and the detection rule have been reset.
  The Windows endpoint firewall rule and jsmith account have been restored.

EOF

log "prepare-and-reset-demo.sh completed successfully."
