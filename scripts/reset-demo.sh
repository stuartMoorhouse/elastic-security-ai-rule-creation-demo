#!/usr/bin/env bash
#
# reset-demo.sh
#
# Run on the operator's machine between demo takes. Uses the Kibana/
# Elasticsearch APIs (credentials from ./shared/env.json, written by
# configure.sh) to clean up the previous take's alerts and cases so the next
# run of demo/simulate-lolbin-chain.ps1 starts from a clean slate.
#
# This script runs on the operator's machine, NOT the VM - it cannot execute
# simulate-lolbin-chain.ps1 itself. Re-triggering the simulation for the next
# take is left as a manual RDP step (printed at the end).
#
# Remote remediation via Fleet's endpoint "runscript" response action is
# intentionally NOT automated here: as of this writing that API surface is
# new (Elastic Defend GA 9.4) and its exact request schema should be verified
# against the Kibana API reference for the deployed stack version before
# scripting against it. Manual "run remediate.ps1 via runscript" instructions
# are printed instead - see the checklist at the end.
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
# 3. Manual next-take instructions
# --------------------------------------------------------------------------
step "Next steps for the next take"

cat <<EOF

  Alerts and cases from the previous take have been reset (see above).

  Remaining manual steps for the next take:

  1. RDP to the VM's public IP (see 'terraform output vm_public_ip').
  2. (Optional, if the previous run's simulated processes/persistence key are
     still present) In Kibana, select the endpoint and run:
       runscript --script="remediate.ps1"
     to clean the VM via the Script library before re-triggering.
  3. On the VM, re-run:
       demo/simulate-lolbin-chain.ps1
     to generate a fresh process tree for the next take.

EOF

log "reset-demo.sh completed successfully."
