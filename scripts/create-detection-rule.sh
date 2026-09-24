#!/usr/bin/env bash
#
# create-detection-rule.sh
#
# Creates the Okta credential stuffing ES|QL detection rule with alert
# suppression, then binds the deployed workflow to it by injecting the
# rule UUID into the workflow YAML trigger (ruleId field). No manual
# Kibana steps required.
#
# Idempotent: if the rule already exists, skips creation but still
# re-binds the workflow (safe to re-run after a workflow redeployment).
#
# Reads credentials from shared/env.json (written by configure.sh).
# Saves the rule UUID to state/rule-id.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"
ESQL_FILE="${SCRIPT_DIR}/okta-credential-stuffing.esql"
STATE_DIR="${REPO_ROOT}/state"
RULE_ID="okta-credential-stuffing"

log() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh after 'terraform apply' first."
    exit 1
fi

KIBANA_URL="$(jq -r '.kibana_url // empty' "${ENV_JSON}")"
U="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
P="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"

if [[ -z "${KIBANA_URL}" || -z "${U}" || -z "${P}" ]]; then
    err "Missing Kibana credentials in ${ENV_JSON}. Run ./scripts/configure.sh first."
    exit 1
fi

# --------------------------------------------------------------------------
# 1. Create rule (idempotent)
# --------------------------------------------------------------------------
EXISTING_RESP="$(curl -s -u "${U}:${P}" -H 'kbn-xsrf: true' \
    "${KIBANA_URL%/}/api/detection_engine/rules?rule_id=${RULE_ID}")"
RULE_UUID="$(jq -r '.id // empty' <<<"${EXISTING_RESP}" 2>/dev/null || true)"

if [[ -n "${RULE_UUID}" && "${RULE_UUID}" != "null" ]]; then
    log "Detection rule already exists (id: ${RULE_UUID}) — skipping creation."
else
    if [[ ! -f "${ESQL_FILE}" ]]; then
        err "ES|QL query file not found: ${ESQL_FILE}"
        exit 1
    fi
    # Strip // comment lines and blank lines
    ESQL_QUERY="$(grep -v '^\s*//' "${ESQL_FILE}" | grep -v '^\s*$')"

    log "Creating detection rule '${RULE_ID}'..."

    RULE_RESP="$(curl -s -X POST "${KIBANA_URL%/}/api/detection_engine/rules" \
        -u "${U}:${P}" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' \
        -d "$(jq -n \
            --arg rule_id "${RULE_ID}" \
            --arg query "${ESQL_QUERY}" \
            '{
                rule_id: $rule_id,
                type: "esql",
                language: "esql",
                name: "Okta Credential Stuffing — Account Takeover",
                description: "Detects credential stuffing and account takeover in Okta: same user and source IP with ≥3 INVALID_CREDENTIALS failures, MFA failures, a successful login, and a post-compromise action. All four stages must be present simultaneously.",
                risk_score: 73,
                severity: "high",
                query: $query,
                interval: "5m",
                from: "now-24h",
                enabled: true,
                tags: ["Okta", "Credential Stuffing", "T1110.004", "T1078", "T1098", "Demo"],
                alert_suppression: {
                    group_by: ["okta.actor.alternate_id", "okta.client.ip"],
                    duration: {value: 1, unit: "h"},
                    missing_fields_strategy: "suppress"
                }
            }')")"

    RULE_UUID="$(jq -r '.id // empty' <<<"${RULE_RESP}" 2>/dev/null || true)"
    if [[ -z "${RULE_UUID}" || "${RULE_UUID}" == "null" ]]; then
        err "Failed to create detection rule. Response:"
        jq . <<<"${RULE_RESP}" >&2
        exit 1
    fi

    log "Detection rule created."
    log "  UUID: ${RULE_UUID}"
    log "  URL:  ${KIBANA_URL%/}/app/security/rules/id/${RULE_UUID}"
fi

mkdir -p "${STATE_DIR}"
echo "${RULE_UUID}" > "${STATE_DIR}/rule-id"

# --------------------------------------------------------------------------
# 2. Bind rule UUID into workflow trigger
#
# The workflow YAML trigger supports an optional ruleId field that scopes
# it to fire only for alerts from this specific rule. We inject the rule
# UUID here every time (idempotent — same UUID, same result).
# --------------------------------------------------------------------------
WORKFLOW_ID_FILE="${STATE_DIR}/workflow-id"
WORKFLOW_DEF="${REPO_ROOT}/terraform/workflows/okta-credential-stuffing.yaml"
SCRIPT_ID_FILE="${STATE_DIR}/script-id"

if [[ ! -f "${WORKFLOW_ID_FILE}" ]]; then
    log ""
    log "Warning: state/workflow-id not found — skipping workflow trigger binding."
    log "  Run 'terraform apply' to deploy the workflow, then re-run this script."
    exit 0
fi

WORKFLOW_ID="$(tr -d '[:space:]' < "${WORKFLOW_ID_FILE}")"
SCRIPT_UUID=""
[[ -f "${SCRIPT_ID_FILE}" ]] && SCRIPT_UUID="$(tr -d '[:space:]' < "${SCRIPT_ID_FILE}")"

UPDATED_YAML="$(sed "s/REPLACE_WITH_SCRIPT_LIBRARY_UUID/${SCRIPT_UUID}/g" "${WORKFLOW_DEF}" \
    | sed "s|  - type: alert|  - type: alert\n    ruleId: ${RULE_UUID}|")"

UPDATE_RESP="$(printf '%s' "${UPDATED_YAML}" | jq -Rs '{"yaml": .}' | \
    curl -s -u "${U}:${P}" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -X PUT "${KIBANA_URL%/}/api/workflows/workflow/${WORKFLOW_ID}" \
    -d @- 2>/dev/null)"

if jq -e '.valid == true' <<<"${UPDATE_RESP}" >/dev/null 2>&1; then
    log "Workflow trigger bound to rule ${RULE_UUID} (workflow: ${WORKFLOW_ID})."
else
    log "Warning: workflow trigger binding may have failed. Response: ${UPDATE_RESP}"
    log "  Check state/workflow-id is current and 'terraform apply' has completed."
fi
