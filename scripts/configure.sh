#!/usr/bin/env bash
#
# configure.sh
#
# Run after `terraform apply`, from the operator's machine. Reads Terraform
# outputs, writes the values needed by the other demo scripts into
# ./shared/env.json, verifies Kibana and Fleet are reachable/healthy, and
# prints the manual steps that remain (per .claude/spec/spec.md, these are
# intentionally NOT automated by Terraform).
#
# Safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"
ENV_JSON="${REPO_ROOT}/shared/env.json"
CONFIG_DIR="${REPO_ROOT}/config"
FLEET_POLICY_PAYLOAD="${CONFIG_DIR}/fleet-agent-policy-payload.json"

FLEET_POLL_INTERVAL_SECS=15
FLEET_POLL_TIMEOUT_SECS=300

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not found on PATH."; exit 1; }
}

require_cmd terraform
require_cmd jq
require_cmd curl

# --------------------------------------------------------------------------
# 1. Read Terraform outputs
# --------------------------------------------------------------------------
step "Reading Terraform outputs"

if [[ ! -d "${TF_DIR}" ]]; then
    err "Terraform directory not found at ${TF_DIR}."
    exit 1
fi

if ! TF_OUTPUT_JSON="$(terraform -chdir="${TF_DIR}" output -json 2>/tmp/configure_tf_err.$$)"; then
    err "Failed to read Terraform outputs. Has 'terraform apply' been run successfully in ${TF_DIR}?"
    err "$(cat /tmp/configure_tf_err.$$ 2>/dev/null)"
    rm -f /tmp/configure_tf_err.$$
    exit 1
fi
rm -f /tmp/configure_tf_err.$$

extract_output() {
    local key="$1"
    jq -r --arg k "$key" '.[$k].value // empty' <<<"${TF_OUTPUT_JSON}"
}

KIBANA_URL="$(extract_output kibana_url)"
ELASTICSEARCH_URL="$(extract_output elasticsearch_url)"
ELASTIC_USERNAME="$(extract_output elastic_username)"
ELASTIC_PASSWORD="$(extract_output elastic_password)"

MISSING=()
[[ -z "${KIBANA_URL}" ]] && MISSING+=("kibana_url")
[[ -z "${ELASTICSEARCH_URL}" ]] && MISSING+=("elasticsearch_url")
[[ -z "${ELASTIC_USERNAME}" ]] && MISSING+=("elastic_username")
[[ -z "${ELASTIC_PASSWORD}" ]] && MISSING+=("elastic_password")

if (( ${#MISSING[@]} > 0 )); then
    err "The following Terraform outputs are missing or empty: ${MISSING[*]}"
    err "Check terraform/outputs.tf and re-run 'terraform apply'."
    exit 1
fi

log "Kibana URL:        ${KIBANA_URL}"
log "Elasticsearch URL: ${ELASTICSEARCH_URL}"
log "(Credentials read successfully - not printed to stdout/logs.)"

# --------------------------------------------------------------------------
# 2. Write ./shared/env.json (merge, don't clobber unrelated keys)
# --------------------------------------------------------------------------
step "Writing ${ENV_JSON}"

mkdir -p "$(dirname "${ENV_JSON}")"
if [[ ! -f "${ENV_JSON}" ]]; then
    echo '{}' > "${ENV_JSON}"
fi

TMP_ENV_JSON="$(mktemp)"
jq \
    --arg kibana_url "${KIBANA_URL}" \
    --arg elasticsearch_url "${ELASTICSEARCH_URL}" \
    --arg elastic_username "${ELASTIC_USERNAME}" \
    --arg elastic_password "${ELASTIC_PASSWORD}" \
    '.kibana_url = $kibana_url
     | .elasticsearch_url = $elasticsearch_url
     | .elastic_username = $elastic_username
     | .elastic_password = $elastic_password
     | .infra_ready = true' \
    "${ENV_JSON}" > "${TMP_ENV_JSON}"
mv "${TMP_ENV_JSON}" "${ENV_JSON}"
chmod 600 "${ENV_JSON}"
log "Wrote Kibana/Elasticsearch endpoints and credentials to ${ENV_JSON} (mode 600, not printed above)."

# --------------------------------------------------------------------------
# 3. Verify Kibana is reachable
# --------------------------------------------------------------------------
step "Verifying Kibana is reachable"

KIBANA_STATUS_CODE="$(curl -s -o /tmp/configure_kibana_status.$$ -w '%{http_code}' \
    -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    -H 'kbn-xsrf: true' \
    "${KIBANA_URL%/}/api/status" || true)"

if [[ "${KIBANA_STATUS_CODE}" != "200" ]]; then
    err "Kibana at ${KIBANA_URL} did not respond with HTTP 200 to an authenticated GET /api/status (got: '${KIBANA_STATUS_CODE:-no response}')."
    err "Check that the deployment finished starting, the URL is correct, and the elastic user credentials are valid."
    rm -f /tmp/configure_kibana_status.$$
    exit 1
fi
rm -f /tmp/configure_kibana_status.$$
log "Kibana is reachable and authenticated (HTTP 200 from /api/status)."

# --------------------------------------------------------------------------
# 4. Poll Fleet for a healthy agent on the demo policy
# --------------------------------------------------------------------------
step "Waiting for the Elastic Agent to show healthy in Fleet (up to ${FLEET_POLL_TIMEOUT_SECS}s)"

if [[ ! -f "${FLEET_POLICY_PAYLOAD}" ]]; then
    err "Expected fleet agent policy payload not found at ${FLEET_POLICY_PAYLOAD}."
    exit 1
fi
POLICY_NAME="$(jq -r '.name' "${FLEET_POLICY_PAYLOAD}")"
log "Looking for agent policy named '${POLICY_NAME}'..."

kibana_get() {
    local path="$1"
    curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' "${KIBANA_URL%/}${path}"
}

POLICY_ID="$(kibana_get "/api/fleet/agent_policies?perPage=100" \
    | jq -r --arg name "${POLICY_NAME}" '.items[]? | select(.name == $name) | .id' | head -n1)"

if [[ -z "${POLICY_ID}" ]]; then
    err "No Fleet agent policy named '${POLICY_NAME}' was found in Kibana yet."
    err "This policy is expected to be created by the Terraform null_resource Fleet-enrollment step - re-check 'terraform apply' output."
    exit 1
fi
log "Found agent policy '${POLICY_NAME}' (id: ${POLICY_ID})."

DEADLINE=$(( $(date +%s) + FLEET_POLL_TIMEOUT_SECS ))
AGENT_HEALTHY=false
while (( $(date +%s) < DEADLINE )); do
    AGENTS_JSON="$(kibana_get "/api/fleet/agents?kuery=$(jq -rn --arg pid "${POLICY_ID}" '"policy_id:\"" + $pid + "\""' | sed 's/ /%20/g')" || true)"
    STATUS="$(jq -r '.items[0].status // empty' <<<"${AGENTS_JSON}" 2>/dev/null || true)"

    if [[ "${STATUS}" == "online" || "${STATUS}" == "healthy" ]]; then
        AGENT_HEALTHY=true
        break
    fi

    log "  agent status: ${STATUS:-not enrolled yet} (retrying in ${FLEET_POLL_INTERVAL_SECS}s)..."
    sleep "${FLEET_POLL_INTERVAL_SECS}"
done

if [[ "${AGENT_HEALTHY}" != true ]]; then
    err "No agent reached healthy ('online') status on policy '${POLICY_NAME}' within ${FLEET_POLL_TIMEOUT_SECS}s."
    err "Check Fleet > Agents in Kibana and the VM's custom_script_extension output for enrollment errors."
    exit 1
fi
log "Elastic Agent is healthy on policy '${POLICY_NAME}'."

TMP_ENV_JSON="$(mktemp)"
jq '.config_ready = true' "${ENV_JSON}" > "${TMP_ENV_JSON}"
mv "${TMP_ENV_JSON}" "${ENV_JSON}"
chmod 600 "${ENV_JSON}"

# --------------------------------------------------------------------------
# 5. Manual steps checklist
# --------------------------------------------------------------------------
step "Manual steps remaining (not automated by Terraform - see README.md)"

cat <<EOF

  1. Install Elastic Defend on the VM via Kibana Fleet (Fleet > Agents > select
     the agent > Add integration > Elastic Defend).

  2. Author the AI/ES|QL detection rule using Agent Builder's AI rule creation.
     Prompt and MITRE mapping reference: ${CONFIG_DIR}/ai-detection-rule-prompt.md

  3. Author the alert-triggered Workflow (create case -> attach alerts ->
     AI analysis comment -> isolate host -> summary comment).
     Reference: ${CONFIG_DIR}/workflow-definition-reference.md

  4. Upload demo/remediate.ps1 to the Elastic Defend Script library so it can
     be run via a 'runscript' response action from an alert.

  5. RDP to the VM and run demo/simulate-lolbin-chain.ps1 to trigger the demo.

See README.md for the full demo flow and acceptance criteria.
EOF

log ""
log "configure.sh completed successfully."
