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
VM_PUBLIC_IP="$(extract_output vm_public_ip)"
VM_ADMIN_USERNAME="$(extract_output vm_admin_username)"
VM_ADMIN_PASSWORD="$(extract_output vm_admin_password)"

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

CURL_AUTH_CONF="$(mktemp)"
chmod 600 "$CURL_AUTH_CONF"
printf 'user = "%s:%s"\n' "$ELASTIC_USERNAME" "$ELASTIC_PASSWORD" > "$CURL_AUTH_CONF"
trap 'rm -f "$CURL_AUTH_CONF"' EXIT

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
    --arg vm_public_ip "${VM_PUBLIC_IP}" \
    --arg vm_admin_username "${VM_ADMIN_USERNAME}" \
    --arg vm_admin_password "${VM_ADMIN_PASSWORD}" \
    '.kibana_url = $kibana_url
     | .elasticsearch_url = $elasticsearch_url
     | .elastic_username = $elastic_username
     | .elastic_password = $elastic_password
     | .vm_public_ip = $vm_public_ip
     | .vm_admin_username = $vm_admin_username
     | .vm_admin_password = $vm_admin_password
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
    -K "$CURL_AUTH_CONF" \
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
# 3b. Verify entity store v2 is running
#
# Elastic Security 9.x auto-initialises entity store v2 on deployment creation.
# Data lands in .entities.v2.latest.security_default-* (all entity types in one
# index). There is no Kibana API to "enable" it — we just confirm the index
# exists and has documents before proceeding.
# --------------------------------------------------------------------------
step "Verifying entity store v2"

ENTITY_INDEX_COUNT="$(curl -s \
    -K "$CURL_AUTH_CONF" \
    "${ELASTICSEARCH_URL%/}/.entities.v2.latest.security_default-*/_count" \
    | jq -r '.count // 0' 2>/dev/null || echo 0)"

if [[ "${ENTITY_INDEX_COUNT}" -gt 0 ]]; then
    log "Entity store v2 is running — ${ENTITY_INDEX_COUNT} entities indexed."
else
    log "Warning: entity store v2 index appears empty or not yet created."
    log "Entity analytics may need a few minutes to initialise after fresh deployment."
fi

# --------------------------------------------------------------------------
# 4a. Create demo_reset role and user (for clearing restricted workflow indices)
#
# The .workflows-executions index is a restricted Elasticsearch index.
# Even the elastic superuser cannot write/delete from it without a role that
# explicitly sets allow_restricted_indices: true. We create a dedicated role
# and user here so that prepare-and-reset-demo.sh can purge failed workflow
# run history without manual intervention.
# --------------------------------------------------------------------------
step "Creating demo_reset role and user (workflow history cleanup)"

curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X PUT "${ELASTICSEARCH_URL%/}/_security/role/demo_reset_workflows" \
    -d '{
      "indices": [{
        "names": [".workflows-executions", ".workflows-step-executions"],
        "privileges": ["all"],
        "allow_restricted_indices": true
      }]
    }' > /dev/null

DEMO_RESET_PASS="DemoReset-$(openssl rand -hex 8)"
curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X PUT "${ELASTICSEARCH_URL%/}/_security/user/demo_reset_user" \
    -d "{\"password\":\"${DEMO_RESET_PASS}\",\"roles\":[\"demo_reset_workflows\"]}" > /dev/null

# Persist to env.json so prepare-and-reset-demo.sh can read it
TMP_ENV_JSON="$(mktemp)"
jq --arg p "${DEMO_RESET_PASS}" '.demo_reset_password = $p' "${ENV_JSON}" > "${TMP_ENV_JSON}"
mv "${TMP_ENV_JSON}" "${ENV_JSON}"
log "demo_reset_user created and credentials saved to env.json."

# --------------------------------------------------------------------------
# 4. Ensure .logs-endpoint.actions-default data stream exists
#    (required for response actions / run_script; not auto-created on new deployments)
# --------------------------------------------------------------------------
step "Initialising endpoint response-actions data stream"

ACTIONS_DS_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
    -K "$CURL_AUTH_CONF" \
    "${ELASTICSEARCH_URL%/}/.logs-endpoint.actions-default/_count" || true)"

if [[ "${ACTIONS_DS_STATUS}" == "200" ]]; then
    log ".logs-endpoint.actions-default already exists — skipping."
else
    HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
        -K "$CURL_AUTH_CONF" \
        -H 'Content-Type: application/json' \
        -X PUT "${ELASTICSEARCH_URL%/}/_data_stream/.logs-endpoint.actions-default" || true)"
    if [[ "${HTTP_CODE}" == "200" ]]; then
        log "Created .logs-endpoint.actions-default (HTTP ${HTTP_CODE})."
    else
        log "Warning: could not create .logs-endpoint.actions-default (HTTP ${HTTP_CODE}) — run_script response actions may not work."
    fi
fi

# --------------------------------------------------------------------------
# 5. Install the Okta integration package (registers the ingest pipeline)
# --------------------------------------------------------------------------
step "Installing Okta integration package"

OKTA_INFO="$(curl -s -K "$CURL_AUTH_CONF" \
    -H 'kbn-xsrf: true' \
    "${KIBANA_URL%/}/api/fleet/epm/packages/okta")"

OKTA_VERSION="$(jq -r '.item.version // .response.version // empty' <<<"${OKTA_INFO}")"
OKTA_STATUS="$(jq -r  '.item.status  // .response.status  // "not_installed"' <<<"${OKTA_INFO}")"

if [[ -z "${OKTA_VERSION}" ]]; then
    err "Could not determine Okta integration version from Fleet API. Response: ${OKTA_INFO}"
    exit 1
fi

log "Okta integration version: ${OKTA_VERSION} (status: ${OKTA_STATUS})"

if [[ "${OKTA_STATUS}" != "installed" ]]; then
    log "Installing..."
    INSTALL_RESPONSE="$(curl -s -K "$CURL_AUTH_CONF" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -X POST "${KIBANA_URL%/}/api/fleet/epm/packages/okta/${OKTA_VERSION}" \
        -d '{}')"
    if jq -e '.items // .response' <<<"${INSTALL_RESPONSE}" >/dev/null 2>&1; then
        log "Okta integration installed."
    else
        err "Unexpected response installing Okta integration: ${INSTALL_RESPONSE}"
        exit 1
    fi
else
    log "Okta integration already installed — skipping."
fi

# --------------------------------------------------------------------------
# 6. Poll Fleet for a healthy agent on the demo policy
# --------------------------------------------------------------------------
step "Waiting for the Elastic Agent to show healthy in Fleet (up to ${FLEET_POLL_TIMEOUT_SECS}s)"

# The policy is created by terraform/scripts/setup-fleet-policy.sh with name
# "${var.prefix}-windows-endpoint-policy" (see terraform/fleet_enrollment.tf).
# config/fleet-agent-policy-payload.json is not read by that script, so we
# match by the same suffix here instead of relying on a name that may not
# agree with the deployed var.prefix.
log "Looking for an agent policy matching '*-windows-endpoint-policy'..."

kibana_get() {
    local path="$1"
    curl -s -K "$CURL_AUTH_CONF" -H 'kbn-xsrf: true' "${KIBANA_URL%/}${path}"
}

POLICY_JSON="$(kibana_get "/api/fleet/agent_policies?perPage=100" \
    | jq -r '[.items[]? | select(.name | endswith("-windows-endpoint-policy"))][0] // empty')"
POLICY_ID="$(jq -r '.id // empty' <<<"${POLICY_JSON}")"
POLICY_NAME="$(jq -r '.name // empty' <<<"${POLICY_JSON}")"

if [[ -z "${POLICY_ID}" ]]; then
    err "No Fleet agent policy matching '*-windows-endpoint-policy' was found in Kibana yet."
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

# --------------------------------------------------------------------------
# 6b. Wait for jsmith entity to appear in entity store v2 with a host association
#
# The EntityStoreSeed scheduled task generates 4 Windows Security event 4624
# records for jsmith (logon type 2 / interactive). The System integration
# forwards them to logs-system.security-*; entity store v2 then creates a user
# entity with user.name=jsmith and host.name=secdemo-vm. This is queried via
# Elasticsearch directly — the Kibana entity list API targets v1 indices which
# do not exist in this deployment.
#
# Schema: entity.type="Identity", host.name=<hostname> (flat field, not array).
# --------------------------------------------------------------------------
step "Waiting for jsmith entity (with host) in entity store v2 (up to 5 min)"

ENTITY_FOUND=false
ENTITY_DEADLINE=$(( $(date +%s) + 300 ))
while (( $(date +%s) < ENTITY_DEADLINE )); do
    ENTITY_RESPONSE="$(curl -s \
        -K "$CURL_AUTH_CONF" \
        -H 'Content-Type: application/json' \
        -X POST "${ELASTICSEARCH_URL%/}/.entities.v2.latest.security_default-*/_search" \
        -d '{"size":1,"_source":["user.name","host.name","entity.name"],"query":{"bool":{"must":[{"term":{"user.name":"jsmith"}},{"exists":{"field":"host.name"}}]}}}' || true)"

    ENTITY_TOTAL="$(jq -r '.hits.total.value // 0' <<<"${ENTITY_RESPONSE}" 2>/dev/null || echo 0)"
    if [[ "${ENTITY_TOTAL}" -gt 0 ]]; then
        ENTITY_HOST="$(jq -r '.hits.hits[0]._source.host.name // "?"' <<<"${ENTITY_RESPONSE}" 2>/dev/null || echo "?")"
        log "jsmith entity found in entity store v2 — host: ${ENTITY_HOST}"
        ENTITY_FOUND=true
        break
    fi

    log "  jsmith entity not yet indexed (retrying in 30s)..."
    sleep 30
done

if [[ "${ENTITY_FOUND}" != true ]]; then
    log "Warning: jsmith entity not found within 5 minutes."
    log "The EntityStoreSeed task may still be waiting for the Elastic Agent to start."
    log "Re-run configure.sh in 5-10 minutes, or check Entity Analytics in Kibana."
fi

# --------------------------------------------------------------------------
# 7. Upload remediation script to Elastic Defend Script Library
# --------------------------------------------------------------------------
step "Uploading remediation script to Elastic Defend Script Library"

REMEDIATION_SCRIPT="${REPO_ROOT}/scripts/remediate-okta-compromise.ps1"
STATE_DIR="${REPO_ROOT}/state"
SCRIPT_ID_FILE="${STATE_DIR}/script-id"

if [[ ! -f "${REMEDIATION_SCRIPT}" ]]; then
    err "Remediation script not found at ${REMEDIATION_SCRIPT}."
    exit 1
fi

# Idempotency: delete previous entry if we have a stored ID.
if [[ -f "${SCRIPT_ID_FILE}" ]]; then
    OLD_SCRIPT_ID="$(tr -d '[:space:]' < "${SCRIPT_ID_FILE}")"
    if [[ -n "${OLD_SCRIPT_ID}" ]]; then
        log "Deleting previous script library entry ${OLD_SCRIPT_ID}..."
        DEL_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
            -K "$CURL_AUTH_CONF" \
            -H 'kbn-xsrf: true' \
            -X DELETE \
            "${KIBANA_URL%/}/api/endpoint/scripts_library/${OLD_SCRIPT_ID}" || true)"
        if [[ "${DEL_CODE}" == "200" || "${DEL_CODE}" == "204" ]]; then
            log "  Deleted."
        else
            log "  Could not delete (HTTP ${DEL_CODE}) — may already be gone."
        fi
    fi
    rm -f "${SCRIPT_ID_FILE}"
fi

log "Uploading ${REMEDIATION_SCRIPT}..."
UPLOAD_RESPONSE="$(curl -s \
    -K "$CURL_AUTH_CONF" \
    -H 'kbn-xsrf: true' \
    -F "name=Okta Compromise Remediation" \
    -F "file=@${REMEDIATION_SCRIPT}" \
    -F "fileType=script" \
    -F 'platform=["windows"]' \
    -F "description=Blocks the attacker source IP at the Windows Firewall and disables the compromised local Windows account. Triggered by the Okta credential stuffing detection rule." \
    -F "requiresInput=true" \
    -F 'tags=["remediationAction"]' \
    "${KIBANA_URL%/}/api/endpoint/scripts_library" || true)"

SCRIPT_ID="$(jq -r '.data.id // empty' <<<"${UPLOAD_RESPONSE}" 2>/dev/null || true)"

if [[ -z "${SCRIPT_ID}" ]]; then
    err "Failed to upload remediation script. Response: ${UPLOAD_RESPONSE}"
    exit 1
fi

mkdir -p "${STATE_DIR}"
echo "${SCRIPT_ID}" > "${SCRIPT_ID_FILE}"
log "Script uploaded — ID: ${SCRIPT_ID} (saved to ${SCRIPT_ID_FILE})"

TMP_ENV_JSON="$(mktemp)"
jq --arg sid "${SCRIPT_ID}" '.config_ready = true | .script_id = $sid' "${ENV_JSON}" > "${TMP_ENV_JSON}"
mv "${TMP_ENV_JSON}" "${ENV_JSON}"
chmod 600 "${ENV_JSON}"

# --------------------------------------------------------------------------
# 8. Bind script ID into the deployed workflow
# --------------------------------------------------------------------------
step "Binding script ID into workflow"

WORKFLOW_ID_FILE="${STATE_DIR}/workflow-id"
WORKFLOW_DEF="${REPO_ROOT}/terraform/workflows/okta-credential-stuffing.yaml"

if [[ ! -f "${WORKFLOW_ID_FILE}" ]]; then
    log "Warning: ${WORKFLOW_ID_FILE} not found — skipping workflow update."
    log "Re-run 'terraform apply' to deploy the workflow, then re-run configure.sh."
else
    WORKFLOW_ID="$(tr -d '[:space:]' < "${WORKFLOW_ID_FILE}")"
    UPDATED_YAML="$(sed "s/REPLACE_WITH_SCRIPT_LIBRARY_UUID/${SCRIPT_ID}/g" "${WORKFLOW_DEF}")"

    UPDATE_RESPONSE="$(printf '%s' "${UPDATED_YAML}" | jq -Rs '{"yaml": .}' | \
        curl -s -K "$CURL_AUTH_CONF" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -X PUT "${KIBANA_URL%/}/api/workflows/workflow/${WORKFLOW_ID}" \
        -d @- 2>/dev/null)"

    if jq -e '.id // empty' <<<"${UPDATE_RESPONSE}" >/dev/null 2>&1; then
        log "Workflow ${WORKFLOW_ID} updated — script_id default is now ${SCRIPT_ID}."
    else
        log "Warning: workflow update may have failed. Response: ${UPDATE_RESPONSE}"
    fi
fi

# --------------------------------------------------------------------------
# 9. Create the detection rule
# --------------------------------------------------------------------------
step "Creating Okta detection rule"

bash "${SCRIPT_DIR}/create-detection-rule.sh"

# --------------------------------------------------------------------------
# 10. Final checklist
# --------------------------------------------------------------------------
step "Setup complete"

cat <<EOF

  Setup complete. Run prepare-and-reset-demo.sh to seed fresh Okta attack
  telemetry — the rule fires within 5 minutes and the Workflow creates and
  closes a case automatically.

    ./scripts/prepare-and-reset-demo.sh

  See README.md for the full demo flow.

EOF

log ""
log "configure.sh completed successfully."
