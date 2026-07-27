#!/bin/bash
################################################################################
# deploy-workflow.sh
#
# Deploys the Okta Credential Stuffing Response workflow to Kibana via the
# Workflows API. Idempotent: deletes the previous workflow (tracked in
# state/workflow-id) before importing the new one.
#
# Called by terraform/workflows.tf as a local-exec provisioner after the
# Elastic Cloud deployment and Azure VM (with Elastic Agent) are ready.
#
# Reads Terraform outputs directly via `terraform output`.
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"
WORKFLOW_DEF="${TERRAFORM_DIR}/workflows/okta-credential-stuffing.yaml"
STATE_DIR="${PROJECT_DIR}/state"
WORKFLOW_ID_FILE="${STATE_DIR}/workflow-id"

log()  { printf '[deploy-workflow] %s\n' "$*"; }
warn() { printf '[deploy-workflow] WARN: %s\n' "$*" >&2; }
err()  { printf '[deploy-workflow] ERROR: %s\n' "$*" >&2; }

# --- Credentials via curl -K (keeps them off the process table) --------------

CURL_AUTH_CONF=""
setup_curl_auth() {
    CURL_AUTH_CONF="$(mktemp)"
    chmod 600 "$CURL_AUTH_CONF"
    printf 'user = "%s:%s"\n' "$1" "$2" > "$CURL_AUTH_CONF"
}
cleanup_curl_auth() { [[ -n "$CURL_AUTH_CONF" ]] && rm -f "$CURL_AUTH_CONF"; }
trap cleanup_curl_auth EXIT

kb() { curl -sSf -K "$CURL_AUTH_CONF" -H "kbn-xsrf: true" "$@"; }
kb_json() { kb -H "Content-Type: application/json" "$@"; }

# =============================================================================
# STEP 1: Read Terraform outputs
# =============================================================================

log "Reading Terraform outputs..."
KIBANA_URL="$(terraform -chdir="$TERRAFORM_DIR" output -raw kibana_url)"
ELASTIC_USER="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_username)"
ELASTIC_PASS="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_password)"

if [[ -z "$KIBANA_URL" || -z "$ELASTIC_USER" || -z "$ELASTIC_PASS" ]]; then
    err "One or more Terraform outputs are empty. Has 'terraform apply' completed?"
    exit 1
fi

KIBANA_URL="${KIBANA_URL%/}"   # strip trailing slash
setup_curl_auth "$ELASTIC_USER" "$ELASTIC_PASS"
log "Kibana: ${KIBANA_URL}"

# =============================================================================
# STEP 2: Delete previous workflow (idempotency)
# =============================================================================

if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    OLD_ID="$(tr -d '[:space:]' < "$WORKFLOW_ID_FILE")"
    if [[ -n "$OLD_ID" ]]; then
        log "Deleting previous workflow ${OLD_ID}..."
        HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
            -K "$CURL_AUTH_CONF" \
            -X DELETE \
            -H "kbn-xsrf: true" \
            "${KIBANA_URL}/api/workflows/workflow/${OLD_ID}" 2>/dev/null)"
        if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]; then
            log "  Deleted."
        else
            warn "  Could not delete (HTTP ${HTTP_CODE}) — may already be gone."
        fi
    fi
    rm -f "$WORKFLOW_ID_FILE"
fi

# =============================================================================
# STEP 3: Import the workflow (POST to create, then PUT to validate/enable)
# =============================================================================

# Substitute script ID placeholder if state/script-id already exists
# (i.e. configure.sh has run before). On first terraform apply the script
# hasn't been uploaded yet — configure.sh will do a second bind pass later.
SCRIPT_ID_FILE="${STATE_DIR}/script-id"
if [[ -f "$SCRIPT_ID_FILE" ]]; then
    SCRIPT_UUID="$(tr -d '[:space:]' < "$SCRIPT_ID_FILE")"
    WORKFLOW_YAML="$(sed "s/REPLACE_WITH_SCRIPT_LIBRARY_UUID/${SCRIPT_UUID}/g" "$WORKFLOW_DEF")"
    log "Script ID ${SCRIPT_UUID} substituted from ${SCRIPT_ID_FILE}"
else
    WORKFLOW_YAML="$(cat "$WORKFLOW_DEF")"
    log "No script ID found yet — placeholder remains (configure.sh will bind it later)."
fi

log "Creating workflow via POST /api/workflows/workflow..."
POST_RESPONSE="$(printf '%s' "${WORKFLOW_YAML}" | jq -Rs '{"yaml": .}' \
    | kb_json -X POST "${KIBANA_URL}/api/workflows/workflow" -d @- 2>/dev/null)"

WORKFLOW_ID="$(jq -r '.id // empty' <<<"$POST_RESPONSE" 2>/dev/null || echo "")"

if [[ -z "$WORKFLOW_ID" ]]; then
    warn "Could not parse workflow ID from POST response:"
    echo "$POST_RESPONSE"
    warn "The workflow may need to be imported manually via the Kibana Workflows UI."
    warn "Workflow YAML is at: ${WORKFLOW_DEF}"
else
    log "Workflow created (ID: ${WORKFLOW_ID}) — validating via PUT..."

    # PUT triggers real schema validation and enables the workflow.
    # POST accepts any YAML silently; PUT returns validationErrors if the schema is wrong.
    PUT_RESPONSE="$(printf '%s' "${WORKFLOW_YAML}" | jq -Rs '{"yaml": .}' \
        | kb_json -X PUT "${KIBANA_URL}/api/workflows/workflow/${WORKFLOW_ID}" -d @- 2>/dev/null)"

    VALID="$(jq -r '.valid // "?"' <<<"$PUT_RESPONSE" 2>/dev/null)"
    ERRORS="$(jq -r '.validationErrors[]? // empty' <<<"$PUT_RESPONSE" 2>/dev/null)"

    if [[ "$VALID" == "True" ]]; then
        log "Workflow is valid and enabled."
    else
        warn "Workflow validation errors:"
        echo "$ERRORS"
    fi

    mkdir -p "$STATE_DIR"
    echo "$WORKFLOW_ID" > "$WORKFLOW_ID_FILE"
    log "Workflow ID saved to ${WORKFLOW_ID_FILE}"
fi

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
log "====================================="
log "Workflow deployment complete"
log "====================================="
log "Workflow:      Okta Credential Stuffing Response (${WORKFLOW_ID:-manual import needed})"
log ""
log "Next step: when creating the AI detection rule in Kibana, add this"
log "Workflow as an action so it fires on every alert."
if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    log "Workflow ID:   $(cat "$WORKFLOW_ID_FILE")"
fi
