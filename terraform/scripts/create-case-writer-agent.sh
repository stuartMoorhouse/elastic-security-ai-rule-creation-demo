#!/bin/bash
################################################################################
# create-case-writer-agent.sh
#
# Creates (or updates) the "case-writer" Agent Builder agent from
# terraform/agents/case-writer.json. Idempotent: PUT if the agent exists,
# otherwise POST. Called by deploy-workflow.sh (so the agent exists before the
# workflow that references it) and by scripts/configure.sh.
#
# Reads Terraform outputs directly via `terraform output`.
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"
AGENT_DEF="${TERRAFORM_DIR}/agents/case-writer.json"
STATE_DIR="${PROJECT_DIR}/state"

log() { printf '[case-writer-agent] %s\n' "$*"; }
err() { printf '[case-writer-agent] ERROR: %s\n' "$*" >&2; }

CURL_AUTH_CONF="$(mktemp)"
chmod 600 "$CURL_AUTH_CONF"
trap 'rm -f "$CURL_AUTH_CONF"' EXIT

KIBANA_URL="$(terraform -chdir="$TERRAFORM_DIR" output -raw kibana_url)"
ELASTIC_USER="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_username)"
ELASTIC_PASS="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_password)"
if [[ -z "$KIBANA_URL" || -z "$ELASTIC_USER" || -z "$ELASTIC_PASS" ]]; then
    err "One or more Terraform outputs are empty. Has 'terraform apply' completed?"
    exit 1
fi
KIBANA_URL="${KIBANA_URL%/}"
printf 'user = "%s:%s"\n' "$ELASTIC_USER" "$ELASTIC_PASS" > "$CURL_AUTH_CONF"

AGENT_ID="$(jq -r '.id' "$AGENT_DEF")"

EXISTS_CODE="$(curl -s -o /dev/null -w '%{http_code}' -K "$CURL_AUTH_CONF" \
    -H 'kbn-xsrf: true' "${KIBANA_URL}/api/agent_builder/agents/${AGENT_ID}" || true)"

if [[ "$EXISTS_CODE" == "200" ]]; then
    log "Updating agent ${AGENT_ID}..."
    # PUT does not accept the id in the body.
    BODY="$(jq 'del(.id)' "$AGENT_DEF")"
    METHOD=PUT
    URL="${KIBANA_URL}/api/agent_builder/agents/${AGENT_ID}"
else
    log "Creating agent ${AGENT_ID}..."
    BODY="$(cat "$AGENT_DEF")"
    METHOD=POST
    URL="${KIBANA_URL}/api/agent_builder/agents"
fi

RESPONSE="$(printf '%s' "$BODY" | curl -s -K "$CURL_AUTH_CONF" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -X "$METHOD" "$URL" -d @-)"

if [[ "$(jq -r '.id // empty' <<<"$RESPONSE" 2>/dev/null)" != "$AGENT_ID" ]]; then
    err "Failed to ${METHOD} agent. Response: ${RESPONSE}"
    exit 1
fi

mkdir -p "$STATE_DIR"
echo "$AGENT_ID" > "${STATE_DIR}/case-writer-agent-id"
log "Agent ${AGENT_ID} ready (saved to ${STATE_DIR}/case-writer-agent-id)."
