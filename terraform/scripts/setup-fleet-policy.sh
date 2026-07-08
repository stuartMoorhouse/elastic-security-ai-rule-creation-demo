#!/bin/bash
################################################################################
# setup-fleet-policy.sh
#
# Terraform `data "external"` program (see fleet_enrollment.tf). Creates (or
# reuses) a Fleet agent policy in Kibana, retrieves an enrollment token for
# it, and resolves the *real* Fleet Server URL.
#
# CRITICAL: the Fleet Server URL is fetched from
#   GET /api/fleet/fleet_server_hosts
# and NOT read from the ec_deployment `integrations_server` endpoint
# attribute — that attribute surfaces the APM endpoint, a documented pitfall.
#
# Contract (Terraform external data source):
#   - Reads a single JSON object from stdin (the `query` map — string values
#     only): {"kibana_url": "...", "username": "...", "password": "...",
#              "policy_name": "..."}
#   - Writes EXACTLY ONE JSON object to stdout on success:
#       {"fleet_url": "...", "enrollment_token": "...", "policy_id": "..."}
#   - All logging/diagnostics go to stderr. stdout must contain nothing else.
#   - Non-zero exit on failure.
################################################################################

set -euo pipefail

log() { echo "[setup-fleet-policy] $*" >&2; }

INPUT="$(cat)"
KIBANA_URL="$(jq -r '.kibana_url' <<<"$INPUT" | sed 's:/*$::')"
USERNAME="$(jq -r '.username' <<<"$INPUT")"
PASSWORD="$(jq -r '.password' <<<"$INPUT")"
POLICY_NAME="$(jq -r '.policy_name' <<<"$INPUT")"

if [ -z "$KIBANA_URL" ] || [ "$KIBANA_URL" = "null" ]; then
  log "ERROR: kibana_url missing from input"
  exit 1
fi

# Credentials via curl -K (config file) instead of -u, so they don't show up
# in the process table.
CURL_AUTH_CONF="$(mktemp)"
chmod 600 "$CURL_AUTH_CONF"
printf 'user = "%s:%s"\n' "$USERNAME" "$PASSWORD" > "$CURL_AUTH_CONF"
trap 'rm -f "$CURL_AUTH_CONF"' EXIT

kb_get() {
  curl -sS -K "$CURL_AUTH_CONF" --header "kbn-xsrf: true" "$@"
}

kb_post() {
  curl -sS -K "$CURL_AUTH_CONF" --header "kbn-xsrf: true" --header "Content-Type: application/json" "$@"
}

# --- Wait for Kibana to be reachable (deployment may still be settling) -----

log "Waiting for Kibana at ${KIBANA_URL}..."
KIBANA_READY=false
for i in $(seq 1 30); do
  if kb_get "${KIBANA_URL}/api/status" | jq -e '.status' >/dev/null 2>&1; then
    KIBANA_READY=true
    break
  fi
  log "  attempt ${i}/30, retrying in 10s..."
  sleep 10
done

if [ "$KIBANA_READY" != true ]; then
  log "ERROR: Kibana never became reachable at ${KIBANA_URL}"
  exit 1
fi

# --- Step 1: create (or reuse) the agent policy -----------------------------

log "Looking up existing agent policy '${POLICY_NAME}'..."
EXISTING_POLICIES="$(kb_get "${KIBANA_URL}/api/fleet/agent_policies?perPage=100")"
POLICY_ID="$(jq -r --arg name "$POLICY_NAME" '.items[]? | select(.name==$name) | .id' <<<"$EXISTING_POLICIES" | head -n1)"

if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  log "Using existing agent policy: ${POLICY_ID}"
else
  log "Creating agent policy '${POLICY_NAME}'..."
  CREATE_BODY="$(jq -n --arg name "$POLICY_NAME" '{
    name: $name,
    namespace: "default",
    description: "Elastic Security webinar demo - Windows VM policy",
    monitoring_enabled: ["logs", "metrics"]
  }')"

  CREATE_RESPONSE="$(kb_post --request POST "${KIBANA_URL}/api/fleet/agent_policies?sys_monitoring=true" --data "$CREATE_BODY")"
  POLICY_ID="$(jq -r '.item.id // empty' <<<"$CREATE_RESPONSE")"

  if [ -z "$POLICY_ID" ]; then
    log "ERROR: failed to create agent policy. Response: ${CREATE_RESPONSE}"
    exit 1
  fi
  log "Created agent policy: ${POLICY_ID}"
fi

# --- Step 2: retrieve an enrollment token for the policy --------------------

log "Retrieving enrollment token for policy ${POLICY_ID}..."
ENROLLMENT_TOKEN=""
for i in $(seq 1 10); do
  ENROLLMENT_RESPONSE="$(kb_get "${KIBANA_URL}/api/fleet/enrollment_api_keys")"
  ENROLLMENT_TOKEN="$(jq -r --arg pid "$POLICY_ID" '.items[]? | select(.policy_id==$pid and .active==true) | .api_key' <<<"$ENROLLMENT_RESPONSE" | head -n1)"
  if [ -n "$ENROLLMENT_TOKEN" ] && [ "$ENROLLMENT_TOKEN" != "null" ]; then
    break
  fi
  log "  no enrollment key yet, retrying in 5s..."
  sleep 5
done

if [ -z "$ENROLLMENT_TOKEN" ] || [ "$ENROLLMENT_TOKEN" = "null" ]; then
  log "ERROR: could not retrieve an enrollment token for policy ${POLICY_ID}"
  exit 1
fi

# --- Step 3: resolve the real Fleet Server URL ------------------------------

log "Resolving Fleet Server URL from /api/fleet/fleet_server_hosts..."
FLEET_URL=""
for i in $(seq 1 10); do
  FLEET_HOSTS="$(kb_get "${KIBANA_URL}/api/fleet/fleet_server_hosts")"
  FLEET_URL="$(jq -r '.items[]? | select(.is_default==true) | .host_urls[0]' <<<"$FLEET_HOSTS" | head -n1)"
  if [ -z "$FLEET_URL" ] || [ "$FLEET_URL" = "null" ]; then
    # Fall back to the first host entry if none is flagged default.
    FLEET_URL="$(jq -r '.items[0].host_urls[0] // empty' <<<"$FLEET_HOSTS")"
  fi
  if [ -n "$FLEET_URL" ] && [ "$FLEET_URL" != "null" ]; then
    break
  fi
  log "  no Fleet Server host registered yet, retrying in 10s..."
  sleep 10
done

if [ -z "$FLEET_URL" ] || [ "$FLEET_URL" = "null" ]; then
  log "ERROR: could not resolve Fleet Server URL from /api/fleet/fleet_server_hosts"
  exit 1
fi

log "Fleet Server URL: ${FLEET_URL}"
log "Policy ID: ${POLICY_ID}"
log "Done."

# --- Emit the result (ONLY this goes to stdout) -----------------------------

jq -n \
  --arg fleet_url "$FLEET_URL" \
  --arg enrollment_token "$ENROLLMENT_TOKEN" \
  --arg policy_id "$POLICY_ID" \
  '{fleet_url: $fleet_url, enrollment_token: $enrollment_token, policy_id: $policy_id}'
