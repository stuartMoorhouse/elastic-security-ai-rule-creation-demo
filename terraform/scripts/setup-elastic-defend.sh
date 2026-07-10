#!/bin/bash
################################################################################
# setup-elastic-defend.sh
#
# Terraform `data "external"` program (see elastic_defend.tf). Installs the
# Elastic Defend ("endpoint") integration on the given Fleet agent policy and
# forces every protection into detect-only mode.
#
# Detect-only is deliberate, not a default left over from the EDRComplete
# preset: it keeps Defend's behavioral/malware prevention passive so it can't
# interfere with the demo's own runscript-based response action
# (block-spray-source.ps1) or surprise the presenter mid-demo. The password-
# spraying detection itself runs over synthetic authentication-failure data
# seeded via demo/create-sample-data.http, not endpoint behavioral telemetry,
# so Defend's prevention mode has no bearing on whether the AI ES|QL rule
# sees events. Adapted from the working sequence in
# elastic-agent-builder-workflow-siem-demo/terraform/scripts/deploy-elastic-agent.sh.
#
# Contract (Terraform external data source):
#   - Reads a single JSON object from stdin (the `query` map — string values
#     only): {"kibana_url": "...", "username": "...", "password": "...",
#              "policy_id": "..."}
#   - Writes EXACTLY ONE JSON object to stdout on success:
#       {"package_policy_id": "..."}
#   - All logging/diagnostics go to stderr. stdout must contain nothing else.
#   - Non-zero exit on failure.
################################################################################

set -euo pipefail

log() { echo "[setup-elastic-defend] $*" >&2; }

INPUT="$(cat)"
KIBANA_URL="$(jq -r '.kibana_url' <<<"$INPUT" | sed 's:/*$::')"
USERNAME="$(jq -r '.username' <<<"$INPUT")"
PASSWORD="$(jq -r '.password' <<<"$INPUT")"
POLICY_ID="$(jq -r '.policy_id' <<<"$INPUT")"

if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
  log "ERROR: policy_id missing from input"
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

kb_send() {
  curl -sS -K "$CURL_AUTH_CONF" --header "kbn-xsrf: true" --header "Content-Type: application/json" "$@"
}

# --- Step 0: skip if Defend is already on this policy -----------------------

log "Checking for an existing Defend package policy on ${POLICY_ID}..."
EXISTING_PACKAGES="$(kb_get "${KIBANA_URL}/api/fleet/package_policies?perPage=100")"
PACKAGE_POLICY_ID="$(jq -r --arg pid "$POLICY_ID" '.items[]? | select(.policy_id==$pid and .package.name=="endpoint") | .id' <<<"$EXISTING_PACKAGES" | head -n1)"

if [ -n "${PACKAGE_POLICY_ID:-}" ] && [ "$PACKAGE_POLICY_ID" != "null" ]; then
  log "Elastic Defend already configured on this policy: ${PACKAGE_POLICY_ID}"
  jq -n --arg id "$PACKAGE_POLICY_ID" '{package_policy_id: $id}'
  exit 0
fi

# --- Step 1: resolve the latest "endpoint" package version ------------------

log "Resolving latest Elastic Defend (endpoint) package version..."
PACKAGE_VERSION="$(kb_get "${KIBANA_URL}/api/fleet/epm/packages/endpoint" | jq -r '.item.version')"
if [ -z "$PACKAGE_VERSION" ] || [ "$PACKAGE_VERSION" = "null" ]; then
  log "ERROR: could not resolve the endpoint package version"
  exit 1
fi
log "Using endpoint package version: ${PACKAGE_VERSION}"

# --- Step 2a: create with the EDRComplete preset -----------------------------

log "Creating Elastic Defend package policy (EDRComplete preset)..."
CREATE_BODY="$(jq -n --arg pid "$POLICY_ID" --arg version "$PACKAGE_VERSION" '{
  name: "Elastic Defend - Detect Mode",
  description: "Defend integration in detect mode with full Windows event collection",
  namespace: "default",
  policy_id: $pid,
  enabled: true,
  inputs: [{
    enabled: true,
    streams: [],
    type: "ENDPOINT_INTEGRATION_CONFIG",
    config: {
      _config: {
        value: {
          type: "endpoint",
          endpointConfig: { preset: "EDRComplete" }
        }
      }
    }
  }],
  package: { name: "endpoint", title: "Elastic Defend", version: $version }
}')"

CREATE_RESPONSE="$(kb_send --request POST "${KIBANA_URL}/api/fleet/package_policies" --data "$CREATE_BODY")"
PACKAGE_POLICY_ID="$(jq -r '.item.id // empty' <<<"$CREATE_RESPONSE")"

if [ -z "$PACKAGE_POLICY_ID" ]; then
  log "ERROR: failed to create Defend package policy. Response: ${CREATE_RESPONSE}"
  exit 1
fi
log "Created Defend package policy: ${PACKAGE_POLICY_ID}"

# --- Step 2b/2c: force every protection into detect-only mode ---------------

log "Forcing Defend into detect-only mode (Windows full event collection)..."
UPDATE_BODY="$(jq -n --arg pid "$POLICY_ID" --arg version "$PACKAGE_VERSION" '{
  name: "Elastic Defend - Detect Mode",
  namespace: "default",
  policy_id: $pid,
  enabled: true,
  package: { name: "endpoint", title: "Elastic Defend", version: $version },
  inputs: [{
    type: "endpoint",
    enabled: true,
    streams: [],
    config: {
      policy: {
        value: {
          windows: {
            events: {
              process: true,
              network: true,
              file: true,
              registry: true,
              security: true,
              dll_and_driver_load: true,
              dns: true
            },
            malware: { mode: "detect" },
            ransomware: { mode: "detect" },
            memory_protection: { mode: "detect" },
            behavior_protection: { mode: "detect" }
          }
        }
      }
    }
  }]
}')"

UPDATE_RESPONSE="$(kb_send --request PUT "${KIBANA_URL}/api/fleet/package_policies/${PACKAGE_POLICY_ID}" --data "$UPDATE_BODY")"
UPDATE_SUCCESS="$(jq -r 'if .item then "true" else "false" end' <<<"$UPDATE_RESPONSE")"

if [ "$UPDATE_SUCCESS" != "true" ]; then
  log "ERROR: failed to switch Defend to detect-only mode. Response: ${UPDATE_RESPONSE}"
  exit 1
fi

log "Elastic Defend configured: detect mode, full Windows event collection."

# --- Emit the result (ONLY this goes to stdout) -----------------------------

jq -n --arg id "$PACKAGE_POLICY_ID" '{package_policy_id: $id}'
