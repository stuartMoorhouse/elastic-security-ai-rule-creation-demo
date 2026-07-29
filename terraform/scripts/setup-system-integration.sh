#!/bin/bash
################################################################################
# setup-system-integration.sh
#
# Terraform `data "external"` program (see system_integration.tf). Installs the
# System integration on the given Fleet agent policy with the Windows Security
# event log (winlog) stream enabled. Event codes 4624/4648 collected here are
# what the Elastic Security entity store uses to build user-host access
# relationships — specifically, to link jsmith to the demo endpoint so the
# Workflow can look up the correct Fleet agent at remediation time.
#
# Contract (Terraform external data source):
#   - Reads a single JSON object from stdin: {"kibana_url": "...", "username":
#     "...", "password": "...", "policy_id": "..."}
#   - Writes EXACTLY ONE JSON object to stdout on success:
#       {"package_policy_id": "..."}
#   - All logging/diagnostics go to stderr. stdout must contain nothing else.
#   - Non-zero exit on failure.
################################################################################

set -euo pipefail

log() { echo "[setup-system-integration] $*" >&2; }

INPUT="$(cat)"
KIBANA_URL="$(jq -r '.kibana_url' <<<"$INPUT" | sed 's:/*$::')"
USERNAME="$(jq -r '.username' <<<"$INPUT")"
PASSWORD="$(jq -r '.password' <<<"$INPUT")"
POLICY_ID="$(jq -r '.policy_id' <<<"$INPUT")"

if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
  log "ERROR: policy_id missing from input"
  exit 1
fi

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

# --- Skip if already installed -----------------------------------------------

log "Checking for an existing System package policy on ${POLICY_ID}..."
EXISTING_PACKAGES="$(kb_get "${KIBANA_URL}/api/fleet/package_policies?perPage=100")"
PACKAGE_POLICY_ID="$(jq -r --arg pid "$POLICY_ID" \
  '.items[]? | select(.policy_id==$pid and .package.name=="system") | .id' \
  <<<"$EXISTING_PACKAGES" | head -n1)"

if [ -n "${PACKAGE_POLICY_ID:-}" ] && [ "$PACKAGE_POLICY_ID" != "null" ]; then
  log "System integration already configured on this policy: ${PACKAGE_POLICY_ID}"
  jq -n --arg id "$PACKAGE_POLICY_ID" '{package_policy_id: $id}'
  exit 0
fi

# --- Resolve package version -------------------------------------------------

log "Resolving System integration package version..."
PACKAGE_VERSION="$(kb_get "${KIBANA_URL}/api/fleet/epm/packages/system" | jq -r '.item.version')"
if [ -z "$PACKAGE_VERSION" ] || [ "$PACKAGE_VERSION" = "null" ]; then
  log "ERROR: could not resolve system package version"
  exit 1
fi
log "Using system package version: ${PACKAGE_VERSION}"

# --- Create package policy with Windows Security event log stream ------------

log "Creating System integration package policy (Windows Security events)..."
CREATE_BODY="$(jq -n \
  --arg pid     "$POLICY_ID" \
  --arg version "$PACKAGE_VERSION" '{
  name: "System - Windows Security Events",
  description: "Collects Windows Security event log (4624/4648) for Elastic Security entity store user-host relationships",
  namespace: "default",
  policy_id: $pid,
  enabled: true,
  inputs: [{
    type: "winlog",
    enabled: true,
    streams: [{
      enabled: true,
      data_stream: { type: "logs", dataset: "system.security" },
      vars: {
        channel:                  { value: "Security",                        type: "text"    },
        event_id:                 { value: "4624,4625,4634,4647,4648,4672",   type: "text"    },
        ignore_older:             { value: "72h",                             type: "text"    },
        language:                 { value: 0,                                 type: "integer" },
        tags:                     { value: [],                                type: "text"    },
        preserve_original_event:  { value: false,                             type: "bool"    }
      }
    }]
  }],
  package: { name: "system", title: "System", version: $version }
}')"

CREATE_RESPONSE="$(kb_send --request POST "${KIBANA_URL}/api/fleet/package_policies" --data "$CREATE_BODY")"
PACKAGE_POLICY_ID="$(jq -r '.item.id // empty' <<<"$CREATE_RESPONSE")"

if [ -z "$PACKAGE_POLICY_ID" ]; then
  log "ERROR: failed to create System package policy. Response: ${CREATE_RESPONSE}"
  exit 1
fi
log "Created System package policy: ${PACKAGE_POLICY_ID}"

jq -n --arg id "$PACKAGE_POLICY_ID" '{package_policy_id: $id}'
