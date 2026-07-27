#!/usr/bin/env bash
#
# add-attack-scenario.sh
#
# Adds a fresh attack scenario without deleting existing events. Each run
# uses the next available attacker IP and victim from a fixed rotation, so
# multiple calls accumulate independent alerts.
#
# Useful for building up a richer alert queue for demo purposes.
#
# WHAT TO EXPECT IN KIBANA
# The detection rule's Workflow action fires on every new alert and runs
# automated remediation (blocks the IP, disables the account, opens+closes
# a Case). After the Workflow completes, the alert's status moves to
# "Acknowledged". The Kibana Alerts page shows only "Open" alerts by
# default, so new scenario alerts will appear to vanish.
#
# To see the full remediated queue:
#   Security → Alerts → Status filter → select "Acknowledged" (or "All")
#
# This is the intended demo story: multiple attackers, each automatically
# detected and remediated — a consistent response every time.
#
# Usage: ./scripts/add-attack-scenario.sh [attacker_ip victim_email]
#   e.g. ./scripts/add-attack-scenario.sh 203.0.113.70 tdavis@example.com

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"
DATA_STREAM="logs-okta.system-default"

log()  { printf '%s\n' "$*"; }
step() { printf '\n== %s ==\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || { err "'$1' required but not found."; exit 1; }; }
require_cmd jq; require_cmd curl; require_cmd date

if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh first."; exit 1
fi

ES_URL="$(jq -r '.elasticsearch_url' "${ENV_JSON}")"
ES_USER="$(jq -r '.elastic_username' "${ENV_JSON}")"
ES_PASS="$(jq -r '.elastic_password' "${ENV_JSON}")"

# Rotation pool — IPs are all TEST-NET-3 (RFC 5737), safe for demos
ATTACKER_IPS=("203.0.113.67" "203.0.113.68" "203.0.113.69" "203.0.113.70" "203.0.113.71")
VICTIMS=("tdavis@example.com" "rjohnson@example.com" "kwilliams@example.com" "pmartin@example.com" "slee@example.com")

if [[ $# -ge 2 ]]; then
    ATTACKER_IP="$1"
    VICTIM="$2"
else
    # Pick the next slot by counting existing scenarios for these IPs
    SLOT=0
    for i in "${!ATTACKER_IPS[@]}"; do
        COUNT="$(curl -s -u "${ES_USER}:${ES_PASS}" \
            "${ES_URL%/}/${DATA_STREAM}/_count" \
            -H 'Content-Type: application/json' \
            -d "{\"query\":{\"term\":{\"source.ip\":\"${ATTACKER_IPS[$i]}\"}}}" \
            | jq -r '.count // 0' 2>/dev/null || echo 0)"
        if [[ "$COUNT" -eq 0 ]]; then
            SLOT=$i; break
        fi
        SLOT=$(( (i + 1) % ${#ATTACKER_IPS[@]} ))
    done
    ATTACKER_IP="${ATTACKER_IPS[$SLOT]}"
    VICTIM="${VICTIMS[$SLOT]}"
fi

minutes_ago() {
    local mins="$1"
    if date -u -v-1M +%s >/dev/null 2>&1; then
        date -u -v-"${mins}"M +"%Y-%m-%dT%H:%M:%S.000Z"
    else
        date -u -d "-${mins} minutes" +"%Y-%m-%dT%H:%M:%S.000Z"
    fi
}

next_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then uuidgen | tr '[:upper:]' '[:lower:]'
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid
    else python3 -c "import uuid; print(uuid.uuid4())"
    fi
}

es_post() { curl -s -u "${ES_USER}:${ES_PASS}" -H 'Content-Type: application/json' -X POST "${ES_URL%/}$1" -d "$2"; }

build_event() {
    local ts="$1" action="$2" outcome="$3" ip="$4" user="$5" reason="${6:-}"
    local uuid; uuid="$(next_uuid)"
    local oupper; oupper="$(printf '%s' "${outcome}" | tr '[:lower:]' '[:upper:]')"

    local display_msg legacy_type severity
    case "${action}:${oupper}" in
        user.session.start:FAILURE|user.authentication.usernamepassword:FAILURE)
            display_msg="User login to Okta"; legacy_type="core.user_auth.login_failed"; severity="WARN" ;;
        user.session.start:SUCCESS|user.authentication.usernamepassword:SUCCESS)
            display_msg="User login to Okta"; legacy_type="core.user_auth.login_success"; severity="INFO" ;;
        user.authentication.auth_via_mfa:FAILURE)
            display_msg="Authentication via MFA"; legacy_type="core.user_auth.mfa.factor.attempt_fail"; severity="WARN" ;;
        user.account.privilege.grant:*)
            display_msg="Grant user privilege"; legacy_type="core.user.account.privilege.grant"; severity="INFO" ;;
        *) display_msg="${action}"; legacy_type="${action}"; severity="INFO" ;;
    esac

    local okta_json
    okta_json="$(jq -nc \
        --arg ts "$ts" --arg uuid "$uuid" --arg action "$action" \
        --arg oupper "$oupper" --arg reason "$reason" --arg user "$user" \
        --arg display_msg "$display_msg" --arg legacy_type "$legacy_type" \
        --arg severity "$severity" --arg ip "$ip" \
        '{
            "published": $ts, "uuid": $uuid, "eventType": $action,
            "displayMessage": $display_msg, "severity": $severity, "version": "0",
            "legacyEventType": $legacy_type,
            "outcome": {"result": $oupper, "reason": (if $reason != "" then $reason else null end)},
            "actor": {
                "id": ("00u" + $uuid[0:17]), "type": "User",
                "alternateId": $user,
                "displayName": ($user | split("@")[0] | split(".") | map(. as $w | ($w[0:1] | ascii_upcase) + $w[1:]) | join(" ")),
                "detailEntry": null
            },
            "client": {
                "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Linux", "browser": "CHROME"},
                "zone": "null", "device": "Computer", "id": null, "ipAddress": $ip,
                "geographicalContext": {"city": "Frankfurt", "state": "Hesse", "country": "Germany",
                    "postalCode": "60311", "geolocation": {"lat": 50.1109, "lon": 8.6821}}
            },
            "authenticationContext": {"externalSessionId": "unknown"},
            "securityContext": {"asNumber": 205100, "asOrg": "anonymous vpn",
                "isp": "anon hosting", "domain": "anonymous.example", "isProxy": true},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn", "requestId": $uuid,
                "threatSuspected": "true", "deviceFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2"}},
            "transaction": {"type": "WEB", "id": $uuid, "detail": {}},
            "request": {"ipChain": [{"ip": $ip, "geographicalContext": {"city": "Frankfurt", "country": "Germany"},
                "version": "V4", "source": null}]},
            "target": null
        }')"

    jq -nc --arg ts "$ts" --arg msg "$okta_json" '{"@timestamp": $ts, "message": $msg}'
}

BULK=""
add() {
    BULK+="{\"create\":{}}"$'\n'
    BULK+="$(build_event "$@")"$'\n'
}

step "Adding attack scenario: ${VICTIM} from ${ATTACKER_IP}"

# Stage 1: credential stuffing — both event types, compressed into a 4-min window
# so all events fall within the detection rule's lookback period
add "$(minutes_ago 4)" "user.session.start"               "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
add "$(minutes_ago 4)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
add "$(minutes_ago 3)" "user.session.start"               "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
add "$(minutes_ago 3)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
add "$(minutes_ago 2)" "user.session.start"               "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
add "$(minutes_ago 2)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "$VICTIM" "INVALID_CREDENTIALS"
# Stage 2: MFA fatigue
add "$(minutes_ago 2)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "$VICTIM" "FACTOR_CHALLENGE_TIMEOUT"
add "$(minutes_ago 2)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "$VICTIM" "FACTOR_CHALLENGE_TIMEOUT"
# Stage 3: successful login — both event types
add "$(minutes_ago 1)" "user.session.start"               "success" "$ATTACKER_IP" "$VICTIM"
add "$(minutes_ago 1)" "user.authentication.usernamepassword" "success" "$ATTACKER_IP" "$VICTIM"
# Stage 4: post-compromise
add "$(minutes_ago 1)" "user.account.privilege.grant"     "success" "$ATTACKER_IP" "$VICTIM"

RESPONSE="$(es_post "/${DATA_STREAM}/_bulk?refresh=true" "${BULK}")"
if [[ "$(jq -r '.errors' <<<"${RESPONSE}" 2>/dev/null || echo true)" != "false" ]]; then
    err "Bulk load errors:"; err "${RESPONSE}"; exit 1
fi

log ""
log "Scenario added:"
log "  ${ATTACKER_IP} / ${VICTIM} — full attack chain (FIRES rule)"
log ""
log "Run this script again to add another scenario with the next IP/victim in rotation."
