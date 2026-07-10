#!/usr/bin/env bash
#
# seed-password-spray-data.sh
#
# Automates the seed data described in demo/create-sample-data.http: deletes
# any previous take's demo events for the two demo source IPs, then
# bulk-loads fresh ones with timestamps computed relative to "now" at run
# time, so the data always lands inside the rule/preview window. Idempotent
# - safe to re-run before every take.
#
# Reads the Elasticsearch endpoint/credentials from ./shared/env.json
# (written by scripts/configure.sh). Run scripts/configure.sh first if that
# file doesn't exist yet.
#
# demo/create-sample-data.http still exists alongside this for manual,
# request-by-request use (e.g. reloading just one IP while tuning the rule
# live in Kibana). This script is the one-command equivalent for a rehearsal
# or a take.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"

DATA_STREAM="logs-system.auth-default"
ATTACKER_IP="203.0.113.66"
BENIGN_IP="198.51.100.20"

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not found on PATH."; exit 1; }
}

require_cmd jq
require_cmd curl
require_cmd date

if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh after 'terraform apply' first."
    exit 1
fi

ES_URL="$(jq -r '.elasticsearch_url // empty' "${ENV_JSON}")"
ES_USER="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
ES_PASSWORD="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"

if [[ -z "${ES_URL}" || -z "${ES_USER}" || -z "${ES_PASSWORD}" ]]; then
    err "${ENV_JSON} is missing elasticsearch_url / elastic_username / elastic_password."
    err "Run ./scripts/configure.sh first."
    exit 1
fi

# "N minutes ago" as UTC ISO8601 - portable across BSD date (macOS) and GNU date (Linux).
minutes_ago() {
    local mins="$1"
    if date -u -v-1M +%s >/dev/null 2>&1; then
        date -u -v-"${mins}"M +"%Y-%m-%dT%H:%M:%S.000Z"
    else
        date -u -d "-${mins} minutes" +"%Y-%m-%dT%H:%M:%S.000Z"
    fi
}

es_post() {
    local path="$1" body="$2"
    curl -s -u "${ES_USER}:${ES_PASSWORD}" -H 'Content-Type: application/json' \
        -X POST "${ES_URL%/}${path}" -d "${body}"
}

build_auth_event() {
    local ts="$1" ip="$2" user="$3" port="$4"
    jq -nc --arg ts "$ts" --arg ip "$ip" --arg user "$user" --arg port "$port" \
        '{"@timestamp":$ts,"event":{"category":["authentication"],"type":["denied"],"outcome":"failure","action":"ssh_login","dataset":"system.auth"},"source":{"ip":$ip},"user":{"name":$user},"host":{"name":"auth-gateway-01"},"message":("Failed password for " + $user + " from " + $ip + " port " + $port + " ssh2")}'
}

# --------------------------------------------------------------------------
# 1. Clear any previous take's demo events for these two source IPs
# --------------------------------------------------------------------------
step "Clearing previous take's demo events (${ATTACKER_IP}, ${BENIGN_IP})"

DELETE_BODY="$(jq -n --arg a "${ATTACKER_IP}" --arg b "${BENIGN_IP}" \
    '{query: {terms: {"source.ip": [$a, $b]}}}')"
DELETE_RESPONSE="$(es_post "/${DATA_STREAM}/_delete_by_query?refresh=true&conflicts=proceed" "${DELETE_BODY}")"
DELETED="$(jq -r '.deleted // "unknown"' <<<"${DELETE_RESPONSE}" 2>/dev/null || echo "unknown")"
log "Deleted ${DELETED} previous demo event(s)."

# --------------------------------------------------------------------------
# 2. Attacker IP - 8 distinct users, 14 failed attempts over ~14 minutes
#    (fires the rule: distinct_users >= 5 AND failed_attempts >= 10)
# --------------------------------------------------------------------------
step "Seeding attacker IP ${ATTACKER_IP} (8 distinct users, 14 failed attempts)"

ATTACKER_USERS=(administrator admin jsmith mjones svc-backup helpdesk guest test administrator admin jsmith mjones svc-backup guest)
ATTACKER_OFFSETS=(14 13 12 11 10 9 8 7 6 5 4 3 2 1)

ATTACKER_BULK=""
for i in "${!ATTACKER_USERS[@]}"; do
    ts="$(minutes_ago "${ATTACKER_OFFSETS[$i]}")"
    port=$((51422 + i))
    ATTACKER_BULK+="{\"create\":{}}"$'\n'
    ATTACKER_BULK+="$(build_auth_event "$ts" "$ATTACKER_IP" "${ATTACKER_USERS[$i]}" "$port")"$'\n'
done

ATTACKER_RESPONSE="$(es_post "/${DATA_STREAM}/_bulk?refresh=true" "${ATTACKER_BULK}")"
if [[ "$(jq -r '.errors' <<<"${ATTACKER_RESPONSE}" 2>/dev/null || echo true)" != "false" ]]; then
    err "Bulk load for attacker IP reported errors:"
    err "${ATTACKER_RESPONSE}"
    exit 1
fi
log "Indexed ${#ATTACKER_USERS[@]} failed-auth events for ${ATTACKER_IP}."

# --------------------------------------------------------------------------
# 3. Benign IP - 2 distinct users, 3 failed attempts
#    (stays under threshold: distinct_users < 5)
# --------------------------------------------------------------------------
step "Seeding benign IP ${BENIGN_IP} (2 distinct users, 3 failed attempts - below threshold)"

BENIGN_USERS=(bob bob alice)
BENIGN_OFFSETS=(6 3 2)

BENIGN_BULK=""
for i in "${!BENIGN_USERS[@]}"; do
    ts="$(minutes_ago "${BENIGN_OFFSETS[$i]}")"
    port=$((60001 + i))
    BENIGN_BULK+="{\"create\":{}}"$'\n'
    BENIGN_BULK+="$(build_auth_event "$ts" "$BENIGN_IP" "${BENIGN_USERS[$i]}" "$port")"$'\n'
done

BENIGN_RESPONSE="$(es_post "/${DATA_STREAM}/_bulk?refresh=true" "${BENIGN_BULK}")"
if [[ "$(jq -r '.errors' <<<"${BENIGN_RESPONSE}" 2>/dev/null || echo true)" != "false" ]]; then
    err "Bulk load for benign IP reported errors:"
    err "${BENIGN_RESPONSE}"
    exit 1
fi
log "Indexed ${#BENIGN_USERS[@]} failed-auth events for ${BENIGN_IP}."

step "Done"
log "Seed data loaded into ${DATA_STREAM}:"
log "  ${ATTACKER_IP} -> distinct_users=8, failed_attempts=14 (should fire the rule)"
log "  ${BENIGN_IP}   -> distinct_users=2, failed_attempts=3  (should NOT fire the rule)"
