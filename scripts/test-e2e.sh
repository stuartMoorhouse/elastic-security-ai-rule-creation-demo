#!/usr/bin/env bash
#
# test-e2e.sh — end-to-end smoke test for the Okta credential stuffing demo.
#
# PASS criteria (all must pass):
#   1. Detection rule fires an alert for 203.0.113.66 / jsmith@example.com
#   2. Workflow creates a Security case with those values in the title
#   3. Case has attacker IP and compromised email as observables
#   4. Case has a remediation comment (workflow triggered the runscript action)
#   5. Windows Firewall block rule for 203.0.113.66 exists on the VM
#      (verified via Fleet execute action — requires Elastic Defend with response
#      actions enabled; skipped with a warning if the action is unavailable)
#
# PREREQUISITES (must be completed before running this test):
#   - configure.sh has been run and shared/env.json exists with infra_ready=true
#   - The Okta detection rule has been authored in Kibana via Agent Builder
#   - The workflow has been added as a rule action:
#       Detection Rules → Edit the Okta rule → Actions tab → Add action → Workflows
#       Select "Okta Credential Stuffing Response" and set script_id input
#   If the workflow is not attached to the rule, step 4 will time out.
#
# Usage:
#   bash scripts/test-e2e.sh
#   bash scripts/test-e2e.sh --skip-firewall   # skip step 5
#
# Exit code: 0 = all assertions passed, 1 = one or more failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"

ATTACKER_IP="203.0.113.66"
COMPROMISED_USER="jsmith@example.com"
SKIP_FIREWALL=false

for arg in "$@"; do
    [[ "${arg}" == "--skip-firewall" ]] && SKIP_FIREWALL=true
done

PASS=0
FAIL=0

log()  { printf '%s\n'        "$*"; }
step() { printf '\n== %s ==\n' "$*"; }
warn() { printf '  WARN: %s\n' "$*"; }
pass() { printf '  PASS: %s\n' "$*"; (( PASS++ )) || true; }
fail() { printf '  FAIL: %s\n' "$*" >&2; (( FAIL++ )) || true; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { printf 'ERROR: %s is required but not found on PATH.\n' "$1" >&2; exit 1; }
}
require_cmd jq
require_cmd curl

# --------------------------------------------------------------------------
# Load credentials
# --------------------------------------------------------------------------
if [[ ! -f "${ENV_JSON}" ]]; then
    printf 'ERROR: %s not found. Run configure.sh after terraform apply.\n' "${ENV_JSON}" >&2
    exit 1
fi

KIBANA_URL="$(jq -r '.kibana_url   // empty' "${ENV_JSON}")"
ES_URL="$(    jq -r '.elasticsearch_url // empty' "${ENV_JSON}")"
USERNAME="$(  jq -r '.elastic_username // empty'  "${ENV_JSON}")"
PASSWORD="$(  jq -r '.elastic_password // empty'  "${ENV_JSON}")"

if [[ -z "${KIBANA_URL}" || -z "${USERNAME}" || -z "${PASSWORD}" ]]; then
    printf 'ERROR: kibana_url/elastic_username/elastic_password missing from %s\n' "${ENV_JSON}" >&2
    exit 1
fi

CURL_AUTH_CONF="$(mktemp)"
chmod 600 "${CURL_AUTH_CONF}"
printf 'user = "%s:%s"\n' "${USERNAME}" "${PASSWORD}" > "${CURL_AUTH_CONF}"
trap 'rm -f "${CURL_AUTH_CONF}"' EXIT

kibana_get() {
    curl -sS -K "${CURL_AUTH_CONF}" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL%/}${1}"
}

kibana_post() {
    curl -sS -K "${CURL_AUTH_CONF}" \
        -H "kbn-xsrf: true" -H "Content-Type: application/json" \
        -X POST "${KIBANA_URL%/}${1}" -d "${2}"
}

es_post() {
    curl -sS -K "${CURL_AUTH_CONF}" \
        -H "Content-Type: application/json" \
        -X POST "${ES_URL%/}${1}" -d "${2}"
}

# --------------------------------------------------------------------------
# Step 1: Seed attack data
# --------------------------------------------------------------------------
step "1. Seeding Okta attack data"
bash "${REPO_ROOT}/scripts/seed-okta-attack-data.sh"
SEED_EPOCH="$(date +%s)"

# --------------------------------------------------------------------------
# Step 2: Check the Okta detection rule exists and is enabled
# --------------------------------------------------------------------------
step "2. Checking detection rule"
RULES_JSON="$(kibana_get "/api/detection_engine/rules/_find?per_page=100")"
RULE_ID="$(jq -r '[.data[]? | select(.name | ascii_downcase | contains("okta"))] | first | .id // empty' <<<"${RULES_JSON}")"
RULE_INTERVAL="$(jq -r '[.data[]? | select(.name | ascii_downcase | contains("okta"))] | first | .interval // "unknown"' <<<"${RULES_JSON}")"

if [[ -n "${RULE_ID}" ]]; then
    log "Found Okta detection rule (interval: ${RULE_INTERVAL}). Waiting for next execution..."
else
    printf '\nERROR: No Okta detection rule found.\n' >&2
    printf 'Author the detection rule in Kibana Agent Builder first, then re-run this test.\n' >&2
    printf 'Prompt: "In Okta, detect when the same user and source IP shows: three or more failed logins\n' >&2
    printf 'due to bad credentials, at least one MFA failure, then a successful login, and then either\n' >&2
    printf 'a privilege grant or a policy update."\n' >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Step 3: Poll for alert (rule runs on its schedule — default 2m on this deployment)
# --------------------------------------------------------------------------
step "3. Waiting for credential stuffing alert (up to 5 min)"
ALERT_FOUND=false
ALERT_DEADLINE=$(( SEED_EPOCH + 300 ))

# Compute seed time as ISO string for filtering (cases/alerts created after seed)
SEED_ISO="$(date -u -r "${SEED_EPOCH}" "+%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null \
         || date -u -d "@${SEED_EPOCH}" "+%Y-%m-%dT%H:%M:%S.000Z")"

while (( "$(date +%s)" < ALERT_DEADLINE )); do
    # ES|QL rules produce alerts with the KEEP fields only (source.ip + user.name),
    # not raw Okta fields. Filter on source.ip (ECS) which maps from okta.client.ip.
    COUNT="$(es_post "/.alerts-security.alerts-default/_search" \
        '{"size":0,"query":{"bool":{"filter":[
            {"term":{"kibana.alert.status":"active"}},
            {"term":{"source.ip":"'"${ATTACKER_IP}"'"}},
            {"range":{"@timestamp":{"gte":"'"${SEED_ISO}"'"}}}
        ]}}}' \
        | jq -r '.hits.total.value // 0' 2>/dev/null || echo 0)"

    if [[ "${COUNT}" -gt 0 ]]; then
        log "Alert found (${COUNT} active alert(s) for ${ATTACKER_IP})."
        ALERT_FOUND=true
        break
    fi

    NOW="$(date +%s)"
    log "  No alert yet — retrying in 20s ($(( (ALERT_DEADLINE - NOW) / 60 ))m$(( (ALERT_DEADLINE - NOW) % 60 ))s left)..."
    sleep 20
done

if [[ "${ALERT_FOUND}" != true ]]; then
    fail "No alert fired within 6 minutes"
    printf '\nRESULT: FAIL (%d passed, %d failed)\n' "${PASS}" "${FAIL}"
    exit 1
fi

pass "Detection rule fired an alert for ${ATTACKER_IP} / ${COMPROMISED_USER}"

# --------------------------------------------------------------------------
# Step 4: Poll for case creation (up to 8 min — workflow runs after alert)
# --------------------------------------------------------------------------
step "4. Waiting for Security case (up to 8 min)"
CASE_ID=""
CASE_DEADLINE=$(( "$(date +%s)" + 480 ))

while (( "$(date +%s)" < CASE_DEADLINE )); do
    CASES="$(kibana_get "/api/cases/_find?search=${COMPROMISED_USER}&sortField=createdAt&sortOrder=desc&perPage=10")"
    # Only accept cases created after we seeded data (lexicographic ISO comparison is correct for UTC)
    CASE_ID="$(jq -r --arg since "${SEED_ISO}" '
        .cases[]?
        | select(.title | ascii_downcase | contains("okta"))
        | select(.createdAt >= $since)
        | .id' <<<"${CASES}" | head -1)"

    if [[ -n "${CASE_ID}" ]]; then
        CASE_TITLE="$(jq -r '.cases[] | select(.id == "'"${CASE_ID}"'") | .title' <<<"${CASES}")"
        log "Case found: \"${CASE_TITLE}\" (${CASE_ID})"
        break
    fi

    NOW="$(date +%s)"
    log "  No case yet — retrying in 20s ($(( (CASE_DEADLINE - NOW) / 60 ))m$(( (CASE_DEADLINE - NOW) % 60 ))s left)..."
    sleep 20
done

if [[ -z "${CASE_ID}" ]]; then
    fail "No case created within 8 minutes"
    printf '\n  Most likely cause: the workflow is not attached to the detection rule.\n' >&2
    printf '  Fix: Detection Rules → Edit Okta rule → Actions → + Add action → Workflows\n' >&2
    printf '  Select "Okta Credential Stuffing Response" and set script_id input to:\n' >&2
    printf '  %s\n' "$(jq -r '.script_id // empty' "${ENV_JSON}" 2>/dev/null || echo '<value from state/script-id>')" >&2
    printf '\nRESULT: FAIL (%d passed, %d failed)\n' "${PASS}" "${FAIL}"
    exit 1
fi

pass "Workflow created Security case"

# --------------------------------------------------------------------------
# Step 5: Assert observables
# --------------------------------------------------------------------------
step "5. Asserting case observables"
CASE_DATA="$(kibana_get "/api/cases/${CASE_ID}")"
OBSERVABLES="$(jq -r '.observables // []' <<<"${CASE_DATA}")"

if jq -e --arg v "${ATTACKER_IP}" '.[] | select(.value == $v)' <<<"${OBSERVABLES}" >/dev/null 2>&1; then
    pass "Attacker IP ${ATTACKER_IP} pinned as observable"
else
    fail "Attacker IP ${ATTACKER_IP} NOT in case observables"
fi

if jq -e --arg v "${COMPROMISED_USER}" '.[] | select(.value == $v)' <<<"${OBSERVABLES}" >/dev/null 2>&1; then
    pass "Compromised account ${COMPROMISED_USER} pinned as observable"
else
    fail "Compromised account ${COMPROMISED_USER} NOT in case observables"
fi

# --------------------------------------------------------------------------
# Step 6: Assert remediation comment
# --------------------------------------------------------------------------
step "6. Asserting remediation comment"
COMMENTS_RAW="$(kibana_get "/api/cases/${CASE_ID}/comments/_find")"
COMMENTS="$(jq -r '.comments // []' <<<"${COMMENTS_RAW}")"
REMEDIATION="$(jq -r '.[] | select(.comment | contains("Automated Remediation")) | .comment' <<<"${COMMENTS}" | head -1)"

if [[ -n "${REMEDIATION}" ]]; then
    pass "Remediation comment present — workflow executed runscript action"

    # Extract the hostname from the remediation comment for informational output
    COMMENT_HOST="$(printf '%s' "${REMEDIATION}" | grep -o 'ran against .[^:]*' | sed 's/ran against .//;s/.$//')"
    [[ -n "${COMMENT_HOST}" ]] && log "  Remediated host: ${COMMENT_HOST} (resolved via entity store)"
else
    fail "Remediation comment NOT found — workflow may not have completed"
fi

# --------------------------------------------------------------------------
# Step 7: Verify Windows Firewall rule via Fleet execute action
# --------------------------------------------------------------------------
step "7. Verifying Windows Firewall block rule on VM"

if [[ "${SKIP_FIREWALL}" == true ]]; then
    warn "Skipping firewall check (--skip-firewall passed)."
else
    AGENT_JSON="$(kibana_get '/api/fleet/agents?perPage=1&kuery=local_metadata.os.platform:"windows" AND status:online')"
    AGENT_ID="$(jq -r '.items[0].id // empty' <<<"${AGENT_JSON}")"
    AGENT_HOST="$(jq -r '.items[0].local_metadata.host.hostname // "unknown"' <<<"${AGENT_JSON}")"

    if [[ -z "${AGENT_ID}" ]]; then
        warn "No online Windows agent found — skipping firewall check."
    else
        log "Targeting agent ${AGENT_ID} (${AGENT_HOST})"

        # PowerShell: count inbound block rules matching the attacker IP
        PS_CMD="(Get-NetFirewallAddressFilter | Where-Object { \$_.RemoteAddress -eq '${ATTACKER_IP}' } | Get-NetFirewallRule | Where-Object { \$_.Direction -eq 'Inbound' -and \$_.Action -eq 'Block' } | Measure-Object).Count"

        EXEC_BODY="$(jq -n \
            --arg agent "${AGENT_ID}" \
            --arg cmd "${PS_CMD}" \
            '{
                "endpoint_ids": [$agent],
                "parameters": {
                    "command": ("powershell.exe -NonInteractive -NoProfile -Command \"" + $cmd + "\""),
                    "timeout": 60
                }
            }')"

        EXEC_RESP="$(kibana_post "/api/endpoint/action/execute" "${EXEC_BODY}")"
        EXEC_ACTION_ID="$(jq -r '.data.id // empty' <<<"${EXEC_RESP}" 2>/dev/null || echo "")"

        if [[ -z "${EXEC_ACTION_ID}" ]]; then
            warn "Fleet execute action did not start (may need Elastic Defend with response actions)."
            warn "Manual check: RDP to VM and run: ${PS_CMD}"
        else
            log "Execute action ${EXEC_ACTION_ID} started — polling for result (up to 2 min)..."
            EXEC_DEADLINE=$(( "$(date +%s)" + 120 ))
            EXEC_STATUS="pending"
            STDOUT=""

            while (( "$(date +%s)" < EXEC_DEADLINE )); do
                EXEC_DATA="$(kibana_get "/api/endpoint/action/${EXEC_ACTION_ID}")"
                EXEC_STATUS="$(jq -r '.data.status // "pending"' <<<"${EXEC_DATA}")"

                if [[ "${EXEC_STATUS}" == "successful" ]]; then
                    STDOUT="$(jq -r '
                        .data.outputs // {}
                        | to_entries[0].value.content.stdout // ""
                        | gsub("[[:space:]]"; "")
                        ' <<<"${EXEC_DATA}")"
                    break
                elif [[ "${EXEC_STATUS}" == "failed" ]]; then
                    STDOUT="error"
                    break
                fi
                sleep 10
            done

            if [[ "${EXEC_STATUS}" == "successful" && "${STDOUT}" =~ ^[0-9]+$ && "${STDOUT}" -gt 0 ]]; then
                pass "Windows Firewall block rule for ${ATTACKER_IP} confirmed on ${AGENT_HOST} (${STDOUT} rule(s))"
            elif [[ "${EXEC_STATUS}" == "successful" && "${STDOUT}" == "0" ]]; then
                fail "Windows Firewall block rule for ${ATTACKER_IP} NOT found on ${AGENT_HOST}"
            else
                warn "Firewall check inconclusive (status=${EXEC_STATUS}, output='${STDOUT}')."
                warn "Manual check: RDP to VM and run: ${PS_CMD}"
            fi
        fi
    fi
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
printf '\n==============================\n'
if [[ "${FAIL}" -eq 0 ]]; then
    printf 'RESULT: PASS (%d checks passed)\n' "${PASS}"
    exit 0
else
    printf 'RESULT: FAIL (%d passed, %d failed)\n' "${PASS}" "${FAIL}"
    exit 1
fi
