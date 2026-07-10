#!/usr/bin/env bash
#
# test-ai-detection-prompt.sh
#
# Pre-demo QA harness for the natural-language prompt in
# config/ai-detection-rule-prompt.md. Does NOT automate or replace the live
# "AI rule creation" demo step in Kibana (that stays manual - see
# config/README.md). This script exists to answer a narrower question before
# the presenter ever gets on stage: does this exact prompt reliably make an
# LLM generate an ES|QL query that correctly flags the seeded attacker IP and
# correctly ignores the seeded benign IP?
#
# Method: send the prompt to the same class of LLM connector Agent Builder
# would use (via Kibana's connector _execute API), extract the ES|QL it
# returns, run that query against the real seeded data (via Elasticsearch's
# _query API), and grade the result against demo/seed-password-spray-data.sh's
# expected outcome. Repeat N times; report the pass rate. If the base prompt
# (as currently documented) doesn't clear the target pass rate, try
# progressively more explicit fallback variants and report which one (if any)
# clears it - this script does NOT silently rewrite the presenter-facing doc.
#
# Grading is heuristic, not string-matching: it looks at the numeric columns
# of the result for the attacker/benign source IPs and checks for two
# separate metrics (>=5 and >=10) rather than requiring specific column
# names, since different LLM calls alias STATS columns differently (e.g.
# "total_attempts" vs "failed_attempts") even when the underlying logic is
# correct.
#
# Usage:
#   ./scripts/test-ai-detection-prompt.sh [connector_id]
#
# Env overrides:
#   TRIALS=20          Number of generations to test per prompt variant.
#   THRESHOLD=0.9       Required pass rate (0-1) to accept a variant.
#   CONNECTOR_ID=...    Kibana connector id to use (overridden by $1 too).
#
# Requires ./shared/env.json (see scripts/configure.sh) and that seed data
# has already been (or will be) loaded - this script seeds it itself.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"
PROMPT_DOC="${REPO_ROOT}/config/ai-detection-rule-prompt.md"

ATTACKER_IP="203.0.113.66"
BENIGN_IP="198.51.100.20"

CONNECTOR_ID="${1:-${CONNECTOR_ID:-Anthropic-Claude-Sonnet-4-6}}"
TRIALS="${TRIALS:-20}"
THRESHOLD="${THRESHOLD:-0.9}"

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not found on PATH."; exit 1; }
}

require_cmd jq
require_cmd curl
require_cmd awk
require_cmd bc

if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh after 'terraform apply' first."
    exit 1
fi

ELASTICSEARCH_URL="$(jq -r '.elasticsearch_url // empty' "${ENV_JSON}")"
KIBANA_URL="$(jq -r '.kibana_url // empty' "${ENV_JSON}")"
ELASTIC_USERNAME="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
ELASTIC_PASSWORD="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"

if [[ -z "${ELASTICSEARCH_URL}" || -z "${KIBANA_URL}" || -z "${ELASTIC_USERNAME}" || -z "${ELASTIC_PASSWORD}" ]]; then
    err "${ENV_JSON} is missing endpoint/credential fields. Run ./scripts/configure.sh first."
    exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

SYSTEM_PROMPT_FILE="${WORKDIR}/system.txt"
cat >"${SYSTEM_PROMPT_FILE}" <<'EOF'
You are generating an Elastic ES|QL query for a Security detection rule, playing the role of Kibana's Agent Builder AI rule creation feature.

Data lives in an index pattern matching authentication logs (e.g. logs-*.auth-*) with these relevant fields:
- @timestamp (date)
- event.category (keyword, e.g. "authentication")
- event.outcome (keyword: "success" or "failure")
- source.ip (ip)
- user.name (keyword)

Given the detection request below, respond with ONLY a single valid ES|QL query that implements it. Do not include any prose, explanation, or markdown code fences - output the raw ES|QL query text only, starting with FROM.
EOF

# --------------------------------------------------------------------------
# Prompt variants: [0] is whatever is currently documented (single source of
# truth). [1]/[2] are progressively more explicit fallbacks tried only if [0]
# misses the target pass rate. This script never edits the fallbacks into
# the doc automatically - it just reports which variant (if any) worked.
# --------------------------------------------------------------------------
extract_base_prompt() {
    awk '
        /^## Prompt to paste/ { found=1; next }
        found && /^```/ { fence++; if (fence==2) exit; next }
        found && fence==1 { print }
    ' "${PROMPT_DOC}"
}

BASE_PROMPT="$(extract_base_prompt)"
if [[ -z "${BASE_PROMPT}" ]]; then
    err "Could not extract the 'Prompt to paste' block from ${PROMPT_DOC}."
    exit 1
fi

VARIANT_1="${BASE_PROMPT}
Use STATS ... BY source.ip with COUNT_DISTINCT(user.name) as a separate metric from the total failed-attempt count - do not rely on COUNT(*) alone."

VARIANT_2="Over authentication logs (event.category == \"authentication\" AND event.outcome == \"failure\"), write an ES|QL query that:
1. Groups results BY source.ip.
2. Computes two separate STATS metrics: the total count of failed attempts, and COUNT_DISTINCT(user.name) as the number of distinct usernames targeted.
3. Filters (in a second WHERE, after STATS) to rows where the distinct-username count is >= 5 AND the total failed-attempt count is >= 10.
This detects password spraying: one source IP failing auth against many distinct accounts, not just many attempts against one account."

VARIANTS=("${BASE_PROMPT}" "${VARIANT_1}" "${VARIANT_2}")
VARIANT_LABELS=("documented prompt (as-is)" "documented prompt + explicit COUNT_DISTINCT hint" "fully explicit step-by-step rewrite")

# --------------------------------------------------------------------------
# API helpers
# --------------------------------------------------------------------------
generate_esql() {
    local user_prompt="$1"
    local user_file body resp status content
    user_file="${WORKDIR}/user.txt"
    printf '%s' "${user_prompt}" >"${user_file}"

    body="$(jq -n --rawfile sys "${SYSTEM_PROMPT_FILE}" --rawfile usr "${user_file}" \
        '{params:{subAction:"unified_completion",subActionParams:{body:{messages:[{role:"system",content:$sys},{role:"user",content:$usr}]}}}}')"

    resp="$(curl -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -X POST "${KIBANA_URL%/}/api/actions/connector/${CONNECTOR_ID}/_execute" --data-binary "${body}")"

    status="$(jq -r '.status // "error"' <<<"${resp}" 2>/dev/null || echo error)"
    if [[ "${status}" != "ok" ]]; then
        echo "LLM_ERROR: $(jq -r '.service_message // .message // "unknown error"' <<<"${resp}" 2>/dev/null)"
        return 1
    fi

    content="$(jq -r '.data.choices[0].message.content // empty' <<<"${resp}" 2>/dev/null)"
    if [[ -z "${content}" ]]; then
        echo "LLM_ERROR: empty response content"
        return 1
    fi

    # Strip any markdown code-fence lines the model added despite instructions.
    content="$(printf '%s' "${content}" | sed -e '/^```/d')"
    printf '%s' "${content}"
}

run_esql() {
    local query="$1" body resp code
    body="$(jq -n --arg q "${query}" '{query:$q}')"
    resp="$(curl -s -w '\n%{http_code}' -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' \
        -X POST "${ELASTICSEARCH_URL%/}/_query" --data-binary "${body}")"
    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    printf '%s\n%s' "${code}" "${body}"
}

GRADE_FILTER='
  (.columns // []) as $cols
  | ($cols | map(.name)) as $names
  | ($cols | map(.type)) as $types
  | ( [ (.values // [])[]? | . as $row
        | reduce range(0; ($names|length)) as $i ({}; . + {($names[$i]): $row[$i]})
      ] ) as $rows
  | ( [ range(0; ($names|length)) | select($types[.] as $t | ($t=="long" or $t=="integer" or $t=="double" or $t=="unsigned_long")) ] ) as $metric_idx
  | ( $rows | map(select(.["source.ip"] == $aip)) | first ) as $a
  | ( $rows | map(select(.["source.ip"] == $bip)) | first ) as $b
  | (if $a == null then [] else [ $metric_idx[] as $i | $a[$names[$i]] ] end) as $am
  | (if $b == null then [] else [ $metric_idx[] as $i | $b[$names[$i]] ] end) as $bm
  | {
      attacker_fires: ( ($am | map(select(. >= 5)) | length) >= 2 and ($am | map(select(. >= 10)) | length) >= 1 ),
      benign_fires: ( ($bm | map(select(. >= 5)) | length) >= 2 and ($bm | map(select(. >= 10)) | length) >= 1 )
    }
'

# grade_query QUERY -> prints one of: PASS | FAIL:reason
grade_query() {
    local query="$1" result code body verdict
    result="$(run_esql "${query}")"
    code="$(head -n1 <<<"${result}")"
    body="$(tail -n +2 <<<"${result}")"

    if [[ "${code}" != "200" ]]; then
        echo "FAIL:esql_error(${code})"
        return
    fi

    verdict="$(jq -c --arg aip "${ATTACKER_IP}" --arg bip "${BENIGN_IP}" "${GRADE_FILTER}" <<<"${body}" 2>/dev/null || echo '{}')"
    local attacker_fires benign_fires
    attacker_fires="$(jq -r '.attacker_fires // false' <<<"${verdict}")"
    benign_fires="$(jq -r '.benign_fires // false' <<<"${verdict}")"

    if [[ "${attacker_fires}" == "true" && "${benign_fires}" == "false" ]]; then
        echo "PASS"
    elif [[ "${attacker_fires}" != "true" ]]; then
        echo "FAIL:missed_attacker"
    else
        echo "FAIL:false_positive_benign"
    fi
}

# --------------------------------------------------------------------------
# Main loop: seed data once, then test each variant in order until one
# clears THRESHOLD (or we run out of variants).
# --------------------------------------------------------------------------
step "Seeding fresh password-spray telemetry"
"${REPO_ROOT}/demo/seed-password-spray-data.sh"

log ""
log "Connector under test: ${CONNECTOR_ID}"
log "Trials per variant:   ${TRIALS}"
log "Pass-rate threshold:  ${THRESHOLD}"

WINNING_VARIANT_INDEX=-1

for i in "${!VARIANTS[@]}"; do
    step "Variant ${i}: ${VARIANT_LABELS[$i]}"

    pass=0
    declare -A fail_reasons=()

    for ((t = 1; t <= TRIALS; t++)); do
        esql_or_err="$(generate_esql "${VARIANTS[$i]}")" || {
            fail_reasons["llm_error"]=$(( ${fail_reasons["llm_error"]:-0} + 1 ))
            printf 'E'
            continue
        }

        verdict="$(grade_query "${esql_or_err}")"
        if [[ "${verdict}" == "PASS" ]]; then
            pass=$((pass + 1))
            printf '.'
        else
            reason="${verdict#FAIL:}"
            fail_reasons["${reason}"]=$(( ${fail_reasons["${reason}"]:-0} + 1 ))
            printf 'x'
        fi
    done
    echo ""

    rate="$(echo "scale=2; ${pass} / ${TRIALS}" | bc)"
    log "Variant ${i} pass rate: ${pass}/${TRIALS} (${rate})"
    if [[ "${#fail_reasons[@]}" -gt 0 ]]; then
        log "Failure breakdown:"
        for reason in "${!fail_reasons[@]}"; do
            log "  - ${reason}: ${fail_reasons[${reason}]}"
        done
    fi

    meets_threshold="$(echo "${rate} >= ${THRESHOLD}" | bc)"
    if [[ "${meets_threshold}" == "1" ]]; then
        WINNING_VARIANT_INDEX="${i}"
        break
    fi

    unset fail_reasons
done

step "Result"

if [[ "${WINNING_VARIANT_INDEX}" -eq 0 ]]; then
    log "The documented prompt (config/ai-detection-rule-prompt.md, as-is) meets the ${THRESHOLD} pass-rate target. No change needed."
    exit 0
elif [[ "${WINNING_VARIANT_INDEX}" -ge 0 ]]; then
    log "The documented prompt did NOT meet the ${THRESHOLD} target, but variant ${WINNING_VARIANT_INDEX} did:"
    log ""
    log "----------------------------------------"
    log "${VARIANTS[$WINNING_VARIANT_INDEX]}"
    log "----------------------------------------"
    log ""
    log "Nothing was written automatically. If you want to adopt this wording, update the"
    log "'Prompt to paste' block in config/ai-detection-rule-prompt.md by hand (or ask for it)."
    exit 1
else
    log "No variant reached the ${THRESHOLD} pass-rate target against connector ${CONNECTOR_ID}."
    log "Review the failure breakdowns above before changing the prompt further."
    exit 1
fi
