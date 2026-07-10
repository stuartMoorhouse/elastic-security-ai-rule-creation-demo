# AI Detection Rule — Presenter Reference

Manual step. Performed live in Kibana during the webinar (Security → Rules → Create new rule → **AI rule creation**, powered by Agent Builder). Not automated by Terraform or any script in this repo.

## Prompt to paste

```
Over authentication logs, detect password spraying: a single source IP that fails authentication against many distinct user accounts. Group by source.ip, count the total failed attempts and the number of distinct usernames targeted, and alert when one IP has failed logins against 5 or more distinct users with at least 10 attempts.
```

Paste this verbatim into the AI rule creation prompt field. Let Agent Builder generate the ES|QL query and rule metadata before refining anything manually.

## Refinements to demo live

The generated query is a good starting point but is a natural fit for a few live refinements, showing AI-assisted iteration rather than one-shot generation:

- **Exclude a known-good egress range** — e.g. `AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8")` for a trusted VPN/office range.
- **Add a time window** — bucket by `BUCKET(@timestamp, 15 minutes)` so the aggregation resets per window instead of running unbounded.
- **Surface the targeted usernames on the alert** — keep `targeted_users = VALUES(user.name)` in the `STATS` and make sure it's mapped as a rule field so it's visible in the alert table and available to the case AI-analysis comment.

## Expected MITRE ATT&CK mapping

After generation, verify the rule's ATT&CK tags include (or map closely to):

| Technique | ID | Why it should appear |
|---|---|---|
| Brute Force: Password Spraying | T1110.003 | The core technique — many accounts, few attempts each, from one source |

If the AI-generated rule omits this, add it manually in the MITRE ATT&CK mapping section before applying — do not skip verification just because generation "looks done."

## Checklist

Run `demo/seed-password-spray-data.sh` (or the requests in `demo/create-sample-data.http`) **before** starting this checklist — the rule preview step below needs live data indexed to validate against, not an empty result set.

1. Paste the prompt above into AI rule creation.
2. Review the generated ES|QL query — confirm it aggregates `BY source.ip` with `COUNT_DISTINCT(user.name)` as the primary signal (not just `COUNT(*)`), and filters on `event.category == "authentication" AND event.outcome == "failure"`.
3. Optionally demo a refinement (egress exclusion, time bucket, or targeted-users field — see above).
4. Verify the MITRE ATT&CK mapping against the table above; add T1110.003 manually if missing.
5. **Click Preview rule results** — this runs the query against the already-seeded live data (no sample/sandbox set) and should reproduce the Expected result table below. This is the validation step: confirm it *before* applying, not after enabling.
6. Click **Apply to creation** to carry the query and mapping into the rule editor.
7. Review rule name, severity, risk score, and index pattern defaults.
8. Save and **enable** the rule.

## Expected result (for reference in the rule preview, and later in the alert)

Seeded via `demo/create-sample-data.http`:

| source.ip | distinct_users | failed_attempts | Fires? |
|---|---|---|---|
| `203.0.113.66` (attacker) | 8 | 14 | Yes |
| `198.51.100.20` (benign) | 2 | 3 | No — below `distinct_users >= 5` |

This is the result the AI-authored rule must reproduce in **Preview rule results** (step 5, against live data — the same proof point the rule uses to fire for real once enabled), and the result that should appear in the alert after enabling (Acceptance Criteria #6).
