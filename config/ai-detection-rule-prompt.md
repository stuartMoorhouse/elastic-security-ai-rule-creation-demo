# AI Detection Rule — Presenter Reference

Manual step. Performed live in Kibana during the webinar (Security → Rules → Create new rule → **AI rule creation**, powered by Agent Builder). Not automated by Terraform or any script in this repo.

## Prompt to paste

```
Detect a ClickFix-style attack where a command from the Run dialog or mshta spawns PowerShell or curl to download a payload.
```

Paste this verbatim into the AI rule creation prompt field. Let Agent Builder generate the ES|QL query and rule metadata before refining anything manually.

## Expected MITRE ATT&CK mapping

After generation, verify the rule's ATT&CK tags include (or map closely to):

| Technique | ID | Why it should appear |
|---|---|---|
| Mshta | T1218.005 | `mshta` is the LOLBin invoked from the Run dialog step |
| PowerShell | T1059.001 | `mshta` spawns `powershell` |
| Windows Command Shell | T1059.003 | `forfiles`/command-shell invocation preceding `mshta` |
| Boot or Logon Autostart Execution | T1547 | `wscript`/`reg.exe` persistence step at the end of the chain |

If the AI-generated rule omits one of these, add it manually in the MITRE ATT&CK mapping section before applying — do not skip verification just because generation "looks done."

## Checklist

1. Paste the prompt above into AI rule creation.
2. Review the generated ES|QL query — confirm it matches on the process chain (parent/child `process.name` sequence), not just a single event.
3. Verify the MITRE ATT&CK mapping against the table above; add any missing techniques manually.
4. Click **Apply to creation** to carry the query and mapping into the rule editor.
5. Review rule name, severity, risk score, and index pattern defaults.
6. Save and **enable** the rule.

## Expected process tree (for reference while reviewing the query and later in the Analyzer)

```
forfiles
  └─ mshta
       └─ powershell
            └─ curl.exe
            └─ wscript  (or reg.exe)
```

`curl.exe` fetches a harmless file (no real payload). `wscript`/`reg.exe` represents the benign persistence step. This is the tree the AI-authored rule must detect, and the tree that should appear in the Analyzer after running `demo/simulate-lolbin-chain.ps1` (Acceptance Criteria #5, #7).
