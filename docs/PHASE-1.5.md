# Phase 1.5 — Definition of Done

**Ship date target:** 2 weeks from today
**One-sentence goal:** Any Claude Code or Cursor repo runs `npx sentinelflow scan`, gets 3–7 high-signal remediable findings with inline fix snippets, and uploads SARIF to GitHub Code Scanning — in under 60 seconds, zero config.

---

## Success Criteria (all must be true)

### 1. Two-command quickstart works on any machine

```bash
npm install -g sentinelflow   # or: npx sentinelflow scan .
sentinelflow scan .
```

No auth. No config file. No interactive prompts. Auto-detects Claude Code and Cursor projects. Produces findings immediately.

**Verification:** Fresh macOS, Linux, and Node 20 CI runner. Clone ECC, run `npx sentinelflow scan .`, confirm findings appear in < 5 seconds.

### 2. Every finding has an inline fix snippet

Each finding in terminal output shows the exact file and line, the problematic config value, a concrete "Fix:" line showing what to change, and a docs URL.

Example output:
```
  CRITICAL  SF-FC-001  .claude/settings.json:3
  Permission checks disabled via --dangerously-skip-permissions

    2│ {
    3│   "dangerouslySkipPermissions": true   ← remove this
    4│ }

  Fix: Remove "dangerouslySkipPermissions" from settings.json.
       Use granular tool permissions instead:
       "allowedTools": ["Bash(npm test)", "Bash(git diff)"]
  Ref: https://sentinelflow.dev/rules/SF-FC-001
       OWASP LLM06 · EU AI Act Art.14 · CWE-862
```

**Verification:** Scan ECC. Every one of the 133 findings has a non-empty `recommendation` field and a `location.file` + `location.line`.

### 3. Suppression system with audit trails

Users can suppress findings three ways, all producing auditable evidence. Inline comments (`# sentinelflow-ignore: SF-FC-001 -- Sandboxed CI only, SEC-1294`), a policy file (`.sentinelflow-policy.yaml` with expiration dates, approver, ticket), and CLI presets (`--preset monitor` makes all findings informational so CI never fails).

**Verification:** Create test project with 3 suppressions. Confirm `sentinelflow scan` respects them. Confirm `sentinelflow scan --show-suppressed` reveals them.

### 4. SARIF output uploads cleanly to GitHub Code Scanning

```yaml
- run: npx sentinelflow scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Verification:** Upload SARIF from ECC scan to a test repo. Confirm findings appear in GitHub Security tab.

### 5. Three scan presets for progressive adoption

`strict` fails CI on any warning or above — for production governance. `standard` (default) fails on critical/high — for active development. `monitor` never fails CI — for initial adoption and baselining.

**Verification:** Same project produces exit code 1 with `strict`, exit code 1 with `standard` (if critical/high exist), exit code 0 with `monitor`.

### 6. Zero critical false positives on test corpus

SentinelFlow CI runs against a curated corpus: ECC (Claude Code, 30 agents, ~35 critical findings), awesome-cursor-rules-mdc (Cursor, 5+ rules, 0 critical), SentinelFlow self-scan (clean by design). A "critical false positive" means a critical finding that recommends removing something that is actually correct and safe. Zero allowed.

**Verification:** Corpus test suite in CI, green on every PR.

### 7. Coverage footer on every scan

Every scan output ends with a coverage note listing what was analyzed (static config) and what was not (IAM roles, runtime secrets, network policies, feature flags), with a link to integration docs.

**Verification:** Footer appears in terminal, JSON, and Markdown output.

---

## Out of Scope for Phase 1.5

Runtime monitoring, policy engine, approval workflows, LangChain/CrewAI/Kiro deep rules (parsers exist but deep rules come after Claude Code + Cursor are bulletproof), dashboard/web UI, npm publish to public registry (comes immediately after Phase 1.5 sign-off), Python SDK.

---

## 90-Day Post-Launch Metrics

500–1,000 GitHub stars, 200+ npm weekly downloads, 10–50 organizations scanning weekly, 0% critical false positive rate, < 60 second install-to-first-finding, 3+ external contributors.
