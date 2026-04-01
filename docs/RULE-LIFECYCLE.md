# Rule Lifecycle

Every SentinelFlow rule follows a defined lifecycle from proposal to deprecation. This document is the canonical reference for rule authors, reviewers, and the CI system that enforces quality.

---

## Rule states

A rule moves through five states: **draft → active → tuning → deprecated → removed**. Draft rules exist only in PRs and test fixtures. Active rules ship in the default rule set and produce findings. Tuning rules are active but flagged for precision/recall review based on user feedback or corpus testing. Deprecated rules emit a warning suggesting their replacement. Removed rules are deleted from the codebase after one major version of deprecation notice.

## Rule ID format

Every rule ID follows the pattern `SF-<CATEGORY>-<NUMBER>`:

```
SF-AC-001    Access Control rule #1
SF-PI-002    Prompt Injection rule #2
SF-FC-007    Framework Config rule #7
```

Categories: PI (Prompt Injection), AC (Access Control), SC (Supply Chain), DG (Data Governance), CG (Cost Governance), FC (Framework Config), MA (Multi-Agent), AL (Audit Logging), CD (Compliance Docs), NS (Network Security).

Rule IDs are **never reused**. A deprecated rule's ID is permanently retired.

## Rule metadata (required for every rule)

Every `ScanRule` object must include:

```typescript
{
  id: "SF-AC-001",
  name: "Hardcoded Credentials in Agent Configuration",
  description: "Detects API keys, tokens, passwords embedded in agent configs.",
  category: "access_control",
  severity: "critical",                    // Default severity
  frameworks: "all",                       // or ["claude-code", "cursor"]
  phase: "static",
  compliance: [
    { framework: "OWASP_LLM_2025", reference: "LLM06:2025" },
    { framework: "EU_AI_ACT", reference: "Article 15" },
  ],

  // === NEW: Lifecycle metadata ===
  // These fields are documented here and enforced by review checklist.
  // They appear in rule comments, not the interface (to avoid breaking changes).
}
```

The following metadata lives in the JSDoc header of each rule's evaluate function:

```typescript
/**
 * @rule SF-AC-001
 * @since v0.1.0
 * @frameworks all
 * @severity critical
 * @fp_rate low — triggers only on high-confidence regex patterns with 16 distinct secret formats
 * @fp_patterns
 *   - Example API keys in documentation/comments (mitigated: skip lines with "example", "placeholder", "xxx")
 *   - Base64-encoded strings that happen to match key prefixes (mitigated: minimum length thresholds)
 * @tuning Users can suppress per-file via policy exclude for test fixtures and documentation directories.
 * @autofix No — secrets must be manually moved to environment variables or a secrets manager.
 * @test_corpus
 *   - ECC: expects 3+ findings (settings.json, .env references)
 *   - cursor-rules-mdc: expects 0 findings (no secrets in rule files)
 */
```

## What "good" looks like for a rule

A rule is ready to ship when it passes this checklist:

**Detection quality:**
- [ ] Produces at least 1 true positive on the test corpus
- [ ] Produces zero critical false positives on the test corpus  
- [ ] Has at least 2 test cases: one that SHOULD trigger and one that SHOULD NOT
- [ ] Documents known false positive patterns and how to suppress them

**Remediation quality:**
- [ ] Every finding includes a `recommendation` with a concrete fix
- [ ] The recommendation includes a copy-pasteable config snippet where possible
- [ ] Autofix is implemented if the fix is mechanical (add a field, change a value)

**Compliance mapping:**
- [ ] Maps to at least one OWASP LLM Top 10 2025 entry
- [ ] Maps to relevant EU AI Act article if applicable (Articles 9–15)
- [ ] Optional: NIST AI RMF subcategory, ISO 42001 control, MITRE ATLAS TTP

**Suppression:**
- [ ] Can be suppressed via inline `# sentinelflow-ignore: SF-XX-NNN -- reason`
- [ ] Can be suppressed via `.sentinelflow-policy.yaml` ignore entry
- [ ] Severity can be overridden via policy `severity_overrides`

## Severity definitions

Severity determines CI exit behavior and triage priority:

**critical** — Actively exploitable or data-leaking configuration. Hardcoded secrets, unrestricted shell execution, missing auth on external endpoints. CI fails in all presets except `monitor`.

**high** — Significant governance gap that a security team would flag in review. Missing human-in-the-loop, overpermissioned tool access, privilege escalation via delegation. CI fails in `standard` and `strict` presets.

**medium** — Best-practice violation that increases risk surface. Missing cost budgets, no agent owner, missing compliance documentation. CI fails only in `strict` preset.

**low** — Improvement opportunity. Missing description, redundant tool declarations, suboptimal model routing. Never fails CI.

**info** — Informational observation. Agent discovered but not registered, framework version detected. Never fails CI.

## False positive handling

Every rule documents its expected false positive patterns in the `@fp_patterns` JSDoc tag. When a user reports a false positive:

1. Triage: Is it a real FP or a misunderstanding of what the rule checks?
2. If real FP: Add the pattern to the rule's negative test cases
3. Implement a filter in the rule's evaluate function to exclude the pattern
4. Document the fix in the rule's `@fp_patterns` section
5. If the FP rate exceeds 20% on the test corpus, move the rule to `tuning` state

## Deprecation process

When a rule needs to be replaced (framework changed, better detection available):

1. Add `@deprecated v0.X.0 — Use SF-XX-NNN instead` to the rule's JSDoc
2. Change the rule's evaluate function to emit a single info-level finding: "Rule SF-XX-NNN is deprecated. Use SF-YY-MMM instead."
3. Keep the deprecated rule for one major version
4. Remove in the next major version

## Test corpus expectations

Each rule documents which test corpus repos it expects to fire on and what finding count is acceptable:

```
@test_corpus
  - ECC: 3-5 findings (true positives: settings.json MCP configs)
  - cursor-awesome-rules: 0 findings (no governance issues in rule templates)
  - langchain-templates/rag: 1-2 findings (ShellTool usage, missing output validation)
  - crewai-quickstart: 1-3 findings (allow_delegation default, no cost budget)
  - sentinelflow: 0 critical findings (self-scan must be clean)
```

CI enforces these ranges. If a rule suddenly produces 0 findings on a corpus where it previously found 3, that's a parser regression.
