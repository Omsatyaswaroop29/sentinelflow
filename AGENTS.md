# SentinelFlow Agent Architecture

This file is the **source-of-truth summary** for SentinelFlow's development agents. Each agent is defined as an executable `.claude/agents/<name>.md` file with a fixed system prompt, structured inputs/outputs, and a quality checklist. Engineers should edit the individual agent files; this document only summarizes them.

---

## Canonical Roles

| Agent | File | Model | Purpose |
|-------|------|-------|---------|
| Rule Author | `.claude/agents/rule-author.md` | opus | Authors governance rules with detection logic, test annotations, compliance mappings, and auto-fix suggestions |
| Parser Engineer | `.claude/agents/parser-engineer.md` | opus | Builds and maintains framework-specific config parsers that normalize agent definitions into the SentinelFlow schema |
| Compliance Mapper | `.claude/agents/compliance-mapper.md` | sonnet | Maps rules and findings to OWASP LLM 2025, EU AI Act, NIST AI RMF, MITRE ATLAS, ISO 42001, SOC 2, HIPAA, GDPR |
| Red-Team Adversary | `.claude/agents/red-team.md` | opus | Attempts to evade rules using obfuscation, encoding, structural tricks, and framework-specific hiding techniques |
| Corpus QA | `.claude/agents/corpus-qa.md` | sonnet | Validates parsers and rules against the curated test corpus; guards against regressions and false positives |

The **SentinelFlow Architect** (you, the human) is the top-level orchestrator — not an agent file. You invoke agents, review their artifacts, and make ship/no-ship decisions.

---

## Core Workflow: New Rule Development

**Step 1 → Parser Engineer** (if the rule requires new config parsing). Proposes changes to `@sentinelflow/parsers` so the scanner can read the config fields the new rule needs. Output: parser diff, 5+ test fixtures from real repos, capability manifest update.

**Step 2 → Rule Author.** Writes the rule implementation in `@sentinelflow/scanner/rules/`. Output: rule TypeScript file with detection logic, test file with `# flagged:` and `# safe:` annotations, compliance mappings, auto-fix suggestion, and CLI remediation text.

**Step 3 → Compliance Mapper** (parallel with Step 4). Verifies and enriches the rule's compliance mappings. Output: validated mapping table with specific article/control references and justifications.

**Step 4 → Red-Team Adversary** (parallel with Step 3). Attempts to evade the rule using 5+ techniques. Output: evasion report with configs that should-have-been-caught (gaps) and configs correctly ignored (FP checks).

**Step 5 → Corpus QA.** Runs the full test suite including any new fixtures from Red-Team. Output: regression report showing new passes/fails, false positive delta, and SARIF sample.

**Step 6 → Architect Decision.** Review artifacts from steps 2–5. Decide: ship as `stable`, ship as `experimental`, or send back for another loop.

---

## Artifact Contracts

**Parser Engineer →** parser diff, test fixture list (≥5 real-world patterns with source URLs), capability manifest (file patterns, versions, edge cases), backward-compat statement.

**Rule Author →** rule `.ts` file, test `.test.ts` file with flagged/safe annotations, severity + compliance mapping table, auto-fix config, known false positive list, CLI remediation text.

**Compliance Mapper →** mapping validation table (framework → reference → justification), new CWE/CVE references if any, one-paragraph compliance impact summary.

**Red-Team Adversary →** 5+ evasion configs per rule, gap analysis (what was missed), false-positive analysis (what was incorrectly flagged), recommendations for rule hardening.

**Corpus QA →** corpus manifest update, regression report (new passes/fails by rule ID), false positive delta, SARIF snippet, go/no-go recommendation.

---

## Rule Graduation Model

`experimental` → New rule. Monitor-only mode. No CI failures. Requires ≥3 flagged and ≥3 safe test annotations. Red-Team must produce ≥3 evasion attempts.

`stable` → Demonstrated <20% FP rate across corpus. Runs in standard preset (CI fails on critical/high). Requires Corpus QA sign-off.

`enforced` → Demonstrated <10% FP rate. Runs in strict preset. Requires Architect approval.

`deprecated` → Superseded. Remains functional but receives no maintenance. `superseded_by` field points to replacement.
