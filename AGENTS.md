# SentinelFlow Agent Architecture

This file is the **source-of-truth summary** for SentinelFlow's development agents. Each agent is defined as an executable `.claude/agents/<name>.md` file. Engineers edit the individual agent files; this document defines roles, workflows, and artifact contracts. The human **SentinelFlow Architect** orchestrates agents, reviews artifacts, and makes ship/no-ship decisions.

## Canonical agent roles

| Agent | File | Domain | Purpose |
|-------|------|--------|---------|
| Rule Author | `.claude/agents/rule-author.md` | Static | Implement static governance rules with tests, compliance mappings, remediation |
| Parser Engineer | `.claude/agents/parser-engineer.md` | Static | Build framework parsers that normalize configs into the core schema |
| Handler Engineer | `.claude/agents/handler-engineer.md` | Runtime | Build framework interceptors, handler scripts, and the code generator |
| Policy Architect | `.claude/agents/policy-architect.md` | Runtime | Design runtime policies, detection patterns, and the central pattern registry |
| Compliance Mapper | `.claude/agents/compliance-mapper.md` | Both | Map rules and controls to OWASP LLM, EU AI Act, NIST, MITRE ATLAS, ISO 42001, SOC 2 |
| Red-Team Adversary | `.claude/agents/red-team.md` | Both | Evade rules and handlers via obfuscation, encoding, multi-step chains |
| Corpus QA | `.claude/agents/corpus-qa.md` | Both | Validate against test suites and golden path scripts; guard regressions |

## Global rules for all agents

1. Follow `CLAUDE.md` constraints. Never mutate schemas without explicit request.
2. Outputs must be structured and machine-checkable.
3. Be honest about uncertainty. Label assumptions.
4. Never introduce secrets into code or tests.
5. Stay within your role. Recommend other agents for cross-cutting work.
6. For runtime changes, golden path scripts must pass alongside `pnpm test`.
7. Never use regex literals in generated handler code — use `JSON.stringify()` + `new RegExp()`.
8. Remember Cursor blocks via stdout JSON, not exit codes.

## Workflow A: New scanner rule

Step 0: Architect defines rule intent, target frameworks, severity.
Step 1: Parser Engineer adds config parsing if needed (≥5 fixtures).
Step 2: Rule Author implements pure function, tests (≥3 flagged, ≥3 safe, ≥1 edge).
Step 3: Compliance Mapper validates mappings (parallel with 4).
Step 4: Red-Team attempts ≥5 evasion techniques (parallel with 3).
Step 5: Corpus QA runs full suite, regression report, go/no-go.
Step 6: Architect ships as stable, experimental, or sends back.

## Workflow B: Runtime interceptor or handler update

Step 0: Architect defines framework, hooks contract, blocking mechanism.
Step 1: Handler Engineer implements using `generatePolicyEvaluationCode()`, correct blocking, CLI, golden path (≥10 tests), E2E vitest (≥10 tests).
Step 2: Policy Architect adds patterns to `patterns.ts` if needed, with tests.
Step 3: Red-Team tests bypass (obfuscation, multi-step, framework evasion).
Step 4: Corpus QA runs all tests + golden paths. Zero regressions.
Step 5: Architect decision.

## Workflow C: New detection pattern (fast path)

1. Policy Architect adds pattern to `patterns.ts` with ID and test.
2. Red-Team verifies catch + no false-positive.
3. Corpus QA runs all tests + golden paths.
4. Architect approves.

## Artifact contracts

**Parser Engineer** — diff summary, fixtures (≥5), capability manifest, backward-compat.
**Rule Author** — metadata, implementation, tests (≥3/≥3/≥1), compliance, remediation, limitations.
**Handler Engineer** — interceptor using handler-codegen, hooks docs, CLI, golden path (≥10), E2E (≥10).
**Policy Architect** — patterns (ID, regex, severity, tags), tests, compliance, codegen verification.
**Compliance Mapper** — mapping table, CWE/CVE, impact summary, open questions.
**Red-Team** — ≥5 evasion configs (labeled), gap analysis, FP analysis, recommendations.
**Corpus QA** — test results, golden paths, regression report, FP delta, SARIF snippet, go/no-go.

## Rule graduation model

**experimental** — Monitor-only. ≥3 flagged + ≥3 safe tests. Red-Team ≥3 evasion attempts.
**stable** — <20% FP rate. Standard preset. Corpus QA sign-off + compliance mapping.
**enforced** — <10% FP rate. Strict preset. Architect approval. No critical gaps.
**deprecated** — Superseded. Functional but unmaintained. Has `superseded_by`.

## Handler graduation model

**draft** — Skeleton, not wired to handler-codegen.
**integrated** — Uses `generatePolicyEvaluationCode()`. Golden paths pass.
**validated** — Tested against real session.
**stable** — External users, no crash reports.

Current: Claude Code (validated), Cursor (integrated), Copilot (integrated), Codex CLI (integrated).

## Architect operating model

The human Architect sets priorities, drafts intents, decides ship/no-ship, maintains CLAUDE.md and agents.md. Treat `.claude/agents/*.md` and this file as the control plane.
