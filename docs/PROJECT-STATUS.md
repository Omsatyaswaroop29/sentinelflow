# Project Status — SentinelFlow (Enterprise-ready overview)

This document is the **living status + roadmap** for SentinelFlow. It’s intended to be readable by both engineers and evaluators.

---

## What SentinelFlow is

SentinelFlow is a vendor-neutral governance layer for AI agents with two capabilities:

- **Static scanning (Phase 1, stable)**: finds security + compliance misconfigurations in agent configuration files (parsers + governance rules + SARIF).
- **Runtime interception (Phase 2, beta)**: intercepts agent tool calls in real-time via framework hooks, evaluates governance policies, logs normalized events, and can block dangerous actions before they execute.

---

## Current state (what’s working)

### Phase 1 — Static scanner (stable)

- **Rules**: 46 governance rules across 10 categories
- **Parsers**: 6 framework parsers (Claude Code, Cursor, Codex, LangChain, CrewAI, Kiro)
- **Outputs**: terminal, Markdown, JSON, SARIF
- **CI-friendly**: presets (`standard`, `monitor`, `strict`) + suppressions

### Phase 2 — Runtime interception (beta)

- **Frameworks supported**:
  - Claude Code
  - Cursor
  - GitHub Copilot
  - Codex CLI
- **Handler scripts**: generated at install time into `.sentinelflow/` and registered via each framework’s native hook config.
- **Blocking contract**:
  - Claude/Copilot/Codex: **exit code 2** + stderr reason
  - Cursor: **stdout JSON** (`{ permission: "deny" | "ask" | "allow" }`) + exit 0
- **Fail-open**: handlers catch errors and allow the tool call if SentinelFlow fails.
- **Event store**: dual-write to **JSONL + SQLite** (`.sentinelflow/events.jsonl`, `.sentinelflow/events.db`) with CLI queries.

---

## Enterprise policy engine (runtime)

### Central registry

All patterns are centralized in `packages/interceptors/src/patterns.ts` and compiled in generated handlers via `JSON.stringify(...)` → `new RegExp(...)` (no regex literals in handler templates).

- **Dangerous command patterns**: 18
- **Secrets patterns**: 15
- **Sensitive file write path patterns**: 12
- **Network egress patterns**: 7

### Policy implementations

There are **8 policy classes** in `packages/interceptors/src/policies.ts` (TypeScript runtime engine).

**Important nuance:** generated production handlers currently enforce the **core subset** needed for safe runtime blocking (dangerous commands + secrets + sensitive write paths + allow/block lists). More advanced policies (data boundary classification, network allowlists, identity governance, and sequence detection) exist in TypeScript and are the next integration step for full parity.

### Runtime enforcement matrix (today)

| Policy / Control | TypeScript engine (`policies.ts`) | Generated hook handlers (`handler-codegen.ts`) |
|---|---:|---:|
| Tool allowlist | Yes | Yes |
| Tool blocklist | Yes | Yes |
| Dangerous command blocking (18 patterns) | Yes | Yes |
| Secrets / credential leak prevention (15 patterns) | Yes | Yes |
| Sensitive file write governance (12 path categories + shell redirects/`tee`) | Yes | Yes |
| Network egress policy (7 patterns + domain allow/block lists) | Yes | Not yet |
| Data boundary classification + clearance | Yes | Not yet |
| Cost budgets | Yes | Not yet |

---

## Test status (production-path validation)

SentinelFlow’s runtime layer is validated two ways:

- **Vitest suite**: unit tests + E2E handler tests in `packages/interceptors/src/__tests__/` (228+ tests)
- **Golden path scripts**: end-to-end contract tests that install hooks via the CLI and run the generated handler scripts:
  - `scripts/golden-path-test.sh` (Claude Code)
  - `scripts/cursor-golden-path-test.sh` (Cursor)
  - `scripts/copilot-golden-path-test.sh` (Copilot)
  - `scripts/codex-golden-path-test.sh` (Codex)

Golden paths include coverage for newer enterprise patterns like `sudo`, `yarn/pnpm publish`, `chmod +s`, PATH manipulation, and a regression guard ensuring `git push --force-with-lease` remains allowed.

---

## Roadmap (next work items)

### P0 — Close “TypeScript engine vs handler” parity gap

- Expand `packages/interceptors/src/handler-codegen.ts` to include additional enterprise policies that are safe to embed self-contained.
- Add “observe-only” evaluation first for higher-risk policies, then allow enforcing behind config flags.

### P1 — Runtime policy configuration

- Expand `.sentinelflow-policy.yaml` runtime surface area (policy toggles, allowlists, domain allowlists, boundary settings).
- Add consistent remediation output across frameworks.

### P2 — Advanced governance features

- Sequence detection and multi-step attack chain blocking (start as monitor-only).
- Identity-based access controls and environment policies (enterprise defaults).

---

## Key references

- **Central patterns**: `packages/interceptors/src/patterns.ts`
- **Handler code generation**: `packages/interceptors/src/handler-codegen.ts`
- **Policies (TypeScript)**: `packages/interceptors/src/policies.ts`
- **Interceptors**: `packages/interceptors/src/{claude-code,cursor,copilot,codex}.ts`
- **Phase 2 docs**: `docs/PHASE-2.md`

