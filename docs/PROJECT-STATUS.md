# Project Status — SentinelFlow (Enterprise-ready overview)

This document is the **living status + roadmap** for SentinelFlow. It's intended to be readable by both engineers and evaluators.

---

## What SentinelFlow is

SentinelFlow is a vendor-neutral governance layer for AI agents with two capabilities:

- **Static scanning (Phase 1, stable)**: finds security + compliance misconfigurations in agent configuration files (parsers + governance rules + SARIF).
- **Runtime interception (Phase 2, beta)**: intercepts agent tool calls in real-time via framework hooks, evaluates governance policies, logs normalized events, and can block dangerous actions before they execute.

---

## Current state (what's working)

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
- **Handler scripts**: generated at install time into `.sentinelflow/` and registered via each framework's native hook config.
- **Blocking contract**:
  - Claude/Copilot/Codex: **exit code 2** + stderr reason
  - Cursor: **stdout JSON** (`{ permission: "deny" | "ask" | "allow" }`) + exit 0
- **Fail-open**: handlers catch errors and allow the tool call if SentinelFlow fails (including when the optional `better-sqlite3` dependency isn't installed — events fall back to JSONL-only).
- **Event store**: dual-write to **JSONL + SQLite** (`.sentinelflow/events.jsonl`, `.sentinelflow/events.db`) with CLI queries.
- **Policy as code**: `.sentinelflow-policy.yaml`'s `runtime_policies` section is loaded by `intercept install` as defaults — CLI flags override, but config can now be checked into version control instead of re-typed on every install.

---

## Enterprise policy engine (runtime)

### Central registry

All patterns are centralized in `packages/interceptors/src/patterns.ts` and compiled in generated handlers via `JSON.stringify(...)` → `new RegExp(...)` (no regex literals in handler templates).

- **Dangerous command patterns**: 18
- **Secrets patterns**: 15
- **Sensitive file write path patterns**: 12
- **Network egress patterns**: 7

### Policy implementations

There are **8 policy classes** in `packages/interceptors/src/policies.ts` (TypeScript runtime engine), plus data boundary classification (`data-boundary.ts`), identity/RBAC/environment policy (`identity.ts`), and multi-step sequence detection (`sequence.ts`, ported into the generated handlers as SQLite-backed history reconstruction — see below).

### Runtime enforcement matrix (today)

| Policy / Control | TypeScript engine (`policies.ts` etc.) | Generated hook handlers (`handler-codegen.ts`) |
|---|---:|---:|
| Tool allowlist | Yes | Yes |
| Tool blocklist | Yes | Yes |
| Dangerous command blocking (18 patterns) | Yes | Yes |
| Secrets / credential leak prevention (15 patterns) | Yes | Yes |
| Sensitive file write governance (12 path categories + shell redirects/`tee`) | Yes | Yes |
| Network egress policy (7 patterns + domain allow/block lists) | Yes | Yes |
| Data boundary classification + clearance (governs reads, not just writes) | Yes | **Yes** — monitor mode by default |
| Identity / role-based access control (reader→admin privilege levels) | Yes | **Yes** — monitor mode by default |
| Environment policy (production/CI/external-facing restrictions) | Yes | **Yes** — monitor mode by default |
| Multi-step sequence detection (script injection, exfiltration, persistence probe, privilege chain) | Yes | **Yes** — SQLite-backed history reconstruction, monitor mode by default |
| Cost budgets | Yes | Not yet — see honest limitation below |

Each advanced policy (data boundary, identity/RBAC, sequence detection) has its **own independent `enforcement_mode`**, defaulting to `monitor`, separate from the core subset's enforcement mode. This means graduating an existing "enforce" installation to the new policies is an explicit opt-in via `.sentinelflow-policy.yaml`, never a surprise behavior change on upgrade. See `.sentinelflow-policy.example.yaml` for the full schema.

**Honest limitation — cost budgets**: no supported framework (Claude Code, Cursor, Copilot, Codex) exposes token/cost data in hook payloads as of this release, so `CostBudgetPolicy` cannot fire on individual tool calls. Cost is still tracked when frameworks report it via the SQLite event store, queryable via `sentinelflow costs`.

### Why sequence detection is SQLite-backed, not in-memory

Framework hooks spawn a **fresh handler process for every tool call** — they are not long-running daemons. An in-memory sliding window (as used by the `SequenceDetector` TypeScript class for programmatic use) would reset on every invocation and never see prior calls. The generated handlers instead reconstruct session history by querying the same SQLite event store they already write to (`SELECT ... WHERE session_id = ? AND ts >= ?`), then run the same deterministic chain-detection logic against that history. If `better-sqlite3` is unavailable, sequence detection no-ops gracefully (consistent with the rest of the fail-open design) — it requires persisted history to correlate against.

### Anomaly detection (batch, not per-call)

`NovelToolDetector`, `CostSpikeDetector`, and `ErrorRateDetector` are statistical/rate-based — they need many events to build a baseline, which is a better fit for periodic analysis than synchronous per-tool-call evaluation. `sentinelflow anomalies` runs them in batch over the SQLite event history. `PrivilegeEscalationDetector` is included only when `.sentinelflow-policy.yaml`'s `identity.agent_roles`/`agent_privileges` are configured — without real per-agent privilege data, its built-in default (privilege 3 for every unlisted agent) would flag nearly every Bash/Write call; real-time RBAC already covers that exact concern with a better-calibrated default (privilege 6).

---

## Test status (production-path validation)

SentinelFlow's runtime layer is validated two ways:

- **Vitest suite**: 442 tests passing across all 5 packages (unit tests, policy/handler-codegen tests, and E2E handler tests that spawn the actual generated handler scripts as subprocesses).
- **Golden path scripts**: end-to-end contract tests that install hooks via the CLI and run the generated handler scripts, covering the core subset (dangerous commands, secrets, egress, allow/blocklist), data boundary, RBAC, and sequence detection:
  - `scripts/golden-path-test.sh` (Claude Code) — 25 assertions
  - `scripts/cursor-golden-path-test.sh` (Cursor) — 22 assertions
  - `scripts/copilot-golden-path-test.sh` (Copilot) — 23 assertions
  - `scripts/codex-golden-path-test.sh` (Codex) — 22 assertions

Golden paths include coverage for enterprise patterns like `sudo`, `yarn/pnpm publish`, `chmod +s`, PATH manipulation, a regression guard ensuring `git push --force-with-lease` remains allowed, and the advanced policies added in this release (data boundary blocking a `~/.ssh/id_rsa` read, RBAC blocking a reader-role agent from Bash, and a write→chmod→execute sequence chain flagged via real SQLite history reconstruction across separate process invocations).

---

## Roadmap (next work items)

### Done in this release

- ~~P0 — Close "TypeScript engine vs handler" parity gap~~ — data boundary, identity/RBAC, environment policy, and sequence detection are now wired into all 4 generated handlers, monitor-by-default with per-policy enforcement mode.
- ~~P1 — Runtime policy configuration~~ — `.sentinelflow-policy.yaml`'s `runtime_policies` section (including the new `data_boundary`, `identity`, `sequence_detection` blocks) is loaded by `intercept install`, with CLI flags overriding.

### P2 — Batch governance surfaces

- `sentinelflow anomalies` — done. Consider a `sentinelflow anomalies --watch` mode or scheduled job for continuous monitoring.
- Consistent remediation output across frameworks (partially done via per-policy reasons; could be templated further).

### P3 — Declarative dashboard / SIEM integration

- Live dashboard (Phase 2.5, not started).
- SIEM/SOAR exporters for the SQLite event store.

---

## Key references

- **Central patterns**: `packages/interceptors/src/patterns.ts`
- **Handler code generation**: `packages/interceptors/src/handler-codegen.ts`
- **Policies (TypeScript)**: `packages/interceptors/src/policies.ts`, `data-boundary.ts`, `identity.ts`, `sequence.ts`, `anomaly.ts`
- **Interceptors**: `packages/interceptors/src/{claude-code,cursor,copilot,codex}.ts`
- **Policy YAML schema**: `packages/scanner/src/suppression.ts` (`RuntimePoliciesConfig` and friends), `.sentinelflow-policy.example.yaml`
- **Phase 2 docs**: `docs/PHASE-2.md`
