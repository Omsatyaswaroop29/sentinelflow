# SentinelFlow

SentinelFlow is the **vendor-neutral governance layer for enterprise AI agents**. It discovers, normalizes, scans, and governs AI coding agents across frameworks — and intercepts their tool calls at runtime to enforce security policies before execution.

This file is the **root context** for all coding agents and human contributors. It explains what SentinelFlow does, how the monorepo is structured, how to work on it safely, and the hard-won design decisions that anyone touching this codebase must understand.

Detailed agent roles and workflows live in `agents.md`. Individual agent prompts live in `.claude/agents/*.md`.

---

## What SentinelFlow does

SentinelFlow operates at two levels:

**Phase 1 — Static Scanning (stable, shipped)**
- **Discovers** AI agent configurations across repositories and frameworks.
- **Normalizes** them into a universal agent schema defined in `packages/core/src/schema/agent.ts`.
- **Scans** them with 46 governance rules across 10 categories for misconfigurations, data exposure, excessive permissions, missing audit logging, and compliance gaps.
- **Reports** findings as SARIF, JSON, Markdown, or terminal output for CI integration.

**Phase 2 — Runtime Interception (beta, active development)**
- **Hooks** into the tool call pipeline of 4 AI coding platforms: Claude Code, Cursor, GitHub Copilot, and Codex CLI.
- **Evaluates** every tool call in real-time against an enterprise policy engine: 18 dangerous command patterns, 15 secret detection patterns, 12 sensitive file write patterns, 7 network egress patterns, tool allowlists/blocklists, and identity-based access control.
- **Blocks** dangerous operations before they execute, using each framework's native hooks protocol.
- **Logs** every event to a unified, append-only event store (JSONL + SQLite) across all frameworks.
- **Detects** multi-step attack sequences by correlating events within sessions.

SentinelFlow's long-term role is to be the **control plane for AI agents**: one canonical agent identity, one findings model, one runtime policy engine, and one place to reason about risk and compliance across all frameworks.

---

## Monorepo layout

This is a pnpm workspace monorepo managed by Turborepo with 5 packages.

- **`packages/core`** — Universal agent schema, event types (`AgentEvent` with identity context), registry abstractions (`IRegistry`), and SQLite-backed governance event store.
- **`packages/parsers`** — 6 framework-specific parsers (Claude Code, Cursor, Codex, LangChain, CrewAI, Kiro) that normalize configs into the core schema.
- **`packages/scanner`** — 46 governance rules across 10 categories, suppression system, formatters for SARIF/JSON/Markdown/terminal. Rules map to OWASP LLM Top 10, EU AI Act, NIST AI RMF, MITRE ATLAS, ISO 42001, SOC 2, HIPAA, GDPR.
- **`packages/interceptors`** — Runtime agent firewall: 4 framework interceptors, 8 enterprise policy classes, central pattern registry, command normalizer, shared handler code generator, multi-step sequence detector, data boundary classification, identity governance, hierarchical escalation, compliance mappings, anomaly detectors, event listeners. 18 source files, 11 test files, 228+ tests.
- **`packages/cli`** — CLI entrypoint bundled to ~800KB via esbuild. Commands: `scan`, `intercept install/uninstall/status/tail`, `intercept test`, `events tail/blocked/stats`, `costs`, `init`.

---

## How to work on this repo

### Commands

- Use **pnpm only** for development.
- `pnpm install` — Install dependencies.
- `pnpm build` — Build all packages (always run before tests).
- `pnpm test` — Run all tests via Turborepo (Vitest 2.x).
- Golden path tests — `bash scripts/golden-path-test.sh` (plus cursor, copilot, codex variants).

**Important:** Vitest 2.x is pinned. Do NOT upgrade to 3.x — ESM incompatibility with Node 20.18.1.

### Development workflow (TDD)

1. Add or update tests so they **fail**.
2. Implement the change.
3. Run `pnpm build && pnpm test` until green.
4. For runtime changes, also run the relevant golden path script(s).
5. Refactor if needed, keeping all tests green.
6. Both `pnpm test` AND golden path scripts must pass before pushing.

---

## Non-negotiable code standards

- **TypeScript strict mode** — No `any`. No `@ts-ignore` unless paired with a removal plan.
- **Immutability** — Never mutate function arguments. Return new objects.
- **Small files** — 200–400 lines typical, 800 max.
- **Feature-oriented** — Group by capability, not by type. No `utils.ts` dumping ground.
- **Error handling** — Never swallow errors silently. Exception: handler scripts use try/catch with fail-open (see below).
- **Secrets** — Never hardcode. Use environment variables. Rotate immediately if found.

---

## Core design principles

1. **Agent schema is the heart** — `packages/core/src/schema/agent.ts` defines canonical agent identity. All parsers normalize into it. All rules evaluate against it. All interceptors reference it.

2. **Rules are pure and composable** — Each rule: `RuleContext → Finding[]`. No side effects, no state, no I/O.

3. **Parsers are pluggable** — Each implements `FrameworkParser`. Adding a framework means registering a new parser, not touching existing ones.

4. **Registry is swappable** — `IRegistry` abstracts storage. No code outside registry depends on storage details.

5. **Central pattern registry is the single source of truth** — `patterns.ts` defines ALL detection patterns. Every handler script and policy class reads from it. **Never add patterns directly to a handler template.**

6. **Handler scripts are self-contained** — Generated handlers work without npm imports. They include their own helpers and compile regex from JSON. The code generator (`handler-codegen.ts`) produces policy evaluation code baked in at install time.

7. **Fail-open everywhere in runtime** — Every handler wraps logic in try/catch, exits 0 on errors. SentinelFlow never breaks developer workflows.

---

## Handler architecture (critical knowledge)

Anyone modifying handler scripts or the code generator **must** read this section.

### How handlers are generated

`sentinelflow intercept install . --framework cursor --mode enforce` triggers the following chain: CLI creates `.sentinelflow/` → framework interceptor's `generateHandlerScript()` calls `generatePolicyEvaluationCode(enforcementMode)` from `handler-codegen.ts` → returns JavaScript code string → embedded via `${policyCode}` in template literal → complete handler written to disk → hooks config written to framework location.

### Each framework blocks differently

| Framework | Config Location | Blocking Mechanism | Handler Script |
|-----------|----------------|-------------------|----------------|
| Claude Code | `.claude/settings.local.json` | Exit code 2 + stderr | `.sentinelflow/handler.js` |
| **Cursor** | `.cursor/hooks.json` | **Stdout JSON `{ permission: "deny" }`** | `.sentinelflow/cursor-handler.js` |
| Copilot | `.github/hooks/sentinelflow.json` | Exit code 2 + stderr | `.sentinelflow/copilot-handler.js` |
| Codex CLI | `.codex/hooks.json` | Exit code 2 + stderr | `.sentinelflow/codex-handler.js` |

**Cursor is the exception.** Using exit code 2 in a Cursor handler causes Cursor to treat it as a crash. Always use stdout JSON + exit 0 for Cursor blocking.

### Hard-won gotchas

- **Template literal escaping** — `handler-codegen.ts` uses `JSON.stringify()` + `new RegExp(string)`. No regex literals in generated code. Use `lines.push()` array joining, not template literals with regex.
- **Copilot toolArgs** — JSON string, not object. Must `JSON.parse()` before extracting command.
- **Copilot event detection order** — Check `hookEventName` BEFORE `toolName`. PostToolUse also has toolName.
- **`file: ` prefix** — Handler scripts format paths as `"file: /path"`. FileWritePolicy strips this before matching.
- **Cursor `command` field** — Cursor sends `command` as a direct field in stdin, not inside `tool_input`.

---

## Testing infrastructure

### Unit tests (Vitest)

228+ tests across 11 test files in interceptors, plus core/parsers/scanner tests. Key files: `policies-enterprise.test.ts` (66), `sequence-boundary.test.ts` (41), `identity-compliance.test.ts` (30+), `escalation.test.ts`, and 4 handler E2E test files (12-14 tests each).

### Golden path tests (bash)

Test the actual production code path: install hooks → pipe JSON → verify exit codes/stdout/stderr/events.

```bash
bash scripts/golden-path-test.sh          # Claude Code
bash scripts/cursor-golden-path-test.sh   # Cursor
bash scripts/copilot-golden-path-test.sh  # Copilot
bash scripts/codex-golden-path-test.sh    # Codex
```

---

## Common task playbooks

### Add a scanner rule
Implement in `packages/scanner/src/rules/`. Pure function `RuleContext → Finding[]`. Minimum 3 flagged, 3 safe, 1 edge case. Map to compliance frameworks. Run: `pnpm build && pnpm test`.

### Add a detection pattern
Add to `patterns.ts` with unique ID (DC-xxx, SK-xxx, FW-xxx, NE-xxx). Add test in `policies-enterprise.test.ts`. Pattern flows to all handlers via `handler-codegen.ts`. Run: `pnpm build && pnpm test` plus all 4 golden paths.

### Modify handler code generation
Edit `handler-codegen.ts`. No regex literals. No handler-template function references. Test with `pnpm build && pnpm test` plus all 4 golden paths. If tests pass but golden paths fail, the generated handler has a runtime error.

### Add a framework interceptor
Create interceptor class → use `generatePolicyEvaluationCode()` → add to CLI → write golden path script → write E2E tests → export from index.ts.

### Add a parser
Implement `FrameworkParser` → register in `auto-detect.ts` → ≥5 fixtures → `pnpm build && pnpm test`.

### Extend the CLI
Implement in `packages/cli/src/commands/`. Consume only public APIs. Never duplicate business logic.

---

## Schema compatibility

Schema changes cascade through all packages. Prefer optional fields. Document breaking changes. Test old + new behavior. The `AgentEvent` type in `packages/core/src/schema/event.ts` is the universal event format — changes here affect all 4 interceptors, the event store, the CLI, and the compliance mappings.

---

## Package Manager Strategy

SentinelFlow uses a **dual-mode architecture**: pnpm internally for development, package-manager-agnostic externally for distribution.

**For contributors (internal):** The monorepo requires pnpm. The root `package.json` declares `packageManager: pnpm@9.15.0`, `.npmrc` has `engine-strict=true`, and Turborepo orchestrates builds. Always use `pnpm install`, `pnpm build`, `pnpm test`.

**For users (published npm package):** The CLI is bundled with esbuild into a single ~800KB JavaScript file with ZERO runtime dependencies. `npx sentinelflow scan .` works identically with npm, yarn, pnpm, or bun. The only optional dependency is `better-sqlite3` (native C++ addon for SQLite event storage), which degrades gracefully to JSONL-only if unavailable.

**Why this matters:** Meta uses Yarn, OpenAI uses a mix of Yarn and pnpm, Anthropic uses Yarn, Apple uses npm. A governance tool that requires pnpm would face adoption barriers at every one of these organizations.

**Critical rules for the published package:**
- The `packages/cli/package.json` must NEVER contain `packageManager`, `pnpm` overrides, or `workspace:*` in any non-dev field
- The `files` field must be an explicit allowlist: `["dist/bundle.js", "README.md", "LICENSE"]`
- `better-sqlite3` must be `optionalDependencies`, not `dependencies`
- All other packages (commander, yaml, toml, etc.) must be bundled by esbuild
- Run `node scripts/prepublish-check.js` before every `npm publish`

---

## Publishing Playbook

1. Build: `pnpm build`
2. Test: `pnpm test` (all unit tests)
3. Golden paths: `bash scripts/golden-path-test.sh` (repeat for cursor, copilot, codex)
4. Pre-publish check: `node scripts/prepublish-check.js`
5. Pack and inspect: `cd packages/cli && npm pack && tar -tzf sentinelflow-*.tgz`
6. Test the packed tarball: `npx ./sentinelflow-*.tgz --help`
7. Publish: `npm publish --access public`
8. Verify: `npx sentinelflow@latest --version`

---

## Compliance context

All 46 scanner rules and 8 runtime controls map to OWASP LLM Top 10 2025, EU AI Act (Articles 9, 10, 12, 14, 15), NIST AI RMF, SOC 2, MITRE ATLAS, ISO 42001, HIPAA, GDPR. Structured mappings and evidence snippets live in `packages/interceptors/src/compliance.ts`. Every new rule or control should include compliance mappings.

---

## Agents and orchestration

SentinelFlow uses specialized development agents orchestrated by a human **SentinelFlow Architect**. This `CLAUDE.md` explains the system. `agents.md` explains roles and workflows. Agent prompts live in `.claude/agents/*.md`. All agents must respect these constraints, test both unit and golden path for runtime changes, and never introduce regex literals in generated code.
