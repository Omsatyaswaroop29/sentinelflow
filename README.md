# SentinelFlow

**The governance scanner for AI agents.** Scans Claude Code, Cursor, Codex, LangChain, CrewAI, and Kiro configurations for security misconfigurations, compliance gaps, and excessive agent permissions — before they reach production.

```bash
npx sentinelflow scan .
```

```
  SentinelFlow v0.2.0 — Agent Governance Scanner

  Frameworks detected:
    ✓ Claude Code

  Agents discovered: 4
    ├── planner (claude-code, orchestrator)
    ├── coder (claude-code, specialist)
    ├── reviewer (claude-code, reviewer)
    └── deployer (claude-code, specialist)

  Findings: 3 critical, 2 high, 5 medium

  CRITICAL
  ┌────────────────────────────────────────────────────────┐
  │ SF-FC-001  --dangerously-skip-permissions detected     │
  │            .claude/settings.json:3                      │
  │ SF-AC-001  Hardcoded database credentials               │
  │            .claude/settings.json:12                     │
  │ SF-FC-008  Codex CLI running in full-auto mode          │
  │            .codex/config.toml:2                         │
  └────────────────────────────────────────────────────────┘
```

---

## Why SentinelFlow?

AI agents ship with configuration files that grant tool access, set permissions, and define behavioral boundaries. These configs are the **security perimeter** for your AI agents — but no existing tool scans them.

SentinelFlow fills that gap. It reads your agent configurations, identifies misconfigurations and compliance issues, and gives you concrete fixes — all as a static scan that runs in CI, produces SARIF for GitHub Code Scanning, and takes under 5 seconds.

## What It Finds

**46 governance rules** across 10 categories, each mapped to OWASP LLM Top 10 2025, EU AI Act, NIST AI RMF, and more.

**Framework Configuration** — `--dangerously-skip-permissions` enabled, `Bash(*)` wildcard access, Codex `full-auto` mode, Cursor `alwaysApply` with broad globs.

**Access Control** — Hardcoded credentials in agent configs (16 secret patterns), excessive tool permissions, missing least-privilege boundaries.

**Supply Chain** — MCP servers without integrity verification, tool description poisoning vectors, LangChain `RunnablePassthrough()` forwarding unsanitized input to tools, known framework CVEs.

**Multi-Agent** — No delegation depth limits, privilege escalation via delegation chains, CrewAI hierarchical processes without worker constraints, permission scope divergence across frameworks.

**Compliance** — Missing risk assessments, no human-in-the-loop documentation, absent incident response plans, missing EU AI Act Article 11 technical documentation.

**Cost Governance** — No token budgets, unrestricted model access, missing rate limiting.

## Quickstart

```bash
# Scan any project with AI agent configs
npx sentinelflow scan .

# Output SARIF for GitHub Code Scanning
npx sentinelflow scan . --format sarif > results.sarif

# Progressive adoption — observe without failing CI
npx sentinelflow scan . --preset monitor

# Strict mode — fail on medium and above
npx sentinelflow scan . --preset strict
```

### GitHub Actions

```yaml
name: Agent Governance
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx sentinelflow scan . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Scan Presets

SentinelFlow supports three presets for progressive adoption.

`standard` (default) fails CI on critical and high findings. This is the right choice for active development — it catches the dangerous stuff without blocking every PR.

`monitor` never fails CI. All findings are reported but the exit code is always 0. Use this when you're first adopting SentinelFlow to see what it finds before enforcing.

`strict` fails CI on medium and above. For production governance where every finding must be addressed or explicitly suppressed.

## Suppression

Not every finding needs immediate action. SentinelFlow provides three suppression layers, all producing auditable evidence.

**Inline comments** for file-level suppressions:
```json
// sentinelflow-ignore: SF-FC-001 -- CI sandbox, no production access, SEC-1294
```

**Policy file** (`.sentinelflow-policy.yaml`) for project-level suppressions with expiration:
```yaml
version: v1
preset: standard
ignore:
  SF-FC-001:
    - path: ".claude/settings.json"
      reason: "CI sandbox environment with ephemeral compute"
      expires: "2026-10-01"
      approved_by: "security-team"
      ticket: "SEC-1294"
```

**Audit review** — see everything that's been suppressed:
```bash
sentinelflow scan . --show-suppressed
```

## Runtime Agent Firewall (Phase 2 Beta) 🆕

SentinelFlow now goes beyond static scanning. Install runtime hooks that intercept every tool call your AI agent makes — in real-time.

```bash
# Install hooks into a Claude Code project (monitor mode — logs everything, blocks nothing)
sentinelflow intercept install . --mode monitor

# Install with enforcement — actually block dangerous tool calls
sentinelflow intercept install . --mode enforce --blocklist NotebookEdit

# Test the interceptor without a live session
sentinelflow intercept test . --tool Bash --input 'rm -rf /home/user'

# Check what's happening
sentinelflow intercept status .

# Query the governance event store (SQLite)
sentinelflow events tail .               # recent events
sentinelflow events blocked .            # blocked tool calls with reasons
sentinelflow events stats .              # aggregate statistics
sentinelflow costs . --window 7d         # token spend by agent

# Remove hooks when done
sentinelflow intercept uninstall .
```

**How it works:** Hooks are installed into `.claude/settings.local.json` using Claude Code's official hooks system. Every `PreToolUse` event passes through SentinelFlow's policy engine. The handler script at `.sentinelflow/handler.js` evaluates policies, writes events to both a JSONL log and a SQLite database, and returns allow/block decisions via exit codes.

**Built-in policies:** Dangerous bash command detection (`rm -rf /`, `curl | bash`, `chmod 777`, `git push --force`, `npm publish`), tool allowlists/blocklists, and `.sentinelflow-policy.yaml` runtime rules.

**Two modes:** Start with `monitor` to see what your agents are doing without breaking anything. Graduate to `enforce` when you're confident in your policies.

**Fail-open by default:** If the handler crashes or can't parse input, it exits 0 (allow). SentinelFlow never silently breaks your Claude Code workflow.

**Event store:** All events are dual-written to `.sentinelflow/events.jsonl` (fast, tail-able, always works) and `.sentinelflow/events.db` (SQLite with indexed queries, rollups, dashboards). Query with `sentinelflow events tail` or connect any SQLite client.

> **Beta notice:** The runtime interceptor is validated against the Claude Code hooks contract but should be tested in your environment before relying on it for production governance. The static scanner (Phase 1) is stable and recommended for CI/CD.

## Frameworks Supported

| Framework | Config Locations | Parser Status |
|-----------|-----------------|---------------|
| Claude Code | `.claude/settings.json`, `CLAUDE.md`, `AGENTS.md`, `agents/*.md` | Full |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/mcp.json` | Full |
| Codex / OpenCode | `.codex/config.toml`, `codex.md`, `.agents/*.md` | Full |
| LangChain | Python source files, `pyproject.toml`, `langgraph.json` | Pattern-based |
| CrewAI | `crew.yaml`, `agents.yaml`, `tasks.yaml` | Full |
| Kiro | `.kiro/steering/*.md`, `.kiro/specs/*.md` | Steering files |

See [Framework Support Matrix](docs/FRAMEWORK-SUPPORT.md) for detailed coverage and known limitations.

## Compliance Mappings

Every finding maps to at least two compliance frameworks.

| Framework | Coverage |
|-----------|----------|
| OWASP LLM Top 10 (2025) | All 46 rules mapped |
| EU AI Act (Articles 9–15) | 28 rules mapped |
| NIST AI RMF 1.0 | 22 rules mapped |
| MITRE ATLAS | 12 rules mapped |
| ISO 42001 | 15 rules mapped |
| SOC 2 Trust Services | 18 rules mapped |
| CWE | 12 specific CWE IDs |

## Architecture

SentinelFlow is a monorepo with five packages.

`@sentinelflow/core` — Universal agent schema, finding types, local registry with atomic writes, and the SQLite-backed governance event store (writer, reader, rollup computation, and query API).

`@sentinelflow/parsers` — Six framework-specific parsers that normalize agent configs into the universal schema.

`@sentinelflow/scanner` — 46 governance rules, suppression engine, SARIF/JSON/Markdown/terminal formatters.

`@sentinelflow/interceptors` — Runtime agent firewall. Hooks into Claude Code via command hooks, evaluates policies on every tool call, emits events to listeners (console, JSONL, SQLite, alerts), and includes anomaly detection (novel tool, cost spike, error rate, privilege escalation).

`sentinelflow` — CLI that ties it all together. This is the package you install. Includes static scan, runtime hook management, event store queries, and cost reporting.

## Validated Against Real Projects

SentinelFlow was validated against [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) (116K+ GitHub stars): 30 agents discovered, 133 findings (35 critical, 30 high, 64 medium), in 32ms.

## Phase 2: Runtime Agent Firewall (Beta)

SentinelFlow now includes a runtime layer that hooks into Claude Code sessions to monitor and govern agent tool calls in real time. This is currently in **beta** — the static scanner (v0.2.3) remains the stable, production-ready component.

### What the Runtime Layer Does

When you install SentinelFlow hooks into a Claude Code project, every tool call passes through a governance handler before (and after) execution. The handler evaluates policies, logs structured events to both JSONL and SQLite, and can optionally block dangerous operations.

```bash
# Install runtime hooks (start with monitor mode — logs everything, blocks nothing)
sentinelflow intercept install --mode monitor

# Run your Claude Code session normally — events are recorded silently
claude

# Review what happened
sentinelflow events tail --since 1h
sentinelflow events blocked --since 7d
sentinelflow costs --window 7d

# Test your policy configuration without a live session
sentinelflow intercept test --tool Bash --input 'rm -rf /' --mode enforce

# When ready, switch to enforce mode to actually block policy violations
sentinelflow intercept install --mode enforce --blocklist NotebookEdit,TodoWrite

# Uninstall when done (event history is preserved)
sentinelflow intercept uninstall
```

### Built-in Policies

The runtime layer includes five built-in policies: tool allowlist (only permit listed tools), tool blocklist (block specific tools), dangerous command detection (catches `rm -rf /`, `curl|bash`, `chmod 777`, `git push --force`, `npm publish`, and more), session cost budgets, and data boundary enforcement (block access to sensitive paths). Custom policies can be added via `.sentinelflow-policy.yaml`.

### Event Store

All runtime events are persisted to an append-only SQLite database at `.sentinelflow/events.db` (with JSONL fallback at `.sentinelflow/events.jsonl`). The database supports governance queries like blocked tool call history, cost-by-agent rollups, session summaries, and active agent inventory — all accessible through the CLI.

### What Is NOT Handled Yet

The runtime layer currently supports **Claude Code only**. LangChain, CrewAI, Cursor, and Copilot Studio interceptors are planned for Phase 3. Token/cost data from Claude Code hooks is not yet available (cost columns will be NULL). Dynamic policy reloading, multi-project dashboards, and advanced anomaly detection in the handler script are on the roadmap.

## Contributing

SentinelFlow uses five canonical agent roles for development, defined in [AGENTS.md](AGENTS.md) and `.claude/agents/`. The closed-loop workflow ensures every rule ships with detection logic, test annotations, compliance mappings, adversarial evasion testing, and corpus regression validation.

```bash
git clone https://github.com/Omsatyaswaroop29/sentinelflow.git
cd sentinelflow
pnpm install
pnpm build
npx vitest run
```

## Roadmap

**Phase 1** (Complete) — Static governance scanner with 46 rules, 6 framework parsers, SARIF output, compliance mappings to OWASP LLM Top 10, EU AI Act, NIST AI RMF, MITRE ATLAS, and more. Validated against Everything Claude Code (133 findings in 32ms).

**Phase 2** (Beta) — Runtime agent firewall via Claude Code hooks. Policy evaluation on every tool call (allow/block/monitor). Append-only SQLite event store with governance queries. CLI for event tailing, blocked call review, and cost reporting. Anomaly detection (novel tool, cost spike, error rate, privilege escalation). Five built-in policies.

**Phase 3** (Months 4–6) — LangChain and CrewAI interceptors. Policy engine with approval workflows. EU AI Act, SOC 2, and ISO 42001 compliance packs. Python SDK. Live governance dashboard.

**Phase 4** (Months 7–12) — Multi-tenant SaaS. SSO/SAML. SIEM integration. Shadow agent discovery across the organization.

## License

MIT
