# SentinelFlow

**The governance platform for AI agents.** Scans Claude Code, Cursor, GitHub Copilot, Codex, LangChain, CrewAI, and Kiro configurations for security misconfigurations — and intercepts dangerous tool calls at runtime before they execute.

```bash
# Static scanning — find security issues in agent configs
npx sentinelflow scan .

# Runtime interception — block dangerous tool calls in real-time
npx sentinelflow intercept install . --framework claude-code --mode enforce
npx sentinelflow intercept install . --framework cursor --mode enforce
npx sentinelflow intercept install . --framework copilot --mode enforce
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

## Runtime Agent Firewall (Phase 2 Beta)

SentinelFlow intercepts every tool call your AI agent makes — in real-time — across **Claude Code, Cursor, and GitHub Copilot**.

```bash
# Claude Code — hooks via .claude/settings.local.json, blocks via exit code 2
sentinelflow intercept install . --framework claude-code --mode enforce

# Cursor — hooks via .cursor/hooks.json, blocks via stdout JSON { permission: deny }
sentinelflow intercept install . --framework cursor --mode enforce

# GitHub Copilot — hooks via .github/hooks/sentinelflow.json, blocks via exit code 2
sentinelflow intercept install . --framework copilot --mode enforce

# Auto-detect framework from project directory (if only one is present)
sentinelflow intercept install . --mode enforce --blocklist NotebookEdit

# Test the interceptor without a live session
sentinelflow intercept test . --tool Bash --input 'rm -rf /home/user'

# Check what's happening
sentinelflow intercept status .

# Query the governance event store
sentinelflow events tail .               # recent events across all frameworks
sentinelflow events blocked .            # blocked tool calls with reasons
sentinelflow events stats .              # aggregate statistics
sentinelflow costs . --window 7d         # token spend by agent

# Remove hooks when done
sentinelflow intercept uninstall .
```

**How it works:** Each framework has its own hooks contract. SentinelFlow generates a framework-specific handler script (`.sentinelflow/handler.js` for Claude Code, `.sentinelflow/cursor-handler.js` for Cursor, `.sentinelflow/copilot-handler.js` for Copilot) that evaluates policies, writes events, and returns allow/block decisions using the correct protocol for each platform.

**Built-in policies:** 9 dangerous command patterns (`rm -rf /`, `curl | bash`, `chmod 777`, `git push --force`, `npm publish`, and more), tool allowlists/blocklists, MCP server blocklists (Cursor), and `.sentinelflow-policy.yaml` runtime rules.

**Two modes:** `monitor` logs everything but never blocks — start here. `enforce` actually blocks dangerous tool calls, with the block reason fed back to the AI model.

**Fail-open by default:** If any handler crashes or can't parse input, it allows the tool call. SentinelFlow never silently breaks your development workflow.

**Unified event store:** All events from all three frameworks are written to the same `.sentinelflow/events.jsonl` log and `.sentinelflow/events.db` SQLite database. A single `sentinelflow events tail .` command shows events from Claude Code, Cursor, and Copilot side by side.

**Live-validated:** Tested against a real Claude Code v2.1.91 session where the handler successfully blocked `rm -rf /home/user/important-data` and Claude acknowledged the policy restriction. Each framework has a golden-path test suite validating the full contract.

## Frameworks Supported

| Framework | Static Scanning | Runtime Interception | Hook Config Location |
|-----------|:-:|:-:|---|
| Claude Code | Full (46 rules) | **Live** | `.claude/settings.local.json` |
| Cursor | Full (46 rules) | **Live** | `.cursor/hooks.json` |
| GitHub Copilot | Via Codex parser | **Live** | `.github/hooks/sentinelflow.json` |
| Codex / OpenCode | Full (46 rules) | Planned | |
| LangChain | Pattern-based | Planned (middleware) | |
| CrewAI | Full (46 rules) | Planned | |
| Kiro | Steering files | Planned | |

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

`@sentinelflow/interceptors` — Runtime agent firewall. Hooks into Claude Code, Cursor, and GitHub Copilot via their official hooks systems, evaluates policies on every tool call, emits events to listeners (console, JSONL, SQLite, alerts), and includes anomaly detection (novel tool, cost spike, error rate, privilege escalation).

`sentinelflow` — CLI that ties it all together. This is the package you install. Includes static scan, runtime hook management, event store queries, and cost reporting.

## Validated Against Real Projects

SentinelFlow was validated against [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) (116K+ GitHub stars): 30 agents discovered, 133 findings (35 critical, 30 high, 64 medium), in 32ms.


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

**Phase 2** (Beta) — Runtime agent firewall for Claude Code, Cursor, and GitHub Copilot. Policy evaluation on every tool call (allow/block/monitor). Each framework uses its native hooks contract. Unified append-only event store with governance queries. CLI for event tailing, blocked call review, and cost reporting. Anomaly detection. Five built-in policies.

**Phase 3** (Months 4–6) — LangChain middleware interceptor. CrewAI task-level hooks. Policy engine with approval workflows. EU AI Act, SOC 2, and ISO 42001 compliance packs. Python SDK. Minimal operational dashboard.

**Phase 4** (Months 7–12) — Multi-tenant SaaS. SSO/SAML. SIEM integration. Shadow agent discovery across the organization.

## License

MIT
