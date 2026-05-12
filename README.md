# SentinelFlow

[![npm version](https://img.shields.io/npm/v/sentinelflow)](https://www.npmjs.com/package/sentinelflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-228%2B%20passing-brightgreen)](#)
[![Frameworks](https://img.shields.io/badge/frameworks-4%20live-blue)](#frameworks-supported)

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
  SentinelFlow v0.3.1 — Agent Governance Scanner

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

SentinelFlow fills that gap. It reads your agent configurations, identifies misconfigurations and compliance issues, and gives you concrete fixes — all as a static scan that runs in CI, produces SARIF for GitHub Code Scanning, and typically completes in under 100ms — the Everything Claude Code validation (30 agents across a 116k-star repo, 133 findings) finished in 32ms.

## What It Finds

**46 governance rules** across 10 categories, each mapped to OWASP LLM Top 10 2025, EU AI Act, NIST AI RMF, and more.

**Framework Configuration** — `--dangerously-skip-permissions` enabled, `Bash(*)` wildcard access, Codex `full-auto` mode, Cursor `alwaysApply` with broad globs.

**Access Control** — Hardcoded credentials in agent configs (16 secret patterns covering API keys, cloud credentials, DB connection strings, and bearer tokens), excessive tool permissions, missing least-privilege boundaries.

**Supply Chain** — MCP servers without integrity verification, tool description poisoning vectors, LangChain `RunnablePassthrough()` forwarding unsanitized input to tools, known framework CVEs.

**Multi-Agent** — No delegation depth limits, privilege escalation via delegation chains, CrewAI hierarchical processes without worker constraints, permission scope divergence across frameworks.

**Compliance** — Missing risk assessments, no human-in-the-loop documentation, absent incident response plans, missing EU AI Act Article 11 technical documentation.

**Cost Governance** — No token budgets, unrestricted model access, missing rate limiting.

## Installation

```bash
npm install -g sentinelflow
# or use directly without installing:
npx sentinelflow scan .
```

Requires Node.js >= 20.

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

SentinelFlow intercepts every tool call your AI agent makes — in real-time — across **Claude Code, Cursor, GitHub Copilot, and Codex CLI**.

```bash
# Claude Code — hooks via .claude/settings.local.json, blocks via exit code 2
sentinelflow intercept install . --framework claude-code --mode enforce

# Cursor — hooks via .cursor/hooks.json, blocks via stdout JSON { permission: deny }
sentinelflow intercept install . --framework cursor --mode enforce

# GitHub Copilot — hooks via .github/hooks/sentinelflow.json, blocks via exit code 2
sentinelflow intercept install . --framework copilot --mode enforce

# Codex CLI — hooks via .codex/hooks.json, blocks via exit code 2 (same contract as Claude Code)
sentinelflow intercept install . --framework codex --mode enforce

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

**How it works:** Each framework has its own hooks contract. SentinelFlow generates a framework-specific handler script (`.sentinelflow/handler.js` for Claude Code, `.sentinelflow/cursor-handler.js` for Cursor, `.sentinelflow/copilot-handler.js` for Copilot, `.sentinelflow/codex-handler.js` for Codex) that evaluates policies, writes events, and returns allow/block decisions using the correct protocol for each platform.

**Built-in policies:** Enterprise policy engine backed by a central registry (**18 dangerous command patterns**, **15 secret patterns**, **12 sensitive file write path patterns**, **7 network egress patterns**) plus **8 runtime policies** (allowlist, blocklist, dangerous commands, secrets leak, file write governance, network egress, data boundary, and cost budgets). Generated hook handlers currently **enforce a safe core subset** (allow/block lists + dangerous commands + secrets + sensitive write paths + network egress domain allow/block lists); the remaining policies are implemented in TypeScript and are next for handler parity.

**Two modes:** `monitor` logs everything but never blocks — start here. `enforce` actually blocks dangerous tool calls, with the block reason fed back to the AI model.

**Fail-open by default:** If any handler crashes or can't parse input, it allows the tool call. SentinelFlow never silently breaks your development workflow.

**Unified event store:** All events from all four frameworks are written to the same `.sentinelflow/events.jsonl` log and `.sentinelflow/events.db` SQLite database. A single `sentinelflow events tail .` command shows events from Claude Code, Cursor, Copilot, and Codex side by side.

**Live-validated:** Tested against a real Claude Code v2.1.91 session where the handler successfully blocked `rm -rf /home/user/important-data` and Claude acknowledged the policy restriction. Each framework has a golden-path test suite validating the full contract.

## Advanced Governance

The runtime engine includes three governance systems beyond the core pattern-based checks, plus an anomaly engine that ties them together.

### Sequence Detection

Single tool-call checks miss attacks that span multiple steps. The sequence detector correlates events within a session — using a 5-minute sliding window per session, bounded to 50 events — and matches them against four known attack chains:

- **Script injection** — file write → `chmod +x` → execute of that same file
- **Data exfiltration** — read of a sensitive path (`.ssh/`, `.aws/`, `.env`, `*.pem`, `*.key`) → outbound `curl`/`wget`/`scp`/`ssh`
- **Persistence probe** — three or more blocked attempts on the same tool, indicating the agent is searching for bypasses or being driven by adversarial input
- **Privilege chain** — write to a privilege-granting file (`authorized_keys`, `sudoers`, `.npmrc`, `.aws/credentials`, `.kube/config`) → `source`/`systemctl reload`/`npm install`

Each detection is deterministic (no ML, no probabilistic scoring) and explainable: the response includes the full chain of events that triggered it.

```text
  ⚠ SEQUENCE DETECTED — script_injection (confidence: 0.92)

  Agent:     deployer-bot
  Session:   sess_4f3a2b1c
  Window:    2026-05-12 14:32:18 → 14:34:51  (2m 33s)

  Chain:
    ├─ 14:32:18  Write      build/deploy.sh         (412 bytes)
    ├─ 14:33:02  Bash       chmod +x build/deploy.sh
    └─ 14:34:51  Bash       ./build/deploy.sh                    ← BLOCKED

  Script injection: file written, made executable, and executed
  within 5 minutes. Each step alone is legal; together they're
  code injection.
```

### Data Boundary Classification

Paths in tool inputs are classified at four sensitivity levels. Each agent has a clearance level; access to a path above the agent's clearance is blocked. Wildcard agent IDs are supported, so policies like "all `external_*` agents are capped at `internal`" work out of the box.

| Level | Example paths | Default behavior |
|---|---|---|
| **public** | Source code, docs, tests | All agents allowed |
| **internal** | `.github/`, `Dockerfile`, `package.json`, `node_modules/`, `*.log` | Default cap for unlisted agents |
| **restricted** | `.ssh/`, `.aws/`, `.kube/`, `.env`, `.pem`/`.key`, `*credentials*` | Blocked unless explicitly cleared |
| **system** | `/etc/`, `/usr/`, `/var/log/`, `/dev/`, `/proc/` | Blocked for all agents |

```text
  ⛔ BLOCKED — data_boundary

  Agent:     external-support-bot      (clearance: internal)
  Tool:      Read
  Path:      ~/.ssh/id_rsa             (classified: restricted, SSH key file)

  Reason:    Path classification "restricted" exceeds agent clearance
             "internal". Requires restricted clearance or higher.

  Audit:     [email protected] · environment=production · role=reader
```

### Identity Governance

Every event is enriched with an identity context — human owner, team, environment, role, privilege level, external-facing flag — resolved from policy config first, then environment variables (`SENTINELFLOW_OWNER`, `SENTINELFLOW_TEAM`, `SENTINELFLOW_ROLE`, `GITHUB_ACTOR`), then sensible defaults. Two policies enforce it: a **role-based access policy** that gates tools by required privilege level, and an **environment policy** that blocks shell + write tools in production, restricts CI agents to an allowlist, and prevents external-facing agents from touching write tools.

| Role | Privilege | Can call |
|---|:-:|---|
| `reader` | 2 | Read, View, ListDir |
| `writer` | 4 | + Write, Edit, MultiEdit, Create |
| `executor` | 6 | + Bash, shell, terminal, RunCommand |
| `deployer` | 8 | + NotebookEdit, TodoWrite |
| `admin` | 10 | All tools |

```text
  ⛔ BLOCKED — role_based_access

  Agent:     reader-bot               (role: reader, privilege: 2)
  Owner:     [email protected]
  Tool:      Bash                     (requires privilege: 6)

  Reason:    Agent does not meet privilege requirement.
             Increase agent privilege or assign a higher role.
```

Every blocked action carries the audit trail of who owns the agent, what role it has, and what environment it ran in.

### Anomaly Detection

The anomaly engine ties the above together with four detectors that flag unusual behavior without blocking: **novel tool** (a tool used for the first time by an agent), **cost spike** (token usage that exceeds the agent's rolling baseline), **error rate** (sustained failure patterns), and **privilege escalation** (attempts to gain capabilities the agent didn't previously have). The sequence detector plugs into the same engine as a fifth detector.

```text
  ⚠ ANOMALY — cost_spike (confidence: 0.81)

  Agent:     research-bot
  Detected:  84,000 tokens in last hour  (12.3× baseline)
  Baseline:  rolling 30-day p50 = 6,820 tokens/hour

  Action:    logged  (anomalies are observe-only by default)
```

## Cost Visibility

Agent governance without cost visibility hides the most common real-world failure mode — an agent silently burning through tokens in a long-running session. SentinelFlow makes token spend a first-class governance signal: every tool call generates an event tagged to the agent that made it, and `sentinelflow costs .` queries the event store for per-agent, per-model, and per-session token spend over any time window.

```bash
sentinelflow costs . --window 7d              # last 7 days, all agents
sentinelflow costs . --window 24h --by agent
sentinelflow costs . --window 30d --by model --format json
```

```text
  $ sentinelflow costs . --window 7d --by agent

  Cost Report — last 7 days
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Agent              Tool calls   Tokens        Cost (USD)
  ─────────────────  ──────────   ───────────   ──────────
  planner-bot            1,247    2.4M             $14.82
  coder-bot                823    8.1M             $48.66
  reviewer-bot             412      920K            $5.52
  deployer-bot              89      156K            $0.94
  ─────────────────  ──────────   ───────────   ──────────
  TOTAL                  2,571   11.6M             $69.94

  Top model: claude-sonnet-4 (87% of spend)
```

Cost data lives in the same SQLite event store as block/allow events, so cost spikes can be correlated with policy violations in a single query. The reported numbers are best-effort — token counts come from the framework's event payload where exposed, and from input-size heuristics where not.

## Frameworks Supported

| Framework | Static Scanning | Runtime Interception | Hook Config Location |
|-----------|:-:|:-:|---|
| Claude Code | Full (46 rules) | **Live** | `.claude/settings.local.json` |
| Cursor | Full (46 rules) | **Live** | `.cursor/hooks.json` |
| GitHub Copilot | Via Codex parser | **Live** | `.github/hooks/sentinelflow.json` |
| Codex / OpenCode | Full (46 rules) | **Live** | `.codex/hooks.json` |
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

`@sentinelflow/interceptors` — Runtime agent firewall. Hooks into Claude Code, Cursor, GitHub Copilot, and Codex CLI via their official hooks systems, evaluates policies on every tool call, emits events to listeners (console, JSONL, SQLite, alerts), and includes anomaly detection (novel tool, cost spike, error rate, privilege escalation).

`sentinelflow` — CLI that ties it all together. This is the package you install. Includes static scan, runtime hook management, event store queries, and cost reporting.

## Built With

SentinelFlow was developed using Claude Code as the primary engineering partner — and applies its own governance philosophy to its own development loop. Five specialized agents are defined in [AGENTS.md](AGENTS.md) and `.claude/agents/`:

| Agent | Model | Role |
|---|---|---|
| **Rule Author** | Opus | Authors governance rules with detection logic, test annotations, compliance mappings, and auto-fix suggestions |
| **Parser Engineer** | Opus | Builds and maintains framework-specific config parsers that normalize agent definitions into the SentinelFlow schema |
| **Compliance Mapper** | Sonnet | Maps rules to OWASP LLM 2025, EU AI Act, NIST AI RMF, MITRE ATLAS, ISO 42001, SOC 2, HIPAA, and GDPR |
| **Red-Team Adversary** | Opus | Attempts to evade rules using obfuscation, encoding, structural tricks, and framework-specific hiding techniques |
| **Corpus QA** | Sonnet | Validates parsers and rules against the curated test corpus; guards against regressions and false positives |

Every new governance rule goes through a six-step closed loop: parser engineer → rule author → compliance mapper (parallel) → red-team adversary (parallel) → corpus QA → human architect ship/no-ship decision. Rules graduate from `experimental` (monitor-only, requires 3+ flagged and 3+ safe test cases plus 3+ Red-Team evasion attempts) to `stable` (<20% false positive rate, runs in CI standard preset) to `enforced` (<10% false positive rate, runs in strict preset). The tooling that governs AI agents is itself the product of a multi-agent governed-development workflow.

## Validated Against Real Projects

**Static scanner — Everything Claude Code (116k+ stars).** Cold-scanned in 32ms: 30 agents discovered, 133 findings across 35 critical, 30 high, and 64 medium severities. [Project link](https://github.com/affaan-m/everything-claude-code).

**Runtime interception — Claude Code v2.1.91, live session.** The generated handler script successfully blocked `rm -rf /home/user/important-data`; the model received the block reason through the hook contract and acknowledged the policy restriction in its next response.

**Test coverage.** 228+ Vitest unit and E2E tests across the interceptors package, plus four golden-path shell scripts that exercise the full install → execute → block contract against generated handler scripts for each supported framework (Claude Code, Cursor, GitHub Copilot, Codex CLI).

## Contributing

Contributions welcome — see [AGENTS.md](AGENTS.md) for the agent-driven development workflow and rule graduation model.

```bash
git clone https://github.com/Omsatyaswaroop29/sentinelflow.git
cd sentinelflow
pnpm install
pnpm build
npx vitest run
```

## Roadmap

**Phase 1** (Complete) — Static governance scanner with 46 rules, 6 framework parsers, SARIF output, compliance mappings to OWASP LLM Top 10, EU AI Act, NIST AI RMF, MITRE ATLAS, and more. Validated against Everything Claude Code (133 findings in 32ms).

**Phase 2** (Beta) — Runtime agent firewall for Claude Code, Cursor, GitHub Copilot, and Codex CLI. Policy evaluation on every tool call (allow/block/monitor). Each framework uses its native hooks contract. Unified append-only event store with governance queries. CLI for event tailing, blocked call review, and cost reporting. Anomaly detection. Eight policy classes backed by a central pattern registry — 18 dangerous-command patterns, 15 secrets patterns, 12 sensitive-file-write paths, 7 network-egress patterns — plus sequence detection, data boundary classification, and identity governance.

**Phase 3** (Months 4–6) — LangChain middleware interceptor. CrewAI task-level hooks. Policy engine with approval workflows. EU AI Act, SOC 2, and ISO 42001 compliance packs. Python SDK. Minimal operational dashboard.

**Phase 4** (Months 7–12) — Multi-tenant SaaS. SSO/SAML. SIEM integration. Shadow agent discovery across the organization.

## Project Status

For a detailed, enterprise-oriented snapshot (current capabilities, validation, and roadmap), see `docs/PROJECT-STATUS.md`.

## License

MIT
