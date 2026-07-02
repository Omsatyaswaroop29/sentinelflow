# SentinelFlow

[![npm version](https://img.shields.io/npm/v/sentinelflow)](https://www.npmjs.com/package/sentinelflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-442%2B%20passing-brightgreen)](#validated-against-real-projects)
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
  SentinelFlow v0.5.0 — Agent Governance Scanner

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

### I want to&hellip;

| Goal | Run this |
|---|---|
| Find misconfigurations before merge | `npx sentinelflow scan . --format sarif > results.sarif` |
| Adopt gradually without breaking CI | `npx sentinelflow scan . --preset monitor` |
| Block dangerous tool calls live | `sentinelflow intercept install . --mode enforce` |
| See what got blocked, and why | `sentinelflow events blocked .` |
| Catch multi-step attack chains | automatic once runtime hooks are installed — see [Sequence Detection](#advanced-governance) |
| Track token spend by agent | `sentinelflow costs . --window 7d` |
| Suppress a finding with an audit trail | see [Suppression](#suppression) |

### Contents

[Why SentinelFlow?](#why-sentinelflow) &nbsp;·&nbsp;
[What It Finds](#what-it-finds) &nbsp;·&nbsp;
[Installation](#installation) &nbsp;·&nbsp;
[Quickstart](#quickstart) &nbsp;·&nbsp;
[Scan Presets](#scan-presets) &nbsp;·&nbsp;
[Suppression](#suppression) &nbsp;·&nbsp;
[Runtime Agent Firewall](#runtime-agent-firewall-phase-2-beta) &nbsp;·&nbsp;
[Advanced Governance](#advanced-governance) &nbsp;·&nbsp;
[Cost Visibility](#cost-visibility) &nbsp;·&nbsp;
[Frameworks Supported](#frameworks-supported) &nbsp;·&nbsp;
[Compliance Mappings](#compliance-mappings) &nbsp;·&nbsp;
[Architecture](#architecture) &nbsp;·&nbsp;
[Built With](#built-with) &nbsp;·&nbsp;
[Validated Against Real Projects](#validated-against-real-projects) &nbsp;·&nbsp;
[Contributing](#contributing) &nbsp;·&nbsp;
[Roadmap](#roadmap)

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
# Use directly without installing (works with any package manager):
npx sentinelflow scan .

# Or install globally:
npm install -g sentinelflow
yarn global add sentinelflow
pnpm add -g sentinelflow
```

Requires Node.js >= 18.

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
sentinelflow anomalies . --since 7d      # batch anomaly detection (novel tool, cost spike, error rate)

# Remove hooks when done
sentinelflow intercept uninstall .
```

**How it works:** Each framework has its own hooks contract. SentinelFlow generates a framework-specific handler script (`.sentinelflow/handler.js` for Claude Code, `.sentinelflow/cursor-handler.js` for Cursor, `.sentinelflow/copilot-handler.js` for Copilot, `.sentinelflow/codex-handler.js` for Codex) that evaluates policies, writes events, and returns allow/block decisions using the correct protocol for each platform.

**Built-in policies:** Enterprise policy engine backed by a central registry (**18 dangerous command patterns**, **15 secret patterns**, **12 sensitive file write path patterns**, **7 network egress patterns**). Generated hook handlers enforce the full policy set: tool allow/blocklist, dangerous commands, secrets leak, sensitive file write governance, network egress — **plus data boundary classification, identity/role-based access control, environment policy, and multi-step sequence detection**, all wired directly into the handlers your framework actually calls (not just the TypeScript library). Cost budgets remain TypeScript-only: no supported framework exposes token/cost data in hook payloads yet, so there's nothing to block on in real time — use `sentinelflow costs`/`sentinelflow anomalies` for after-the-fact cost governance instead.

**Two enforcement modes, set independently per policy:** `monitor` logs everything but never blocks; `enforce` actually blocks. The core subset (dangerous commands, secrets, egress, allow/blocklist) and each advanced policy (data boundary, identity/RBAC, sequence detection) have **independent enforcement modes** — the advanced policies default to `monitor` even if you've already graduated the core subset to `enforce`, so upgrading never silently starts blocking things it didn't before. Configure via `.sentinelflow-policy.yaml`'s `runtime_policies` section (loaded automatically by `intercept install`, with CLI flags taking precedence) — see `.sentinelflow-policy.example.yaml` for the full schema.

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

Framework hooks spawn a fresh handler process for every tool call — they're not long-running daemons — so the generated handlers reconstruct session history from the same SQLite event store they already write to, rather than an in-memory window. If `better-sqlite3` isn't available, sequence detection no-ops gracefully (it needs persisted history to correlate against; everything else keeps working via the JSONL fallback).

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

`sentinelflow anomalies` runs a batch pass over event history with three statistical detectors: **novel tool** (a tool used for the first time by an agent), **cost spike** (token usage that exceeds the agent's rolling baseline), and **error rate** (sustained failure patterns). These need many events to build a baseline, so they're a periodic/on-demand check rather than something evaluated synchronously on every tool call. **Privilege escalation** detection is included automatically once you configure `identity.agent_roles`/`agent_privileges` in `.sentinelflow-policy.yaml` — without real per-agent data it would flag nearly every Bash/Write call, and real-time RBAC already covers that concern with a better-calibrated default.

```bash
sentinelflow anomalies . --since 7d
```

```text
  ⚠ ANOMALY — cost_spike (confidence: 0.81)

  Agent:     research-bot
  Detected:  84,000 tokens in last hour  (12.3× baseline)
  Baseline:  rolling 30-day p50 = 6,820 tokens/hour

  Action:    logged  (anomalies are observe-only)
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
| **Handler Engineer** | Opus | Builds framework interceptors, handler scripts, and the shared code generator that bakes enterprise policies into every handler |
| **Policy Architect** | Opus | Designs runtime policies, detection patterns, and the central pattern registry that flows to all handlers |
| **Compliance Mapper** | Sonnet | Maps rules to OWASP LLM 2025, EU AI Act, NIST AI RMF, MITRE ATLAS, ISO 42001, SOC 2, HIPAA, and GDPR |
| **Red-Team Adversary** | Opus | Attempts to evade rules using obfuscation, encoding, structural tricks, and framework-specific hiding techniques |
| **Corpus QA** | Sonnet | Validates parsers, rules, and handlers against test suites and golden path scripts; guards against regressions |

Every new governance rule goes through a six-step closed loop: parser engineer → rule author → compliance mapper (parallel) → red-team adversary (parallel) → corpus QA → human architect ship/no-ship decision. Rules graduate from `experimental` (monitor-only, requires 3+ flagged and 3+ safe test cases plus 3+ Red-Team evasion attempts) to `stable` (<20% false positive rate, runs in CI standard preset) to `enforced` (<10% false positive rate, runs in strict preset). The tooling that governs AI agents is itself the product of a multi-agent governed-development workflow.

## Validated Against Real Projects

SentinelFlow is dogfooded against real, actively-maintained agent repositories — not synthetic fixtures — before every release.

<details open>
<summary><strong>ECC (ecc.tools)</strong> — 129 agents across 4 frameworks detected in one pass, 868ms <em>(tested 2026-07-02)</em></summary>

<br>

[`affaan-m/ECC`](https://github.com/affaan-m/ECC) is a large, actively-maintained "agent harness" project — Discord community, GitHub App, published npm packages (`ecc-universal`, `ecc-agentshield`) — with 67 Claude Code subagents plus Cursor rules, Codex/OpenCode config, and Kiro steering docs. It's a good stress test for multi-framework auto-detection in a single scan.

```text
$ npx sentinelflow scan .

Frameworks detected:  Claude Code, Cursor, Codex / OpenCode, Kiro
Agents discovered:    129
Scan time:            868ms

Findings: 66 critical, 132 high, 265 medium, 8 low   (471 total)
```

| Rule | Finding | Severity | Count |
|---|---|:-:|:-:|
| `SF-AC-008` | Agent has no declared owner | medium | 129 |
| `SF-CG-001` | No token budget configured | medium | 129 |
| `SF-AC-002` | Agent permissions exceed least privilege | high | 67 |
| `SF-AC-005` | No human-in-the-loop for high-impact actions | high | 54 |
| `SF-DG-003` | Unrestricted file system write access | critical | 30 |
| `SF-AC-007` | Agent can escalate its own privileges | critical | 28 |
| `SF-CG-004` | Expensive model used without routing strategy | low | 8 |
| `SF-AC-001` | Hardcoded credentials in agent configuration | critical | 7 |
| `SF-PI-005` | No output validation before tool execution | high | 7 |
| `SF-PI-002` | System prompt contains sensitive data | high | 4 |
| `SF-NS-003` | No network egress filtering for agent environment | medium | 2 |
| 6 more rules | `SF-FC-001`, `SF-SC-008`, `SF-MA-006`, `SF-MA-008`, `SF-AL-004`, `SF-CD-001` — 1 hit each | mixed | 6 |

**What held up:** the structural findings — unrestricted write access, self-privilege-escalation, missing owners, no token budgets, permissions exceeding least privilege — accurately reflect real properties of a repo that auto-generates dozens of specialized subagents. None of that is noise, and it's exactly the signal a repo like this needs before shipping more agents.

**What we're disclosing, not hiding:** spot-checking the seven `SF-AC-001` (hardcoded credential) hits found 2 were documentation examples, not live secrets — one a "BAD vs GOOD" code-smell teaching snippet inside an agent's own review instructions, the other a `.env.example`-style template (`postgresql://user:password@localhost/mydb`). This is a known limitation of every regex-based secret scanner, not something specific to SentinelFlow — it's the same reason this repo ships its own `.gitleaksignore` — but treat `SF-AC-001` hits as "investigate," not "assume breach." We also noticed `SF-AC-007` findings don't currently carry a file/line location the way most other rules do; that's a real gap we're tracking as a fix, not something we're smoothing over here.

</details>

<details>
<summary><strong>Everything Claude Code</strong> (116k+ stars) — 30 agents, 133 findings, 32ms</summary>

<br>

Cold-scanned in 32ms: 30 agents discovered, 133 findings across 35 critical, 30 high, and 64 medium severities. [Project link](https://github.com/affaan-m/everything-claude-code).

</details>

<br>

**Runtime interception — Claude Code v2.1.91, live session.** The generated handler script successfully blocked `rm -rf /home/user/important-data`; the model received the block reason through the hook contract and acknowledged the policy restriction in its next response.

**Test coverage.** 442 Vitest unit and E2E tests across all five packages (258 in the interceptors package alone, including E2E tests that spawn the actual generated handler scripts as subprocesses), plus four golden-path shell scripts totaling 92 assertions that exercise the full install → execute → block contract — including data boundary, RBAC, and sequence detection — against generated handler scripts for each supported framework (Claude Code, Cursor, GitHub Copilot, Codex CLI).

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
