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

SentinelFlow is a monorepo with four packages.

`@sentinelflow/core` — Universal agent schema, finding types, local registry with atomic writes.

`@sentinelflow/parsers` — Six framework-specific parsers that normalize agent configs into the universal schema.

`@sentinelflow/scanner` — 46 governance rules, suppression engine, SARIF/JSON/Markdown/terminal formatters.

`sentinelflow` — CLI that ties it all together. This is the package you install.

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

**Phase 2** (Weeks 7–12) — Runtime interceptors via Claude Code hooks and LangChain callbacks. Anomaly detection for token spend and tool invocation patterns. Live dashboard.

**Phase 3** (Months 4–6) — Policy engine with approval workflows. EU AI Act, SOC 2, and ISO 42001 compliance packs. Python SDK.

**Phase 4** (Months 7–12) — Multi-tenant SaaS. SSO/SAML. SIEM integration. Shadow agent discovery across the organization.

## License

MIT
