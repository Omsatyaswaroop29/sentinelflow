# SentinelFlow

**The vendor-neutral governance layer for enterprise AI agents.**

41 governance rules · 10 security categories · 8 compliance frameworks · 12 CWE references · 5 CVE mappings · CI/CD ready

```bash
# Scan any project — no install needed
npx sentinelflow scan
```

---

## The Problem

**80% of Fortune 500 companies now run active AI agents** ([Microsoft Cyber Pulse, Feb 2026](https://www.microsoft.com/en-us/security/blog/2026/02/10/80-of-fortune-500-use-active-ai-agents-observability-governance-and-security-shape-the-new-frontier/)). Over 3 million corporate agents operate today — but only 47% are monitored. Microsoft Agent 365 governs Microsoft agents. Datadog monitors agents on their platform. **Nobody governs the heterogeneous fleet** — the Claude Code agents alongside LangChain deployments alongside Cursor workflows alongside custom builds.

SentinelFlow does.

---

## Quick Start

```bash
# Scan for agents and governance issues
npx sentinelflow scan

# Initialize governance in your project
npx sentinelflow init

# JSON output for CI/CD pipelines
npx sentinelflow scan --format json

# Markdown governance report
npx sentinelflow scan --format md > GOVERNANCE_REPORT.md

# SARIF output for GitHub Security tab
npx sentinelflow scan --format sarif > results.sarif

# List registered agents
npx sentinelflow registry list
```

**Output:**

```
  SentinelFlow v0.1.0 — Agent Governance Scanner

  Scanning /Users/you/my-project...

  Frameworks detected:
    ✓ Claude Code (.claude/, AGENTS.md)
    ✓ LangChain (pyproject.toml)

  Agents discovered: 5
    ├── planner (claude-code, orchestrator)
    ├── code-reviewer (claude-code, reviewer)
    ├── tdd-guide (claude-code, specialist)
    ├── research-agent (langchain, worker)
    └── summarizer (langchain, worker)

  Findings: 1 critical, 3 high, 4 medium, 2 low

  CRITICAL
  ┌────────────────────────────────────────────────────────────┐
  │ SF-SEC-001  AWS Access Key in .claude/settings.json:14     │
  └────────────────────────────────────────────────────────────┘

  HIGH
  ┌────────────────────────────────────────────────────────────┐
  │ SF-SEC-003  --no-verify bypass in hooks/hooks.json:8       │
  │ SF-PERM-001 4 agents have no explicit tool allowlist        │
  │ SF-SEC-005  planner has unrestricted bash execution         │
  └────────────────────────────────────────────────────────────┘

  Scan completed in 127ms
  Registry updated: 5 agents in .sentinelflow/
```

---

## Installation

### Plugin Marketplace (Claude Code)

```bash
/plugin marketplace add omswaroop/sentinelflow
/plugin install sentinelflow@sentinelflow
```

### npm (recommended)

```bash
npm install -g sentinelflow
# or: pnpm add -g sentinelflow
# or: npx sentinelflow scan (zero-install)
```

### Manual Clone

```bash
git clone https://github.com/omswaroop/sentinelflow.git
cd sentinelflow
pnpm install && pnpm build
./install.sh
```

---

## What's Inside

```
sentinelflow/
├── CLAUDE.md                          # Project guidance for Claude Code
├── AGENTS.md                          # Cross-platform agent instructions
├── .claude-plugin/plugin.json         # Plugin manifest for marketplace
├── .claude/agents/                    # Claude Code governance agent
├── .claude/commands/                  # /governance-scan slash command
├── packages/
│   ├── core/src/schema/               # Universal agent schema & registry
│   ├── parsers/src/                   # Framework-specific config parsers
│   ├── scanner/src/rules/             # Static analysis governance rules
│   ├── interceptors/src/              # Runtime monitoring SDK (Phase 2)
│   └── cli/src/                       # The sentinelflow command
├── rules/                             # Community governance rules
├── compliance-packs/                  # EU AI Act, SOC 2, HIPAA (Phase 3)
├── install.sh                         # Cross-platform installer
└── llms.txt                           # LLM-optimized project docs
```

---

## Governance Rules — 41 Rules Across 10 Categories

| Category | Rules | Key Detections |
|----------|:-----:|----------------|
| **Prompt Injection** (PI) | 4 | No system prompt, sensitive data in prompts, unsafe output handling, context window risks |
| **Access Control** (AC) | 5 | Hardcoded credentials (16 patterns), excessive permissions, no human oversight, privilege escalation, no owner |
| **Supply Chain** (SC) | 5 | MCP server integrity, tool description poisoning, no MCP auth, framework CVEs, config in public repos |
| **Data Governance** (DG) | 3 | Unclassified data sources, cross-environment bridging, unrestricted file writes |
| **Cost Governance** (CG) | 5 | No token budget, no iteration limits, no timeouts, expensive model routing, no cost attribution |
| **Framework Config** (FC) | 6 | `--dangerously-skip-permissions`, wildcard Bash, git hook bypass, unsafe deserialization, unrestricted delegation |
| **Multi-Agent** (MA) | 3 | No delegation depth limit, privilege escalation via delegation, no inter-agent validation |
| **Audit Logging** (AL) | 3 | No audit logging, no SIEM integration, sensitive data in logs |
| **Compliance Docs** (CD) | 4 | No risk assessment, no technical docs, no human oversight docs, no incident response plan |
| **Network Security** (NS) | 3 | Unrestricted network egress, no code sandboxing, unencrypted MCP transport |

**Compliance framework mappings on every finding:** OWASP LLM Top 10 2025, NIST AI RMF, EU AI Act, MITRE ATLAS, HIPAA, SOC 2, ISO 42001, GDPR.

**12 CWE references:** CWE-94, CWE-200, CWE-269, CWE-306, CWE-319, CWE-441, CWE-502, CWE-540, CWE-693, CWE-732, CWE-798, CWE-862.

**5 CVE mappings:** CVE-2023-29374, CVE-2023-36258, CVE-2023-36188, CVE-2023-44467, CVE-2024-21511.

Contributing a new rule = implementing one interface. See [`packages/scanner/src/rules/interface.ts`](packages/scanner/src/rules/interface.ts).

---

## Supported Frameworks

| Framework | Detection | Parsing | Monitoring |
|-----------|:---------:|:-------:|:----------:|
| Claude Code | ✅ | ✅ | 🔜 |
| ECC-Enhanced Projects | ✅ | ✅ | 🔜 |
| Cursor | ✅ | ✅ | 🔜 |
| Codex / OpenCode | ✅ | ✅ | 🔜 |
| LangChain / LangGraph | ✅ | ✅ | 🔜 |
| CrewAI | ✅ | ✅ | 🔜 |
| Kiro | ✅ | ✅ | 🔜 |

Adding a new framework = implementing one interface. See [`packages/parsers/src/interface.ts`](packages/parsers/src/interface.ts).

---

## CI/CD Integration

SentinelFlow exits with code 1 on critical/high findings — drop it into any pipeline:

```yaml
# GitHub Actions
- name: Agent governance gate
  run: npx sentinelflow scan --min-severity critical

# With SARIF upload to GitHub Security
- name: Upload governance findings
  run: npx sentinelflow scan --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## The Universal Agent Schema

Every agent gets normalized into one type regardless of framework:

```typescript
interface SentinelFlowAgent {
  // Identity
  id, name, description, framework, source_file
  // Ownership
  owner, team, created_at, updated_at
  // Capabilities
  tools[], allowed_tools[], model, mcp_servers[]
  // Data Access
  data_sources[], data_classification[], file_system_access, network_access
  // Relationships
  delegates_to[], swarm_role, topology
  // Governance
  governance: { status, risk_level, compliance_tags, token_budget }
  // Runtime (Phase 2)
  runtime: { last_active, cost_30d_usd, anomalies_detected }
}
```

Full schema: [`packages/core/src/schema/agent.ts`](packages/core/src/schema/agent.ts)

---

## Roadmap

**✅ Phase 1 — Scanner & Registry** (Now)
Static scanning · agent discovery · 9 rules · local registry · 4 output formats

**🔜 Phase 2 — Runtime Monitoring** (Weeks 7–12)
Interceptor SDK · anomaly detection · live dashboard · Python SDK

**📋 Phase 3 — Enterprise Governance** (Months 4–6)
Policy engine · approval workflows · EU AI Act / SOC 2 / ISO 42001 compliance packs

**🏢 Phase 4 — Enterprise Scale** (Months 7–12)
Multi-tenant · SSO/SAML · SIEM integration · shadow agent discovery

---

## Relationship to Everything Claude Code

SentinelFlow's architecture draws inspiration from [ECC's AgentShield](https://github.com/affaan-m/everything-claude-code) (116K+ stars). While ECC optimizes agent performance, SentinelFlow governs agent behavior. They're complementary: ECC makes your agents better, SentinelFlow makes them accountable.

---

## Contributing

The easiest ways to contribute:
- **Add a framework parser** — implement `FrameworkParser` in `packages/parsers/src/`
- **Add a governance rule** — implement `ScanRule` in `packages/scanner/src/rules/`
- **Report bugs or request features** — GitHub Issues
- **Translate** — PRs welcome for README translations

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for detailed guidelines.

---

## License

MIT — [LICENSE](LICENSE)

---

Built by [Om Satya Swaroop](https://github.com/omswaroop). Star this repo if you think enterprises should know what their AI agents are doing.
