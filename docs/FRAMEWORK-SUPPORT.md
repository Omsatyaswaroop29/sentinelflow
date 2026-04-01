# Framework Support Matrix

**Last updated:** April 2026 · **Scanner version:** 0.2.0

SentinelFlow performs static analysis of AI agent configuration files before deployment. This page documents exactly what each parser reads, what governance rules apply, and what falls outside static analysis.

---

## Parser Coverage

### Claude Code — Full Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `.claude/settings.json` | allowedTools, blockedTools, mcpServers, permissions | SF-FC-001, SF-FC-002, SF-AC-001, SF-AC-002, SF-SC-001 |
| `CLAUDE.md` | Project instructions, tool restrictions, behavioral rules | SF-PI-001, SF-PI-002, SF-DG-002 |
| `AGENTS.md` | Agent definitions, orchestration patterns | SF-MA-001, SF-MA-003, SF-CD-001 |
| `agents/*.md` | YAML frontmatter (name, tools, model), Markdown instructions | SF-AC-005, SF-AC-008, SF-FC-007 |
| `.claude/agents/*.md` | Agent definitions in .claude directory | Same as agents/*.md |
| `.claude/commands/*.md` | Slash command definitions | SF-PI-001 (prompt content analysis) |
| `hooks/hooks.json` | Hook event bindings (PreToolUse, PostToolUse, etc.) | SF-AL-001, SF-FC-003 |

**Tested against:** Everything Claude Code (ECC) — 116K+ stars, 30 agents, 133 findings in 32ms.
**Known limitation:** CLAUDE.md content analysis is heuristic-based (regex patterns). Highly dynamic or templated instructions may not be fully parsed.

### Cursor — Full Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `.cursor/rules/*.mdc` | YAML frontmatter (description, globs, alwaysApply), rule content | SF-FC-007, SF-PI-001 |
| `.cursorrules` | Legacy root-level rules (plaintext) | SF-FC-007, SF-PI-001 |
| `.cursor/mcp.json` | MCP server definitions (name, url, tools) | SF-SC-001, SF-SC-007, SF-NS-001 |
| `.cursorignore` | File exclusion patterns | Collected for context |

**Known limitation:** Cursor's `.mdc` format has evolved through three generations (`.cursorrules` → `.mdc` → folder-based). SentinelFlow reads all three but does not detect which version Cursor itself will prioritize at runtime. The `alwaysApply` field in `.mdc` frontmatter is checked but glob pattern evaluation is not performed.

### Codex / OpenCode — Full Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `.codex/config.toml` | model, approval_mode (suggest/auto-edit/full-auto) | SF-FC-001 (full-auto), SF-CG-004 |
| `codex.md` | Project instructions | SF-PI-001, SF-PI-002 |
| `.agents/*.md` | Agent definitions with YAML frontmatter | SF-AC-005, SF-AC-008, SF-FC-007 |
| `.opencode/config.json` | Model selection, settings | SF-CG-004 |
| `.opencode/instructions/*.md` | Agent instructions | SF-PI-001 |

**Known limitation:** Codex CLI's `config.toml` parsing uses regex-based key extraction, not a full TOML parser. Multiline values or complex TOML structures may not be read correctly.

### LangChain / LangGraph — Pattern-Based Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `pyproject.toml`, `requirements.txt` | LangChain/LangGraph dependency detection | SF-SC-009 (known CVEs) |
| `langgraph.json` | LangGraph deployment config | SF-FC-007 |
| `*.py` (Python source files) | Agent factory calls, tool bindings, model selections | SF-AC-002, SF-FC-002, SF-CG-004 |
| `.env` | Environment variable references | SF-AC-001 (hardcoded secrets) |

**What we detect in Python files:** `create_react_agent`, `AgentExecutor`, `StateGraph`, `CompiledGraph` (agent definitions). `ShellTool`, `PythonREPLTool`, `SQLDatabaseToolkit` (high-risk tools). `ChatOpenAI`, `ChatAnthropic`, `ChatGoogleGenerativeAI` (model selection).

**Known limitation:** Python source scanning is pattern-based, not AST-based. Dynamically constructed agents, aliased imports, and metaprogramming patterns will not be detected. LangChain v1.0's removal of LCEL changed import paths — rules target both pre-1.0 and 1.0+ patterns but edge cases may exist.

### CrewAI — YAML-Based Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `crew.yaml`, `agents.yaml` | Agent role, goal, backstory, tools, allow_delegation | SF-MA-001, SF-MA-003, SF-FC-006, SF-FC-007 |
| `tasks.yaml` | Task definitions with agent assignments | Collected for context |
| `config/agents.yaml` | Alternative config location | Same as crew.yaml |
| `*.py` (Python source) | `@agent` decorator patterns | SF-AC-005 |

**Known limitation:** CrewAI releases rapidly (12+ versions in 5 months post-1.0). The `allow_delegation` field defaults to `true` in older versions — SentinelFlow flags this but cannot determine the installed CrewAI version statically.

### Kiro — Steering File Support

| Config location | What we read | Governance rules applied |
|----------------|-------------|------------------------|
| `.kiro/steering/*.md` | Steering file definitions with YAML frontmatter | SF-FC-007, SF-PI-001 |
| `.kiro/specs/*.md` | Feature specification files | Collected for context |
| `kiro.md` | Project instructions | SF-PI-001 |

**Known limitation:** Kiro is the newest supported framework. The parser reads steering files but does not yet have Kiro-specific governance rules (e.g., spec-driven development safety patterns). This is planned for Phase 2.

---

## What Static Analysis Cannot See

SentinelFlow scans configuration files at a point in time. The following require runtime context or cloud API integration and are **not covered by static scanning:**

| Risk Category | Static Coverage | What's Missing | Roadmap |
|--------------|----------------|----------------|---------|
| Agent config policy violations | ✅ Full | — | — |
| Tool permission over-provisioning | ✅ Full | — | — |
| Missing human-in-the-loop | ✅ Full | — | — |
| Hardcoded secrets in config | ✅ Full (16 patterns) | — | — |
| IAM/cloud permission sprawl | ⚠️ Flags role ARN references | Actual IAM policy evaluation | v2.x: AWS/Azure/GCP API connectors |
| Runtime secret injection | ⚠️ Detects hardcoded only | Vault, Secrets Manager, K8s secrets | v2.x: Vault integration |
| Network access controls | ❌ Not in config files | K8s NetworkPolicies, service mesh | v3.x: K8s API integration |
| Feature-flag-gated capabilities | ❌ Not in config files | LaunchDarkly, Split.io state | v3.x: Feature flag API |
| Dynamic MCP tool registration | ⚠️ Scans static MCP configs | Runtime `tools/list` responses | v2.x: MCP live introspection |
| Database-driven agent configs | ❌ Not in files | DB-stored agent definitions | v3.x: DB query adapters |
| Off-platform human approvals | ❌ Not in code | Jira/Slack approval workflows | v3.x: Ticketing integration |

**What this means in practice:** A clean SentinelFlow scan means your agent configurations follow governance best practices as declared in code. It does not mean your agents are safe at runtime. Static scanning is one layer in a defense-in-depth strategy.

---

## Rule Applicability by Framework

Each rule declares which frameworks it applies to. Rules with `frameworks: "all"` run against every detected framework.

| Rule ID | Name | Frameworks | Severity |
|---------|------|------------|----------|
| SF-PI-001 | No system prompt defined | all | medium |
| SF-PI-002 | Sensitive data in prompts | all | high |
| SF-AC-001 | Hardcoded credentials | all | critical |
| SF-AC-002 | Excessive permissions | all | high |
| SF-FC-001 | Permission checks disabled | claude-code | critical |
| SF-FC-002 | Wildcard bash permissions | claude-code | high |
| SF-FC-003 | Git hook bypass patterns | claude-code | high |
| SF-MA-001 | No delegation depth limit | all (multi-agent) | medium |
| SF-MA-003 | Privilege escalation via delegation | all (multi-agent) | high |
| SF-SC-001 | MCP server without integrity check | all (with MCP) | high |
| SF-CG-001 | No token budget | all | medium |

Full rule reference: see `packages/scanner/src/rules/` in the repository.

---

## Version Compatibility

SentinelFlow aims to support the current and previous major version of each framework. When a framework introduces breaking config format changes, rules declare version bounds:

| Framework | Supported Config Formats | Notes |
|-----------|-------------------------|-------|
| Claude Code | .claude/settings.json (all versions), CLAUDE.md, AGENTS.md | Stable format since 2025 |
| Cursor | .cursorrules (legacy), .cursor/rules/*.mdc (current) | Both parsed simultaneously |
| Codex CLI | .codex/config.toml | Format introduced May 2025 |
| LangChain | Python imports for v0.2+ and v1.0+ | Pattern-based, both versions |
| CrewAI | crew.yaml (v0.30+), agents.yaml (v1.0+) | YAML format stable since v0.30 |
| Kiro | .kiro/ directory structure | Format may evolve |
