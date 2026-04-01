# Framework Support Matrix

SentinelFlow scans AI agent configurations for governance risks before deployment. This page maps exactly what we analyze, what requires integration with external systems, and what's on the roadmap. **If a risk category says "not covered," it means static analysis of config files cannot detect it — not that we ignored it.**

---

## Coverage by framework

### Claude Code — Deep support (primary)

SentinelFlow reads 7 config locations for Claude Code, making it the most thoroughly analyzed framework.

**What we scan:** `.claude/settings.json` (allowedTools, blockedTools, mcpServers), `CLAUDE.md`, `AGENTS.md`, `agents/*.md` and `.claude/agents/*.md` (YAML frontmatter agent definitions), `.claude/commands/*.md` (slash command definitions), `hooks/hooks.json` (hook event handlers). We classify every tool by risk level, detect delegation chains between agents, and infer swarm roles (orchestrator, worker, reviewer, specialist).

**Known limitations:** We cannot detect tools granted via `--dangerously-skip-permissions` at runtime (we only detect if the flag is present in hook scripts or shell configs). We cannot see what MCP servers actually expose at runtime — only what's declared in settings.json. We do not parse CLAUDE.md for natural-language permission grants (e.g., "you may use any tool") because NLP-based detection has unacceptable false positive rates.

**Validated against:** Everything Claude Code (ECC) — 30 agents, 133 findings, 0 crashes, 0 false positives at critical severity.

### Cursor — Deep support (primary)

**What we scan:** `.cursor/rules/*.mdc` files with frontmatter (description, globs, alwaysApply, model), `.cursorrules` (legacy format), `.cursor/mcp.json` (MCP server configurations), `.cursorignore`.

**Known limitations:** Cursor has cycled through three rule format generations (plaintext → .mdc → folder-based RULE.md). Our parser handles `.mdc` and plaintext `.cursorrules`. The folder-based `RULE.md` format (introduced in Cursor 0.48+) is on the roadmap. We cannot detect user-level Cursor settings stored in `~/Library/Application Support/Cursor/` — only project-level configs.

**Validated against:** 3 popular cursor rules repositories (awesome-cursor-rules-mdc, cursor-rules, cursor-custom-agents).

### Codex CLI / OpenCode — Standard support

**What we scan:** `.codex/config.toml` (model, approval_mode), `codex.md`, `.agents/*.md` (agent definitions with frontmatter), `.opencode/config.json`, `.opencode/` subdirectories (instructions, agents, commands, prompts).

**Known limitations:** Codex CLI's `approval_mode` settings can be overridden by command-line flags at runtime (`--full-auto`). We detect the config file setting but not runtime flag usage. OpenCode's plugin system can dynamically register tools that are invisible to static analysis.

**Validated against:** ECC's .codex/ directory, 2 Codex starter templates.

### LangChain / LangGraph — Standard support (heuristic)

**What we scan:** Python source files for agent construction patterns (`create_react_agent`, `AgentExecutor`, `StateGraph`, `CompiledGraph`, `MessageGraph`), dangerous tool imports (`ShellTool`, `PythonREPLTool`, `SQLDatabaseToolkit`, `FileManagementToolkit`), model selections (`ChatOpenAI`, `ChatAnthropic`, `AzureChatOpenAI`), `pyproject.toml`/`requirements.txt` for dependency detection, `langgraph.json` for deployment config.

**Known limitations:** Our Python scanning is heuristic-based (regex pattern matching), not AST-based. We cannot follow dynamic tool construction, conditional imports, or tools loaded from databases or environment variables. We scan files up to 3 directories deep — deeply nested agent definitions may be missed. LangChain v1.0 (October 2025) removed LCEL pipe syntax — our patterns target both pre-1.0 and post-1.0 patterns but may miss hybrid codebases.

**Validated against:** LangChain RAG template, LangGraph quickstart, one production LangChain app.

### CrewAI — Standard support

**What we scan:** `crew.yaml` / `agents.yaml` / `config/agents.yaml` (agent role, goal, backstory, tools, allow_delegation), `tasks.yaml`, Python files with `@agent` and `@task` decorators, `pyproject.toml`/`requirements.txt` for dependency detection.

**Known limitations:** CrewAI's YAML parsing is based on our own block parser, not a full YAML library. Complex YAML features (anchors, multi-document, flow sequences) may not parse correctly. CrewAI's `process: "hierarchical"` creates implicit manager agents that our parser does not yet extract as separate agent entities. Tools referenced by class name in YAML are mapped to our risk taxonomy for 12 known tool classes — custom tools appear as "unknown" risk.

**Validated against:** CrewAI quickstart template, one production crew configuration.

### Kiro — Basic support

**What we scan:** `.kiro/steering/*.md` (behavioral rules with frontmatter), `.kiro/specs/*.md` (feature specifications), `kiro.md`.

**Known limitations:** Kiro is AWS's newest AI IDE and its configuration format is still evolving. We parse steering files and specs as governance-relevant artifacts but do not yet have Kiro-specific governance rules. Findings come from framework-agnostic rules only.

**Validated against:** ECC's .kiro/ directory.

---

## Coverage by risk category

This is the most important table in SentinelFlow's documentation. It shows exactly what static analysis covers today, what requires runtime or cloud integration, and what's on the roadmap.

| Risk Category | Static (v1) | Requires Integration | Roadmap |
|---|---|---|---|
| **Hardcoded secrets in config files** | ✅ 16 secret patterns (AWS, GitHub, Slack, generic) | — | — |
| **Tool permission over-provisioning** | ✅ Checks declared tools against risk taxonomy | — | — |
| **Missing human-in-the-loop controls** | ✅ Detects absent approval gates | — | — |
| **MCP server misconfiguration** | ✅ No auth, no integrity verification, untrusted URLs | — | — |
| **Multi-agent delegation risks** | ✅ Delegation depth, privilege escalation chains | — | — |
| **Missing governance metadata** | ✅ No owner, no description, no risk assessment | — | — |
| **Cost governance gaps** | ✅ No token budget, no iteration limit, no timeout | — | — |
| **Framework-specific misconfig** | ✅ dangerously-skip-permissions, full-auto mode, etc. | — | — |
| **Prompt injection surface area** | ⚠️ Missing system prompt, no output validation | 🔗 Runtime prompt monitoring | v2.x |
| **Cloud IAM permission sprawl** | ⚠️ Flags role references without scope | 🔗 AWS/Azure/GCP IAM APIs | v2.x |
| **Runtime secret exposure** | ⚠️ Detects hardcoded secrets only | 🔗 Vault/Secrets Manager | v2.x |
| **Dynamic MCP tool registration** | ⚠️ Scans static configs only | 🔗 MCP tools/list introspection | v2.x |
| **Kubernetes network policies** | ❌ Not visible in agent configs | 🔗 K8s API + service mesh | v3.x |
| **Feature-flag-gated capabilities** | ❌ Not visible in agent configs | 🔗 LaunchDarkly/Split.io API | v3.x |
| **Database-driven agent configs** | ❌ Not visible in files | 🔗 Database query adapters | v3.x |
| **Off-platform human approvals** | ❌ Not visible in files | 🔗 Jira/ServiceNow API | v3.x |

Legend: ✅ Covered natively | ⚠️ Partial — see limitations | 🔗 Requires external integration | ❌ Not detectable via static analysis

---

## Test corpus

SentinelFlow's CI runs every parser and rule set against real-world repositories. If any of these break, the build fails.

| Repository | Framework | Expected Agents | Expected Findings | Purpose |
|---|---|---|---|---|
| everything-claude-code | Claude Code | 28-32 | 100-150 | Primary validation (largest public agent project) |
| awesome-cursor-rules-mdc | Cursor | 5-15 | 3-10 | Cursor .mdc format parsing |
| langchain-templates/rag | LangChain | 1-3 | 2-5 | Python heuristic scanning |
| crewai-quickstart | CrewAI | 2-4 | 1-5 | YAML agent parsing, delegation |
| sentinelflow (self) | Claude Code | 1-3 | 0 critical | Self-scan dogfooding |

### Adding to the test corpus

To add a new test corpus entry:

1. Add the repo URL to `tests/corpus/repos.json`
2. Define expected ranges for agent count and finding count
3. Run `pnpm test:corpus` to validate
4. If the scan produces unexpected results, investigate whether it's a parser bug or an intentional difference
5. Submit a PR with the new corpus entry and updated expectations
