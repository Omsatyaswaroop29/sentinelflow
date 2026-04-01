Run a governance scan on the current project using the governance-scanner agent.

Discover all AI agents in this project, check for security issues and governance gaps, and produce a structured report with findings grouped by severity.

Focus on:
1. Agent discovery across all frameworks (Claude Code, Cursor, Codex, LangChain, etc.)
2. Security: secrets in configs, overprivileged access, git hook bypasses
3. Governance: missing owners, no tool allowlists, no cost budgets
4. Report with actionable recommendations

Output the report in Markdown format suitable for committing to the repository as GOVERNANCE_REPORT.md.
