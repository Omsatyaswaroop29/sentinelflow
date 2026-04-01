/**
 * @module @sentinelflow/parsers/claude-code
 *
 * Parses Claude Code agent configurations from:
 *   1. .claude/settings.json — tool permissions, MCP servers
 *   2. CLAUDE.md — project guidance and behavioral rules
 *   3. agents/*.md — ECC-style agent definitions with YAML frontmatter
 *   4. AGENTS.md — cross-platform agent instructions
 *   5. .claude/commands/*.md — custom slash commands
 *   6. hooks/hooks.json — hook definitions (runtime behavior)
 *
 * Uses gray-matter for reliable YAML frontmatter extraction.
 * Handles both vanilla Claude Code and ECC-enhanced projects.
 */

import * as fs from "fs";
import * as path from "path";
import matter from "gray-matter";
import {
  createAgent,
  type SentinelFlowAgent,
  type AgentTool,
  type MCPServer,
  type SwarmRole,
} from "@sentinelflow/core";
import type { FrameworkParser, ParseResult, ConfigFile } from "./interface";

/** Safely read a file, returning null if it doesn't exist or can't be read */
function safeReadFile(filePath: string): string | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, "utf-8");
  } catch (error: unknown) {
    return null;
  }
}

/** Safely parse JSON, returning null on failure */
function safeParseJSON(content: string, filePath: string): Record<string, unknown> | null {
  try {
    return JSON.parse(content) as Record<string, unknown>;
  } catch (error: unknown) {
    return null;
  }
}

/** Safely list files in a directory, returning empty array if it doesn't exist */
function safeListDir(dirPath: string, extensions: string[]): string[] {
  try {
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
      return [];
    }
    return fs.readdirSync(dirPath).filter((f: string) =>
      extensions.some((ext) => f.endsWith(ext))
    );
  } catch {
    return [];
  }
}

export class ClaudeCodeParser implements FrameworkParser {
  readonly framework = "claude-code" as const;
  readonly displayName = "Claude Code";
  readonly markers = [".claude", "CLAUDE.md", "AGENTS.md"];

  async detect(rootDir: string): Promise<boolean> {
    return (
      fs.existsSync(path.join(rootDir, ".claude")) ||
      fs.existsSync(path.join(rootDir, "CLAUDE.md")) ||
      fs.existsSync(path.join(rootDir, "AGENTS.md"))
    );
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // ── 1. Parse .claude/settings.json ───────────────────────
    this.parseSettingsFile(rootDir, agents, configFiles, warnings);

    // ── 2. Parse agents/*.md (ECC-style agent definitions) ──
    this.parseAgentsDirectory(rootDir, agents, configFiles, warnings);

    // ── 3. Collect CLAUDE.md ────────────────────────────────
    this.collectConfigFile(
      path.join(rootDir, "CLAUDE.md"),
      configFiles
    );

    // ── 4. Collect AGENTS.md ────────────────────────────────
    this.collectConfigFile(
      path.join(rootDir, "AGENTS.md"),
      configFiles
    );

    // ── 5. Collect hooks/hooks.json ─────────────────────────
    this.collectConfigFile(
      path.join(rootDir, "hooks", "hooks.json"),
      configFiles
    );

    // ── 6. Collect .claude/commands/*.md ─────────────────────
    const commandsDir = path.join(rootDir, ".claude", "commands");
    for (const file of safeListDir(commandsDir, [".md"])) {
      this.collectConfigFile(path.join(commandsDir, file), configFiles);
    }

    // ── 7. Collect .claude/agents/*.md ──────────────────────
    const claudeAgentsDir = path.join(rootDir, ".claude", "agents");
    for (const file of safeListDir(claudeAgentsDir, [".md"])) {
      const filePath = path.join(claudeAgentsDir, file);
      const content = safeReadFile(filePath);
      if (content !== null) {
        configFiles.push({ path: filePath, content, framework: "claude-code" });
        const agent = this.parseAgentMarkdown(content, filePath, warnings);
        if (agent) agents.push(agent);
      }
    }

    // If no agents were discovered from structured sources,
    // create a default project-level agent from config files
    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(
        createAgent({
          name: "claude-code-default",
          framework: "claude-code",
          description: "Default Claude Code agent for this project",
          source_file: configFiles[0]?.path,
          swarm_role: "standalone",
        })
      );
    }

    return { agents, config_files: configFiles, warnings };
  }

  // ─── Private: Parse .claude/settings.json ───────────────────

  private parseSettingsFile(
    rootDir: string,
    agents: SentinelFlowAgent[],
    configFiles: ConfigFile[],
    warnings: string[]
  ): void {
    const settingsPath = path.join(rootDir, ".claude", "settings.json");
    const content = safeReadFile(settingsPath);
    if (content === null) return;

    configFiles.push({ path: settingsPath, content, framework: "claude-code" });

    const settings = safeParseJSON(content, settingsPath);
    if (settings === null) {
      warnings.push(`Invalid JSON in ${settingsPath}`);
      return;
    }

    // Extract tools configuration
    const allowedTools = Array.isArray(settings.allowedTools)
      ? (settings.allowedTools as string[])
      : [];
    const blockedTools = Array.isArray(settings.blockedTools)
      ? (settings.blockedTools as string[])
      : [];

    // Extract MCP servers
    const mcpServers: MCPServer[] = [];
    if (settings.mcpServers && typeof settings.mcpServers === "object") {
      for (const [name, config] of Object.entries(
        settings.mcpServers as Record<string, Record<string, unknown>>
      )) {
        mcpServers.push({
          name,
          url: typeof config.url === "string" ? config.url : undefined,
          tools_exposed: Array.isArray(config.tools)
            ? (config.tools as string[])
            : undefined,
        });
      }
    }

    // Build tools list
    const tools: AgentTool[] = allowedTools.map((t) => this.classifyTool(t));

    agents.push(
      createAgent({
        name: "claude-code-project",
        framework: "claude-code",
        description: "Project-level Claude Code configuration from settings.json",
        source_file: settingsPath,
        tools,
        allowed_tools: allowedTools.length > 0 ? allowedTools : undefined,
        blocked_tools: blockedTools.length > 0 ? blockedTools : undefined,
        mcp_servers: mcpServers.length > 0 ? mcpServers : undefined,
        swarm_role: "standalone",
      })
    );

    // Also check .claude/settings.local.json for local overrides
    const localSettingsPath = path.join(rootDir, ".claude", "settings.local.json");
    const localContent = safeReadFile(localSettingsPath);
    if (localContent !== null) {
      configFiles.push({
        path: localSettingsPath,
        content: localContent,
        framework: "claude-code",
      });
    }
  }

  // ─── Private: Parse agents/ directory ───────────────────────

  private parseAgentsDirectory(
    rootDir: string,
    agents: SentinelFlowAgent[],
    configFiles: ConfigFile[],
    warnings: string[]
  ): void {
    const agentsDir = path.join(rootDir, "agents");
    const files = safeListDir(agentsDir, [".md", ".yaml", ".yml"]);

    for (const file of files) {
      const filePath = path.join(agentsDir, file);
      const content = safeReadFile(filePath);
      if (content === null) continue;

      configFiles.push({ path: filePath, content, framework: "claude-code" });

      const agent = this.parseAgentMarkdown(content, filePath, warnings);
      if (agent) agents.push(agent);
    }
  }

  // ─── Private: Parse a single agent Markdown file ────────────

  private parseAgentMarkdown(
    content: string,
    filePath: string,
    warnings: string[]
  ): SentinelFlowAgent | null {
    // Skip empty files
    if (content.trim().length === 0) {
      warnings.push(`Empty file: ${filePath}`);
      return null;
    }

    // Use gray-matter for reliable YAML frontmatter extraction
    let frontmatterData: Record<string, unknown> = {};
    let bodyContent = content;

    try {
      const parsed = matter(content);
      frontmatterData = parsed.data as Record<string, unknown>;
      bodyContent = parsed.content;
    } catch (error: unknown) {
      // File has no frontmatter or invalid frontmatter — use filename as agent name
      const name = path.basename(filePath, path.extname(filePath));
      warnings.push(
        `Could not parse frontmatter in ${filePath}: ${
          error instanceof Error ? error.message : String(error)
        }. Using filename as agent name.`
      );
      return createAgent({
        name,
        framework: "claude-code",
        description: bodyContent.slice(0, 200).trim(),
        source_file: filePath,
      });
    }

    // Extract fields from frontmatter
    const name =
      typeof frontmatterData.name === "string"
        ? frontmatterData.name
        : path.basename(filePath, path.extname(filePath));

    const description =
      typeof frontmatterData.description === "string"
        ? frontmatterData.description
        : bodyContent.trim().slice(0, 200);

    const model =
      typeof frontmatterData.model === "string"
        ? frontmatterData.model
        : undefined;

    // Parse tools — can be string (comma-separated) or array
    let toolNames: string[] = [];
    if (Array.isArray(frontmatterData.tools)) {
      toolNames = frontmatterData.tools.map(String);
    } else if (typeof frontmatterData.tools === "string") {
      toolNames = frontmatterData.tools.split(",").map((t: string) => t.trim());
    }
    // Also check allowed-tools (Claude Code SKILL.md format)
    if (typeof frontmatterData["allowed-tools"] === "string") {
      const additional = frontmatterData["allowed-tools"]
        .split(",")
        .map((t: string) => t.trim());
      toolNames = [...toolNames, ...additional];
    }

    const tools: AgentTool[] = toolNames
      .filter((t) => t.length > 0)
      .map((t) => this.classifyTool(t));

    const swarmRole = this.inferSwarmRole(name, description);

    return createAgent({
      name,
      framework: "claude-code",
      description,
      source_file: filePath,
      model,
      tools,
      swarm_role: swarmRole,
    });
  }

  // ─── Private: Collect a config file without parsing agents ──

  private collectConfigFile(filePath: string, configFiles: ConfigFile[]): void {
    const content = safeReadFile(filePath);
    if (content !== null) {
      configFiles.push({ path: filePath, content, framework: "claude-code" });
    }
  }

  // ─── Private: Classify a tool name by type and risk ─────────

  private classifyTool(toolName: string): AgentTool {
    const lower = toolName.toLowerCase().trim();

    if (
      lower.includes("bash") ||
      lower.includes("shell") ||
      lower.includes("exec") ||
      lower === "command"
    ) {
      return { name: toolName, type: "bash", risk_level: "high" };
    }
    if (
      lower.includes("write") ||
      lower.includes("create_file") ||
      lower.includes("str_replace") ||
      lower === "edit"
    ) {
      return { name: toolName, type: "file_write", risk_level: "medium" };
    }
    if (
      lower.includes("read") ||
      lower.includes("view") ||
      lower.includes("cat") ||
      lower.includes("glob") ||
      lower.includes("grep")
    ) {
      return { name: toolName, type: "file_read", risk_level: "low" };
    }
    if (lower.includes("search") || lower.includes("web_search")) {
      return { name: toolName, type: "web_search", risk_level: "low" };
    }
    if (
      lower.includes("fetch") ||
      lower.includes("http") ||
      lower.includes("curl") ||
      lower.includes("web_fetch")
    ) {
      return { name: toolName, type: "web_fetch", risk_level: "medium" };
    }
    if (lower.includes("mcp")) {
      return { name: toolName, type: "mcp", risk_level: "medium" };
    }

    return { name: toolName, type: "custom", risk_level: "low" };
  }

  // ─── Private: Infer swarm role from name/description ────────

  private inferSwarmRole(name: string, description: string): SwarmRole {
    const text = `${name} ${description}`.toLowerCase();

    if (
      text.includes("planner") ||
      text.includes("orchestrat") ||
      text.includes("coordinat") ||
      text.includes("dispatcher")
    ) {
      return "orchestrator";
    }
    if (
      text.includes("review") ||
      text.includes("audit") ||
      text.includes("check") ||
      text.includes("verify")
    ) {
      return "reviewer";
    }
    if (
      text.includes("specialist") ||
      text.includes("expert") ||
      text.includes("specific") ||
      text.includes("resolver")
    ) {
      return "specialist";
    }
    if (
      text.includes("worker") ||
      text.includes("execut") ||
      text.includes("build") ||
      text.includes("runner")
    ) {
      return "worker";
    }

    return "standalone";
  }
}
