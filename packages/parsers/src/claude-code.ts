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
    // Original signals: .claude/ dir, CLAUDE.md, AGENTS.md.
    if (
      fs.existsSync(path.join(rootDir, ".claude")) ||
      fs.existsSync(path.join(rootDir, "CLAUDE.md")) ||
      fs.existsSync(path.join(rootDir, "AGENTS.md"))
    ) return true;

    // NEW: also detect repos whose entire purpose is a collection of agent
    // definition files stored in a root-level `agents/` directory (e.g.
    // furai/claude-code-subagents, iannuttall/claude-agents). These repos
    // have no .claude/ dir because they are MEANT to be copied INTO one
    // -- but they are 100% Claude Code agent content and must be scanned.
    const agentsDir = path.join(rootDir, "agents");
    if (fs.existsSync(agentsDir) && fs.statSync(agentsDir).isDirectory()) {
      const files = fs.readdirSync(agentsDir);
      if (files.some((f) => f.endsWith(".md"))) return true;
    }

    return false;
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

  // ─── Private: Find all `agents/` directories anywhere under rootDir ──
  //
  // Walks rootDir looking for directories literally named `agents` at any
  // depth. This handles wshobson-style repos where agents live under
  // plugins/*/agents/ rather than at the conventional rootDir/agents/.
  // We cap depth and skip known non-source dirs to stay fast.
  private findAgentsDirs(
    dir: string,
    found: string[],
    depth: number = 0
  ): void {
    if (depth > 5) return;

    const SKIP = new Set([
      "node_modules", ".git", ".cache", "dist", "build", "coverage",
      "__pycache__", ".turbo", ".next", "references", "docs", "assets",
    ]);

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIP.has(entry.name.toLowerCase()) || entry.name.startsWith(".")) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.name.toLowerCase() === "agents") {
        found.push(fullPath);
        // Don't recurse into an agents/ dir — its contents are files, not
        // nested agents/ dirs. collectAgentFilesRecursive handles the files.
      } else {
        this.findAgentsDirs(fullPath, found, depth + 1);
      }
    }
  }

  // ─── Private: Is this .md file an agent definition? ─────────
  //
  // This is the guard against over-discovery. When we recurse into `agents/`
  // subtrees we find a mix of real agent definitions AND supporting files
  // (README.md, SKILL.md, commands/*.md, references/*.md, ARCHITECTURE.md).
  // Only the former should be parsed as agents.
  //
  // Allow heuristic: the file is under an `agents/` path segment.
  // Deny heuristic: the filename or parent directory matches a known
  // non-agent pattern.
  //
  // This is deliberately conservative: when uncertain, we include the file
  // (a false-positive agent is less harmful than a false-negative miss).
  // The deny list targets only high-confidence non-agent names.
  private isAgentFile(filePath: string): boolean {
    const fileName = path.basename(filePath).toLowerCase();
    const dirName = path.dirname(filePath).toLowerCase();

    // ── Deny list: known non-agent filenames ─────────────────
    const DENY_FILENAMES = new Set([
      "readme.md", "architecture.md", "contributing.md", "changelog.md",
      "license.md", "workflow_config.md", "workflows.md", "soul.md",
      "sponsoring.md", "sponsors.md", "troubleshooting.md", "security.md",
      "rules.md", "agents.md", "claude.md",
      // wshobson-specific support files:
      "skill.md", "details.md",
    ]);
    if (DENY_FILENAMES.has(fileName)) return false;

    // ── Deny list: known non-agent parent directories ────────
    const DENY_DIRS = ["commands", "references", "skills", "docs", "examples"];
    if (DENY_DIRS.some((d) => dirName.includes(`/${d}/`) || dirName.endsWith(`/${d}`))) {
      return false;
    }

    return true;
  }

  // ─── Private: Recursively collect agent .md files ──────────
  //
  // Walks all `agents/` subdirectories anywhere under rootDir, collecting
  // files that pass isAgentFile(). This handles three layouts we've seen:
  //   1. flat:     agents/actix-expert.md          (furai)
  //   2. category: data-ai/ml-engineer.md          (rshah — rootDir IS the agents tree)
  //   3. nested:   plugins/ui-design/agents/*.md   (wshobson)
  //
  // It does NOT walk the entire rootDir blindly — only paths that contain
  // an `agents/` segment, OR the rootDir itself when it IS an agents collection
  // (detected because it has CLAUDE.md / AGENTS.md alongside agent .md files).
  private collectAgentFilesRecursive(
    dir: string,
    agentFiles: string[],
    depth: number = 0
  ): void {
    // Safety cap: never recurse more than 6 levels deep.
    if (depth > 6) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    const SKIP_DIRS = new Set([
      "node_modules", ".git", ".cache", "dist", "build", "coverage",
      "__pycache__", ".turbo", ".next", "commands", "references",
      "skills", "docs", "examples", "assets",
    ]);

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        this.collectAgentFilesRecursive(fullPath, agentFiles, depth + 1);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith(".md") || entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) &&
        this.isAgentFile(fullPath)
      ) {
        agentFiles.push(fullPath);
      }
    }
  }

  // ─── Private: Parse agents/ directory (now recursive) ───────

  private parseAgentsDirectory(
    rootDir: string,
    agents: SentinelFlowAgent[],
    configFiles: ConfigFile[],
    warnings: string[]
  ): void {
    // Collect all agent files by recursively walking two sources:
    // (a) the conventional `rootDir/agents/` directory, and
    // (b) the full rootDir when it IS an agent-collection repo (i.e. the .md
    //     files live directly in category subfolders at the root, like rshah).
    //
    // To avoid scanning ALL .md files in every project (too broad), we restrict
    // the full-rootDir walk to repos that look like agent collections: they have
    // an `agents/` dir OR their root contains category-style subdirs with .md.
    // In practice, the detect() guard already filtered for this pattern.

    const agentFiles: string[] = [];

    // (a) Find ALL `agents/` directories anywhere under rootDir — covers:
    //   - conventional:  rootDir/agents/          (flat, furai-style)
    //   - nested:        plugins/*/agents/         (wshobson-style)
    //   - .claude:       .claude/agents/           (standard)
    // findAgentsDirs walks rootDir looking for any dir literally named
    // `agents`, then collectAgentFilesRecursive gathers the .md files inside.
    const agentsDirs: string[] = [];
    this.findAgentsDirs(rootDir, agentsDirs);
    for (const dir of agentsDirs) {
      this.collectAgentFilesRecursive(dir, agentFiles);
    }

    // (b) For rshah-style repos: agents live in category subdirs at the root
    //     (data-ai/, security/, research/ …) with no intermediate `agents/`
    //     path segment. We only trigger this walk when there is NO `.claude/`
    //     dir and NO `agents/` dir — meaning the whole repo IS the agent tree.
    const hasClaudeDir = fs.existsSync(path.join(rootDir, ".claude"));
    const hasAgentsDir = agentsDirs.length > 0;
    if (!hasClaudeDir && !hasAgentsDir) {
      // rootDir is itself an agent-collection repo. Walk it, but stay shallow
      // (depth 2) to avoid crawling unrelated subtrees if any exist.
      const topLevelDirs = (() => {
        try {
          return fs.readdirSync(rootDir, { withFileTypes: true })
            .filter((e) => e.isDirectory())
            .map((e) => path.join(rootDir, e.name));
        } catch { return []; }
      })();

      const SKIP_ROOTS = new Set([
        "node_modules", ".git", ".cache", "dist", "build",
        "__pycache__", ".turbo", ".next",
      ]);

      for (const subDir of topLevelDirs) {
        const name = path.basename(subDir).toLowerCase();
        if (SKIP_ROOTS.has(name) || name.startsWith(".")) continue;
        this.collectAgentFilesRecursive(subDir, agentFiles, 0);
      }
    }

    // De-duplicate (in case two walk paths found the same file).
    const seen = new Set<string>();
    for (const filePath of agentFiles) {
      if (seen.has(filePath)) continue;
      seen.add(filePath);

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
