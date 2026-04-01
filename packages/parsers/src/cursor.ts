/**
 * @module @sentinelflow/parsers/cursor
 *
 * Parses Cursor AI agent configurations from:
 *   1. .cursor/rules/ — project-level cursor rules (*.mdc files)
 *   2. .cursorrules — legacy root-level rules file
 *   3. .cursor/mcp.json — MCP server configurations
 *   4. .cursorignore — file exclusion patterns
 *
 * Cursor uses a rules-based system where each rule file can specify
 * glob patterns for when it applies, model preferences, and behavioral
 * instructions. Unlike Claude Code's agent frontmatter, Cursor rules
 * use .mdc (Markdown Cursor) format with frontmatter.
 */

import * as fs from "fs";
import * as path from "path";
import matter from "gray-matter";
import {
  createAgent,
  type SentinelFlowAgent,
  type AgentTool,
  type MCPServer,
} from "@sentinelflow/core";
import type { FrameworkParser, ParseResult, ConfigFile } from "./interface";

function safeReadFile(filePath: string): string | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

function safeListDir(dirPath: string, extensions: string[]): string[] {
  try {
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) return [];
    return fs.readdirSync(dirPath).filter((f: string) =>
      extensions.some((ext) => f.endsWith(ext))
    );
  } catch {
    return [];
  }
}

export class CursorParser implements FrameworkParser {
  readonly framework = "cursor" as const;
  readonly displayName = "Cursor";
  readonly markers = [".cursor", ".cursorrules"];

  async detect(rootDir: string): Promise<boolean> {
    return (
      fs.existsSync(path.join(rootDir, ".cursor")) ||
      fs.existsSync(path.join(rootDir, ".cursorrules"))
    );
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // 1. Parse .cursor/rules/*.mdc (project rules)
    const rulesDir = path.join(rootDir, ".cursor", "rules");
    for (const file of safeListDir(rulesDir, [".mdc", ".md"])) {
      const filePath = path.join(rulesDir, file);
      const content = safeReadFile(filePath);
      if (!content) continue;
      configFiles.push({ path: filePath, content, framework: "cursor" });

      try {
        const parsed = matter(content);
        const data = parsed.data as Record<string, unknown>;
        const name = typeof data.description === "string"
          ? data.description.substring(0, 60).replace(/[^a-zA-Z0-9-_ ]/g, "").trim().toLowerCase().replace(/\s+/g, "-")
          : path.basename(file, path.extname(file));

        agents.push(createAgent({
          name: `cursor-rule-${name}`,
          framework: "cursor",
          description: typeof data.description === "string" ? data.description : parsed.content.slice(0, 200).trim(),
          source_file: filePath,
          model: typeof data.model === "string" ? data.model : undefined,
        }));
      } catch (error: unknown) {
        warnings.push(`Could not parse ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    // 2. Parse .cursorrules (legacy root-level rules)
    const legacyRulesPath = path.join(rootDir, ".cursorrules");
    const legacyContent = safeReadFile(legacyRulesPath);
    if (legacyContent) {
      configFiles.push({ path: legacyRulesPath, content: legacyContent, framework: "cursor" });
      agents.push(createAgent({
        name: "cursor-legacy-rules",
        framework: "cursor",
        description: legacyContent.slice(0, 200).trim(),
        source_file: legacyRulesPath,
      }));
    }

    // 3. Parse .cursor/mcp.json (MCP servers)
    const mcpPath = path.join(rootDir, ".cursor", "mcp.json");
    const mcpContent = safeReadFile(mcpPath);
    if (mcpContent) {
      configFiles.push({ path: mcpPath, content: mcpContent, framework: "cursor" });
      try {
        const mcpConfig = JSON.parse(mcpContent) as Record<string, unknown>;
        const servers = mcpConfig.mcpServers as Record<string, Record<string, unknown>> | undefined;
        if (servers) {
          const mcpServers: MCPServer[] = Object.entries(servers).map(([name, config]) => ({
            name,
            url: typeof config.url === "string" ? config.url : undefined,
            tools_exposed: Array.isArray(config.tools) ? config.tools as string[] : undefined,
          }));

          // Attach MCP servers to first agent or create one
          if (agents.length > 0 && agents[0]) {
            agents[0].mcp_servers = mcpServers;
          } else {
            agents.push(createAgent({
              name: "cursor-mcp-config",
              framework: "cursor",
              description: "Cursor MCP server configuration",
              source_file: mcpPath,
              mcp_servers: mcpServers,
            }));
          }
        }
      } catch {
        warnings.push(`Invalid JSON in ${mcpPath}`);
      }
    }

    // 4. Collect .cursorignore
    const ignorePath = path.join(rootDir, ".cursorignore");
    const ignoreContent = safeReadFile(ignorePath);
    if (ignoreContent) {
      configFiles.push({ path: ignorePath, content: ignoreContent, framework: "cursor" });
    }

    // Default agent if configs found but no agents parsed
    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(createAgent({
        name: "cursor-default",
        framework: "cursor",
        description: "Default Cursor configuration for this project",
        source_file: configFiles[0]?.path,
      }));
    }

    return { agents, config_files: configFiles, warnings };
  }
}
