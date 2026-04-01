/**
 * @module @sentinelflow/parsers/codex
 *
 * Parses OpenAI Codex CLI and OpenCode agent configurations from:
 *   1. .codex/ — Codex CLI config directory
 *   2. .codex/config.toml — Codex settings (model, approval mode)
 *   3. codex.md — Codex-specific instructions (like CLAUDE.md)
 *   4. .agents/ — Agent definition files
 *   5. .opencode/ — OpenCode config directory
 *   6. .opencode/config.json — OpenCode settings
 *
 * Codex CLI uses AGENTS.md for agent instructions (same as Claude Code)
 * and config.toml for settings like model selection and approval_mode
 * (suggest/auto-edit/full-auto corresponding to permission levels).
 */

import * as fs from "fs";
import * as path from "path";
import matter from "gray-matter";
import {
  createAgent,
  type SentinelFlowAgent,
  type AgentTool,
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

export class CodexParser implements FrameworkParser {
  readonly framework = "codex" as const;
  readonly displayName = "Codex / OpenCode";
  readonly markers = [".codex", "codex.md", ".opencode", ".agents"];

  async detect(rootDir: string): Promise<boolean> {
    return (
      fs.existsSync(path.join(rootDir, ".codex")) ||
      fs.existsSync(path.join(rootDir, "codex.md")) ||
      fs.existsSync(path.join(rootDir, ".opencode")) ||
      fs.existsSync(path.join(rootDir, ".agents"))
    );
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // 1. Parse .codex/config.toml
    const codexConfigPath = path.join(rootDir, ".codex", "config.toml");
    const codexConfig = safeReadFile(codexConfigPath);
    if (codexConfig) {
      configFiles.push({ path: codexConfigPath, content: codexConfig, framework: "codex" });

      // Extract approval_mode and model from TOML (simple key=value parsing)
      const modelMatch = codexConfig.match(/model\s*=\s*["']([^"']+)["']/);
      const approvalMatch = codexConfig.match(/approval_mode\s*=\s*["']([^"']+)["']/);
      const model = modelMatch?.[1];
      const approvalMode = approvalMatch?.[1]; // suggest | auto-edit | full-auto

      const tools: AgentTool[] = [];
      if (approvalMode === "full-auto") {
        tools.push({ name: "full-auto-execution", type: "bash", risk_level: "high" });
        tools.push({ name: "full-auto-write", type: "file_write", risk_level: "high" });
      } else if (approvalMode === "auto-edit") {
        tools.push({ name: "auto-edit", type: "file_write", risk_level: "medium" });
      }

      agents.push(createAgent({
        name: "codex-project",
        framework: "codex",
        description: `Codex CLI configuration (approval_mode: ${approvalMode ?? "suggest"})`,
        source_file: codexConfigPath,
        model,
        tools,
      }));
    }

    // 2. Collect codex.md
    const codexMdPath = path.join(rootDir, "codex.md");
    const codexMd = safeReadFile(codexMdPath);
    if (codexMd) {
      configFiles.push({ path: codexMdPath, content: codexMd, framework: "codex" });
    }

    // 3. Parse .agents/*.md
    const agentsDir = path.join(rootDir, ".agents");
    for (const file of safeListDir(agentsDir, [".md", ".yaml", ".yml"])) {
      const filePath = path.join(agentsDir, file);
      const content = safeReadFile(filePath);
      if (!content || content.trim().length === 0) continue;
      configFiles.push({ path: filePath, content, framework: "codex" });

      try {
        const parsed = matter(content);
        const data = parsed.data as Record<string, unknown>;
        const name = typeof data.name === "string"
          ? data.name
          : path.basename(file, path.extname(file));

        agents.push(createAgent({
          name,
          framework: "codex",
          description: typeof data.description === "string"
            ? data.description
            : parsed.content.trim().slice(0, 200),
          source_file: filePath,
          model: typeof data.model === "string" ? data.model : undefined,
        }));
      } catch (error: unknown) {
        warnings.push(`Could not parse ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    // 4. Parse .opencode/ config
    const opencodePath = path.join(rootDir, ".opencode", "config.json");
    const opencodeConfig = safeReadFile(opencodePath);
    if (opencodeConfig) {
      configFiles.push({ path: opencodePath, content: opencodeConfig, framework: "codex" });
      try {
        const config = JSON.parse(opencodeConfig) as Record<string, unknown>;
        if (!agents.some((a) => a.name === "codex-project")) {
          agents.push(createAgent({
            name: "opencode-project",
            framework: "codex",
            description: "OpenCode project configuration",
            source_file: opencodePath,
            model: typeof config.model === "string" ? config.model : undefined,
          }));
        }
      } catch {
        warnings.push(`Invalid JSON in ${opencodePath}`);
      }
    }

    // 5. Collect .opencode/ instructions, agents, commands
    for (const subdir of ["instructions", "agents", "commands", "prompts"]) {
      const dir = path.join(rootDir, ".opencode", subdir);
      for (const file of safeListDir(dir, [".md", ".txt"])) {
        const filePath = path.join(dir, file);
        const content = safeReadFile(filePath);
        if (content) {
          configFiles.push({ path: filePath, content, framework: "codex" });
        }
      }
    }

    // Default agent
    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(createAgent({
        name: "codex-default",
        framework: "codex",
        description: "Default Codex/OpenCode configuration",
        source_file: configFiles[0]?.path,
      }));
    }

    return { agents, config_files: configFiles, warnings };
  }
}
