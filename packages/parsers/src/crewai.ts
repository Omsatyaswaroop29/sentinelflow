/**
 * @module @sentinelflow/parsers/crewai
 *
 * Parses CrewAI agent configurations from:
 *   1. crew.yaml / agents.yaml — YAML agent definitions
 *   2. tasks.yaml — task definitions with agent assignments
 *   3. Python files — Crew class definitions with @agent/@task decorators
 *   4. config/ directory — alternative config location
 *
 * CrewAI uses a YAML-first configuration model where agents define
 * role, goal, backstory, tools, and delegation permissions. The
 * allow_delegation flag is critical for governance — it defaults
 * to True, enabling unrestricted inter-agent delegation.
 */

import * as fs from "fs";
import * as path from "path";
import {
  createAgent,
  type SentinelFlowAgent,
  type AgentTool,
  type SwarmRole,
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

function findPythonFiles(dir: string, maxDepth = 3): string[] {
  const results: string[] = [];
  function walk(currentDir: string, depth: number): void {
    if (depth > maxDepth) return;
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory() && !["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"].includes(entry.name)) {
          walk(fullPath, depth + 1);
        } else if (entry.isFile() && entry.name.endsWith(".py")) {
          results.push(fullPath);
        }
      }
    } catch { /* skip */ }
  }
  walk(dir, 0);
  return results;
}

// Simple YAML block parser for CrewAI agent definitions
// Handles the format: agent_name:\n  role: ...\n  goal: ...\n  tools: [...]
function parseCrewYAML(content: string): Array<Record<string, string | string[] | boolean>> {
  const agents: Array<Record<string, string | string[] | boolean>> = [];
  const blocks = content.split(/\n(?=\w)/);

  for (const block of blocks) {
    const lines = block.split("\n");
    const headerLine = lines[0];
    if (!headerLine || !headerLine.trim().endsWith(":")) continue;

    const agentKey = headerLine.trim().replace(":", "");
    const fields: Record<string, string | string[] | boolean> = { _key: agentKey };

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const match = line.match(/^\s+(\w[\w_]*):\s*(.*)/);
      if (match && match[1] && match[2] !== undefined) {
        const key = match[1];
        let value = match[2].trim();
        // Handle boolean
        if (value === "true" || value === "True") {
          fields[key] = true;
        } else if (value === "false" || value === "False") {
          fields[key] = false;
        }
        // Handle inline array: [tool1, tool2]
        else if (value.startsWith("[") && value.endsWith("]")) {
          fields[key] = value.slice(1, -1).split(",").map((s) => s.trim().replace(/["']/g, ""));
        }
        // Handle quoted string
        else {
          fields[key] = value.replace(/^["']|["']$/g, "");
        }
      }
    }

    if (Object.keys(fields).length > 1) {
      agents.push(fields);
    }
  }

  return agents;
}

const CREWAI_TOOL_MAP: Record<string, { type: AgentTool["type"]; risk: AgentTool["risk_level"] }> = {
  "SerperDevTool": { type: "web_search", risk: "low" },
  "ScrapeWebsiteTool": { type: "web_fetch", risk: "medium" },
  "WebsiteSearchTool": { type: "web_search", risk: "low" },
  "FileReadTool": { type: "file_read", risk: "low" },
  "FileWriterTool": { type: "file_write", risk: "medium" },
  "DirectoryReadTool": { type: "file_read", risk: "low" },
  "DirectorySearchTool": { type: "file_read", risk: "low" },
  "CodeInterpreterTool": { type: "code_execution", risk: "high" },
  "CodeDocsSearchTool": { type: "web_search", risk: "low" },
  "GithubSearchTool": { type: "api_call", risk: "low" },
  "PGSearchTool": { type: "database", risk: "medium" },
  "MySQLSearchTool": { type: "database", risk: "medium" },
};

export class CrewAIParser implements FrameworkParser {
  readonly framework = "crewai" as const;
  readonly displayName = "CrewAI";
  readonly markers = ["crew.yaml", "agents.yaml"];

  async detect(rootDir: string): Promise<boolean> {
    // Check for YAML configs
    const yamlFiles = ["crew.yaml", "crew.yml", "agents.yaml", "agents.yml"];
    for (const f of yamlFiles) {
      if (fs.existsSync(path.join(rootDir, f))) return true;
      if (fs.existsSync(path.join(rootDir, "config", f))) return true;
    }

    // Check for CrewAI in dependencies
    for (const depFile of ["pyproject.toml", "requirements.txt"]) {
      const content = safeReadFile(path.join(rootDir, depFile));
      if (content && content.includes("crewai")) return true;
    }

    return false;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // 1. Parse YAML agent definitions
    const yamlLocations = [
      path.join(rootDir, "crew.yaml"),
      path.join(rootDir, "crew.yml"),
      path.join(rootDir, "agents.yaml"),
      path.join(rootDir, "agents.yml"),
      path.join(rootDir, "config", "agents.yaml"),
      path.join(rootDir, "config", "agents.yml"),
    ];

    for (const yamlPath of yamlLocations) {
      const content = safeReadFile(yamlPath);
      if (!content) continue;
      configFiles.push({ path: yamlPath, content, framework: "crewai" });

      const parsedAgents = parseCrewYAML(content);
      for (const agentDef of parsedAgents) {
        const name = String(agentDef._key ?? "unnamed");
        const role = typeof agentDef.role === "string" ? agentDef.role : "";
        const goal = typeof agentDef.goal === "string" ? agentDef.goal : "";
        const backstory = typeof agentDef.backstory === "string" ? agentDef.backstory : "";

        // Parse tools
        const toolNames = Array.isArray(agentDef.tools)
          ? agentDef.tools
          : typeof agentDef.tools === "string"
            ? [agentDef.tools]
            : [];

        const tools: AgentTool[] = toolNames.map((t) => {
          const mapped = CREWAI_TOOL_MAP[t];
          return mapped
            ? { name: t, type: mapped.type, risk_level: mapped.risk }
            : { name: t, type: "custom" as const, risk_level: "low" as const };
        });

        const allowDelegation = agentDef.allow_delegation;
        const delegateTo = allowDelegation === true || allowDelegation === undefined
          ? parsedAgents.filter((a) => a._key !== name).map((a) => String(a._key))
          : undefined;

        const swarmRole: SwarmRole = role.toLowerCase().includes("manager") ||
          role.toLowerCase().includes("lead") ||
          role.toLowerCase().includes("coordinator")
          ? "orchestrator"
          : "worker";

        agents.push(createAgent({
          name,
          framework: "crewai",
          description: `${role}${goal ? ` — ${goal}` : ""}`,
          source_file: yamlPath,
          tools,
          swarm_role: swarmRole,
          delegates_to: delegateTo && delegateTo.length > 0 ? delegateTo : undefined,
        }));
      }
    }

    // 2. Parse tasks.yaml
    for (const tasksFile of ["tasks.yaml", "tasks.yml", "config/tasks.yaml"]) {
      const content = safeReadFile(path.join(rootDir, tasksFile));
      if (content) {
        configFiles.push({ path: path.join(rootDir, tasksFile), content, framework: "crewai" });
      }
    }

    // 3. Scan Python files for @agent, @task, @crew decorators
    const pyFiles = findPythonFiles(rootDir);
    for (const pyFile of pyFiles) {
      const content = safeReadFile(pyFile);
      if (!content || !content.includes("crewai")) continue;
      configFiles.push({ path: pyFile, content, framework: "crewai" });

      // Extract agents from @agent decorator pattern
      const agentDecorators = content.matchAll(/@agent\s*\n\s*def\s+(\w+)/g);
      for (const match of agentDecorators) {
        const name = match[1];
        if (name && !agents.some((a) => a.name === name)) {
          agents.push(createAgent({
            name,
            framework: "crewai",
            description: `CrewAI agent defined in ${path.relative(rootDir, pyFile)}`,
            source_file: pyFile,
            swarm_role: "worker",
          }));
        }
      }
    }

    // 4. Collect dependency files
    for (const depFile of ["pyproject.toml", "requirements.txt"]) {
      const filePath = path.join(rootDir, depFile);
      const content = safeReadFile(filePath);
      if (content && content.includes("crewai")) {
        configFiles.push({ path: filePath, content, framework: "crewai" });
      }
    }

    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(createAgent({
        name: "crewai-project",
        framework: "crewai",
        description: "CrewAI project detected from configuration",
        source_file: configFiles[0]?.path,
      }));
    }

    return { agents, config_files: configFiles, warnings };
  }
}
