/**
 * @module @sentinelflow/parsers/langchain
 *
 * Parses LangChain / LangGraph agent configurations from:
 *   1. pyproject.toml / requirements.txt — dependency detection
 *   2. Python files — agent class definitions, tool bindings, chain configs
 *   3. langgraph.json — LangGraph deployment config
 *   4. .env files — environment variable references
 *
 * LangChain agents are defined in Python code rather than YAML/Markdown,
 * so this parser uses pattern matching on Python source files to extract
 * agent definitions, tool bindings, model selections, and configurations.
 */

import * as fs from "fs";
import * as path from "path";
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

function findPythonFiles(dir: string, maxDepth = 3): string[] {
  const results: string[] = [];
  function walk(currentDir: string, depth: number): void {
    if (depth > maxDepth) return;
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory() && !["node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", "dist", "build"].includes(entry.name)) {
          walk(fullPath, depth + 1);
        } else if (entry.isFile() && entry.name.endsWith(".py")) {
          results.push(fullPath);
        }
      }
    } catch {
      // Skip unreadable directories
    }
  }
  walk(dir, 0);
  return results;
}

// Patterns that indicate LangChain agent definitions
const AGENT_PATTERNS = [
  { pattern: /(?:create_react_agent|create_openai_functions_agent|create_tool_calling_agent|create_structured_chat_agent)\s*\(/g, type: "agent_factory" },
  { pattern: /AgentExecutor\s*(?:\(|\.from_agent_and_tools)/g, type: "agent_executor" },
  { pattern: /class\s+(\w+).*(?:BaseTool|StructuredTool|Tool)/g, type: "custom_tool" },
  { pattern: /StateGraph\s*\(/g, type: "langgraph" },
  { pattern: /CompiledGraph|MessageGraph/g, type: "langgraph" },
];

const TOOL_PATTERNS = [
  { pattern: /(?:PythonREPLTool|ShellTool|BashTool)\s*\(/g, name: "code_execution", type: "bash" as const, risk: "high" as const },
  { pattern: /(?:SQLDatabaseToolkit|QuerySQLDataBaseTool)\s*\(/g, name: "database", type: "database" as const, risk: "high" as const },
  { pattern: /(?:RequestsGetTool|RequestsPostTool|RequestsPutTool)\s*\(/g, name: "http_requests", type: "web_fetch" as const, risk: "medium" as const },
  { pattern: /(?:FileSearchTool|DirectoryReadTool|ReadFileTool)\s*\(/g, name: "file_read", type: "file_read" as const, risk: "low" as const },
  { pattern: /(?:WriteFileTool|FileManagementToolkit)\s*\(/g, name: "file_write", type: "file_write" as const, risk: "medium" as const },
  { pattern: /(?:DuckDuckGoSearchRun|GoogleSearchAPIWrapper|TavilySearchResults|BraveSearchRun)\s*\(/g, name: "web_search", type: "web_search" as const, risk: "low" as const },
  { pattern: /(?:GmailToolkit|SlackToolkit|JiraToolkit)\s*\(/g, name: "saas_integration", type: "api_call" as const, risk: "medium" as const },
];

const MODEL_PATTERNS = [
  { pattern: /ChatOpenAI\s*\([^)]*model\s*=\s*["']([^"']+)["']/g, provider: "openai" },
  { pattern: /ChatAnthropic\s*\([^)]*model\s*=\s*["']([^"']+)["']/g, provider: "anthropic" },
  { pattern: /ChatGoogleGenerativeAI\s*\([^)]*model\s*=\s*["']([^"']+)["']/g, provider: "google" },
  { pattern: /AzureChatOpenAI\s*\(/g, provider: "azure_openai" },
  { pattern: /ChatBedrock\s*\(/g, provider: "aws_bedrock" },
];

export class LangChainParser implements FrameworkParser {
  readonly framework = "langchain" as const;
  readonly displayName = "LangChain / LangGraph";
  readonly markers = ["langgraph.json"];

  async detect(rootDir: string): Promise<boolean> {
    // Check for LangChain in dependency files
    const pyprojectPath = path.join(rootDir, "pyproject.toml");
    const requirementsPath = path.join(rootDir, "requirements.txt");
    const langgraphPath = path.join(rootDir, "langgraph.json");

    if (fs.existsSync(langgraphPath)) return true;

    for (const depFile of [pyprojectPath, requirementsPath]) {
      const content = safeReadFile(depFile);
      if (content && (content.includes("langchain") || content.includes("langgraph"))) {
        return true;
      }
    }

    // Check for Poetry lock file
    const poetryLock = safeReadFile(path.join(rootDir, "poetry.lock"));
    if (poetryLock && poetryLock.includes("langchain")) return true;

    return false;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // 1. Collect dependency files
    for (const depFile of ["pyproject.toml", "requirements.txt", "setup.py", "poetry.lock"]) {
      const filePath = path.join(rootDir, depFile);
      const content = safeReadFile(filePath);
      if (content && (content.includes("langchain") || content.includes("langgraph"))) {
        configFiles.push({ path: filePath, content, framework: "langchain" });
      }
    }

    // 2. Collect langgraph.json
    const lgPath = path.join(rootDir, "langgraph.json");
    const lgContent = safeReadFile(lgPath);
    if (lgContent) {
      configFiles.push({ path: lgPath, content: lgContent, framework: "langchain" });
    }

    // 3. Scan Python files for agent definitions
    const pyFiles = findPythonFiles(rootDir);
    let agentCount = 0;

    for (const pyFile of pyFiles) {
      const content = safeReadFile(pyFile);
      if (!content) continue;

      // Skip files that don't import langchain/langgraph
      if (!content.includes("langchain") && !content.includes("langgraph")) continue;

      configFiles.push({ path: pyFile, content, framework: "langchain" });

      // Detect agent definitions
      let hasAgent = false;
      for (const { pattern, type } of AGENT_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(content)) {
          hasAgent = true;
          break;
        }
      }

      if (!hasAgent) continue;

      // Extract tools used in this file
      const tools: AgentTool[] = [];
      for (const { pattern, name, type, risk } of TOOL_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(content)) {
          tools.push({ name, type, risk_level: risk });
        }
      }

      // Extract model
      let model: string | undefined;
      for (const { pattern, provider } of MODEL_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(content);
        if (match) {
          model = match[1] ? `${provider}/${match[1]}` : provider;
          break;
        }
      }

      // Extract agent name from filename or class name
      const classMatch = content.match(/class\s+(\w+Agent)\b/);
      const agentName = classMatch?.[1]
        ?? path.basename(pyFile, ".py").replace(/_/g, "-");

      const isLangGraph = content.includes("StateGraph") || content.includes("langgraph");

      agents.push(createAgent({
        name: agentName,
        framework: "langchain",
        description: `${isLangGraph ? "LangGraph" : "LangChain"} agent defined in ${path.relative(rootDir, pyFile)}`,
        source_file: pyFile,
        model,
        tools,
        swarm_role: isLangGraph ? "worker" : "standalone",
      }));
      agentCount++;
    }

    // 4. Collect .env for governance scanning (secrets detection)
    const envPath = path.join(rootDir, ".env");
    const envContent = safeReadFile(envPath);
    if (envContent) {
      configFiles.push({ path: envPath, content: envContent, framework: "langchain" });
    }

    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(createAgent({
        name: "langchain-project",
        framework: "langchain",
        description: "LangChain/LangGraph project detected from dependencies",
        source_file: configFiles[0]?.path,
      }));
    }

    return { agents, config_files: configFiles, warnings };
  }
}
