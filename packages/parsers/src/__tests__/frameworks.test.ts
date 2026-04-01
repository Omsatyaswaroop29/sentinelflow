import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { CursorParser } from "../cursor";
import { CodexParser } from "../codex";
import { LangChainParser } from "../langchain";
import { CrewAIParser } from "../crewai";
import { KiroParser } from "../kiro";
import { detectFrameworks } from "../auto-detect";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-parser-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ─── Cursor Parser ──────────────────────────────────────────────

describe("CursorParser", () => {
  const parser = new CursorParser();

  it("detects .cursor directory", async () => {
    fs.mkdirSync(path.join(tmpDir, ".cursor"), { recursive: true });
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects .cursorrules file", async () => {
    fs.writeFileSync(path.join(tmpDir, ".cursorrules"), "Always use TypeScript");
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("returns false for empty directory", async () => {
    expect(await parser.detect(tmpDir)).toBe(false);
  });

  it("parses .cursorrules into an agent", async () => {
    fs.writeFileSync(path.join(tmpDir, ".cursorrules"), "Use functional components. Prefer hooks over classes.");
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
    expect(result.agents.some((a) => a.framework === "cursor")).toBe(true);
  });

  it("parses .cursor/rules/*.mdc files", async () => {
    fs.mkdirSync(path.join(tmpDir, ".cursor", "rules"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, ".cursor", "rules", "typescript.mdc"),
      "---\ndescription: TypeScript coding standards\nglobs: \"**/*.ts\"\n---\nAlways use strict types."
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
  });

  it("parses .cursor/mcp.json", async () => {
    fs.mkdirSync(path.join(tmpDir, ".cursor"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { github: { url: "https://github.com" } } })
    );
    const result = await parser.parse(tmpDir);
    const agentWithMcp = result.agents.find((a) => a.mcp_servers && a.mcp_servers.length > 0);
    expect(agentWithMcp).toBeDefined();
  });
});

// ─── Codex Parser ───────────────────────────────────────────────

describe("CodexParser", () => {
  const parser = new CodexParser();

  it("detects .codex directory", async () => {
    fs.mkdirSync(path.join(tmpDir, ".codex"), { recursive: true });
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects codex.md file", async () => {
    fs.writeFileSync(path.join(tmpDir, "codex.md"), "# Codex instructions");
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects .opencode directory", async () => {
    fs.mkdirSync(path.join(tmpDir, ".opencode"), { recursive: true });
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects .agents directory", async () => {
    fs.mkdirSync(path.join(tmpDir, ".agents"), { recursive: true });
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("parses .codex/config.toml with full-auto mode", async () => {
    fs.mkdirSync(path.join(tmpDir, ".codex"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, ".codex", "config.toml"),
      'model = "o4-mini"\napproval_mode = "full-auto"\n'
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
    const agent = result.agents[0]!;
    expect(agent.model).toBe("o4-mini");
    expect(agent.tools.some((t) => t.type === "bash")).toBe(true);
  });

  it("parses .agents/*.md files", async () => {
    fs.mkdirSync(path.join(tmpDir, ".agents"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, ".agents", "researcher.md"),
      "---\nname: researcher\ndescription: Researches topics\n---\nYou are a research agent."
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.some((a) => a.name === "researcher")).toBe(true);
  });
});

// ─── LangChain Parser ──────────────────────────────────────────

describe("LangChainParser", () => {
  const parser = new LangChainParser();

  it("detects langchain in pyproject.toml", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["langchain>=0.2.0", "openai"]\n'
    );
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects langchain in requirements.txt", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "langchain==0.2.5\nopenai\n");
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects langgraph.json", async () => {
    fs.writeFileSync(path.join(tmpDir, "langgraph.json"), '{"graphs": {}}');
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("returns false when no langchain deps", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "flask\nrequests\n");
    expect(await parser.detect(tmpDir)).toBe(false);
  });

  it("extracts agents from Python files with langchain imports", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "langchain\n");
    fs.writeFileSync(
      path.join(tmpDir, "agent.py"),
      `from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from langchain_community.tools import ShellTool

llm = ChatOpenAI(model="gpt-4o")
agent = create_react_agent(llm, tools=[ShellTool()])
`
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
    const agent = result.agents.find((a) => a.name === "agent");
    expect(agent).toBeDefined();
    expect(agent!.tools.some((t) => t.type === "bash")).toBe(true);
  });

  it("detects LangGraph StateGraph patterns", async () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "langgraph\n");
    fs.writeFileSync(
      path.join(tmpDir, "graph.py"),
      `from langgraph.graph import StateGraph
graph = StateGraph(AgentState)
`
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── CrewAI Parser ──────────────────────────────────────────────

describe("CrewAIParser", () => {
  const parser = new CrewAIParser();

  it("detects crew.yaml", async () => {
    fs.writeFileSync(path.join(tmpDir, "crew.yaml"), "researcher:\n  role: researcher\n");
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects crewai in pyproject.toml", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "pyproject.toml"),
      '[project]\ndependencies = ["crewai>=0.30.0"]\n'
    );
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("parses agents from crew.yaml", async () => {
    fs.writeFileSync(
      path.join(tmpDir, "crew.yaml"),
      `researcher:
  role: Senior Research Analyst
  goal: Find and analyze information
  tools: [SerperDevTool, ScrapeWebsiteTool]
  allow_delegation: true
writer:
  role: Content Writer
  goal: Write compelling content
  allow_delegation: false
`
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents).toHaveLength(2);

    const researcher = result.agents.find((a) => a.name === "researcher");
    expect(researcher).toBeDefined();
    expect(researcher!.tools).toHaveLength(2);
    expect(researcher!.delegates_to).toBeDefined();
    expect(researcher!.delegates_to!.length).toBeGreaterThan(0);

    const writer = result.agents.find((a) => a.name === "writer");
    expect(writer).toBeDefined();
    expect(writer!.delegates_to).toBeUndefined();
  });

  it("parses agents from config/agents.yaml", async () => {
    fs.mkdirSync(path.join(tmpDir, "config"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, "config", "agents.yaml"),
      "analyzer:\n  role: Data Analyst\n  goal: Analyze datasets\n"
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.some((a) => a.name === "analyzer")).toBe(true);
  });
});

// ─── Kiro Parser ────────────────────────────────────────────────

describe("KiroParser", () => {
  const parser = new KiroParser();

  it("detects .kiro directory", async () => {
    fs.mkdirSync(path.join(tmpDir, ".kiro"), { recursive: true });
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("detects kiro.md", async () => {
    fs.writeFileSync(path.join(tmpDir, "kiro.md"), "# Kiro instructions");
    expect(await parser.detect(tmpDir)).toBe(true);
  });

  it("parses steering files", async () => {
    fs.mkdirSync(path.join(tmpDir, ".kiro", "steering"), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, ".kiro", "steering", "coding-standards.md"),
      "---\nname: coding-standards\ndescription: TypeScript coding rules\n---\nUse strict types."
    );
    const result = await parser.parse(tmpDir);
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── Auto-Detection ─────────────────────────────────────────────

describe("detectFrameworks", () => {
  it("detects multiple frameworks in one project", async () => {
    // Project with both Claude Code and Cursor
    fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, ".cursor"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "CLAUDE.md"), "# Project");

    const { detected } = await detectFrameworks(tmpDir);
    expect(detected.length).toBe(2);
    const names = detected.map((p) => p.displayName);
    expect(names).toContain("Claude Code");
    expect(names).toContain("Cursor");
  });

  it("returns empty for vanilla project", async () => {
    fs.writeFileSync(path.join(tmpDir, "index.js"), "console.log('hello')");
    const { detected } = await detectFrameworks(tmpDir);
    expect(detected).toHaveLength(0);
  });

  it("detects all 6 frameworks when all present", async () => {
    fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, ".cursor"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, ".codex"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, ".kiro"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "langchain\ncrewai\n");
    fs.writeFileSync(path.join(tmpDir, "crew.yaml"), "agent:\n  role: test\n");

    const { detected } = await detectFrameworks(tmpDir);
    expect(detected.length).toBe(6);
  });
});
