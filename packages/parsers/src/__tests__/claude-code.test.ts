import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ClaudeCodeParser } from "../claude-code";

describe("ClaudeCodeParser", () => {
  let parser: ClaudeCodeParser;
  let tmpDir: string;

  beforeEach(() => {
    parser = new ClaudeCodeParser();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-parser-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("detect", () => {
    it("detects .claude directory", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      expect(await parser.detect(tmpDir)).toBe(true);
    });

    it("detects CLAUDE.md file", async () => {
      fs.writeFileSync(path.join(tmpDir, "CLAUDE.md"), "# Project");
      expect(await parser.detect(tmpDir)).toBe(true);
    });

    it("detects AGENTS.md file", async () => {
      fs.writeFileSync(path.join(tmpDir, "AGENTS.md"), "# Agents");
      expect(await parser.detect(tmpDir)).toBe(true);
    });

    it("returns false for empty directory", async () => {
      expect(await parser.detect(tmpDir)).toBe(false);
    });
  });

  describe("parse settings.json", () => {
    it("extracts tools from allowedTools", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        JSON.stringify({
          allowedTools: ["Read", "Write", "Bash"],
          blockedTools: ["dangerous-tool"],
        })
      );

      const result = await parser.parse(tmpDir);

      expect(result.agents).toHaveLength(1);
      const agent = result.agents[0]!;
      expect(agent.name).toBe("claude-code-project");
      expect(agent.tools).toHaveLength(3);
      expect(agent.allowed_tools).toEqual(["Read", "Write", "Bash"]);
      expect(agent.blocked_tools).toEqual(["dangerous-tool"]);
    });

    it("extracts MCP servers", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        JSON.stringify({
          allowedTools: [],
          mcpServers: {
            github: { url: "https://github.com", tools: ["create_issue"] },
            db: { url: "postgres://localhost" },
          },
        })
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents[0]!;

      expect(agent.mcp_servers).toHaveLength(2);
      expect(agent.mcp_servers![0]!.name).toBe("github");
      expect(agent.mcp_servers![0]!.tools_exposed).toEqual(["create_issue"]);
    });

    it("handles invalid JSON gracefully", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        "{ invalid json }"
      );

      const result = await parser.parse(tmpDir);

      // Should still return something (default agent from other config files)
      expect(result.warnings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("parse agent markdown files", () => {
    it("parses YAML frontmatter with array tools", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "agents", "reviewer.md"),
        `---
name: code-reviewer
description: Reviews code for quality
model: sonnet
tools: [Read, Grep, Glob]
---

Review instructions here.`
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents.find((a) => a.name === "code-reviewer");

      expect(agent).toBeDefined();
      expect(agent!.description).toBe("Reviews code for quality");
      expect(agent!.model).toBe("sonnet");
      expect(agent!.tools).toHaveLength(3);
      expect(agent!.swarm_role).toBe("reviewer");
    });

    it("parses comma-separated tools string", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "agents", "planner.md"),
        `---
name: planner
description: Creates implementation plans and orchestrates agents
tools: Read, Grep, Glob, Bash
---

Planning instructions.`
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents.find((a) => a.name === "planner");

      expect(agent).toBeDefined();
      expect(agent!.tools).toHaveLength(4);
      expect(agent!.swarm_role).toBe("orchestrator");
    });

    it("uses filename when no name in frontmatter", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "agents", "my-special-agent.md"),
        `---
description: An agent without a name field
---

Instructions.`
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents.find((a) => a.name === "my-special-agent");

      expect(agent).toBeDefined();
    });

    it("handles files with no frontmatter", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "agents", "simple-agent.md"),
        "Just plain text with no frontmatter."
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents.find((a) => a.name === "simple-agent");

      expect(agent).toBeDefined();
      expect(agent!.description).toContain("Just plain text");
    });

    it("handles empty files", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, "agents", "empty.md"), "");

      const result = await parser.parse(tmpDir);

      // Empty file should produce a warning, not an agent
      expect(result.warnings.some((w) => w.includes("Empty file"))).toBe(true);
    });
  });

  describe("parse .claude/agents/ directory", () => {
    it("discovers agents from .claude/agents/", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude", "agents"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "agents", "security-auditor.md"),
        `---
name: security-auditor
description: Audits code for security vulnerabilities
model: opus
tools: Read, Grep, Glob, Bash
---

Security audit instructions.`
      );

      const result = await parser.parse(tmpDir);
      const agent = result.agents.find((a) => a.name === "security-auditor");

      expect(agent).toBeDefined();
      expect(agent!.swarm_role).toBe("reviewer"); // "audit" triggers reviewer
    });
  });

  describe("tool classification", () => {
    it("classifies Bash as high risk", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        JSON.stringify({ allowedTools: ["Bash"] })
      );

      const result = await parser.parse(tmpDir);
      const bashTool = result.agents[0]?.tools.find((t) => t.name === "Bash");

      expect(bashTool?.type).toBe("bash");
      expect(bashTool?.risk_level).toBe("high");
    });

    it("classifies Read as low risk", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        JSON.stringify({ allowedTools: ["Read"] })
      );

      const result = await parser.parse(tmpDir);
      const readTool = result.agents[0]?.tools.find((t) => t.name === "Read");

      expect(readTool?.type).toBe("file_read");
      expect(readTool?.risk_level).toBe("low");
    });
  });

  describe("config file collection", () => {
    it("collects CLAUDE.md as a config file", async () => {
      fs.writeFileSync(path.join(tmpDir, "CLAUDE.md"), "# Project guidance");

      const result = await parser.parse(tmpDir);

      expect(
        result.config_files.some((f) => f.path.endsWith("CLAUDE.md"))
      ).toBe(true);
    });

    it("collects hooks/hooks.json as a config file", async () => {
      fs.mkdirSync(path.join(tmpDir, "hooks"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "hooks", "hooks.json"),
        JSON.stringify({ hooks: {} })
      );

      const result = await parser.parse(tmpDir);

      expect(
        result.config_files.some((f) => f.path.includes("hooks.json"))
      ).toBe(true);
    });

    it("collects .claude/commands/*.md as config files", async () => {
      fs.mkdirSync(path.join(tmpDir, ".claude", "commands"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "commands", "deploy.md"),
        "Deploy instructions"
      );

      const result = await parser.parse(tmpDir);

      expect(
        result.config_files.some((f) => f.path.includes("deploy.md"))
      ).toBe(true);
    });
  });

  describe("default agent creation", () => {
    it("creates a default agent when only CLAUDE.md exists", async () => {
      fs.writeFileSync(path.join(tmpDir, "CLAUDE.md"), "# My project");

      const result = await parser.parse(tmpDir);

      expect(result.agents).toHaveLength(1);
      expect(result.agents[0]!.name).toBe("claude-code-default");
    });
  });
});
