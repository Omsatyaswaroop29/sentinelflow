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

  // ─── Agent-discovery layout tests ────────────────────────────────
  //
  // These tests reproduce the three repo shapes that broke discovery:
  //
  //  Layout A ("furai"): flat agents/ dir at root, no .claude/ or CLAUDE.md.
  //    agents/actix-expert.md
  //    agents/bash-expert.md
  //    README.md
  //
  //  Layout B ("rshah"): category subdirs at root, no agents/ dir.
  //    data-ai/ml-engineer.md
  //    security/auditor.md
  //    CLAUDE.md   ← root marker exists
  //
  //  Layout C ("wshobson"): agents nested under plugins/*/agents/,
  //                         alongside SKILL.md / README.md noise.
  //    plugins/ui-design/agents/ui-designer.md
  //    plugins/ui-design/skills/responsive-design/SKILL.md  ← must NOT be an agent
  //    plugins/ui-design/README.md                           ← must NOT be an agent
  //    .claude/settings.json

  describe("agent discovery — layout A: flat agents/ at root (furai-style)", () => {
    beforeEach(() => {
      // Simulate a repo that IS a collection: no .claude/, no CLAUDE.md,
      // just agents/ with flat .md files.
      fs.mkdirSync(path.join(tmpDir, "agents"));
      fs.writeFileSync(
        path.join(tmpDir, "agents", "actix-expert.md"),
        `---\nname: actix-expert\ndescription: Actix web framework expert\n---\nSystem prompt.`
      );
      fs.writeFileSync(
        path.join(tmpDir, "agents", "bash-expert.md"),
        `---\nname: bash-expert\ndescription: Bash scripting expert\ntools: Bash\n---\nSystem prompt.`
      );
      fs.writeFileSync(
        path.join(tmpDir, "agents", "python-expert.md"),
        `---\nname: python-expert\ndescription: Python expert\n---\nSystem prompt.`
      );
      // README.md in agents/ root — must NOT become an agent.
      fs.writeFileSync(path.join(tmpDir, "agents", "README.md"), "# README");
      fs.writeFileSync(path.join(tmpDir, "README.md"), "# Repo readme");
    });

    it("detects the repo as a Claude Code project", async () => {
      expect(await parser.detect(tmpDir)).toBe(true);
    });

    it("discovers all three agent files", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name);
      expect(names).toContain("actix-expert");
      expect(names).toContain("bash-expert");
      expect(names).toContain("python-expert");
    });

    it("does NOT ingest README.md as an agent", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name);
      // README would show up as name 'README' or 'readme' if ingested.
      expect(names.map((n) => n.toLowerCase())).not.toContain("readme");
    });

    it("finds at least 3 agents (the three expert files)", async () => {
      const result = await parser.parse(tmpDir);
      expect(result.agents.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("agent discovery — layout B: category subdirs at root (rshah-style)", () => {
    beforeEach(() => {
      // CLAUDE.md exists (root marker), but agents live in category subdirs.
      fs.writeFileSync(path.join(tmpDir, "CLAUDE.md"), "# Project");
      fs.mkdirSync(path.join(tmpDir, "data-ai"));
      fs.writeFileSync(
        path.join(tmpDir, "data-ai", "ml-engineer.md"),
        `---\nname: ml-engineer\ndescription: ML engineer\n---\nPrompt.`
      );
      fs.writeFileSync(
        path.join(tmpDir, "data-ai", "data-scientist.md"),
        `---\nname: data-scientist\ndescription: Data scientist\n---\nPrompt.`
      );
      fs.mkdirSync(path.join(tmpDir, "security"));
      fs.writeFileSync(
        path.join(tmpDir, "security", "security-auditor.md"),
        `---\nname: security-auditor\ndescription: Security audit specialist\n---\nPrompt.`
      );
      // CONTRIBUTING.md in a subdir — must NOT be an agent.
      fs.writeFileSync(
        path.join(tmpDir, "data-ai", "CONTRIBUTING.md"),
        "# Contributing"
      );
    });

    it("discovers agents from category subdirectories", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name);
      expect(names).toContain("ml-engineer");
      expect(names).toContain("data-scientist");
      expect(names).toContain("security-auditor");
    });

    it("does NOT ingest CONTRIBUTING.md as an agent", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name.toLowerCase());
      expect(names).not.toContain("contributing");
    });

    it("finds at least 3 agents", async () => {
      const result = await parser.parse(tmpDir);
      expect(result.agents.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("agent discovery — layout C: nested plugins/*/agents/ (wshobson-style)", () => {
    beforeEach(() => {
      // .claude/ exists, agents are nested under plugins.
      fs.mkdirSync(path.join(tmpDir, ".claude"), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, ".claude", "settings.json"),
        JSON.stringify({ allowedTools: ["Read"] })
      );
      // Real agents
      fs.mkdirSync(
        path.join(tmpDir, "plugins", "ui-design", "agents"),
        { recursive: true }
      );
      fs.writeFileSync(
        path.join(tmpDir, "plugins", "ui-design", "agents", "ui-designer.md"),
        `---\nname: ui-designer\ndescription: UI design specialist\n---\nPrompt.`
      );
      fs.writeFileSync(
        path.join(tmpDir, "plugins", "ui-design", "agents", "accessibility-expert.md"),
        `---\nname: accessibility-expert\ndescription: Accessibility expert\n---\nPrompt.`
      );
      // SKILL.md — must NOT be an agent.
      fs.mkdirSync(
        path.join(tmpDir, "plugins", "ui-design", "skills", "responsive-design"),
        { recursive: true }
      );
      fs.writeFileSync(
        path.join(
          tmpDir, "plugins", "ui-design", "skills", "responsive-design", "SKILL.md"
        ),
        "# Skill instructions"
      );
      // README.md in plugin dir — must NOT be an agent.
      fs.writeFileSync(
        path.join(tmpDir, "plugins", "ui-design", "README.md"),
        "# UI design plugin"
      );
    });

    it("discovers agents from plugins/*/agents/", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name);
      expect(names).toContain("ui-designer");
      expect(names).toContain("accessibility-expert");
    });

    it("does NOT ingest SKILL.md as an agent", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name.toLowerCase());
      expect(names).not.toContain("skill");
    });

    it("does NOT ingest README.md as an agent", async () => {
      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name.toLowerCase());
      expect(names).not.toContain("readme");
    });

    it("finds at least 2 agents (the two real agent files)", async () => {
      const result = await parser.parse(tmpDir);
      // settings.json creates claude-code-project, plus the two nested agents.
      expect(result.agents.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("isAgentFile deny list", () => {
    // Verifies the deny list directly without needing full parse.
    // Access via the parser's parse() and checking what doesn't show up.
    it("does not create agents from canonical non-agent filenames", async () => {
      fs.mkdirSync(path.join(tmpDir, "agents"));
      // Plant known non-agent filenames alongside a real agent.
      const NON_AGENTS = [
        "README.md", "ARCHITECTURE.md", "CONTRIBUTING.md",
        "CHANGELOG.md", "SKILL.md",
      ];
      for (const f of NON_AGENTS) {
        fs.writeFileSync(path.join(tmpDir, "agents", f), `# ${f}`);
      }
      fs.writeFileSync(
        path.join(tmpDir, "agents", "real-agent.md"),
        `---\nname: real-agent\ndescription: A real agent\n---\nPrompt.`
      );

      const result = await parser.parse(tmpDir);
      const names = result.agents.map((a) => a.name.toLowerCase());

      // Only real-agent should appear.
      expect(names).toContain("real-agent");
      for (const f of NON_AGENTS) {
        expect(names).not.toContain(f.replace(".md", "").toLowerCase());
      }
    });
  });
});
