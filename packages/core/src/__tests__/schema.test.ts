import { describe, it, expect } from "vitest";
import { createAgent, type SentinelFlowAgent } from "../schema/agent";
import { createScanReport, type Finding } from "../schema/finding";

describe("createAgent", () => {
  it("creates an agent with required fields and sensible defaults", () => {
    const agent = createAgent({
      name: "test-agent",
      framework: "claude-code",
    });

    expect(agent.name).toBe("test-agent");
    expect(agent.framework).toBe("claude-code");
    expect(agent.id).toMatch(/^sf-/);
    expect(agent.description).toBe("");
    expect(agent.tools).toEqual([]);
    expect(agent.data_sources).toEqual([]);
    expect(agent.swarm_role).toBe("standalone");
    expect(agent.topology).toBe("standalone");
    expect(agent.governance.status).toBe("discovered");
    expect(agent.created_at).toBeTruthy();
    expect(agent.updated_at).toBeTruthy();
  });

  it("preserves all provided fields", () => {
    const agent = createAgent({
      name: "custom-agent",
      framework: "langchain",
      description: "A custom agent for testing",
      owner: "om",
      team: "ml-team",
      model: "claude-sonnet-4-6",
      swarm_role: "orchestrator",
      tools: [{ name: "Bash", type: "bash", risk_level: "high" }],
      governance: {
        status: "approved",
        risk_level: "low",
      },
    });

    expect(agent.name).toBe("custom-agent");
    expect(agent.framework).toBe("langchain");
    expect(agent.description).toBe("A custom agent for testing");
    expect(agent.owner).toBe("om");
    expect(agent.team).toBe("ml-team");
    expect(agent.model).toBe("claude-sonnet-4-6");
    expect(agent.swarm_role).toBe("orchestrator");
    expect(agent.tools).toHaveLength(1);
    expect(agent.tools[0]?.name).toBe("Bash");
    expect(agent.governance.status).toBe("approved");
    expect(agent.governance.risk_level).toBe("low");
  });

  it("generates unique IDs for each agent", () => {
    const agent1 = createAgent({ name: "a", framework: "claude-code" });
    const agent2 = createAgent({ name: "b", framework: "claude-code" });

    expect(agent1.id).not.toBe(agent2.id);
  });

  it("uses provided ID when given", () => {
    const agent = createAgent({
      id: "custom-id-123",
      name: "test",
      framework: "claude-code",
    });

    expect(agent.id).toBe("custom-id-123");
  });
});

describe("createScanReport", () => {
  const sampleFindings: Finding[] = [
    {
      id: "f1",
      rule_id: "SF-SEC-001",
      rule_name: "Test Rule",
      severity: "critical",
      category: "secrets",
      title: "Secret found",
      description: "A secret was found",
      recommendation: "Remove it",
      first_detected: new Date().toISOString(),
      status: "open",
    },
    {
      id: "f2",
      rule_id: "SF-PERM-001",
      rule_name: "Permissions Rule",
      severity: "high",
      category: "permissions",
      title: "Overprivileged",
      description: "Too many permissions",
      recommendation: "Restrict access",
      first_detected: new Date().toISOString(),
      status: "open",
    },
    {
      id: "f3",
      rule_id: "SF-ID-002",
      rule_name: "Identity Rule",
      severity: "low",
      category: "identity",
      title: "No description",
      description: "Agent lacks description",
      recommendation: "Add one",
      first_detected: new Date().toISOString(),
      status: "open",
    },
  ];

  it("creates a report with correct summary counts", () => {
    const report = createScanReport("/test", sampleFindings, ["Claude Code"], 3, 100);

    expect(report.summary.critical).toBe(1);
    expect(report.summary.high).toBe(1);
    expect(report.summary.medium).toBe(0);
    expect(report.summary.low).toBe(1);
    expect(report.summary.info).toBe(0);
    expect(report.summary.total).toBe(3);
  });

  it("includes metadata in the report", () => {
    const report = createScanReport("/test", [], ["Claude Code", "LangChain"], 5, 250);

    expect(report.root_dir).toBe("/test");
    expect(report.frameworks_detected).toEqual(["Claude Code", "LangChain"]);
    expect(report.agents_discovered).toBe(5);
    expect(report.duration_ms).toBe(250);
    expect(report.timestamp).toBeTruthy();
    expect(report.id).toMatch(/^scan-/);
  });

  it("handles empty findings correctly", () => {
    const report = createScanReport("/test", [], [], 0, 50);

    expect(report.summary.total).toBe(0);
    expect(report.findings).toEqual([]);
  });
});
