/**
 * Tests for identity governance and compliance mappings.
 *
 * Priority 9: Identity and delegation awareness
 * Priority 10: Compliance mapping completeness
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  IdentityResolver,
  RoleBasedAccessPolicy,
  EnvironmentPolicy,
} from "../identity";
import {
  RUNTIME_COMPLIANCE_MAPPINGS,
  getControlsForOwaspRisk,
  getControlsForEuArticle,
  getEvidenceSnippet,
  generateComplianceSummary,
} from "../compliance";
import type { AgentEvent } from "@sentinelflow/core";

// ─── Helpers ────────────────────────────────────────────────────────

let counter = 0;
function makeEvent(opts: {
  tool_name?: string;
  input_summary?: string;
  agent_id?: string;
  session_id?: string;
}): AgentEvent {
  counter++;
  return {
    id: `evt-${counter}`,
    timestamp: new Date().toISOString(),
    agent_id: opts.agent_id ?? "test-agent",
    session_id: opts.session_id ?? "session-001",
    type: "tool_call_start",
    tool: opts.tool_name ? {
      name: opts.tool_name,
      input_summary: opts.input_summary ?? "",
      status: "success",
    } : undefined,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  Priority 9: Identity Tests
// ═══════════════════════════════════════════════════════════════════

describe("IdentityResolver", () => {
  it("populates identity context on events", () => {
    const resolver = new IdentityResolver({
      human_owner: "om@company.com",
      team: "platform",
      role: "executor",
      environment: "development",
    });

    const event = makeEvent({ tool_name: "Bash" });
    resolver.onEvent(event);

    expect(event.identity).toBeDefined();
    expect(event.identity!.human_owner).toBe("om@company.com");
    expect(event.identity!.team).toBe("platform");
    expect(event.identity!.role).toBe("executor");
    expect(event.identity!.environment).toBe("development");
    expect(event.identity!.privilege_level).toBe(6); // executor default
  });

  it("resolves per-agent role overrides", () => {
    const resolver = new IdentityResolver({
      human_owner: "om",
      role: "executor",
      agent_roles: { "reader-bot": "reader", "deploy-bot": "deployer" },
    });

    const readerIdentity = resolver.resolveForAgent("reader-bot");
    expect(readerIdentity.role).toBe("reader");
    expect(readerIdentity.privilege_level).toBe(2);

    const deployIdentity = resolver.resolveForAgent("deploy-bot");
    expect(deployIdentity.role).toBe("deployer");
    expect(deployIdentity.privilege_level).toBe(8);

    const defaultIdentity = resolver.resolveForAgent("unknown-bot");
    expect(defaultIdentity.role).toBe("executor");
    expect(defaultIdentity.privilege_level).toBe(6);
  });

  it("supports privilege level overrides", () => {
    const resolver = new IdentityResolver({
      human_owner: "om",
      agent_privileges: { "restricted-bot": 1 },
    });

    const identity = resolver.resolveForAgent("restricted-bot");
    expect(identity.privilege_level).toBe(1);
  });

  it("does not overwrite existing identity context", () => {
    const resolver = new IdentityResolver({ human_owner: "om" });
    const event = makeEvent({});
    event.identity = {
      human_owner: "alice",
      environment: "production",
      role: "admin",
      privilege_level: 10,
    };
    resolver.onEvent(event);
    expect(event.identity.human_owner).toBe("alice"); // Not overwritten
  });
});

describe("RoleBasedAccessPolicy", () => {
  const policy = new RoleBasedAccessPolicy();

  it("blocks reader agent from using Bash", () => {
    const event = makeEvent({ tool_name: "Bash", agent_id: "reader-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "reader", privilege_level: 2 };
    const result = policy.evaluate(event);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("privilege");
    expect(result.reason).toContain("reader");
  });

  it("allows executor agent to use Bash", () => {
    const event = makeEvent({ tool_name: "Bash", agent_id: "exec-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "executor", privilege_level: 6 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("blocks writer agent from using Bash", () => {
    const event = makeEvent({ tool_name: "Bash", agent_id: "writer-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "writer", privilege_level: 4 };
    expect(policy.evaluate(event).decision).toBe("block");
  });

  it("allows writer agent to use Write", () => {
    const event = makeEvent({ tool_name: "Write", agent_id: "writer-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "writer", privilege_level: 4 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("blocks reader agent from using Write", () => {
    const event = makeEvent({ tool_name: "Write", agent_id: "reader-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "reader", privilege_level: 2 };
    expect(policy.evaluate(event).decision).toBe("block");
  });

  it("allows admin agent to use any tool", () => {
    const event = makeEvent({ tool_name: "Bash", agent_id: "admin-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "admin", privilege_level: 10 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("allows Read tool for any role", () => {
    const event = makeEvent({ tool_name: "Read", agent_id: "reader-bot" });
    event.identity = { human_owner: "om", environment: "development", role: "reader", privilege_level: 2 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("includes human_owner in block reason for audit", () => {
    const event = makeEvent({ tool_name: "Bash", agent_id: "reader-bot" });
    event.identity = { human_owner: "alice@company.com", environment: "development", role: "reader", privilege_level: 2 };
    const result = policy.evaluate(event);
    expect(result.reason).toContain("alice@company.com");
  });
});

describe("EnvironmentPolicy", () => {
  const policy = new EnvironmentPolicy();

  it("blocks Bash in production", () => {
    const event = makeEvent({ tool_name: "Bash" });
    event.identity = { human_owner: "om", environment: "production", role: "executor", privilege_level: 6 };
    const result = policy.evaluate(event);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("production");
  });

  it("allows Bash in development", () => {
    const event = makeEvent({ tool_name: "Bash" });
    event.identity = { human_owner: "om", environment: "development", role: "executor", privilege_level: 6 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("blocks Write for external-facing agents", () => {
    const event = makeEvent({ tool_name: "Write" });
    event.identity = { human_owner: "om", environment: "development", role: "writer", privilege_level: 4, external_facing: true };
    const result = policy.evaluate(event);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("external");
  });

  it("allows Read for external-facing agents", () => {
    const event = makeEvent({ tool_name: "Read" });
    event.identity = { human_owner: "om", environment: "development", role: "reader", privilege_level: 2, external_facing: true };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("blocks non-allowed tools in CI", () => {
    const event = makeEvent({ tool_name: "Write" });
    event.identity = { human_owner: "ci", environment: "ci", role: "executor", privilege_level: 6 };
    const result = policy.evaluate(event);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("CI");
  });

  it("allows Bash in CI (needed for test/build)", () => {
    const event = makeEvent({ tool_name: "Bash" });
    event.identity = { human_owner: "ci", environment: "ci", role: "executor", privilege_level: 6 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });

  it("allows Read in CI", () => {
    const event = makeEvent({ tool_name: "Read" });
    event.identity = { human_owner: "ci", environment: "ci", role: "reader", privilege_level: 2 };
    expect(policy.evaluate(event).decision).toBe("allow");
  });
});

// ═══════════════════════════════════════════════════════════════════
//  Priority 10: Compliance Mapping Tests
// ═══════════════════════════════════════════════════════════════════

describe("Compliance Mappings", () => {
  it("has mappings for all 8 runtime controls", () => {
    expect(RUNTIME_COMPLIANCE_MAPPINGS.length).toBe(8);
  });

  it("every control has at least one OWASP mapping", () => {
    for (const m of RUNTIME_COMPLIANCE_MAPPINGS) {
      expect(m.owasp_llm.length).toBeGreaterThan(0);
    }
  });

  it("every control has at least one EU AI Act mapping", () => {
    for (const m of RUNTIME_COMPLIANCE_MAPPINGS) {
      expect(m.eu_ai_act.length).toBeGreaterThan(0);
    }
  });

  it("every control has an evidence snippet", () => {
    for (const m of RUNTIME_COMPLIANCE_MAPPINGS) {
      expect(m.evidence_snippet.length).toBeGreaterThan(50);
    }
  });

  it("every control documents its limitations", () => {
    for (const m of RUNTIME_COMPLIANCE_MAPPINGS) {
      expect(m.limitations.length).toBeGreaterThan(0);
    }
  });

  it("OWASP LLM09 (Excessive Agency) is the most-covered risk", () => {
    const controls = getControlsForOwaspRisk("LLM09");
    expect(controls.length).toBeGreaterThanOrEqual(5);
  });

  it("EU AI Act Article 12 (Record-Keeping) has multiple controls", () => {
    const controls = getControlsForEuArticle("Article 12");
    expect(controls.length).toBeGreaterThanOrEqual(2);
  });

  it("getEvidenceSnippet returns correct content", () => {
    const snippet = getEvidenceSnippet("RT-001");
    expect(snippet).toContain("DangerousCommandPolicy");
    expect(snippet).toContain("18 dangerous command patterns");
  });

  it("generateComplianceSummary produces formatted output", () => {
    const summary = generateComplianceSummary();
    expect(summary).toContain("RT-001");
    expect(summary).toContain("RT-008");
    expect(summary).toContain("OWASP");
    expect(summary).toContain("EU AI Act");
  });
});
