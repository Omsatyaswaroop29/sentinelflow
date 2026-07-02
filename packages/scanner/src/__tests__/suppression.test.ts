import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  parseInlineSuppressions,
  applySuppressions,
  loadPolicyFile,
  PRESETS,
} from "../suppression";
import type { EnterpriseFinding } from "../rules/interface";

function makeFinding(
  ruleId: string,
  file?: string,
  line?: number
): EnterpriseFinding {
  return {
    id: `finding-${ruleId}`,
    rule_id: ruleId,
    rule_name: "Test Rule",
    severity: "high",
    category: "access_control",
    title: "Test finding",
    description: "Test",
    recommendation: "Fix it",
    compliance: [],
    first_detected: new Date().toISOString(),
    status: "open",
    location: file ? { file, line } : undefined,
  };
}

describe("parseInlineSuppressions", () => {
  it("parses # sentinelflow-ignore with justification", () => {
    const content = `tools:
  - name: sql
    access: all  # sentinelflow-ignore: SF-AC-001 -- Scoped by gateway per SEC-1294`;
    const sups = parseInlineSuppressions("/test.yaml", content);
    expect(sups.size).toBe(1);
    const s = [...sups.values()][0]!;
    expect(s.rule_id).toBe("SF-AC-001");
    expect(s.reason).toBe("Scoped by gateway per SEC-1294");
    expect(s.source).toBe("inline");
  });

  it("parses // comment style", () => {
    const content = `// sentinelflow-ignore: SF-FC-001 -- Legacy migration
{}`;
    const sups = parseInlineSuppressions("/config.json", content);
    expect(sups.size).toBe(1);
  });

  it("captures bare ignore without justification (empty reason)", () => {
    const content = `# sentinelflow-ignore: SF-AC-001`;
    const sups = parseInlineSuppressions("/test.yaml", content);
    expect(sups.size).toBe(1);
    expect([...sups.values()][0]!.reason).toBe("");
  });

  it("returns empty map when no ignores present", () => {
    const sups = parseInlineSuppressions("/safe.yaml", "tools:\n  - read\n");
    expect(sups.size).toBe(0);
  });
});

describe("applySuppressions", () => {
  it("suppresses with justified inline ignore on preceding line", () => {
    const findings = [makeFinding("SF-AC-001", "/test.yaml", 3)];
    const configs = [{
      path: "/test.yaml",
      content: "line1\n# sentinelflow-ignore: SF-AC-001 -- Accepted risk\nline3_issue",
    }];
    const result = applySuppressions(findings, configs, "/");
    expect(result.active).toHaveLength(0);
    expect(result.suppressed).toHaveLength(1);
    expect(result.suppressed[0]!.suppression.reason).toBe("Accepted risk");
  });

  it("does NOT suppress unjustified inline ignore", () => {
    const findings = [makeFinding("SF-AC-001", "/test.yaml", 2)];
    const configs = [{
      path: "/test.yaml",
      content: "# sentinelflow-ignore: SF-AC-001\nline2",
    }];
    const result = applySuppressions(findings, configs, "/");
    expect(result.active).toHaveLength(1);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it("does not suppress when rule IDs differ", () => {
    const findings = [makeFinding("SF-FC-001", "/test.yaml", 2)];
    const configs = [{
      path: "/test.yaml",
      content: "# sentinelflow-ignore: SF-AC-001 -- Wrong rule\nline2",
    }];
    const result = applySuppressions(findings, configs, "/");
    expect(result.active).toHaveLength(1);
  });

  it("passes through all findings when no suppressions exist", () => {
    const findings = [makeFinding("SF-AC-001"), makeFinding("SF-FC-001")];
    const result = applySuppressions(findings, [], "/test");
    expect(result.active).toHaveLength(2);
    expect(result.suppressed).toHaveLength(0);
  });
});

describe("loadPolicyFile", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  function writePolicy(yamlContent: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-policy-"));
    tempDirs.push(dir);
    fs.writeFileSync(path.join(dir, ".sentinelflow-policy.yaml"), yamlContent);
    return dir;
  }

  it("returns null when no policy file exists", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-policy-"));
    tempDirs.push(dir);
    const { policy, warnings } = loadPolicyFile(dir);
    expect(policy).toBeNull();
    expect(warnings).toHaveLength(0);
  });

  it("parses nested ignore blocks with real YAML (regression: old hand-rolled regex parser could not)", () => {
    const dir = writePolicy(`
version: v1
preset: strict
severity_overrides:
  SF-CG-001: low
exclude:
  - "test/**"
  - "vendor/**"
ignore:
  SF-AC-001:
    - path: "agents/legacy.yaml"
      reason: "Legacy agent being decommissioned"
      expires: "2026-07-01"
      approved_by: "security-team"
      ticket: "SEC-1294"
`);
    const { policy, warnings } = loadPolicyFile(dir);
    expect(warnings).toHaveLength(0);
    expect(policy?.preset).toBe("strict");
    expect(policy?.severity_overrides).toEqual({ "SF-CG-001": "low" });
    expect(policy?.exclude).toEqual(["test/**", "vendor/**"]);
    expect(policy?.ignore?.["SF-AC-001"]).toHaveLength(1);
    expect(policy?.ignore?.["SF-AC-001"]![0]).toMatchObject({
      path: "agents/legacy.yaml",
      reason: "Legacy agent being decommissioned",
      expires: "2026-07-01",
      approved_by: "security-team",
      ticket: "SEC-1294",
    });
  });

  it("parses the full runtime_policies schema including nested data_boundary/identity/sequence_detection", () => {
    const dir = writePolicy(`
version: v1
runtime_policies:
  blocked_tools:
    - NotebookEdit
  allowed_tools:
    - Read
    - Bash
  max_cost_per_session: 5.00
  enforcement_mode: enforce
  egress_allowed_domains:
    - "*.corp.internal"
  egress_blocked_domains:
    - evil.example.com
  data_boundary:
    enabled: true
    enforcement_mode: monitor
    default_max_classification: internal
    agent_clearances:
      - agent: "deploy-*"
        max_classification: restricted
    custom_rules:
      - pattern: "config/secrets/"
        classification: restricted
        label: "Custom secrets dir"
  identity:
    human_owner: "alice@example.com"
    team: platform
    environment: production
    role: executor
    external_facing: false
    agent_roles:
      reviewer-agent: reader
    agent_privileges:
      custom-agent: 7
  sequence_detection:
    enabled: true
    enforcement_mode: monitor
    window_minutes: 5
    min_confidence: 0.7
`);
    const { policy, warnings } = loadPolicyFile(dir);
    expect(warnings).toHaveLength(0);
    const rp = policy?.runtime_policies;
    expect(rp?.blocked_tools).toEqual(["NotebookEdit"]);
    expect(rp?.allowed_tools).toEqual(["Read", "Bash"]);
    expect(rp?.max_cost_per_session).toBe(5);
    expect(rp?.enforcement_mode).toBe("enforce");
    expect(rp?.egress_allowed_domains).toEqual(["*.corp.internal"]);
    expect(rp?.egress_blocked_domains).toEqual(["evil.example.com"]);

    expect(rp?.data_boundary?.enabled).toBe(true);
    expect(rp?.data_boundary?.enforcement_mode).toBe("monitor");
    expect(rp?.data_boundary?.default_max_classification).toBe("internal");
    expect(rp?.data_boundary?.agent_clearances).toEqual([
      { agent: "deploy-*", max_classification: "restricted" },
    ]);
    expect(rp?.data_boundary?.custom_rules).toEqual([
      { pattern: "config/secrets/", classification: "restricted", label: "Custom secrets dir" },
    ]);

    expect(rp?.identity?.human_owner).toBe("alice@example.com");
    expect(rp?.identity?.team).toBe("platform");
    expect(rp?.identity?.environment).toBe("production");
    expect(rp?.identity?.role).toBe("executor");
    expect(rp?.identity?.agent_roles).toEqual({ "reviewer-agent": "reader" });
    expect(rp?.identity?.agent_privileges).toEqual({ "custom-agent": 7 });

    expect(rp?.sequence_detection?.enabled).toBe(true);
    expect(rp?.sequence_detection?.window_minutes).toBe(5);
    expect(rp?.sequence_detection?.min_confidence).toBe(0.7);
  });

  it("skips malformed data_boundary entries with a warning instead of throwing", () => {
    const dir = writePolicy(`
version: v1
runtime_policies:
  data_boundary:
    agent_clearances:
      - agent: "ok-agent"
        max_classification: restricted
      - agent: "bad-agent"
        max_classification: "not-a-real-level"
`);
    const { policy, warnings } = loadPolicyFile(dir);
    expect(policy?.runtime_policies?.data_boundary?.agent_clearances).toEqual([
      { agent: "ok-agent", max_classification: "restricted" },
    ]);
    expect(warnings.some((w) => w.includes("agent_clearances"))).toBe(true);
  });

  it("reports a warning instead of throwing on invalid YAML", () => {
    const dir = writePolicy("version: v1\n  bad indentation: [unterminated");
    const { policy, warnings } = loadPolicyFile(dir);
    expect(policy).toBeNull();
    expect(warnings.length).toBeGreaterThan(0);
  });
});

describe("PRESETS", () => {
  it("strict fails on medium+", () => {
    expect(PRESETS.strict.exitOnSeverities).toContain("medium");
  });
  it("standard fails on high+", () => {
    expect(PRESETS.standard.exitOnSeverities).toContain("high");
    expect(PRESETS.standard.exitOnSeverities).not.toContain("medium");
  });
  it("monitor never fails", () => {
    expect(PRESETS.monitor.exitOnSeverities).toHaveLength(0);
  });
});
