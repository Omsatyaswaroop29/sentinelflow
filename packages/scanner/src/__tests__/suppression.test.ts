import { describe, it, expect } from "vitest";
import {
  parseInlineSuppressions,
  applySuppressions,
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
