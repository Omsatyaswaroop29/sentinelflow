import { describe, it, expect } from "vitest";
import { createAgent } from "@sentinelflow/core";
import type { ScanResult } from "../engine";
import {
  formatTerminal,
  formatJSON,
  formatMarkdown,
  formatSARIF,
} from "../reporter";

function makeScanResult(): ScanResult {
  return {
    report: {
      id: "scan-test",
      timestamp: "2026-03-31T00:00:00.000Z",
      root_dir: "/test/project",
      duration_ms: 150,
      frameworks_detected: ["Claude Code"],
      agents_discovered: 2,
      findings: [
        {
          id: "f1",
          rule_id: "SF-AC-001",
          rule_name: "Hardcoded Credentials",
          severity: "critical",
          category: "access_control",
          title: "AWS key found in settings.json",
          description: "An AWS access key was detected.",
          recommendation: "Move to environment variable.",
          location: { file: ".claude/settings.json", line: 5 },
          first_detected: "2026-03-31T00:00:00.000Z",
          status: "open",
        },
        {
          id: "f2",
          rule_id: "SF-AC-008",
          rule_name: "No Owner",
          severity: "medium",
          category: "access_control",
          title: "Agent has no owner",
          description: "No owner assigned.",
          recommendation: "Add an owner.",
          first_detected: "2026-03-31T00:00:00.000Z",
          status: "open",
        },
      ],
      summary: { critical: 1, high: 0, medium: 1, low: 0, info: 0, total: 2 },
    },
    agents: [
      createAgent({ name: "agent-a", framework: "claude-code" }),
      createAgent({ name: "agent-b", framework: "claude-code" }),
    ],
    frameworks: ["Claude Code"],
    warnings: [],
  };
}

describe("formatTerminal", () => {
  it("includes project path and framework", () => {
    const output = formatTerminal(makeScanResult());
    expect(output).toContain("/test/project");
    expect(output).toContain("Claude Code");
  });

  it("includes finding rule IDs", () => {
    const output = formatTerminal(makeScanResult());
    expect(output).toContain("SF-AC-001");
  });

  it("shows all-clear for zero findings", () => {
    const result = makeScanResult();
    result.report.findings = [];
    result.report.summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const output = formatTerminal(result);
    expect(output).toContain("all clear");
  });
});

describe("formatJSON", () => {
  it("outputs valid JSON with all report fields", () => {
    const output = formatJSON(makeScanResult());
    const parsed = JSON.parse(output);
    expect(parsed.id).toBe("scan-test");
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.summary.critical).toBe(1);
  });
});

describe("formatMarkdown", () => {
  it("includes heading and summary table", () => {
    const output = formatMarkdown(makeScanResult());
    expect(output).toContain("# SentinelFlow Governance Report");
    expect(output).toContain("| Critical | 1 |");
  });
});

describe("formatSARIF", () => {
  it("outputs valid SARIF 2.1.0 JSON", () => {
    const output = formatSARIF(makeScanResult());
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.name).toBe("SentinelFlow");
  });

  it("includes all 41 rule definitions", () => {
    const output = formatSARIF(makeScanResult());
    const parsed = JSON.parse(output);
    expect(parsed.runs[0].tool.driver.rules.length).toBe(41);
  });

  it("maps severity to SARIF levels correctly", () => {
    const output = formatSARIF(makeScanResult());
    const parsed = JSON.parse(output);
    const results = parsed.runs[0].results;
    expect(results[0].level).toBe("error");     // critical → error
    expect(results[1].level).toBe("warning");    // medium → warning
  });

  it("includes file locations", () => {
    const output = formatSARIF(makeScanResult());
    const parsed = JSON.parse(output);
    const loc = parsed.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toContain("settings.json");
    expect(loc.region.startLine).toBe(5);
  });
});
