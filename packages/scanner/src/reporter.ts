/**
 * @module @sentinelflow/scanner/reporter
 *
 * Formats scan results for terminal output, JSON, and Markdown.
 */

import type { ScanResult } from "./engine";

// ANSI color codes
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";
const BG_RED = "\x1b[41m";
const BG_YELLOW = "\x1b[43m";

const SEVERITY_COLORS: Record<string, string> = {
  critical: `${BG_RED}${WHITE}${BOLD}`,
  high: `${RED}${BOLD}`,
  medium: `${YELLOW}`,
  low: `${DIM}`,
  info: `${DIM}`,
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function formatTerminal(result: ScanResult): string {
  const lines: string[] = [];
  const { report, agents, frameworks } = result;

  // Header
  lines.push("");
  lines.push(
    `  ${BOLD}${CYAN}SentinelFlow v0.1.0${RESET} ${DIM}— Agent Governance Scanner${RESET}`
  );
  lines.push("");
  lines.push(`  Scanning ${BOLD}${report.root_dir}${RESET}...`);
  lines.push("");

  // Frameworks detected
  lines.push(`  ${BOLD}Frameworks detected:${RESET}`);
  if (frameworks.length === 0) {
    lines.push(`    ${DIM}No agent frameworks found${RESET}`);
  } else {
    for (const fw of frameworks) {
      lines.push(`    ${GREEN}✓${RESET} ${fw}`);
    }
  }
  lines.push("");

  // Agents discovered
  lines.push(`  ${BOLD}Agents discovered:${RESET} ${agents.length}`);
  for (let i = 0; i < agents.length; i++) {
    const agent = agents[i];
    if (!agent) continue;
    const isLast = i === agents.length - 1;
    const prefix = isLast ? "└──" : "├──";
    const role = agent.swarm_role !== "standalone" ? `, ${agent.swarm_role}` : "";
    lines.push(
      `    ${DIM}${prefix}${RESET} ${BOLD}${agent.name}${RESET} ${DIM}(${agent.framework}${role})${RESET}`
    );
  }
  lines.push("");

  // Findings summary
  const { summary } = report;
  if (summary.total === 0) {
    lines.push(`  ${GREEN}${BOLD}✓ No findings — all clear!${RESET}`);
  } else {
    const parts: string[] = [];
    if (summary.critical > 0)
      parts.push(`${RED}${BOLD}${summary.critical} critical${RESET}`);
    if (summary.high > 0)
      parts.push(`${RED}${summary.high} high${RESET}`);
    if (summary.medium > 0)
      parts.push(`${YELLOW}${summary.medium} medium${RESET}`);
    if (summary.low > 0) parts.push(`${DIM}${summary.low} low${RESET}`);
    if (summary.info > 0) parts.push(`${DIM}${summary.info} info${RESET}`);

    lines.push(`  ${BOLD}Findings:${RESET} ${parts.join(", ")}`);
    lines.push("");

    // Group findings by severity
    for (const severity of ["critical", "high", "medium", "low"] as const) {
      const findings = report.findings.filter((f) => f.severity === severity);
      if (findings.length === 0) continue;

      const color = SEVERITY_COLORS[severity];
      lines.push(`  ${color}${SEVERITY_LABELS[severity]}${RESET}`);
      lines.push(
        `  ${DIM}┌${"─".repeat(60)}┐${RESET}`
      );

      for (const finding of findings) {
        const location = finding.location
          ? `${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`
          : "";
        lines.push(
          `  ${DIM}│${RESET} ${BOLD}${finding.rule_id}${RESET}  ${finding.title}`
        );
        if (location) {
          lines.push(`  ${DIM}│${RESET}          ${DIM}${location}${RESET}`);
        }
      }

      lines.push(
        `  ${DIM}└${"─".repeat(60)}┘${RESET}`
      );
      lines.push("");
    }
  }

  // Footer
  lines.push(
    `  ${DIM}Scan completed in ${report.duration_ms}ms${RESET}`
  );
  lines.push(
    `  ${DIM}Registry updated: ${agents.length} agents in .sentinelflow/${RESET}`
  );
  lines.push("");

  return lines.join("\n");
}

export function formatJSON(result: ScanResult): string {
  return JSON.stringify(result.report, null, 2);
}

/**
 * SARIF 2.1.0 output for GitHub Advanced Security integration.
 * This gets SentinelFlow findings into GitHub's Security tab for free.
 */
export function formatSARIF(result: ScanResult): string {
  const { report } = result;

  const sarifReport = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "SentinelFlow",
            version: "0.1.0",
            informationUri: "https://github.com/omswaroop/sentinelflow",
            rules: BUILT_IN_RULES.map((rule) => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.name },
              fullDescription: { text: rule.description },
              defaultConfiguration: {
                level: mapSeverityToSARIF(rule.severity),
              },
              properties: {
                tags: [rule.category],
              },
            })),
          },
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.rule_id,
          level: mapSeverityToSARIF(finding.severity),
          message: {
            text: `${finding.title}\n\n${finding.description}\n\nRecommendation: ${finding.recommendation}`,
          },
          locations: finding.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: finding.location.file,
                    },
                    region: finding.location.line
                      ? {
                          startLine: finding.location.line,
                        }
                      : undefined,
                  },
                },
              ]
            : [],
        })),
      },
    ],
  };

  return JSON.stringify(sarifReport, null, 2);
}

function mapSeverityToSARIF(
  severity: string
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    default:
      return "none";
  }
}

// Need access to BUILT_IN_RULES for SARIF rule definitions
import { BUILT_IN_RULES } from "./rules/index";

export function formatMarkdown(result: ScanResult): string {
  const { report, agents, frameworks } = result;
  const lines: string[] = [];

  lines.push("# SentinelFlow Governance Report");
  lines.push("");
  lines.push(`**Scanned:** ${report.root_dir}`);
  lines.push(`**Date:** ${report.timestamp}`);
  lines.push(`**Duration:** ${report.duration_ms}ms`);
  lines.push(`**Frameworks:** ${frameworks.join(", ") || "None detected"}`);
  lines.push(`**Agents discovered:** ${report.agents_discovered}`);
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${report.summary.critical} |`);
  lines.push(`| High | ${report.summary.high} |`);
  lines.push(`| Medium | ${report.summary.medium} |`);
  lines.push(`| Low | ${report.summary.low} |`);
  lines.push(`| **Total** | **${report.summary.total}** |`);
  lines.push("");

  // Agents
  lines.push("## Agents");
  lines.push("");
  for (const agent of agents) {
    lines.push(
      `- **${agent.name}** (${agent.framework}) — ${agent.swarm_role} — Risk: ${agent.governance.risk_level ?? "unassessed"}`
    );
  }
  lines.push("");

  // Findings
  if (report.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");

    for (const severity of ["critical", "high", "medium", "low"] as const) {
      const findings = report.findings.filter((f) => f.severity === severity);
      if (findings.length === 0) continue;

      lines.push(`### ${severity.toUpperCase()}`);
      lines.push("");

      for (const f of findings) {
        lines.push(`#### ${f.rule_id}: ${f.title}`);
        lines.push("");
        lines.push(f.description);
        lines.push("");
        lines.push(`**Recommendation:** ${f.recommendation}`);
        if (f.location) {
          lines.push(`**Location:** \`${f.location.file}${f.location.line ? `:${f.location.line}` : ""}\``);
        }
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}
