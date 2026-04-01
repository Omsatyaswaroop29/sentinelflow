/**
 * sentinelflow scan [path]
 *
 * The main scanning command. Detects frameworks, parses agents,
 * runs governance rules, applies suppressions, and reports findings.
 *
 * Phase 1.5 additions:
 * - --preset flag (strict/standard/monitor) for progressive adoption
 * - --show-suppressed flag for audit review of hidden findings
 * - .sentinelflow-policy.yaml loading for project-level suppressions
 * - Coverage footer showing what static analysis can and cannot see
 * - Preset-aware exit codes (monitor never fails CI)
 */

import * as fs from "fs";
import * as path from "path";
import {
  scan,
  formatTerminal,
  formatJSON,
  formatMarkdown,
  formatSARIF,
  applySuppressions,
  loadPolicyFile,
  PRESETS,
  type ScanPreset,
  type SuppressionResult,
} from "@sentinelflow/scanner";

const VALID_FORMATS = ["terminal", "json", "md", "sarif"] as const;
const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const VALID_PRESETS = ["strict", "standard", "monitor"] as const;

type OutputFormat = (typeof VALID_FORMATS)[number];
type Severity = (typeof VALID_SEVERITIES)[number];

interface ScanCommandOptions {
  format: string;
  minSeverity?: string;
  rules?: string;
  registry?: boolean;
  preset?: string;
  showSuppressed?: boolean;
}

export async function scanCommand(
  targetPath: string,
  options: ScanCommandOptions
): Promise<void> {
  const rootDir = path.resolve(targetPath);

  // ── Input Validation ──────────────────────────────────────
  if (!fs.existsSync(rootDir)) {
    console.error(`\n  \x1b[31mError:\x1b[0m Directory not found: ${rootDir}\n`);
    process.exit(2);
  }

  if (!fs.statSync(rootDir).isDirectory()) {
    console.error(`\n  \x1b[31mError:\x1b[0m Not a directory: ${rootDir}\n`);
    process.exit(2);
  }

  const format = options.format as OutputFormat;
  if (!VALID_FORMATS.includes(format)) {
    console.error(
      `\n  \x1b[31mError:\x1b[0m Invalid format "${options.format}". ` +
        `Valid formats: ${VALID_FORMATS.join(", ")}\n`
    );
    process.exit(2);
  }

  if (options.minSeverity && !VALID_SEVERITIES.includes(options.minSeverity as Severity)) {
    console.error(
      `\n  \x1b[31mError:\x1b[0m Invalid severity "${options.minSeverity}". ` +
        `Valid values: ${VALID_SEVERITIES.join(", ")}\n`
    );
    process.exit(2);
  }

  const preset = (options.preset ?? "standard") as ScanPreset;
  if (!VALID_PRESETS.includes(preset)) {
    console.error(
      `\n  \x1b[31mError:\x1b[0m Invalid preset "${options.preset}". ` +
        `Valid presets: ${VALID_PRESETS.join(", ")}\n`
    );
    process.exit(2);
  }

  // ── Run Scan ──────────────────────────────────────────────
  try {
    const result = await scan({
      rootDir,
      minSeverity: options.minSeverity as Severity | undefined,
      rules: options.rules?.split(",").map((r) => r.trim()),
      updateRegistry: options.registry,
    });

    // ── Handle Empty Scans ────────────────────────────────
    if (result.frameworks.length === 0 && format === "terminal") {
      console.log(`
  \x1b[36m\x1b[1mSentinelFlow v0.2.0\x1b[0m — Agent Governance Scanner

  Scanning ${rootDir}...

  \x1b[33mNo agent frameworks detected.\x1b[0m

  SentinelFlow scans for agents in:
    • Claude Code  (.claude/ directory, CLAUDE.md, AGENTS.md)
    • Cursor       (.cursor/ directory, .cursorrules)
    • Codex        (.codex/ directory, .agents/)
    • LangChain    (pyproject.toml with langchain dependency)
    • CrewAI       (crew.yaml, agents.yaml)
    • Kiro         (.kiro/ directory)

  Run \x1b[1msentinelflow init\x1b[0m to set up governance for this project.
`);
      return;
    }

    // ── Apply Suppressions ────────────────────────────────
    // Load policy file if it exists
    const { policy, warnings: policyWarnings } = loadPolicyFile(rootDir);

    // Determine effective preset (CLI flag overrides policy file)
    const effectivePreset = options.preset
      ? preset
      : (policy?.preset as ScanPreset) ?? "standard";

    // Apply suppressions from inline comments + policy file
    // Pass empty config files array — inline suppression parsing happens
    // inside applySuppressions via the policy file loader. Config file content
    // isn't available from ScanResult, but policy-file and preset suppressions
    // still work fully.
    const suppressionResult: SuppressionResult = applySuppressions(
      result.report.findings as any[],
      [],
      rootDir
    );

    // Replace findings with active-only (unless --show-suppressed)
    if (!options.showSuppressed) {
      result.report.findings = suppressionResult.active as any[];
      // Recalculate summary
      result.report.summary = {
        critical: result.report.findings.filter((f) => f.severity === "critical").length,
        high: result.report.findings.filter((f) => f.severity === "high").length,
        medium: result.report.findings.filter((f) => f.severity === "medium").length,
        low: result.report.findings.filter((f) => f.severity === "low").length,
        info: result.report.findings.filter((f) => f.severity === "info").length,
        total: result.report.findings.length,
      };
    }

    // ── Output in Requested Format ────────────────────────
    switch (format) {
      case "json":
        console.log(formatJSON(result));
        break;
      case "md":
        console.log(formatMarkdown(result));
        break;
      case "sarif":
        console.log(formatSARIF(result));
        break;
      case "terminal":
      default:
        console.log(formatTerminal(result));
        break;
    }

    // ── Suppression Summary (terminal only) ───────────────
    if (format === "terminal" && suppressionResult.suppressed.length > 0) {
      if (options.showSuppressed) {
        console.log(`  \x1b[33mSuppressed findings (${suppressionResult.suppressed.length}):\x1b[0m`);
        for (const { finding, suppression } of suppressionResult.suppressed) {
          console.log(`    \x1b[2m${finding.rule_id}\x1b[0m ${finding.title}`);
          console.log(`      Reason: ${suppression.reason}`);
          if (suppression.expires) console.log(`      Expires: ${suppression.expires}`);
          if (suppression.ticket) console.log(`      Ticket: ${suppression.ticket}`);
        }
        console.log("");
      } else {
        console.log(
          `  \x1b[2m${suppressionResult.suppressed.length} finding(s) suppressed. ` +
            `Use --show-suppressed to review.\x1b[0m`
        );
        console.log("");
      }
    }

    // ── Expired Suppressions Warning ──────────────────────
    if (format === "terminal" && suppressionResult.expired_suppressions.length > 0) {
      console.log(`  \x1b[33m⚠ ${suppressionResult.expired_suppressions.length} expired suppression(s):\x1b[0m`);
      for (const exp of suppressionResult.expired_suppressions) {
        console.log(`    ${exp.rule_id} — expired ${exp.expires} — ${exp.reason}`);
      }
      console.log("  \x1b[2mRemove expired entries from .sentinelflow-policy.yaml\x1b[0m");
      console.log("");
    }

    // ── Coverage Footer ───────────────────────────────────
    if (format === "terminal") {
      const agentCount = result.agents.length;
      const configCount = result.report.findings.length;
      console.log(`  \x1b[2m┌─ Coverage ──────────────────────────────────────────┐\x1b[0m`);
      console.log(`  \x1b[2m│ Static analysis of ${agentCount} agent definition(s).          │\x1b[0m`);
      console.log(`  \x1b[2m│                                                    │\x1b[0m`);
      console.log(`  \x1b[2m│ Not analyzed (requires runtime context):            │\x1b[0m`);
      console.log(`  \x1b[2m│  · IAM roles and cloud permissions                  │\x1b[0m`);
      console.log(`  \x1b[2m│  · Secrets injected via Vault / env variables       │\x1b[0m`);
      console.log(`  \x1b[2m│  · Network policies and service mesh config         │\x1b[0m`);
      console.log(`  \x1b[2m│  · Feature flags gating agent capabilities          │\x1b[0m`);
      console.log(`  \x1b[2m│                                                    │\x1b[0m`);
      console.log(`  \x1b[2m│ Preset: ${effectivePreset.padEnd(10)} Docs: sentinelflow.dev │\x1b[0m`);
      console.log(`  \x1b[2m└────────────────────────────────────────────────────┘\x1b[0m`);
      console.log("");
    }

    // Print warnings
    const allWarnings = [...result.warnings, ...policyWarnings];
    if (allWarnings.length > 0 && format === "terminal") {
      console.log("  \x1b[33mWarnings:\x1b[0m");
      for (const warning of allWarnings) {
        console.log(`    \x1b[33m⚠\x1b[0m ${warning}`);
      }
      console.log("");
    }

    // ── Exit Code (preset-aware) ──────────────────────────
    const presetConfig = PRESETS[effectivePreset];
    const { summary } = result.report;

    const shouldFail = presetConfig.exitOnSeverities.some((sev) => {
      switch (sev) {
        case "critical": return summary.critical > 0;
        case "high": return summary.high > 0;
        case "medium": return summary.medium > 0;
        case "low": return summary.low > 0;
        default: return false;
      }
    });

    if (shouldFail) {
      process.exit(1);
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`\n  \x1b[31mError:\x1b[0m ${message}\n`);
    process.exit(2);
  }
}
