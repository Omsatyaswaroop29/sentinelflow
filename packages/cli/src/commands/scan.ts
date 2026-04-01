/**
 * sentinelflow scan [path]
 *
 * The main scanning command. Detects frameworks, parses agents,
 * runs governance rules, and reports findings.
 *
 * Enterprise considerations:
 * - Input validation with clear error messages for every argument
 * - Non-zero exit code on critical/high findings (for CI/CD gating)
 * - SARIF output for GitHub Advanced Security integration
 * - Helpful guidance when no frameworks are detected
 */

import * as fs from "fs";
import * as path from "path";
import {
  scan,
  formatTerminal,
  formatJSON,
  formatMarkdown,
  formatSARIF,
} from "@sentinelflow/scanner";

const VALID_FORMATS = ["terminal", "json", "md", "sarif"] as const;
const VALID_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

type OutputFormat = (typeof VALID_FORMATS)[number];
type Severity = (typeof VALID_SEVERITIES)[number];

interface ScanCommandOptions {
  format: string;
  minSeverity?: string;
  rules?: string;
  registry?: boolean;
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

  if (
    options.minSeverity &&
    !VALID_SEVERITIES.includes(options.minSeverity as Severity)
  ) {
    console.error(
      `\n  \x1b[31mError:\x1b[0m Invalid severity "${options.minSeverity}". ` +
        `Valid values: ${VALID_SEVERITIES.join(", ")}\n`
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
    if (
      result.frameworks.length === 0 &&
      format === "terminal"
    ) {
      console.log(`
  \x1b[36m\x1b[1mSentinelFlow v0.1.0\x1b[0m — Agent Governance Scanner

  Scanning ${rootDir}...

  \x1b[33mNo agent frameworks detected.\x1b[0m

  SentinelFlow scans for agents in:
    • Claude Code  (.claude/ directory, CLAUDE.md, AGENTS.md)
    • Cursor       (.cursor/ directory)
    • Codex        (.codex/ directory, .agents/)
    • LangChain    (pyproject.toml with langchain dependency)
    • CrewAI       (crew.yaml, agents.yaml)

  If your project uses AI agents, ensure their config files are
  present in the project directory.

  Run \x1b[1msentinelflow init\x1b[0m to set up governance for this project.
`);
      return;
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

    // Print warnings (terminal only)
    if (result.warnings.length > 0 && format === "terminal") {
      console.log("  \x1b[33mWarnings:\x1b[0m");
      for (const warning of result.warnings) {
        console.log(`    \x1b[33m⚠\x1b[0m ${warning}`);
      }
      console.log("");
    }

    // ── Exit Code for CI/CD ───────────────────────────────
    // Exit 1 if critical or high findings exist (blocks CI pipelines)
    const { summary } = result.report;
    if (summary.critical > 0 || summary.high > 0) {
      process.exit(1);
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : String(error);
    console.error(`\n  \x1b[31mError:\x1b[0m ${message}\n`);
    process.exit(2);
  }
}
