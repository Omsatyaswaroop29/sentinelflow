/**
 * @module @sentinelflow/scanner/engine
 *
 * The main scanner engine. Orchestrates the detect → parse → analyze → report pipeline.
 *
 * Enterprise considerations:
 * - Rules are filtered by framework (a Claude Code rule won't run against LangChain agents)
 * - Empty projects get helpful guidance instead of confusing empty output
 * - Every error is caught, logged as a warning, and never crashes the scan
 * - Registry updates use atomic writes to prevent corruption
 */

import * as path from "path";
import {
  type SentinelFlowAgent,
  type Finding,
  type ScanReport,
  createScanReport,
  LocalRegistry,
} from "@sentinelflow/core";
import { parseAll, type ConfigFile } from "@sentinelflow/parsers";
import { BUILT_IN_RULES, type RuleContext, type ScanRule } from "./rules/index";

export interface ScanOptions {
  /** Project root directory to scan */
  rootDir: string;
  /** Specific rule IDs to run (default: all) */
  rules?: string[];
  /** Minimum severity to report */
  minSeverity?: "critical" | "high" | "medium" | "low" | "info";
  /** Update the local registry with results */
  updateRegistry?: boolean;
}

export interface ScanResult {
  report: ScanReport;
  agents: SentinelFlowAgent[];
  frameworks: string[];
  warnings: string[];
}

const SEVERITY_ORDER: readonly string[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/**
 * Run a full governance scan on the given directory.
 *
 * The pipeline:
 * 1. Detect which frameworks are present
 * 2. Parse agent configurations from each framework
 * 3. Select applicable rules (respecting framework filters)
 * 4. Run rules against discovered agents
 * 5. Sort findings by severity
 * 6. Update the local registry (optional)
 * 7. Return the complete scan report
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const rootDir = path.resolve(options.rootDir);

  // Validate that the directory exists
  const fs = await import("fs");
  if (!fs.existsSync(rootDir)) {
    throw new Error(`Directory not found: ${rootDir}`);
  }
  if (!fs.statSync(rootDir).isDirectory()) {
    throw new Error(`Not a directory: ${rootDir}`);
  }

  // ── Step 1: Parse all frameworks ──────────────────────────
  const parseResult = await parseAll(rootDir);

  // Collect the set of frameworks that were actually detected
  const detectedFrameworkSet = new Set(
    parseResult.agents.map((a) => a.framework)
  );

  // ── Step 2: Build rule context ────────────────────────────
  const context: RuleContext = {
    agents: parseResult.agents,
    config_files: parseResult.config_files,
    root_dir: rootDir,
  };

  // ── Step 3: Select and filter rules ───────────────────────
  let rules: ScanRule[] = [...BUILT_IN_RULES];

  // Filter by specific rule IDs if provided
  if (options.rules && options.rules.length > 0) {
    const requestedIds = new Set(options.rules);
    rules = rules.filter((r) => requestedIds.has(r.id));

    if (rules.length === 0) {
      parseResult.warnings.push(
        `No matching rules found for IDs: ${options.rules.join(", ")}. ` +
          `Available rule IDs: ${BUILT_IN_RULES.map((r) => r.id).join(", ")}`
      );
    }
  }

  // Filter by minimum severity
  if (options.minSeverity) {
    const minIdx = SEVERITY_ORDER.indexOf(options.minSeverity);
    if (minIdx === -1) {
      parseResult.warnings.push(
        `Invalid severity: "${options.minSeverity}". ` +
          `Valid values: ${SEVERITY_ORDER.join(", ")}`
      );
    } else {
      rules = rules.filter((r) => {
        const ruleIdx = SEVERITY_ORDER.indexOf(r.severity);
        return ruleIdx <= minIdx;
      });
    }
  }

  // ── Step 4: Run rules (with framework filtering) ──────────
  const allFindings: Finding[] = [];

  for (const rule of rules) {
    // H5 FIX: Skip rules that don't apply to any detected framework
    if (rule.frameworks !== "all") {
      const ruleFrameworks = new Set(rule.frameworks);
      const hasApplicableFramework = [...detectedFrameworkSet].some((f) =>
        ruleFrameworks.has(f)
      );
      if (!hasApplicableFramework) {
        continue; // Skip this rule — no applicable frameworks detected
      }
    }

    try {
      const findings = rule.evaluate(context);
      allFindings.push(...findings);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error);
      parseResult.warnings.push(
        `Rule ${rule.id} (${rule.name}) failed: ${message}`
      );
    }
  }

  // Sort findings by severity (critical first)
  allFindings.sort((a, b) => {
    return (
      SEVERITY_ORDER.indexOf(a.severity) -
      SEVERITY_ORDER.indexOf(b.severity)
    );
  });

  // ── Step 5: Build report ──────────────────────────────────
  const durationMs = Date.now() - startTime;
  const report = createScanReport(
    rootDir,
    allFindings,
    parseResult.frameworks,
    parseResult.agents.length,
    durationMs
  );

  // ── Step 6: Update registry (if enabled) ──────────────────
  if (options.updateRegistry !== false) {
    try {
      const registry = new LocalRegistry(rootDir);
      await registry.initialize();

      for (const agent of parseResult.agents) {
        // Calculate per-agent findings and risk level
        const agentFindings = allFindings.filter(
          (f) => f.agent_id === agent.id
        );
        agent.governance.last_scan = new Date().toISOString();
        agent.governance.findings_count = {
          critical: agentFindings.filter((f) => f.severity === "critical")
            .length,
          high: agentFindings.filter((f) => f.severity === "high").length,
          medium: agentFindings.filter((f) => f.severity === "medium").length,
          low: agentFindings.filter((f) => f.severity === "low").length,
          info: agentFindings.filter((f) => f.severity === "info").length,
        };

        // Determine risk level from most severe finding
        if (agentFindings.some((f) => f.severity === "critical")) {
          agent.governance.risk_level = "critical";
        } else if (agentFindings.some((f) => f.severity === "high")) {
          agent.governance.risk_level = "high";
        } else if (agentFindings.some((f) => f.severity === "medium")) {
          agent.governance.risk_level = "medium";
        } else {
          agent.governance.risk_level = "low";
        }

        await registry.upsertAgent(agent);
      }

      await registry.storeScanReport(report);
      await registry.close();
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error);
      parseResult.warnings.push(`Failed to update registry: ${message}`);
    }
  }

  return {
    report,
    agents: parseResult.agents,
    frameworks: parseResult.frameworks,
    warnings: parseResult.warnings,
  };
}
