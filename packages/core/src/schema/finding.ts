/**
 * @module @sentinelflow/core/schema/finding
 *
 * A governance or security finding produced by the SentinelFlow scanner.
 * Compatible with SARIF (Static Analysis Results Interchange Format)
 * for integration with GitHub Advanced Security.
 */

export type FindingCategory =
  // Legacy categories (kept for backward compatibility)
  | "secrets"
  | "permissions"
  | "guardrails"
  | "git_safety"
  | "data_access"
  | "config_protection"
  | "mcp_risk"
  | "identity"
  | "cost"
  | "compliance"
  | "topology"
  | "drift"
  // Enterprise categories (v0.1.0+)
  | "prompt_injection"
  | "access_control"
  | "supply_chain"
  | "data_governance"
  | "cost_governance"
  | "framework_config"
  | "multi_agent"
  | "audit_logging"
  | "compliance_docs"
  | "network_security";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface FindingLocation {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: FindingSeverity;
  category: FindingCategory;
  title: string;
  description: string;
  recommendation: string;
  agent_id?: string;
  agent_name?: string;
  framework?: string;
  location?: FindingLocation;
  metadata?: Record<string, unknown>;
  first_detected: string;
  status: FindingStatus;
}

/**
 * Aggregate scan results for a single run.
 */
export interface ScanReport {
  id: string;
  timestamp: string;
  root_dir: string;
  duration_ms: number;
  frameworks_detected: string[];
  agents_discovered: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

export function createScanReport(
  rootDir: string,
  findings: Finding[],
  frameworksDetected: string[],
  agentsDiscovered: number,
  durationMs: number
): ScanReport {
  const summary = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    total: findings.length,
  };

  return {
    id: `scan-${Date.now()}`,
    timestamp: new Date().toISOString(),
    root_dir: rootDir,
    duration_ms: durationMs,
    frameworks_detected: frameworksDetected,
    agents_discovered: agentsDiscovered,
    findings,
    summary,
  };
}
