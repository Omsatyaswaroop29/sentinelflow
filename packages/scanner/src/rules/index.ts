/**
 * SentinelFlow Enterprise Rule Registry
 *
 * 41 governance rules · 10 categories · 7 compliance frameworks
 *
 * Categories:
 *   1. Prompt Injection & Input Validation  (PI-*)
 *   2. Agent Identity & Access Control      (AC-*)
 *   3. Supply Chain Integrity               (SC-*)
 *   4. Data Governance & PII Protection     (DG-*)
 *   5. Cost & Resource Governance           (CG-*)
 *   6. Agent Framework Configuration        (FC-*)
 *   7. Multi-Agent Orchestration Security   (MA-*)
 *   8. Audit Logging & Observability        (AL-*)
 *   9. Compliance Documentation             (CD-*)
 *  10. Network & Infrastructure Security    (NS-*)
 *
 * Compliance frameworks mapped:
 *   OWASP LLM Top 10 2025, NIST AI RMF, EU AI Act,
 *   MITRE ATLAS, HIPAA, SOC 2, ISO 42001
 */

import type { ScanRule } from "./interface";

// Import all category rule arrays
import { PROMPT_INJECTION_RULES } from "./prompt-injection";
import { ACCESS_CONTROL_RULES } from "./access-control";
import { SUPPLY_CHAIN_RULES } from "./supply-chain";
import { DATA_GOVERNANCE_RULES } from "./data-governance";
import { COST_GOVERNANCE_RULES } from "./cost-governance";
import { FRAMEWORK_CONFIG_RULES } from "./framework-config";
import { MULTI_AGENT_RULES } from "./multi-agent";
import { AUDIT_LOGGING_RULES } from "./audit-logging";
import { COMPLIANCE_DOCS_RULES } from "./compliance-docs";
import { NETWORK_SECURITY_RULES } from "./network-security";

/** All built-in scan rules — 46 statically-detectable rules */
export const BUILT_IN_RULES: ScanRule[] = [
  ...PROMPT_INJECTION_RULES,   // 4 rules
  ...ACCESS_CONTROL_RULES,     // 5 rules
  ...SUPPLY_CHAIN_RULES,       // 6 rules (+1: SC-010 LangChain passthrough)
  ...DATA_GOVERNANCE_RULES,    // 3 rules
  ...COST_GOVERNANCE_RULES,    // 5 rules
  ...FRAMEWORK_CONFIG_RULES,   // 8 rules (+2: FC-008 Codex full-auto, FC-009 Cursor alwaysApply)
  ...MULTI_AGENT_RULES,        // 5 rules (+2: MA-007 CrewAI hierarchical, MA-008 config drift)
  ...AUDIT_LOGGING_RULES,      // 3 rules
  ...COMPLIANCE_DOCS_RULES,    // 4 rules
  ...NETWORK_SECURITY_RULES,   // 3 rules
];

// ─── Query helpers ──────────────────────────────────────────────

export function getRuleById(id: string): ScanRule | undefined {
  return BUILT_IN_RULES.find((r) => r.id === id);
}

export function getRulesByCategory(category: string): ScanRule[] {
  return BUILT_IN_RULES.filter((r) => r.category === category);
}

export function getRulesBySeverity(severity: string): ScanRule[] {
  return BUILT_IN_RULES.filter((r) => r.severity === severity);
}

export function getRulesByFramework(framework: string): ScanRule[] {
  return BUILT_IN_RULES.filter(
    (r) => r.frameworks === "all" || r.frameworks.includes(framework as any)
  );
}

export function getRulesByCompliance(framework: string): ScanRule[] {
  return BUILT_IN_RULES.filter((r) =>
    r.compliance.some((c) => c.framework === framework)
  );
}

/** Summary statistics for CLI and dashboard display */
export function getRuleSummary(): {
  total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  by_compliance: Record<string, number>;
} {
  const by_category: Record<string, number> = {};
  const by_severity: Record<string, number> = {};
  const by_compliance: Record<string, number> = {};

  for (const rule of BUILT_IN_RULES) {
    by_category[rule.category] = (by_category[rule.category] ?? 0) + 1;
    by_severity[rule.severity] = (by_severity[rule.severity] ?? 0) + 1;
    for (const mapping of rule.compliance) {
      by_compliance[mapping.framework] = (by_compliance[mapping.framework] ?? 0) + 1;
    }
  }

  return {
    total: BUILT_IN_RULES.length,
    by_category,
    by_severity,
    by_compliance,
  };
}

// Re-export types
export type { ScanRule, RuleContext, EnterpriseFinding, ComplianceMapping, RuleCategory } from "./interface";
export { createEnterpriseFinding } from "./interface";
