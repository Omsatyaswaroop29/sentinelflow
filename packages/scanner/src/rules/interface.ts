/**
 * @module @sentinelflow/scanner/rules/interface
 *
 * Enterprise-grade rule interface with compliance framework mappings,
 * rule lifecycle management, auto-fix suggestions, false-positive
 * patterns, and suppression support with audit trails.
 *
 * Every rule maps to OWASP LLM Top 10, NIST AI RMF, EU AI Act,
 * MITRE ATLAS, HIPAA, SOC 2, and/or ISO 42001.
 */

import type {
  SentinelFlowAgent,
  AgentFramework,
  Finding,
  FindingCategory,
  FindingSeverity,
} from "@sentinelflow/core";
import type { ConfigFile } from "@sentinelflow/parsers";

// ─── Compliance Framework References ────────────────────────────

export interface ComplianceMapping {
  framework: ComplianceFramework;
  reference: string;       // e.g., "Article 14", "CC6.1", "LLM01:2025"
  description?: string;    // Short description of the requirement
}

export type ComplianceFramework =
  | "OWASP_LLM_2025"
  | "NIST_AI_RMF"
  | "EU_AI_ACT"
  | "MITRE_ATLAS"
  | "HIPAA"
  | "SOC2"
  | "ISO_42001"
  | "NIST_AI_600_1"
  | "GDPR"
  | "COLORADO_AI_ACT";

// ─── Rule Categories (expanded from 5 to 10) ───────────────────

export type RuleCategory =
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

// ─── Rule Lifecycle ─────────────────────────────────────────────

/** Where a rule is in its lifecycle — determines visibility and defaults */
export type RuleLifecycle =
  | "stable"         // Production-ready, enabled by default
  | "experimental"   // New rule, may have higher FP rate, opt-in
  | "deprecated"     // Superseded, will be removed in a future version
  | "disabled";      // Known issues, temporarily disabled

/** Auto-fix suggestion that can be shown in CLI or applied programmatically */
export interface AutoFix {
  /** What the fix does, in plain English */
  description: string;
  /** The file path pattern this fix applies to (glob or exact) */
  file_pattern?: string;
  /** The string/regex to find */
  find?: string;
  /** The replacement string */
  replace?: string;
  /** Complete replacement content for the section (when find/replace is insufficient) */
  suggested_config?: string;
}

/** Known false positive pattern with description of when this rule misfires */
export interface FalsePositivePattern {
  /** When this FP occurs (e.g., "CI-only environments with no production access") */
  condition: string;
  /** Recommended action (e.g., "Suppress with: # sentinelflow-ignore: SF-FC-001 -- CI sandbox") */
  recommended_action: string;
}

/** Framework version compatibility for the rule */
export interface FrameworkCompat {
  framework: string;
  min_version?: string;   // Minimum framework version (e.g., "1.0.0")
  max_version?: string;   // Maximum framework version (e.g., "2.99.99")
}

// ─── Rule Context ───────────────────────────────────────────────

export interface RuleContext {
  agents: SentinelFlowAgent[];
  config_files: ConfigFile[];
  root_dir: string;
  /** Loaded policy file suppressions (if .sentinelflow-policy.yaml exists) */
  suppressions?: SuppressionEntry[];
  /** Active scan preset */
  preset?: ScanPreset;
}

export type ScanPreset = "strict" | "standard" | "monitor";

// ─── Suppression System ─────────────────────────────────────────

/** A single suppression entry from .sentinelflow-policy.yaml or inline comment */
export interface SuppressionEntry {
  rule_id: string;
  path?: string;            // File glob pattern (e.g., "agents/legacy-*.yaml")
  reason: string;           // Why this is suppressed — mandatory for audit
  expires?: string;         // ISO 8601 date — suppression auto-expires
  approved_by?: string;     // Who approved the suppression
  ticket?: string;          // Jira/Linear ticket reference
  source: "inline" | "policy_file" | "cli";
}

/** The full .sentinelflow-policy.yaml schema */
export interface PolicyFile {
  version: "v1";
  ignore?: Record<string, PolicyIgnoreEntry[]>;
  severity_overrides?: Record<string, FindingSeverity>;
  exclude?: string[];       // Glob patterns for files to skip entirely
  preset?: ScanPreset;
}

export interface PolicyIgnoreEntry {
  path?: string;
  reason: string;
  expires?: string;
  approved_by?: string;
  ticket?: string;
}

/** Result of checking whether a finding is suppressed */
export interface SuppressionResult {
  suppressed: boolean;
  entry?: SuppressionEntry;
  expired?: boolean;        // True if suppression exists but has expired
}

// ─── Enterprise Finding (extends core Finding) ──────────────────

export interface EnterpriseFinding extends Finding {
  compliance: ComplianceMapping[];
  cwe?: string;            // CWE ID if applicable (e.g., "CWE-798")
  cve?: string[];          // Related CVEs if applicable
  mitre_atlas?: string;    // MITRE ATLAS TTP (e.g., "AML.T0051")
  remediation_effort?: "low" | "medium" | "high";
  false_positive_rate?: "low" | "medium" | "high";
  /** Auto-fix suggestion if available */
  auto_fix?: AutoFix;
  /** Whether this finding was suppressed (and by what) */
  suppression?: SuppressionResult;
}

// ─── Scan Rule ──────────────────────────────────────────────────

export type RulePhase = "static" | "runtime" | "both";

export interface ScanRule {
  /** Unique rule ID: SF-<CATEGORY>-<NUMBER> */
  id: string;
  /** Human-readable name */
  name: string;
  /** What this rule detects */
  description: string;
  /** Rule category */
  category: RuleCategory;
  /** Default severity */
  severity: FindingSeverity;
  /** Which frameworks this applies to */
  frameworks: AgentFramework[] | "all";
  /** Compliance framework mappings */
  compliance: ComplianceMapping[];
  /** Whether this rule runs on static config or needs runtime data */
  phase: RulePhase;

  // ─── Lifecycle fields (Phase 1.5) ─────────────────────────────

  /** Rule lifecycle state — defaults to "stable" if omitted */
  lifecycle?: RuleLifecycle;
  /** When this rule was introduced (semver, e.g., "0.1.0") */
  since?: string;
  /** If deprecated, which rule supersedes it */
  superseded_by?: string;
  /** Auto-fix suggestions for this rule's findings */
  auto_fix?: AutoFix;
  /** Known false positive patterns — helps users decide whether to suppress */
  known_false_positives?: FalsePositivePattern[];
  /** Framework version compatibility — rule is skipped outside these bounds */
  framework_compat?: FrameworkCompat[];
  /** Docs URL for this rule (overrides default pattern) */
  docs_url?: string;

  /** Run the rule and return findings */
  evaluate(context: RuleContext): EnterpriseFinding[];
}

// ─── Helper: Create a finding with compliance data ──────────────

export function createEnterpriseFinding(
  rule: ScanRule,
  params: {
    id: string;
    title: string;
    description: string;
    recommendation: string;
    agent_id?: string;
    agent_name?: string;
    framework?: string;
    location?: { file: string; line?: number; snippet?: string };
    cwe?: string;
    cve?: string[];
    mitre_atlas?: string;
    remediation_effort?: "low" | "medium" | "high";
    metadata?: Record<string, unknown>;
    auto_fix?: AutoFix;
  }
): EnterpriseFinding {
  return {
    id: params.id,
    rule_id: rule.id,
    rule_name: rule.name,
    severity: rule.severity,
    category: rule.category as FindingCategory,
    title: params.title,
    description: params.description,
    recommendation: params.recommendation,
    agent_id: params.agent_id,
    agent_name: params.agent_name,
    framework: params.framework,
    location: params.location,
    compliance: rule.compliance,
    cwe: params.cwe,
    cve: params.cve,
    mitre_atlas: params.mitre_atlas,
    remediation_effort: params.remediation_effort,
    auto_fix: params.auto_fix ?? rule.auto_fix,
    metadata: params.metadata,
    first_detected: new Date().toISOString(),
    status: "open",
  };
}

// ─── Helper: Check if a finding is suppressed ───────────────────

/**
 * Check suppressions from inline comments and policy file against a finding.
 * Returns suppressed=true if a valid (non-expired) suppression matches.
 */
export function checkSuppression(
  ruleId: string,
  filePath: string | undefined,
  suppressions: SuppressionEntry[],
  now: Date = new Date()
): SuppressionResult {
  for (const entry of suppressions) {
    if (entry.rule_id !== ruleId) continue;

    // Check path match (if specified)
    if (entry.path && filePath) {
      const pattern = entry.path.replace(/\*/g, ".*");
      if (!new RegExp(`^${pattern}$`).test(filePath)) continue;
    }

    // Check expiration
    if (entry.expires) {
      const expiresDate = new Date(entry.expires);
      if (now > expiresDate) {
        return { suppressed: false, entry, expired: true };
      }
    }

    return { suppressed: true, entry };
  }

  return { suppressed: false };
}

// ─── Helper: Parse inline suppression comments ──────────────────

const INLINE_SUPPRESS_PATTERN =
  /[#\/\/]\s*sentinelflow-ignore:\s*(SF-[A-Z]+-\d+)\s*(?:--\s*(.+))?$/;

/**
 * Scan file content for inline `# sentinelflow-ignore: SF-XX-NNN -- reason` comments.
 * Returns suppression entries for any found.
 */
export function parseInlineSuppressions(
  filePath: string,
  content: string
): SuppressionEntry[] {
  const entries: SuppressionEntry[] = [];
  const lines = content.split("\n");
  for (const line of lines) {
    const match = INLINE_SUPPRESS_PATTERN.exec(line);
    if (match && match[1]) {
      entries.push({
        rule_id: match[1],
        path: filePath,
        reason: match[2]?.trim() ?? "No justification provided",
        source: "inline",
      });
    }
  }
  return entries;
}

// ─── Helper: Default docs URL for a rule ────────────────────────

export function getRuleDocsUrl(rule: ScanRule): string {
  return rule.docs_url ?? `https://sentinelflow.dev/rules/${rule.id}`;
}
