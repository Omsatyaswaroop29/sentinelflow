/**
 * @module @sentinelflow/scanner/suppression
 *
 * Multi-layer finding suppression with audit trails.
 *
 * Three suppression layers (ordered by specificity):
 *   1. Inline comments: `# sentinelflow-ignore: SF-AC-001 -- reason`
 *   2. Policy file: `.sentinelflow-policy.yaml` with expiration + approval
 *   3. CLI preset: --preset monitor|standard|strict
 *
 * Design principles:
 *   - Every suppression requires a justification (no blanket ignores)
 *   - Suppressions expire — stale ignores resurface automatically
 *   - `--show-suppressed` reveals everything hidden, for audit
 *   - The suppression record itself is auditable evidence (who, when, why, ticket)
 */

import * as fs from "fs";
import * as path from "path";
import * as YAML from "yaml";
import type { EnterpriseFinding } from "./rules/interface";

// ─── Types ──────────────────────────────────────────────────

export interface SuppressionRecord {
  rule_id: string;
  reason: string;
  source: "inline" | "policy" | "preset";
  path_pattern?: string;      // glob pattern for which files this applies to
  expires?: string;           // ISO 8601 — suppression auto-expires after this date
  approved_by?: string;       // Who approved the suppression
  ticket?: string;            // Jira/Linear/GitHub issue reference
  created_at?: string;        // When the suppression was added
}

export interface SuppressionResult {
  /** Findings that passed suppression (should be reported) */
  active: EnterpriseFinding[];
  /** Findings that were suppressed (hidden unless --show-suppressed) */
  suppressed: Array<{
    finding: EnterpriseFinding;
    suppression: SuppressionRecord;
  }>;
  /** Suppressions that have expired and should be cleaned up */
  expired_suppressions: SuppressionRecord[];
  /** Policy parse warnings */
  warnings: string[];
}

export interface PolicyFile {
  version: string;
  ignore?: Record<string, PolicyIgnoreEntry[]>;
  severity_overrides?: Record<string, string>;
  exclude?: string[];
  preset?: "strict" | "standard" | "monitor";
  runtime_policies?: RuntimePoliciesConfig;
}

export interface PolicyIgnoreEntry {
  path?: string;
  reason: string;
  expires?: string;
  approved_by?: string;
  ticket?: string;
}

export type ScanPreset = "strict" | "standard" | "monitor";

export type DataClassificationLevel = "public" | "internal" | "restricted" | "system";

export interface RuntimeAgentClearance {
  agent: string;
  max_classification: DataClassificationLevel;
}

export interface RuntimeClassificationRule {
  pattern: string;
  classification: DataClassificationLevel;
  label?: string;
}

export interface RuntimeDataBoundaryConfig {
  enabled?: boolean;
  enforcement_mode?: "monitor" | "enforce";
  default_max_classification?: DataClassificationLevel;
  agent_clearances?: RuntimeAgentClearance[];
  custom_rules?: RuntimeClassificationRule[];
}

export interface RuntimeIdentityConfig {
  enabled?: boolean;
  enforcement_mode?: "monitor" | "enforce";
  human_owner?: string;
  human_email?: string;
  team?: string;
  environment?: "development" | "staging" | "production" | "ci";
  role?: "reader" | "writer" | "executor" | "deployer" | "admin" | "custom";
  privilege_level?: number;
  external_facing?: boolean;
  agent_roles?: Record<string, string>;
  agent_privileges?: Record<string, number>;
}

export interface RuntimeSequenceDetectionConfig {
  enabled?: boolean;
  enforcement_mode?: "monitor" | "enforce";
  window_minutes?: number;
  min_confidence?: number;
}

export interface RuntimePoliciesConfig {
  blocked_tools?: string[];
  allowed_tools?: string[];
  max_cost_per_session?: number;
  enforcement_mode?: "monitor" | "enforce";
  egress_allowed_domains?: string[];
  egress_blocked_domains?: string[];
  data_boundary?: RuntimeDataBoundaryConfig;
  identity?: RuntimeIdentityConfig;
  sequence_detection?: RuntimeSequenceDetectionConfig;
}

// ─── Inline Suppression Parser ──────────────────────────────

/**
 * Parse inline `# sentinelflow-ignore: RULE-ID -- justification` comments
 * from config file content.
 *
 * Syntax: `# sentinelflow-ignore: <rule-id> -- <reason>`
 * The `--` separator and reason are REQUIRED. Bare ignores without
 * justification are flagged as warnings (not honored by default).
 *
 * Returns a map of file:line → suppression record.
 */
export function parseInlineSuppressions(
  filePath: string,
  content: string
): Map<string, SuppressionRecord> {
  const suppressions = new Map<string, SuppressionRecord>();

  // Match both # and // comment styles
  const pattern =
    /(?:#|\/\/)\s*sentinelflow-ignore:\s*(SF-[A-Z]+-\d+)\s*(?:--\s*(.+))?$/gm;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    const lineNum =
      content.substring(0, match.index).split("\n").length;
    const ruleId = match[1]!;
    const reason = match[2]?.trim() ?? "";

    const key = `${filePath}:${lineNum}`;
    suppressions.set(key, {
      rule_id: ruleId,
      reason,
      source: "inline",
      path_pattern: filePath,
    });
  }

  return suppressions;
}

// ─── Policy File Parser ─────────────────────────────────────

const POLICY_FILENAMES = [
  ".sentinelflow-policy.yaml",
  ".sentinelflow-policy.yml",
  ".sentinelflow.yaml",
  ".sentinelflow.yml",
];

/**
 * Load and parse the .sentinelflow-policy.yaml file from the project root.
 * Returns null if no policy file exists (which is fine — policy is optional).
 */
export function loadPolicyFile(rootDir: string): {
  policy: PolicyFile | null;
  warnings: string[];
} {
  const warnings: string[] = [];

  for (const filename of POLICY_FILENAMES) {
    const filePath = path.join(rootDir, filename);
    if (!fs.existsSync(filePath)) continue;

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const parsed = YAML.parse(content) as Record<string, unknown> | null;
      const policy = normalizePolicyFile(parsed ?? {}, warnings);
      return { policy, warnings };
    } catch (error: unknown) {
      warnings.push(
        `Failed to parse ${filename}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  return { policy: null, warnings };
}

const VALID_PRESETS: ScanPreset[] = ["strict", "standard", "monitor"];
const VALID_CLASSIFICATIONS: DataClassificationLevel[] = ["public", "internal", "restricted", "system"];
const VALID_ENFORCEMENT_MODES = ["monitor", "enforce"];

/**
 * Normalize a raw parsed YAML object into a well-typed PolicyFile,
 * tolerating unknown/malformed fields (warns instead of throwing —
 * a malformed policy file should never take down a scan).
 */
function normalizePolicyFile(raw: Record<string, unknown>, warnings: string[]): PolicyFile {
  const policy: PolicyFile = { version: typeof raw.version === "string" ? raw.version : "v1" };

  if (typeof raw.preset === "string" && VALID_PRESETS.includes(raw.preset as ScanPreset)) {
    policy.preset = raw.preset as ScanPreset;
  }

  if (isPlainObject(raw.severity_overrides)) {
    policy.severity_overrides = {};
    for (const [ruleId, severity] of Object.entries(raw.severity_overrides)) {
      if (typeof severity === "string") policy.severity_overrides[ruleId] = severity;
    }
  }

  if (Array.isArray(raw.exclude)) {
    policy.exclude = raw.exclude.filter((e): e is string => typeof e === "string");
  }

  if (isPlainObject(raw.ignore)) {
    policy.ignore = {};
    for (const [ruleId, entries] of Object.entries(raw.ignore)) {
      if (!Array.isArray(entries)) continue;
      const parsedEntries: PolicyIgnoreEntry[] = [];
      for (const entry of entries) {
        if (!isPlainObject(entry) || typeof entry.reason !== "string" || !entry.reason) continue;
        parsedEntries.push({
          reason: entry.reason,
          path: typeof entry.path === "string" ? entry.path : undefined,
          expires: typeof entry.expires === "string" ? entry.expires : undefined,
          approved_by: typeof entry.approved_by === "string" ? entry.approved_by : undefined,
          ticket: typeof entry.ticket === "string" ? entry.ticket : undefined,
        });
      }
      if (parsedEntries.length > 0) policy.ignore[ruleId] = parsedEntries;
    }
  }

  if (isPlainObject(raw.runtime_policies)) {
    policy.runtime_policies = normalizeRuntimePolicies(raw.runtime_policies, warnings);
  }

  return policy;
}

function normalizeRuntimePolicies(raw: Record<string, unknown>, warnings: string[]): RuntimePoliciesConfig {
  const rp: RuntimePoliciesConfig = {};

  if (Array.isArray(raw.blocked_tools)) {
    rp.blocked_tools = raw.blocked_tools.filter((t): t is string => typeof t === "string");
  }
  if (Array.isArray(raw.allowed_tools)) {
    rp.allowed_tools = raw.allowed_tools.filter((t): t is string => typeof t === "string");
  }
  if (typeof raw.max_cost_per_session === "number") {
    rp.max_cost_per_session = raw.max_cost_per_session;
  }
  if (typeof raw.enforcement_mode === "string" && VALID_ENFORCEMENT_MODES.includes(raw.enforcement_mode)) {
    rp.enforcement_mode = raw.enforcement_mode as "monitor" | "enforce";
  }
  if (Array.isArray(raw.egress_allowed_domains)) {
    rp.egress_allowed_domains = raw.egress_allowed_domains.filter((d): d is string => typeof d === "string");
  }
  if (Array.isArray(raw.egress_blocked_domains)) {
    rp.egress_blocked_domains = raw.egress_blocked_domains.filter((d): d is string => typeof d === "string");
  }

  if (isPlainObject(raw.data_boundary)) {
    const db = raw.data_boundary;
    const parsed: RuntimeDataBoundaryConfig = {};
    if (typeof db.enabled === "boolean") parsed.enabled = db.enabled;
    if (typeof db.enforcement_mode === "string" && VALID_ENFORCEMENT_MODES.includes(db.enforcement_mode)) {
      parsed.enforcement_mode = db.enforcement_mode as "monitor" | "enforce";
    }
    if (typeof db.default_max_classification === "string" && VALID_CLASSIFICATIONS.includes(db.default_max_classification as DataClassificationLevel)) {
      parsed.default_max_classification = db.default_max_classification as DataClassificationLevel;
    }
    if (Array.isArray(db.agent_clearances)) {
      parsed.agent_clearances = [];
      for (const c of db.agent_clearances) {
        if (isPlainObject(c) && typeof c.agent === "string" &&
            typeof c.max_classification === "string" &&
            VALID_CLASSIFICATIONS.includes(c.max_classification as DataClassificationLevel)) {
          parsed.agent_clearances.push({ agent: c.agent, max_classification: c.max_classification as DataClassificationLevel });
        } else {
          warnings.push("runtime_policies.data_boundary.agent_clearances: skipped malformed entry");
        }
      }
    }
    if (Array.isArray(db.custom_rules)) {
      parsed.custom_rules = [];
      for (const r of db.custom_rules) {
        if (isPlainObject(r) && typeof r.pattern === "string" &&
            typeof r.classification === "string" &&
            VALID_CLASSIFICATIONS.includes(r.classification as DataClassificationLevel)) {
          parsed.custom_rules.push({
            pattern: r.pattern,
            classification: r.classification as DataClassificationLevel,
            label: typeof r.label === "string" ? r.label : undefined,
          });
        } else {
          warnings.push("runtime_policies.data_boundary.custom_rules: skipped malformed entry");
        }
      }
    }
    rp.data_boundary = parsed;
  }

  if (isPlainObject(raw.identity)) {
    const id = raw.identity;
    const parsed: RuntimeIdentityConfig = {};
    if (typeof id.enabled === "boolean") parsed.enabled = id.enabled;
    if (typeof id.enforcement_mode === "string" && VALID_ENFORCEMENT_MODES.includes(id.enforcement_mode)) {
      parsed.enforcement_mode = id.enforcement_mode as "monitor" | "enforce";
    }
    if (typeof id.human_owner === "string") parsed.human_owner = id.human_owner;
    if (typeof id.human_email === "string") parsed.human_email = id.human_email;
    if (typeof id.team === "string") parsed.team = id.team;
    if (typeof id.environment === "string" && ["development", "staging", "production", "ci"].includes(id.environment)) {
      parsed.environment = id.environment as RuntimeIdentityConfig["environment"];
    }
    if (typeof id.role === "string" && ["reader", "writer", "executor", "deployer", "admin", "custom"].includes(id.role)) {
      parsed.role = id.role as RuntimeIdentityConfig["role"];
    }
    if (typeof id.privilege_level === "number") parsed.privilege_level = id.privilege_level;
    if (typeof id.external_facing === "boolean") parsed.external_facing = id.external_facing;
    if (isPlainObject(id.agent_roles)) {
      parsed.agent_roles = {};
      for (const [agent, role] of Object.entries(id.agent_roles)) {
        if (typeof role === "string") parsed.agent_roles[agent] = role;
      }
    }
    if (isPlainObject(id.agent_privileges)) {
      parsed.agent_privileges = {};
      for (const [agent, level] of Object.entries(id.agent_privileges)) {
        if (typeof level === "number") parsed.agent_privileges[agent] = level;
      }
    }
    rp.identity = parsed;
  }

  if (isPlainObject(raw.sequence_detection)) {
    const sd = raw.sequence_detection;
    const parsed: RuntimeSequenceDetectionConfig = {};
    if (typeof sd.enabled === "boolean") parsed.enabled = sd.enabled;
    if (typeof sd.enforcement_mode === "string" && VALID_ENFORCEMENT_MODES.includes(sd.enforcement_mode)) {
      parsed.enforcement_mode = sd.enforcement_mode as "monitor" | "enforce";
    }
    if (typeof sd.window_minutes === "number") parsed.window_minutes = sd.window_minutes;
    if (typeof sd.min_confidence === "number") parsed.min_confidence = sd.min_confidence;
    rp.sequence_detection = parsed;
  }

  return rp;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ─── Suppression Engine ─────────────────────────────────────

/**
 * Apply all suppression layers to a set of findings.
 *
 * Order of evaluation:
 *   1. Check if the file is in the policy exclude list
 *   2. Check for inline sentinelflow-ignore comments
 *   3. Check policy file ignore entries (with expiration check)
 *   4. Apply severity overrides from policy
 *
 * Returns the filtered findings plus audit information about what was suppressed.
 */
export function applySuppressions(
  findings: EnterpriseFinding[],
  configFiles: Array<{ path: string; content: string }>,
  rootDir: string,
  options?: { showSuppressed?: boolean }
): SuppressionResult {
  const result: SuppressionResult = {
    active: [],
    suppressed: [],
    expired_suppressions: [],
    warnings: [],
  };

  // Load policy file
  const { policy, warnings: policyWarnings } = loadPolicyFile(rootDir);
  result.warnings.push(...policyWarnings);

  // Collect all inline suppressions from config files
  const allInlineSuppressions = new Map<string, SuppressionRecord>();
  for (const file of configFiles) {
    const fileSups = parseInlineSuppressions(file.path, file.content);
    for (const [key, sup] of fileSups) {
      allInlineSuppressions.set(key, sup);
    }
  }

  // Warn about unjustified inline ignores
  for (const [location, sup] of allInlineSuppressions) {
    if (!sup.reason) {
      result.warnings.push(
        `Unjustified suppression at ${location}: ` +
          `"# sentinelflow-ignore: ${sup.rule_id}" requires a justification after "--". ` +
          `Example: # sentinelflow-ignore: ${sup.rule_id} -- Accepted risk per SEC-1234`
      );
    }
  }

  const now = new Date();

  // Check for expired policy suppressions
  if (policy?.ignore) {
    for (const [ruleId, entries] of Object.entries(policy.ignore)) {
      for (const entry of entries) {
        if (entry.expires) {
          const expiryDate = new Date(entry.expires);
          if (expiryDate < now) {
            result.expired_suppressions.push({
              rule_id: ruleId,
              reason: entry.reason,
              source: "policy",
              path_pattern: entry.path,
              expires: entry.expires,
              approved_by: entry.approved_by,
              ticket: entry.ticket,
            });
          }
        }
      }
    }
  }

  // Process each finding
  for (const finding of findings) {
    let suppression: SuppressionRecord | null = null;

    // Check 1: Is the finding's file in the exclude list?
    if (policy?.exclude && finding.location?.file) {
      const relPath = path.relative(rootDir, finding.location.file);
      for (const pattern of policy.exclude) {
        if (matchGlob(relPath, pattern)) {
          suppression = {
            rule_id: finding.rule_id,
            reason: `File excluded by policy: ${pattern}`,
            source: "policy",
            path_pattern: pattern,
          };
          break;
        }
      }
    }

    // Check 2: Inline suppression on the same file+line
    if (!suppression && finding.location?.file && finding.location?.line) {
      const key = `${finding.location.file}:${finding.location.line}`;
      const inlineSup = allInlineSuppressions.get(key);
      if (inlineSup && inlineSup.rule_id === finding.rule_id && inlineSup.reason) {
        suppression = inlineSup;
      }
      // Also check the line above (common pattern: ignore comment on preceding line)
      const keyAbove = `${finding.location.file}:${finding.location.line - 1}`;
      const inlineSupAbove = allInlineSuppressions.get(keyAbove);
      if (!suppression && inlineSupAbove && inlineSupAbove.rule_id === finding.rule_id && inlineSupAbove.reason) {
        suppression = inlineSupAbove;
      }
    }

    // Check 3: Policy file ignore entries (non-expired only)
    if (!suppression && policy?.ignore) {
      const policyEntries = policy.ignore[finding.rule_id];
      if (policyEntries) {
        for (const entry of policyEntries) {
          // Check expiration
          if (entry.expires && new Date(entry.expires) < now) {
            continue; // Expired — don't suppress
          }

          // Check path pattern if specified
          if (entry.path && finding.location?.file) {
            const relPath = path.relative(rootDir, finding.location.file);
            if (!matchGlob(relPath, entry.path)) {
              continue; // Path doesn't match
            }
          }

          suppression = {
            rule_id: finding.rule_id,
            reason: entry.reason,
            source: "policy",
            path_pattern: entry.path,
            expires: entry.expires,
            approved_by: entry.approved_by,
            ticket: entry.ticket,
          };
          break;
        }
      }
    }

    // Apply severity overrides (even if not suppressed)
    if (policy?.severity_overrides?.[finding.rule_id]) {
      const override = policy.severity_overrides[finding.rule_id] as string;
      if (["critical", "high", "medium", "low", "info"].includes(override)) {
        finding.severity = override as EnterpriseFinding["severity"];
      }
    }

    // Route finding to active or suppressed
    if (suppression) {
      result.suppressed.push({ finding, suppression });
    } else {
      result.active.push(finding);
    }
  }

  return result;
}

// ─── Glob Matching (simple) ─────────────────────────────────

/**
 * Simple glob matching for policy file paths.
 * Supports * (any segment) and ** (any depth).
 */
function matchGlob(filePath: string, pattern: string): boolean {
  const regexStr = pattern
    .replace(/\./g, "\\.")
    .replace(/\*\*/g, "§DOUBLESTAR§")
    .replace(/\*/g, "[^/]*")
    .replace(/§DOUBLESTAR§/g, ".*");
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(filePath);
}

// ─── Preset Definitions ─────────────────────────────────────

export const PRESETS: Record<
  ScanPreset,
  { exitOnSeverities: string[]; description: string }
> = {
  strict: {
    exitOnSeverities: ["critical", "high", "medium"],
    description: "Production governance. CI fails on medium and above.",
  },
  standard: {
    exitOnSeverities: ["critical", "high"],
    description: "Active development. CI fails on high and above. (Default)",
  },
  monitor: {
    exitOnSeverities: [],
    description: "Adoption mode. All findings reported, CI never fails.",
  },
};
