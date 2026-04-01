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
}

export interface PolicyIgnoreEntry {
  path?: string;
  reason: string;
  expires?: string;
  approved_by?: string;
  ticket?: string;
}

export type ScanPreset = "strict" | "standard" | "monitor";

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
      // Simple YAML-like parsing for the policy file structure
      // In production, use yaml package — for now, parse the structured format
      const policy = parseSimpleYAML(content);
      return { policy, warnings };
    } catch (error: unknown) {
      warnings.push(
        `Failed to parse ${filename}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  return { policy: null, warnings };
}

/**
 * Simple structured parser for the policy YAML.
 * Handles the specific schema we define — not a full YAML parser.
 * Production version should use the `yaml` npm package.
 */
function parseSimpleYAML(content: string): PolicyFile {
  const policy: PolicyFile = { version: "v1" };

  // Extract version
  const versionMatch = content.match(/^version:\s*(.+)$/m);
  if (versionMatch?.[1]) {
    policy.version = versionMatch[1].trim();
  }

  // Extract preset
  const presetMatch = content.match(/^preset:\s*(.+)$/m);
  if (presetMatch?.[1]) {
    const preset = presetMatch[1].trim() as ScanPreset;
    if (["strict", "standard", "monitor"].includes(preset)) {
      policy.preset = preset;
    }
  }

  // Extract severity overrides (simple key: value pairs under severity_overrides:)
  const overridesBlock = content.match(
    /severity_overrides:\s*\n((?:\s+\S+.*\n)*)/
  );
  if (overridesBlock?.[1]) {
    policy.severity_overrides = {};
    const lines = overridesBlock[1].split("\n");
    for (const line of lines) {
      const kvMatch = line.match(/^\s+(SF-[A-Z]+-\d+):\s*(.+)$/);
      if (kvMatch?.[1] && kvMatch[2]) {
        policy.severity_overrides[kvMatch[1]] = kvMatch[2].trim();
      }
    }
  }

  // Extract exclude patterns
  const excludeBlock = content.match(/exclude:\s*\n((?:\s+-\s+.+\n)*)/);
  if (excludeBlock?.[1]) {
    policy.exclude = [];
    const lines = excludeBlock[1].split("\n");
    for (const line of lines) {
      const itemMatch = line.match(/^\s+-\s+"?([^"]+)"?\s*$/);
      if (itemMatch?.[1]) {
        policy.exclude.push(itemMatch[1]);
      }
    }
  }

  // Extract ignore rules (structured blocks under ignore:)
  const ignoreBlock = content.match(/ignore:\s*\n([\s\S]*?)(?=\n\w|\n*$)/);
  if (ignoreBlock?.[1]) {
    policy.ignore = {};
    const ruleBlocks = ignoreBlock[1].split(/\n\s{2}(SF-[A-Z]+-\d+):/);

    for (let i = 1; i < ruleBlocks.length; i += 2) {
      const ruleId = ruleBlocks[i];
      const blockContent = ruleBlocks[i + 1] ?? "";
      if (!ruleId) continue;

      const entries: PolicyIgnoreEntry[] = [];
      const entryChunks = blockContent.split(/\n\s{4}- /);

      for (const chunk of entryChunks) {
        if (!chunk.trim()) continue;
        const entry: PolicyIgnoreEntry = { reason: "" };

        const pathMatch = chunk.match(/path:\s*"?([^"\n]+)"?/);
        if (pathMatch?.[1]) entry.path = pathMatch[1].trim();

        const reasonMatch = chunk.match(/reason:\s*"?([^"\n]+)"?/);
        if (reasonMatch?.[1]) entry.reason = reasonMatch[1].trim();

        const expiresMatch = chunk.match(/expires:\s*"?([^"\n]+)"?/);
        if (expiresMatch?.[1]) entry.expires = expiresMatch[1].trim();

        const approvedMatch = chunk.match(/approved_by:\s*"?([^"\n]+)"?/);
        if (approvedMatch?.[1]) entry.approved_by = approvedMatch[1].trim();

        const ticketMatch = chunk.match(/ticket:\s*"?([^"\n]+)"?/);
        if (ticketMatch?.[1]) entry.ticket = ticketMatch[1].trim();

        if (entry.reason) entries.push(entry);
      }

      if (entries.length > 0) {
        policy.ignore[ruleId] = entries;
      }
    }
  }

  return policy;
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
