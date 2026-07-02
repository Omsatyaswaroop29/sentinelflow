/**
 * @module @sentinelflow/interceptors/data-boundary
 *
 * Enhanced data boundary governance with path classification.
 *
 * Moves from checking `input_summary` strings to parsing actual
 * structured tool_input content and classifying paths by sensitivity.
 *
 * Path Classification Levels:
 *   - public:      Source code, docs, test files — any agent can access
 *   - internal:    Internal configs, logs, build artifacts — read with caution
 *   - restricted:  Credentials, keys, secrets, PII — block by default
 *   - system:      OS/system files — block always
 *
 * How It Works:
 *   1. Extracts all paths from the event (tool_input JSON, input_summary, metadata)
 *   2. Classifies each path using configurable rules
 *   3. Checks if the agent's clearance level allows access to that classification
 *   4. Blocks if the agent doesn't have sufficient clearance
 *
 * This aligns with:
 *   - Data-layer governance (Kiteworks, Varonis-style data classification)
 *   - EU AI Act Article 10 (data governance requirements)
 *   - NIST AI RMF Govern 1.5 (data management and access controls)
 *   - Least-privilege recommendations in enterprise LLM guidance
 */

import type { AgentEvent, AnomalyResult } from "@sentinelflow/core";
import type { PolicyProvider, PolicyEvaluationResult } from "./interface";

// ─── Classification Types ───────────────────────────────────────────

export type DataClassification = "public" | "internal" | "restricted" | "system";

/** Numeric levels for comparison: higher = more sensitive */
const CLASSIFICATION_LEVEL: Record<DataClassification, number> = {
  public: 0,
  internal: 1,
  restricted: 2,
  system: 3,
};

export interface ClassificationRule {
  /** Regex pattern matching file paths */
  pattern: string;
  /** What classification to assign */
  classification: DataClassification;
  /** Human-readable label */
  label: string;
}

export interface AgentClearance {
  /** Agent ID or pattern (supports * wildcard) */
  agent: string;
  /** Maximum classification this agent can access */
  maxClassification: DataClassification;
}

// ─── Default Classification Rules ───────────────────────────────────

/**
 * Built-in path classification rules.
 * Ordered from most specific to least specific — first match wins.
 */
export const DEFAULT_CLASSIFICATION_RULES: ClassificationRule[] = [
  // ── SYSTEM (most restricted) ──────────────────────────────
  { pattern: "^/etc/",                    classification: "system",     label: "System configuration" },
  { pattern: "^/usr/",                    classification: "system",     label: "System binaries" },
  { pattern: "^/var/log/",               classification: "system",     label: "System logs" },
  { pattern: "^/dev/",                    classification: "system",     label: "Device files" },
  { pattern: "^/proc/",                   classification: "system",     label: "Process info" },

  // ── RESTRICTED (secrets, credentials, keys) ───────────────
  { pattern: "\\.ssh/",                   classification: "restricted", label: "SSH keys/config" },
  { pattern: "\\.gnupg/",                 classification: "restricted", label: "GPG keys" },
  { pattern: "\\.aws/",                   classification: "restricted", label: "AWS credentials" },
  { pattern: "\\.kube/",                  classification: "restricted", label: "Kubernetes config" },
  { pattern: "\\.docker/",               classification: "restricted", label: "Docker config" },
  { pattern: "(?:^|/)\\.env(?:\\..+)?$",  classification: "restricted", label: "Environment variables" },
  { pattern: "(?:^|/)\\.npmrc$",          classification: "restricted", label: "npm credentials" },
  { pattern: "(?:^|/)\\.netrc$",          classification: "restricted", label: "Network credentials" },
  { pattern: "\\.pem$",                   classification: "restricted", label: "PEM certificate/key" },
  { pattern: "\\.key$",                   classification: "restricted", label: "Private key file" },
  { pattern: "\\.p12$",                   classification: "restricted", label: "PKCS#12 key store" },
  { pattern: "(?:secret|credential|password|token)s?(?:\\.json|\\.yaml|\\.yml|\\.toml|\\.txt)$",
                                          classification: "restricted", label: "Secrets file" },
  { pattern: "id_(?:rsa|ed25519|ecdsa|dsa)(?:\\.pub)?$",
                                          classification: "restricted", label: "SSH key file" },

  // ── INTERNAL (configs, CI/CD, build, logs) ────────────────
  { pattern: "\\.github/",               classification: "internal",   label: "GitHub config/CI" },
  { pattern: "\\.gitlab-ci",             classification: "internal",   label: "GitLab CI" },
  { pattern: "(?:^|/)Jenkinsfile$",      classification: "internal",   label: "Jenkins pipeline" },
  { pattern: "(?:^|/)Dockerfile",        classification: "internal",   label: "Docker build" },
  { pattern: "docker-compose",           classification: "internal",   label: "Docker Compose" },
  { pattern: "(?:^|/)package\\.json$",   classification: "internal",   label: "Package manifest" },
  { pattern: "(?:^|/)tsconfig\\.json$",  classification: "internal",   label: "TypeScript config" },
  { pattern: "(?:^|/)\\.",               classification: "internal",   label: "Hidden/config file" },
  { pattern: "(?:^|/)node_modules/",     classification: "internal",   label: "Dependencies" },
  { pattern: "(?:^|/)dist/",            classification: "internal",   label: "Build output" },
  { pattern: "\\.log$",                  classification: "internal",   label: "Log file" },

  // Everything else is public (source code, docs, tests)
];

// ─── Path Extraction ────────────────────────────────────────────────

/**
 * Extract all file paths from an AgentEvent.
 * Looks in multiple places: tool input summary, metadata, and
 * attempts to parse structured tool_input if available.
 */
export function extractPaths(event: AgentEvent): string[] {
  const paths: string[] = [];

  // 1. Extract from input_summary
  const summary = event.tool?.input_summary ?? "";
  if (summary) {
    // "file: /path/to/file" format
    const filePrefix = summary.match(/^(?:file|path):\s*(.+)$/);
    if (filePrefix?.[1]) {
      paths.push(filePrefix[1].trim());
    }

    // Bare path-like strings in the summary
    const pathMatches = summary.matchAll(
      /(?:^|\s)((?:\.{0,2}\/)?[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)+)/g
    );
    for (const m of pathMatches) {
      if (m[1]) paths.push(m[1]);
    }
  }

  // 2. Extract from metadata (structured tool_input)
  if (event.metadata) {
    const extractFromObj = (obj: Record<string, unknown>, depth = 0) => {
      if (depth > 3) return; // Prevent infinite recursion
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === "string" && isPathLike(value)) {
          paths.push(value);
        } else if (
          typeof value === "string" &&
          (key === "file_path" || key === "filePath" || key === "path" ||
           key === "file" || key === "target" || key === "source" ||
           key === "destination" || key === "filename")
        ) {
          paths.push(value);
        } else if (value && typeof value === "object" && !Array.isArray(value)) {
          extractFromObj(value as Record<string, unknown>, depth + 1);
        }
      }
    };
    extractFromObj(event.metadata);
  }

  // Deduplicate
  return [...new Set(paths)];
}

/** Simple heuristic: does this string look like a file path? */
function isPathLike(s: string): boolean {
  if (!s || s.length < 2 || s.length > 500) return false;
  // Starts with /, ./, ../, ~/, or looks like a relative path with extension
  return /^(?:\/|\.{0,2}\/|~\/|[a-zA-Z]:[\\/])/.test(s) ||
    /\.[a-zA-Z0-9]{1,10}$/.test(s);
}

// ─── Path Classifier ────────────────────────────────────────────────

export class PathClassifier {
  private _rules: Array<ClassificationRule & { compiled: RegExp }>;

  constructor(rules?: ClassificationRule[]) {
    const ruleSet = rules ?? DEFAULT_CLASSIFICATION_RULES;
    this._rules = ruleSet.map((r) => ({
      ...r,
      compiled: new RegExp(r.pattern, "i"),
    }));
  }

  /**
   * Classify a file path. Returns the first matching rule's classification,
   * or "public" if no rule matches (default-open for source code).
   */
  classify(filePath: string): { classification: DataClassification; label: string } {
    for (const rule of this._rules) {
      if (rule.compiled.test(filePath)) {
        return { classification: rule.classification, label: rule.label };
      }
    }
    return { classification: "public", label: "Source code / general" };
  }

  /**
   * Classify multiple paths and return the highest classification.
   */
  classifyHighest(paths: string[]): { classification: DataClassification; label: string; path: string } | null {
    let highest: { classification: DataClassification; label: string; path: string } | null = null;
    let highestLevel = -1;

    for (const p of paths) {
      const result = this.classify(p);
      const level = CLASSIFICATION_LEVEL[result.classification];
      if (level > highestLevel) {
        highestLevel = level;
        highest = { ...result, path: p };
      }
    }

    return highest;
  }
}

// ─── Enhanced Data Boundary Policy ──────────────────────────────────

/**
 * Enterprise data boundary policy with path classification.
 *
 * Instead of simple regex matching on input_summary, this policy:
 *   1. Extracts ALL paths from the event (summary, metadata, structured input)
 *   2. Classifies each path using configurable rules
 *   3. Checks the agent's clearance level against the path's classification
 *   4. Blocks if the agent doesn't have sufficient clearance
 *
 * Default behavior:
 *   - All agents can access "public" paths (source code, docs)
 *   - "internal" paths (configs, CI) require explicit agent clearance
 *   - "restricted" paths (secrets, credentials) are blocked by default
 *   - "system" paths (/etc, /dev) are always blocked
 *
 * COUPLING: When identity carries BOTH `authorized_scope` and `supervisor`,
 * this policy short-circuits to allow so that HierarchicalEscalationPolicy's
 * "escalate" decision can survive the base interceptor's precedence ladder
 * (block > escalate). Register HierarchicalEscalationPolicy BEFORE this one.
 */
export class EnhancedDataBoundaryPolicy implements PolicyProvider {
  readonly name = "enhanced_data_boundary";

  private _classifier: PathClassifier;
  private _agentClearances: Map<string, DataClassification>;
  private _defaultMaxClassification: DataClassification;
  private _wildcardClearances: Array<{ pattern: RegExp; max: DataClassification }>;

  constructor(config?: {
    /** Custom classification rules (replaces defaults) */
    classificationRules?: ClassificationRule[];
    /** Per-agent clearance levels */
    agentClearances?: AgentClearance[];
    /** Default max classification for unlisted agents. Default: "internal" */
    defaultMaxClassification?: DataClassification;
  }) {
    this._classifier = new PathClassifier(config?.classificationRules);
    this._defaultMaxClassification = config?.defaultMaxClassification ?? "internal";

    this._agentClearances = new Map();
    this._wildcardClearances = [];

    for (const c of config?.agentClearances ?? []) {
      if (c.agent.includes("*")) {
        const pattern = new RegExp("^" + c.agent.replace(/\*/g, ".*") + "$");
        this._wildcardClearances.push({ pattern, max: c.maxClassification });
      } else {
        this._agentClearances.set(c.agent, c.maxClassification);
      }
    }
  }

  private getAgentMaxClassification(agentId: string): DataClassification {
    // Exact match first
    const exact = this._agentClearances.get(agentId);
    if (exact) return exact;

    // Wildcard match
    for (const { pattern, max } of this._wildcardClearances) {
      if (pattern.test(agentId)) return max;
    }

    return this._defaultMaxClassification;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    // Coupling guard — HierarchicalEscalationPolicy owns this event when
    // both authorized_scope and supervisor are present. Allow here so the
    // escalate decision is not shadowed by a parallel block on the same path.
    if (event.identity?.authorized_scope && event.identity?.supervisor?.id) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    // Extract all paths from the event
    const paths = extractPaths(event);
    if (paths.length === 0) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    // Get the highest classification among all paths
    const highest = this._classifier.classifyHighest(paths);
    if (!highest) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    // Check against agent clearance
    const agentMax = this.getAgentMaxClassification(event.agent_id);
    const agentLevel = CLASSIFICATION_LEVEL[agentMax];
    const pathLevel = CLASSIFICATION_LEVEL[highest.classification];

    if (pathLevel > agentLevel) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason: `Agent "${event.agent_id}" (clearance: ${agentMax}) attempted to access ` +
          `${highest.classification}-level path "${highest.path}" (${highest.label}). ` +
          `Requires ${highest.classification} clearance or higher.`,
        evaluation_ms: Date.now() - start,
      };
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}
