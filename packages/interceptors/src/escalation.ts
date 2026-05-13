/**
 * @module @sentinelflow/interceptors/escalation
 *
 * HierarchicalEscalationPolicy — when an agent reaches outside its
 * authorized data scope, escalate to a configured supervisor instead
 * of blocking outright. That's the difference between a guardrail and
 * a workflow.
 *
 * COUPLING: Must run BEFORE EnhancedDataBoundaryPolicy in the policy
 * chain. The base interceptor's precedence ladder ranks block > escalate,
 * so if boundary fires "block" alongside this policy's "escalate" the
 * block would silently shadow the escalation. EnhancedDataBoundaryPolicy
 * therefore short-circuits with "allow" when both identity.authorized_scope
 * AND identity.supervisor are present on the event — preserving the
 * escalate decision so the supervisor record survives.
 *
 * Flow:
 *   1. Identity must carry both `authorized_scope` and `supervisor`.
 *      If either is missing, this policy is a no-op (return allow) and
 *      the boundary policy handles the event normally.
 *   2. Extract every path referenced by the tool call (reuses extractPaths).
 *   3. Classify the highest-sensitivity path (reuses PathClassifier).
 *   4. If that classification ≤ authorized_scope, allow.
 *   5. Otherwise: write a record to .sentinelflow/escalations.jsonl and
 *      return decision "escalate".
 *
 * Maps to:
 *   - OWASP LLM09 (Excessive Agency): escalation as a workflow control
 *   - EU AI Act Article 14: human oversight via approval gate
 *   - NIST AI RMF Govern 1.4: organizational roles and delegation
 *   - SOC 2 CC6.1: access control with separation-of-duties
 */

import { randomBytes } from "crypto";
import { appendFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import type { AgentEvent } from "@sentinelflow/core";
import type { PolicyProvider, PolicyEvaluationResult } from "./interface";
import {
  PathClassifier,
  extractPaths,
  type ClassificationRule,
  type DataClassification,
} from "./data-boundary";

// Numeric ladder for classification comparison.
// Kept in sync with CLASSIFICATION_LEVEL in data-boundary.ts.
// See also: TODO(data-classification-drift) in @sentinelflow/core IdentityContext.
const CLASSIFICATION_LEVEL: Record<DataClassification, number> = {
  public: 0,
  internal: 1,
  restricted: 2,
  system: 3,
};

/**
 * Shape of one line in .sentinelflow/escalations.jsonl.
 * `resolved_*` are reserved for a future approval-resolution path
 * and are written as `null` in v1.
 */
export interface EscalationRecord {
  schema_version: 1;
  escalation_id: string;
  timestamp: string;
  event_id: string;
  session_id: string;
  agent_id: string;
  human_owner: string | null;
  tool_name: string | null;
  requested_paths: string[];
  requested_classification: DataClassification;
  requested_label: string;
  authorized_scope: DataClassification;
  supervisor: { id: string; email: string | null };
  reason: string;
  status: "pending";
  resolved_at: null;
  resolved_by: null;
  resolution: null;
}

export interface HierarchicalEscalationPolicyConfig {
  /** Override default classification rules (see data-boundary.ts) */
  classificationRules?: ClassificationRule[];
  /** Absolute or cwd-relative path. Default: <cwd>/.sentinelflow/escalations.jsonl */
  logPath?: string;
}

function makeEscalationId(): string {
  // unix-ms + 4 random bytes (8 hex chars) → collision-free for any realistic
  // call rate, and the timestamp prefix sorts naturally in audit listings.
  return `esc_${Date.now()}_${randomBytes(4).toString("hex")}`;
}

export class HierarchicalEscalationPolicy implements PolicyProvider {
  readonly name = "hierarchical_escalation";

  private _classifier: PathClassifier;
  private _logPath: string;
  private _dirEnsured = false;

  constructor(config?: HierarchicalEscalationPolicyConfig) {
    this._classifier = new PathClassifier(config?.classificationRules);
    this._logPath =
      config?.logPath ?? join(process.cwd(), ".sentinelflow", "escalations.jsonl");
  }

  /** Where escalation records are appended. Exposed for tests/diagnostics. */
  get logPath(): string {
    return this._logPath;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const allow = (): PolicyEvaluationResult => ({
      decision: "allow",
      matched_policies: [],
      evaluation_ms: Date.now() - start,
    });

    const identity = event.identity;
    // Not configured for escalation → defer to other policies. Boundary will
    // run because its skip-condition (both authorized_scope AND supervisor)
    // is unsatisfied.
    if (!identity?.authorized_scope || !identity?.supervisor?.id) {
      return allow();
    }

    const paths = extractPaths(event);
    if (paths.length === 0) return allow();

    const highest = this._classifier.classifyHighest(paths);
    if (!highest) return allow();

    const authLevel = CLASSIFICATION_LEVEL[identity.authorized_scope];
    const pathLevel = CLASSIFICATION_LEVEL[highest.classification];
    if (pathLevel <= authLevel) return allow();

    // Out of scope. Record and escalate.
    const escalationId = makeEscalationId();
    const reason =
      `Agent "${event.agent_id}" (scope: ${identity.authorized_scope}) requested ` +
      `${highest.classification} path "${highest.path}" (${highest.label}). ` +
      `Escalated to supervisor "${identity.supervisor.id}".`;

    const record: EscalationRecord = {
      schema_version: 1,
      escalation_id: escalationId,
      timestamp: new Date().toISOString(),
      event_id: event.id,
      session_id: event.session_id,
      agent_id: event.agent_id,
      human_owner: identity.human_owner ?? null,
      tool_name: event.tool?.name ?? null,
      requested_paths: paths,
      requested_classification: highest.classification,
      requested_label: highest.label,
      authorized_scope: identity.authorized_scope,
      supervisor: {
        id: identity.supervisor.id,
        email: identity.supervisor.email ?? null,
      },
      reason,
      status: "pending",
      resolved_at: null,
      resolved_by: null,
      resolution: null,
    };

    this.writeRecord(record);

    return {
      decision: "escalate",
      matched_policies: [this.name],
      reason: `${reason} (escalation_id: ${escalationId})`,
      evaluation_ms: Date.now() - start,
    };
  }

  private writeRecord(record: EscalationRecord): void {
    if (!this._dirEnsured) {
      mkdirSync(dirname(this._logPath), { recursive: true });
      this._dirEnsured = true;
    }
    appendFileSync(this._logPath, JSON.stringify(record) + "\n", "utf8");
  }
}
