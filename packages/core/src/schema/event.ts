/**
 * @module @sentinelflow/core/schema/event
 *
 * Telemetry events emitted by runtime interceptors.
 * Event types map directly from ECC's hook events:
 *   PreToolUse  → tool_call_start
 *   PostToolUse → tool_call_end
 *   SessionStart → session_start
 *   SessionEnd  → session_end
 *   Stop        → stop
 */

export type EventType =
  | "session_start"
  | "session_end"
  | "tool_call_start"
  | "tool_call_end"
  | "tool_call_blocked"
  | "tool_call_escalated"
  | "delegation"
  | "model_switch"
  | "error"
  | "stop";

export type AnomalyType =
  | "novel_tool"
  | "data_boundary"
  | "cost_spike"
  | "error_spike"
  | "privilege_escalation"
  | "unusual_pattern";

export interface ToolEventData {
  name: string;
  input_summary?: string;
  output_summary?: string;
  status: "success" | "error" | "blocked" | "escalated";
  duration_ms?: number;
  error_message?: string;
}

export interface TokenUsage {
  input: number;
  output: number;
  model: string;
  estimated_cost_usd: number;
}

export interface GovernanceEvaluation {
  policies_evaluated: string[];
  policies_passed: string[];
  policies_failed: string[];
  action_taken: "allowed" | "blocked" | "escalated" | "flagged" | "logged";
  reason?: string;
}

export interface AnomalyResult {
  detected: boolean;
  type?: AnomalyType;
  confidence: number;
  description?: string;
}

// ─── Identity Context (Priority 9) ─────────────────────────────────

export type Environment = "development" | "staging" | "production" | "ci" | "unknown";

export type AgentRole =
  | "reader"        // Can only read files and data
  | "writer"        // Can read and write source code
  | "executor"      // Can run commands (bash, shell)
  | "deployer"      // Can publish, deploy, push
  | "admin"         // Full access
  | "custom";       // Custom role defined in policy

/**
 * Identity context — links agent actions back to human sponsors.
 *
 * This is what compliance auditors ask for: "Who authorized this agent
 * to run? What team owns it? Is this production or development?"
 *
 * Populated from:
 *   - .sentinelflow-policy.yaml (static config)
 *   - Environment variables (SENTINELFLOW_OWNER, SENTINELFLOW_TEAM, etc.)
 *   - Git config (user.name, user.email as fallback)
 *   - CI/CD context (GITHUB_ACTOR, CI_PIPELINE_SOURCE, etc.)
 */
export interface IdentityContext {
  /** Human who authorized this agent session. Required for audit. */
  human_owner?: string;
  /** Email of the human owner (for alerting and audit trails) */
  human_email?: string;
  /** Team that owns this agent/project */
  team?: string;
  /** Deployment environment */
  environment: Environment;
  /** Agent's assigned role — determines what tools it can access */
  role: AgentRole;
  /** Privilege level 1-10 (1 = lowest, 10 = admin) */
  privilege_level: number;
  /** Whether this agent is in an external-facing workflow */
  external_facing?: boolean;
  /** Custom tags for organization-specific categorization */
  tags?: string[];
  /**
   * Maximum data classification this agent is authorized to access without
   * triggering escalation. Values mirror the four-level classification scale
   * defined by PathClassifier in @sentinelflow/interceptors/data-boundary
   * ("public" < "internal" < "restricted" < "system"). Kept inline here to
   * avoid a core → interceptors dependency.
   *
   * TODO(data-classification-drift): keep this literal in lockstep with the
   *   canonical `DataClassification` type in
   *   `packages/interceptors/src/data-boundary.ts`. If a fifth level is ever
   *   added there, TypeScript will NOT catch the drift — extend this union
   *   in the same PR. Grep for this TODO when touching DataClassification.
   */
  authorized_scope?: "public" | "internal" | "restricted" | "system";
  /**
   * Supervisor who can authorize requests outside `authorized_scope`.
   * When set, out-of-scope tool calls escalate to this supervisor rather
   * than block outright. A future version may extend this into an ordered
   * approval chain — keeping it a single ref for v1 keeps the contract small.
   */
  supervisor?: {
    /** Supervisor identifier (agent_id, human handle, or service principal) */
    id: string;
    /** Optional email for downstream notification channels */
    email?: string;
  };
}

// ─── Main Event Type ────────────────────────────────────────────────

export interface AgentEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  type: EventType;
  tool?: ToolEventData;
  tokens?: TokenUsage;
  governance?: GovernanceEvaluation;
  anomaly?: AnomalyResult;
  metadata?: Record<string, unknown>;
  /** Identity context — who authorized this agent and what role it has */
  identity?: IdentityContext;
}
