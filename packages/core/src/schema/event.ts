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
  status: "success" | "error" | "blocked";
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
  action_taken: "allowed" | "blocked" | "flagged" | "logged";
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
