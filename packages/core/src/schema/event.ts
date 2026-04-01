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
}
