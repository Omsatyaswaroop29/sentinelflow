/**
 * @module @sentinelflow/core/event-store/schema
 *
 * The canonical governance event envelope.
 *
 * Design principles (from the Phase 2.2 architecture spec):
 *
 *   1. Governance-aligned, not generic observability. Event types map to
 *      governance questions: "was this tool call allowed?", "did this exceed
 *      the budget?", "was a human approval required?" — not generic spans/traces.
 *
 *   2. Structured columns for fields we KNOW we'll filter/aggregate on.
 *      Agent ID, event type, tool name, outcome, cost — these are first-class
 *      indexed columns. Auxiliary metadata lives in payload_json.
 *
 *   3. Append-only and immutable. Events are facts that happened. We never
 *      update or delete them (except for retention). Mutable "current state"
 *      lives in separate summary tables.
 *
 *   4. Version-stamped. The schema version lets us evolve the event shape
 *      without breaking old consumers. New fields are always optional.
 *
 * This contract is the single source of truth. The SQLite writer, query API,
 * JSONL listener, and future OpenTelemetry exporter all consume this shape.
 */

// ─── Governance Event Types ─────────────────────────────────────────
//
// These are NOT generic telemetry events. Each type answers a specific
// governance question that auditors, security teams, or compliance
// officers would ask.

export type GovernanceEventType =
  // Tool execution lifecycle
  | "tool_call_attempted"      // Agent tried to call a tool (pre-execution)
  | "tool_call_completed"      // Tool call finished successfully
  | "tool_call_failed"         // Tool call finished with an error
  | "tool_call_blocked"        // Policy engine blocked the tool call

  // Policy evaluation
  | "policy_evaluated"         // A policy was checked (even if it passed)
  | "policy_violation"         // A policy was violated (may not be blocked in monitor mode)

  // Cost governance
  | "budget_threshold_warning" // Cost approaching budget limit (80%)
  | "budget_threshold_exceeded"// Cost exceeded budget limit

  // Agent lifecycle
  | "session_started"          // Agent session began
  | "session_ended"            // Agent session ended
  | "delegation_spawned"       // Agent delegated to another agent

  // Static analysis
  | "scan_completed"           // A static scan finished
  | "finding_emitted"          // A scan finding was produced

  // Anomaly detection (Phase 2.4)
  | "anomaly_detected"         // Anomaly detector flagged something
  | "novel_tool_observed";     // Agent used a tool for the first time

// ─── Outcome ────────────────────────────────────────────────────────

export type EventOutcome =
  | "allowed"     // Action proceeded normally
  | "blocked"     // Action was prevented by policy
  | "flagged"     // Action proceeded but was flagged for review
  | "error"       // Action failed due to an error
  | "info";       // Informational event, no action taken

// ─── Severity (for governance significance) ─────────────────────────

export type EventSeverity =
  | "critical"    // Requires immediate attention
  | "high"        // Should be reviewed within 24h
  | "medium"      // Should be reviewed within a week
  | "low"         // Informational, for baseline building
  | "info";       // Normal operation, audit trail only

// ─── The Canonical Event Envelope ───────────────────────────────────

export interface GovernanceEvent {
  // ── Identity ──────────────────────────────────────────────
  /** Unique event ID (UUID v4) */
  event_id: string;
  /** Schema version for forward compatibility. Current: 1 */
  schema_version: number;
  /** ISO 8601 timestamp with millisecond precision */
  timestamp: string;

  // ── Source ────────────────────────────────────────────────
  /** Which agent produced this event */
  agent_id: string;
  /** Which framework the agent runs on */
  framework: string;
  /** Session correlation ID (groups events within one agent run) */
  session_id: string;
  /** Optional: parent event ID for causal chains (e.g., delegation → child session) */
  parent_event_id?: string;

  // ── Governance Classification ─────────────────────────────
  /** What kind of governance event this is */
  event_type: GovernanceEventType;
  /** What happened as a result */
  outcome: EventOutcome;
  /** How significant this event is */
  severity: EventSeverity;

  // ── Tool Context (when applicable) ────────────────────────
  /** Tool name (e.g., "Bash", "Read", "Write") */
  tool_name?: string;
  /** Short summary of the tool input (truncated for storage) */
  tool_input_summary?: string;
  /** What the tool was asked to do (e.g., "rm -rf /tmp/build") */
  action?: string;

  // ── Policy Context (when applicable) ──────────────────────
  /** Which policy rule was evaluated or triggered */
  policy_id?: string;
  /** Policy rule name */
  policy_name?: string;
  /** Human-readable reason for the outcome */
  reason?: string;

  // ── Cost Context ──────────────────────────────────────────
  /** Prompt/input tokens consumed */
  prompt_tokens?: number;
  /** Completion/output tokens consumed */
  completion_tokens?: number;
  /** Estimated cost in USD */
  cost_usd?: number;
  /** Model used for this interaction */
  model?: string;

  // ── Duration ──────────────────────────────────────────────
  /** How long the action took in milliseconds */
  duration_ms?: number;

  // ── Auxiliary Metadata ────────────────────────────────────
  /**
   * Arbitrary metadata that doesn't warrant its own column.
   * Examples: raw tool input/output, stack traces, user context.
   *
   * IMPORTANT: Do NOT put fields here that you plan to filter or
   * aggregate on. Those must be first-class columns above.
   */
  payload?: Record<string, unknown>;
}

// ─── Event Factory ──────────────────────────────────────────────────

const CURRENT_SCHEMA_VERSION = 1;

/**
 * Create a new governance event with required fields pre-filled.
 * All optional fields default to undefined (not stored in JSON).
 */
export function createGovernanceEvent(
  params: Pick<GovernanceEvent, "agent_id" | "framework" | "session_id" | "event_type" | "outcome" | "severity"> &
    Partial<GovernanceEvent>
): GovernanceEvent {
  return {
    event_id: params.event_id ?? crypto.randomUUID(),
    schema_version: CURRENT_SCHEMA_VERSION,
    timestamp: params.timestamp ?? new Date().toISOString(),
    agent_id: params.agent_id,
    framework: params.framework,
    session_id: params.session_id,
    parent_event_id: params.parent_event_id,
    event_type: params.event_type,
    outcome: params.outcome,
    severity: params.severity,
    tool_name: params.tool_name,
    tool_input_summary: params.tool_input_summary,
    action: params.action,
    policy_id: params.policy_id,
    policy_name: params.policy_name,
    reason: params.reason,
    prompt_tokens: params.prompt_tokens,
    completion_tokens: params.completion_tokens,
    cost_usd: params.cost_usd,
    model: params.model,
    duration_ms: params.duration_ms,
    payload: params.payload,
  };
}

// ─── Rollup Types ───────────────────────────────────────────────────

/**
 * Pre-computed daily summary for an agent. These power the dashboard
 * without requiring full table scans on the events table.
 */
export interface DailyRollup {
  /** Date in YYYY-MM-DD format */
  date: string;
  /** Agent this rollup is for */
  agent_id: string;
  /** Framework */
  framework: string;
  /** Total events in this period */
  total_events: number;
  /** Tool calls attempted */
  tool_calls: number;
  /** Tool calls blocked by policy */
  tool_calls_blocked: number;
  /** Tool calls that errored */
  tool_calls_failed: number;
  /** Unique tools used */
  unique_tools: number;
  /** Comma-separated list of tools used */
  tools_used: string;
  /** Total prompt tokens */
  prompt_tokens: number;
  /** Total completion tokens */
  completion_tokens: number;
  /** Total estimated cost in USD */
  cost_usd: number;
  /** Number of policy violations */
  policy_violations: number;
  /** Number of anomalies detected */
  anomalies_detected: number;
  /** Number of sessions */
  sessions: number;
}
