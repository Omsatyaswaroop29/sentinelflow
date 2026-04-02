/**
 * @module @sentinelflow/interceptors/interface
 *
 * The base interceptor interface. Every framework-specific interceptor
 * (Claude Code hooks, LangChain callbacks, etc.) implements this contract.
 *
 * The flow:
 *   1. Interceptor hooks into the framework's lifecycle events
 *   2. Framework emits an event (e.g., PreToolUse)
 *   3. Interceptor normalizes it into an AgentEvent
 *   4. Interceptor calls the policy engine for an allow/block decision
 *   5. Interceptor emits the event to all registered listeners
 *   6. If blocked, interceptor returns a rejection to the framework
 *
 * This is the "SentinelFlow Runtime Agent Firewall" concept:
 * every tool call passes through our interceptor before execution.
 */

import type { AgentEvent } from "@sentinelflow/core";

// ─── Policy Decision ────────────────────────────────────────────────

export type PolicyDecision = "allow" | "block" | "flag" | "log";

export interface PolicyEvaluationResult {
  decision: PolicyDecision;
  /** Which policy rules matched */
  matched_policies: string[];
  /** Human-readable reason for block/flag decisions */
  reason?: string;
  /** How long the policy evaluation took */
  evaluation_ms: number;
}

// ─── Event Listener ─────────────────────────────────────────────────

/**
 * Anything that wants to react to agent events: the event store,
 * anomaly detector, dashboard websocket, Slack alerter, etc.
 */
export interface EventListener {
  /** Unique name for this listener (for debug/logging) */
  name: string;
  /** Called for every event the interceptor produces */
  onEvent(event: AgentEvent): void | Promise<void>;
  /** Called when the interceptor shuts down */
  onShutdown?(): void | Promise<void>;
}

// ─── Policy Provider ────────────────────────────────────────────────

/**
 * Evaluates whether a tool call should be allowed. The interceptor
 * calls this BEFORE the tool executes. If the decision is "block",
 * the interceptor prevents execution and emits a tool_call_blocked event.
 */
export interface PolicyProvider {
  /** Human-readable name */
  name: string;
  /**
   * Evaluate a pre-execution event. Only called for tool_call_start events.
   * Return "allow" to let the call proceed, "block" to prevent it.
   */
  evaluate(event: AgentEvent): PolicyEvaluationResult | Promise<PolicyEvaluationResult>;
}

// ─── Interceptor Configuration ──────────────────────────────────────

export interface InterceptorConfig {
  /** Enable/disable the interceptor without removing it */
  enabled: boolean;
  /** Policy providers to consult before allowing tool calls */
  policies: PolicyProvider[];
  /** Event listeners that receive all events */
  listeners: EventListener[];
  /** Whether to block on policy failures or just flag them */
  enforcement_mode: "enforce" | "monitor";
  /** Log level for internal interceptor diagnostics */
  log_level: "debug" | "info" | "warn" | "error" | "silent";
  /** Agent ID to tag all events with (auto-generated if not provided) */
  agent_id?: string;
  /** Session ID for correlating events within a single run */
  session_id?: string;
}

// ─── Base Interceptor ───────────────────────────────────────────────

/**
 * The base interface every framework interceptor must implement.
 * 
 * Lifecycle:
 *   const interceptor = new ClaudeCodeInterceptor(config);
 *   await interceptor.start();    // Hook into the framework
 *   // ... agent runs, events flow ...
 *   await interceptor.stop();     // Unhook, flush events, cleanup
 *   const stats = interceptor.getStats();
 */
export interface Interceptor {
  /** Which framework this interceptor handles */
  readonly framework: string;
  /** Current state */
  readonly active: boolean;

  /** Start intercepting. Hooks into the framework's event system. */
  start(): Promise<void>;
  /** Stop intercepting. Flushes pending events and unhooks. */
  stop(): Promise<void>;

  /** Add a listener after construction */
  addListener(listener: EventListener): void;
  /** Remove a listener */
  removeListener(name: string): void;

  /** Add a policy provider after construction */
  addPolicy(policy: PolicyProvider): void;
  /** Remove a policy provider */
  removePolicy(name: string): void;

  /** Get runtime statistics */
  getStats(): InterceptorStats;
}

// ─── Runtime Statistics ─────────────────────────────────────────────

export interface InterceptorStats {
  framework: string;
  active: boolean;
  started_at: string | null;
  uptime_ms: number;
  events_emitted: number;
  events_by_type: Record<string, number>;
  policy_evaluations: number;
  policy_blocks: number;
  policy_avg_ms: number;
  errors: number;
}
