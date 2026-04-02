/**
 * @module @sentinelflow/interceptors/base
 *
 * Abstract base class for all framework interceptors. Handles:
 *   - Event emission to all registered listeners
 *   - Policy evaluation with timing and error handling
 *   - Statistics tracking
 *   - Lifecycle management (start/stop)
 *
 * Framework-specific interceptors (ClaudeCodeInterceptor, LangChainInterceptor)
 * extend this and implement only the hookFramework() / unhookFramework() methods.
 */

import { v4 as uuidv4 } from "uuid";
import type { AgentEvent, EventType, ToolEventData, TokenUsage } from "@sentinelflow/core";
import type {
  Interceptor,
  InterceptorConfig,
  InterceptorStats,
  EventListener,
  PolicyProvider,
  PolicyEvaluationResult,
} from "./interface";

export abstract class BaseInterceptor implements Interceptor {
  abstract readonly framework: string;

  private _active = false;
  private _startedAt: Date | null = null;
  private _listeners: EventListener[] = [];
  private _policies: PolicyProvider[] = [];
  private _config: InterceptorConfig;

  // Statistics
  private _eventsEmitted = 0;
  private _eventsByType: Record<string, number> = {};
  private _policyEvaluations = 0;
  private _policyBlocks = 0;
  private _policyTotalMs = 0;
  private _errors = 0;

  constructor(config: Partial<InterceptorConfig> = {}) {
    this._config = {
      enabled: config.enabled ?? true,
      policies: config.policies ?? [],
      listeners: config.listeners ?? [],
      enforcement_mode: config.enforcement_mode ?? "monitor",
      log_level: config.log_level ?? "info",
      agent_id: config.agent_id ?? `agent-${uuidv4().slice(0, 8)}`,
      session_id: config.session_id ?? uuidv4(),
    };

    this._listeners = [...this._config.listeners];
    this._policies = [...this._config.policies];
  }

  get active(): boolean {
    return this._active;
  }

  get agentId(): string {
    return this._config.agent_id!;
  }

  get sessionId(): string {
    return this._config.session_id!;
  }

  get enforcementMode(): "enforce" | "monitor" {
    return this._config.enforcement_mode;
  }

  // ─── Lifecycle ──────────────────────────────────────────────

  async start(): Promise<void> {
    if (this._active) {
      this.log("warn", "Interceptor already active, ignoring start()");
      return;
    }

    if (!this._config.enabled) {
      this.log("info", "Interceptor disabled via config, skipping start()");
      return;
    }

    this.log("info", `Starting ${this.framework} interceptor (mode=${this._config.enforcement_mode})`);

    // Hook into the framework's event system
    await this.hookFramework();

    this._active = true;
    this._startedAt = new Date();

    // Emit session_start event
    await this.emitEvent(this.createEvent("session_start"));

    this.log("info", `${this.framework} interceptor started`);
  }

  async stop(): Promise<void> {
    if (!this._active) {
      return;
    }

    this.log("info", `Stopping ${this.framework} interceptor`);

    // Emit session_end event
    await this.emitEvent(this.createEvent("session_end"));

    // Unhook from the framework
    await this.unhookFramework();

    this._active = false;

    // Notify listeners of shutdown
    for (const listener of this._listeners) {
      try {
        await listener.onShutdown?.();
      } catch (err) {
        this._errors++;
        this.log("error", `Listener ${listener.name} shutdown failed: ${err}`);
      }
    }

    this.log("info", `${this.framework} interceptor stopped`);
  }

  // ─── Abstract Methods (framework-specific) ─────────────────

  /**
   * Hook into the framework's event system.
   * Called by start(). Must set up whatever listeners/hooks
   * the framework provides (e.g., Claude Code hooks.json, LangChain callbacks).
   */
  protected abstract hookFramework(): Promise<void>;

  /**
   * Unhook from the framework's event system.
   * Called by stop(). Must cleanly remove all hooks/listeners.
   */
  protected abstract unhookFramework(): Promise<void>;

  // ─── Event Creation ─────────────────────────────────────────

  /**
   * Create a normalized AgentEvent with all common fields pre-filled.
   * Framework interceptors call this and add framework-specific data.
   */
  protected createEvent(
    type: EventType,
    opts?: {
      tool?: ToolEventData;
      tokens?: TokenUsage;
      metadata?: Record<string, unknown>;
    }
  ): AgentEvent {
    return {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      agent_id: this._config.agent_id!,
      session_id: this._config.session_id!,
      type,
      tool: opts?.tool,
      tokens: opts?.tokens,
      metadata: opts?.metadata,
    };
  }

  // ─── Policy Evaluation ──────────────────────────────────────

  /**
   * Run all policy providers against a tool_call_start event.
   * Returns the most restrictive decision (block > flag > log > allow).
   *
   * This is THE critical path for the runtime agent firewall:
   * every tool call passes through here before execution.
   */
  protected async evaluatePolicies(event: AgentEvent): Promise<PolicyEvaluationResult> {
    if (this._policies.length === 0) {
      return {
        decision: "allow",
        matched_policies: [],
        evaluation_ms: 0,
      };
    }

    const start = Date.now();
    const allMatched: string[] = [];
    let finalDecision: "allow" | "block" | "flag" | "log" = "allow";
    let blockReason: string | undefined;

    for (const policy of this._policies) {
      try {
        const result = await policy.evaluate(event);
        this._policyEvaluations++;

        if (result.matched_policies.length > 0) {
          allMatched.push(...result.matched_policies);
        }

        // Escalate decision: block > flag > log > allow
        if (result.decision === "block" && finalDecision !== "block") {
          finalDecision = "block";
          blockReason = result.reason;
          this._policyBlocks++;
        } else if (result.decision === "flag" && finalDecision === "allow") {
          finalDecision = "flag";
        } else if (result.decision === "log" && finalDecision === "allow") {
          finalDecision = "log";
        }
      } catch (err) {
        this._errors++;
        this.log("error", `Policy ${policy.name} evaluation failed: ${err}`);
        // On policy error, default to "flag" (fail-open in monitor, fail-closed in enforce)
        if (this._config.enforcement_mode === "enforce") {
          finalDecision = "block";
          blockReason = `Policy evaluation error: ${err}`;
        }
      }
    }

    const evaluationMs = Date.now() - start;
    this._policyTotalMs += evaluationMs;

    // In monitor mode, downgrade "block" to "flag" — never actually block
    if (this._config.enforcement_mode === "monitor" && finalDecision === "block") {
      this.log("warn", `Would block tool call (monitor mode): ${blockReason}`);
      finalDecision = "flag";
    }

    return {
      decision: finalDecision,
      matched_policies: allMatched,
      reason: blockReason,
      evaluation_ms: evaluationMs,
    };
  }

  // ─── Event Emission ─────────────────────────────────────────

  /**
   * Emit an event to all registered listeners.
   * Listeners are called in parallel. Failures are logged but never
   * block the event pipeline — we never want governance overhead
   * to break the agent's actual work.
   */
  protected async emitEvent(event: AgentEvent): Promise<void> {
    this._eventsEmitted++;
    this._eventsByType[event.type] = (this._eventsByType[event.type] || 0) + 1;

    // Fire-and-forget to all listeners (parallel, non-blocking)
    const promises = this._listeners.map(async (listener) => {
      try {
        await listener.onEvent(event);
      } catch (err) {
        this._errors++;
        this.log("error", `Listener ${listener.name} failed on ${event.type}: ${err}`);
      }
    });

    await Promise.allSettled(promises);
  }

  /**
   * The main tool-call interception flow. Framework interceptors call this
   * when they detect a tool call about to happen.
   *
   * Returns true if the tool call should proceed, false if blocked.
   */
  protected async handleToolCall(
    toolName: string,
    inputSummary?: string,
    metadata?: Record<string, unknown>
  ): Promise<{ allowed: boolean; event: AgentEvent }> {
    // 1. Create the pre-execution event
    const event = this.createEvent("tool_call_start", {
      tool: {
        name: toolName,
        input_summary: inputSummary,
        status: "success", // Will be updated if blocked
      },
      metadata,
    });

    // 2. Run policy evaluation
    const policyResult = await this.evaluatePolicies(event);

    // 3. Attach governance evaluation to the event
    event.governance = {
      policies_evaluated: this._policies.map((p) => p.name),
      policies_passed: policyResult.matched_policies.length === 0
        ? this._policies.map((p) => p.name)
        : this._policies
            .map((p) => p.name)
            .filter((n) => !policyResult.matched_policies.includes(n)),
      policies_failed: policyResult.matched_policies,
      action_taken: policyResult.decision === "block" ? "blocked" : "allowed",
      reason: policyResult.reason,
    };

    // 4. If blocked, emit a blocked event and return false
    if (policyResult.decision === "block") {
      event.type = "tool_call_blocked";
      event.tool!.status = "blocked";
      await this.emitEvent(event);
      return { allowed: false, event };
    }

    // 5. Otherwise emit the start event and allow the call
    await this.emitEvent(event);
    return { allowed: true, event };
  }

  /**
   * Called after a tool call completes. Emits the tool_call_end event
   * with duration, output summary, and token usage.
   */
  protected async handleToolResult(
    startEvent: AgentEvent,
    result: {
      status: "success" | "error";
      outputSummary?: string;
      errorMessage?: string;
      durationMs?: number;
      tokens?: TokenUsage;
    }
  ): Promise<void> {
    const endEvent = this.createEvent("tool_call_end", {
      tool: {
        name: startEvent.tool!.name,
        input_summary: startEvent.tool?.input_summary,
        output_summary: result.outputSummary,
        status: result.status,
        duration_ms: result.durationMs,
        error_message: result.errorMessage,
      },
      tokens: result.tokens,
      metadata: startEvent.metadata,
    });

    await this.emitEvent(endEvent);
  }

  // ─── Listener / Policy Management ───────────────────────────

  addListener(listener: EventListener): void {
    this._listeners.push(listener);
    this.log("debug", `Added listener: ${listener.name}`);
  }

  removeListener(name: string): void {
    this._listeners = this._listeners.filter((l) => l.name !== name);
    this.log("debug", `Removed listener: ${name}`);
  }

  addPolicy(policy: PolicyProvider): void {
    this._policies.push(policy);
    this.log("debug", `Added policy: ${policy.name}`);
  }

  removePolicy(name: string): void {
    this._policies = this._policies.filter((p) => p.name !== name);
    this.log("debug", `Removed policy: ${name}`);
  }

  // ─── Statistics ─────────────────────────────────────────────

  getStats(): InterceptorStats {
    const now = Date.now();
    const uptimeMs = this._startedAt ? now - this._startedAt.getTime() : 0;

    return {
      framework: this.framework,
      active: this._active,
      started_at: this._startedAt?.toISOString() ?? null,
      uptime_ms: uptimeMs,
      events_emitted: this._eventsEmitted,
      events_by_type: { ...this._eventsByType },
      policy_evaluations: this._policyEvaluations,
      policy_blocks: this._policyBlocks,
      policy_avg_ms:
        this._policyEvaluations > 0
          ? Math.round(this._policyTotalMs / this._policyEvaluations)
          : 0,
      errors: this._errors,
    };
  }

  // ─── Logging ────────────────────────────────────────────────

  protected log(level: "debug" | "info" | "warn" | "error", message: string): void {
    const levels = ["debug", "info", "warn", "error", "silent"];
    const configLevel = levels.indexOf(this._config.log_level);
    const messageLevel = levels.indexOf(level);

    if (messageLevel >= configLevel) {
      const prefix = `[sentinelflow:${this.framework}]`;
      switch (level) {
        case "debug":
          console.debug(prefix, message);
          break;
        case "info":
          console.info(prefix, message);
          break;
        case "warn":
          console.warn(prefix, message);
          break;
        case "error":
          console.error(prefix, message);
          break;
      }
    }
  }
}
