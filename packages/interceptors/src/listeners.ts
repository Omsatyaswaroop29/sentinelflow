/**
 * @module @sentinelflow/interceptors/listeners
 *
 * Built-in event listeners that react to AgentEvents from interceptors.
 * These are the "output side" of the pipeline:
 *
 *   Framework → Interceptor → Policy Engine → Event Listeners
 *
 * Built-in listeners:
 *   1. ConsoleListener — Pretty-prints events to the terminal
 *   2. JsonlFileListener — Appends events to a JSONL file (for event store)
 *   3. CallbackListener — Calls a user-provided function (for custom integrations)
 *   4. AlertListener — Sends alerts on blocked events or anomalies
 */

import * as fs from "fs";
import * as path from "path";
import type { AgentEvent } from "@sentinelflow/core";
import {
  EventStoreWriter,
  createGovernanceEvent,
  type GovernanceEvent,
  type GovernanceEventType,
  type EventOutcome,
  type EventSeverity,
} from "@sentinelflow/core";
import type { EventListener } from "./interface";

// ─── 1. Console Listener ────────────────────────────────────────────

/**
 * Pretty-prints events to the terminal. Useful for development
 * and debugging. Color-coded by event type.
 */
export class ConsoleListener implements EventListener {
  readonly name = "console";
  private _verbose: boolean;

  constructor(opts?: { verbose?: boolean }) {
    this._verbose = opts?.verbose ?? false;
  }

  onEvent(event: AgentEvent): void {
    const timestamp = new Date(event.timestamp).toLocaleTimeString();
    const prefix = `[${timestamp}]`;

    switch (event.type) {
      case "session_start":
        console.log(`${prefix} 🟢 Session started (agent=${event.agent_id})`);
        break;

      case "session_end":
        console.log(`${prefix} 🔴 Session ended (agent=${event.agent_id})`);
        break;

      case "tool_call_start":
        console.log(
          `${prefix} 🔧 ${event.tool?.name}` +
            (event.tool?.input_summary ? ` → ${event.tool.input_summary.slice(0, 80)}` : "")
        );
        break;

      case "tool_call_end":
        if (event.tool?.status === "error") {
          console.log(
            `${prefix} ❌ ${event.tool?.name} failed: ${event.tool?.error_message?.slice(0, 80)}`
          );
        } else if (this._verbose) {
          console.log(
            `${prefix} ✅ ${event.tool?.name} completed` +
              (event.tool?.duration_ms ? ` (${event.tool.duration_ms}ms)` : "")
          );
        }
        break;

      case "tool_call_blocked":
        console.log(
          `${prefix} 🚫 BLOCKED: ${event.tool?.name}` +
            (event.governance?.reason ? ` — ${event.governance.reason}` : "")
        );
        break;

      case "delegation":
        console.log(`${prefix} 🔄 Delegation event`);
        break;

      case "error":
        console.log(`${prefix} ⚠️  Error event`);
        break;

      default:
        if (this._verbose) {
          console.log(`${prefix} 📝 ${event.type}`);
        }
    }

    // In verbose mode, show governance details
    if (this._verbose && event.governance) {
      const g = event.governance;
      console.log(
        `         Policies: ${g.policies_evaluated.length} evaluated, ` +
          `${g.policies_failed.length} failed → ${g.action_taken}`
      );
    }

    // In verbose mode, show token usage
    if (this._verbose && event.tokens) {
      console.log(
        `         Tokens: ${event.tokens.input}in/${event.tokens.output}out ` +
          `(${event.tokens.model}, $${event.tokens.estimated_cost_usd.toFixed(4)})`
      );
    }
  }
}

// ─── 2. JSONL File Listener ─────────────────────────────────────────

/**
 * Appends events to a JSONL (JSON Lines) file. Each line is one event.
 * This is the primary persistence mechanism for the event store.
 *
 * The JSONL format is chosen because:
 * - Append-only (no corruption on crash)
 * - Line-by-line streaming reads
 * - No need for SQLite at the interceptor layer
 * - Easy to cat/grep/tail in the terminal
 */
export class JsonlFileListener implements EventListener {
  readonly name = "jsonl_file";
  private _filePath: string;
  private _maxSizeBytes: number;
  private _buffer: string[] = [];
  private _flushIntervalMs: number;
  private _flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: {
    filePath: string;
    maxSizeBytes?: number;
    flushIntervalMs?: number;
  }) {
    this._filePath = opts.filePath;
    this._maxSizeBytes = opts.maxSizeBytes ?? 50 * 1024 * 1024; // 50MB
    this._flushIntervalMs = opts.flushIntervalMs ?? 1000; // 1 second

    // Ensure directory exists
    const dir = path.dirname(this._filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Start periodic flush
    this._flushTimer = setInterval(() => this.flush(), this._flushIntervalMs);
  }

  onEvent(event: AgentEvent): void {
    this._buffer.push(JSON.stringify(event));

    // Flush immediately if buffer is large
    if (this._buffer.length >= 100) {
      this.flush();
    }
  }

  async onShutdown(): Promise<void> {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    this.flush();
  }

  private flush(): void {
    if (this._buffer.length === 0) return;

    try {
      // Rotate if too large
      if (
        fs.existsSync(this._filePath) &&
        fs.statSync(this._filePath).size > this._maxSizeBytes
      ) {
        const rotated = this._filePath + ".1";
        if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
        fs.renameSync(this._filePath, rotated);
      }

      fs.appendFileSync(
        this._filePath,
        this._buffer.join("\n") + "\n",
        "utf-8"
      );
      this._buffer = [];
    } catch {
      // Never crash on write failure
    }
  }
}

// ─── 3. Callback Listener ───────────────────────────────────────────

/**
 * Calls a user-provided function for every event.
 * Use this for custom integrations (Slack, PagerDuty, webhooks, etc.)
 */
export class CallbackListener implements EventListener {
  readonly name: string;
  private _callback: (event: AgentEvent) => void | Promise<void>;

  constructor(
    name: string,
    callback: (event: AgentEvent) => void | Promise<void>
  ) {
    this.name = name;
    this._callback = callback;
  }

  async onEvent(event: AgentEvent): Promise<void> {
    await this._callback(event);
  }
}

// ─── 4. Alert Listener ──────────────────────────────────────────────

/**
 * Sends alerts when specific event conditions are met:
 * - Tool calls are blocked
 * - Anomalies are detected
 * - Error rates exceed thresholds
 *
 * Alerts are dispatched through a pluggable AlertChannel interface
 * so users can send to Slack, email, PagerDuty, etc.
 */
export interface AlertChannel {
  name: string;
  send(alert: AlertPayload): Promise<void>;
}

export interface AlertPayload {
  severity: "info" | "warning" | "critical";
  title: string;
  message: string;
  event: AgentEvent;
  timestamp: string;
}

export class AlertListener implements EventListener {
  readonly name = "alerter";
  private _channels: AlertChannel[];
  private _errorCount = 0;
  private _errorWindowMs: number;
  private _errorThreshold: number;
  private _errorWindowStart = Date.now();

  constructor(opts: {
    channels: AlertChannel[];
    /** Time window for error rate calculation (ms). Default: 5 min */
    errorWindowMs?: number;
    /** Errors within window to trigger alert. Default: 5 */
    errorThreshold?: number;
  }) {
    this._channels = opts.channels;
    this._errorWindowMs = opts.errorWindowMs ?? 5 * 60 * 1000;
    this._errorThreshold = opts.errorThreshold ?? 5;
  }

  async onEvent(event: AgentEvent): Promise<void> {
    // Alert on blocked tool calls
    if (event.type === "tool_call_blocked") {
      await this.sendAlert({
        severity: "critical",
        title: `Tool call blocked: ${event.tool?.name}`,
        message:
          `Agent ${event.agent_id} attempted to call ${event.tool?.name} ` +
          `but was blocked. Reason: ${event.governance?.reason ?? "policy violation"}`,
        event,
        timestamp: event.timestamp,
      });
    }

    // Alert on anomalies
    if (event.anomaly?.detected) {
      await this.sendAlert({
        severity: "warning",
        title: `Anomaly detected: ${event.anomaly.type}`,
        message:
          `Agent ${event.agent_id}: ${event.anomaly.description ?? event.anomaly.type} ` +
          `(confidence: ${(event.anomaly.confidence * 100).toFixed(0)}%)`,
        event,
        timestamp: event.timestamp,
      });
    }

    // Track error rate
    if (event.tool?.status === "error") {
      const now = Date.now();
      if (now - this._errorWindowStart > this._errorWindowMs) {
        this._errorCount = 0;
        this._errorWindowStart = now;
      }
      this._errorCount++;

      if (this._errorCount >= this._errorThreshold) {
        await this.sendAlert({
          severity: "warning",
          title: `Error rate spike: ${this._errorCount} errors in ${Math.round(this._errorWindowMs / 1000)}s`,
          message:
            `Agent ${event.agent_id} has produced ${this._errorCount} errors ` +
            `in the last ${Math.round(this._errorWindowMs / 60000)} minutes`,
          event,
          timestamp: event.timestamp,
        });
        // Reset to avoid repeated alerts
        this._errorCount = 0;
        this._errorWindowStart = now;
      }
    }
  }

  private async sendAlert(alert: AlertPayload): Promise<void> {
    for (const channel of this._channels) {
      try {
        await channel.send(alert);
      } catch {
        // Never crash on alert failure
      }
    }
  }
}

// ─── 5. Event Store Listener ────────────────────────────────────────

/**
 * The critical bridge between the interceptor pipeline and the SQLite
 * event store. Receives AgentEvent objects from the interceptor, converts
 * them to GovernanceEvent objects (the event store's canonical schema),
 * and writes them to SQLite via the EventStoreWriter.
 *
 * This is what connects the full pipeline:
 *   Framework → Interceptor → EventStoreListener → SQLite → Query API
 *
 * The conversion maps the interceptor's telemetry-oriented AgentEvent
 * into the event store's governance-oriented GovernanceEvent, including:
 *   - event type normalization (tool_call_start → tool_call_attempted)
 *   - outcome classification (success/error/blocked → allowed/error/blocked)
 *   - severity inference from event type and governance data
 *   - cost/token extraction from the tokens field
 *   - payload preservation for drill-down detail
 */
export class EventStoreListener implements EventListener {
  readonly name = "event_store";
  private _writer: EventStoreWriter;
  private _framework: string;

  constructor(opts: {
    /** Path to the project root (where .sentinelflow/ lives) */
    projectDir: string;
    /** Framework name to tag events with */
    framework?: string;
    /** Custom database path (overrides default .sentinelflow/events.db) */
    dbPath?: string;
    /** Flush buffer size. Default: 50 */
    flushSize?: number;
  }) {
    this._framework = opts.framework ?? "unknown";
    this._writer = new EventStoreWriter({
      projectDir: opts.projectDir,
      dbPath: opts.dbPath,
      flushSize: opts.flushSize,
    });
  }

  onEvent(event: AgentEvent): void {
    const govEvent = this.convertEvent(event);
    this._writer.ingest(govEvent);
  }

  async onShutdown(): Promise<void> {
    // Flush remaining buffered events and compute today's rollup
    this._writer.flush();
    try {
      this._writer.computeTodayRollup();
    } catch {
      // Rollup failure is non-fatal
    }
    this._writer.close();
  }

  /** Expose the writer for manual flush/rollup operations */
  get writer(): EventStoreWriter {
    return this._writer;
  }

  /**
   * Convert an interceptor AgentEvent into a governance GovernanceEvent.
   *
   * This is the normalization layer. The interceptor speaks in
   * telemetry terms (tool_call_start, tool_call_end), while the
   * event store speaks in governance terms (tool_call_attempted,
   * tool_call_completed, policy_violation).
   */
  private convertEvent(event: AgentEvent): GovernanceEvent {
    return createGovernanceEvent({
      event_id: event.id,
      timestamp: event.timestamp,
      agent_id: event.agent_id,
      framework: this._framework,
      session_id: event.session_id,
      event_type: this.mapEventType(event),
      outcome: this.mapOutcome(event),
      severity: this.mapSeverity(event),
      tool_name: event.tool?.name,
      tool_input_summary: event.tool?.input_summary,
      action: event.tool?.input_summary,
      policy_id: event.governance?.policies_failed?.[0],
      policy_name: event.governance?.policies_failed?.[0],
      reason: event.governance?.reason,
      prompt_tokens: event.tokens?.input,
      completion_tokens: event.tokens?.output,
      cost_usd: event.tokens?.estimated_cost_usd,
      model: event.tokens?.model,
      duration_ms: event.tool?.duration_ms,
      payload: event.metadata as Record<string, unknown> | undefined,
    });
  }

  /**
   * Map interceptor event types to governance event types.
   * The interceptor uses telemetry-oriented names (tool_call_start),
   * while the event store uses governance-oriented names (tool_call_attempted).
   */
  private mapEventType(event: AgentEvent): GovernanceEventType {
    switch (event.type) {
      case "tool_call_start":
        return "tool_call_attempted";
      case "tool_call_end":
        return event.tool?.status === "error"
          ? "tool_call_failed"
          : "tool_call_completed";
      case "tool_call_blocked":
        return "tool_call_blocked";
      case "session_start":
        return "session_started";
      case "session_end":
        return "session_ended";
      case "delegation":
        return "delegation_spawned";
      default:
        return "tool_call_attempted";
    }
  }

  /**
   * Map the interceptor's tool status into a governance outcome.
   * "blocked" is the most governance-significant outcome — it means
   * a policy actively prevented an agent action.
   */
  private mapOutcome(event: AgentEvent): EventOutcome {
    if (event.type === "tool_call_blocked") return "blocked";
    if (event.governance?.action_taken === "blocked") return "blocked";
    if (event.governance?.action_taken === "flagged") return "flagged";
    if (event.tool?.status === "error") return "error";
    if (event.tool?.status === "blocked") return "blocked";
    if (event.type === "session_start" || event.type === "session_end") return "info";
    return "allowed";
  }

  /**
   * Infer severity from the event. Blocked tool calls are high severity
   * because they represent policy enforcement actions. Errors are medium.
   * Normal operations are low/info.
   */
  private mapSeverity(event: AgentEvent): EventSeverity {
    if (event.type === "tool_call_blocked") return "high";
    if (event.governance?.action_taken === "blocked") return "high";
    if (event.tool?.status === "error") return "medium";
    if (event.anomaly?.detected) {
      return event.anomaly.confidence > 0.8 ? "high" : "medium";
    }
    return "info";
  }
}
