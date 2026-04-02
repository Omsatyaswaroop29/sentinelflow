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
