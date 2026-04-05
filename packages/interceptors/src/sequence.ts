/**
 * @module @sentinelflow/interceptors/sequence
 *
 * Multi-step attack sequence detection.
 *
 * Moves SentinelFlow from "single-call guardrails" to "session-level governance."
 * Instead of evaluating each tool call in isolation, this module correlates
 * events within a session to detect attack chains that are individually
 * harmless but collectively dangerous.
 *
 * Known attack sequences detected:
 *
 *   1. SCRIPT_INJECTION: Write file → chmod +x → execute that file
 *      An agent writes a script, makes it executable, then runs it.
 *      Each step alone is legal; together they're code injection.
 *
 *   2. DATA_EXFILTRATION: Read sensitive path → outbound network call
 *      An agent reads credentials or source code, then makes an HTTP
 *      request. Classic data exfiltration pattern.
 *
 *   3. PERSISTENCE_PROBE: Repeated blocked attempts on similar patterns
 *      An agent keeps trying dangerous operations after being blocked,
 *      possibly probing for bypasses or being driven by adversarial input.
 *
 *   4. PRIVILEGE_CHAIN: Write to config → restart/reload → elevated access
 *      An agent modifies a config file that grants privileges, then
 *      triggers a reload.
 *
 * Architecture:
 *   - Implements AnomalyDetector so it plugs into the existing AnomalyEngine
 *   - Maintains a per-session sliding window of recent events
 *   - Each sequence rule is a simple state machine checked on every event
 *   - Window is time-bounded (default 5 minutes) and size-bounded (default 50 events)
 *
 * Design principles:
 *   - Deterministic: no ML, no probabilistic scoring for sequence matching
 *   - Explainable: every detection includes the full chain of events that triggered it
 *   - Conservative: requires all steps of a sequence to match, not "close enough"
 */

import type { AgentEvent, AnomalyResult } from "@sentinelflow/core";
import type { AnomalyDetector } from "./anomaly";
import { SHELL_TOOL_NAMES, SENSITIVE_WRITE_PATHS, compilePatterns } from "./patterns";
import { extractDomain } from "./normalizer";

// ─── Types ──────────────────────────────────────────────────────────

export type SequenceType =
  | "script_injection"
  | "data_exfiltration"
  | "persistence_probe"
  | "privilege_chain";

export interface SequenceMatch {
  type: SequenceType;
  description: string;
  confidence: number;
  /** The chain of events that formed this sequence */
  chain: Array<{
    event_id: string;
    timestamp: string;
    tool_name: string;
    summary: string;
  }>;
}

interface WindowEvent {
  id: string;
  timestamp: string;
  ts: number;
  tool_name: string;
  input_summary: string;
  event_type: string;
  outcome: string;
  session_id: string;
}

// ─── Configuration ──────────────────────────────────────────────────

export interface SequenceDetectorConfig {
  /** Maximum age of events in the window (ms). Default: 5 minutes */
  windowMs?: number;
  /** Maximum events to keep per session. Default: 50 */
  maxWindowSize?: number;
  /** Minimum confidence to report. Default: 0.7 */
  minConfidence?: number;
  /** Sequence types to detect. Default: all */
  enabledSequences?: SequenceType[];
}

// ─── Detector Implementation ────────────────────────────────────────

export class SequenceDetector implements AnomalyDetector {
  readonly name = "sequence_detector";
  readonly type = "unusual_pattern" as const;

  private _windowMs: number;
  private _maxWindowSize: number;
  private _minConfidence: number;
  private _enabledSequences: Set<SequenceType>;

  /** Per-session sliding window of recent events */
  private _windows: Map<string, WindowEvent[]> = new Map();

  /** Compiled sensitive path patterns for data exfiltration detection */
  private _sensitivePaths = compilePatterns(SENSITIVE_WRITE_PATHS);

  /** Shell tool names for identifying command execution */
  private _shellTools = SHELL_TOOL_NAMES;

  /** Write tool names */
  private _writeTools = new Set([
    "Write", "write", "Edit", "edit", "MultiEdit", "multiedit",
    "Create", "create", "FileEdit", "file_edit",
    "create_file", "write_file", "edit_file",
  ]);

  /** Read tool names */
  private _readTools = new Set([
    "Read", "read", "ReadFile", "read_file", "View", "view",
    "Cat", "cat", "ListDir", "list_dir",
  ]);

  constructor(config?: SequenceDetectorConfig) {
    this._windowMs = config?.windowMs ?? 5 * 60 * 1000;
    this._maxWindowSize = config?.maxWindowSize ?? 50;
    this._minConfidence = config?.minConfidence ?? 0.7;
    this._enabledSequences = new Set(
      config?.enabledSequences ?? [
        "script_injection",
        "data_exfiltration",
        "persistence_probe",
        "privilege_chain",
      ]
    );
  }

  analyze(event: AgentEvent): AnomalyResult | null {
    const sessionId = event.session_id;
    if (!sessionId) return null;

    // Build window event from the AgentEvent
    const windowEvent: WindowEvent = {
      id: event.id,
      timestamp: event.timestamp,
      ts: new Date(event.timestamp).getTime(),
      tool_name: event.tool?.name ?? "",
      input_summary: event.tool?.input_summary ?? "",
      event_type: event.type,
      outcome: event.governance?.action_taken ?? (event.tool?.status === "blocked" ? "blocked" : "allowed"),
      session_id: sessionId,
    };

    // Get or create window for this session
    if (!this._windows.has(sessionId)) {
      this._windows.set(sessionId, []);
    }
    const window = this._windows.get(sessionId)!;

    // Add event to window
    window.push(windowEvent);

    // Evict old events (time-based)
    const cutoff = windowEvent.ts - this._windowMs;
    while (window.length > 0 && window[0]!.ts < cutoff) {
      window.shift();
    }

    // Evict if window is too large (size-based)
    while (window.length > this._maxWindowSize) {
      window.shift();
    }

    // Run all enabled sequence detectors
    const matches: SequenceMatch[] = [];

    if (this._enabledSequences.has("script_injection")) {
      const m = this.detectScriptInjection(window, windowEvent);
      if (m) matches.push(m);
    }

    if (this._enabledSequences.has("data_exfiltration")) {
      const m = this.detectDataExfiltration(window, windowEvent);
      if (m) matches.push(m);
    }

    if (this._enabledSequences.has("persistence_probe")) {
      const m = this.detectPersistenceProbe(window, windowEvent);
      if (m) matches.push(m);
    }

    if (this._enabledSequences.has("privilege_chain")) {
      const m = this.detectPrivilegeChain(window, windowEvent);
      if (m) matches.push(m);
    }

    // Return the highest-confidence match
    if (matches.length === 0) return null;

    matches.sort((a, b) => b.confidence - a.confidence);
    const best = matches[0]!;

    if (best.confidence < this._minConfidence) return null;

    return {
      detected: true,
      type: "unusual_pattern",
      confidence: best.confidence,
      description: `[${best.type.toUpperCase()}] ${best.description}` +
        ` | Chain: ${best.chain.map((e) => e.tool_name + "(" + e.summary.slice(0, 40) + ")").join(" → ")}`,
    };
  }

  reset(): void {
    this._windows.clear();
  }

  /** Get the current window size for a session (for testing) */
  getWindowSize(sessionId: string): number {
    return this._windows.get(sessionId)?.length ?? 0;
  }

  // ─── Sequence 1: Script Injection ───────────────────────────

  /**
   * Detect: Write file → chmod +x → execute that file
   *
   * Checks if the current event is a shell execution of a file
   * that was recently written and made executable in this session.
   */
  private detectScriptInjection(
    window: WindowEvent[],
    current: WindowEvent
  ): SequenceMatch | null {
    // Current event must be a shell command
    if (!this._shellTools.has(current.tool_name)) return null;

    const cmd = current.input_summary.toLowerCase();

    // Look backward through the window for write → chmod → execute chain
    for (let i = window.length - 2; i >= 0; i--) {
      const prev = window[i]!;

      // Step 2: chmod +x on a specific file
      if (this._shellTools.has(prev.tool_name)) {
        const chmodMatch = prev.input_summary.match(
          /chmod\s+(?:\+x|[0-7]*[1357][0-7]*)\s+(\S+)/
        );
        if (!chmodMatch) continue;
        const targetFile = chmodMatch[1]!;

        // Does the current command execute that file?
        if (!cmd.includes(targetFile.toLowerCase()) &&
            !cmd.includes("./" + targetFile.toLowerCase().replace(/^\.\//, ""))) {
          continue;
        }

        // Step 1: Look for a write to that same file before the chmod
        for (let j = i - 1; j >= 0; j--) {
          const writeEvent = window[j]!;

          const isWrite =
            this._writeTools.has(writeEvent.tool_name) ||
            (this._shellTools.has(writeEvent.tool_name) &&
              /(?:>>?|tee)\s/.test(writeEvent.input_summary));

          if (!isWrite) continue;

          // Check if the write target matches the chmod target
          if (writeEvent.input_summary.toLowerCase().includes(targetFile.toLowerCase())) {
            return {
              type: "script_injection",
              description: `Script injection chain detected: file "${targetFile}" was written, made executable, and then executed within ${Math.round(this._windowMs / 60000)} minutes.`,
              confidence: 0.92,
              chain: [
                { event_id: writeEvent.id, timestamp: writeEvent.timestamp, tool_name: writeEvent.tool_name, summary: writeEvent.input_summary },
                { event_id: prev.id, timestamp: prev.timestamp, tool_name: prev.tool_name, summary: prev.input_summary },
                { event_id: current.id, timestamp: current.timestamp, tool_name: current.tool_name, summary: current.input_summary },
              ],
            };
          }
        }
      }
    }

    return null;
  }

  // ─── Sequence 2: Data Exfiltration ──────────────────────────

  /**
   * Detect: Read sensitive path → outbound network call
   *
   * Checks if the current event is a network command that follows
   * a recent read of a sensitive file in this session.
   */
  private detectDataExfiltration(
    window: WindowEvent[],
    current: WindowEvent
  ): SequenceMatch | null {
    // Current event must be a shell command with network activity
    if (!this._shellTools.has(current.tool_name)) return null;

    const cmd = current.input_summary;
    const hasNetwork = /\b(curl|wget|fetch|http|requests\.|nc\b|netcat|scp\b|ssh\b)/i.test(cmd);
    if (!hasNetwork) return null;

    // Look backward for a recent read of a sensitive path
    for (let i = window.length - 2; i >= 0; i--) {
      const prev = window[i]!;

      // Was this a file read?
      const isRead =
        this._readTools.has(prev.tool_name) ||
        (this._shellTools.has(prev.tool_name) &&
          /\b(cat|head|tail|less|more|grep)\b/.test(prev.input_summary));

      if (!isRead) continue;

      // Was the read target a sensitive path?
      const readPath = prev.input_summary;
      let isSensitive = false;
      let sensitiveLabel = "";

      for (const pattern of this._sensitivePaths) {
        if (pattern.compiled.test(readPath)) {
          isSensitive = true;
          sensitiveLabel = pattern.description;
          break;
        }
      }

      // Also check common sensitive path keywords
      if (!isSensitive) {
        if (/\.(env|pem|key|secret|credential|token|password)/i.test(readPath) ||
            /\/\.ssh\//i.test(readPath) ||
            /\/\.aws\//i.test(readPath) ||
            /\/\.gnupg\//i.test(readPath)) {
          isSensitive = true;
          sensitiveLabel = "sensitive file pattern";
        }
      }

      if (isSensitive) {
        return {
          type: "data_exfiltration",
          description: `Potential data exfiltration: read of ${sensitiveLabel} followed by outbound network call within ${Math.round(this._windowMs / 60000)} minutes.`,
          confidence: 0.85,
          chain: [
            { event_id: prev.id, timestamp: prev.timestamp, tool_name: prev.tool_name, summary: prev.input_summary },
            { event_id: current.id, timestamp: current.timestamp, tool_name: current.tool_name, summary: current.input_summary },
          ],
        };
      }
    }

    return null;
  }

  // ─── Sequence 3: Persistence Probe ──────────────────────────

  /**
   * Detect: Repeated blocked attempts on similar patterns
   *
   * If the same session has N+ blocked tool calls within the window,
   * that's a sign of an agent probing for bypasses or being driven
   * by adversarial input that keeps retrying.
   */
  private detectPersistenceProbe(
    window: WindowEvent[],
    current: WindowEvent
  ): SequenceMatch | null {
    // Only trigger on blocked events
    if (current.outcome !== "blocked") return null;

    // Count recent blocked events in this window
    const blockedEvents = window.filter((e) => e.outcome === "blocked");

    // Need at least 3 blocked attempts to flag
    if (blockedEvents.length < 3) return null;

    // Check if the blocked attempts are similar (same tool or similar commands)
    const toolCounts = new Map<string, number>();
    for (const e of blockedEvents) {
      const key = e.tool_name;
      toolCounts.set(key, (toolCounts.get(key) ?? 0) + 1);
    }

    // Find the most-repeated blocked tool
    let maxTool = "";
    let maxCount = 0;
    for (const [tool, count] of toolCounts) {
      if (count > maxCount) {
        maxTool = tool;
        maxCount = count;
      }
    }

    // At least 3 blocked attempts on the same tool
    if (maxCount < 3) return null;

    const confidence = Math.min(0.95, 0.7 + (maxCount - 3) * 0.05);
    const chain = blockedEvents
      .filter((e) => e.tool_name === maxTool)
      .slice(-5) // Show last 5
      .map((e) => ({
        event_id: e.id,
        timestamp: e.timestamp,
        tool_name: e.tool_name,
        summary: e.input_summary,
      }));

    return {
      type: "persistence_probe",
      description: `Persistence probe detected: ${maxCount} blocked attempts on tool "${maxTool}" within ${Math.round(this._windowMs / 60000)} minutes. The agent may be probing for bypasses.`,
      confidence,
      chain,
    };
  }

  // ─── Sequence 4: Privilege Chain ────────────────────────────

  /**
   * Detect: Write to config/auth file → restart/reload service
   *
   * An agent modifying privilege-granting config files (authorized_keys,
   * sudoers, .npmrc, docker configs) followed by a service restart
   * or source command is a privilege escalation chain.
   */
  private detectPrivilegeChain(
    window: WindowEvent[],
    current: WindowEvent
  ): SequenceMatch | null {
    // Current event must be a shell command that triggers a reload
    if (!this._shellTools.has(current.tool_name)) return null;

    const cmd = current.input_summary.toLowerCase();
    const isReload = /\b(source|reload|restart|systemctl|service\s+\S+\s+(start|restart)|npm\s+install|pip\s+install)\b/.test(cmd) ||
      /\.\s+(\.bashrc|\.profile|\.zshrc|\.bash_profile)/.test(cmd);

    if (!isReload) return null;

    // Look backward for a write to a privilege-granting file
    const privilegeFiles = [
      /\.ssh\/authorized_keys/i,
      /sudoers/i,
      /\.bashrc|\.profile|\.zshrc|\.bash_profile/i,
      /\.npmrc/i,
      /\.netrc/i,
      /docker.*\.json/i,
      /\.kube\/config/i,
      /\.aws\/credentials/i,
    ];

    for (let i = window.length - 2; i >= 0; i--) {
      const prev = window[i]!;

      const isWrite =
        this._writeTools.has(prev.tool_name) ||
        (this._shellTools.has(prev.tool_name) &&
          /(?:>>?|tee)\s/.test(prev.input_summary));

      if (!isWrite) continue;

      for (const pattern of privilegeFiles) {
        if (pattern.test(prev.input_summary)) {
          return {
            type: "privilege_chain",
            description: `Privilege escalation chain: write to privilege-granting file followed by reload/restart within ${Math.round(this._windowMs / 60000)} minutes.`,
            confidence: 0.88,
            chain: [
              { event_id: prev.id, timestamp: prev.timestamp, tool_name: prev.tool_name, summary: prev.input_summary },
              { event_id: current.id, timestamp: current.timestamp, tool_name: current.tool_name, summary: current.input_summary },
            ],
          };
        }
      }
    }

    return null;
  }
}
