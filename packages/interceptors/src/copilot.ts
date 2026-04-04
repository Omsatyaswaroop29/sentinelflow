/**
 * @module @sentinelflow/interceptors/copilot
 *
 * GitHub Copilot Runtime Interceptor — verified against official GitHub docs.
 *
 * Sources:
 *   - docs.github.com/en/copilot/reference/hooks-configuration
 *   - docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks
 *   - code.visualstudio.com/docs/copilot/customization/hooks
 *
 * CRITICAL COMPATIBILITY NOTE from VS Code docs:
 *   "VS Code uses the same hook format as Claude Code and Copilot CLI for compatibility"
 *
 * Hooks contract:
 *
 *   Config lives at `.github/hooks/<name>.json` (multiple files merge).
 *   Must be on the repo's default branch for Copilot cloud agent.
 *   CLI loads hooks from the current working directory.
 *
 *   Format:
 *   {
 *     "version": 1,
 *     "hooks": {
 *       "preToolUse": [{
 *         "type": "command",
 *         "bash": "node .sentinelflow/copilot-handler.js",
 *         "timeoutSec": 10
 *       }]
 *     }
 *   }
 *
 *   Stdin JSON for preToolUse:
 *   {
 *     "timestamp": 1704614400000,
 *     "cwd": "/path/to/project",
 *     "sessionId": "session-id",
 *     "hookEventName": "PreToolUse",
 *     "toolName": "bash",
 *     "toolArgs": "{\"command\":\"npm test\"}"
 *   }
 *
 *   NOTE: toolArgs is a JSON STRING, not an object. Must be parsed.
 *
 *   Blocking (identical to Claude Code):
 *     Exit 0 = allow (proceed with tool execution)
 *     Exit 2 = block (stderr fed back to model as context)
 *
 *   6 lifecycle hooks:
 *     sessionStart         — session begins or resumes
 *     sessionEnd           — session completes or terminates
 *     userPromptSubmitted  — user submits a prompt
 *     preToolUse           — before tool execution (CAN BLOCK via exit 2)
 *     postToolUse          — after tool execution
 *     errorOccurred        — when errors happen
 */

import * as fs from "fs";
import * as path from "path";
import { v4 as uuidv4 } from "uuid";
import type { AgentEvent, ToolEventData, TokenUsage } from "@sentinelflow/core";
import { BaseInterceptor } from "./base";
import type {
  InterceptorConfig,
  PolicyProvider,
  EventListener,
} from "./interface";

// ─── Copilot Hook Event Types ───────────────────────────────────────

/** preToolUse stdin payload */
export interface CopilotPreToolUsePayload {
  timestamp: number | string;
  cwd: string;
  sessionId?: string;
  hookEventName?: string;
  toolName: string;
  toolArgs: string;  // JSON STRING — must be parsed
}

/** postToolUse stdin payload */
export interface CopilotPostToolUsePayload {
  timestamp: number | string;
  cwd: string;
  sessionId?: string;
  hookEventName?: string;
  toolName: string;
  toolArgs?: string;
  toolResult?: string;
  exitCode?: number;
}

/** sessionStart stdin payload */
export interface CopilotSessionStartPayload {
  timestamp: number | string;
  cwd: string;
  sessionId?: string;
  hookEventName?: string;
  source?: string;
  initialPrompt?: string;
}

/** sessionEnd stdin payload */
export interface CopilotSessionEndPayload {
  timestamp: number | string;
  cwd: string;
  sessionId?: string;
  hookEventName?: string;
}

/** Union of all Copilot hook payloads */
export type CopilotHookInput =
  | CopilotPreToolUsePayload
  | CopilotPostToolUsePayload
  | CopilotSessionStartPayload
  | CopilotSessionEndPayload;

// ─── Configuration ──────────────────────────────────────────────────

export interface CopilotInterceptorConfig extends Partial<InterceptorConfig> {
  projectDir: string;
  eventLogPath?: string;
  maxLogSizeBytes?: number;
  toolAllowlist?: string[];
  toolBlocklist?: string[];
  maxInputSummaryLength?: number;
  /** Name for the hooks JSON file. Default: "sentinelflow" → .github/hooks/sentinelflow.json */
  hooksFileName?: string;
}

// ─── Constants ──────────────────────────────────────────────────────

const GITHUB_DIR = ".github";
const HOOKS_DIR = "hooks";
const SF_DIR = ".sentinelflow";
const HANDLER_SCRIPT = "copilot-handler.js";
const EVENT_LOG_FILE = "events.jsonl";
const DEFAULT_MAX_LOG_SIZE = 50 * 1024 * 1024;
const DEFAULT_MAX_INPUT_LENGTH = 500;
const HOOK_TIMEOUT_SEC = 10;

// ─── Interceptor Implementation ─────────────────────────────────────

export class CopilotInterceptor extends BaseInterceptor {
  readonly framework = "copilot";

  private _projectDir: string;
  private _eventLogPath: string;
  private _maxLogSize: number;
  private _toolAllowlist: Set<string>;
  private _toolBlocklist: Set<string>;
  private _maxInputLength: number;
  private _hooksFileName: string;
  private _originalHooksJson: string | null = null;

  constructor(config: CopilotInterceptorConfig) {
    super(config);
    this._projectDir = path.resolve(config.projectDir);
    this._eventLogPath =
      config.eventLogPath ??
      path.join(this._projectDir, SF_DIR, EVENT_LOG_FILE);
    this._maxLogSize = config.maxLogSizeBytes ?? DEFAULT_MAX_LOG_SIZE;
    this._toolAllowlist = new Set(config.toolAllowlist ?? []);
    this._toolBlocklist = new Set(config.toolBlocklist ?? []);
    this._maxInputLength = config.maxInputSummaryLength ?? DEFAULT_MAX_INPUT_LENGTH;
    this._hooksFileName = config.hooksFileName ?? "sentinelflow";
  }

  // ─── Static Helpers ─────────────────────────────────────────

  static isInstalled(projectDir: string): boolean {
    const hooksDir = path.join(projectDir, GITHUB_DIR, HOOKS_DIR);
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    if (!fs.existsSync(handlerPath)) return false;
    if (!fs.existsSync(hooksDir)) return false;
    // Check if any hooks JSON in .github/hooks/ references sentinelflow
    try {
      const files = fs.readdirSync(hooksDir).filter((f) => f.endsWith(".json"));
      for (const file of files) {
        const content = fs.readFileSync(path.join(hooksDir, file), "utf-8");
        if (content.includes("sentinelflow") || content.includes(HANDLER_SCRIPT)) return true;
      }
    } catch { /* directory might not exist */ }
    return false;
  }

  static uninstall(projectDir: string): void {
    // Remove handler script
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    if (fs.existsSync(handlerPath)) fs.unlinkSync(handlerPath);

    // Remove our hooks JSON file(s) from .github/hooks/
    const hooksDir = path.join(projectDir, GITHUB_DIR, HOOKS_DIR);
    if (fs.existsSync(hooksDir)) {
      try {
        const files = fs.readdirSync(hooksDir).filter((f) => f.endsWith(".json"));
        for (const file of files) {
          const filePath = path.join(hooksDir, file);
          const content = fs.readFileSync(filePath, "utf-8");
          if (content.includes("sentinelflow") || content.includes(HANDLER_SCRIPT)) {
            fs.unlinkSync(filePath);
          }
        }
        // Clean up empty hooks directory
        const remaining = fs.readdirSync(hooksDir);
        if (remaining.length === 0) {
          fs.rmdirSync(hooksDir);
        }
      } catch { /* skip cleanup errors */ }
    }
  }

  // ─── Framework Hook Methods ─────────────────────────────────

  protected async hookFramework(): Promise<void> {
    const sfDir = path.join(this._projectDir, SF_DIR);
    const hooksDir = path.join(this._projectDir, GITHUB_DIR, HOOKS_DIR);
    fs.mkdirSync(sfDir, { recursive: true });
    fs.mkdirSync(hooksDir, { recursive: true });

    // Generate the handler script
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);
    fs.writeFileSync(handlerPath, this.generateHandlerScript());
    fs.chmodSync(handlerPath, "755");

    // Write the hooks config to .github/hooks/sentinelflow.json
    const hooksPath = path.join(hooksDir, `${this._hooksFileName}.json`);
    if (fs.existsSync(hooksPath)) {
      this._originalHooksJson = fs.readFileSync(hooksPath, "utf-8");
    }
    fs.writeFileSync(hooksPath, JSON.stringify(this.generateHooksConfig(), null, 2));

    this.log("info", `Installed Copilot hooks at ${hooksPath}`);
    this.log("info", `Handler: ${handlerPath}`);
  }

  protected async unhookFramework(): Promise<void> {
    const handlerPath = path.join(this._projectDir, SF_DIR, HANDLER_SCRIPT);
    if (fs.existsSync(handlerPath)) fs.unlinkSync(handlerPath);

    const hooksPath = path.join(this._projectDir, GITHUB_DIR, HOOKS_DIR, `${this._hooksFileName}.json`);
    if (this._originalHooksJson) {
      fs.writeFileSync(hooksPath, this._originalHooksJson);
    } else if (fs.existsSync(hooksPath)) {
      fs.unlinkSync(hooksPath);
    }

    this.log("info", "Uninstalled Copilot hooks");
  }

  // ─── Hooks Config ───────────────────────────────────────────

  /**
   * Generate .github/hooks/sentinelflow.json
   *
   * Uses `bash` key for the command. On Windows, users would need
   * to add a `powershell` key alongside — we can add this later.
   *
   * Commands run from the repository root (no `cwd` specified).
   */
  private generateHooksConfig(): Record<string, unknown> {
    const handlerCmd = `node ${SF_DIR}/${HANDLER_SCRIPT}`;

    const hookEntry = {
      type: "command",
      bash: handlerCmd,
      timeoutSec: HOOK_TIMEOUT_SEC,
    };

    return {
      version: 1,
      hooks: {
        preToolUse: [hookEntry],
        postToolUse: [hookEntry],
        sessionStart: [hookEntry],
        sessionEnd: [hookEntry],
        errorOccurred: [hookEntry],
      },
    };
  }

  /**
   * Generate the Copilot handler script.
   *
   * BLOCKING IS IDENTICAL TO CLAUDE CODE:
   *   Exit 0 = allow. Exit 2 = block (stderr → model feedback).
   *
   * KEY DIFFERENCE: toolArgs is a JSON STRING, must be parsed.
   * Also: timestamp is a number (epoch ms) not ISO string.
   */
  private generateHandlerScript(): string {
    return `#!/usr/bin/env node
/**
 * SentinelFlow GitHub Copilot Hook Handler
 * Generated by @sentinelflow/interceptors
 *
 * Blocking contract (same as Claude Code):
 *   Exit 0 = allow. Exit 2 = block (stderr fed to model).
 *
 * Fail-open: errors always exit 0.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ─── Configuration ──────────────────────────────────────────
const PROJECT_DIR = ${JSON.stringify(this._projectDir)};
const SF_DIR = path.join(PROJECT_DIR, ".sentinelflow");
const EVENT_LOG = path.join(SF_DIR, "events.jsonl");
const DB_PATH = path.join(SF_DIR, "events.db");
const TOOL_ALLOWLIST = new Set(${JSON.stringify([...this._toolAllowlist])});
const TOOL_BLOCKLIST = new Set(${JSON.stringify([...this._toolBlocklist])});
const ENFORCEMENT_MODE = ${JSON.stringify(this.enforcementMode)};
const MAX_INPUT_LENGTH = ${this._maxInputLength};

// ─── Module resolution ──────────────────────────────────────
const _addPaths = [
  path.join(PROJECT_DIR, "node_modules"),
  path.join(PROJECT_DIR, "node_modules", ".pnpm", "node_modules"),
  path.join(PROJECT_DIR, "..", "node_modules"),
];
for (const p of _addPaths) {
  if (fs.existsSync(p) && !module.paths.includes(p)) module.paths.unshift(p);
}

// ─── SQLite (optional) ──────────────────────────────────────
let db = null;
try {
  const Database = require("better-sqlite3");
  if (!fs.existsSync(SF_DIR)) fs.mkdirSync(SF_DIR, { recursive: true });
  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("busy_timeout = 3000");
  db.exec(\`
    CREATE TABLE IF NOT EXISTS events (
      event_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1,
      ts TEXT NOT NULL, agent_id TEXT NOT NULL, framework TEXT NOT NULL,
      session_id TEXT NOT NULL, parent_event_id TEXT,
      event_type TEXT NOT NULL, outcome TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      tool_name TEXT, tool_input_summary TEXT, action TEXT,
      policy_id TEXT, policy_name TEXT, reason TEXT,
      prompt_tokens INTEGER, completion_tokens INTEGER, cost_usd REAL,
      model TEXT, duration_ms INTEGER, payload_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events(agent_id, ts);
    CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts);
    CREATE INDEX IF NOT EXISTS idx_events_outcome_ts ON events(outcome, ts);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name, ts);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, ts);
  \`);
} catch (e) { /* SQLite unavailable */ }

// ─── Helpers ────────────────────────────────────────────────
function persistEvent(ev) {
  try {
    if (!fs.existsSync(SF_DIR)) fs.mkdirSync(SF_DIR, { recursive: true });
    fs.appendFileSync(EVENT_LOG, JSON.stringify(ev) + "\\n");
  } catch { /* never crash on log failure */ }
  if (db) {
    try {
      db.prepare(\`INSERT OR IGNORE INTO events (
        event_id, ts, agent_id, framework, session_id,
        event_type, outcome, severity,
        tool_name, tool_input_summary, action,
        policy_id, reason, payload_json
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)\`).run(
        ev.event_id, ev.timestamp, ev.agent_id, ev.framework, ev.session_id,
        ev.event_type, ev.outcome, ev.severity,
        ev.tool_name || null, ev.tool_input_summary || null, ev.action || null,
        ev.policy_id || null, ev.reason || null,
        ev.payload ? JSON.stringify(ev.payload) : null
      );
    } catch { /* non-fatal */ }
  }
}

function makeEvent(type, outcome, severity, opts = {}) {
  return {
    event_id: crypto.randomUUID(),
    schema_version: 1,
    timestamp: new Date().toISOString(),
    agent_id: opts.agent_id || "copilot-agent",
    framework: "copilot",
    session_id: opts.session_id || "unknown",
    event_type: type, outcome, severity,
    tool_name: opts.tool_name || null,
    tool_input_summary: opts.tool_input_summary || null,
    action: opts.action || null,
    policy_id: opts.policy_id || null,
    reason: opts.reason || null,
    payload: opts.payload || null,
  };
}

// ─── Dangerous Command Detection ────────────────────────────
const DANGEROUS_PATTERNS = [
  { pattern: /rm\\s+-rf\\s+\\/(?!tmp)/, label: "rm -rf outside /tmp" },
  { pattern: /curl\\s+.*\\|\\s*(bash|sh|zsh)/, label: "curl piped to shell" },
  { pattern: /wget\\s+.*\\|\\s*(bash|sh|zsh)/, label: "wget piped to shell" },
  { pattern: /chmod\\s+777/, label: "chmod 777" },
  { pattern: />(\\s*)\\/etc\\//, label: "write to /etc" },
  { pattern: /\\bdd\\b.*\\bof=\\/dev\\//, label: "dd to block device" },
  { pattern: /mkfs\\./, label: "filesystem format" },
  { pattern: /\\bnpm\\s+publish\\b/, label: "npm publish" },
  { pattern: /\\bgit\\s+push\\b.*--force/, label: "force push" },
];

function checkDangerousCommand(cmd) {
  for (const { pattern, label } of DANGEROUS_PATTERNS) {
    if (pattern.test(cmd)) return { dangerous: true, label, command: cmd };
  }
  return { dangerous: false };
}

/**
 * Parse toolArgs — Copilot sends this as a JSON STRING, not an object.
 * e.g. toolArgs: '{"command":"ls -la"}'
 */
function parseToolArgs(toolArgs) {
  if (!toolArgs) return {};
  if (typeof toolArgs === "object") return toolArgs;
  try { return JSON.parse(toolArgs); } catch { return { raw: toolArgs }; }
}

function summarizeToolArgs(toolName, parsedArgs) {
  if (parsedArgs.command) return parsedArgs.command.slice(0, MAX_INPUT_LENGTH);
  if (parsedArgs.file_path) return "file: " + parsedArgs.file_path;
  if (parsedArgs.filePath) return "file: " + parsedArgs.filePath;
  const raw = JSON.stringify(parsedArgs);
  return raw.length > MAX_INPUT_LENGTH ? raw.slice(0, MAX_INPUT_LENGTH) + "..." : raw;
}

// ─── Main Handler ───────────────────────────────────────────
(async () => {
  let raw = "";
  try {
    raw = await new Promise((resolve, reject) => {
      const chunks = [];
      process.stdin.on("data", (c) => chunks.push(c));
      process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
      process.stdin.on("error", reject);
      setTimeout(() => resolve(Buffer.concat(chunks).toString("utf-8")), 5000);
    });
  } catch { process.exit(0); }

  if (!raw.trim()) { process.exit(0); }

  let input;
  try { input = JSON.parse(raw); }
  catch (e) {
    process.stderr.write("SentinelFlow: Failed to parse stdin JSON\\n");
    process.exit(0); // fail open
  }

  // Detect hook event from hookEventName (VS Code) or infer from fields
  const hookEvent = (input.hookEventName || input.hook_event_name || "").toLowerCase();
  const sessionId = input.sessionId || input.session_id || "unknown";

  // Determine event type
  let eventType = "unknown";
  if (hookEvent.includes("pretooluse") || input.toolName) {
    eventType = "preToolUse";
  } else if (hookEvent.includes("posttooluse")) {
    eventType = "postToolUse";
  } else if (hookEvent.includes("sessionstart")) {
    eventType = "sessionStart";
  } else if (hookEvent.includes("sessionend")) {
    eventType = "sessionEnd";
  } else if (hookEvent.includes("error")) {
    eventType = "errorOccurred";
  } else if (hookEvent.includes("prompt")) {
    eventType = "userPromptSubmitted";
  } else if (input.toolName) {
    eventType = "preToolUse"; // fallback: if toolName is present, likely preToolUse
  }

  try {
    switch (eventType) {

    case "preToolUse": {
      const toolName = input.toolName || "unknown";
      const parsedArgs = parseToolArgs(input.toolArgs);
      const inputSummary = summarizeToolArgs(toolName, parsedArgs);

      // Tool blocklist check
      if (ENFORCEMENT_MODE === "enforce" && TOOL_BLOCKLIST.has(toolName)) {
        const reason = 'Tool "' + toolName + '" is in the blocklist';
        persistEvent(makeEvent("tool_call_blocked", "blocked", "medium",
          { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
            action: inputSummary, policy_id: "tool_blocklist", reason,
            payload: { hook: "preToolUse", cwd: input.cwd } }));
        process.stderr.write("SentinelFlow: " + reason + "\\n");
        process.exit(2); // EXIT 2 = BLOCK (same as Claude Code)
      }

      // Dangerous command check (for bash/shell tools)
      if (ENFORCEMENT_MODE === "enforce" &&
          (toolName === "bash" || toolName === "shell" || toolName === "terminal")) {
        const cmd = parsedArgs.command || parsedArgs.raw || "";
        const check = checkDangerousCommand(cmd);
        if (check.dangerous) {
          const reason = "Dangerous command: " + check.label + " \\u2014 " + cmd.slice(0, 100);
          persistEvent(makeEvent("tool_call_blocked", "blocked", "high",
            { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
              action: inputSummary, policy_id: "dangerous_commands", reason,
              payload: { hook: "preToolUse", cwd: input.cwd } }));
          process.stderr.write("SentinelFlow: " + reason + "\\n");
          process.exit(2); // EXIT 2 = BLOCK
        }
      }

      // Allowed
      persistEvent(makeEvent("tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary, payload: { hook: "preToolUse", cwd: input.cwd } }));
      process.exit(0);
    }

    case "postToolUse": {
      const toolName = input.toolName || "unknown";
      const parsedArgs = parseToolArgs(input.toolArgs);
      const inputSummary = summarizeToolArgs(toolName, parsedArgs);
      const hasError = input.exitCode && input.exitCode !== 0;

      persistEvent(makeEvent(
        hasError ? "tool_call_failed" : "tool_call_completed",
        hasError ? "error" : "allowed",
        hasError ? "medium" : "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary, reason: hasError ? ("Exit code: " + input.exitCode) : null,
          payload: { hook: "postToolUse", cwd: input.cwd, exitCode: input.exitCode } }
      ));
      process.exit(0);
    }

    case "sessionStart": {
      persistEvent(makeEvent("session_started", "info", "info",
        { session_id: sessionId,
          payload: { hook: "sessionStart", cwd: input.cwd, source: input.source } }));
      process.exit(0);
    }

    case "sessionEnd": {
      persistEvent(makeEvent("session_ended", "info", "info",
        { session_id: sessionId, payload: { hook: "sessionEnd", cwd: input.cwd } }));
      process.exit(0);
    }

    case "errorOccurred": {
      persistEvent(makeEvent("tool_call_failed", "error", "medium",
        { session_id: sessionId, payload: { hook: "errorOccurred", cwd: input.cwd } }));
      process.exit(0);
    }

    case "userPromptSubmitted": {
      persistEvent(makeEvent("tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: "PromptSubmit",
          tool_input_summary: (input.prompt || "").slice(0, 200),
          payload: { hook: "userPromptSubmitted" } }));
      process.exit(0);
    }

    default:
      process.exit(0);
    }
  } catch (err) {
    process.stderr.write("SentinelFlow handler error: " + (err.message || err) + "\\n");
    process.exit(0); // FAIL OPEN
  }
})();
`;
  }

  // ─── Event Log ──────────────────────────────────────────────

  private appendToEventLog(event: AgentEvent): void {
    try {
      const dir = path.dirname(this._eventLogPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      if (
        fs.existsSync(this._eventLogPath) &&
        fs.statSync(this._eventLogPath).size > this._maxLogSize
      ) {
        const rotated = this._eventLogPath + ".1";
        if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
        fs.renameSync(this._eventLogPath, rotated);
      }
      fs.appendFileSync(this._eventLogPath, JSON.stringify(event) + "\n", "utf-8");
    } catch (err) {
      this.log("error", `Failed to write event log: ${err}`);
    }
  }
}
