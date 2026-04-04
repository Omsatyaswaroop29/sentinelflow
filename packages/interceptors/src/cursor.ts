/**
 * @module @sentinelflow/interceptors/cursor
 *
 * Cursor Runtime Interceptor — built against the verified Cursor hooks contract.
 *
 * Hooks contract (verified against cursor.com/docs/hooks + GitButler deep dive):
 *
 *   Configuration lives in `.cursor/hooks.json` (project-level, committed),
 *   `~/.cursor/hooks.json` (user-level), or `/etc/cursor/hooks.json` (enterprise).
 *   All hooks from all locations merge additively — no override hierarchy.
 *
 *   Format:
 *   {
 *     "version": 1,
 *     "hooks": {
 *       "beforeShellExecution": [{
 *         "command": "../.sentinelflow/cursor-handler.js"
 *       }]
 *     }
 *   }
 *
 *   Command paths are RELATIVE to the hooks.json file location.
 *   So if hooks.json is at `.cursor/hooks.json`, the command
 *   `../.sentinelflow/cursor-handler.js` resolves to `.sentinelflow/cursor-handler.js`
 *   from the project root.
 *
 *   Stdin JSON for beforeShellExecution:
 *   {
 *     "conversation_id": "668320d2-...",
 *     "generation_id": "490b90b7-...",
 *     "command": "npm test",
 *     "cwd": "",
 *     "hook_event_name": "beforeShellExecution",
 *     "workspace_roots": ["/Users/user/project"]
 *   }
 *
 *   Stdout JSON for blocking hooks (beforeShellExecution, beforeMCPExecution, beforeReadFile):
 *   {
 *     "permission": "allow" | "deny" | "ask",
 *     "userMessage": "Shown to the developer in Cursor UI",
 *     "agentMessage": "Fed back to the AI model as context"
 *   }
 *
 *   Blocking is via stdout JSON, NOT exit codes.
 *   `permission: "deny"` blocks the action.
 *   `permission: "ask"` escalates to the user for manual approval.
 *   `permission: "allow"` (or no output) lets it proceed.
 *
 *   Observe-only hooks (afterFileEdit, stop, beforeSubmitPrompt):
 *   Cursor does NOT respect stdout JSON for these. They are informational only.
 *
 *   6 lifecycle hooks:
 *     beforeSubmitPrompt   — observe-only, prompt text + attachments
 *     beforeShellExecution — CAN BLOCK, shell command + cwd
 *     beforeMCPExecution   — CAN BLOCK, MCP server + tool name + input
 *     beforeReadFile       — CAN BLOCK, file path + content
 *     afterFileEdit        — observe-only, file path + edits (old/new strings)
 *     stop                 — observe-only, status (completed/aborted/error)
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

// ─── Cursor Hook Event Types ────────────────────────────────────────

/** Common fields present in ALL Cursor hook stdin payloads. */
interface CursorHookBase {
  conversation_id: string;
  generation_id: string;
  hook_event_name: string;
  workspace_roots: string[];
}

/** beforeShellExecution stdin payload */
export interface CursorBeforeShellPayload extends CursorHookBase {
  hook_event_name: "beforeShellExecution";
  command: string;
  cwd: string;
}

/** beforeMCPExecution stdin payload */
export interface CursorBeforeMCPPayload extends CursorHookBase {
  hook_event_name: "beforeMCPExecution";
  tool_name: string;
  tool_input: string;  // Escaped JSON string of MCP tool parameters
  server?: string;
  command?: string;    // MCP server command
  url?: string;        // MCP server URL (alternative to command)
}

/** beforeReadFile stdin payload */
export interface CursorBeforeReadFilePayload extends CursorHookBase {
  hook_event_name: "beforeReadFile";
  file_path: string;
  content: string;
}

/** afterFileEdit stdin payload */
export interface CursorAfterFileEditPayload extends CursorHookBase {
  hook_event_name: "afterFileEdit";
  file_path: string;
  edits: Array<{
    old_string: string;
    new_string: string;
  }>;
}

/** stop stdin payload */
export interface CursorStopPayload extends CursorHookBase {
  hook_event_name: "stop";
  status: "completed" | "aborted" | "error";
}

/** beforeSubmitPrompt stdin payload */
export interface CursorBeforeSubmitPromptPayload extends CursorHookBase {
  hook_event_name: "beforeSubmitPrompt";
  prompt: string;
  attachments?: Array<{
    type: string;
    file_path?: string;
  }>;
}

/** Union of all possible Cursor hook stdin payloads */
export type CursorHookInput =
  | CursorBeforeShellPayload
  | CursorBeforeMCPPayload
  | CursorBeforeReadFilePayload
  | CursorAfterFileEditPayload
  | CursorStopPayload
  | CursorBeforeSubmitPromptPayload;

/** Stdout JSON for blocking hooks (beforeShellExecution, beforeMCPExecution, beforeReadFile) */
export interface CursorHookResponse {
  permission: "allow" | "deny" | "ask";
  userMessage?: string;
  agentMessage?: string;
}

// ─── Configuration ──────────────────────────────────────────────────

export interface CursorInterceptorConfig extends Partial<InterceptorConfig> {
  /** Path to the project root (where .cursor/ lives) */
  projectDir: string;
  /** Path to write the event log (JSONL). Default: .sentinelflow/events.jsonl */
  eventLogPath?: string;
  /** Maximum event log size in bytes before rotation. Default: 50MB */
  maxLogSizeBytes?: number;
  /** Tools that are always allowed (bypass policy evaluation) */
  toolAllowlist?: string[];
  /** Tools that are always blocked */
  toolBlocklist?: string[];
  /** MCP servers to block entirely */
  mcpServerBlocklist?: string[];
  /** File patterns to block reading (e.g., [".env", "*.pem"]) */
  readFileBlockPatterns?: string[];
  /** Maximum input summary length stored in events. Default: 500 chars */
  maxInputSummaryLength?: number;
  /** Escalation mode: "deny" blocks outright, "ask" escalates to user */
  escalationMode?: "deny" | "ask";
}

// ─── Constants ──────────────────────────────────────────────────────

const CURSOR_DIR = ".cursor";
const HOOKS_JSON = "hooks.json";
const SF_DIR = ".sentinelflow";
const HANDLER_SCRIPT = "cursor-handler.js";
const EVENT_LOG_FILE = "events.jsonl";
const DEFAULT_MAX_LOG_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_INPUT_LENGTH = 500;

// ─── Interceptor Implementation ─────────────────────────────────────

export class CursorInterceptor extends BaseInterceptor {
  readonly framework = "cursor";

  private _projectDir: string;
  private _eventLogPath: string;
  private _maxLogSize: number;
  private _toolAllowlist: Set<string>;
  private _toolBlocklist: Set<string>;
  private _mcpServerBlocklist: Set<string>;
  private _readFileBlockPatterns: string[];
  private _maxInputLength: number;
  private _escalationMode: "deny" | "ask";
  private _originalHooksJson: string | null = null;

  constructor(config: CursorInterceptorConfig) {
    super(config);
    this._projectDir = path.resolve(config.projectDir);
    this._eventLogPath =
      config.eventLogPath ??
      path.join(this._projectDir, SF_DIR, EVENT_LOG_FILE);
    this._maxLogSize = config.maxLogSizeBytes ?? DEFAULT_MAX_LOG_SIZE;
    this._toolAllowlist = new Set(config.toolAllowlist ?? []);
    this._toolBlocklist = new Set(config.toolBlocklist ?? []);
    this._mcpServerBlocklist = new Set(config.mcpServerBlocklist ?? []);
    this._readFileBlockPatterns = config.readFileBlockPatterns ?? [];
    this._maxInputLength = config.maxInputSummaryLength ?? DEFAULT_MAX_INPUT_LENGTH;
    this._escalationMode = config.escalationMode ?? "deny";
  }

  // ─── Static Helpers ─────────────────────────────────────────

  /** Check if SentinelFlow hooks are installed in a project */
  static isInstalled(projectDir: string): boolean {
    const hooksPath = path.join(projectDir, CURSOR_DIR, HOOKS_JSON);
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    if (!fs.existsSync(hooksPath) || !fs.existsSync(handlerPath)) return false;
    try {
      const content = fs.readFileSync(hooksPath, "utf-8");
      return content.includes("sentinelflow") || content.includes(HANDLER_SCRIPT);
    } catch {
      return false;
    }
  }

  /** Uninstall SentinelFlow hooks from a Cursor project */
  static uninstall(projectDir: string): void {
    const sfDir = path.join(projectDir, SF_DIR);
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);
    const hooksPath = path.join(projectDir, CURSOR_DIR, HOOKS_JSON);

    // Remove handler script
    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    // Remove our hooks from hooks.json (preserve other hooks)
    if (fs.existsSync(hooksPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
        if (config.hooks) {
          for (const eventName of Object.keys(config.hooks)) {
            config.hooks[eventName] = (config.hooks[eventName] as Array<Record<string, string>>)
              .filter((entry) =>
                !(entry.command ?? "").includes("sentinelflow") &&
                !(entry.command ?? "").includes(HANDLER_SCRIPT)
              );
            if (config.hooks[eventName].length === 0) {
              delete config.hooks[eventName];
            }
          }
          if (Object.keys(config.hooks).length === 0) {
            // If no hooks remain, remove the file entirely
            fs.unlinkSync(hooksPath);
          } else {
            fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2));
          }
        }
      } catch {
        // If we can't parse hooks.json, leave it alone
      }
    }
  }

  // ─── Framework Hook Methods ─────────────────────────────────

  protected async hookFramework(): Promise<void> {
    const sfDir = path.join(this._projectDir, SF_DIR);
    const cursorDir = path.join(this._projectDir, CURSOR_DIR);
    fs.mkdirSync(sfDir, { recursive: true });
    fs.mkdirSync(cursorDir, { recursive: true });

    // Generate the handler script
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);
    fs.writeFileSync(handlerPath, this.generateHandlerScript());
    fs.chmodSync(handlerPath, "755");

    // Merge our hooks into .cursor/hooks.json
    const hooksPath = path.join(cursorDir, HOOKS_JSON);

    if (fs.existsSync(hooksPath)) {
      this._originalHooksJson = fs.readFileSync(hooksPath, "utf-8");
    }

    let config: Record<string, unknown> = { version: 1, hooks: {} };
    if (this._originalHooksJson) {
      try {
        config = JSON.parse(this._originalHooksJson);
      } catch {
        config = { version: 1, hooks: {} };
      }
    }

    // Merge our hooks (preserving any existing hooks)
    const hooks = (config.hooks ?? {}) as Record<string, Array<Record<string, string>>>;
    const ourHooks = this.generateHooksConfig();

    for (const [eventName, entries] of Object.entries(ourHooks)) {
      if (!hooks[eventName]) {
        hooks[eventName] = [];
      }
      // Remove existing SentinelFlow entries before adding fresh ones
      hooks[eventName] = hooks[eventName]!.filter(
        (entry) =>
          !(entry.command ?? "").includes("sentinelflow") &&
          !(entry.command ?? "").includes(HANDLER_SCRIPT)
      );
      hooks[eventName]!.push(...entries);
    }

    config.hooks = hooks;
    fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2));

    this.log("info", `Installed Cursor hooks in ${hooksPath}`);
    this.log("info", `Handler: ${handlerPath}`);
  }

  protected async unhookFramework(): Promise<void> {
    const sfDir = path.join(this._projectDir, SF_DIR);
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);

    // Remove handler script
    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    // Restore or clean up hooks.json
    const hooksPath = path.join(this._projectDir, CURSOR_DIR, HOOKS_JSON);
    if (this._originalHooksJson) {
      fs.writeFileSync(hooksPath, this._originalHooksJson);
    } else {
      CursorInterceptor.uninstall(this._projectDir);
    }

    this.log("info", "Uninstalled Cursor hooks");
  }

  // ─── Hooks Config Generation ────────────────────────────────

  /**
   * Generate the hooks entries for .cursor/hooks.json.
   *
   * CRITICAL: Cursor command paths are RELATIVE to the hooks.json file.
   * Since hooks.json lives at .cursor/hooks.json, we need "../.sentinelflow/cursor-handler.js"
   * to reach .sentinelflow/cursor-handler.js at the project root.
   */
  private generateHooksConfig(): Record<string, Array<Record<string, string>>> {
    // Relative path from .cursor/ to .sentinelflow/cursor-handler.js
    const handlerCmd = `node ../${SF_DIR}/${HANDLER_SCRIPT}`;

    return {
      // Blocking hooks — these can deny tool calls
      beforeShellExecution: [{ command: handlerCmd }],
      beforeMCPExecution: [{ command: handlerCmd }],
      beforeReadFile: [{ command: handlerCmd }],
      // Observe-only hooks — these log events but can't block
      afterFileEdit: [{ command: handlerCmd }],
      stop: [{ command: handlerCmd }],
    };
  }

  /**
   * Generate the Cursor handler script. Self-contained Node.js file.
   *
   * CRITICAL DIFFERENCE FROM CLAUDE CODE:
   *   - Cursor blocks via stdout JSON `{ permission: "deny" }`, NOT exit codes
   *   - Cursor uses conversation_id (not session_id) for correlation
   *   - Always output valid JSON to stdout for blocking hooks
   *   - Fail-open means: output `{ "permission": "allow" }` on any error
   */
  private generateHandlerScript(): string {
    return `#!/usr/bin/env node
/**
 * SentinelFlow Cursor Hook Handler
 * Generated by @sentinelflow/interceptors
 *
 * This script is invoked by Cursor's hooks system.
 * The hook type is determined from stdin JSON's "hook_event_name" field.
 *
 * BLOCKING (Cursor hooks contract):
 *   Cursor reads stdout JSON for beforeShellExecution, beforeMCPExecution, beforeReadFile.
 *   { "permission": "deny", "userMessage": "...", "agentMessage": "..." } = block
 *   { "permission": "allow" } = allow
 *   { "permission": "ask", "userMessage": "..." } = escalate to user
 *
 *   For afterFileEdit and stop, stdout is ignored (observe-only).
 *
 * FAIL-OPEN:
 *   On ANY error, output { "permission": "allow" } to stdout.
 *   SentinelFlow must never break Cursor workflows.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ─── Configuration (baked in at install time) ───────────────
// Resolve project dir: hooks.json is at .cursor/hooks.json,
// handler is at .sentinelflow/cursor-handler.js.
// __dirname gives us .sentinelflow/, so project root is one level up.
const PROJECT_DIR = ${JSON.stringify(this._projectDir)};
const SF_DIR = path.join(PROJECT_DIR, ".sentinelflow");
const EVENT_LOG = path.join(SF_DIR, "events.jsonl");
const DB_PATH = path.join(SF_DIR, "events.db");
const TOOL_ALLOWLIST = new Set(${JSON.stringify([...this._toolAllowlist])});
const TOOL_BLOCKLIST = new Set(${JSON.stringify([...this._toolBlocklist])});
const MCP_SERVER_BLOCKLIST = new Set(${JSON.stringify([...this._mcpServerBlocklist])});
const READ_FILE_BLOCK_PATTERNS = ${JSON.stringify(this._readFileBlockPatterns)};
const ENFORCEMENT_MODE = ${JSON.stringify(this.enforcementMode)};
const ESCALATION_MODE = ${JSON.stringify(this._escalationMode)};
const MAX_INPUT_LENGTH = ${this._maxInputLength};

// ─── Module resolution (for better-sqlite3) ─────────────────
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
} catch (e) {
  // SQLite unavailable — JSONL-only mode
}

// ─── Helpers ────────────────────────────────────────────────
function summarizeInput(input) {
  if (!input) return null;
  if (typeof input === "string") return input.slice(0, MAX_INPUT_LENGTH);
  if (typeof input.command === "string") return input.command.slice(0, MAX_INPUT_LENGTH);
  if (typeof input.file_path === "string") return "file: " + input.file_path;
  const raw = JSON.stringify(input);
  return raw.length > MAX_INPUT_LENGTH ? raw.slice(0, MAX_INPUT_LENGTH) + "..." : raw;
}

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
    } catch { /* SQLite failure is non-fatal */ }
  }
}

function makeEvent(type, outcome, severity, opts = {}) {
  return {
    event_id: crypto.randomUUID(),
    schema_version: 1,
    timestamp: new Date().toISOString(),
    agent_id: opts.agent_id || "cursor-agent",
    framework: "cursor",
    session_id: opts.session_id || "unknown",
    event_type: type,
    outcome, severity,
    tool_name: opts.tool_name || null,
    tool_input_summary: opts.tool_input_summary || null,
    action: opts.action || null,
    policy_id: opts.policy_id || null,
    reason: opts.reason || null,
    payload: opts.payload || null,
  };
}

// ─── Dangerous Command Detection ────────────────────────────
// Same patterns as Claude Code handler — consistency across frameworks
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
    if (pattern.test(cmd)) {
      return { dangerous: true, label, command: cmd };
    }
  }
  return { dangerous: false };
}

function checkReadFileBlocked(filePath) {
  for (const pattern of READ_FILE_BLOCK_PATTERNS) {
    if (pattern.startsWith("*.")) {
      // Extension match: *.pem, *.key
      if (filePath.endsWith(pattern.slice(1))) return true;
    } else {
      // Exact filename match: .env, .npmrc
      const basename = filePath.split("/").pop() || "";
      if (basename === pattern) return true;
    }
  }
  return false;
}

// ─── Response Helpers ───────────────────────────────────────
function allowResponse() {
  return JSON.stringify({ permission: "allow" });
}

function denyResponse(userMsg, agentMsg) {
  const permission = ESCALATION_MODE === "ask" ? "ask" : "deny";
  return JSON.stringify({
    permission,
    userMessage: userMsg,
    agentMessage: agentMsg || userMsg,
  });
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
  } catch {
    // Can't read stdin — fail open
    process.stdout.write(allowResponse());
    process.exit(0);
  }

  if (!raw.trim()) {
    process.stdout.write(allowResponse());
    process.exit(0);
  }

  let input;
  try {
    input = JSON.parse(raw);
  } catch (e) {
    process.stderr.write("SentinelFlow: Failed to parse stdin JSON\\n");
    process.stdout.write(allowResponse());
    process.exit(0);
  }

  const hookEvent = input.hook_event_name || "unknown";
  const sessionId = input.conversation_id || "unknown";

  try {
    switch (hookEvent) {

    // ─── beforeShellExecution (CAN BLOCK) ───────────────
    case "beforeShellExecution": {
      const cmd = input.command || "";
      const inputSummary = cmd.slice(0, MAX_INPUT_LENGTH);

      // Check dangerous command patterns
      if (ENFORCEMENT_MODE === "enforce") {
        const check = checkDangerousCommand(cmd);
        if (check.dangerous) {
          const reason = "Dangerous command: " + check.label + " \\u2014 " + cmd.slice(0, 100);
          persistEvent(makeEvent(
            "tool_call_blocked", "blocked", "high",
            { session_id: sessionId, tool_name: "Shell", tool_input_summary: inputSummary,
              action: inputSummary, policy_id: "dangerous_commands", reason,
              payload: { hook: "beforeShellExecution", cwd: input.cwd, workspace_roots: input.workspace_roots } }
          ));
          process.stdout.write(denyResponse(
            "SentinelFlow: " + reason,
            "This command was blocked by a SentinelFlow governance policy. " + reason + ". Try a safer alternative."
          ));
          process.exit(0);
        }
      }

      // Allowed — log and proceed
      persistEvent(makeEvent(
        "tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: "Shell", tool_input_summary: inputSummary,
          action: inputSummary,
          payload: { hook: "beforeShellExecution", cwd: input.cwd } }
      ));
      process.stdout.write(allowResponse());
      break;
    }

    // ─── beforeMCPExecution (CAN BLOCK) ─────────────────
    case "beforeMCPExecution": {
      const toolName = input.tool_name || "unknown-mcp-tool";
      const serverName = input.server || input.command || "unknown-server";
      let toolInput = null;
      try { toolInput = JSON.parse(input.tool_input || "{}"); } catch { toolInput = input.tool_input; }
      const inputSummary = summarizeInput(toolInput) || toolName;

      // Check MCP server blocklist
      if (ENFORCEMENT_MODE === "enforce" && MCP_SERVER_BLOCKLIST.has(serverName)) {
        const reason = 'MCP server "' + serverName + '" is in the blocklist';
        persistEvent(makeEvent(
          "tool_call_blocked", "blocked", "high",
          { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
            action: inputSummary, policy_id: "mcp_server_blocklist", reason,
            payload: { hook: "beforeMCPExecution", server: serverName } }
        ));
        process.stdout.write(denyResponse(
          "SentinelFlow: " + reason,
          "This MCP tool call was blocked by governance policy. " + reason
        ));
        process.exit(0);
      }

      // Check tool blocklist
      if (ENFORCEMENT_MODE === "enforce" && TOOL_BLOCKLIST.has(toolName)) {
        const reason = 'Tool "' + toolName + '" is in the blocklist';
        persistEvent(makeEvent(
          "tool_call_blocked", "blocked", "medium",
          { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
            action: inputSummary, policy_id: "tool_blocklist", reason,
            payload: { hook: "beforeMCPExecution", server: serverName } }
        ));
        process.stdout.write(denyResponse(
          "SentinelFlow: " + reason,
          "This MCP tool call was blocked by governance policy. " + reason
        ));
        process.exit(0);
      }

      // Allowed
      persistEvent(makeEvent(
        "tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary,
          payload: { hook: "beforeMCPExecution", server: serverName } }
      ));
      process.stdout.write(allowResponse());
      break;
    }

    // ─── beforeReadFile (CAN BLOCK) ─────────────────────
    case "beforeReadFile": {
      const filePath = input.file_path || "unknown";

      // Check file block patterns (.env, *.pem, *.key, etc.)
      if (ENFORCEMENT_MODE === "enforce" && checkReadFileBlocked(filePath)) {
        const reason = 'Reading "' + filePath + '" is blocked by file access policy';
        persistEvent(makeEvent(
          "tool_call_blocked", "blocked", "high",
          { session_id: sessionId, tool_name: "ReadFile", tool_input_summary: "file: " + filePath,
            action: "file: " + filePath, policy_id: "read_file_policy", reason,
            payload: { hook: "beforeReadFile", file_path: filePath } }
        ));
        process.stdout.write(denyResponse(
          "SentinelFlow: " + reason,
          "This file read was blocked by a SentinelFlow governance policy. The file matches a blocked pattern."
        ));
        process.exit(0);
      }

      // Allowed
      persistEvent(makeEvent(
        "tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: "ReadFile", tool_input_summary: "file: " + filePath,
          action: "file: " + filePath,
          payload: { hook: "beforeReadFile", file_path: filePath } }
      ));
      process.stdout.write(allowResponse());
      break;
    }

    // ─── afterFileEdit (OBSERVE-ONLY) ───────────────────
    case "afterFileEdit": {
      const filePath = input.file_path || "unknown";
      const editCount = (input.edits || []).length;
      persistEvent(makeEvent(
        "tool_call_completed", "allowed", "info",
        { session_id: sessionId, tool_name: "FileEdit", tool_input_summary: "file: " + filePath,
          action: filePath + " (" + editCount + " edit" + (editCount !== 1 ? "s" : "") + ")",
          payload: { hook: "afterFileEdit", file_path: filePath, edit_count: editCount } }
      ));
      // No stdout JSON — Cursor ignores it for afterFileEdit
      break;
    }

    // ─── stop (OBSERVE-ONLY) ────────────────────────────
    case "stop": {
      const status = input.status || "completed";
      persistEvent(makeEvent(
        "session_ended", "info", "info",
        { session_id: sessionId,
          payload: { hook: "stop", status } }
      ));
      // No stdout JSON — Cursor ignores it for stop
      break;
    }

    // ─── beforeSubmitPrompt (OBSERVE-ONLY) ──────────────
    case "beforeSubmitPrompt": {
      const prompt = (input.prompt || "").slice(0, 200);
      const attachmentCount = (input.attachments || []).length;
      persistEvent(makeEvent(
        "tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: "PromptSubmit",
          tool_input_summary: prompt,
          action: prompt + (attachmentCount > 0 ? " [" + attachmentCount + " attachments]" : ""),
          payload: { hook: "beforeSubmitPrompt", attachment_count: attachmentCount } }
      ));
      // No stdout JSON — Cursor ignores it for beforeSubmitPrompt
      break;
    }

    default:
      // Unknown hook event — fail open, log it
      persistEvent(makeEvent(
        "tool_call_attempted", "allowed", "info",
        { session_id: sessionId,
          payload: { hook: hookEvent, unknown: true } }
      ));
      process.stdout.write(allowResponse());
      break;
    }
  } catch (err) {
    // FAIL OPEN — never break Cursor because our handler crashed
    process.stderr.write("SentinelFlow handler error: " + (err.message || err) + "\\n");
    process.stdout.write(allowResponse());
  }

  // Clean exit
  process.exit(0);
})();
`;
  }

  // ─── Event Log (JSONL) ──────────────────────────────────────

  private appendToEventLog(event: AgentEvent): void {
    try {
      const dir = path.dirname(this._eventLogPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      if (
        fs.existsSync(this._eventLogPath) &&
        fs.statSync(this._eventLogPath).size > this._maxLogSize
      ) {
        const rotatedPath = this._eventLogPath + ".1";
        if (fs.existsSync(rotatedPath)) fs.unlinkSync(rotatedPath);
        fs.renameSync(this._eventLogPath, rotatedPath);
        this.log("info", "Rotated event log");
      }

      fs.appendFileSync(this._eventLogPath, JSON.stringify(event) + "\n", "utf-8");
    } catch (err) {
      this.log("error", `Failed to write event log: ${err}`);
    }
  }

  // ─── Process Hook Event (for tests / TypeScript callers) ────

  async processHookEvent(rawEvent: CursorHookInput): Promise<CursorHookResponse> {
    const hookName = rawEvent.hook_event_name;

    switch (hookName) {
      case "beforeShellExecution":
        return this.handleBeforeShell(rawEvent as CursorBeforeShellPayload);
      case "beforeMCPExecution":
        return this.handleBeforeMCP(rawEvent as CursorBeforeMCPPayload);
      case "beforeReadFile":
        return this.handleBeforeReadFile(rawEvent as CursorBeforeReadFilePayload);
      case "afterFileEdit":
        await this.handleAfterFileEdit(rawEvent as CursorAfterFileEditPayload);
        return { permission: "allow" };
      case "stop":
        await this.handleStop(rawEvent as CursorStopPayload);
        return { permission: "allow" };
      default:
        return { permission: "allow" };
    }
  }

  // ─── Hook Event Handlers ────────────────────────────────────

  private async handleBeforeShell(event: CursorBeforeShellPayload): Promise<CursorHookResponse> {
    const toolName = "Shell";
    const inputSummary = event.command.slice(0, this._maxInputLength);

    const { allowed, event: agentEvent } = await this.handleToolCall(
      toolName,
      inputSummary,
      {
        cursor_conversation_id: event.conversation_id,
        cursor_generation_id: event.generation_id,
        cwd: event.cwd,
        workspace_roots: event.workspace_roots,
      }
    );

    this.appendToEventLog(agentEvent);

    if (!allowed) {
      return {
        permission: this._escalationMode,
        userMessage: `SentinelFlow: ${agentEvent.governance?.reason ?? "Blocked by policy"}`,
        agentMessage: `This command was blocked by a SentinelFlow governance policy. ${agentEvent.governance?.reason ?? ""}. Try a safer alternative.`,
      };
    }

    return { permission: "allow" };
  }

  private async handleBeforeMCP(event: CursorBeforeMCPPayload): Promise<CursorHookResponse> {
    const toolName = event.tool_name ?? "unknown-mcp-tool";

    const { allowed, event: agentEvent } = await this.handleToolCall(
      toolName,
      event.tool_input?.slice(0, this._maxInputLength),
      {
        cursor_conversation_id: event.conversation_id,
        mcp_server: event.server ?? event.command,
      }
    );

    this.appendToEventLog(agentEvent);

    if (!allowed) {
      return {
        permission: this._escalationMode,
        userMessage: `SentinelFlow: ${agentEvent.governance?.reason ?? "Blocked by policy"}`,
        agentMessage: `This MCP tool call was blocked by governance policy. ${agentEvent.governance?.reason ?? ""}`,
      };
    }

    return { permission: "allow" };
  }

  private async handleBeforeReadFile(event: CursorBeforeReadFilePayload): Promise<CursorHookResponse> {
    const { allowed, event: agentEvent } = await this.handleToolCall(
      "ReadFile",
      `file: ${event.file_path}`,
      {
        cursor_conversation_id: event.conversation_id,
        file_path: event.file_path,
      }
    );

    this.appendToEventLog(agentEvent);

    if (!allowed) {
      return {
        permission: this._escalationMode,
        userMessage: `SentinelFlow: ${agentEvent.governance?.reason ?? "Blocked by policy"}`,
        agentMessage: `This file read was blocked by governance policy. ${agentEvent.governance?.reason ?? ""}`,
      };
    }

    return { permission: "allow" };
  }

  private async handleAfterFileEdit(event: CursorAfterFileEditPayload): Promise<void> {
    const agentEvent = this.createEvent("tool_call_end", {
      tool: {
        name: "FileEdit",
        input_summary: `file: ${event.file_path}`,
        status: "success",
      },
      metadata: {
        cursor_conversation_id: event.conversation_id,
        file_path: event.file_path,
        edit_count: event.edits?.length ?? 0,
      },
    });
    await this.emitEvent(agentEvent);
    this.appendToEventLog(agentEvent);
  }

  private async handleStop(event: CursorStopPayload): Promise<void> {
    const agentEvent = this.createEvent("session_end", {
      metadata: {
        cursor_conversation_id: event.conversation_id,
        status: event.status,
      },
    });
    await this.emitEvent(agentEvent);
    this.appendToEventLog(agentEvent);
  }
}
