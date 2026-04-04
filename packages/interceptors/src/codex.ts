/**
 * @module @sentinelflow/interceptors/codex
 *
 * OpenAI Codex CLI Runtime Interceptor — verified against official docs.
 *
 * Source: developers.openai.com/codex/hooks
 *
 * CRITICAL COMPATIBILITY NOTE:
 *   The Codex CLI hooks format is nearly identical to Claude Code's:
 *   same matcher + hooks array structure, same PascalCase event names,
 *   same exit code 2 blocking, same type: "command" entries.
 *
 * Hooks contract:
 *
 *   Config lives at `.codex/hooks.json` (project-level, next to config layers).
 *   If more than one hooks.json exists, Codex loads all matching hooks.
 *   Higher-precedence config layers do NOT replace lower-precedence hooks.
 *
 *   Format (nearly identical to Claude Code):
 *   {
 *     "hooks": {
 *       "PreToolUse": [{
 *         "matcher": "Bash",
 *         "hooks": [{
 *           "type": "command",
 *           "command": "node .sentinelflow/codex-handler.js",
 *           "statusMessage": "SentinelFlow: Checking tool call"
 *         }]
 *       }]
 *     }
 *   }
 *
 *   Blocking (identical to Claude Code):
 *     Exit 0 = allow. Exit 2 = block (stderr fed back as context).
 *     OR stdout JSON: { hookSpecificOutput: { permissionDecision: "deny", ... } }
 *
 *   5 lifecycle hooks:
 *     SessionStart      — session begins or resumes
 *     PreToolUse        — before tool execution (CAN BLOCK, currently Bash only)
 *     PostToolUse       — after tool execution
 *     UserPromptSubmit  — user submits a prompt
 *     Stop              — session ends
 *
 *   KEY LIMITATION from official docs:
 *     "Currently PreToolUse only supports Bash tool interception."
 *     This is fine — Bash is where dangerous commands happen.
 */

import * as fs from "fs";
import * as path from "path";
import { v4 as uuidv4 } from "uuid";
import type { AgentEvent } from "@sentinelflow/core";
import { BaseInterceptor } from "./base";
import type { InterceptorConfig } from "./interface";

// ─── Configuration ──────────────────────────────────────────────────

export interface CodexInterceptorConfig extends Partial<InterceptorConfig> {
  projectDir: string;
  eventLogPath?: string;
  maxLogSizeBytes?: number;
  toolAllowlist?: string[];
  toolBlocklist?: string[];
  maxInputSummaryLength?: number;
}

// ─── Constants ──────────────────────────────────────────────────────

const CODEX_DIR = ".codex";
const HOOKS_JSON = "hooks.json";
const SF_DIR = ".sentinelflow";
const HANDLER_SCRIPT = "codex-handler.js";
const EVENT_LOG_FILE = "events.jsonl";
const DEFAULT_MAX_LOG_SIZE = 50 * 1024 * 1024;
const DEFAULT_MAX_INPUT_LENGTH = 500;
const HOOK_TIMEOUT = 10;

// ─── Interceptor Implementation ─────────────────────────────────────

export class CodexInterceptor extends BaseInterceptor {
  readonly framework = "codex";

  private _projectDir: string;
  private _eventLogPath: string;
  private _maxLogSize: number;
  private _toolAllowlist: Set<string>;
  private _toolBlocklist: Set<string>;
  private _maxInputLength: number;
  private _originalHooksJson: string | null = null;

  constructor(config: CodexInterceptorConfig) {
    super(config);
    this._projectDir = path.resolve(config.projectDir);
    this._eventLogPath =
      config.eventLogPath ??
      path.join(this._projectDir, SF_DIR, EVENT_LOG_FILE);
    this._maxLogSize = config.maxLogSizeBytes ?? DEFAULT_MAX_LOG_SIZE;
    this._toolAllowlist = new Set(config.toolAllowlist ?? []);
    this._toolBlocklist = new Set(config.toolBlocklist ?? []);
    this._maxInputLength = config.maxInputSummaryLength ?? DEFAULT_MAX_INPUT_LENGTH;
  }

  // ─── Static Helpers ─────────────────────────────────────────

  static isInstalled(projectDir: string): boolean {
    const hooksPath = path.join(projectDir, CODEX_DIR, HOOKS_JSON);
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    if (!fs.existsSync(hooksPath) || !fs.existsSync(handlerPath)) return false;
    try {
      const content = fs.readFileSync(hooksPath, "utf-8");
      return content.includes("sentinelflow") || content.includes(HANDLER_SCRIPT);
    } catch { return false; }
  }

  static uninstall(projectDir: string): void {
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    if (fs.existsSync(handlerPath)) fs.unlinkSync(handlerPath);

    const hooksPath = path.join(projectDir, CODEX_DIR, HOOKS_JSON);
    if (fs.existsSync(hooksPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
        if (config.hooks) {
          for (const eventName of Object.keys(config.hooks)) {
            config.hooks[eventName] = (config.hooks[eventName] as Array<Record<string, unknown>>)
              .filter((entry) => {
                const innerHooks = (entry.hooks as Array<Record<string, string>>) ?? [];
                return !innerHooks.some((h) =>
                  (h.command ?? "").includes("sentinelflow") || (h.command ?? "").includes(HANDLER_SCRIPT)
                );
              });
            if ((config.hooks[eventName] as unknown[]).length === 0) delete config.hooks[eventName];
          }
          if (Object.keys(config.hooks).length === 0) {
            fs.unlinkSync(hooksPath);
          } else {
            fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2));
          }
        }
      } catch { /* leave alone if unparseable */ }
    }
  }

  // ─── Framework Hook Methods ─────────────────────────────────

  protected async hookFramework(): Promise<void> {
    const sfDir = path.join(this._projectDir, SF_DIR);
    const codexDir = path.join(this._projectDir, CODEX_DIR);
    fs.mkdirSync(sfDir, { recursive: true });
    fs.mkdirSync(codexDir, { recursive: true });

    // Generate handler script
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);
    fs.writeFileSync(handlerPath, this.generateHandlerScript());
    fs.chmodSync(handlerPath, "755");

    // Merge hooks into .codex/hooks.json
    const hooksPath = path.join(codexDir, HOOKS_JSON);
    if (fs.existsSync(hooksPath)) {
      this._originalHooksJson = fs.readFileSync(hooksPath, "utf-8");
    }

    let config: Record<string, unknown> = { hooks: {} };
    if (this._originalHooksJson) {
      try { config = JSON.parse(this._originalHooksJson); } catch { config = { hooks: {} }; }
    }

    const hooks = (config.hooks ?? {}) as Record<string, Array<Record<string, unknown>>>;
    const ourHooks = this.generateHooksConfig();

    for (const [eventName, entries] of Object.entries(ourHooks)) {
      if (!hooks[eventName]) hooks[eventName] = [];
      // Remove existing SentinelFlow entries
      hooks[eventName] = hooks[eventName]!.filter((entry) => {
        const innerHooks = (entry.hooks as Array<Record<string, string>>) ?? [];
        return !innerHooks.some((h) =>
          (h.command ?? "").includes("sentinelflow") || (h.command ?? "").includes(HANDLER_SCRIPT)
        );
      });
      hooks[eventName]!.push(...entries);
    }

    config.hooks = hooks;
    fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2));

    this.log("info", `Installed Codex hooks at ${hooksPath}`);
    this.log("info", `Handler: ${handlerPath}`);
  }

  protected async unhookFramework(): Promise<void> {
    const handlerPath = path.join(this._projectDir, SF_DIR, HANDLER_SCRIPT);
    if (fs.existsSync(handlerPath)) fs.unlinkSync(handlerPath);

    const hooksPath = path.join(this._projectDir, CODEX_DIR, HOOKS_JSON);
    if (this._originalHooksJson) {
      fs.writeFileSync(hooksPath, this._originalHooksJson);
    } else {
      CodexInterceptor.uninstall(this._projectDir);
    }

    this.log("info", "Uninstalled Codex hooks");
  }

  // ─── Hooks Config ───────────────────────────────────────────

  /**
   * Generate hooks config in the Codex format.
   *
   * NEARLY IDENTICAL to Claude Code's format:
   *   matcher + hooks array, type: "command", PascalCase event names.
   *
   * Codex-specific addition: statusMessage (shown in TUI while hook runs).
   */
  private generateHooksConfig(): Record<string, Array<Record<string, unknown>>> {
    const handlerCmd = `node "${this._projectDir}/${SF_DIR}/${HANDLER_SCRIPT}"`;

    const hookEntry = (matcher: string, statusMsg: string) => ({
      matcher,
      hooks: [{
        type: "command",
        command: handlerCmd,
        timeout: HOOK_TIMEOUT,
        statusMessage: statusMsg,
      }],
    });

    return {
      // PreToolUse currently only supports Bash in Codex, but we register for all
      // so we're ready when they expand support
      PreToolUse: [hookEntry("", "SentinelFlow: Evaluating tool call")],
      PostToolUse: [hookEntry("", "SentinelFlow: Recording tool result")],
      SessionStart: [hookEntry("", "SentinelFlow: Session started")],
      Stop: [hookEntry("", "SentinelFlow: Session ended")],
    };
  }

  /**
   * Generate the Codex handler script.
   *
   * Because the Codex hooks contract is nearly identical to Claude Code's,
   * this handler shares the same blocking mechanism (exit 2 + stderr)
   * and the same stdin JSON parsing approach (hook_event_name from stdin).
   *
   * The Codex-specific stdin field is `hook_event_name` in PascalCase
   * (PreToolUse, PostToolUse, etc.) — same as Claude Code.
   */
  private generateHandlerScript(): string {
    return `#!/usr/bin/env node
/**
 * SentinelFlow Codex CLI Hook Handler
 * Generated by @sentinelflow/interceptors
 *
 * Codex CLI hooks contract (nearly identical to Claude Code):
 *   Exit 0 = allow. Exit 2 = block (stderr fed back as context).
 *   Stdin: JSON with hook_event_name, tool_name, tool_input, session_id, cwd.
 *   PascalCase event names: PreToolUse, PostToolUse, Stop, SessionStart.
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
    agent_id: opts.agent_id || "codex-agent",
    framework: "codex",
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

function summarizeInput(input) {
  if (!input) return null;
  if (typeof input.command === "string") return input.command.slice(0, MAX_INPUT_LENGTH);
  if (typeof input.file_path === "string") return "file: " + input.file_path;
  if (typeof input.path === "string") return "path: " + input.path;
  if (typeof input.content === "string") return "content: " + input.content.slice(0, 100) + "...";
  const raw = JSON.stringify(input);
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
  catch {
    process.stderr.write("SentinelFlow: Failed to parse stdin JSON\\n");
    process.exit(0);
  }

  // Codex uses PascalCase hook_event_name, same as Claude Code
  const hookEvent = input.hook_event_name || "";
  const sessionId = input.session_id || "unknown";
  const toolName = input.tool_name || "";
  const toolInput = input.tool_input || {};
  const inputSummary = summarizeInput(toolInput);

  try {
    switch (hookEvent) {

    case "PreToolUse": {
      // Tool blocklist check
      if (ENFORCEMENT_MODE === "enforce" && TOOL_BLOCKLIST.has(toolName)) {
        const reason = 'Tool "' + toolName + '" is in the blocklist';
        persistEvent(makeEvent("tool_call_blocked", "blocked", "medium",
          { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
            action: inputSummary, policy_id: "tool_blocklist", reason,
            payload: { hook: "PreToolUse", cwd: input.cwd } }));
        process.stderr.write("SentinelFlow: " + reason + "\\n");
        process.exit(2);
      }

      // Dangerous command check (Bash is the primary tool in Codex)
      if (ENFORCEMENT_MODE === "enforce" && (toolName === "Bash" || toolName === "bash")) {
        const cmd = toolInput.command || "";
        const check = checkDangerousCommand(cmd);
        if (check.dangerous) {
          const reason = "Dangerous command: " + check.label + " \\u2014 " + cmd.slice(0, 100);
          persistEvent(makeEvent("tool_call_blocked", "blocked", "high",
            { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
              action: inputSummary, policy_id: "dangerous_commands", reason,
              payload: { hook: "PreToolUse", cwd: input.cwd } }));
          process.stderr.write("SentinelFlow: " + reason + "\\n");
          process.exit(2);
        }
      }

      // Allowed
      persistEvent(makeEvent("tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary, payload: { hook: "PreToolUse", cwd: input.cwd } }));
      process.exit(0);
    }

    case "PostToolUse": {
      const hasError = input.error || (input.tool_response && input.tool_response.error);
      persistEvent(makeEvent(
        hasError ? "tool_call_failed" : "tool_call_completed",
        hasError ? "error" : "allowed",
        hasError ? "medium" : "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary,
          reason: hasError ? (input.error || "Tool returned an error") : null,
          payload: { hook: "PostToolUse", cwd: input.cwd, error: input.error || null } }
      ));
      process.exit(0);
    }

    case "SessionStart": {
      persistEvent(makeEvent("session_started", "info", "info",
        { session_id: sessionId,
          payload: { hook: "SessionStart", cwd: input.cwd } }));
      process.exit(0);
    }

    case "Stop": {
      persistEvent(makeEvent("session_ended", "info", "info",
        { session_id: sessionId,
          payload: { hook: "Stop", cwd: input.cwd } }));
      process.exit(0);
    }

    case "UserPromptSubmit": {
      persistEvent(makeEvent("tool_call_attempted", "allowed", "info",
        { session_id: sessionId, tool_name: "PromptSubmit",
          payload: { hook: "UserPromptSubmit" } }));
      process.exit(0);
    }

    default:
      // Unknown hook — fail open
      process.exit(0);
    }
  } catch (err) {
    process.stderr.write("SentinelFlow handler error: " + (err.message || err) + "\\n");
    process.exit(0);
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
