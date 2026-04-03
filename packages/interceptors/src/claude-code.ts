/**
 * @module @sentinelflow/interceptors/claude-code
 *
 * Claude Code Runtime Interceptor — HARDENED against official hooks contract.
 *
 * Hooks contract (verified against code.claude.com/docs/en/hooks):
 *
 *   Configuration lives in `.claude/settings.local.json` (per-user, gitignored)
 *   or `.claude/settings.json` (project-level, committed). Format:
 *
 *   {
 *     "hooks": {
 *       "PreToolUse": [{
 *         "matcher": "",
 *         "hooks": [{
 *           "type": "command",
 *           "command": "node \"$CLAUDE_PROJECT_DIR/.sentinelflow/handler.js\"",
 *           "timeout": 10000
 *         }]
 *       }]
 *     }
 *   }
 *
 *   Stdin JSON for PreToolUse:
 *   {
 *     "session_id": "abc123",
 *     "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
 *     "cwd": "/home/user/my-project",
 *     "permission_mode": "default",
 *     "hook_event_name": "PreToolUse",
 *     "tool_name": "Bash",
 *     "tool_input": { "command": "npm test" }
 *   }
 *
 *   Exit codes:
 *     0 = allow. Stdout JSON optional (shown in verbose mode only).
 *     2 = block. Stderr text fed back to Claude as error message.
 *     Other = non-blocking error. Stderr shown in verbose mode.
 *
 *   Structured JSON decisions (stdout, exit 0):
 *     { "decision": "block", "reason": "..." }  — blocks the tool call
 *     { "decision": "approve", "reason": "..." } — bypasses permission prompt
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

// ─── Claude Code Hook Event Types (matches real stdin JSON) ─────────

/** The actual JSON shape Claude Code sends on stdin for ALL hook events. */
export interface ClaudeCodeHookInput {
  /** Session correlation ID */
  session_id: string;
  /** Path to the session transcript JSONL file */
  transcript_path?: string;
  /** Current working directory */
  cwd: string;
  /** Permission mode: "default", "plan", "bypassPermissions" */
  permission_mode?: string;
  /** Which hook event fired: "PreToolUse", "PostToolUse", "Stop", etc. */
  hook_event_name: string;
  /** Tool name (PreToolUse/PostToolUse only): "Bash", "Read", "Write", "Edit", etc. */
  tool_name?: string;
  /** Tool input parameters (PreToolUse/PostToolUse only) */
  tool_input?: Record<string, unknown>;
  /** Tool response (PostToolUse only) */
  tool_response?: unknown;
  /** Agent name when running with --agent or inside a subagent */
  agent_name?: string;
  /** Agent CWD when running inside a subagent */
  agent_cwd?: string;
}

/** What our handler writes to stdout (exit 0) for PreToolUse hooks. */
export interface ClaudeCodeHookDecision {
  /** "block" prevents the tool call. "approve" bypasses permission prompt. */
  decision?: "block" | "approve";
  /** Reason text. For "block": fed back to Claude. For "approve": shown to user. */
  reason?: string;
}

// ─── Configuration ──────────────────────────────────────────────────

export interface ClaudeCodeInterceptorConfig extends Partial<InterceptorConfig> {
  /** Path to the project root (where .claude/ lives) */
  projectDir: string;
  /** Path to write the event log (JSONL). Default: .sentinelflow/events.jsonl */
  eventLogPath?: string;
  /** Maximum event log size in bytes before rotation. Default: 50MB */
  maxLogSizeBytes?: number;
  /** Tools that are always allowed (bypass policy evaluation) */
  toolAllowlist?: string[];
  /** Tools that are always blocked (bypass policy evaluation) */
  toolBlocklist?: string[];
  /** Maximum input summary length stored in events (truncated). Default: 500 chars */
  maxInputSummaryLength?: number;
  /** Write hooks to settings.json (committed) vs settings.local.json (gitignored). Default: "local" */
  settingsTarget?: "local" | "project";
}

// ─── Constants ──────────────────────────────────────────────────────

const CLAUDE_DIR = ".claude";
const SETTINGS_LOCAL = "settings.local.json";
const SETTINGS_PROJECT = "settings.json";
const SF_DIR = ".sentinelflow";
const HANDLER_SCRIPT = "handler.js";
const EVENT_LOG_FILE = "events.jsonl";
const DEFAULT_MAX_LOG_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_INPUT_LENGTH = 500;
const HOOK_TIMEOUT_MS = 10000; // 10 seconds

// High-risk tools that get extra scrutiny in policy evaluation
const HIGH_RISK_TOOLS = new Set([
  "Bash",
  "Write",
  "MultiEdit",
  "NotebookEdit",
  "TodoWrite",
]);

// ─── Interceptor Implementation ─────────────────────────────────────

export class ClaudeCodeInterceptor extends BaseInterceptor {
  readonly framework = "claude-code";

  private _projectDir: string;
  private _eventLogPath: string;
  private _maxLogSize: number;
  private _toolAllowlist: Set<string>;
  private _toolBlocklist: Set<string>;
  private _maxInputLength: number;
  private _settingsTarget: "local" | "project";
  private _originalSettings: string | null = null;

  constructor(config: ClaudeCodeInterceptorConfig) {
    super(config);
    this._projectDir = path.resolve(config.projectDir);
    this._eventLogPath =
      config.eventLogPath ??
      path.join(this._projectDir, SF_DIR, EVENT_LOG_FILE);
    this._maxLogSize = config.maxLogSizeBytes ?? DEFAULT_MAX_LOG_SIZE;
    this._toolAllowlist = new Set(config.toolAllowlist ?? []);
    this._toolBlocklist = new Set(config.toolBlocklist ?? []);
    this._maxInputLength = config.maxInputSummaryLength ?? DEFAULT_MAX_INPUT_LENGTH;
    this._settingsTarget = config.settingsTarget ?? "local";
  }

  // ─── Framework Hook Methods ─────────────────────────────────

  protected async hookFramework(): Promise<void> {
    // Ensure the .sentinelflow and .claude directories exist
    const sfDir = path.join(this._projectDir, SF_DIR);
    const claudeDir = path.join(this._projectDir, CLAUDE_DIR);
    fs.mkdirSync(sfDir, { recursive: true });
    fs.mkdirSync(claudeDir, { recursive: true });

    // Generate the handler script into .sentinelflow/handler.js
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);
    fs.writeFileSync(handlerPath, this.generateHandlerScript());
    fs.chmodSync(handlerPath, "755");

    // Merge our hooks into the correct settings file
    const settingsFile = this._settingsTarget === "local"
      ? SETTINGS_LOCAL
      : SETTINGS_PROJECT;
    const settingsPath = path.join(claudeDir, settingsFile);

    // Backup existing settings
    if (fs.existsSync(settingsPath)) {
      this._originalSettings = fs.readFileSync(settingsPath, "utf-8");
    }

    // Read existing settings or start fresh
    let settings: Record<string, unknown> = {};
    if (this._originalSettings) {
      try {
        settings = JSON.parse(this._originalSettings);
      } catch {
        settings = {};
      }
    }

    // Merge our hooks config (preserving any existing hooks)
    const hooksConfig = this.generateHooksConfig();
    const existingHooks = (settings.hooks ?? {}) as Record<string, unknown[]>;

    for (const [eventName, hookEntries] of Object.entries(hooksConfig.hooks)) {
      if (!existingHooks[eventName]) {
        existingHooks[eventName] = [];
      }
      // Remove any existing SentinelFlow hooks before adding fresh ones
      existingHooks[eventName] = (existingHooks[eventName] as Array<Record<string, unknown>>).filter(
        (entry) => {
          const innerHooks = entry.hooks as Array<Record<string, string>> | undefined;
          if (!innerHooks) return true;
          return !innerHooks.some((h) =>
            (h.command ?? "").includes("sentinelflow") || (h.command ?? "").includes(HANDLER_SCRIPT)
          );
        }
      );
      existingHooks[eventName].push(...hookEntries);
    }

    settings.hooks = existingHooks;
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

    this.log("info", `Installed hooks in ${settingsPath}`);
    this.log("info", `Handler: ${handlerPath}`);
    this.log("info", `Event log: ${this._eventLogPath}`);
  }

  protected async unhookFramework(): Promise<void> {
    const sfDir = path.join(this._projectDir, SF_DIR);
    const handlerPath = path.join(sfDir, HANDLER_SCRIPT);

    // Remove handler script
    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    // Restore or clean up settings file
    const settingsFile = this._settingsTarget === "local"
      ? SETTINGS_LOCAL
      : SETTINGS_PROJECT;
    const settingsPath = path.join(this._projectDir, CLAUDE_DIR, settingsFile);

    if (this._originalSettings) {
      fs.writeFileSync(settingsPath, this._originalSettings);
      this.log("info", "Restored original settings");
    } else if (fs.existsSync(settingsPath)) {
      // Remove our hooks from the settings
      try {
        const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
        if (settings.hooks) {
          for (const eventName of Object.keys(settings.hooks)) {
            settings.hooks[eventName] = (settings.hooks[eventName] as Array<Record<string, unknown>>).filter(
              (entry) => {
                const innerHooks = entry.hooks as Array<Record<string, string>> | undefined;
                if (!innerHooks) return true;
                return !innerHooks.some((h) =>
                  (h.command ?? "").includes("sentinelflow") || (h.command ?? "").includes(HANDLER_SCRIPT)
                );
              }
            );
            // Remove empty arrays
            if ((settings.hooks[eventName] as unknown[]).length === 0) {
              delete settings.hooks[eventName];
            }
          }
          if (Object.keys(settings.hooks).length === 0) {
            delete settings.hooks;
          }
        }
        // Only write back if there's still content
        if (Object.keys(settings).length > 0) {
          fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
        } else {
          fs.unlinkSync(settingsPath);
        }
      } catch {
        // If we can't parse it, leave it alone
      }
    }

    this.log("info", "Uninstalled Claude Code hooks");
  }

  // ─── Process a Hook Event (called by handler script or tests) ─

  async processHookEvent(
    rawEvent: ClaudeCodeHookInput
  ): Promise<ClaudeCodeHookDecision | null> {
    const hookName = rawEvent.hook_event_name;

    switch (hookName) {
      case "PreToolUse":
        return this.handlePreToolUse(rawEvent);
      case "PostToolUse":
        await this.handlePostToolUse(rawEvent);
        return null;
      case "Stop":
        await this.handleStop(rawEvent);
        return null;
      case "SessionStart":
        await this.handleSessionStart(rawEvent);
        return null;
      default:
        this.log("debug", `Unhandled hook event: ${hookName}`);
        return null;
    }
  }

  // ─── Hook Event Handlers ────────────────────────────────────

  private async handleSessionStart(rawEvent: ClaudeCodeHookInput): Promise<void> {
    const event = this.createEvent("session_start", {
      metadata: {
        claude_session_id: rawEvent.session_id,
        cwd: rawEvent.cwd,
        agent_name: rawEvent.agent_name,
        permission_mode: rawEvent.permission_mode,
      },
    });
    await this.emitEvent(event);
    this.appendToEventLog(event);
  }

  private async handlePreToolUse(
    rawEvent: ClaudeCodeHookInput
  ): Promise<ClaudeCodeHookDecision> {
    const toolName = rawEvent.tool_name ?? "unknown";

    // Fast path: allowlist bypass
    if (this._toolAllowlist.has(toolName)) {
      const event = this.createEvent("tool_call_start", {
        tool: {
          name: toolName,
          input_summary: this.summarizeInput(rawEvent.tool_input),
          status: "success",
        },
        metadata: {
          claude_session_id: rawEvent.session_id,
          cwd: rawEvent.cwd,
          bypassed_by: "allowlist",
        },
      });
      await this.emitEvent(event);
      this.appendToEventLog(event);
      return {}; // Empty object = allow (no decision field)
    }

    // Fast path: blocklist immediate block
    if (this._toolBlocklist.has(toolName)) {
      const event = this.createEvent("tool_call_blocked", {
        tool: {
          name: toolName,
          input_summary: this.summarizeInput(rawEvent.tool_input),
          status: "blocked",
        },
        metadata: {
          claude_session_id: rawEvent.session_id,
          blocked_by: "blocklist",
        },
      });
      event.governance = {
        policies_evaluated: ["tool_blocklist"],
        policies_passed: [],
        policies_failed: ["tool_blocklist"],
        action_taken: "blocked",
        reason: `Tool "${toolName}" is in the blocklist`,
      };
      await this.emitEvent(event);
      this.appendToEventLog(event);
      return {
        decision: "block",
        reason: `SentinelFlow: Tool "${toolName}" is blocked by policy`,
      };
    }

    // Normal path: run through the policy engine
    const { allowed, event } = await this.handleToolCall(
      toolName,
      this.summarizeInput(rawEvent.tool_input),
      {
        claude_session_id: rawEvent.session_id,
        cwd: rawEvent.cwd,
        tool_input_raw: rawEvent.tool_input,
        is_high_risk: HIGH_RISK_TOOLS.has(toolName),
      }
    );

    this.appendToEventLog(event);

    if (!allowed) {
      return {
        decision: "block",
        reason: `SentinelFlow: ${event.governance?.reason ?? "Blocked by policy"}`,
      };
    }

    return {}; // Allow
  }

  private async handlePostToolUse(rawEvent: ClaudeCodeHookInput): Promise<void> {
    const toolName = rawEvent.tool_name ?? "unknown";

    const event = this.createEvent("tool_call_end", {
      tool: {
        name: toolName,
        input_summary: this.summarizeInput(rawEvent.tool_input),
        status: "success",
      },
      metadata: {
        claude_session_id: rawEvent.session_id,
        cwd: rawEvent.cwd,
      },
    });

    await this.emitEvent(event);
    this.appendToEventLog(event);
  }

  private async handleStop(rawEvent: ClaudeCodeHookInput): Promise<void> {
    const event = this.createEvent("session_end", {
      metadata: {
        claude_session_id: rawEvent.session_id,
      },
    });
    await this.emitEvent(event);
    this.appendToEventLog(event);
  }

  // ─── Event Log (JSONL) ──────────────────────────────────────

  private appendToEventLog(event: AgentEvent): void {
    try {
      const dir = path.dirname(this._eventLogPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      // Rotate if too large
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

  // ─── Helper: Summarize Tool Input ───────────────────────────

  private summarizeInput(input?: Record<string, unknown>): string | undefined {
    if (!input) return undefined;
    if (typeof input.command === "string") return input.command.slice(0, this._maxInputLength);
    if (typeof input.file_path === "string") return `file: ${input.file_path}`;
    if (typeof input.path === "string") return `path: ${input.path}`;
    if (typeof input.content === "string") return `content: ${input.content.slice(0, 100)}...`;
    const raw = JSON.stringify(input);
    return raw.length > this._maxInputLength ? raw.slice(0, this._maxInputLength) + "..." : raw;
  }

  // ─── Hooks Config Generation ────────────────────────────────

  /**
   * Generate the hooks config object that gets merged into
   * .claude/settings.local.json. Uses $CLAUDE_PROJECT_DIR for
   * reliable path resolution across working directories.
   */
  private generateHooksConfig(): { hooks: Record<string, Array<Record<string, unknown>>> } {
    // Use $CLAUDE_PROJECT_DIR env var for path resolution.
    // Claude Code sets this to the project root automatically.
    const handlerCmd = `node "$CLAUDE_PROJECT_DIR/${SF_DIR}/${HANDLER_SCRIPT}"`;

    const hookEntry = (matcher: string) => ({
      matcher,
      hooks: [
        {
          type: "command",
          command: handlerCmd,
          timeout: HOOK_TIMEOUT_MS,
        },
      ],
    });

    return {
      hooks: {
        PreToolUse: [hookEntry("")],   // Match ALL tools
        PostToolUse: [hookEntry("")],   // Match ALL tools
        Stop: [hookEntry("")],
      },
    };
  }

  /**
   * Generate the handler script. This is a self-contained Node.js file
   * that Claude Code invokes as a subprocess.
   *
   * CRITICAL: The handler determines the hook phase from stdin JSON's
   * `hook_event_name` field — NOT from process.argv. Claude Code sends
   * the same handler command for all hook events.
   *
   * Dual-write: events go to both JSONL (fast, always works) and
   * SQLite (structured queries). SQLite failure never blocks the workflow.
   */
  private generateHandlerScript(): string {
    return `#!/usr/bin/env node
/**
 * SentinelFlow Claude Code Hook Handler
 * Generated by @sentinelflow/interceptors
 *
 * This script is invoked by Claude Code's hooks system for ALL hook events.
 * The hook type is determined from stdin JSON's "hook_event_name" field.
 *
 * Exit codes (Claude Code hooks contract):
 *   0 = success. Stdout JSON processed (shown in verbose mode).
 *   2 = block. Stderr text fed back to Claude as error message.
 *   Other = non-blocking error. Stderr shown in verbose mode.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ─── Configuration (baked in at install time) ───────────────
const PROJECT_DIR = process.env.CLAUDE_PROJECT_DIR || ${JSON.stringify(this._projectDir)};
const SF_DIR = path.join(PROJECT_DIR, ".sentinelflow");
const EVENT_LOG = path.join(SF_DIR, "events.jsonl");
const DB_PATH = path.join(SF_DIR, "events.db");
const TOOL_ALLOWLIST = new Set(${JSON.stringify([...this._toolAllowlist])});
const TOOL_BLOCKLIST = new Set(${JSON.stringify([...this._toolBlocklist])});
const ENFORCEMENT_MODE = ${JSON.stringify(this.enforcementMode)};
const MAX_INPUT_LENGTH = ${this._maxInputLength};

// ─── SQLite (optional — graceful degradation) ───────────────
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
  // SQLite unavailable — JSONL-only mode. This is fine.
}

// ─── Helpers ────────────────────────────────────────────────
function summarizeInput(input) {
  if (!input) return null;
  if (typeof input.command === "string") return input.command.slice(0, MAX_INPUT_LENGTH);
  if (typeof input.file_path === "string") return "file: " + input.file_path;
  if (typeof input.path === "string") return "path: " + input.path;
  if (typeof input.content === "string") return "content: " + input.content.slice(0, 100) + "...";
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
    agent_id: opts.agent_id || "claude-code",
    framework: "claude_code",
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

// ─── Policy Evaluation ──────────────────────────────────────
function evaluatePolicy(toolName, toolInput) {
  if (TOOL_BLOCKLIST.has(toolName))
    return { block: true, reason: 'Tool "' + toolName + '" is in the blocklist', id: "tool_blocklist" };
  if (TOOL_ALLOWLIST.has(toolName))
    return { block: false };

  // Load runtime policies from .sentinelflow-policy.yaml if present
  const policyPath = path.join(PROJECT_DIR, ".sentinelflow-policy.yaml");
  if (fs.existsSync(policyPath)) {
    try {
      const content = fs.readFileSync(policyPath, "utf-8");
      const rtMatch = content.match(/runtime_policies:([\\s\\S]*?)(?=\\n[a-z]|$)/);
      if (rtMatch) {
        const block = rtMatch[1];
        const blockedMatch = block.match(/blocked_tools:\\s*\\n((?:\\s+-\\s+.+\\n?)*)/);
        if (blockedMatch) {
          const blocked = blockedMatch[1].split("\\n").map(l => l.trim().replace(/^-\\s+/, "")).filter(Boolean);
          if (blocked.includes(toolName))
            return { block: true, reason: 'Tool "' + toolName + '" blocked by policy file', id: "policy_yaml" };
        }
      }
    } catch { /* ignore policy parse errors */ }
  }

  // Dangerous command patterns (Bash tool only)
  if (toolName === "Bash" && toolInput && typeof toolInput.command === "string") {
    const cmd = toolInput.command;
    const patterns = [
      [/rm\\s+-rf\\s+\\/(?!tmp)/, "rm -rf outside /tmp"],
      [/curl.*\\|\\s*(?:bash|sh)/, "curl piped to shell"],
      [/wget.*\\|\\s*(?:bash|sh)/, "wget piped to shell"],
      [/chmod\\s+777/, "world-writable permissions"],
      [/>(\\s*)\\/etc\\//, "writing to /etc"],
      [/dd\\s+if=.*of=\\/dev\\//, "dd to block device"],
      [/mkfs\\./, "filesystem format"],
      [/npm\\s+publish/, "npm publish"],
      [/git\\s+push.*--force/, "force push"],
    ];
    for (const [re, desc] of patterns) {
      if (re.test(cmd)) {
        return {
          block: ENFORCEMENT_MODE === "enforce",
          reason: "Dangerous command: " + desc + " — " + cmd.slice(0, 100),
          id: "dangerous_commands",
        };
      }
    }
  }

  return { block: false };
}

// ─── Main ───────────────────────────────────────────────────
async function main() {
  // Read all of stdin
  let rawInput = "";
  for await (const chunk of process.stdin) { rawInput += chunk; }

  // Parse JSON — fail open on parse failure
  let input;
  try {
    input = JSON.parse(rawInput);
  } catch {
    process.stderr.write("[sentinelflow] Failed to parse stdin JSON, failing open\\n");
    process.exit(0);
  }

  // Determine hook type from the JSON — NOT from process.argv
  const hookEvent = input.hook_event_name;
  const toolName = input.tool_name;
  const toolInput = input.tool_input;
  const sessionId = input.session_id || "unknown";
  const inputSummary = summarizeInput(toolInput);

  switch (hookEvent) {
    case "PreToolUse": {
      const policy = evaluatePolicy(toolName, toolInput);
      const isBlock = policy.block;

      persistEvent(makeEvent(
        isBlock ? "tool_call_blocked" : "tool_call_attempted",
        isBlock ? "blocked" : "allowed",
        isBlock ? "high" : "info",
        { session_id: sessionId, tool_name: toolName, tool_input_summary: inputSummary,
          action: inputSummary, policy_id: policy.id, reason: policy.reason,
          payload: { hook: "PreToolUse", cwd: input.cwd } }
      ));

      if (isBlock) {
        // Exit 2 = block. Stderr message is fed back to Claude.
        process.stderr.write("SentinelFlow: " + (policy.reason || "Blocked by policy"));
        process.exit(2);
      }
      // Exit 0 = allow. No stdout needed.
      break;
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
      break;
    }

    case "Stop": {
      persistEvent(makeEvent(
        "session_ended", "info", "info",
        { session_id: sessionId, payload: { hook: "Stop" } }
      ));
      break;
    }

    default:
      // Unknown hook event — log it and continue
      persistEvent(makeEvent(
        "tool_call_attempted", "info", "info",
        { session_id: sessionId, payload: { hook: hookEvent, raw: input } }
      ));
  }

  // Clean up SQLite
  if (db) { try { db.close(); } catch {} }
}

main().catch((err) => {
  // ALWAYS fail open. Never break the user's Claude Code workflow.
  process.stderr.write("[sentinelflow] Handler error (failing open): " + (err.message || err) + "\\n");
  if (db) { try { db.close(); } catch {} }
  process.exit(0);
});
`;
  }

  // ─── Static Methods ─────────────────────────────────────────

  static async install(config: ClaudeCodeInterceptorConfig): Promise<ClaudeCodeInterceptor> {
    const interceptor = new ClaudeCodeInterceptor(config);
    await interceptor.start();
    return interceptor;
  }

  static isInstalled(projectDir: string): boolean {
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);
    return fs.existsSync(handlerPath);
  }

  static async uninstall(projectDir: string): Promise<void> {
    const handlerPath = path.join(projectDir, SF_DIR, HANDLER_SCRIPT);

    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    // Remove hooks from both settings files
    for (const settingsFile of [SETTINGS_LOCAL, SETTINGS_PROJECT]) {
      const settingsPath = path.join(projectDir, CLAUDE_DIR, settingsFile);
      if (!fs.existsSync(settingsPath)) continue;

      try {
        const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
        if (!settings.hooks) continue;

        for (const eventName of Object.keys(settings.hooks)) {
          settings.hooks[eventName] = (settings.hooks[eventName] as Array<Record<string, unknown>>).filter(
            (entry) => {
              const innerHooks = entry.hooks as Array<Record<string, string>> | undefined;
              if (!innerHooks) return true;
              return !innerHooks.some((h) =>
                (h.command ?? "").includes("sentinelflow") || (h.command ?? "").includes(HANDLER_SCRIPT)
              );
            }
          );
          if ((settings.hooks[eventName] as unknown[]).length === 0) {
            delete settings.hooks[eventName];
          }
        }

        if (Object.keys(settings.hooks).length === 0) {
          delete settings.hooks;
        }

        if (Object.keys(settings).length > 0) {
          fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
        } else {
          fs.unlinkSync(settingsPath);
        }
      } catch {
        // If we can't parse it, leave it alone
      }
    }
  }
}
