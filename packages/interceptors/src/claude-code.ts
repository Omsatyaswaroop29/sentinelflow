/**
 * @module @sentinelflow/interceptors/claude-code
 *
 * Claude Code Runtime Interceptor
 * ================================
 *
 * Claude Code provides a hooks system (hooks/hooks.json) that lets you run
 * shell commands at key lifecycle points:
 *
 *   PreToolUse  → Fires BEFORE a tool executes. Can return {"decision":"block"}
 *                 to prevent the tool call. This is our enforcement point.
 *   PostToolUse → Fires AFTER a tool completes. Gets the result. This is
 *                 our telemetry and anomaly detection point.
 *   Stop        → Fires when the agent session ends.
 *
 * How this interceptor works:
 *
 *   1. install() generates a hooks.json that routes events to our handler
 *   2. The handler is a small Node.js script that reads the hook event from
 *      stdin, converts it to an AgentEvent, evaluates policies, and returns
 *      a decision to stdout (for PreToolUse) or just logs (for PostToolUse)
 *   3. Events are written to a local event log (JSONL file) that the event
 *      store and dashboard can consume
 *   4. uninstall() removes the hooks config
 *
 * The hooks.json format (from Claude Code docs):
 * {
 *   "hooks": {
 *     "PreToolUse": [{ "type": "command", "command": "node handler.js pre" }],
 *     "PostToolUse": [{ "type": "command", "command": "node handler.js post" }],
 *     "Stop": [{ "type": "command", "command": "node handler.js stop" }]
 *   }
 * }
 *
 * The handler receives the event on stdin as JSON:
 * {
 *   "hook_type": "PreToolUse",
 *   "tool_name": "Bash",
 *   "tool_input": { "command": "rm -rf /" },
 *   "session_id": "abc123"
 * }
 *
 * For PreToolUse, the handler returns a decision on stdout:
 * { "decision": "allow" } or { "decision": "block", "reason": "..." }
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

// ─── Claude Code Hook Event Types ───────────────────────────────────

export interface ClaudeCodeHookEvent {
  hook_type: "PreToolUse" | "PostToolUse" | "Stop" | "PreCompact" | "SessionStart";
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_output?: string;
  session_id?: string;
  agent_name?: string;
  /** Error from the tool, if PostToolUse with a failed tool */
  error?: string;
}

export interface ClaudeCodeHookDecision {
  decision: "allow" | "block";
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
}

// ─── Constants ──────────────────────────────────────────────────────

const HOOKS_DIR = "hooks";
const HOOKS_JSON = "hooks.json";
const HANDLER_SCRIPT = "sentinelflow-handler.js";
const EVENT_LOG_DIR = ".sentinelflow";
const EVENT_LOG_FILE = "events.jsonl";
const DEFAULT_MAX_LOG_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_INPUT_LENGTH = 500;

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
  private _originalHooksJson: string | null = null;

  constructor(config: ClaudeCodeInterceptorConfig) {
    super(config);
    this._projectDir = path.resolve(config.projectDir);
    this._eventLogPath =
      config.eventLogPath ??
      path.join(this._projectDir, EVENT_LOG_DIR, EVENT_LOG_FILE);
    this._maxLogSize = config.maxLogSizeBytes ?? DEFAULT_MAX_LOG_SIZE;
    this._toolAllowlist = new Set(config.toolAllowlist ?? []);
    this._toolBlocklist = new Set(config.toolBlocklist ?? []);
    this._maxInputLength = config.maxInputSummaryLength ?? DEFAULT_MAX_INPUT_LENGTH;
  }

  // ─── Framework Hook Methods ─────────────────────────────────

  protected async hookFramework(): Promise<void> {
    // Ensure the hooks directory and event log directory exist
    const hooksDir = path.join(this._projectDir, HOOKS_DIR);
    const eventLogDir = path.dirname(this._eventLogPath);
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.mkdirSync(eventLogDir, { recursive: true });

    // Backup existing hooks.json if present
    const hooksJsonPath = path.join(hooksDir, HOOKS_JSON);
    if (fs.existsSync(hooksJsonPath)) {
      this._originalHooksJson = fs.readFileSync(hooksJsonPath, "utf-8");
      this.log("info", "Backed up existing hooks.json");
    }

    // Generate the handler script that Claude Code will invoke
    const handlerPath = path.join(hooksDir, HANDLER_SCRIPT);
    fs.writeFileSync(handlerPath, this.generateHandlerScript());
    fs.chmodSync(handlerPath, "755");

    // Generate hooks.json that wires Claude Code events to our handler
    const hooksConfig = this.generateHooksJson(handlerPath);
    fs.writeFileSync(hooksJsonPath, JSON.stringify(hooksConfig, null, 2));

    this.log("info", `Installed hooks at ${hooksJsonPath}`);
    this.log("info", `Event log: ${this._eventLogPath}`);
  }

  protected async unhookFramework(): Promise<void> {
    const hooksDir = path.join(this._projectDir, HOOKS_DIR);
    const hooksJsonPath = path.join(hooksDir, HOOKS_JSON);
    const handlerPath = path.join(hooksDir, HANDLER_SCRIPT);

    // Restore original hooks.json or remove ours
    if (this._originalHooksJson) {
      fs.writeFileSync(hooksJsonPath, this._originalHooksJson);
      this.log("info", "Restored original hooks.json");
    } else if (fs.existsSync(hooksJsonPath)) {
      fs.unlinkSync(hooksJsonPath);
    }

    // Remove our handler script
    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    this.log("info", "Uninstalled Claude Code hooks");
  }

  // ─── Process a Hook Event (called by the handler script) ────

  /**
   * Process a raw Claude Code hook event. This is the main entry point
   * called by the handler script when Claude Code fires a hook.
   *
   * For PreToolUse: evaluates policies and returns allow/block.
   * For PostToolUse: logs the result and checks for anomalies.
   * For Stop: emits session_end.
   */
  async processHookEvent(
    rawEvent: ClaudeCodeHookEvent
  ): Promise<ClaudeCodeHookDecision | null> {
    switch (rawEvent.hook_type) {
      case "SessionStart":
        return this.handleSessionStart(rawEvent);
      case "PreToolUse":
        return this.handlePreToolUse(rawEvent);
      case "PostToolUse":
        await this.handlePostToolUse(rawEvent);
        return null;
      case "Stop":
        await this.handleStop(rawEvent);
        return null;
      default:
        this.log("warn", `Unknown hook type: ${rawEvent.hook_type}`);
        return null;
    }
  }

  // ─── Hook Event Handlers ────────────────────────────────────

  private async handleSessionStart(
    rawEvent: ClaudeCodeHookEvent
  ): Promise<null> {
    const event = this.createEvent("session_start", {
      metadata: {
        claude_session_id: rawEvent.session_id,
        agent_name: rawEvent.agent_name,
      },
    });
    await this.emitEvent(event);
    this.appendToEventLog(event);
    return null;
  }

  private async handlePreToolUse(
    rawEvent: ClaudeCodeHookEvent
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
          bypassed_by: "allowlist",
        },
      });
      await this.emitEvent(event);
      this.appendToEventLog(event);
      return { decision: "allow" };
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
        reason: `Tool "${toolName}" is blocked by SentinelFlow policy`,
      };
    }

    // Normal path: run through the policy engine
    const { allowed, event } = await this.handleToolCall(
      toolName,
      this.summarizeInput(rawEvent.tool_input),
      {
        claude_session_id: rawEvent.session_id,
        tool_input_raw: rawEvent.tool_input,
        is_high_risk: HIGH_RISK_TOOLS.has(toolName),
      }
    );

    this.appendToEventLog(event);

    if (!allowed) {
      return {
        decision: "block",
        reason: event.governance?.reason ?? "Blocked by SentinelFlow policy",
      };
    }

    return { decision: "allow" };
  }

  private async handlePostToolUse(rawEvent: ClaudeCodeHookEvent): Promise<void> {
    const toolName = rawEvent.tool_name ?? "unknown";
    const hasError = !!rawEvent.error;

    const event = this.createEvent("tool_call_end", {
      tool: {
        name: toolName,
        input_summary: this.summarizeInput(rawEvent.tool_input),
        output_summary: rawEvent.tool_output
          ? rawEvent.tool_output.slice(0, this._maxInputLength)
          : undefined,
        status: hasError ? "error" : "success",
        error_message: rawEvent.error,
      },
      metadata: {
        claude_session_id: rawEvent.session_id,
      },
    });

    await this.emitEvent(event);
    this.appendToEventLog(event);
  }

  private async handleStop(rawEvent: ClaudeCodeHookEvent): Promise<void> {
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
      // Rotate if too large
      if (
        fs.existsSync(this._eventLogPath) &&
        fs.statSync(this._eventLogPath).size > this._maxLogSize
      ) {
        const rotatedPath = this._eventLogPath + ".1";
        if (fs.existsSync(rotatedPath)) {
          fs.unlinkSync(rotatedPath);
        }
        fs.renameSync(this._eventLogPath, rotatedPath);
        this.log("info", "Rotated event log");
      }

      fs.appendFileSync(
        this._eventLogPath,
        JSON.stringify(event) + "\n",
        "utf-8"
      );
    } catch (err) {
      this.log("error", `Failed to write event log: ${err}`);
    }
  }

  // ─── Helper: Summarize Tool Input ───────────────────────────

  private summarizeInput(input?: Record<string, unknown>): string | undefined {
    if (!input) return undefined;

    // For Bash tools, show the command
    if (typeof input.command === "string") {
      return input.command.slice(0, this._maxInputLength);
    }
    // For file tools, show the path
    if (typeof input.file_path === "string") {
      return `file: ${input.file_path}`;
    }
    if (typeof input.path === "string") {
      return `path: ${input.path}`;
    }

    // Generic: JSON stringify truncated
    const raw = JSON.stringify(input);
    return raw.length > this._maxInputLength
      ? raw.slice(0, this._maxInputLength) + "..."
      : raw;
  }

  // ─── Code Generation ────────────────────────────────────────

  /**
   * Generate the hooks.json config that wires Claude Code events
   * to our handler script.
   */
  private generateHooksJson(handlerPath: string): object {
    return {
      hooks: {
        PreToolUse: [
          {
            type: "command",
            command: `node "${handlerPath}" pre`,
          },
        ],
        PostToolUse: [
          {
            type: "command",
            command: `node "${handlerPath}" post`,
          },
        ],
        Stop: [
          {
            type: "command",
            command: `node "${handlerPath}" stop`,
          },
        ],
      },
    };
  }

  /**
   * Generate the handler script that Claude Code will invoke.
   * This script runs as a subprocess — it reads the hook event from stdin,
   * processes it, and writes the decision to stdout (for PreToolUse).
   *
   * The handler is a self-contained Node.js script that:
   * 1. Reads the hook event from stdin
   * 2. Loads the policy config from .sentinelflow-policy.yaml
   * 3. Evaluates tool allowlists/blocklists
   * 4. Writes the decision to stdout (PreToolUse only)
   * 5. Appends the event to the JSONL log
   */
  private generateHandlerScript(): string {
    // The handler needs to be self-contained because Claude Code
    // runs it as a subprocess. We inline the config values.
    return `#!/usr/bin/env node
/**
 * SentinelFlow Claude Code Hook Handler
 * Generated by @sentinelflow/interceptors
 *
 * This script is invoked by Claude Code's hooks system.
 * It reads event data from stdin and writes decisions to stdout.
 */

const fs = require("fs");
const path = require("path");

// ─── Configuration (generated at install time) ──────────────
const EVENT_LOG = ${JSON.stringify(this._eventLogPath)};
const TOOL_ALLOWLIST = new Set(${JSON.stringify([...this._toolAllowlist])});
const TOOL_BLOCKLIST = new Set(${JSON.stringify([...this._toolBlocklist])});
const ENFORCEMENT_MODE = ${JSON.stringify(this.enforcementMode)};
const MAX_INPUT_LENGTH = ${this._maxInputLength};
const PROJECT_DIR = ${JSON.stringify(this._projectDir)};

// ─── Policy Loading ─────────────────────────────────────────
function loadPolicies() {
  const policyPath = path.join(PROJECT_DIR, ".sentinelflow-policy.yaml");
  if (!fs.existsSync(policyPath)) return null;
  try {
    // Simple YAML parsing for the runtime_policies section
    const content = fs.readFileSync(policyPath, "utf-8");
    // Look for runtime_policies block
    const runtimeMatch = content.match(/runtime_policies:([\\s\\S]*?)(?=\\n[a-z]|$)/);
    if (!runtimeMatch) return null;
    
    const block = runtimeMatch[1];
    const policies = {};
    
    // Parse blocked_tools list
    const blockedMatch = block.match(/blocked_tools:\\s*\\n((?:\\s+-\\s+.+\\n?)*)/);
    if (blockedMatch) {
      policies.blocked_tools = blockedMatch[1]
        .split("\\n")
        .map(l => l.trim().replace(/^-\\s+/, ""))
        .filter(Boolean);
    }
    
    // Parse allowed_tools list
    const allowedMatch = block.match(/allowed_tools:\\s*\\n((?:\\s+-\\s+.+\\n?)*)/);
    if (allowedMatch) {
      policies.allowed_tools = allowedMatch[1]
        .split("\\n")
        .map(l => l.trim().replace(/^-\\s+/, ""))
        .filter(Boolean);
    }

    // Parse max_cost_per_session
    const costMatch = block.match(/max_cost_per_session:\\s*([\\d.]+)/);
    if (costMatch) {
      policies.max_cost_per_session = parseFloat(costMatch[1]);
    }

    return policies;
  } catch {
    return null;
  }
}

// ─── Event Logging ──────────────────────────────────────────
function logEvent(event) {
  try {
    const dir = path.dirname(EVENT_LOG);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(EVENT_LOG, JSON.stringify(event) + "\\n");
  } catch { /* never crash on log failure */ }
}

function createEvent(type, toolName, toolInput, sessionId, extra = {}) {
  return {
    id: Math.random().toString(36).slice(2) + Date.now().toString(36),
    timestamp: new Date().toISOString(),
    agent_id: "claude-code",
    session_id: sessionId || "unknown",
    type,
    tool: toolName ? {
      name: toolName,
      input_summary: summarizeInput(toolInput),
      status: extra.status || "success",
    } : undefined,
    governance: extra.governance,
    metadata: extra.metadata,
  };
}

function summarizeInput(input) {
  if (!input) return undefined;
  if (typeof input.command === "string") return input.command.slice(0, MAX_INPUT_LENGTH);
  if (typeof input.file_path === "string") return "file: " + input.file_path;
  if (typeof input.path === "string") return "path: " + input.path;
  const raw = JSON.stringify(input);
  return raw.length > MAX_INPUT_LENGTH ? raw.slice(0, MAX_INPUT_LENGTH) + "..." : raw;
}

// ─── Policy Evaluation ──────────────────────────────────────
function evaluateToolPolicy(toolName, toolInput) {
  // Static blocklist/allowlist
  if (TOOL_BLOCKLIST.has(toolName)) {
    return { decision: "block", reason: "Tool \\"" + toolName + "\\" is in the blocklist" };
  }
  if (TOOL_ALLOWLIST.has(toolName)) {
    return { decision: "allow" };
  }

  // Dynamic policies from .sentinelflow-policy.yaml
  const policies = loadPolicies();
  if (policies) {
    if (policies.blocked_tools && policies.blocked_tools.includes(toolName)) {
      return { decision: "block", reason: "Tool \\"" + toolName + "\\" blocked by .sentinelflow-policy.yaml" };
    }
    if (policies.allowed_tools && policies.allowed_tools.length > 0) {
      if (!policies.allowed_tools.includes(toolName)) {
        return { 
          decision: ENFORCEMENT_MODE === "enforce" ? "block" : "allow",
          reason: "Tool \\"" + toolName + "\\" not in allowed_tools list"
        };
      }
    }
  }

  // Dangerous command patterns (Bash tool)
  if (toolName === "Bash" && toolInput && typeof toolInput.command === "string") {
    const cmd = toolInput.command;
    const dangerousPatterns = [
      /rm\\s+-rf\\s+\\/(?!tmp)/,      // rm -rf outside /tmp
      /curl.*\\|\\s*(?:bash|sh)/,     // curl | bash (pipe to shell)
      /wget.*\\|\\s*(?:bash|sh)/,     // wget | bash
      /chmod\\s+777/,                  // world-writable permissions
      />(\\s*)\\/etc\\//,              // writing to /etc
    ];
    for (const pattern of dangerousPatterns) {
      if (pattern.test(cmd)) {
        return {
          decision: ENFORCEMENT_MODE === "enforce" ? "block" : "allow",
          reason: "Dangerous command pattern detected: " + cmd.slice(0, 100),
        };
      }
    }
  }

  return { decision: "allow" };
}

// ─── Main ───────────────────────────────────────────────────
async function main() {
  const hookPhase = process.argv[2]; // "pre", "post", or "stop"

  // Read the hook event from stdin
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  let hookEvent;
  try {
    hookEvent = JSON.parse(input);
  } catch {
    // If stdin is empty or invalid, just exit cleanly
    process.exit(0);
  }

  const toolName = hookEvent.tool_name;
  const toolInput = hookEvent.tool_input;
  const sessionId = hookEvent.session_id;

  switch (hookPhase) {
    case "pre": {
      const policy = evaluateToolPolicy(toolName, toolInput);
      const event = createEvent(
        policy.decision === "block" ? "tool_call_blocked" : "tool_call_start",
        toolName,
        toolInput,
        sessionId,
        {
          status: policy.decision === "block" ? "blocked" : "success",
          governance: {
            policies_evaluated: ["tool_allowlist", "tool_blocklist", "command_patterns", "policy_yaml"],
            policies_passed: policy.decision === "allow" ? ["all"] : [],
            policies_failed: policy.decision === "block" ? [policy.reason] : [],
            action_taken: policy.decision === "block" ? "blocked" : "allowed",
            reason: policy.reason,
          },
        }
      );
      logEvent(event);

      // Write decision to stdout for Claude Code
      if (policy.decision === "block") {
        console.log(JSON.stringify({
          decision: "block",
          reason: policy.reason,
        }));
      }
      // For "allow", we output nothing (Claude Code treats no output as allow)
      break;
    }

    case "post": {
      const event = createEvent("tool_call_end", toolName, toolInput, sessionId, {
        status: hookEvent.error ? "error" : "success",
      });
      if (hookEvent.error) {
        event.tool.error_message = hookEvent.error;
      }
      logEvent(event);
      break;
    }

    case "stop": {
      const event = createEvent("session_end", null, null, sessionId);
      logEvent(event);
      break;
    }
  }
}

main().catch(() => process.exit(0)); // Never crash — that would block Claude Code
`;
  }

  // ─── Static Methods ─────────────────────────────────────────

  /**
   * Install SentinelFlow hooks into a Claude Code project.
   * This is the main user-facing API for setup.
   *
   * Usage:
   *   npx sentinelflow intercept --project ./my-project
   *
   * Or programmatically:
   *   await ClaudeCodeInterceptor.install({ projectDir: "./my-project" });
   */
  static async install(config: ClaudeCodeInterceptorConfig): Promise<ClaudeCodeInterceptor> {
    const interceptor = new ClaudeCodeInterceptor(config);
    await interceptor.start();
    return interceptor;
  }

  /**
   * Check if SentinelFlow hooks are installed in a project.
   */
  static isInstalled(projectDir: string): boolean {
    const handlerPath = path.join(projectDir, HOOKS_DIR, HANDLER_SCRIPT);
    return fs.existsSync(handlerPath);
  }

  /**
   * Uninstall SentinelFlow hooks from a project.
   */
  static async uninstall(projectDir: string): Promise<void> {
    const hooksDir = path.join(projectDir, HOOKS_DIR);
    const handlerPath = path.join(hooksDir, HANDLER_SCRIPT);
    const hooksJsonPath = path.join(hooksDir, HOOKS_JSON);

    if (fs.existsSync(handlerPath)) {
      fs.unlinkSync(handlerPath);
    }

    // Only remove hooks.json if it only contains our hooks
    if (fs.existsSync(hooksJsonPath)) {
      try {
        const content = JSON.parse(fs.readFileSync(hooksJsonPath, "utf-8"));
        const hasOnlySentinelflow =
          JSON.stringify(content).includes("sentinelflow-handler");
        if (hasOnlySentinelflow) {
          fs.unlinkSync(hooksJsonPath);
        }
      } catch {
        // If we can't parse it, leave it alone
      }
    }
  }
}
