/**
 * @module @sentinelflow/interceptors/policies
 *
 * Built-in policy providers for the runtime agent firewall.
 * These ship with SentinelFlow and cover the most common governance needs.
 * Users can also write custom PolicyProvider implementations.
 *
 * Built-in policies:
 *   1. ToolAllowlistPolicy — Only allow explicitly listed tools
 *   2. ToolBlocklistPolicy — Block specific tools
 *   3. DangerousCommandPolicy — Block dangerous bash patterns
 *   4. CostBudgetPolicy — Block when session cost exceeds budget
 *   5. DataBoundaryPolicy — Block tool calls that reference sensitive paths/patterns
 */

import type { AgentEvent } from "@sentinelflow/core";
import type { PolicyProvider, PolicyEvaluationResult } from "./interface";

// ─── 1. Tool Allowlist Policy ───────────────────────────────────────

/**
 * Only allow tool calls to explicitly listed tools.
 * Everything not on the list is blocked (enforce) or flagged (monitor).
 * This is the strictest policy — use it for production agents.
 */
export class ToolAllowlistPolicy implements PolicyProvider {
  readonly name = "tool_allowlist";
  private _allowedTools: Set<string>;

  constructor(allowedTools: string[]) {
    this._allowedTools = new Set(allowedTools);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    if (!event.tool?.name) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    if (this._allowedTools.has(event.tool.name)) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    return {
      decision: "block",
      matched_policies: [this.name],
      reason: `Tool "${event.tool.name}" is not in the allowlist. Allowed: ${[...this._allowedTools].join(", ")}`,
      evaluation_ms: Date.now() - start,
    };
  }
}

// ─── 2. Tool Blocklist Policy ───────────────────────────────────────

/**
 * Block specific tools. Use this to prevent agents from using
 * known-dangerous tools while allowing everything else.
 * Less strict than allowlist — good for development environments.
 */
export class ToolBlocklistPolicy implements PolicyProvider {
  readonly name = "tool_blocklist";
  private _blockedTools: Set<string>;

  constructor(blockedTools: string[]) {
    this._blockedTools = new Set(blockedTools);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    if (!event.tool?.name) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    if (this._blockedTools.has(event.tool.name)) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason: `Tool "${event.tool.name}" is blocked by policy`,
        evaluation_ms: Date.now() - start,
      };
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}

// ─── 3. Dangerous Command Policy ────────────────────────────────────

/**
 * Inspects Bash tool inputs for dangerous command patterns.
 * Catches common footguns like `rm -rf /`, `curl | bash`,
 * `chmod 777`, writing to system directories, etc.
 *
 * This is heuristic-based — it will miss obfuscated commands
 * and creative shell escapes. It's a safety net, not a sandbox.
 */
export class DangerousCommandPolicy implements PolicyProvider {
  readonly name = "dangerous_commands";

  private _patterns: Array<{ regex: RegExp; description: string }> = [
    { regex: /rm\s+-rf\s+\/(?!tmp)/, description: "rm -rf outside /tmp" },
    { regex: /curl.*\|\s*(?:bash|sh)/, description: "curl piped to shell" },
    { regex: /wget.*\|\s*(?:bash|sh)/, description: "wget piped to shell" },
    { regex: /chmod\s+777/, description: "world-writable permissions" },
    { regex: />\s*\/etc\//, description: "writing to /etc" },
    { regex: /dd\s+if=.*of=\/dev\//, description: "dd to block device" },
    { regex: /mkfs\./, description: "filesystem format command" },
    { regex: /:()\{\s*:\|\:&\s*\};:/, description: "fork bomb" },
    { regex: /eval\s+"?\$\(.*curl/, description: "eval with curl" },
    { regex: /npm\s+publish/, description: "npm publish (unexpected in agent context)" },
    { regex: /git\s+push.*--force/, description: "force push" },
    { regex: />\s*\/dev\/sd[a-z]/, description: "writing to raw device" },
  ];

  private _customPatterns: Array<{ regex: RegExp; description: string }>;

  constructor(customPatterns?: Array<{ pattern: string; description: string }>) {
    this._customPatterns = (customPatterns ?? []).map((p) => ({
      regex: new RegExp(p.pattern),
      description: p.description,
    }));
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    // Only evaluate Bash tool calls
    if (!event.tool?.name || event.tool.name !== "Bash") {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    const command = event.tool.input_summary ?? "";
    const allPatterns = [...this._patterns, ...this._customPatterns];

    for (const { regex, description } of allPatterns) {
      if (regex.test(command)) {
        return {
          decision: "block",
          matched_policies: [this.name],
          reason: `Dangerous command pattern detected: ${description} — command: ${command.slice(0, 100)}`,
          evaluation_ms: Date.now() - start,
        };
      }
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}

// ─── 4. Cost Budget Policy ──────────────────────────────────────────

/**
 * Tracks estimated cost during a session and blocks tool calls
 * when the budget is exceeded. Cost is estimated from token counts
 * in tool_call_end events.
 *
 * This is a soft limit — it can only block FUTURE calls after
 * the budget is exceeded, not retroactively stop past ones.
 */
export class CostBudgetPolicy implements PolicyProvider {
  readonly name = "cost_budget";

  private _maxCostUsd: number;
  private _currentCostUsd = 0;

  constructor(maxCostPerSessionUsd: number) {
    this._maxCostUsd = maxCostPerSessionUsd;
  }

  get currentCost(): number {
    return this._currentCostUsd;
  }

  /** Call this when a tool_call_end event arrives with token usage */
  recordCost(costUsd: number): void {
    this._currentCostUsd += costUsd;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    // Record cost from token usage if present
    if (event.tokens?.estimated_cost_usd) {
      this._currentCostUsd += event.tokens.estimated_cost_usd;
    }

    if (this._currentCostUsd >= this._maxCostUsd) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason: `Session cost $${this._currentCostUsd.toFixed(4)} exceeds budget $${this._maxCostUsd.toFixed(2)}`,
        evaluation_ms: Date.now() - start,
      };
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }

  reset(): void {
    this._currentCostUsd = 0;
  }
}

// ─── 5. Data Boundary Policy ────────────────────────────────────────

/**
 * Blocks tool calls that reference sensitive file paths or data patterns.
 * Use this to prevent agents from accessing production databases,
 * credential files, or regulated data directories.
 */
export class DataBoundaryPolicy implements PolicyProvider {
  readonly name = "data_boundary";

  private _blockedPaths: RegExp[];
  private _blockedPatterns: RegExp[];

  constructor(config: {
    blockedPaths?: string[];
    blockedPatterns?: string[];
  }) {
    this._blockedPaths = (config.blockedPaths ?? []).map(
      (p) => new RegExp(p.replace(/\*/g, ".*"))
    );
    this._blockedPatterns = (config.blockedPatterns ?? []).map(
      (p) => new RegExp(p, "i")
    );
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    const input = event.tool?.input_summary ?? "";

    // Check blocked paths
    for (const pathRegex of this._blockedPaths) {
      if (pathRegex.test(input)) {
        return {
          decision: "block",
          matched_policies: [this.name],
          reason: `Tool input references blocked path pattern: ${input.slice(0, 100)}`,
          evaluation_ms: Date.now() - start,
        };
      }
    }

    // Check blocked data patterns (e.g., SSN, credit card, etc.)
    for (const patternRegex of this._blockedPatterns) {
      if (patternRegex.test(input)) {
        return {
          decision: "block",
          matched_policies: [this.name],
          reason: `Tool input matches blocked data pattern`,
          evaluation_ms: Date.now() - start,
        };
      }
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}
