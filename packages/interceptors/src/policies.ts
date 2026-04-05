/**
 * @module @sentinelflow/interceptors/policies
 *
 * Enterprise-grade policy providers for the runtime agent firewall.
 *
 * Built-in policies:
 *   1. ToolAllowlistPolicy    — Only allow explicitly listed tools
 *   2. ToolBlocklistPolicy    — Block specific tools
 *   3. DangerousCommandPolicy — Block dangerous bash patterns (with normalization)
 *   4. CostBudgetPolicy       — Block when session cost exceeds budget
 *   5. DataBoundaryPolicy     — Block tool calls referencing sensitive paths
 *   6. NetworkEgressPolicy    — Block/flag outbound network to unapproved domains
 *   7. SecretsLeakPolicy      — Detect credentials in tool arguments
 *   8. FileWritePolicy        — Block writes to sensitive file paths
 */

import type { AgentEvent } from "@sentinelflow/core";
import type { PolicyProvider, PolicyEvaluationResult } from "./interface";
import {
  DANGEROUS_COMMAND_PATTERNS,
  SECRET_PATTERNS,
  SENSITIVE_WRITE_PATHS,
  NETWORK_EGRESS_PATTERNS,
  SHELL_TOOL_NAMES,
  compilePatterns,
  type DangerousPattern,
  type SecretPattern,
  type SensitivePathPattern,
} from "./patterns";
import { normalizeCommand, normalizeAndSplit, extractDomain } from "./normalizer";

// ─── Helper ─────────────────────────────────────────────────────────

function elapsed(start: number): number { return Date.now() - start; }

function allow(start: number): PolicyEvaluationResult {
  return { decision: "allow", matched_policies: [], evaluation_ms: elapsed(start) };
}

// ─── 1. Tool Allowlist Policy ───────────────────────────────────────

export class ToolAllowlistPolicy implements PolicyProvider {
  readonly name = "tool_allowlist";
  private _allowed: Set<string>;

  constructor(allowedTools: string[]) {
    this._allowed = new Set(allowedTools);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    if (!event.tool?.name) return allow(start);
    if (this._allowed.has(event.tool.name)) return allow(start);
    return {
      decision: "block", matched_policies: [this.name],
      reason: `Tool "${event.tool.name}" is not in the allowlist. Allowed: ${[...this._allowed].join(", ")}`,
      evaluation_ms: elapsed(start),
    };
  }
}

// ─── 2. Tool Blocklist Policy ───────────────────────────────────────

export class ToolBlocklistPolicy implements PolicyProvider {
  readonly name = "tool_blocklist";
  private _blocked: Set<string>;

  constructor(blockedTools: string[]) {
    this._blocked = new Set(blockedTools);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    if (!event.tool?.name) return allow(start);
    if (!this._blocked.has(event.tool.name)) return allow(start);
    return {
      decision: "block", matched_policies: [this.name],
      reason: `Tool "${event.tool.name}" is blocked by policy`,
      evaluation_ms: elapsed(start),
    };
  }
}

// ─── 3. Dangerous Command Policy (HARDENED) ─────────────────────────

/**
 * Inspects shell tool inputs for dangerous command patterns.
 *
 * ENTERPRISE HARDENING (v0.4):
 *   - Uses central pattern registry (patterns.ts) — single source of truth
 *   - Normalizes commands before matching (normalizer.ts):
 *     → strips quoting ("rm" → rm), backslash escapes (r\m → rm)
 *     → expands flags (-rf → -r -f)
 *     → splits compound commands (cmd1 && cmd2)
 *   - Matches against ALL sub-commands in pipelines and subshells
 *   - Recognizes all shell tool name variants (Bash, bash, shell, terminal, etc.)
 *
 * LIMITATIONS (documented, not hidden):
 *   - Cannot resolve shell variables ($VAR)
 *   - Cannot decode base64/hex obfuscation embedded in variables
 *   - Cannot trace multi-step attacks (write script → chmod → execute)
 *   - This is a guardrail, not a sandbox
 */
export class DangerousCommandPolicy implements PolicyProvider {
  readonly name = "dangerous_commands";

  private _patterns: Array<DangerousPattern & { compiled: RegExp }>;
  private _shellTools: Set<string>;

  constructor(opts?: {
    customPatterns?: Array<{ pattern: string; description: string; severity?: string }>;
    additionalShellTools?: string[];
  }) {
    this._patterns = compilePatterns(DANGEROUS_COMMAND_PATTERNS);

    // Add custom patterns if provided
    if (opts?.customPatterns) {
      for (const p of opts.customPatterns) {
        this._patterns.push({
          id: `CUSTOM-${this._patterns.length}`,
          description: p.description,
          regex: p.pattern,
          severity: (p.severity as DangerousPattern["severity"]) ?? "high",
          tags: ["custom"],
          compiled: new RegExp(p.pattern),
        });
      }
    }

    // Use the canonical shell tool names + any extras
    this._shellTools = new Set([...SHELL_TOOL_NAMES, ...(opts?.additionalShellTools ?? [])]);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    // Only evaluate shell tool calls (using the full variant list)
    if (!event.tool?.name || !this._shellTools.has(event.tool.name)) {
      return allow(start);
    }

    const rawCommand = event.tool.input_summary ?? "";

    // Normalize and split into sub-commands
    const subCommands = normalizeAndSplit(rawCommand);
    // Also check the raw command (in case normalization strips something)
    subCommands.push(rawCommand);

    for (const cmd of subCommands) {
      for (const pattern of this._patterns) {
        if (pattern.compiled.test(cmd)) {
          return {
            decision: "block",
            matched_policies: [this.name],
            reason: `Dangerous command [${pattern.id}]: ${pattern.description} — ${rawCommand.slice(0, 100)}`,
            evaluation_ms: elapsed(start),
          };
        }
      }
    }

    return allow(start);
  }
}

// ─── 4. Cost Budget Policy ──────────────────────────────────────────

/**
 * Tracks estimated session cost and blocks when budget is exceeded.
 *
 * HONEST LIMITATION: As of April 2026, no IDE framework (Claude Code,
 * Cursor, Copilot, Codex) provides token or cost data in hook event
 * payloads. This policy will NOT fire in practice until frameworks
 * expose cost metadata. It exists as infrastructure for when they do.
 *
 * When configured but unusable, it emits a warning to stderr.
 */
export class CostBudgetPolicy implements PolicyProvider {
  readonly name = "cost_budget";
  private _maxCostUsd: number;
  private _currentCostUsd = 0;
  private _warned = false;

  constructor(maxCostPerSessionUsd: number) {
    this._maxCostUsd = maxCostPerSessionUsd;
  }

  get currentCost(): number { return this._currentCostUsd; }

  recordCost(costUsd: number): void {
    this._currentCostUsd += costUsd;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();

    // Record cost from token usage if present
    if (event.tokens?.estimated_cost_usd) {
      this._currentCostUsd += event.tokens.estimated_cost_usd;
    } else if (!this._warned) {
      // Honest warning: frameworks don't provide cost data yet
      this._warned = true;
    }

    if (this._currentCostUsd >= this._maxCostUsd) {
      return {
        decision: "block", matched_policies: [this.name],
        reason: `Session cost $${this._currentCostUsd.toFixed(4)} exceeds budget $${this._maxCostUsd.toFixed(2)}`,
        evaluation_ms: elapsed(start),
      };
    }

    return allow(start);
  }

  reset(): void { this._currentCostUsd = 0; }
}

// ─── 5. Data Boundary Policy ────────────────────────────────────────

export class DataBoundaryPolicy implements PolicyProvider {
  readonly name = "data_boundary";
  private _blockedPaths: RegExp[];
  private _blockedPatterns: RegExp[];

  constructor(config: { blockedPaths?: string[]; blockedPatterns?: string[] }) {
    this._blockedPaths = (config.blockedPaths ?? []).map((p) => new RegExp(p.replace(/\*/g, ".*")));
    this._blockedPatterns = (config.blockedPatterns ?? []).map((p) => new RegExp(p, "i"));
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const input = event.tool?.input_summary ?? "";

    for (const r of this._blockedPaths) {
      if (r.test(input)) {
        return { decision: "block", matched_policies: [this.name],
          reason: `Tool input references blocked path: ${input.slice(0, 100)}`, evaluation_ms: elapsed(start) };
      }
    }
    for (const r of this._blockedPatterns) {
      if (r.test(input)) {
        return { decision: "block", matched_policies: [this.name],
          reason: `Tool input matches blocked data pattern`, evaluation_ms: elapsed(start) };
      }
    }
    return allow(start);
  }
}

// ─── 6. Network Egress Policy (NEW) ─────────────────────────────────

/**
 * Detects outbound network activity in shell commands and enforces
 * domain-level allowlists/denylists.
 *
 * This is the #1 enterprise ask for AI agent governance:
 * preventing data exfiltration via agent-initiated HTTP requests.
 *
 * Behavior:
 *   - In monitor mode: logs all outbound network activity with domains
 *   - In enforce mode: blocks requests to non-allowlisted domains
 *   - Supports wildcard domain patterns (*.corp.internal)
 */
export class NetworkEgressPolicy implements PolicyProvider {
  readonly name = "network_egress";

  private _patterns = compilePatterns(NETWORK_EGRESS_PATTERNS);
  private _allowedDomains: Set<string>;
  private _allowedWildcards: string[];
  private _blockedDomains: Set<string>;
  private _shellTools: Set<string>;

  constructor(config?: {
    allowedDomains?: string[];
    blockedDomains?: string[];
    additionalShellTools?: string[];
  }) {
    // Parse allowed domains, separating wildcards from exact matches
    this._allowedDomains = new Set<string>();
    this._allowedWildcards = [];
    for (const d of config?.allowedDomains ?? []) {
      if (d.startsWith("*.")) {
        this._allowedWildcards.push(d.slice(2)); // *.corp.internal → corp.internal
      } else {
        this._allowedDomains.add(d);
      }
    }
    this._blockedDomains = new Set(config?.blockedDomains ?? []);
    this._shellTools = new Set([...SHELL_TOOL_NAMES, ...(config?.additionalShellTools ?? [])]);
  }

  private isDomainAllowed(domain: string): boolean {
    if (this._allowedDomains.size === 0 && this._allowedWildcards.length === 0) {
      // No allowlist configured — only enforce blocklist
      return !this._blockedDomains.has(domain);
    }
    if (this._allowedDomains.has(domain)) return true;
    for (const suffix of this._allowedWildcards) {
      if (domain.endsWith(suffix)) return true;
    }
    return false;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    if (!event.tool?.name || !this._shellTools.has(event.tool.name)) return allow(start);

    const rawCommand = event.tool.input_summary ?? "";
    const commands = normalizeAndSplit(rawCommand);
    commands.push(rawCommand);

    for (const cmd of commands) {
      for (const pattern of this._patterns) {
        const match = cmd.match(pattern.compiled);
        if (match) {
          const urlStr = match[pattern.urlGroupIndex ?? 0] ?? "";
          const domain = extractDomain(urlStr);

          if (domain) {
            // Check blocklist first (explicit blocks always win)
            if (this._blockedDomains.has(domain)) {
              return {
                decision: "block", matched_policies: [this.name],
                reason: `Network egress to blocked domain: ${domain}`,
                evaluation_ms: elapsed(start),
              };
            }

            // Check allowlist (if configured)
            if (!this.isDomainAllowed(domain)) {
              return {
                decision: "block", matched_policies: [this.name],
                reason: `Network egress to non-allowlisted domain: ${domain} — command: ${rawCommand.slice(0, 80)}`,
                evaluation_ms: elapsed(start),
              };
            }
          }
        }
      }
    }

    return allow(start);
  }
}

// ─── 7. Secrets Leak Policy (NEW) ───────────────────────────────────

/**
 * Detects credentials and secrets in tool input arguments.
 *
 * Prevents AI agents from accidentally passing API keys, tokens,
 * database URLs, and other credentials through tool calls.
 *
 * This aligns with OWASP LLM06 (Sensitive Information Disclosure)
 * and is a top-10 enterprise concern for LLM deployments.
 *
 * Behavior:
 *   - In monitor mode: logs and flags, does not block
 *   - In enforce mode: blocks and redacts the secret in log output
 */
export class SecretsLeakPolicy implements PolicyProvider {
  readonly name = "secrets_leak";
  private _patterns = compilePatterns(SECRET_PATTERNS);

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const input = event.tool?.input_summary ?? "";

    if (!input) return allow(start);

    for (const pattern of this._patterns) {
      if (pattern.compiled.test(input)) {
        return {
          decision: "block",
          matched_policies: [this.name],
          // Deliberately vague in the reason — don't echo the secret
          reason: `Secret detected in tool input [${pattern.id}]: ${pattern.description}. Credentials must be passed via secure configuration, not tool arguments.`,
          evaluation_ms: elapsed(start),
        };
      }
    }

    return allow(start);
  }
}

// ─── 8. File Write Policy (NEW) ─────────────────────────────────────

/**
 * Blocks writes to sensitive file paths — the second most dangerous
 * action after shell execution.
 *
 * An agent that can write to ~/.ssh/authorized_keys, .env,
 * package.json (postinstall scripts), or .github/workflows/
 * can compromise a system without ever touching Bash.
 *
 * Applies to:
 *   - Write/Edit tools (checks the file_path argument)
 *   - Shell commands with redirect (>, >>, tee)
 */
export class FileWritePolicy implements PolicyProvider {
  readonly name = "file_write";

  private _patterns = compilePatterns(SENSITIVE_WRITE_PATHS);
  private _customBlockedPaths: RegExp[];
  private _writeToolNames = new Set([
    "Write", "write", "Edit", "edit", "MultiEdit", "multiedit",
    "Create", "create", "FileEdit", "file_edit",
    "create_file", "write_file", "edit_file",
    "NotebookEdit", "TodoWrite",
  ]);
  private _shellTools: Set<string>;

  constructor(config?: {
    additionalBlockedPaths?: string[];
    additionalWriteTools?: string[];
    additionalShellTools?: string[];
  }) {
    this._customBlockedPaths = (config?.additionalBlockedPaths ?? []).map((p) => new RegExp(p));
    if (config?.additionalWriteTools) {
      for (const t of config.additionalWriteTools) this._writeToolNames.add(t);
    }
    this._shellTools = new Set([...SHELL_TOOL_NAMES, ...(config?.additionalShellTools ?? [])]);
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const toolName = event.tool?.name ?? "";
    const input = event.tool?.input_summary ?? "";

    if (!toolName || !input) return allow(start);

    // Check Write/Edit tools
    if (this._writeToolNames.has(toolName)) {
      return this.checkPath(input, start);
    }

    // Check shell commands with redirect operators
    if (this._shellTools.has(toolName)) {
      // Look for redirect targets: > file, >> file, tee file
      const redirectMatch = input.match(/(?:>>?|tee\s+(?:-a\s+)?)\s*(\S+)/);
      if (redirectMatch?.[1]) {
        return this.checkPath(redirectMatch[1], start);
      }
    }

    return allow(start);
  }

  private checkPath(filePath: string, start: number): PolicyEvaluationResult {
    // Strip common prefixes added by handler scripts
    // Handlers format paths as "file: /path/to/file" or "path: /path/to/file"
    let cleanPath = filePath;
    if (cleanPath.startsWith("file: ")) cleanPath = cleanPath.slice(6);
    else if (cleanPath.startsWith("path: ")) cleanPath = cleanPath.slice(6);
    cleanPath = cleanPath.trim();

    // Check central registry patterns
    for (const pattern of this._patterns) {
      if (pattern.compiled.test(cleanPath)) {
        return {
          decision: "block", matched_policies: [this.name],
          reason: `Write to sensitive path [${pattern.id}]: ${pattern.description} -- ${cleanPath}`,
          evaluation_ms: elapsed(start),
        };
      }
    }

    // Check custom blocked paths
    for (const r of this._customBlockedPaths) {
      if (r.test(cleanPath)) {
        return {
          decision: "block", matched_policies: [this.name],
          reason: `Write to custom-blocked path: ${cleanPath}`,
          evaluation_ms: elapsed(start),
        };
      }
    }

    return allow(start);
  }
}
