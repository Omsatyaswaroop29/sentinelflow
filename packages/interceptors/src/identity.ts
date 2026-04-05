/**
 * @module @sentinelflow/interceptors/identity
 *
 * Identity and delegation governance — links agent actions to human sponsors.
 *
 * This module answers the question compliance auditors always ask:
 * "Who authorized this agent to run, and what is it allowed to do?"
 *
 * Three components:
 *
 *   1. IdentityResolver — populates identity context on every event
 *      from policy config, environment variables, and git config.
 *
 *   2. RoleBasedAccessPolicy — enforces "low-privilege agents may not
 *      call high-privilege tools" using the agent's role/privilege level.
 *
 *   3. EnvironmentPolicy — enforces environment-specific restrictions
 *      like "production agents cannot use write tools" or "external-facing
 *      agents cannot touch restricted paths."
 *
 * Maps to:
 *   - OWASP LLM09 (Excessive Agency): prevents agents from exceeding authorized scope
 *   - OWASP LLM08 (Insecure Plugin Design): controls which tools each agent can use
 *   - EU AI Act Article 14: human oversight and intervention capability
 *   - NIST AI RMF Govern 1.4: organizational roles and responsibilities
 *   - SOC 2 CC6.1: logical and physical access controls
 */

import type {
  AgentEvent,
  IdentityContext,
  AgentRole,
  Environment,
} from "@sentinelflow/core";
import type { PolicyProvider, PolicyEvaluationResult, EventListener } from "./interface";
import { SHELL_TOOL_NAMES } from "./patterns";

// ─── Role → Privilege Level Mapping ─────────────────────────────────

const DEFAULT_ROLE_PRIVILEGES: Record<AgentRole, number> = {
  reader: 2,
  writer: 4,
  executor: 6,
  deployer: 8,
  admin: 10,
  custom: 5,
};

// ─── Tool → Minimum Privilege Mapping ───────────────────────────────

/**
 * Default tool privilege requirements.
 * Tools not listed here require privilege level 1 (anyone can use them).
 */
const DEFAULT_TOOL_PRIVILEGES: Record<string, number> = {
  // Shell tools require executor (6) or higher
  Bash: 6, bash: 6, shell: 6, Shell: 6,
  terminal: 6, Terminal: 6, exec: 6, Exec: 6,
  RunCommand: 6, run_command: 6, execute: 6, Execute: 6,

  // Write tools require writer (4) or higher
  Write: 4, write: 4, Edit: 4, edit: 4,
  MultiEdit: 4, multiedit: 4, Create: 4, create: 4,
  FileEdit: 4, file_edit: 4, create_file: 4, write_file: 4,

  // Deploy tools require deployer (8) or higher
  NotebookEdit: 8, TodoWrite: 8,
};

// ─── 1. Identity Resolver ───────────────────────────────────────────

export interface IdentityConfig {
  /** Human owner of this agent (required for audit compliance) */
  human_owner?: string;
  /** Owner email */
  human_email?: string;
  /** Team name */
  team?: string;
  /** Deployment environment */
  environment?: Environment;
  /** Agent role */
  role?: AgentRole;
  /** Privilege level (overrides role-based default) */
  privilege_level?: number;
  /** Whether agent faces external users */
  external_facing?: boolean;
  /** Custom tags */
  tags?: string[];
  /** Per-agent role overrides: agent_id → role */
  agent_roles?: Record<string, AgentRole>;
  /** Per-agent privilege overrides: agent_id → level */
  agent_privileges?: Record<string, number>;
}

/**
 * Resolves identity context for every event.
 *
 * Acts as an EventListener — attaches identity to each event as it flows
 * through the pipeline. Downstream policies can then use event.identity
 * to make access control decisions.
 *
 * Resolution order:
 *   1. Per-agent overrides (agent_roles, agent_privileges)
 *   2. Explicit config (role, privilege_level, human_owner)
 *   3. Environment variables (SENTINELFLOW_OWNER, SENTINELFLOW_TEAM, etc.)
 *   4. Defaults (role: executor, environment: development, privilege: 6)
 */
export class IdentityResolver implements EventListener {
  readonly name = "identity_resolver";

  private _config: IdentityConfig;
  private _defaultIdentity: IdentityContext;

  constructor(config?: IdentityConfig) {
    this._config = config ?? {};

    // Resolve the default identity from config + environment
    const role = this._config.role ?? this.envOr("SENTINELFLOW_ROLE", "executor") as AgentRole;
    const privLevel = this._config.privilege_level ?? DEFAULT_ROLE_PRIVILEGES[role] ?? 5;

    this._defaultIdentity = {
      human_owner:
        this._config.human_owner ??
        this.envOr("SENTINELFLOW_OWNER", undefined) ??
        this.envOr("USER", undefined) ??
        this.envOr("GITHUB_ACTOR", "unknown"),
      human_email:
        this._config.human_email ??
        this.envOr("SENTINELFLOW_EMAIL", undefined),
      team:
        this._config.team ??
        this.envOr("SENTINELFLOW_TEAM", undefined) ??
        this.envOr("GITHUB_REPOSITORY_OWNER", undefined),
      environment: this._config.environment ?? this.resolveEnvironment(),
      role,
      privilege_level: privLevel,
      external_facing: this._config.external_facing ?? false,
      tags: this._config.tags ?? [],
    };
  }

  /** Attach identity context to every event */
  onEvent(event: AgentEvent): void {
    if (!event.identity) {
      event.identity = this.resolveForAgent(event.agent_id);
    }
  }

  /** Get the identity context for a specific agent */
  resolveForAgent(agentId: string): IdentityContext {
    const agentRole = this._config.agent_roles?.[agentId];
    const agentPriv = this._config.agent_privileges?.[agentId];

    if (!agentRole && agentPriv === undefined) {
      return { ...this._defaultIdentity };
    }

    const role = agentRole ?? this._defaultIdentity.role;
    return {
      ...this._defaultIdentity,
      role,
      privilege_level: agentPriv ?? DEFAULT_ROLE_PRIVILEGES[role] ?? this._defaultIdentity.privilege_level,
    };
  }

  /** Get the default identity (for display/debug) */
  getDefaultIdentity(): IdentityContext {
    return { ...this._defaultIdentity };
  }

  private envOr(key: string, fallback: string | undefined): string | undefined {
    try {
      return process.env[key] ?? fallback;
    } catch {
      return fallback;
    }
  }

  private resolveEnvironment(): Environment {
    // Check common CI/CD environment indicators
    const ciVars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "BUILDKITE"];
    for (const v of ciVars) {
      try { if (process.env[v]) return "ci"; } catch { /* ignore */ }
    }

    // Check explicit env var
    const envStr = this.envOr("SENTINELFLOW_ENV", undefined)?.toLowerCase();
    if (envStr === "production" || envStr === "prod") return "production";
    if (envStr === "staging" || envStr === "stage") return "staging";
    if (envStr === "development" || envStr === "dev") return "development";
    if (envStr === "ci") return "ci";

    // Check NODE_ENV
    const nodeEnv = this.envOr("NODE_ENV", undefined)?.toLowerCase();
    if (nodeEnv === "production") return "production";
    if (nodeEnv === "staging") return "staging";

    return "development";
  }
}

// ─── 2. Role-Based Access Policy ────────────────────────────────────

/**
 * Enforces role-based access control for agent tool calls.
 *
 * "Low-privilege agents may not call high-privilege tools."
 *
 * Uses the identity context attached to events by IdentityResolver.
 * If no identity is present, uses a configurable default privilege level.
 *
 * Maps to:
 *   - OWASP LLM09: Excessive Agency
 *   - SOC 2 CC6.1: Logical Access Controls
 *   - NIST AI RMF Map 1.5: AI-specific access management
 */
export class RoleBasedAccessPolicy implements PolicyProvider {
  readonly name = "role_based_access";

  private _toolPrivileges: Record<string, number>;
  private _defaultAgentPrivilege: number;

  constructor(config?: {
    /** Override default tool → privilege mappings */
    toolPrivileges?: Record<string, number>;
    /** Default privilege for agents without identity context */
    defaultAgentPrivilege?: number;
  }) {
    this._toolPrivileges = {
      ...DEFAULT_TOOL_PRIVILEGES,
      ...(config?.toolPrivileges ?? {}),
    };
    this._defaultAgentPrivilege = config?.defaultAgentPrivilege ?? 6;
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const toolName = event.tool?.name;
    if (!toolName) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    // Get required privilege for this tool
    const requiredPrivilege = this._toolPrivileges[toolName] ?? 1;

    // Get agent's privilege level from identity context
    const agentPrivilege = event.identity?.privilege_level ?? this._defaultAgentPrivilege;
    const agentRole = event.identity?.role ?? "unknown";
    const agentOwner = event.identity?.human_owner ?? "unknown";

    if (agentPrivilege < requiredPrivilege) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason:
          `Agent "${event.agent_id}" (role: ${agentRole}, privilege: ${agentPrivilege}, ` +
          `owner: ${agentOwner}) attempted to use tool "${toolName}" ` +
          `which requires privilege level ${requiredPrivilege}. ` +
          `Increase agent privilege or assign a higher role.`,
        evaluation_ms: Date.now() - start,
      };
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}

// ─── 3. Environment Policy ──────────────────────────────────────────

/**
 * Enforces environment-specific restrictions.
 *
 * Examples:
 *   - "Production agents cannot use Bash or Write tools"
 *   - "External-facing agents cannot access restricted paths"
 *   - "CI agents can only use read and test tools"
 *
 * Maps to:
 *   - EU AI Act Article 9: Risk management across environments
 *   - SOC 2 CC8.1: Change management (production restrictions)
 *   - NIST AI RMF Govern 1.7: AI deployment governance
 */
export class EnvironmentPolicy implements PolicyProvider {
  readonly name = "environment_policy";

  private _productionBlockedTools: Set<string>;
  private _ciAllowedTools: Set<string>;
  private _externalBlockedTools: Set<string>;
  private _stagingBlockedTools: Set<string>;

  constructor(config?: {
    /** Tools blocked in production. Default: all shell + write tools */
    productionBlockedTools?: string[];
    /** Tools allowed in CI. Default: read + test tools only */
    ciAllowedTools?: string[];
    /** Tools blocked for external-facing agents. Default: shell + write tools */
    externalBlockedTools?: string[];
    /** Tools blocked in staging. Default: deploy tools */
    stagingBlockedTools?: string[];
  }) {
    this._productionBlockedTools = new Set(
      config?.productionBlockedTools ?? [...SHELL_TOOL_NAMES]
    );
    this._ciAllowedTools = new Set(
      config?.ciAllowedTools ?? [
        "Read", "read", "ReadFile", "read_file",
        "ListDir", "list_dir", "View", "view",
        "Bash", "bash", // CI needs bash for test/build
      ]
    );
    this._externalBlockedTools = new Set(
      config?.externalBlockedTools ?? [
        ...SHELL_TOOL_NAMES,
        "Write", "write", "Edit", "edit", "MultiEdit", "multiedit",
        "Create", "create",
      ]
    );
    this._stagingBlockedTools = new Set(
      config?.stagingBlockedTools ?? ["NotebookEdit", "TodoWrite"]
    );
  }

  evaluate(event: AgentEvent): PolicyEvaluationResult {
    const start = Date.now();
    const toolName = event.tool?.name;
    if (!toolName) {
      return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
    }

    const env = event.identity?.environment ?? "development";
    const isExternal = event.identity?.external_facing ?? false;
    const owner = event.identity?.human_owner ?? "unknown";

    // Production restrictions
    if (env === "production" && this._productionBlockedTools.has(toolName)) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason:
          `Tool "${toolName}" is blocked in production environment. ` +
          `Agent "${event.agent_id}" (owner: ${owner}) attempted a restricted operation. ` +
          `Production agents should use read-only tools or request a deployment pipeline.`,
        evaluation_ms: Date.now() - start,
      };
    }

    // CI restrictions (allowlist-based)
    if (env === "ci" && !this._ciAllowedTools.has(toolName)) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason:
          `Tool "${toolName}" is not in the CI-allowed tools list. ` +
          `CI agents can only use: ${[...this._ciAllowedTools].join(", ")}.`,
        evaluation_ms: Date.now() - start,
      };
    }

    // External-facing agent restrictions
    if (isExternal && this._externalBlockedTools.has(toolName)) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason:
          `Tool "${toolName}" is blocked for external-facing agents. ` +
          `Agent "${event.agent_id}" is marked as external_facing and cannot ` +
          `use write or execute tools. Restrict to read-only operations.`,
        evaluation_ms: Date.now() - start,
      };
    }

    // Staging restrictions
    if (env === "staging" && this._stagingBlockedTools.has(toolName)) {
      return {
        decision: "block",
        matched_policies: [this.name],
        reason:
          `Tool "${toolName}" is blocked in staging environment.`,
        evaluation_ms: Date.now() - start,
      };
    }

    return { decision: "allow", matched_policies: [], evaluation_ms: Date.now() - start };
  }
}
