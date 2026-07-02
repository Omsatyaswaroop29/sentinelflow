/**
 * sentinelflow intercept — Runtime agent firewall commands.
 *
 * Supports multiple frameworks:
 *   - Claude Code: hooks in .claude/settings.local.json
 *   - Cursor:      hooks in .cursor/hooks.json
 *   - Copilot:     hooks in .github/hooks/sentinelflow.json
 *
 * Auto-detects the framework from the project directory, or use --framework.
 */

import * as path from "path";
import * as fs from "fs";
import {
  ClaudeCodeInterceptor, CursorInterceptor, CopilotInterceptor, CodexInterceptor,
  type DataBoundaryCodegenConfig, type IdentityCodegenConfig, type SequenceDetectionCodegenConfig,
} from "@sentinelflow/interceptors";
import { loadPolicyFile, type RuntimePoliciesConfig } from "@sentinelflow/scanner";

/**
 * Map the YAML policy schema (snake_case, matches .sentinelflow-policy.yaml)
 * onto the handler codegen's config shape (camelCase). Fields left
 * undefined fall back to generatePolicyEvaluationCode()'s own defaults
 * (enabled + monitor mode).
 */
function toDataBoundaryCodegenConfig(cfg?: RuntimePoliciesConfig["data_boundary"]): DataBoundaryCodegenConfig | undefined {
  if (!cfg) return undefined;
  return {
    enabled: cfg.enabled ?? true,
    enforcementMode: cfg.enforcement_mode ?? "monitor",
    defaultMaxClassification: cfg.default_max_classification ?? "internal",
    agentClearances: cfg.agent_clearances ?? [],
    customRules: cfg.custom_rules ?? [],
  };
}

function toIdentityCodegenConfig(cfg?: RuntimePoliciesConfig["identity"]): IdentityCodegenConfig | undefined {
  if (!cfg) return undefined;
  const role = cfg.role ?? "executor";
  const rolePrivileges: Record<string, number> = { reader: 2, writer: 4, executor: 6, deployer: 8, admin: 10, custom: 5 };
  return {
    enabled: cfg.enabled ?? true,
    enforcementMode: cfg.enforcement_mode ?? "monitor",
    defaultRole: role,
    defaultPrivilege: cfg.privilege_level ?? rolePrivileges[role] ?? 6,
    environment: cfg.environment ?? "development",
    externalFacing: cfg.external_facing ?? false,
    agentRoles: cfg.agent_roles ?? {},
    agentPrivileges: cfg.agent_privileges ?? {},
  };
}

function toSequenceDetectionCodegenConfig(cfg?: RuntimePoliciesConfig["sequence_detection"]): SequenceDetectionCodegenConfig | undefined {
  if (!cfg) return undefined;
  return {
    enabled: cfg.enabled ?? true,
    enforcementMode: cfg.enforcement_mode ?? "monitor",
    windowMinutes: cfg.window_minutes ?? 5,
    minConfidence: cfg.min_confidence ?? 0.7,
  };
}

type Framework = "claude-code" | "cursor" | "copilot" | "codex";

function detectFrameworks(projectDir: string): Framework[] {
  const found: Framework[] = [];
  if (fs.existsSync(path.join(projectDir, ".claude"))) found.push("claude-code");
  if (fs.existsSync(path.join(projectDir, ".cursor"))) found.push("cursor");
  if (fs.existsSync(path.join(projectDir, ".github"))) found.push("copilot");
  if (fs.existsSync(path.join(projectDir, ".codex"))) found.push("codex");
  return found;
}

function resolveFramework(projectDir: string, explicit?: string): Framework {
  if (explicit) {
    const n = explicit.toLowerCase().replace(/\s+/g, "-");
    if (n === "claude-code" || n === "claude" || n === "cc") return "claude-code";
    if (n === "cursor") return "cursor";
    if (n === "copilot" || n === "github-copilot" || n === "gh") return "copilot";
    if (n === "codex" || n === "openai-codex" || n === "opencode") return "codex";
    console.error(`\n  Unknown framework: "${explicit}". Supported: claude-code, cursor, copilot, codex\n`);
    process.exit(1);
  }

  const detected = detectFrameworks(projectDir);

  if (detected.length === 0) {
    console.log("\n  No .claude/, .cursor/, or .github/ directory found.");
    console.log("  Use --framework to specify: claude-code, cursor, or copilot\n");
    process.exit(1);
  }

  if (detected.length === 1) return detected[0]!;

  // Multiple detected — check which has hooks installed
  if (ClaudeCodeInterceptor.isInstalled(projectDir)) return "claude-code";
  if (CursorInterceptor.isInstalled(projectDir)) return "cursor";
  if (CopilotInterceptor.isInstalled(projectDir)) return "copilot";
  if (CodexInterceptor.isInstalled(projectDir)) return "codex";

  console.log(`\n  Multiple frameworks detected: ${detected.join(", ")}.`);
  console.log("  Use --framework to specify which one:");
  console.log("    sentinelflow intercept install --framework claude-code");
  console.log("    sentinelflow intercept install --framework cursor");
  console.log("    sentinelflow intercept install --framework copilot\n");
  process.exit(1);
}

function isInstalled(projectDir: string): { installed: boolean; framework?: Framework } {
  if (ClaudeCodeInterceptor.isInstalled(projectDir)) return { installed: true, framework: "claude-code" };
  if (CursorInterceptor.isInstalled(projectDir)) return { installed: true, framework: "cursor" };
  if (CopilotInterceptor.isInstalled(projectDir)) return { installed: true, framework: "copilot" };
  if (CodexInterceptor.isInstalled(projectDir)) return { installed: true, framework: "codex" };
  return { installed: false };
}

// ─── Install ────────────────────────────────────────────────────────

/**
 * Load .sentinelflow-policy.yaml's runtime_policies section, if present.
 * This is the "policy as code" story: config checked into git, not just
 * passed as CLI flags that nobody remembers to repeat.
 */
function loadRuntimePolicyDefaults(projectDir: string): RuntimePoliciesConfig {
  const { policy, warnings } = loadPolicyFile(projectDir);
  for (const w of warnings) {
    console.log(`  Warning: ${w}`);
  }
  return policy?.runtime_policies ?? {};
}

export async function interceptInstallCommand(
  targetPath: string,
  options: {
    mode?: string;
    blocklist?: string;
    allowlist?: string;
    budget?: string;
    framework?: string;
    egressAllow?: string;
    egressBlock?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  if (!fs.existsSync(projectDir)) { console.error(`\n  Error: Directory not found: ${projectDir}\n`); process.exit(1); }

  const framework = resolveFramework(projectDir, options.framework);

  // CLI flags take precedence; .sentinelflow-policy.yaml's runtime_policies
  // section supplies defaults so policy can be checked into version control
  // instead of re-typed on every install.
  const yamlDefaults = loadRuntimePolicyDefaults(projectDir);
  const usingYamlDefaults: string[] = [];

  const mode = (options.mode ?? yamlDefaults.enforcement_mode ?? "monitor") as "monitor" | "enforce";
  if (!options.mode && yamlDefaults.enforcement_mode) usingYamlDefaults.push("mode");

  const toolBlocklist = options.blocklist
    ? options.blocklist.split(",").map((t) => t.trim())
    : yamlDefaults.blocked_tools;
  if (!options.blocklist && yamlDefaults.blocked_tools) usingYamlDefaults.push("blocklist");

  const toolAllowlist = options.allowlist
    ? options.allowlist.split(",").map((t) => t.trim())
    : yamlDefaults.allowed_tools;
  if (!options.allowlist && yamlDefaults.allowed_tools) usingYamlDefaults.push("allowlist");

  const egressAllowedDomains = options.egressAllow
    ? options.egressAllow.split(",").map((d) => d.trim()).filter(Boolean)
    : yamlDefaults.egress_allowed_domains;
  if (!options.egressAllow && yamlDefaults.egress_allowed_domains) usingYamlDefaults.push("egress-allow");

  const egressBlockedDomains = options.egressBlock
    ? options.egressBlock.split(",").map((d) => d.trim()).filter(Boolean)
    : yamlDefaults.egress_blocked_domains;
  if (!options.egressBlock && yamlDefaults.egress_blocked_domains) usingYamlDefaults.push("egress-block");

  const maxCostPerSession = options.budget !== undefined
    ? parseFloat(options.budget)
    : yamlDefaults.max_cost_per_session;
  if (options.budget === undefined && yamlDefaults.max_cost_per_session !== undefined) usingYamlDefaults.push("budget");

  console.log("");
  console.log("  SentinelFlow Runtime Agent Firewall");
  console.log("  -----------------------------------");
  console.log("");
  console.log(`  Project:     ${projectDir}`);
  console.log(`  Framework:   ${framework}`);
  console.log(`  Mode:        ${mode}`);
  if (toolBlocklist) console.log(`  Blocklist:   ${toolBlocklist.join(", ")}`);
  if (toolAllowlist) console.log(`  Allowlist:   ${toolAllowlist.join(", ")}`);
  if (egressAllowedDomains) console.log(`  Egress allow: ${egressAllowedDomains.join(", ")}`);
  if (egressBlockedDomains) console.log(`  Egress block: ${egressBlockedDomains.join(", ")}`);
  if (maxCostPerSession !== undefined) {
    console.log(`  Budget:      $${maxCostPerSession.toFixed(2)}/session`);
    console.log("    Note: no supported framework exposes token/cost data in hook payloads yet,");
    console.log("    so this cannot block tool calls in real time. Use 'sentinelflow costs' to");
    console.log("    review spend after the fact instead.");
  }
  if (usingYamlDefaults.length > 0) {
    console.log(`  (from .sentinelflow-policy.yaml: ${usingYamlDefaults.join(", ")})`);
  }

  const dataBoundary = toDataBoundaryCodegenConfig(yamlDefaults.data_boundary);
  const identity = toIdentityCodegenConfig(yamlDefaults.identity);
  const sequenceDetection = toSequenceDetectionCodegenConfig(yamlDefaults.sequence_detection);
  if (dataBoundary || identity || sequenceDetection) {
    const advanced: string[] = [];
    if (dataBoundary) advanced.push(`data boundary (${dataBoundary.enforcementMode})`);
    if (identity) advanced.push(`identity/RBAC (${identity.enforcementMode})`);
    if (sequenceDetection) advanced.push(`sequence detection (${sequenceDetection.enforcementMode})`);
    console.log(`  Advanced:    ${advanced.join(", ")}`);
  } else {
    console.log("  Advanced:    data boundary, identity/RBAC, sequence detection (all enabled, monitor mode -- defaults)");
  }

  // Check existing installation
  const existing = isInstalled(projectDir);
  if (existing.installed && existing.framework === framework) {
    console.log(`\n  Reinstalling ${framework} hooks...`);
    if (framework === "claude-code") await ClaudeCodeInterceptor.uninstall(projectDir);
    else if (framework === "cursor") CursorInterceptor.uninstall(projectDir);
    else if (framework === "copilot") CopilotInterceptor.uninstall(projectDir);
    else CodexInterceptor.uninstall(projectDir);
  }

  // Install
  const commonConfig = {
    projectDir,
    enforcement_mode: mode,
    toolBlocklist,
    toolAllowlist,
    egressAllowedDomains,
    egressBlockedDomains,
    dataBoundary,
    identity,
    sequenceDetection,
    log_level: "silent" as const,
  };

  if (framework === "claude-code") {
    await new ClaudeCodeInterceptor(commonConfig).start();
    console.log("\n  Hooks installed:");
    console.log("    .claude/settings.local.json  (hooks config)");
    console.log("    .sentinelflow/handler.js      (event handler)");
  } else if (framework === "cursor") {
    await new CursorInterceptor(commonConfig).start();
    console.log("\n  Hooks installed:");
    console.log("    .cursor/hooks.json               (hooks config)");
    console.log("    .sentinelflow/cursor-handler.js   (event handler)");
  } else if (framework === "copilot") {
    await new CopilotInterceptor(commonConfig).start();
    console.log("\n  Hooks installed:");
    console.log("    .github/hooks/sentinelflow.json   (hooks config)");
    console.log("    .sentinelflow/copilot-handler.js  (event handler)");
  } else {
    await new CodexInterceptor(commonConfig).start();
    console.log("\n  Hooks installed:");
    console.log("    .codex/hooks.json                 (hooks config)");
    console.log("    .sentinelflow/codex-handler.js    (event handler)");
  }

  console.log("");
  console.log("  Events will be logged to:");
  console.log("    .sentinelflow/events.jsonl    (tail-able log)");
  console.log("    .sentinelflow/events.db       (SQLite, if available)");
  console.log("");
  if (mode === "monitor") console.log("  Monitor mode: All tool calls logged but never blocked.");
  else console.log("  Enforce mode: Tool calls violating policy will be BLOCKED.");
  console.log("");
}

// ─── Uninstall ──────────────────────────────────────────────────────

export async function interceptUninstallCommand(
  targetPath: string,
  options?: { framework?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const existing = isInstalled(projectDir);

  if (!existing.installed) { console.log("\n  No SentinelFlow hooks found.\n"); return; }

  const framework = options?.framework ? resolveFramework(projectDir, options.framework) : existing.framework!;

  if (framework === "claude-code") await ClaudeCodeInterceptor.uninstall(projectDir);
  else if (framework === "cursor") CursorInterceptor.uninstall(projectDir);
  else if (framework === "copilot") CopilotInterceptor.uninstall(projectDir);
  else CodexInterceptor.uninstall(projectDir);

  console.log(`\n  SentinelFlow ${framework} hooks removed.\n`);
}

// ─── Status ─────────────────────────────────────────────────────────

export async function interceptStatusCommand(targetPath: string): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const logPath = path.join(projectDir, ".sentinelflow", "events.jsonl");

  console.log("");
  console.log("  SentinelFlow Runtime Status");
  console.log("  --------------------------");
  console.log(`  Project:      ${projectDir}`);
  console.log(`  Claude Code:  ${ClaudeCodeInterceptor.isInstalled(projectDir) ? "installed" : "-"}`);
  console.log(`  Cursor:       ${CursorInterceptor.isInstalled(projectDir) ? "installed" : "-"}`);
  console.log(`  Copilot:      ${CopilotInterceptor.isInstalled(projectDir) ? "installed" : "-"}`);
  console.log(`  Codex:        ${CodexInterceptor.isInstalled(projectDir) ? "installed" : "-"}`);

  if (fs.existsSync(logPath)) {
    const lines = fs.readFileSync(logPath, "utf-8").trim().split("\n").filter(Boolean);
    const sizeKb = (fs.statSync(logPath).size / 1024).toFixed(1);
    let blocked = 0;
    const fwCounts: Record<string, number> = {};
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (e.outcome === "blocked") blocked++;
        fwCounts[e.framework] = (fwCounts[e.framework] || 0) + 1;
      } catch { continue; }
    }
    console.log(`  Events:       ${lines.length} (${sizeKb} KB)`);
    if (blocked > 0) console.log(`  Blocked:      ${blocked}`);
    for (const [fw, count] of Object.entries(fwCounts)) {
      console.log(`  ${fw}: ${count} events`);
    }
  } else {
    console.log("  Events:       no events yet");
  }
  console.log("");
}

// ─── Tail ───────────────────────────────────────────────────────────

export async function interceptTailCommand(
  targetPath: string,
  options: { lines?: string; follow?: boolean }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const logPath = path.join(projectDir, ".sentinelflow", "events.jsonl");

  if (!fs.existsSync(logPath)) {
    console.log("\n  No event log found. Install hooks first:\n    sentinelflow intercept install\n");
    process.exit(1);
  }

  const n = parseInt(options.lines ?? "20", 10);
  const lines = fs.readFileSync(logPath, "utf-8").trim().split("\n").filter(Boolean).slice(-n);

  console.log(`\n  SentinelFlow Event Log (last ${lines.length} events)\n  ${"-".repeat(50)}\n`);

  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      const time = new Date(e.timestamp).toLocaleTimeString();
      const fw = `[${(e.framework || "?").slice(0, 7)}]`;
      const type = e.event_type || e.type || "?";
      const outcome = e.outcome || "";
      const tool = e.tool_name || e.tool?.name || "";
      const reason = e.reason || e.governance?.reason || "";
      const marker = outcome === "blocked" ? "XX" : outcome === "error" ? "ER" : outcome === "allowed" ? "OK" : "..";
      const detail = tool ? ` ${tool}` : "";
      const reasonStr = reason ? ` -- ${reason.slice(0, 50)}` : "";
      console.log(`  ${time} ${marker} ${fw.padEnd(10)} ${type}${detail}${reasonStr}`);
    } catch { continue; }
  }

  console.log("");

  if (options.follow) {
    console.log("  Watching for new events... (Ctrl+C to stop)\n");
    let lastSize = fs.statSync(logPath).size;
    const interval = setInterval(() => {
      try {
        const sz = fs.statSync(logPath).size;
        if (sz > lastSize) {
          const content = fs.readFileSync(logPath, "utf-8");
          const all = content.trim().split("\n").filter(Boolean);
          for (const nl of all.slice(-3)) {
            try {
              const e = JSON.parse(nl);
              console.log(`  ${new Date(e.timestamp).toLocaleTimeString()} [${e.framework}] ${e.event_type} ${e.tool_name || ""}`);
            } catch {}
          }
          lastSize = sz;
        }
      } catch { clearInterval(interval); }
    }, 1000);
    process.on("SIGINT", () => { clearInterval(interval); console.log("\n  Stopped.\n"); process.exit(0); });
    await new Promise(() => {});
  }
}
