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
import { ClaudeCodeInterceptor, CursorInterceptor, CopilotInterceptor, CodexInterceptor } from "@sentinelflow/interceptors";

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

export async function interceptInstallCommand(
  targetPath: string,
  options: { mode?: string; blocklist?: string; allowlist?: string; budget?: string; framework?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  if (!fs.existsSync(projectDir)) { console.error(`\n  Error: Directory not found: ${projectDir}\n`); process.exit(1); }

  const framework = resolveFramework(projectDir, options.framework);
  const mode = (options.mode ?? "monitor") as "monitor" | "enforce";
  const toolBlocklist = options.blocklist ? options.blocklist.split(",").map((t) => t.trim()) : undefined;
  const toolAllowlist = options.allowlist ? options.allowlist.split(",").map((t) => t.trim()) : undefined;

  console.log("");
  console.log("  SentinelFlow Runtime Agent Firewall");
  console.log("  -----------------------------------");
  console.log("");
  console.log(`  Project:     ${projectDir}`);
  console.log(`  Framework:   ${framework}`);
  console.log(`  Mode:        ${mode}`);
  if (toolBlocklist) console.log(`  Blocklist:   ${toolBlocklist.join(", ")}`);
  if (toolAllowlist) console.log(`  Allowlist:   ${toolAllowlist.join(", ")}`);

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
  const commonConfig = { projectDir, enforcement_mode: mode, toolBlocklist, toolAllowlist, log_level: "silent" as const };

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
