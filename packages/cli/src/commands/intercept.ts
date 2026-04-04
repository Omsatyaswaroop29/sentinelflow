/**
 * sentinelflow intercept — Runtime agent firewall commands.
 *
 * Supports multiple frameworks:
 *   - Claude Code: hooks in .claude/settings.local.json
 *   - Cursor:      hooks in .cursor/hooks.json
 *
 * Auto-detects the framework from the project directory, or use --framework.
 *
 * Usage:
 *   sentinelflow intercept install [path]    Install runtime hooks
 *   sentinelflow intercept uninstall [path]  Remove runtime hooks
 *   sentinelflow intercept status [path]     Check hook status
 *   sentinelflow intercept tail [path]       View recent events
 */

import * as path from "path";
import * as fs from "fs";
import { ClaudeCodeInterceptor, CursorInterceptor } from "@sentinelflow/interceptors";

// ─── Framework Detection ────────────────────────────────────────────

type Framework = "claude-code" | "cursor";

/**
 * Auto-detect which AI coding framework is present in the project.
 * Checks for characteristic directories and config files.
 * If both are present, returns both so the user can choose.
 */
function detectFrameworks(projectDir: string): Framework[] {
  const found: Framework[] = [];

  // Claude Code markers
  const claudeDir = path.join(projectDir, ".claude");
  if (fs.existsSync(claudeDir)) {
    found.push("claude-code");
  }

  // Cursor markers
  const cursorDir = path.join(projectDir, ".cursor");
  if (fs.existsSync(cursorDir)) {
    found.push("cursor");
  }

  return found;
}

/**
 * Resolve which framework to use based on explicit flag or auto-detection.
 */
function resolveFramework(projectDir: string, explicit?: string): Framework {
  if (explicit) {
    const normalized = explicit.toLowerCase().replace(/\s+/g, "-");
    if (normalized === "claude-code" || normalized === "claude" || normalized === "cc") {
      return "claude-code";
    }
    if (normalized === "cursor") {
      return "cursor";
    }
    console.error(`\n  Unknown framework: "${explicit}"`);
    console.error(`  Supported: claude-code, cursor\n`);
    process.exit(1);
  }

  const detected = detectFrameworks(projectDir);

  if (detected.length === 0) {
    // No framework detected — create .cursor by default since hooks.json
    // is self-contained, or let the user specify
    console.log("\n  No .claude/ or .cursor/ directory found.");
    console.log("  Use --framework to specify: claude-code or cursor\n");
    process.exit(1);
  }

  if (detected.length === 1) {
    return detected[0]!;
  }

  // Both detected — prefer Claude Code if hooks are already installed there
  if (ClaudeCodeInterceptor.isInstalled(projectDir)) {
    return "claude-code";
  }
  if (CursorInterceptor.isInstalled(projectDir)) {
    return "cursor";
  }

  // Both exist, neither has hooks — ask user
  console.log("\n  Multiple frameworks detected: Claude Code and Cursor.");
  console.log("  Use --framework to specify which one:");
  console.log("    sentinelflow intercept install --framework claude-code");
  console.log("    sentinelflow intercept install --framework cursor\n");
  process.exit(1);
}

function isInstalled(projectDir: string): { installed: boolean; framework?: Framework } {
  if (ClaudeCodeInterceptor.isInstalled(projectDir)) {
    return { installed: true, framework: "claude-code" };
  }
  if (CursorInterceptor.isInstalled(projectDir)) {
    return { installed: true, framework: "cursor" };
  }
  return { installed: false };
}

// ─── Install Command ────────────────────────────────────────────────

export async function interceptInstallCommand(
  targetPath: string,
  options: {
    mode?: string;
    blocklist?: string;
    allowlist?: string;
    budget?: string;
    framework?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  if (!fs.existsSync(projectDir)) {
    console.error(`\n  Error: Directory not found: ${projectDir}\n`);
    process.exit(1);
  }

  const framework = resolveFramework(projectDir, options.framework);
  const mode = (options.mode ?? "monitor") as "monitor" | "enforce";

  const toolBlocklist = options.blocklist
    ? options.blocklist.split(",").map((t) => t.trim())
    : undefined;
  const toolAllowlist = options.allowlist
    ? options.allowlist.split(",").map((t) => t.trim())
    : undefined;

  console.log("");
  console.log("  SentinelFlow Runtime Agent Firewall");
  console.log("  -----------------------------------");
  console.log("");
  console.log(`  Project:     ${projectDir}`);
  console.log(`  Framework:   ${framework}`);
  console.log(`  Mode:        ${mode}`);

  if (toolBlocklist) {
    console.log(`  Blocklist:   ${toolBlocklist.join(", ")}`);
  }
  if (toolAllowlist) {
    console.log(`  Allowlist:   ${toolAllowlist.join(", ")}`);
  }

  // Check if already installed (possibly for a different framework)
  const existing = isInstalled(projectDir);
  if (existing.installed) {
    if (existing.framework !== framework) {
      console.log("");
      console.log(`  Note: ${existing.framework} hooks already installed. Adding ${framework} hooks alongside.`);
    } else {
      console.log("");
      console.log(`  Reinstalling ${framework} hooks...`);
      if (framework === "claude-code") {
        await ClaudeCodeInterceptor.uninstall(projectDir);
      } else {
        CursorInterceptor.uninstall(projectDir);
      }
    }
  }

  // Install the appropriate interceptor
  if (framework === "claude-code") {
    const interceptor = new ClaudeCodeInterceptor({
      projectDir,
      enforcement_mode: mode,
      toolBlocklist,
      toolAllowlist,
      log_level: "silent",
    });
    await interceptor.start();

    console.log("");
    console.log("  Hooks installed:");
    console.log(`    .claude/settings.local.json  (hooks config)`);
    console.log(`    .sentinelflow/handler.js      (event handler)`);
  } else {
    const interceptor = new CursorInterceptor({
      projectDir,
      enforcement_mode: mode,
      toolBlocklist,
      toolAllowlist,
      log_level: "silent",
    });
    await interceptor.start();

    console.log("");
    console.log("  Hooks installed:");
    console.log(`    .cursor/hooks.json               (hooks config)`);
    console.log(`    .sentinelflow/cursor-handler.js   (event handler)`);
  }

  console.log("");
  console.log("  Events will be logged to:");
  console.log(`    .sentinelflow/events.jsonl    (tail-able log)`);
  console.log(`    .sentinelflow/events.db       (SQLite, if available)`);
  console.log("");

  if (mode === "monitor") {
    console.log("  Monitor mode: All tool calls are logged but never blocked.");
    console.log("     Review events with: sentinelflow events tail");
  } else {
    console.log("  Enforce mode: Tool calls violating policy will be BLOCKED.");
  }

  console.log("");
}

// ─── Uninstall Command ──────────────────────────────────────────────

export async function interceptUninstallCommand(
  targetPath: string,
  options?: { framework?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const existing = isInstalled(projectDir);

  if (!existing.installed) {
    console.log("\n  No SentinelFlow hooks found in this project.\n");
    return;
  }

  const framework = options?.framework
    ? resolveFramework(projectDir, options.framework)
    : existing.framework!;

  if (framework === "claude-code") {
    await ClaudeCodeInterceptor.uninstall(projectDir);
  } else {
    CursorInterceptor.uninstall(projectDir);
  }

  console.log("");
  console.log(`  SentinelFlow ${framework} hooks removed.`);
  console.log("    Event log preserved at .sentinelflow/events.jsonl");
  console.log("");
}

// ─── Status Command ─────────────────────────────────────────────────

export async function interceptStatusCommand(
  targetPath: string
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  const ccInstalled = ClaudeCodeInterceptor.isInstalled(projectDir);
  const cursorInstalled = CursorInterceptor.isInstalled(projectDir);
  const eventLogPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  const hasEventLog = fs.existsSync(eventLogPath);

  console.log("");
  console.log("  SentinelFlow Runtime Status");
  console.log("  --------------------------");
  console.log("");
  console.log(`  Project:          ${projectDir}`);
  console.log(`  Claude Code:      ${ccInstalled ? "installed" : "not installed"}`);
  console.log(`  Cursor:           ${cursorInstalled ? "installed" : "not installed"}`);
  console.log(`  Event log:        ${hasEventLog ? "present" : "no events yet"}`);

  if (hasEventLog) {
    try {
      const stats = fs.statSync(eventLogPath);
      const lines = fs.readFileSync(eventLogPath, "utf-8").trim().split("\n").filter(Boolean);
      const sizeKb = (stats.size / 1024).toFixed(1);
      console.log(`  Events:           ${lines.length} events (${sizeKb} KB)`);

      // Count by framework
      let ccEvents = 0;
      let cursorEvents = 0;
      let blocked = 0;
      for (const line of lines) {
        try {
          const e = JSON.parse(line);
          if (e.framework === "claude_code") ccEvents++;
          if (e.framework === "cursor") cursorEvents++;
          if (e.outcome === "blocked") blocked++;
        } catch { continue; }
      }
      if (ccEvents > 0) console.log(`  Claude Code:      ${ccEvents} events`);
      if (cursorEvents > 0) console.log(`  Cursor:           ${cursorEvents} events`);
      if (blocked > 0) console.log(`  Blocked calls:    ${blocked}`);
    } catch { /* skip */ }
  }

  console.log("");
}

// ─── Tail Command ───────────────────────────────────────────────────

export async function interceptTailCommand(
  targetPath: string,
  options: { lines?: string; follow?: boolean }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const eventLogPath = path.join(projectDir, ".sentinelflow", "events.jsonl");

  if (!fs.existsSync(eventLogPath)) {
    console.log("\n  No event log found. Install hooks first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  const numLines = parseInt(options.lines ?? "20", 10);
  const lines = fs.readFileSync(eventLogPath, "utf-8").trim().split("\n").filter(Boolean).slice(-numLines);

  console.log("");
  console.log(`  SentinelFlow Event Log (last ${lines.length} events)`);
  console.log("  " + "-".repeat(50));
  console.log("");

  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      const time = new Date(event.timestamp).toLocaleTimeString();
      const fw = (event.framework === "cursor") ? "[cursor]" : "[claude]";
      const type = event.event_type || event.type || "unknown";
      const outcome = event.outcome || "";
      const tool = event.tool_name || event.tool?.name || "";
      const reason = event.reason || event.governance?.reason || "";

      let marker = "  ";
      if (outcome === "blocked") marker = "XX";
      else if (outcome === "error") marker = "ER";
      else if (outcome === "allowed") marker = "OK";
      else marker = "..";

      const detail = tool ? ` ${tool}` : "";
      const reasonStr = reason ? ` — ${reason.slice(0, 50)}` : "";

      console.log(`  ${time} ${marker} ${fw} ${type}${detail}${reasonStr}`);
    } catch { continue; }
  }

  console.log("");

  if (options.follow) {
    console.log("  Watching for new events... (Ctrl+C to stop)\n");
    let lastSize = fs.statSync(eventLogPath).size;
    const interval = setInterval(() => {
      try {
        const currentSize = fs.statSync(eventLogPath).size;
        if (currentSize > lastSize) {
          const content = fs.readFileSync(eventLogPath, "utf-8");
          const allLines = content.trim().split("\n").filter(Boolean);
          const newLines = allLines.slice(-Math.max(1, allLines.length - lines.length));
          for (const newLine of newLines) {
            try {
              const event = JSON.parse(newLine);
              const time = new Date(event.timestamp).toLocaleTimeString();
              const fw = event.framework === "cursor" ? "[cursor]" : "[claude]";
              console.log(`  ${time} ${fw} ${event.event_type || event.type} ${event.tool_name || ""}`);
            } catch { /* skip */ }
          }
          lastSize = currentSize;
        }
      } catch { clearInterval(interval); }
    }, 1000);

    process.on("SIGINT", () => {
      clearInterval(interval);
      console.log("\n  Stopped.\n");
      process.exit(0);
    });
    await new Promise(() => {});
  }
}
