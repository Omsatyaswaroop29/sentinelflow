/**
 * sentinelflow intercept — Runtime agent firewall commands.
 *
 * Usage:
 *   sentinelflow intercept install [path]   Install runtime hooks into a project
 *   sentinelflow intercept uninstall [path]  Remove runtime hooks
 *   sentinelflow intercept status [path]    Check if hooks are installed
 *   sentinelflow intercept tail [path]      Live-tail the event log
 *
 * The install command generates:
 *   hooks/hooks.json              — Claude Code hook config
 *   hooks/sentinelflow-handler.js — Event handler script
 *   .sentinelflow/events.jsonl    — Runtime event log (created on first event)
 *
 * Enforcement modes:
 *   --mode monitor  (default) Log everything, block nothing. Start here.
 *   --mode enforce  Actually block tool calls that violate policy.
 */

import * as path from "path";
import * as fs from "fs";
import { ClaudeCodeInterceptor } from "@sentinelflow/interceptors";

export async function interceptInstallCommand(
  targetPath: string,
  options: {
    mode?: string;
    blocklist?: string;
    allowlist?: string;
    budget?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  if (!fs.existsSync(projectDir)) {
    console.error(`\n  ❌ Directory not found: ${projectDir}\n`);
    process.exit(1);
  }

  const mode = (options.mode ?? "monitor") as "monitor" | "enforce";

  // Parse tool lists
  const toolBlocklist = options.blocklist
    ? options.blocklist.split(",").map((t) => t.trim())
    : undefined;
  const toolAllowlist = options.allowlist
    ? options.allowlist.split(",").map((t) => t.trim())
    : undefined;

  console.log("");
  console.log("  SentinelFlow Runtime Agent Firewall");
  console.log("  ───────────────────────────────────");
  console.log("");
  console.log(`  Project:     ${projectDir}`);
  console.log(`  Mode:        ${mode}`);

  if (toolBlocklist) {
    console.log(`  Blocklist:   ${toolBlocklist.join(", ")}`);
  }
  if (toolAllowlist) {
    console.log(`  Allowlist:   ${toolAllowlist.join(", ")}`);
  }
  if (options.budget) {
    console.log(`  Budget:      $${options.budget}/session`);
  }

  // Check if already installed
  if (ClaudeCodeInterceptor.isInstalled(projectDir)) {
    console.log("");
    console.log("  ⚠️  Hooks already installed. Reinstalling...");
    await ClaudeCodeInterceptor.uninstall(projectDir);
  }

  // Install the interceptor
  const interceptor = new ClaudeCodeInterceptor({
    projectDir,
    enforcement_mode: mode,
    toolBlocklist,
    toolAllowlist,
    log_level: "silent", // Don't spam the terminal during install
  });

  await interceptor.start();
  // NOTE: Do NOT call interceptor.stop() here.
  // start() creates the persistent hook files (.claude/settings.local.json + .sentinelflow/handler.js).
  // stop() would delete them via unhookFramework(). The hooks are files that persist
  // on disk — they don't need a running process. Claude Code reads them directly.

  console.log("");
  console.log("  ✓ Hooks installed:");
  console.log(`    .claude/settings.local.json  (hooks config)`);
  console.log(`    .sentinelflow/handler.js      (event handler)`);
  console.log("");
  console.log("  Events will be logged to:");
  console.log(`    .sentinelflow/events.jsonl    (tail-able log)`);
  console.log(`    .sentinelflow/events.db       (SQLite, if available)`);
  console.log("");

  if (mode === "monitor") {
    console.log("  📊 Monitor mode: All tool calls are logged but never blocked.");
    console.log("     Review events with: sentinelflow intercept tail");
    console.log("     Switch to enforce:  sentinelflow intercept install --mode enforce");
  } else {
    console.log("  🛡️  Enforce mode: Tool calls violating policy will be BLOCKED.");
    console.log("     Make sure your allowlist/blocklist is correct before using.");
  }

  console.log("");
}

export async function interceptUninstallCommand(
  targetPath: string
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  if (!ClaudeCodeInterceptor.isInstalled(projectDir)) {
    console.log("\n  ℹ️  No SentinelFlow hooks found in this project.\n");
    return;
  }

  await ClaudeCodeInterceptor.uninstall(projectDir);

  console.log("");
  console.log("  ✓ SentinelFlow hooks removed.");
  console.log("    Event log preserved at .sentinelflow/events.jsonl");
  console.log("    Event database preserved at .sentinelflow/events.db");
  console.log("");
}

export async function interceptStatusCommand(
  targetPath: string
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  const installed = ClaudeCodeInterceptor.isInstalled(projectDir);
  const eventLogPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  const hasEventLog = fs.existsSync(eventLogPath);

  console.log("");
  console.log("  SentinelFlow Runtime Status");
  console.log("  ──────────────────────────");
  console.log("");
  console.log(`  Project:       ${projectDir}`);
  console.log(`  Hooks:         ${installed ? "✓ Installed" : "✗ Not installed"}`);
  console.log(`  Event log:     ${hasEventLog ? "✓ Present" : "✗ No events yet"}`);

  if (hasEventLog) {
    const stats = fs.statSync(eventLogPath);
    const lineCount = fs
      .readFileSync(eventLogPath, "utf-8")
      .split("\n")
      .filter(Boolean).length;
    const sizeKb = (stats.size / 1024).toFixed(1);
    console.log(`  Events:        ${lineCount} events (${sizeKb} KB)`);

    // Parse last event for timestamp
    const lines = fs
      .readFileSync(eventLogPath, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean);
    if (lines.length > 0) {
      try {
        const lastLine = lines[lines.length - 1];
        const lastEvent = JSON.parse(lastLine!);
        console.log(`  Last event:    ${lastEvent.timestamp}`);
        console.log(`  Last type:     ${lastEvent.type}`);
      } catch {
        // Skip if can't parse
      }
    }

    // Count blocked events
    let blocked = 0;
    let errors = 0;
    for (const line of lines) {
      try {
        const event = JSON.parse(line);
        if (event.type === "tool_call_blocked") blocked++;
        if (event.tool?.status === "error") errors++;
      } catch {
        continue;
      }
    }
    if (blocked > 0) {
      console.log(`  Blocked calls: ${blocked}`);
    }
    if (errors > 0) {
      console.log(`  Tool errors:   ${errors}`);
    }
  }

  console.log("");
}

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
  const lines = fs
    .readFileSync(eventLogPath, "utf-8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .slice(-numLines);

  console.log("");
  console.log(`  SentinelFlow Event Log (last ${lines.length} events)`);
  console.log("  ─────────────────────────────────────────────");
  console.log("");

  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      const time = new Date(event.timestamp).toLocaleTimeString();
      const type = event.type;

      let icon = "📝";
      switch (type) {
        case "session_start":
          icon = "🟢";
          break;
        case "session_end":
          icon = "🔴";
          break;
        case "tool_call_start":
          icon = "🔧";
          break;
        case "tool_call_end":
          icon = event.tool?.status === "error" ? "❌" : "✅";
          break;
        case "tool_call_blocked":
          icon = "🚫";
          break;
      }

      let detail = "";
      if (event.tool?.name) {
        detail = ` ${event.tool.name}`;
        if (event.tool.input_summary) {
          detail += ` → ${event.tool.input_summary.slice(0, 60)}`;
        }
      }
      if (event.governance?.reason) {
        detail += ` (${event.governance.reason.slice(0, 60)})`;
      }

      console.log(`  ${time} ${icon} ${type}${detail}`);
    } catch {
      continue;
    }
  }

  console.log("");

  if (options.follow) {
    console.log("  Watching for new events... (Ctrl+C to stop)");
    console.log("");

    // Simple follow mode: poll the file every second
    let lastSize = fs.statSync(eventLogPath).size;
    const interval = setInterval(() => {
      try {
        const currentSize = fs.statSync(eventLogPath).size;
        if (currentSize > lastSize) {
          const content = fs.readFileSync(eventLogPath, "utf-8");
          const allLines = content.trim().split("\n").filter(Boolean);
          // Show new lines only
          const newLines = allLines.slice(-Math.max(1, allLines.length - lines.length));
          for (const newLine of newLines) {
            try {
              const event = JSON.parse(newLine);
              const time = new Date(event.timestamp).toLocaleTimeString();
              console.log(`  ${time} ${event.type} ${event.tool?.name ?? ""}`);
            } catch {
              // skip
            }
          }
          lastSize = currentSize;
        }
      } catch {
        clearInterval(interval);
      }
    }, 1000);

    // Keep process alive
    process.on("SIGINT", () => {
      clearInterval(interval);
      console.log("\n  Stopped.\n");
      process.exit(0);
    });

    // Block indefinitely
    await new Promise(() => {});
  }
}
