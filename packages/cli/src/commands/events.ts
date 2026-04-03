/**
 * sentinelflow events — Query the governance event store (SQLite).
 *
 * Usage:
 *   sentinelflow events tail [path]              Show recent events
 *   sentinelflow events blocked [path]           Show blocked tool calls
 *   sentinelflow events stats [path]             Show event store statistics
 *
 * Options:
 *   --since <duration>    Time window: 1h, 24h, 7d, 30d (default: 24h)
 *   --agent <id>          Filter by agent ID
 *   --tool <name>         Filter by tool name
 *   --limit <n>           Maximum events to show (default: 50)
 *   --format <fmt>        Output format: table, json (default: table)
 *
 * The event store is a SQLite database at .sentinelflow/events.db
 * populated by the runtime hook handler during Claude Code sessions.
 */

import * as path from "path";
import * as fs from "fs";
import { EventStoreReader } from "@sentinelflow/core";

// ─── Duration parser ────────────────────────────────────────────────

function parseDuration(input: string): Date {
  const match = input.match(/^(\d+)(h|d|m|w)$/);
  if (!match) {
    throw new Error(
      `Invalid duration "${input}". Use format: 1h, 24h, 7d, 30d, 4w`
    );
  }
  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const now = new Date();

  switch (unit) {
    case "m":
      now.setMinutes(now.getMinutes() - value);
      break;
    case "h":
      now.setHours(now.getHours() - value);
      break;
    case "d":
      now.setDate(now.getDate() - value);
      break;
    case "w":
      now.setDate(now.getDate() - value * 7);
      break;
  }
  return now;
}

// ─── Table formatter ────────────────────────────────────────────────

function padRight(str: string, len: number): string {
  return str.length >= len ? str.slice(0, len) : str + " ".repeat(len - str.length);
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso.slice(0, 19);
  }
}

function outcomeIcon(outcome: string): string {
  switch (outcome) {
    case "allowed": return "✅";
    case "blocked": return "🚫";
    case "flagged": return "⚠️ ";
    case "error":   return "❌";
    case "info":    return "ℹ️ ";
    default:        return "  ";
  }
}

// ─── Commands ───────────────────────────────────────────────────────

export async function eventsTailCommand(
  targetPath: string,
  options: {
    since?: string;
    agent?: string;
    tool?: string;
    limit?: string;
    format?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const dbPath = path.join(projectDir, ".sentinelflow", "events.db");

  if (!fs.existsSync(dbPath)) {
    console.log("\n  No event store found. Install hooks and run a Claude Code session first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  const reader = new EventStoreReader({ projectDir });
  const since = parseDuration(options.since ?? "24h");
  const limit = parseInt(options.limit ?? "50", 10);
  const format = options.format ?? "table";

  const events = reader.getEvents({
    agent_id: options.agent,
    tool_name: options.tool,
    time_range: { since: since.toISOString() },
    limit,
  });

  if (format === "json") {
    console.log(JSON.stringify(events, null, 2));
    reader.close();
    return;
  }

  if (events.length === 0) {
    console.log(`\n  No events found in the last ${options.since ?? "24h"}.`);
    console.log("  Make sure hooks are installed and a Claude Code session has been run.\n");
    reader.close();
    return;
  }

  console.log("");
  console.log(`  SentinelFlow Events (last ${options.since ?? "24h"}, ${events.length} shown)`);
  console.log("  " + "─".repeat(80));
  console.log("");

  // Column headers
  console.log(
    `  ${padRight("TIMESTAMP", 20)} ${padRight("", 3)} ${padRight("TYPE", 22)} ${padRight("TOOL", 12)} ${padRight("REASON", 30)}`
  );
  console.log("  " + "─".repeat(90));

  for (const evt of events) {
    const ts = formatTimestamp(evt.timestamp);
    const icon = outcomeIcon(evt.outcome);
    const type = evt.event_type;
    const tool = evt.tool_name ?? "";
    const reason = evt.reason ?? "";

    console.log(
      `  ${padRight(ts, 20)} ${icon} ${padRight(type, 22)} ${padRight(tool, 12)} ${reason.slice(0, 40)}`
    );
  }

  console.log("");
  reader.close();
}

export async function eventsBlockedCommand(
  targetPath: string,
  options: {
    since?: string;
    agent?: string;
    limit?: string;
    format?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const dbPath = path.join(projectDir, ".sentinelflow", "events.db");

  if (!fs.existsSync(dbPath)) {
    console.log("\n  No event store found.\n");
    process.exit(1);
  }

  const reader = new EventStoreReader({ projectDir });
  const since = parseDuration(options.since ?? "7d");
  const limit = parseInt(options.limit ?? "50", 10);
  const format = options.format ?? "table";

  const events = reader.getBlockedToolCalls(since.toISOString(), options.agent, limit);

  if (format === "json") {
    console.log(JSON.stringify(events, null, 2));
    reader.close();
    return;
  }

  if (events.length === 0) {
    console.log(`\n  No blocked tool calls in the last ${options.since ?? "7d"}. 🎉\n`);
    reader.close();
    return;
  }

  console.log("");
  console.log(`  SentinelFlow Blocked Tool Calls (${events.length} found)`);
  console.log("  " + "─".repeat(80));
  console.log("");

  for (const evt of events) {
    const ts = formatTimestamp(evt.timestamp);
    console.log(`  🚫  ${ts}  ${evt.tool_name ?? "unknown"}`);
    console.log(`      Agent:   ${evt.agent_id}`);
    console.log(`      Policy:  ${evt.policy_id ?? "—"}`);
    console.log(`      Reason:  ${evt.reason ?? "—"}`);
    if (evt.action) {
      console.log(`      Action:  ${evt.action.slice(0, 80)}`);
    }
    console.log("");
  }

  reader.close();
}

export async function eventsStatsCommand(
  targetPath: string,
  options: { format?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const dbPath = path.join(projectDir, ".sentinelflow", "events.db");

  if (!fs.existsSync(dbPath)) {
    console.log("\n  No event store found.\n");
    process.exit(1);
  }

  // Use the writer's getStats for basic counts (open read-only via reader)
  const reader = new EventStoreReader({ projectDir });

  const total = reader.countEvents();
  const blocked = reader.countEvents({ outcome: "blocked" as any });
  const errors = reader.countEvents({ outcome: "error" as any });
  const agents = reader.getActiveAgents(30);

  if (options.format === "json") {
    console.log(JSON.stringify({ total, blocked, errors, agents }, null, 2));
    reader.close();
    return;
  }

  const dbStats = fs.statSync(dbPath);
  const sizeKb = (dbStats.size / 1024).toFixed(1);

  console.log("");
  console.log("  SentinelFlow Event Store");
  console.log("  " + "─".repeat(40));
  console.log("");
  console.log(`  Database:      ${dbPath}`);
  console.log(`  Size:          ${sizeKb} KB`);
  console.log(`  Total events:  ${total}`);
  console.log(`  Blocked:       ${blocked}`);
  console.log(`  Errors:        ${errors}`);
  console.log(`  Active agents: ${agents.length}`);
  console.log("");

  if (agents.length > 0) {
    console.log("  Agents (last 30 days):");
    console.log("  " + "─".repeat(60));
    for (const agent of agents) {
      console.log(
        `    ${agent.agent_id} (${agent.framework})  —  ` +
        `${agent.total_events} events, ${agent.total_blocked} blocked, ` +
        `$${agent.total_cost_usd.toFixed(4)} cost`
      );
    }
    console.log("");
  }

  reader.close();
}
