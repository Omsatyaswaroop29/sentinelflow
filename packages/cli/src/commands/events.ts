/**
 * sentinelflow events — Query the governance event store.
 *
 * Reads from SQLite (.sentinelflow/events.db) when available,
 * falls back to JSONL (.sentinelflow/events.jsonl) when SQLite isn't installed.
 */

import * as path from "path";
import * as fs from "fs";
import { EventStoreReader } from "@sentinelflow/core";

// ─── JSONL Fallback ─────────────────────────────────────────────────

function readJsonlEvents(projectDir: string): Array<Record<string, unknown>> {
  const jsonlPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  if (!fs.existsSync(jsonlPath)) return [];
  return fs.readFileSync(jsonlPath, "utf-8").trim().split("\n").filter(Boolean)
    .map((line) => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean) as Array<Record<string, unknown>>;
}

function hasDb(projectDir: string): boolean {
  return fs.existsSync(path.join(projectDir, ".sentinelflow", "events.db"));
}

function hasLog(projectDir: string): boolean {
  return fs.existsSync(path.join(projectDir, ".sentinelflow", "events.jsonl"));
}

function noStoreError(): never {
  console.log("\n  No event store found. Install hooks and run a Claude Code session first:");
  console.log("    sentinelflow intercept install\n");
  process.exit(1);
}

// ─── Helpers ────────────────────────────────────────────────────────

function parseDuration(input: string): Date {
  const match = input.match(/^(\d+)(h|d|m|w)$/);
  if (!match) throw new Error(`Invalid duration "${input}". Use: 1h, 24h, 7d, 30d`);
  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const now = new Date();
  switch (unit) {
    case "m": now.setMinutes(now.getMinutes() - value); break;
    case "h": now.setHours(now.getHours() - value); break;
    case "d": now.setDate(now.getDate() - value); break;
    case "w": now.setDate(now.getDate() - value * 7); break;
  }
  return now;
}

function pad(str: string, len: number): string {
  return str.length >= len ? str.slice(0, len) : str + " ".repeat(len - str.length);
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  } catch { return iso.slice(0, 19); }
}

function icon(outcome: string): string {
  switch (outcome) {
    case "allowed": return "OK";
    case "blocked": return "XX";
    case "flagged": return "!!";
    case "error":   return "ER";
    case "info":    return "..";
    default:        return "  ";
  }
}

// ─── Commands ───────────────────────────────────────────────────────

export async function eventsTailCommand(
  targetPath: string,
  options: { since?: string; agent?: string; tool?: string; limit?: string; format?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  if (!hasDb(projectDir) && !hasLog(projectDir)) noStoreError();

  const since = parseDuration(options.since ?? "24h");
  const limit = parseInt(options.limit ?? "50", 10);
  const fmt = options.format ?? "table";

  let events: Array<Record<string, unknown>>;

  if (hasDb(projectDir)) {
    const reader = new EventStoreReader({ projectDir });
    events = reader.getEvents({
      agent_id: options.agent, tool_name: options.tool,
      time_range: { since: since.toISOString() }, limit,
    }) as unknown as Array<Record<string, unknown>>;
    reader.close();
  } else {
    const sinceTs = since.toISOString();
    events = readJsonlEvents(projectDir)
      .filter((e) => {
        if (((e.timestamp as string) ?? "") < sinceTs) return false;
        if (options.agent && e.agent_id !== options.agent) return false;
        if (options.tool && e.tool_name !== options.tool) return false;
        return true;
      })
      .slice(-limit).reverse();
  }

  if (fmt === "json") { console.log(JSON.stringify(events, null, 2)); return; }

  if (events.length === 0) {
    console.log(`\n  No events found in the last ${options.since ?? "24h"}.\n`);
    return;
  }

  console.log("");
  console.log(`  SentinelFlow Events (last ${options.since ?? "24h"}, ${events.length} shown)`);
  console.log("  " + "-".repeat(80));
  console.log(`  ${pad("TIMESTAMP", 20)} ${pad("", 3)} ${pad("TYPE", 22)} ${pad("TOOL", 12)} ${pad("REASON", 30)}`);
  console.log("  " + "-".repeat(90));

  for (const evt of events) {
    const ts = fmtTime((evt.timestamp as string) ?? "");
    const ic = icon((evt.outcome as string) ?? "");
    const type = (evt.event_type as string) ?? "";
    const tool = (evt.tool_name as string) ?? "";
    const reason = (evt.reason as string) ?? "";
    console.log(`  ${pad(ts, 20)} ${ic} ${pad(type, 22)} ${pad(tool, 12)} ${reason.slice(0, 40)}`);
  }
  console.log("");
}

export async function eventsBlockedCommand(
  targetPath: string,
  options: { since?: string; agent?: string; limit?: string; format?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  if (!hasDb(projectDir) && !hasLog(projectDir)) noStoreError();

  const since = parseDuration(options.since ?? "7d");
  const limit = parseInt(options.limit ?? "50", 10);
  const fmt = options.format ?? "table";

  let events: Array<Record<string, unknown>>;

  if (hasDb(projectDir)) {
    const reader = new EventStoreReader({ projectDir });
    events = reader.getBlockedToolCalls(since.toISOString(), options.agent, limit) as unknown as Array<Record<string, unknown>>;
    reader.close();
  } else {
    const sinceTs = since.toISOString();
    events = readJsonlEvents(projectDir)
      .filter((e) => {
        if ((e.outcome as string) !== "blocked") return false;
        if (((e.timestamp as string) ?? "") < sinceTs) return false;
        if (options.agent && e.agent_id !== options.agent) return false;
        return true;
      })
      .slice(-limit).reverse();
  }

  if (fmt === "json") { console.log(JSON.stringify(events, null, 2)); return; }

  if (events.length === 0) {
    console.log(`\n  No blocked tool calls in the last ${options.since ?? "7d"}.\n`);
    return;
  }

  console.log("");
  console.log(`  SentinelFlow Blocked Tool Calls (${events.length} found)`);
  console.log("  " + "-".repeat(80));
  console.log("");

  for (const evt of events) {
    const ts = fmtTime((evt.timestamp as string) ?? "");
    console.log(`  BLOCKED  ${ts}  ${(evt.tool_name as string) ?? "unknown"}`);
    console.log(`      Agent:   ${(evt.agent_id as string) ?? "-"}`);
    console.log(`      Policy:  ${(evt.policy_id as string) ?? "-"}`);
    console.log(`      Reason:  ${(evt.reason as string) ?? "-"}`);
    if (evt.action) console.log(`      Action:  ${(evt.action as string).slice(0, 80)}`);
    console.log("");
  }
}

export async function eventsStatsCommand(
  targetPath: string,
  options: { format?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  if (!hasDb(projectDir) && !hasLog(projectDir)) noStoreError();

  let total = 0, blocked = 0, errors = 0;
  let agents: Array<{ agent_id: string; framework: string; total_events: number; total_blocked: number; total_cost_usd: number }> = [];
  let sizeKb = "0";
  let storePath = "";

  if (hasDb(projectDir)) {
    const reader = new EventStoreReader({ projectDir });
    total = reader.countEvents();
    blocked = reader.countEvents({ outcome: "blocked" as any });
    errors = reader.countEvents({ outcome: "error" as any });
    agents = reader.getActiveAgents(30) as any;
    reader.close();
    const dbPath = path.join(projectDir, ".sentinelflow", "events.db");
    sizeKb = (fs.statSync(dbPath).size / 1024).toFixed(1);
    storePath = dbPath;
  } else {
    const all = readJsonlEvents(projectDir);
    total = all.length;
    blocked = all.filter((e) => e.outcome === "blocked").length;
    errors = all.filter((e) => e.outcome === "error").length;
    const logPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
    sizeKb = (fs.statSync(logPath).size / 1024).toFixed(1);
    storePath = logPath + " (JSONL mode)";

    const agentMap = new Map<string, { framework: string; events: number; blocked: number; cost: number }>();
    for (const e of all) {
      const aid = (e.agent_id as string) ?? "unknown";
      if (!agentMap.has(aid)) agentMap.set(aid, { framework: (e.framework as string) ?? "unknown", events: 0, blocked: 0, cost: 0 });
      const a = agentMap.get(aid)!;
      a.events++;
      if (e.outcome === "blocked") a.blocked++;
      if (typeof e.cost_usd === "number") a.cost += e.cost_usd;
    }
    agents = [...agentMap.entries()].map(([id, a]) => ({
      agent_id: id, framework: a.framework, total_events: a.events, total_blocked: a.blocked, total_cost_usd: a.cost,
    }));
  }

  if (options.format === "json") { console.log(JSON.stringify({ total, blocked, errors, agents }, null, 2)); return; }

  console.log("");
  console.log("  SentinelFlow Event Store");
  console.log("  " + "-".repeat(40));
  console.log("");
  console.log(`  Store:         ${storePath}`);
  console.log(`  Size:          ${sizeKb} KB`);
  console.log(`  Total events:  ${total}`);
  console.log(`  Blocked:       ${blocked}`);
  console.log(`  Errors:        ${errors}`);
  console.log(`  Active agents: ${agents.length}`);
  console.log("");

  if (agents.length > 0) {
    console.log("  Agents:");
    console.log("  " + "-".repeat(60));
    for (const a of agents) {
      console.log(`    ${a.agent_id} (${a.framework}) -- ${a.total_events} events, ${a.total_blocked} blocked, $${a.total_cost_usd.toFixed(4)} cost`);
    }
    console.log("");
  }
}
