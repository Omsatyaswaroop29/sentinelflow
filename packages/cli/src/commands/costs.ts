/**
 * sentinelflow costs — Token spend and cost reporting from the event store.
 *
 * Usage:
 *   sentinelflow costs [path]
 *
 * Options:
 *   --window <duration>   Time window: 1d, 7d, 30d (default: 7d)
 *   --agent <id>          Filter by agent ID
 *   --format <fmt>        Output format: table, json (default: table)
 *
 * Reads from the daily_rollups table in the SQLite event store for
 * fast aggregation without scanning the full events table.
 */

import * as path from "path";
import * as fs from "fs";
import { EventStoreReader } from "@sentinelflow/core";

function parseDuration(input: string): string {
  const match = input.match(/^(\d+)(d|w)$/);
  if (!match) {
    throw new Error(`Invalid window "${input}". Use format: 1d, 7d, 30d, 4w`);
  }
  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const now = new Date();
  if (unit === "w") {
    now.setDate(now.getDate() - value * 7);
  } else {
    now.setDate(now.getDate() - value);
  }
  return now.toISOString().split("T")[0]!;
}

function padRight(str: string, len: number): string {
  return str.length >= len ? str.slice(0, len) : str + " ".repeat(len - str.length);
}

export async function costsCommand(
  targetPath: string,
  options: {
    window?: string;
    agent?: string;
    format?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const dbPath = path.join(projectDir, ".sentinelflow", "events.db");

  if (!fs.existsSync(dbPath)) {
    console.log("\n  No event store found. Install hooks and run a session first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  const reader = new EventStoreReader({ projectDir });
  const window = options.window ?? "7d";
  const sinceDate = parseDuration(window);
  const format = options.format ?? "table";

  // Get cost summaries from rollups (fast path)
  const costs = reader.getTokenSpendByAgent({ since: sinceDate });

  // If filtering by agent, narrow down
  const filtered = options.agent
    ? costs.filter((c) => c.agent_id === options.agent)
    : costs;

  if (format === "json") {
    console.log(JSON.stringify(filtered, null, 2));
    reader.close();
    return;
  }

  if (filtered.length === 0) {
    console.log(`\n  No cost data found for the last ${window}.`);
    console.log("  Cost data is populated from rollups computed at session end.\n");

    // Fallback: try reading directly from events table
    const events = reader.getEvents({
      agent_id: options.agent,
      time_range: { since: sinceDate + "T00:00:00.000Z" },
      limit: 1,
    });

    if (events.length > 0) {
      console.log("  Note: There are events in the store, but no rollups have been computed yet.");
      console.log("  Rollups are computed automatically at session end.\n");
    }

    reader.close();
    return;
  }

  // Calculate totals
  const totalCost = filtered.reduce((sum, c) => sum + c.total_cost_usd, 0);
  const totalPrompt = filtered.reduce((sum, c) => sum + c.total_prompt_tokens, 0);
  const totalCompletion = filtered.reduce((sum, c) => sum + c.total_completion_tokens, 0);
  const totalEvents = filtered.reduce((sum, c) => sum + c.event_count, 0);

  console.log("");
  console.log(`  SentinelFlow Cost Report (last ${window})`);
  console.log("  " + "─".repeat(70));
  console.log("");

  // Column headers
  console.log(
    `  ${padRight("AGENT", 24)} ${padRight("FRAMEWORK", 14)} ` +
    `${padRight("PROMPT", 10)} ${padRight("COMPLETION", 12)} ` +
    `${padRight("EVENTS", 8)} ${padRight("COST", 10)}`
  );
  console.log("  " + "─".repeat(80));

  for (const row of filtered) {
    console.log(
      `  ${padRight(row.agent_id, 24)} ${padRight(row.framework, 14)} ` +
      `${padRight(row.total_prompt_tokens.toLocaleString(), 10)} ` +
      `${padRight(row.total_completion_tokens.toLocaleString(), 12)} ` +
      `${padRight(row.event_count.toLocaleString(), 8)} ` +
      `$${row.total_cost_usd.toFixed(4)}`
    );
  }

  console.log("  " + "─".repeat(80));
  console.log(
    `  ${padRight("TOTAL", 24)} ${padRight("", 14)} ` +
    `${padRight(totalPrompt.toLocaleString(), 10)} ` +
    `${padRight(totalCompletion.toLocaleString(), 12)} ` +
    `${padRight(totalEvents.toLocaleString(), 8)} ` +
    `$${totalCost.toFixed(4)}`
  );
  console.log("");

  // Also show per-agent timeline if there's rollup data
  if (options.agent) {
    const timeline = reader.getCostTimeline(
      { since: sinceDate },
      options.agent
    );
    if (timeline.length > 1) {
      console.log(`  Daily breakdown for ${options.agent}:`);
      console.log("  " + "─".repeat(50));
      for (const day of timeline) {
        const bar = "█".repeat(
          Math.min(40, Math.round((day.cost_usd / totalCost) * 40))
        );
        console.log(
          `  ${day.date}  $${day.cost_usd.toFixed(4)}  ${bar}  (${day.tool_calls} calls)`
        );
      }
      console.log("");
    }
  }

  reader.close();
}
