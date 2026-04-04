#!/usr/bin/env node

/**
 * SentinelFlow CLI
 *
 * The vendor-neutral governance layer for enterprise AI agents.
 *
 * Usage:
 *   sentinelflow scan [path]       Scan for agents and governance issues
 *   sentinelflow init              Initialize SentinelFlow in a project
 *   sentinelflow registry list     List registered agents
 *
 * Future (Phase 2):
 *   sentinelflow monitor           Live-tail agent events
 *   sentinelflow dashboard         Launch the governance dashboard
 *
 * Future (Phase 3):
 *   sentinelflow comply <standard> Run compliance checks
 */

import { Command } from "commander";
import { scanCommand } from "./commands/scan";
import { initCommand } from "./commands/init";
import {
  interceptInstallCommand,
  interceptUninstallCommand,
  interceptStatusCommand,
  interceptTailCommand,
} from "./commands/intercept";
import { interceptTestCommand } from "./commands/intercept-test";
import {
  eventsTailCommand,
  eventsBlockedCommand,
  eventsStatsCommand,
} from "./commands/events";
import { costsCommand } from "./commands/costs";

const program = new Command();

program
  .name("sentinelflow")
  .description("The vendor-neutral governance layer for enterprise AI agents")
  .version("0.3.0");

// ── sentinelflow scan ───────────────────────────────────────
program
  .command("scan")
  .description("Scan for AI agents and governance issues")
  .argument("[path]", "Project directory to scan", ".")
  .option("-f, --format <format>", "Output format: terminal, json, md, sarif", "terminal")
  .option("--min-severity <severity>", "Minimum severity: critical, high, medium, low, info")
  .option("--rules <rules>", "Comma-separated rule IDs to run")
  .option("--preset <preset>", "Scan preset: strict, standard, monitor", "standard")
  .option("--show-suppressed", "Show suppressed findings for audit review")
  .option("--no-registry", "Skip updating the local registry")
  .action(scanCommand);

// ── sentinelflow init ───────────────────────────────────────
program
  .command("init")
  .description("Initialize SentinelFlow in the current project")
  .argument("[path]", "Project directory", ".")
  .action(initCommand);

// ── sentinelflow intercept ───────────────────────────────────
const intercept = program
  .command("intercept")
  .description("Runtime agent firewall — install/manage runtime hooks");

intercept
  .command("install")
  .description("Install runtime governance hooks into a project")
  .argument("[path]", "Project directory", ".")
  .option("--mode <mode>", "Enforcement mode: monitor, enforce", "monitor")
  .option("--blocklist <tools>", "Comma-separated tools to block")
  .option("--allowlist <tools>", "Comma-separated tools to allow (blocks all others)")
  .option("--budget <usd>", "Max cost per session in USD")
  .action(interceptInstallCommand);

intercept
  .command("uninstall")
  .description("Remove runtime hooks from a project")
  .argument("[path]", "Project directory", ".")
  .action(interceptUninstallCommand);

intercept
  .command("status")
  .description("Check runtime hook status and event log stats")
  .argument("[path]", "Project directory", ".")
  .action(interceptStatusCommand);

intercept
  .command("tail")
  .description("View recent events from the runtime log")
  .argument("[path]", "Project directory", ".")
  .option("-n, --lines <count>", "Number of events to show", "20")
  .option("-f, --follow", "Follow the log in real-time")
  .action(interceptTailCommand);

intercept
  .command("test")
  .description("Test the interceptor with a fixture or synthetic event")
  .argument("[path]", "Project directory", ".")
  .option("--fixture <file>", "JSON fixture file with a hook event")
  .option("--tool <name>", "Tool name (e.g., Bash, Read, Write)")
  .option("--input <json>", "Tool input as JSON string or plain command")
  .option("--phase <phase>", "Hook phase: PreToolUse, PostToolUse", "PreToolUse")
  .option("--mode <mode>", "Enforcement mode: monitor, enforce", "enforce")
  .option("--blocklist <tools>", "Comma-separated tools to block")
  .option("--allowlist <tools>", "Comma-separated tools to allow")
  .action(interceptTestCommand);

// ── sentinelflow events ─────────────────────────────────────
const events = program
  .command("events")
  .description("Query the governance event store (SQLite)");

events
  .command("tail")
  .description("Show recent events from the SQLite event store")
  .argument("[path]", "Project directory", ".")
  .option("--since <duration>", "Time window: 1h, 24h, 7d, 30d", "24h")
  .option("--agent <id>", "Filter by agent ID")
  .option("--tool <name>", "Filter by tool name")
  .option("--limit <n>", "Max events to show", "50")
  .option("--format <fmt>", "Output format: table, json", "table")
  .action(eventsTailCommand);

events
  .command("blocked")
  .description("Show blocked tool calls")
  .argument("[path]", "Project directory", ".")
  .option("--since <duration>", "Time window: 1d, 7d, 30d", "7d")
  .option("--agent <id>", "Filter by agent ID")
  .option("--limit <n>", "Max events to show", "50")
  .option("--format <fmt>", "Output format: table, json", "table")
  .action(eventsBlockedCommand);

events
  .command("stats")
  .description("Show event store statistics")
  .argument("[path]", "Project directory", ".")
  .option("--format <fmt>", "Output format: table, json", "table")
  .action(eventsStatsCommand);

// ── sentinelflow costs ──────────────────────────────────────
program
  .command("costs")
  .description("Token spend and cost report from the event store")
  .argument("[path]", "Project directory", ".")
  .option("--window <duration>", "Time window: 1d, 7d, 30d", "7d")
  .option("--agent <id>", "Filter by agent ID")
  .option("--format <fmt>", "Output format: table, json", "table")
  .action(costsCommand);

// ── sentinelflow registry ───────────────────────────────────
const registry = program
  .command("registry")
  .description("Manage the agent registry");

registry
  .command("list")
  .description("List all registered agents")
  .option("--framework <framework>", "Filter by framework")
  .option("--status <status>", "Filter by governance status")
  .option("--json", "Output as JSON")
  .action(async (options) => {
    const path = await import("path");
    const { LocalRegistry } = await import("@sentinelflow/core");
    const reg = new LocalRegistry(process.cwd());
    await reg.initialize();

    const agents = await reg.listAgents({
      framework: options.framework,
      status: options.status,
    });

    if (options.json) {
      console.log(JSON.stringify(agents, null, 2));
    } else {
      if (agents.length === 0) {
        console.log("\n  No agents registered. Run 'sentinelflow scan' first.\n");
        return;
      }
      console.log(`\n  ${agents.length} agents registered:\n`);
      for (const agent of agents) {
        const risk = agent.governance.risk_level ?? "unassessed";
        const status = agent.governance.status;
        console.log(
          `    ${agent.name} (${agent.framework}) — ${status} — risk: ${risk}`
        );
      }
      console.log("");
    }

    await reg.close();
  });

program.parse();
