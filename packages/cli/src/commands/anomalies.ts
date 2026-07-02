/**
 * sentinelflow anomalies — Batch anomaly detection over event history.
 *
 * Usage:
 *   sentinelflow anomalies [path]
 *
 * Options:
 *   --since <duration>   Time window: 1d, 7d, 30d (default: 7d)
 *   --agent <id>         Filter by agent ID
 *   --format <fmt>       Output format: table, json (default: table)
 *
 * Runs the statistical/rate-based detectors (novel tool, cost spike, error
 * rate) over historical events from the SQLite store. These are batch/
 * periodic checks rather than per-call hot-path checks: building a cost or
 * error-rate baseline needs many events, which is a better fit for
 * on-demand analysis than synchronous per-tool-call evaluation in the
 * generated handlers.
 *
 * Privilege escalation detection is included only when the policy YAML's
 * identity.agent_privileges/agent_roles are configured — without real
 * per-agent privilege data, PrivilegeEscalationDetector's built-in default
 * (privilege 3 for every unlisted agent) would flag nearly every Bash/Write
 * call. Real-time RBAC (via `sentinelflow intercept install`) already
 * covers this exact concern with a better-calibrated default (privilege 6),
 * so this command doesn't duplicate it with a noisier fallback.
 */

import * as path from "path";
import * as fs from "fs";
import { EventStoreReader, isSqliteAvailable, type GovernanceEvent } from "@sentinelflow/core";
import type { AgentEvent, EventType, ToolEventData } from "@sentinelflow/core";
import {
  NovelToolDetector,
  CostSpikeDetector,
  ErrorRateDetector,
  PrivilegeEscalationDetector,
  AnomalyEngine,
  type AnomalyDetector,
} from "@sentinelflow/interceptors";
import { loadPolicyFile } from "@sentinelflow/scanner";

const ROLE_PRIVILEGES: Record<string, number> = {
  reader: 2, writer: 4, executor: 6, deployer: 8, admin: 10, custom: 5,
};

const EVENT_TYPE_MAP: Record<string, EventType> = {
  tool_call_attempted: "tool_call_start",
  tool_call_completed: "tool_call_end",
  tool_call_failed: "tool_call_end",
  tool_call_blocked: "tool_call_blocked",
  session_started: "session_start",
  session_ended: "session_end",
  delegation_spawned: "delegation",
};

const OUTCOME_STATUS_MAP: Record<string, ToolEventData["status"]> = {
  allowed: "success",
  blocked: "blocked",
  error: "error",
};

/** Convert a stored GovernanceEvent back into the AgentEvent shape the anomaly detectors expect. */
function toAgentEvent(ge: GovernanceEvent): AgentEvent {
  const event: AgentEvent = {
    id: ge.event_id,
    timestamp: ge.timestamp,
    agent_id: ge.agent_id,
    session_id: ge.session_id,
    type: EVENT_TYPE_MAP[ge.event_type] ?? "tool_call_end",
  };

  if (ge.tool_name) {
    event.tool = {
      name: ge.tool_name,
      input_summary: ge.tool_input_summary,
      status: OUTCOME_STATUS_MAP[ge.outcome] ?? "success",
    };
  }

  if (ge.cost_usd !== undefined) {
    event.tokens = {
      input: ge.prompt_tokens ?? 0,
      output: ge.completion_tokens ?? 0,
      model: ge.model ?? "unknown",
      estimated_cost_usd: ge.cost_usd,
    };
  }

  return event;
}

function parseDuration(input: string): Date {
  const match = input.match(/^(\d+)(h|d|w)$/);
  if (!match) throw new Error(`Invalid duration "${input}". Use: 1h, 24h, 7d, 30d`);
  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const now = new Date();
  switch (unit) {
    case "h": now.setHours(now.getHours() - value); break;
    case "d": now.setDate(now.getDate() - value); break;
    case "w": now.setDate(now.getDate() - value * 7); break;
  }
  return now;
}

/** Resolve a flat agent_id -> privilege level map from the policy YAML's identity config, if configured. */
function resolvePrivilegeMap(projectDir: string): Record<string, number> | null {
  const { policy } = loadPolicyFile(projectDir);
  const identity = policy?.runtime_policies?.identity;
  if (!identity || (!identity.agent_privileges && !identity.agent_roles)) return null;

  const map: Record<string, number> = {};
  for (const [agent, role] of Object.entries(identity.agent_roles ?? {})) {
    map[agent] = ROLE_PRIVILEGES[role] ?? 5;
  }
  for (const [agent, level] of Object.entries(identity.agent_privileges ?? {})) {
    map[agent] = level;
  }
  return map;
}

interface AnomalyRow {
  timestamp: string;
  agent_id: string;
  type: string;
  confidence: number;
  description: string;
}

export async function anomaliesCommand(
  targetPath: string,
  options: { since?: string; agent?: string; format?: string }
): Promise<void> {
  const projectDir = path.resolve(targetPath);
  const dbPath = path.join(projectDir, ".sentinelflow", "events.db");

  if (!fs.existsSync(dbPath)) {
    console.log("\n  No event store found. Install hooks and run a session first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  if (!isSqliteAvailable()) {
    console.log("\n  Anomaly detection requires the optional 'better-sqlite3' dependency, which");
    console.log("  isn't available in this environment. Install better-sqlite3 to enable");
    console.log("  'sentinelflow anomalies'.\n");
    process.exit(1);
  }

  const since = parseDuration(options.since ?? "7d");
  const format = options.format ?? "table";

  const reader = new EventStoreReader({ projectDir });
  // getEvents() sorts newest-first and caps at 1000 -- reverse for chronological
  // replay, since the detectors are stateful and build baselines incrementally.
  const events = reader
    .getEvents({ agent_id: options.agent, time_range: { since: since.toISOString() }, limit: 1000 })
    .reverse();
  reader.close();

  const privilegeMap = resolvePrivilegeMap(projectDir);
  const detectors: AnomalyDetector[] = [
    new NovelToolDetector(),
    new CostSpikeDetector(),
    new ErrorRateDetector(),
  ];
  if (privilegeMap) {
    detectors.push(new PrivilegeEscalationDetector({ privilegeMap }));
  }

  const anomalies: AnomalyRow[] = [];
  const engine = new AnomalyEngine({
    detectors,
    onAnomaly: (event, result) => {
      anomalies.push({
        timestamp: event.timestamp,
        agent_id: event.agent_id,
        type: result.type ?? "unknown",
        confidence: result.confidence,
        description: result.description ?? "",
      });
    },
  });

  for (const ge of events) {
    engine.onEvent(toAgentEvent(ge));
  }

  if (format === "json") {
    console.log(JSON.stringify(anomalies, null, 2));
    return;
  }

  console.log("");
  console.log(`  SentinelFlow Anomaly Report (last ${options.since ?? "7d"}, ${events.length} events analyzed)`);
  console.log("  " + "-".repeat(78));

  if (!privilegeMap) {
    console.log("  Note: privilege escalation detection skipped -- configure");
    console.log("  runtime_policies.identity.agent_roles/agent_privileges in");
    console.log("  .sentinelflow-policy.yaml to enable it.");
    console.log("");
  }

  if (anomalies.length === 0) {
    console.log("\n  No anomalies detected.\n");
    return;
  }

  console.log("");
  for (const a of anomalies) {
    const time = new Date(a.timestamp).toLocaleString("en-US", {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
    });
    console.log(`  ${time}  [${a.type}] agent="${a.agent_id}" confidence=${a.confidence.toFixed(2)}`);
    console.log(`    ${a.description}`);
    console.log("");
  }
  console.log(`  ${anomalies.length} anomalies found.\n`);
}
