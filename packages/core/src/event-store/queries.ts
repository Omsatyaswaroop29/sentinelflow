/**
 * @module @sentinelflow/core/event-store/queries
 *
 * The read-side API for the governance event store.
 *
 * Design principles:
 *
 *   1. Named methods, not raw SQL. Each method answers a specific governance
 *      question: "which tool calls were blocked today?", "what's the cost trend
 *      for agent X?", "has this agent ever used this tool before?" The dashboard,
 *      anomaly detector, and CLI all call these methods — they never write SQL.
 *
 *   2. Read from rollups when possible. Aggregate queries (cost over time,
 *      tool call counts) read from daily_rollups, not from scanning the entire
 *      events table. Only drill-down queries (specific blocked events, event
 *      detail) hit the events table.
 *
 *   3. Pagination built in. Every list method accepts limit/offset. The event
 *      table can grow to millions of rows; unbounded SELECTs are not allowed.
 *
 *   4. Same SQLite connection as the writer (via shared db path). WAL mode
 *      ensures reads don't block writes.
 */

import Database from "better-sqlite3";
import * as path from "path";
import * as fs from "fs";
import type {
  GovernanceEvent,
  GovernanceEventType,
  EventOutcome,
  EventSeverity,
  DailyRollup,
} from "./schema";

// ─── Query Parameter Types ──────────────────────────────────────────

export interface TimeRange {
  /** ISO 8601 start time (inclusive) */
  since: string;
  /** ISO 8601 end time (inclusive). Defaults to now. */
  until?: string;
}

export interface PaginationOptions {
  limit?: number;
  offset?: number;
}

export interface EventFilter extends PaginationOptions {
  agent_id?: string;
  session_id?: string;
  event_type?: GovernanceEventType;
  outcome?: EventOutcome;
  severity?: EventSeverity;
  tool_name?: string;
  policy_id?: string;
  time_range?: TimeRange;
}

// ─── Aggregation Result Types ───────────────────────────────────────

export interface AgentCostSummary {
  agent_id: string;
  framework: string;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_usd: number;
  event_count: number;
}

export interface ToolUsageSummary {
  tool_name: string;
  call_count: number;
  blocked_count: number;
  error_count: number;
  avg_duration_ms: number;
}

export interface SessionSummary {
  session_id: string;
  agent_id: string;
  framework: string;
  started_at: string;
  ended_at: string | null;
  event_count: number;
  tool_calls: number;
  blocked_calls: number;
  cost_usd: number;
}

// ─── Constants ──────────────────────────────────────────────────────

const SF_DIR = ".sentinelflow";
const DB_FILE = "events.db";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

// ─── EventStoreReader ───────────────────────────────────────────────

export class EventStoreReader {
  private db: Database.Database;
  private _closed = false;

  constructor(config: { projectDir: string; dbPath?: string }) {
    const dbPath =
      config.dbPath ?? path.join(config.projectDir, SF_DIR, DB_FILE);

    if (!fs.existsSync(dbPath)) {
      throw new Error(
        `Event store not found at ${dbPath}. Run 'sentinelflow intercept install' first.`
      );
    }

    // Open read-only connection for safety
    this.db = new Database(dbPath, { readonly: true });
    this.db.pragma("busy_timeout = 5000");
  }

  // ─── Core Event Queries ─────────────────────────────────────

  /**
   * Get events matching a flexible filter. This is the general-purpose
   * query method — all other methods are convenience wrappers.
   */
  getEvents(filter: EventFilter = {}): GovernanceEvent[] {
    this.ensureOpen();

    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filter.agent_id) {
      conditions.push("agent_id = ?");
      params.push(filter.agent_id);
    }
    if (filter.session_id) {
      conditions.push("session_id = ?");
      params.push(filter.session_id);
    }
    if (filter.event_type) {
      conditions.push("event_type = ?");
      params.push(filter.event_type);
    }
    if (filter.outcome) {
      conditions.push("outcome = ?");
      params.push(filter.outcome);
    }
    if (filter.severity) {
      conditions.push("severity = ?");
      params.push(filter.severity);
    }
    if (filter.tool_name) {
      conditions.push("tool_name = ?");
      params.push(filter.tool_name);
    }
    if (filter.policy_id) {
      conditions.push("policy_id = ?");
      params.push(filter.policy_id);
    }
    if (filter.time_range?.since) {
      conditions.push("ts >= ?");
      params.push(filter.time_range.since);
    }
    if (filter.time_range?.until) {
      conditions.push("ts <= ?");
      params.push(filter.time_range.until);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = Math.min(filter.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    const offset = filter.offset ?? 0;

    const sql = `SELECT * FROM events ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const rows = this.db.prepare(sql).all(...params) as RawEventRow[];
    return rows.map(rowToEvent);
  }

  /**
   * Count events matching a filter. Useful for pagination.
   */
  countEvents(filter: Omit<EventFilter, "limit" | "offset"> = {}): number {
    this.ensureOpen();

    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filter.agent_id) { conditions.push("agent_id = ?"); params.push(filter.agent_id); }
    if (filter.event_type) { conditions.push("event_type = ?"); params.push(filter.event_type); }
    if (filter.outcome) { conditions.push("outcome = ?"); params.push(filter.outcome); }
    if (filter.time_range?.since) { conditions.push("ts >= ?"); params.push(filter.time_range.since); }
    if (filter.time_range?.until) { conditions.push("ts <= ?"); params.push(filter.time_range.until); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = this.db.prepare(`SELECT COUNT(*) as c FROM events ${where}`).get(...params) as { c: number };
    return result.c;
  }

  // ─── Governance-Specific Queries ────────────────────────────

  /**
   * "Which tool calls were blocked and why?"
   * The most important governance query — feeds the security dashboard.
   */
  getBlockedToolCalls(
    since: string,
    agentId?: string,
    limit = 50
  ): GovernanceEvent[] {
    return this.getEvents({
      event_type: "tool_call_blocked",
      agent_id: agentId,
      time_range: { since },
      limit,
    });
  }

  /**
   * "What's the token spend and cost by agent over a time range?"
   * Reads from daily_rollups for efficiency.
   */
  getTokenSpendByAgent(range: TimeRange): AgentCostSummary[] {
    this.ensureOpen();
    const until = range.until ?? new Date().toISOString().split("T")[0]!;
    const since = range.since.split("T")[0]!;

    return this.db
      .prepare(
        `SELECT
          agent_id,
          framework,
          SUM(prompt_tokens) as total_prompt_tokens,
          SUM(completion_tokens) as total_completion_tokens,
          SUM(cost_usd) as total_cost_usd,
          SUM(total_events) as event_count
        FROM daily_rollups
        WHERE date >= ? AND date <= ?
        GROUP BY agent_id, framework
        ORDER BY total_cost_usd DESC`
      )
      .all(since, until) as AgentCostSummary[];
  }

  /**
   * "Has this agent ever used this tool before?"
   * Critical for novel tool detection in anomaly detection.
   */
  getNovelToolUsage(
    agentId: string,
    lookbackDays: number = 30
  ): { knownTools: string[]; recentTools: string[] } {
    this.ensureOpen();

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - lookbackDays);
    const cutoffStr = cutoff.toISOString();

    // Tools seen in the lookback period (the "baseline")
    const known = this.db
      .prepare(
        `SELECT DISTINCT tool_name FROM events
         WHERE agent_id = ? AND ts < ? AND tool_name IS NOT NULL`
      )
      .all(agentId, cutoffStr) as Array<{ tool_name: string }>;

    // Tools seen in the last 24 hours
    const recent24h = new Date();
    recent24h.setHours(recent24h.getHours() - 24);
    const recent = this.db
      .prepare(
        `SELECT DISTINCT tool_name FROM events
         WHERE agent_id = ? AND ts >= ? AND tool_name IS NOT NULL`
      )
      .all(agentId, recent24h.toISOString()) as Array<{ tool_name: string }>;

    return {
      knownTools: known.map((r) => r.tool_name),
      recentTools: recent.map((r) => r.tool_name),
    };
  }

  /**
   * "What's the tool usage breakdown for an agent?"
   * Powers the tool usage chart in the dashboard.
   */
  getToolUsageSummary(
    agentId: string,
    range: TimeRange
  ): ToolUsageSummary[] {
    this.ensureOpen();
    return this.db
      .prepare(
        `SELECT
          tool_name,
          COUNT(*) as call_count,
          SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
          SUM(CASE WHEN outcome = 'error' THEN 1 ELSE 0 END) as error_count,
          COALESCE(AVG(duration_ms), 0) as avg_duration_ms
        FROM events
        WHERE agent_id = ? AND ts >= ? AND ts <= ?
          AND tool_name IS NOT NULL
        GROUP BY tool_name
        ORDER BY call_count DESC`
      )
      .all(agentId, range.since, range.until ?? new Date().toISOString()) as ToolUsageSummary[];
  }

  /**
   * "What policy violations happened recently?"
   * Feeds the compliance review queue.
   */
  getPolicyViolations(
    since: string,
    agentId?: string,
    limit = 50
  ): GovernanceEvent[] {
    return this.getEvents({
      event_type: "policy_violation",
      agent_id: agentId,
      time_range: { since },
      limit,
    });
  }

  /**
   * "Show me session summaries for this agent."
   * High-level view of agent activity.
   */
  getSessionSummaries(
    agentId: string,
    limit = 20
  ): SessionSummary[] {
    this.ensureOpen();
    return this.db
      .prepare(
        `SELECT
          session_id,
          agent_id,
          framework,
          MIN(ts) as started_at,
          MAX(ts) as ended_at,
          COUNT(*) as event_count,
          SUM(CASE WHEN event_type IN ('tool_call_attempted', 'tool_call_completed', 'tool_call_failed', 'tool_call_blocked') THEN 1 ELSE 0 END) as tool_calls,
          SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END) as blocked_calls,
          COALESCE(SUM(cost_usd), 0.0) as cost_usd
        FROM events
        WHERE agent_id = ?
        GROUP BY session_id
        ORDER BY started_at DESC
        LIMIT ?`
      )
      .all(agentId, limit) as SessionSummary[];
  }

  // ─── Rollup Queries (Fast Aggregates) ───────────────────────

  /**
   * "Show me cost over time for all agents."
   * Reads from daily_rollups — fast even with millions of events.
   */
  getCostTimeline(
    range: TimeRange,
    agentId?: string
  ): DailyRollup[] {
    this.ensureOpen();
    const since = range.since.split("T")[0]!;
    const until = (range.until ?? new Date().toISOString()).split("T")[0]!;

    if (agentId) {
      return this.db
        .prepare(
          `SELECT * FROM daily_rollups
           WHERE agent_id = ? AND date >= ? AND date <= ?
           ORDER BY date ASC`
        )
        .all(agentId, since, until) as DailyRollup[];
    }

    return this.db
      .prepare(
        `SELECT * FROM daily_rollups
         WHERE date >= ? AND date <= ?
         ORDER BY date ASC`
      )
      .all(since, until) as DailyRollup[];
  }

  /**
   * "What does the last week look like for this agent?"
   * Quick dashboard summary using rollups.
   */
  getAgentWeekSummary(agentId: string): DailyRollup[] {
    this.ensureOpen();
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const since = weekAgo.toISOString().split("T")[0]!;

    return this.db
      .prepare(
        `SELECT * FROM daily_rollups
         WHERE agent_id = ? AND date >= ?
         ORDER BY date ASC`
      )
      .all(agentId, since) as DailyRollup[];
  }

  /**
   * "List all agents that have ever generated events."
   * Useful for the dashboard agent inventory.
   */
  getActiveAgents(sinceDays: number = 30): Array<{
    agent_id: string;
    framework: string;
    last_seen: string;
    total_events: number;
    total_blocked: number;
    total_cost_usd: number;
  }> {
    this.ensureOpen();
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - sinceDays);

    return this.db
      .prepare(
        `SELECT
          agent_id,
          framework,
          MAX(ts) as last_seen,
          COUNT(*) as total_events,
          SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END) as total_blocked,
          COALESCE(SUM(cost_usd), 0.0) as total_cost_usd
        FROM events
        WHERE ts >= ?
        GROUP BY agent_id, framework
        ORDER BY last_seen DESC`
      )
      .all(cutoff.toISOString()) as Array<{
      agent_id: string;
      framework: string;
      last_seen: string;
      total_events: number;
      total_blocked: number;
      total_cost_usd: number;
    }>;
  }

  // ─── Lifecycle ────────────────────────────────────────────────

  close(): void {
    if (this._closed) return;
    this.db.close();
    this._closed = true;
  }

  private ensureOpen(): void {
    if (this._closed) {
      throw new Error("EventStoreReader is closed. Create a new instance.");
    }
  }
}

// ─── Row Mapping Helpers ────────────────────────────────────────────

interface RawEventRow {
  event_id: string;
  schema_version: number;
  ts: string;
  agent_id: string;
  framework: string;
  session_id: string;
  parent_event_id: string | null;
  event_type: string;
  outcome: string;
  severity: string;
  tool_name: string | null;
  tool_input_summary: string | null;
  action: string | null;
  policy_id: string | null;
  policy_name: string | null;
  reason: string | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  cost_usd: number | null;
  model: string | null;
  duration_ms: number | null;
  payload_json: string | null;
}

function rowToEvent(row: RawEventRow): GovernanceEvent {
  return {
    event_id: row.event_id,
    schema_version: row.schema_version,
    timestamp: row.ts,
    agent_id: row.agent_id,
    framework: row.framework,
    session_id: row.session_id,
    parent_event_id: row.parent_event_id ?? undefined,
    event_type: row.event_type as GovernanceEvent["event_type"],
    outcome: row.outcome as GovernanceEvent["outcome"],
    severity: row.severity as GovernanceEvent["severity"],
    tool_name: row.tool_name ?? undefined,
    tool_input_summary: row.tool_input_summary ?? undefined,
    action: row.action ?? undefined,
    policy_id: row.policy_id ?? undefined,
    policy_name: row.policy_name ?? undefined,
    reason: row.reason ?? undefined,
    prompt_tokens: row.prompt_tokens ?? undefined,
    completion_tokens: row.completion_tokens ?? undefined,
    cost_usd: row.cost_usd ?? undefined,
    model: row.model ?? undefined,
    duration_ms: row.duration_ms ?? undefined,
    payload: row.payload_json ? JSON.parse(row.payload_json) : undefined,
  };
}
