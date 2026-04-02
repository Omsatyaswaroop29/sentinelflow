/**
 * @module @sentinelflow/core/event-store/writer
 *
 * SQLite-backed event store writer with append-only semantics.
 *
 * Architecture decisions:
 *
 *   WAL mode: Enables concurrent reads while writing. The dashboard can
 *   query while the interceptor is writing events without locking.
 *
 *   Batch inserts: Events are buffered and flushed in transactions.
 *   A single INSERT inside a transaction is ~100x faster than individual
 *   INSERTs because SQLite only syncs to disk once per transaction.
 *
 *   Append-only: We never UPDATE or DELETE event rows. Events are
 *   immutable facts. The only mutation is retention cleanup (deleteOlderThan)
 *   which is a separate maintenance operation, not part of normal flow.
 *
 *   Indexed columns: Fields we filter/aggregate on are first-class columns.
 *   The payload_json column holds auxiliary metadata that we never filter on
 *   directly — it's there for drill-down detail, not primary queries.
 *
 *   Connection pooling: Not needed for SQLite — a single connection with
 *   WAL mode handles concurrent access. We keep one connection for the
 *   lifetime of the EventStore instance.
 */

import Database from "better-sqlite3";
import * as path from "path";
import * as fs from "fs";
import type { GovernanceEvent, DailyRollup } from "./schema";

// ─── Constants ──────────────────────────────────────────────────────

const SF_DIR = ".sentinelflow";
const DB_FILE = "events.db";
const DEFAULT_FLUSH_SIZE = 50;
const DEFAULT_RETENTION_DAYS = 90;

// ─── SQL Statements ─────────────────────────────────────────────────

const CREATE_EVENTS_TABLE = `
CREATE TABLE IF NOT EXISTS events (
  event_id          TEXT PRIMARY KEY,
  schema_version    INTEGER NOT NULL DEFAULT 1,
  ts                TEXT NOT NULL,
  agent_id          TEXT NOT NULL,
  framework         TEXT NOT NULL,
  session_id        TEXT NOT NULL,
  parent_event_id   TEXT,
  event_type        TEXT NOT NULL,
  outcome           TEXT NOT NULL,
  severity          TEXT NOT NULL DEFAULT 'info',
  tool_name         TEXT,
  tool_input_summary TEXT,
  action            TEXT,
  policy_id         TEXT,
  policy_name       TEXT,
  reason            TEXT,
  prompt_tokens     INTEGER,
  completion_tokens INTEGER,
  cost_usd          REAL,
  model             TEXT,
  duration_ms       INTEGER,
  payload_json      TEXT
);
`;

const CREATE_EVENTS_INDEXES = [
  `CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events(agent_id, ts);`,
  `CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts);`,
  `CREATE INDEX IF NOT EXISTS idx_events_outcome_ts ON events(outcome, ts);`,
  `CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);`,
  `CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name, ts);`,
  `CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, ts);`,
];

const CREATE_ROLLUPS_TABLE = `
CREATE TABLE IF NOT EXISTS daily_rollups (
  date              TEXT NOT NULL,
  agent_id          TEXT NOT NULL,
  framework         TEXT NOT NULL,
  total_events      INTEGER NOT NULL DEFAULT 0,
  tool_calls        INTEGER NOT NULL DEFAULT 0,
  tool_calls_blocked INTEGER NOT NULL DEFAULT 0,
  tool_calls_failed INTEGER NOT NULL DEFAULT 0,
  unique_tools      INTEGER NOT NULL DEFAULT 0,
  tools_used        TEXT NOT NULL DEFAULT '',
  prompt_tokens     INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd          REAL NOT NULL DEFAULT 0.0,
  policy_violations INTEGER NOT NULL DEFAULT 0,
  anomalies_detected INTEGER NOT NULL DEFAULT 0,
  sessions          INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (date, agent_id)
);
`;

const CREATE_ROLLUPS_INDEXES = [
  `CREATE INDEX IF NOT EXISTS idx_rollups_agent ON daily_rollups(agent_id, date);`,
  `CREATE INDEX IF NOT EXISTS idx_rollups_date ON daily_rollups(date);`,
];

const INSERT_EVENT = `
INSERT OR IGNORE INTO events (
  event_id, schema_version, ts, agent_id, framework, session_id,
  parent_event_id, event_type, outcome, severity,
  tool_name, tool_input_summary, action,
  policy_id, policy_name, reason,
  prompt_tokens, completion_tokens, cost_usd, model,
  duration_ms, payload_json
) VALUES (
  ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?
);
`;

const UPSERT_ROLLUP = `
INSERT INTO daily_rollups (
  date, agent_id, framework,
  total_events, tool_calls, tool_calls_blocked, tool_calls_failed,
  unique_tools, tools_used,
  prompt_tokens, completion_tokens, cost_usd,
  policy_violations, anomalies_detected, sessions
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(date, agent_id) DO UPDATE SET
  total_events = excluded.total_events,
  tool_calls = excluded.tool_calls,
  tool_calls_blocked = excluded.tool_calls_blocked,
  tool_calls_failed = excluded.tool_calls_failed,
  unique_tools = excluded.unique_tools,
  tools_used = excluded.tools_used,
  prompt_tokens = excluded.prompt_tokens,
  completion_tokens = excluded.completion_tokens,
  cost_usd = excluded.cost_usd,
  policy_violations = excluded.policy_violations,
  anomalies_detected = excluded.anomalies_detected,
  sessions = excluded.sessions;
`;

// ─── EventStore Writer ──────────────────────────────────────────────

export interface EventStoreConfig {
  /** Path to the project root (where .sentinelflow/ lives) */
  projectDir: string;
  /** Custom database file path (overrides default .sentinelflow/events.db) */
  dbPath?: string;
  /** Number of events to buffer before flushing. Default: 50 */
  flushSize?: number;
  /** Retention period in days. Events older than this are eligible for cleanup. Default: 90 */
  retentionDays?: number;
}

export class EventStoreWriter {
  private db: Database.Database;
  private buffer: GovernanceEvent[] = [];
  private flushSize: number;
  private retentionDays: number;
  private insertStmt: Database.Statement;
  private insertMany: Database.Transaction<(events: GovernanceEvent[]) => void>;
  private _closed = false;

  constructor(config: EventStoreConfig) {
    const dbPath =
      config.dbPath ?? path.join(config.projectDir, SF_DIR, DB_FILE);

    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.flushSize = config.flushSize ?? DEFAULT_FLUSH_SIZE;
    this.retentionDays = config.retentionDays ?? DEFAULT_RETENTION_DAYS;

    // Open database with WAL mode for concurrent read/write
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL"); // Good balance of safety and speed
    this.db.pragma("busy_timeout = 5000");  // Wait up to 5s for locks

    // Create schema
    this.db.exec(CREATE_EVENTS_TABLE);
    for (const idx of CREATE_EVENTS_INDEXES) {
      this.db.exec(idx);
    }
    this.db.exec(CREATE_ROLLUPS_TABLE);
    for (const idx of CREATE_ROLLUPS_INDEXES) {
      this.db.exec(idx);
    }

    // Prepare statements (reused for performance)
    this.insertStmt = this.db.prepare(INSERT_EVENT);

    // Batch insert transaction — all events in one transaction = one disk sync
    this.insertMany = this.db.transaction((events: GovernanceEvent[]) => {
      for (const event of events) {
        this.insertStmt.run(
          event.event_id,
          event.schema_version,
          event.timestamp,
          event.agent_id,
          event.framework,
          event.session_id,
          event.parent_event_id ?? null,
          event.event_type,
          event.outcome,
          event.severity,
          event.tool_name ?? null,
          event.tool_input_summary ?? null,
          event.action ?? null,
          event.policy_id ?? null,
          event.policy_name ?? null,
          event.reason ?? null,
          event.prompt_tokens ?? null,
          event.completion_tokens ?? null,
          event.cost_usd ?? null,
          event.model ?? null,
          event.duration_ms ?? null,
          event.payload ? JSON.stringify(event.payload) : null
        );
      }
    });
  }

  // ─── Write Operations ───────────────────────────────────────

  /**
   * Ingest a single event. Buffers it and flushes when the buffer
   * reaches flushSize. Call flush() to force-write remaining events.
   */
  ingest(event: GovernanceEvent): void {
    this.ensureOpen();
    this.buffer.push(event);

    if (this.buffer.length >= this.flushSize) {
      this.flush();
    }
  }

  /**
   * Ingest multiple events at once. More efficient than calling
   * ingest() in a loop because it triggers a single batch flush.
   */
  ingestBatch(events: GovernanceEvent[]): void {
    this.ensureOpen();
    this.buffer.push(...events);

    if (this.buffer.length >= this.flushSize) {
      this.flush();
    }
  }

  /**
   * Flush all buffered events to SQLite in a single transaction.
   * This is the performance-critical path — a single transaction
   * with 50 INSERTs is ~100x faster than 50 individual transactions.
   */
  flush(): void {
    this.ensureOpen();
    if (this.buffer.length === 0) return;

    const toFlush = this.buffer.splice(0);
    this.insertMany(toFlush);
  }

  // ─── Rollup Operations ──────────────────────────────────────

  /**
   * Compute daily rollups for a specific date. This reads from the events
   * table and upserts into the daily_rollups table. Safe to call multiple
   * times for the same date (idempotent via UPSERT).
   *
   * Typically called at the end of a session or via a scheduled job.
   */
  computeRollup(date: string): void {
    this.ensureOpen();
    const upsertStmt = this.db.prepare(UPSERT_ROLLUP);

    // Get all unique agent_ids for this date
    const agents = this.db
      .prepare(
        `SELECT DISTINCT agent_id, framework FROM events
         WHERE ts >= ? AND ts < date(?, '+1 day')`
      )
      .all(date, date) as Array<{ agent_id: string; framework: string }>;

    const computeOne = this.db.transaction(
      (agentId: string, framework: string) => {
        const dateStart = date;
        const dateEnd = date + "T23:59:59.999Z";

        // Count events by type/outcome
        const counts = this.db
          .prepare(
            `SELECT
              COUNT(*) as total_events,
              SUM(CASE WHEN event_type IN ('tool_call_attempted', 'tool_call_completed', 'tool_call_failed', 'tool_call_blocked') THEN 1 ELSE 0 END) as tool_calls,
              SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END) as tool_calls_blocked,
              SUM(CASE WHEN outcome = 'error' THEN 1 ELSE 0 END) as tool_calls_failed,
              SUM(CASE WHEN event_type = 'policy_violation' THEN 1 ELSE 0 END) as policy_violations,
              SUM(CASE WHEN event_type = 'anomaly_detected' THEN 1 ELSE 0 END) as anomalies_detected,
              SUM(CASE WHEN event_type = 'session_started' THEN 1 ELSE 0 END) as sessions,
              COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
              COALESCE(SUM(completion_tokens), 0) as completion_tokens,
              COALESCE(SUM(cost_usd), 0.0) as cost_usd
            FROM events
            WHERE agent_id = ? AND ts >= ? AND ts <= ?`
          )
          .get(agentId, dateStart, dateEnd) as Record<string, number>;

        // Get unique tools
        const tools = this.db
          .prepare(
            `SELECT DISTINCT tool_name FROM events
            WHERE agent_id = ? AND ts >= ? AND ts <= ?
              AND tool_name IS NOT NULL`
          )
          .all(agentId, dateStart, dateEnd) as Array<{ tool_name: string }>;

        const toolsList = tools.map((t) => t.tool_name);

        upsertStmt.run(
          date,
          agentId,
          framework,
          counts.total_events ?? 0,
          counts.tool_calls ?? 0,
          counts.tool_calls_blocked ?? 0,
          counts.tool_calls_failed ?? 0,
          toolsList.length,
          toolsList.join(","),
          counts.prompt_tokens ?? 0,
          counts.completion_tokens ?? 0,
          counts.cost_usd ?? 0,
          counts.policy_violations ?? 0,
          counts.anomalies_detected ?? 0,
          counts.sessions ?? 0
        );
      }
    );

    for (const { agent_id, framework } of agents) {
      computeOne(agent_id, framework);
    }
  }

  /**
   * Compute rollups for today. Convenience wrapper.
   */
  computeTodayRollup(): void {
    const today = new Date().toISOString().split("T")[0]!;
    this.computeRollup(today);
  }

  // ─── Retention ────────────────────────────────────────────────

  /**
   * Delete events older than the retention period.
   * This is the ONLY mutation allowed on the events table.
   * Should be called from a scheduled maintenance job, not inline.
   */
  applyRetention(): number {
    this.ensureOpen();
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.retentionDays);
    const cutoffStr = cutoff.toISOString();

    const result = this.db
      .prepare(`DELETE FROM events WHERE ts < ?`)
      .run(cutoffStr);
    return result.changes;
  }

  // ─── Stats ────────────────────────────────────────────────────

  /**
   * Quick stats about the event store. Useful for the CLI status command.
   */
  getStats(): {
    totalEvents: number;
    oldestEvent: string | null;
    newestEvent: string | null;
    dbSizeBytes: number;
    rollupDays: number;
  } {
    this.ensureOpen();
    const count = this.db
      .prepare(`SELECT COUNT(*) as c FROM events`)
      .get() as { c: number };
    const oldest = this.db
      .prepare(`SELECT MIN(ts) as ts FROM events`)
      .get() as { ts: string | null };
    const newest = this.db
      .prepare(`SELECT MAX(ts) as ts FROM events`)
      .get() as { ts: string | null };
    const rollups = this.db
      .prepare(`SELECT COUNT(*) as c FROM daily_rollups`)
      .get() as { c: number };
    const dbPath = this.db.name;
    const dbSize = fs.existsSync(dbPath) ? fs.statSync(dbPath).size : 0;

    return {
      totalEvents: count.c,
      oldestEvent: oldest.ts,
      newestEvent: newest.ts,
      dbSizeBytes: dbSize,
      rollupDays: rollups.c,
    };
  }

  // ─── Lifecycle ────────────────────────────────────────────────

  /**
   * Flush remaining events and close the database connection.
   * Always call this before exiting to avoid data loss.
   */
  close(): void {
    if (this._closed) return;
    this.flush();
    this.db.close();
    this._closed = true;
  }

  private ensureOpen(): void {
    if (this._closed) {
      throw new Error("EventStore is closed. Create a new instance.");
    }
  }
}
