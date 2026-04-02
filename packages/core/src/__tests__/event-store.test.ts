/**
 * Tests for the governance event store.
 *
 * Covers:
 * 1. EventStoreWriter — append-only inserts, batch flushing, rollup computation
 * 2. EventStoreReader — filtered queries, governance-specific methods, rollup reads
 * 3. End-to-end — write events, compute rollups, read back via query API
 * 4. Retention — old events get cleaned up
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  EventStoreWriter,
  EventStoreReader,
  createGovernanceEvent,
  type GovernanceEvent,
} from "../event-store/index";

// ─── Helpers ────────────────────────────────────────────────────────

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sf-eventstore-"));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

function makeEvent(overrides: Partial<GovernanceEvent> = {}): GovernanceEvent {
  return createGovernanceEvent({
    agent_id: overrides.agent_id ?? "test-agent",
    framework: overrides.framework ?? "claude_code",
    session_id: overrides.session_id ?? "session-1",
    event_type: overrides.event_type ?? "tool_call_attempted",
    outcome: overrides.outcome ?? "allowed",
    severity: overrides.severity ?? "info",
    ...overrides,
  });
}

// ─── Writer Tests ───────────────────────────────────────────────────

describe("EventStoreWriter", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    cleanup(tmpDir);
  });

  it("creates the database and tables on construction", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir });
    const dbPath = path.join(tmpDir, ".sentinelflow", "events.db");
    expect(fs.existsSync(dbPath)).toBe(true);
    writer.close();
  });

  it("ingests and flushes a single event", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 1 });
    const event = makeEvent({ tool_name: "Bash", action: "npm test" });
    writer.ingest(event);
    // flushSize=1 means it auto-flushed
    writer.close();

    // Verify via reader
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const events = reader.getEvents();
    expect(events).toHaveLength(1);
    expect(events[0]!.tool_name).toBe("Bash");
    expect(events[0]!.action).toBe("npm test");
    reader.close();
  });

  it("batch inserts events in a single transaction", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 100 });
    const events = Array.from({ length: 50 }, (_, i) =>
      makeEvent({
        tool_name: `Tool-${i}`,
        timestamp: `2026-04-01T10:00:${String(i).padStart(2, "0")}.000Z`,
      })
    );
    writer.ingestBatch(events);
    writer.flush();
    writer.close();

    const reader = new EventStoreReader({ projectDir: tmpDir });
    const count = reader.countEvents();
    expect(count).toBe(50);
    reader.close();
  });

  it("stores cost and token fields as indexed columns", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 1 });
    writer.ingest(
      makeEvent({
        prompt_tokens: 1500,
        completion_tokens: 300,
        cost_usd: 0.025,
        model: "claude-sonnet-4",
      })
    );
    writer.close();

    const reader = new EventStoreReader({ projectDir: tmpDir });
    const events = reader.getEvents();
    expect(events[0]!.prompt_tokens).toBe(1500);
    expect(events[0]!.completion_tokens).toBe(300);
    expect(events[0]!.cost_usd).toBeCloseTo(0.025);
    expect(events[0]!.model).toBe("claude-sonnet-4");
    reader.close();
  });

  it("stores payload as JSON without polluting indexed columns", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 1 });
    writer.ingest(
      makeEvent({
        payload: { raw_input: "very long command...", trace_id: "abc-123" },
      })
    );
    writer.close();

    const reader = new EventStoreReader({ projectDir: tmpDir });
    const events = reader.getEvents();
    expect(events[0]!.payload).toEqual({
      raw_input: "very long command...",
      trace_id: "abc-123",
    });
    reader.close();
  });

  it("reports stats correctly", () => {
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 1 });
    writer.ingest(makeEvent({ timestamp: "2026-04-01T10:00:00.000Z" }));
    writer.ingest(makeEvent({ timestamp: "2026-04-01T12:00:00.000Z" }));
    const stats = writer.getStats();
    expect(stats.totalEvents).toBe(2);
    expect(stats.oldestEvent).toBe("2026-04-01T10:00:00.000Z");
    expect(stats.newestEvent).toBe("2026-04-01T12:00:00.000Z");
    expect(stats.dbSizeBytes).toBeGreaterThan(0);
    writer.close();
  });
});

// ─── Reader Tests (Query API) ───────────────────────────────────────

describe("EventStoreReader", () => {
  let tmpDir: string;

  // Seed the database with a realistic set of events before each test
  beforeEach(() => {
    tmpDir = createTempDir();
    const writer = new EventStoreWriter({ projectDir: tmpDir, flushSize: 100 });

    // 10 allowed tool calls
    for (let i = 0; i < 10; i++) {
      writer.ingest(
        makeEvent({
          event_type: "tool_call_completed",
          outcome: "allowed",
          tool_name: i < 5 ? "Read" : "Bash",
          cost_usd: 0.01,
          prompt_tokens: 100,
          completion_tokens: 50,
          timestamp: `2026-04-01T10:${String(i).padStart(2, "0")}:00.000Z`,
        })
      );
    }

    // 3 blocked tool calls
    for (let i = 0; i < 3; i++) {
      writer.ingest(
        makeEvent({
          event_type: "tool_call_blocked",
          outcome: "blocked",
          severity: "high",
          tool_name: "Bash",
          action: "rm -rf /",
          policy_id: "AC-005",
          timestamp: `2026-04-01T11:${String(i).padStart(2, "0")}:00.000Z`,
        })
      );
    }

    // 2 error events
    for (let i = 0; i < 2; i++) {
      writer.ingest(
        makeEvent({
          event_type: "tool_call_failed",
          outcome: "error",
          tool_name: "Write",
          timestamp: `2026-04-01T12:${String(i).padStart(2, "0")}:00.000Z`,
        })
      );
    }

    // 1 session start
    writer.ingest(
      makeEvent({
        event_type: "session_started",
        outcome: "info",
        timestamp: "2026-04-01T09:00:00.000Z",
      })
    );

    // Second agent's events
    writer.ingest(
      makeEvent({
        agent_id: "agent-2",
        event_type: "tool_call_completed",
        outcome: "allowed",
        tool_name: "Read",
        cost_usd: 0.05,
        timestamp: "2026-04-01T10:00:00.000Z",
      })
    );

    writer.flush();
    writer.computeRollup("2026-04-01");
    writer.close();
  });

  afterEach(() => {
    cleanup(tmpDir);
  });

  it("filters events by event_type", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const blocked = reader.getEvents({ event_type: "tool_call_blocked" });
    expect(blocked).toHaveLength(3);
    expect(blocked.every((e) => e.outcome === "blocked")).toBe(true);
    reader.close();
  });

  it("filters events by agent_id", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const agentEvents = reader.getEvents({ agent_id: "agent-2" });
    expect(agentEvents).toHaveLength(1);
    expect(agentEvents[0]!.agent_id).toBe("agent-2");
    reader.close();
  });

  it("filters events by time range", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const events = reader.getEvents({
      time_range: {
        since: "2026-04-01T11:00:00.000Z",
        until: "2026-04-01T11:59:59.999Z",
      },
    });
    expect(events).toHaveLength(3); // The 3 blocked events
    reader.close();
  });

  it("counts events correctly", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    expect(reader.countEvents()).toBe(17); // 10 + 3 + 2 + 1 + 1
    expect(reader.countEvents({ outcome: "blocked" })).toBe(3);
    reader.close();
  });

  it("getBlockedToolCalls returns only blocked events", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const blocked = reader.getBlockedToolCalls("2026-04-01");
    expect(blocked).toHaveLength(3);
    expect(blocked[0]!.policy_id).toBe("AC-005");
    reader.close();
  });

  it("getTokenSpendByAgent reads from rollups", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const costs = reader.getTokenSpendByAgent({ since: "2026-04-01" });
    expect(costs).toHaveLength(2); // test-agent and agent-2

    const testAgent = costs.find((c) => c.agent_id === "test-agent");
    expect(testAgent).toBeDefined();
    // 10 events * 0.01 = 0.10
    expect(testAgent!.total_cost_usd).toBeCloseTo(0.1);
    reader.close();
  });

  it("getToolUsageSummary shows breakdown by tool", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const tools = reader.getToolUsageSummary("test-agent", {
      since: "2026-04-01",
    });

    expect(tools.length).toBeGreaterThan(0);
    const bash = tools.find((t) => t.tool_name === "Bash");
    expect(bash).toBeDefined();
    // 5 allowed + 3 blocked = 8 total Bash calls
    expect(bash!.call_count).toBe(8);
    expect(bash!.blocked_count).toBe(3);
    reader.close();
  });

  it("getCostTimeline reads from daily rollups", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const timeline = reader.getCostTimeline({ since: "2026-04-01" });
    expect(timeline.length).toBeGreaterThan(0);
    expect(timeline[0]!.date).toBe("2026-04-01");
    reader.close();
  });

  it("getActiveAgents lists agents with activity", () => {
    const reader = new EventStoreReader({ projectDir: tmpDir });
    const agents = reader.getActiveAgents(30);
    expect(agents).toHaveLength(2);
    expect(agents.map((a) => a.agent_id).sort()).toEqual(["agent-2", "test-agent"]);
    reader.close();
  });
});

// ─── Retention Tests ────────────────────────────────────────────────

describe("EventStore Retention", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    cleanup(tmpDir);
  });

  it("deletes events older than retention period", () => {
    const writer = new EventStoreWriter({
      projectDir: tmpDir,
      flushSize: 1,
      retentionDays: 7,
    });

    // Old event (30 days ago)
    const oldDate = new Date();
    oldDate.setDate(oldDate.getDate() - 30);
    writer.ingest(makeEvent({ timestamp: oldDate.toISOString() }));

    // Recent event (today)
    writer.ingest(makeEvent({ timestamp: new Date().toISOString() }));

    const deleted = writer.applyRetention();
    expect(deleted).toBe(1);

    const stats = writer.getStats();
    expect(stats.totalEvents).toBe(1);
    writer.close();
  });
});
