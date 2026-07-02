/**
 * Integration test for `sentinelflow anomalies` — verifies the
 * GovernanceEvent -> AgentEvent conversion feeds the real AnomalyEngine
 * detectors correctly end-to-end against a real SQLite event store.
 */

import { describe, it, expect, afterEach, beforeEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { EventStoreWriter, createGovernanceEvent, isSqliteAvailable } from "@sentinelflow/core";
import { anomaliesCommand } from "../commands/anomalies";

const describeIfSqlite = isSqliteAvailable() ? describe : describe.skip;

describeIfSqlite("anomaliesCommand", () => {
  let dir: string;
  let logs: string[];
  let originalLog: typeof console.log;
  let originalExit: typeof process.exit;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-anomalies-"));
    logs = [];
    originalLog = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(" ")); };
    originalExit = process.exit;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    process.exit = ((code?: number) => { throw new Error(`process.exit(${code})`); }) as any;
  });

  afterEach(() => {
    console.log = originalLog;
    process.exit = originalExit;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function seedCostSpike(): void {
    const writer = new EventStoreWriter({ projectDir: dir });
    const now = Date.now();
    const costs = [0.008, 0.012, 0.009, 0.011, 0.010, 0.013, 0.007, 0.011];
    costs.forEach((cost, i) => {
      writer.ingest(createGovernanceEvent({
        agent_id: "agent1",
        framework: "claude_code",
        session_id: `sess-${i}`,
        event_type: "tool_call_completed",
        outcome: "allowed",
        severity: "info",
        tool_name: "Read",
        timestamp: new Date(now + i * 6 * 60000).toISOString(),
        cost_usd: cost,
      }));
    });
    writer.ingest(createGovernanceEvent({
      agent_id: "agent1",
      framework: "claude_code",
      session_id: "sess-spike",
      event_type: "tool_call_completed",
      outcome: "allowed",
      severity: "info",
      tool_name: "Bash",
      timestamp: new Date(now + costs.length * 6 * 60000 + 120000).toISOString(),
      cost_usd: 5.0,
    }));
    writer.close();
  }

  it("errors clearly when no event store exists", async () => {
    await expect(anomaliesCommand(dir, {})).rejects.toThrow("process.exit(1)");
    expect(logs.join("\n")).toMatch(/No event store found/);
  });

  it("detects a cost spike from real SQLite-stored events", async () => {
    seedCostSpike();
    await anomaliesCommand(dir, { since: "30d", format: "json" });
    const jsonOutput = logs.find((l) => l.trim().startsWith("["));
    expect(jsonOutput).toBeDefined();
    const anomalies = JSON.parse(jsonOutput!);
    expect(anomalies.length).toBeGreaterThan(0);
    const spike = anomalies.find((a: { confidence: number }) => a.confidence > 0.9);
    expect(spike).toBeDefined();
    expect(spike.type).toBe("cost_spike");
    expect(spike.agent_id).toBe("agent1");
    expect(spike.description).toMatch(/\$5\.0000/);
  });

  it("skips privilege escalation detection without configured identity, and notes it", async () => {
    seedCostSpike();
    await anomaliesCommand(dir, { since: "30d" });
    expect(logs.join("\n")).toMatch(/privilege escalation detection skipped/);
  });

  it("enables privilege escalation detection when identity config is present", async () => {
    fs.writeFileSync(
      path.join(dir, ".sentinelflow-policy.yaml"),
      "version: v1\nruntime_policies:\n  identity:\n    agent_roles:\n      agent1: reader\n"
    );
    seedCostSpike();
    await anomaliesCommand(dir, { since: "30d" });
    expect(logs.join("\n")).not.toMatch(/privilege escalation detection skipped/);
  });
});
