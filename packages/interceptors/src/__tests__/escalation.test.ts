/**
 * Tests for HierarchicalEscalationPolicy and its coupling with
 * EnhancedDataBoundaryPolicy.
 *
 * Required scenarios (per session brief):
 *   1. In-scope → allow, no JSONL row
 *   2. Out-of-scope WITH supervisor → escalate, JSONL row written
 *   3. Out-of-scope WITHOUT supervisor → boundary blocks
 *   4. JSONL record carries all required fields including resolved_* nulls
 *   5. Reason string names supervisor + escalation_id
 *   6. Two out-of-scope calls → two unique escalation_ids
 *   7. Compose: both policies registered → only escalate wins,
 *      only one JSONL entry
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import type { AgentEvent, IdentityContext } from "@sentinelflow/core";
import { HierarchicalEscalationPolicy, type EscalationRecord } from "../escalation";
import { EnhancedDataBoundaryPolicy } from "../data-boundary";

// ─── Test fixtures ──────────────────────────────────────────────────

let tmpDir: string;
let logPath: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sf-escalation-"));
  logPath = join(tmpDir, ".sentinelflow", "escalations.jsonl");
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function makeIdentity(overrides: Partial<IdentityContext> = {}): IdentityContext {
  return {
    human_owner: "alice@example.com",
    environment: "development",
    role: "executor",
    privilege_level: 6,
    ...overrides,
  };
}

function makeEvent(opts: {
  toolName?: string;
  inputSummary?: string;
  metadata?: Record<string, unknown>;
  identity?: IdentityContext;
  id?: string;
  session_id?: string;
  agent_id?: string;
} = {}): AgentEvent {
  return {
    id: opts.id ?? "evt_test_1",
    timestamp: new Date().toISOString(),
    agent_id: opts.agent_id ?? "claude-code-main",
    session_id: opts.session_id ?? "sess_test_1",
    type: "tool_call_start",
    tool: {
      name: opts.toolName ?? "Read",
      input_summary: opts.inputSummary,
      status: "success",
    },
    metadata: opts.metadata,
    identity: opts.identity,
  };
}

function readJsonlLines(path: string): EscalationRecord[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, "utf8").trim();
  if (!raw) return [];
  return raw.split("\n").map((line) => JSON.parse(line) as EscalationRecord);
}

// ─── 1. In-scope → allow ────────────────────────────────────────────

describe("HierarchicalEscalationPolicy — in-scope access", () => {
  it("allows when path classification is within authorized_scope", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        authorized_scope: "restricted",
        supervisor: { id: "secops-admin", email: "secops@example.com" },
      }),
    });

    const result = policy.evaluate(event);

    expect(result.decision).toBe("allow");
    expect(result.matched_policies).toEqual([]);
    expect(existsSync(logPath)).toBe(false);
  });
});

// ─── 2. Out-of-scope WITH supervisor → escalate + JSONL ─────────────

describe("HierarchicalEscalationPolicy — escalation path", () => {
  it("escalates when path exceeds authorized_scope and writes a JSONL record", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        authorized_scope: "internal",
        supervisor: { id: "secops-admin", email: "secops@example.com" },
      }),
    });

    const result = policy.evaluate(event);

    expect(result.decision).toBe("escalate");
    expect(result.matched_policies).toEqual(["hierarchical_escalation"]);

    const lines = readJsonlLines(logPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.requested_classification).toBe("restricted");
    expect(lines[0]?.authorized_scope).toBe("internal");
  });
});

// ─── 3. Out-of-scope WITHOUT supervisor → boundary blocks ───────────

describe("HierarchicalEscalationPolicy — no supervisor configured", () => {
  it("escalation no-ops and EnhancedDataBoundaryPolicy emits a clear block", () => {
    const escalation = new HierarchicalEscalationPolicy({ logPath });
    const boundary = new EnhancedDataBoundaryPolicy({
      // Force the agent's clearance to "internal" so a restricted path blocks.
      agentClearances: [{ agent: "claude-code-main", maxClassification: "internal" }],
    });

    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        authorized_scope: "internal",
        // supervisor intentionally omitted
      }),
    });

    const escResult = escalation.evaluate(event);
    expect(escResult.decision).toBe("allow");
    expect(existsSync(logPath)).toBe(false);

    const bndResult = boundary.evaluate(event);
    expect(bndResult.decision).toBe("block");
    expect(bndResult.reason).toMatch(/restricted/);
    expect(bndResult.reason).toMatch(/clearance/i);
  });
});

// ─── 4. JSONL schema (incl. resolved_* nulls) ───────────────────────

describe("HierarchicalEscalationPolicy — JSONL record schema", () => {
  it("writes all required fields including resolved_* nulls", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const event = makeEvent({
      id: "evt_42",
      session_id: "sess_42",
      agent_id: "agent-42",
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        human_owner: "alice@example.com",
        authorized_scope: "internal",
        supervisor: { id: "secops-admin", email: "secops@example.com" },
      }),
    });

    policy.evaluate(event);

    const [record] = readJsonlLines(logPath);
    expect(record).toBeDefined();
    if (!record) return;

    expect(record.schema_version).toBe(1);
    expect(record.escalation_id).toMatch(/^esc_\d+_[0-9a-f]{8}$/);
    expect(typeof record.timestamp).toBe("string");
    expect(new Date(record.timestamp).toString()).not.toBe("Invalid Date");
    expect(record.event_id).toBe("evt_42");
    expect(record.session_id).toBe("sess_42");
    expect(record.agent_id).toBe("agent-42");
    expect(record.human_owner).toBe("alice@example.com");
    expect(record.tool_name).toBe("Read");
    expect(record.requested_paths).toContain("/Users/test/.aws/credentials");
    expect(record.requested_classification).toBe("restricted");
    expect(record.requested_label).toMatch(/AWS credentials/i);
    expect(record.authorized_scope).toBe("internal");
    expect(record.supervisor).toEqual({ id: "secops-admin", email: "secops@example.com" });
    expect(record.status).toBe("pending");
    expect(record.resolved_at).toBeNull();
    expect(record.resolved_by).toBeNull();
    expect(record.resolution).toBeNull();
  });

  it("represents missing optional identity fields as null, not undefined", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: {
        environment: "development",
        role: "executor",
        privilege_level: 6,
        // no human_owner
        authorized_scope: "internal",
        supervisor: { id: "secops-admin" }, // no email
      },
    });

    policy.evaluate(event);

    const [record] = readJsonlLines(logPath);
    expect(record).toBeDefined();
    if (!record) return;
    expect(record.human_owner).toBeNull();
    expect(record.supervisor.email).toBeNull();
  });
});

// ─── 5. Reason string includes supervisor + escalation_id ───────────

describe("HierarchicalEscalationPolicy — agent-facing reason", () => {
  it("names the supervisor and includes the escalation_id", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        authorized_scope: "internal",
        supervisor: { id: "secops-admin", email: "secops@example.com" },
      }),
    });

    const result = policy.evaluate(event);
    expect(result.reason).toBeDefined();
    expect(result.reason).toMatch(/secops-admin/);
    expect(result.reason).toMatch(/esc_\d+_[0-9a-f]{8}/);

    const [record] = readJsonlLines(logPath);
    expect(record).toBeDefined();
    if (!record) return;
    expect(result.reason).toContain(record.escalation_id);
  });
});

// ─── 6. Unique escalation_ids across multiple calls ─────────────────

describe("HierarchicalEscalationPolicy — uniqueness", () => {
  it("emits a fresh escalation_id for each out-of-scope call in a session", () => {
    const policy = new HierarchicalEscalationPolicy({ logPath });
    const identity = makeIdentity({
      authorized_scope: "internal",
      supervisor: { id: "secops-admin", email: "secops@example.com" },
    });

    const event1 = makeEvent({
      id: "evt_1",
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity,
    });
    const event2 = makeEvent({
      id: "evt_2",
      toolName: "Read",
      metadata: { file_path: "/Users/test/.ssh/id_rsa" },
      identity,
    });

    const r1 = policy.evaluate(event1);
    const r2 = policy.evaluate(event2);

    expect(r1.decision).toBe("escalate");
    expect(r2.decision).toBe("escalate");

    const lines = readJsonlLines(logPath);
    expect(lines).toHaveLength(2);
    expect(lines[0]?.escalation_id).not.toEqual(lines[1]?.escalation_id);

    // And the agent-facing reasons reflect those distinct IDs.
    expect(r1.reason).toContain(lines[0]!.escalation_id);
    expect(r2.reason).toContain(lines[1]!.escalation_id);
  });
});

// ─── 7. Compose: escalate wins, only one JSONL entry ────────────────

describe("HierarchicalEscalationPolicy ↔ EnhancedDataBoundaryPolicy", () => {
  it("escalate survives precedence: boundary skips and only one JSONL row is written", () => {
    const escalation = new HierarchicalEscalationPolicy({ logPath });
    const boundary = new EnhancedDataBoundaryPolicy({
      // Even with the strictest possible config, boundary must skip when
      // identity carries both authorized_scope and supervisor.
      agentClearances: [{ agent: "claude-code-main", maxClassification: "public" }],
    });

    const event = makeEvent({
      toolName: "Read",
      metadata: { file_path: "/Users/test/.aws/credentials" },
      identity: makeIdentity({
        authorized_scope: "internal",
        supervisor: { id: "secops-admin", email: "secops@example.com" },
      }),
    });

    const escResult = escalation.evaluate(event);
    const bndResult = boundary.evaluate(event);

    expect(escResult.decision).toBe("escalate");
    expect(bndResult.decision).toBe("allow");
    expect(bndResult.matched_policies).toEqual([]);

    // Simulate the base interceptor's precedence ladder (block > escalate).
    // With boundary skipping, the only non-allow decision in the chain is
    // "escalate" — which is exactly what we want to survive.
    const decisions = [escResult.decision, bndResult.decision];
    const winning =
      decisions.includes("block") ? "block" :
      decisions.includes("escalate") ? "escalate" :
      "allow";
    expect(winning).toBe("escalate");

    const lines = readJsonlLines(logPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.requested_classification).toBe("restricted");
  });
});
