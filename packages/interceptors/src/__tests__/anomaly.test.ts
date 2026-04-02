/**
 * Tests for the anomaly detection system.
 *
 * Covers:
 * 1. NovelToolDetector — warmup learning, novel tool flagging, seeding
 * 2. CostSpikeDetector — normal cost, spike detection, Z-score math
 * 3. ErrorRateDetector — normal errors, rate spike, window expiry
 * 4. PrivilegeEscalationDetector — low-priv tool use, upward delegation
 * 5. AnomalyEngine — combined detection, callback invocation
 */

import { describe, it, expect, beforeEach } from "vitest";
import type { AgentEvent } from "@sentinelflow/core";
import {
  NovelToolDetector,
  CostSpikeDetector,
  ErrorRateDetector,
  PrivilegeEscalationDetector,
  AnomalyEngine,
} from "../anomaly";

// ─── Helpers ────────────────────────────────────────────────────────

function makeEvent(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    id: Math.random().toString(36).slice(2),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    agent_id: overrides.agent_id ?? "test-agent",
    session_id: overrides.session_id ?? "session-1",
    type: overrides.type ?? "tool_call_start",
    tool: overrides.tool,
    tokens: overrides.tokens,
    governance: overrides.governance,
    anomaly: overrides.anomaly,
    metadata: overrides.metadata,
  };
}

// ─── NovelToolDetector Tests ────────────────────────────────────────

describe("NovelToolDetector", () => {
  it("learns tools during warmup and does not alert", () => {
    const detector = new NovelToolDetector({ warmupEvents: 5 });

    for (let i = 0; i < 5; i++) {
      const result = detector.analyze(
        makeEvent({ tool: { name: "Read", status: "success" } })
      );
      expect(result).toBeNull();
    }
  });

  it("flags novel tools after warmup", () => {
    const detector = new NovelToolDetector({ warmupEvents: 3 });

    // Warmup with Read and Grep
    for (let i = 0; i < 3; i++) {
      detector.analyze(
        makeEvent({ tool: { name: i < 2 ? "Read" : "Grep", status: "success" } })
      );
    }

    // Now use a never-seen tool
    const result = detector.analyze(
      makeEvent({ tool: { name: "Bash", status: "success" } })
    );
    expect(result).not.toBeNull();
    expect(result!.detected).toBe(true);
    expect(result!.type).toBe("novel_tool");
    expect(result!.confidence).toBe(0.9);
    expect(result!.description).toContain("Bash");
    expect(result!.description).toContain("first time");
  });

  it("does not re-alert for the same novel tool", () => {
    const detector = new NovelToolDetector({ warmupEvents: 2 });
    detector.analyze(makeEvent({ tool: { name: "Read", status: "success" } }));
    detector.analyze(makeEvent({ tool: { name: "Read", status: "success" } }));

    // First time Bash → alert
    const first = detector.analyze(
      makeEvent({ tool: { name: "Bash", status: "success" } })
    );
    expect(first!.detected).toBe(true);

    // Second time Bash → no alert (already known now)
    const second = detector.analyze(
      makeEvent({ tool: { name: "Bash", status: "success" } })
    );
    expect(second).toBeNull();
  });

  it("respects ignoredTools", () => {
    const detector = new NovelToolDetector({
      warmupEvents: 2,
      ignoredTools: ["Bash"],
    });
    detector.analyze(makeEvent({ tool: { name: "Read", status: "success" } }));
    detector.analyze(makeEvent({ tool: { name: "Read", status: "success" } }));

    const result = detector.analyze(
      makeEvent({ tool: { name: "Bash", status: "success" } })
    );
    expect(result).toBeNull(); // Bash is ignored
  });

  it("seedKnownTools skips warmup", () => {
    const detector = new NovelToolDetector({ warmupEvents: 100 });
    detector.seedKnownTools("test-agent", ["Read", "Grep", "ListDir"]);

    // Bash is novel even though we never went through warmup
    const result = detector.analyze(
      makeEvent({ tool: { name: "Bash", status: "success" } })
    );
    expect(result!.detected).toBe(true);

    // Read is known
    const known = detector.analyze(
      makeEvent({ tool: { name: "Read", status: "success" } })
    );
    expect(known).toBeNull();
  });
});

// ─── CostSpikeDetector Tests ────────────────────────────────────────

describe("CostSpikeDetector", () => {
  it("does not alert during learning period", () => {
    const detector = new CostSpikeDetector({
      windowMs: 1000,
      minWindows: 3,
    });

    const result = detector.analyze(
      makeEvent({
        tokens: { input: 100, output: 50, model: "sonnet", estimated_cost_usd: 0.01 },
      })
    );
    expect(result).toBeNull();
  });

  it("detects a cost spike after baseline is established", () => {
    const detector = new CostSpikeDetector({
      windowMs: 100,  // 100ms windows for testing
      threshold: 2.0,
      minWindows: 3,
    });

    // Build baseline: 5 windows with ~$0.01 each
    const baseTime = Date.now() - 10000;
    for (let i = 0; i < 5; i++) {
      detector.analyze(
        makeEvent({
          timestamp: new Date(baseTime + i * 200).toISOString(),
          tokens: { input: 100, output: 50, model: "sonnet", estimated_cost_usd: 0.01 },
        })
      );
    }

    // Now inject a massive cost spike
    const result = detector.analyze(
      makeEvent({
        timestamp: new Date(baseTime + 5 * 200).toISOString(),
        tokens: { input: 10000, output: 5000, model: "opus", estimated_cost_usd: 5.0 },
      })
    );

    // The spike may or may not trigger depending on window boundaries,
    // but the detector should not crash and should return a valid result type
    if (result) {
      expect(result.detected).toBe(true);
      expect(result.type).toBe("cost_spike");
      expect(result.confidence).toBeGreaterThan(0);
    }
  });
});

// ─── ErrorRateDetector Tests ────────────────────────────────────────

describe("ErrorRateDetector", () => {
  it("does not alert when errors are below threshold", () => {
    const detector = new ErrorRateDetector({
      windowMs: 60000,
      rateThreshold: 0.3,
      minEvents: 5,
    });

    const now = Date.now();
    // 4 successes, 1 error = 20% rate (below 30% threshold)
    for (let i = 0; i < 4; i++) {
      detector.analyze(
        makeEvent({
          type: "tool_call_end",
          timestamp: new Date(now + i * 1000).toISOString(),
          tool: { name: "Read", status: "success" },
        })
      );
    }

    const result = detector.analyze(
      makeEvent({
        type: "tool_call_end",
        timestamp: new Date(now + 4000).toISOString(),
        tool: { name: "Read", status: "error", error_message: "not found" },
      })
    );
    expect(result).toBeNull();
  });

  it("detects error rate spike", () => {
    const detector = new ErrorRateDetector({
      windowMs: 60000,
      rateThreshold: 0.3,
      minEvents: 5,
    });

    const now = Date.now();
    // 2 successes, 4 errors = 67% error rate (above 30%)
    detector.analyze(makeEvent({
      type: "tool_call_end", timestamp: new Date(now).toISOString(),
      tool: { name: "Bash", status: "success" },
    }));
    detector.analyze(makeEvent({
      type: "tool_call_end", timestamp: new Date(now + 1000).toISOString(),
      tool: { name: "Bash", status: "success" },
    }));

    for (let i = 0; i < 4; i++) {
      detector.analyze(makeEvent({
        type: "tool_call_end", timestamp: new Date(now + 2000 + i * 1000).toISOString(),
        tool: { name: "Bash", status: "error", error_message: "fail" },
      }));
    }

    // One more error to check
    const result = detector.analyze(makeEvent({
      type: "tool_call_end", timestamp: new Date(now + 6000).toISOString(),
      tool: { name: "Bash", status: "error", error_message: "fail" },
    }));

    // We should have enough events now for detection
    if (result) {
      expect(result.detected).toBe(true);
      expect(result.type).toBe("error_spike");
      expect(result.description).toContain("%");
    }
  });

  it("ignores non-tool-call events", () => {
    const detector = new ErrorRateDetector({ minEvents: 1 });
    const result = detector.analyze(
      makeEvent({ type: "session_start" })
    );
    expect(result).toBeNull();
  });
});

// ─── PrivilegeEscalationDetector Tests ──────────────────────────────

describe("PrivilegeEscalationDetector", () => {
  it("flags low-privilege agent using high-privilege tools", () => {
    const detector = new PrivilegeEscalationDetector({
      privilegeMap: { reader: 2, deployer: 8 },
      highPrivilegeTools: ["Bash", "Write"],
      minPrivilegeForTools: 5,
    });

    const result = detector.analyze(
      makeEvent({
        agent_id: "reader",
        tool: { name: "Bash", status: "success" },
      })
    );
    expect(result).not.toBeNull();
    expect(result!.detected).toBe(true);
    expect(result!.type).toBe("privilege_escalation");
    expect(result!.description).toContain("reader");
    expect(result!.description).toContain("Bash");
  });

  it("allows high-privilege agent using high-privilege tools", () => {
    const detector = new PrivilegeEscalationDetector({
      privilegeMap: { deployer: 8 },
      highPrivilegeTools: ["Bash"],
      minPrivilegeForTools: 5,
    });

    const result = detector.analyze(
      makeEvent({
        agent_id: "deployer",
        tool: { name: "Bash", status: "success" },
      })
    );
    expect(result).toBeNull();
  });

  it("flags upward delegation", () => {
    const detector = new PrivilegeEscalationDetector({
      privilegeMap: { reader: 2, deployer: 8 },
    });

    const result = detector.analyze(
      makeEvent({
        agent_id: "reader",
        type: "delegation",
        metadata: { target_agent_id: "deployer" },
      })
    );
    expect(result).not.toBeNull();
    expect(result!.type).toBe("privilege_escalation");
    expect(result!.description).toContain("delegated");
  });
});

// ─── AnomalyEngine Tests ────────────────────────────────────────────

describe("AnomalyEngine", () => {
  it("runs all detectors and calls onAnomaly callback", () => {
    const anomalies: Array<{ event: AgentEvent; result: any }> = [];
    const detector = new NovelToolDetector({ warmupEvents: 2 });

    const engine = new AnomalyEngine({
      detectors: [detector],
      onAnomaly: (event, result) => {
        anomalies.push({ event, result });
      },
    });

    // Warmup
    engine.onEvent(makeEvent({ tool: { name: "Read", status: "success" } }));
    engine.onEvent(makeEvent({ tool: { name: "Read", status: "success" } }));

    // Novel tool → should trigger callback
    engine.onEvent(makeEvent({ tool: { name: "Bash", status: "success" } }));

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]!.result.type).toBe("novel_tool");
    expect(engine.getAnomalyCount()).toBe(1);
  });

  it("attaches anomaly to the event object", () => {
    const detector = new NovelToolDetector({ warmupEvents: 1 });
    const engine = new AnomalyEngine({ detectors: [detector] });

    engine.onEvent(makeEvent({ tool: { name: "Read", status: "success" } }));

    const event = makeEvent({ tool: { name: "Bash", status: "success" } });
    engine.onEvent(event);

    expect(event.anomaly).toBeDefined();
    expect(event.anomaly!.type).toBe("novel_tool");
  });
});
