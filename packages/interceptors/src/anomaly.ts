/**
 * @module @sentinelflow/interceptors/anomaly
 *
 * Anomaly detection for AI agent governance.
 *
 * This module provides pattern-based detectors that analyze the event stream
 * and flag unusual agent behavior. Each detector answers a specific governance
 * question:
 *
 *   NovelToolDetector:     "Is this agent using a tool it's never used before?"
 *   CostSpikeDetector:     "Is this agent spending significantly more than usual?"
 *   ErrorRateDetector:     "Is this agent failing more than normal?"
 *   PrivilegeEscalation:   "Is this agent delegating to a higher-privilege agent?"
 *
 * Architecture:
 *
 *   Detectors are stateful — they maintain a sliding window of recent events
 *   to build baselines. They can be fed events in two ways:
 *
 *   1. As an EventListener plugged into the interceptor pipeline (real-time)
 *   2. By loading historical events from the EventStoreReader (backfill)
 *
 *   When a detector flags an anomaly, it returns an AnomalyResult that gets
 *   attached to the event and forwarded to alert channels.
 *
 * Design principles:
 *
 *   - Simple statistics first. We use moving averages and standard deviations,
 *     not ML models. This keeps the system deterministic, explainable, and
 *     auditable — all properties that governance systems need.
 *
 *   - Every anomaly has a confidence score (0-1) and a human-readable
 *     description. No opaque "anomaly score 0.73" without context.
 *
 *   - False positive tuning is built in. Each detector has configurable
 *     thresholds and warmup periods (don't alert until baseline is stable).
 */

import type { AgentEvent, AnomalyResult, AnomalyType } from "@sentinelflow/core";
import type { EventListener } from "./interface";

// ─── Detector Interface ─────────────────────────────────────────────

export interface AnomalyDetector {
  /** Human-readable name */
  readonly name: string;
  /** What type of anomaly this detects */
  readonly type: AnomalyType;
  /**
   * Analyze an event and return an anomaly result if detected.
   * Returns null if no anomaly is found (the common case).
   */
  analyze(event: AgentEvent): AnomalyResult | null;
  /** Reset internal state (for testing or recalibration) */
  reset(): void;
}

// ─── 1. Novel Tool Detector ─────────────────────────────────────────

/**
 * Detects when an agent uses a tool it has never used before during
 * its baseline period. This catches prompt injection attacks that
 * convince an agent to call unexpected tools, and detects configuration
 * drift where an agent's tool access expands silently.
 *
 * How it works:
 *   - Maintains a set of "known tools" per agent from the warmup period
 *   - After warmup, any tool call not in the known set triggers an anomaly
 *   - Confidence is 0.9 (high) because novel tools are a strong signal
 *
 * Tuning:
 *   - warmupEvents: How many events to observe before alerting (default: 50)
 *   - ignoredTools: Tools that should never trigger (e.g., Read, ListDir)
 */
export class NovelToolDetector implements AnomalyDetector {
  readonly name = "novel_tool";
  readonly type: AnomalyType = "novel_tool";

  private knownTools: Map<string, Set<string>> = new Map();  // agent_id → tools
  private eventCounts: Map<string, number> = new Map();       // agent_id → count
  private warmupEvents: number;
  private ignoredTools: Set<string>;

  constructor(opts?: { warmupEvents?: number; ignoredTools?: string[] }) {
    this.warmupEvents = opts?.warmupEvents ?? 50;
    this.ignoredTools = new Set(opts?.ignoredTools ?? []);
  }

  analyze(event: AgentEvent): AnomalyResult | null {
    if (!event.tool?.name) return null;

    const agentId = event.agent_id;
    const toolName = event.tool.name;

    // Skip ignored tools
    if (this.ignoredTools.has(toolName)) return null;

    // Initialize tracking for new agents
    if (!this.knownTools.has(agentId)) {
      this.knownTools.set(agentId, new Set());
      this.eventCounts.set(agentId, 0);
    }

    const known = this.knownTools.get(agentId)!;
    const count = (this.eventCounts.get(agentId) ?? 0) + 1;
    this.eventCounts.set(agentId, count);

    // During warmup: learn the baseline
    if (count <= this.warmupEvents) {
      known.add(toolName);
      return null;
    }

    // After warmup: detect novel tools
    if (!known.has(toolName)) {
      known.add(toolName); // Add it so we only alert once per novel tool
      return {
        detected: true,
        type: "novel_tool",
        confidence: 0.9,
        description:
          `Agent "${agentId}" used tool "${toolName}" for the first time ` +
          `(not seen in first ${this.warmupEvents} events). ` +
          `Known tools: ${[...this.knownTools.get(agentId)!].filter(t => t !== toolName).join(", ")}`,
      };
    }

    return null;
  }

  reset(): void {
    this.knownTools.clear();
    this.eventCounts.clear();
  }

  /** Pre-seed known tools for an agent (from historical data) */
  seedKnownTools(agentId: string, tools: string[]): void {
    this.knownTools.set(agentId, new Set(tools));
    this.eventCounts.set(agentId, this.warmupEvents + 1); // Skip warmup
  }
}

// ─── 2. Cost Spike Detector ─────────────────────────────────────────

/**
 * Detects when an agent's cost per time window is significantly higher
 * than its historical average. Uses a simple moving average + standard
 * deviation approach (Z-score).
 *
 * How it works:
 *   - Tracks cost per sliding window (default: 5 minutes)
 *   - Maintains a running mean and standard deviation of window costs
 *   - Flags when current window cost exceeds mean + (threshold * stdev)
 *
 * Tuning:
 *   - windowMs: Size of the sliding window (default: 5 min)
 *   - threshold: Number of standard deviations to trigger (default: 2.0)
 *   - minWindows: Minimum windows before alerting (default: 5)
 */
export class CostSpikeDetector implements AnomalyDetector {
  readonly name = "cost_spike";
  readonly type: AnomalyType = "cost_spike";

  private windowMs: number;
  private threshold: number;
  private minWindows: number;

  // Per-agent tracking
  private windowCosts: Map<string, number[]> = new Map();     // agent → historical window costs
  private currentWindow: Map<string, { start: number; cost: number }> = new Map();

  constructor(opts?: {
    windowMs?: number;
    threshold?: number;
    minWindows?: number;
  }) {
    this.windowMs = opts?.windowMs ?? 5 * 60 * 1000; // 5 minutes
    this.threshold = opts?.threshold ?? 2.0;
    this.minWindows = opts?.minWindows ?? 5;
  }

  analyze(event: AgentEvent): AnomalyResult | null {
    if (!event.tokens?.estimated_cost_usd) return null;

    const agentId = event.agent_id;
    const cost = event.tokens.estimated_cost_usd;
    const now = new Date(event.timestamp).getTime();

    // Initialize tracking
    if (!this.currentWindow.has(agentId)) {
      this.currentWindow.set(agentId, { start: now, cost: 0 });
      this.windowCosts.set(agentId, []);
    }

    const window = this.currentWindow.get(agentId)!;
    const history = this.windowCosts.get(agentId)!;

    // Check if we've moved past the current window
    if (now - window.start >= this.windowMs) {
      // Close the current window and record its cost
      history.push(window.cost);

      // Keep only last 100 windows to bound memory
      if (history.length > 100) {
        history.shift();
      }

      // Start a new window
      this.currentWindow.set(agentId, { start: now, cost });
    } else {
      // Accumulate cost in the current window
      window.cost += cost;
    }

    // Need enough history to compute statistics
    if (history.length < this.minWindows) return null;

    // Compute Z-score of current window cost
    const mean = history.reduce((a, b) => a + b, 0) / history.length;
    const variance =
      history.reduce((sum, val) => sum + (val - mean) ** 2, 0) / history.length;
    const stdev = Math.sqrt(variance);

    // Avoid division by zero (all windows had same cost)
    if (stdev === 0) return null;

    const currentCost = this.currentWindow.get(agentId)!.cost;
    const zScore = (currentCost - mean) / stdev;

    if (zScore > this.threshold) {
      const confidence = Math.min(0.95, 0.5 + (zScore - this.threshold) * 0.15);
      return {
        detected: true,
        type: "cost_spike",
        confidence,
        description:
          `Agent "${agentId}" cost spike: $${currentCost.toFixed(4)} in current window ` +
          `vs $${mean.toFixed(4)} average (${zScore.toFixed(1)}σ above mean). ` +
          `Threshold: ${this.threshold}σ.`,
      };
    }

    return null;
  }

  reset(): void {
    this.windowCosts.clear();
    this.currentWindow.clear();
  }
}

// ─── 3. Error Rate Detector ─────────────────────────────────────────

/**
 * Detects when an agent's error rate exceeds a threshold within a
 * sliding time window. A sudden burst of errors often indicates
 * misconfiguration, broken tools, or an adversarial input causing
 * repeated tool failures.
 *
 * How it works:
 *   - Tracks tool call outcomes in a sliding time window
 *   - Computes error rate = errors / total within the window
 *   - Flags when rate exceeds threshold
 *
 * Tuning:
 *   - windowMs: Sliding window size (default: 5 min)
 *   - rateThreshold: Error rate to trigger (default: 0.3 = 30%)
 *   - minEvents: Minimum events in window to alert (default: 5)
 */
export class ErrorRateDetector implements AnomalyDetector {
  readonly name = "error_rate";
  readonly type: AnomalyType = "error_spike";

  private windowMs: number;
  private rateThreshold: number;
  private minEvents: number;

  // Per-agent sliding window of (timestamp, isError) pairs
  private windows: Map<string, Array<{ ts: number; isError: boolean }>> = new Map();

  constructor(opts?: {
    windowMs?: number;
    rateThreshold?: number;
    minEvents?: number;
  }) {
    this.windowMs = opts?.windowMs ?? 5 * 60 * 1000;
    this.rateThreshold = opts?.rateThreshold ?? 0.3;
    this.minEvents = opts?.minEvents ?? 5;
  }

  analyze(event: AgentEvent): AnomalyResult | null {
    // Only track tool call outcomes
    if (
      event.type !== "tool_call_end" &&
      event.type !== "tool_call_blocked"
    ) {
      return null;
    }

    const agentId = event.agent_id;
    const now = new Date(event.timestamp).getTime();
    const isError = event.tool?.status === "error";

    if (!this.windows.has(agentId)) {
      this.windows.set(agentId, []);
    }

    const window = this.windows.get(agentId)!;

    // Add current event
    window.push({ ts: now, isError });

    // Evict events outside the window
    const cutoff = now - this.windowMs;
    while (window.length > 0 && window[0]!.ts < cutoff) {
      window.shift();
    }

    // Need enough events to compute a meaningful rate
    if (window.length < this.minEvents) return null;

    const errorCount = window.filter((e) => e.isError).length;
    const rate = errorCount / window.length;

    if (rate >= this.rateThreshold) {
      return {
        detected: true,
        type: "error_spike",
        confidence: Math.min(0.95, 0.6 + rate * 0.3),
        description:
          `Agent "${agentId}" error rate spike: ${(rate * 100).toFixed(0)}% ` +
          `(${errorCount}/${window.length} calls failed in last ` +
          `${Math.round(this.windowMs / 60000)} minutes). ` +
          `Threshold: ${(this.rateThreshold * 100).toFixed(0)}%.`,
      };
    }

    return null;
  }

  reset(): void {
    this.windows.clear();
  }
}

// ─── 4. Privilege Escalation Detector ───────────────────────────────

/**
 * Detects when an agent delegates to or interacts with a higher-privilege
 * agent. This catches scenarios where a low-privilege "reader" agent
 * somehow triggers actions on a high-privilege "deployer" agent.
 *
 * How it works:
 *   - Maintains a privilege map: agent_id → privilege level (1-10)
 *   - On delegation events, checks if target has higher privilege
 *   - Also flags tool calls that match high-privilege tool patterns
 *     (e.g., a "reader" agent calling Write or Bash)
 *
 * Tuning:
 *   - privilegeMap: agent_id → level (higher = more privileged)
 *   - highPrivilegeTools: tools that only high-privilege agents should use
 *   - minPrivilegeForTools: minimum privilege level to use high-risk tools
 */
export class PrivilegeEscalationDetector implements AnomalyDetector {
  readonly name = "privilege_escalation";
  readonly type: AnomalyType = "privilege_escalation";

  private privilegeMap: Map<string, number>;
  private highPrivilegeTools: Set<string>;
  private minPrivilegeForTools: number;

  constructor(opts?: {
    privilegeMap?: Record<string, number>;
    highPrivilegeTools?: string[];
    minPrivilegeForTools?: number;
  }) {
    this.privilegeMap = new Map(
      Object.entries(opts?.privilegeMap ?? {})
    );
    this.highPrivilegeTools = new Set(
      opts?.highPrivilegeTools ?? ["Bash", "Write", "MultiEdit", "NotebookEdit"]
    );
    this.minPrivilegeForTools = opts?.minPrivilegeForTools ?? 5;
  }

  analyze(event: AgentEvent): AnomalyResult | null {
    const agentId = event.agent_id;
    const agentPrivilege = this.privilegeMap.get(agentId) ?? 3; // Default: medium

    // Check 1: Low-privilege agent using high-privilege tools
    if (
      event.tool?.name &&
      this.highPrivilegeTools.has(event.tool.name) &&
      agentPrivilege < this.minPrivilegeForTools
    ) {
      return {
        detected: true,
        type: "privilege_escalation",
        confidence: 0.85,
        description:
          `Agent "${agentId}" (privilege ${agentPrivilege}) used high-privilege tool ` +
          `"${event.tool.name}" (requires privilege ${this.minPrivilegeForTools}+). ` +
          `This may indicate privilege escalation.`,
      };
    }

    // Check 2: Delegation to a higher-privilege agent
    if (event.type === "delegation" && event.metadata) {
      const targetAgentId = event.metadata.target_agent_id as string | undefined;
      if (targetAgentId) {
        const targetPrivilege = this.privilegeMap.get(targetAgentId) ?? 3;
        if (targetPrivilege > agentPrivilege) {
          return {
            detected: true,
            type: "privilege_escalation",
            confidence: 0.8,
            description:
              `Agent "${agentId}" (privilege ${agentPrivilege}) delegated to ` +
              `"${targetAgentId}" (privilege ${targetPrivilege}). ` +
              `Upward delegation may indicate privilege escalation.`,
          };
        }
      }
    }

    return null;
  }

  reset(): void {
    // Privilege map is configuration, not state — don't clear it
  }

  /** Update the privilege map dynamically */
  setPrivilege(agentId: string, level: number): void {
    this.privilegeMap.set(agentId, level);
  }
}

// ─── Anomaly Engine (combines all detectors) ────────────────────────

/**
 * The AnomalyEngine combines all detectors and plugs into the interceptor
 * pipeline as an EventListener. For every event, it runs all detectors
 * and attaches anomaly results to the event.
 *
 * Usage:
 *   const engine = new AnomalyEngine({
 *     detectors: [
 *       new NovelToolDetector(),
 *       new CostSpikeDetector(),
 *       new ErrorRateDetector(),
 *       new PrivilegeEscalationDetector({ privilegeMap: { reader: 2, deployer: 8 } }),
 *     ],
 *     onAnomaly: (event, result) => {
 *       console.log(`ANOMALY: ${result.description}`);
 *     },
 *   });
 *
 *   interceptor.addListener(engine);
 */
export class AnomalyEngine implements EventListener {
  readonly name = "anomaly_engine";

  private detectors: AnomalyDetector[];
  private onAnomaly?: (event: AgentEvent, result: AnomalyResult) => void;
  private anomalyCount = 0;

  constructor(opts: {
    detectors: AnomalyDetector[];
    onAnomaly?: (event: AgentEvent, result: AnomalyResult) => void;
  }) {
    this.detectors = opts.detectors;
    this.onAnomaly = opts.onAnomaly;
  }

  onEvent(event: AgentEvent): void {
    for (const detector of this.detectors) {
      try {
        const result = detector.analyze(event);
        if (result?.detected) {
          // Attach anomaly to the event (mutating in place is intentional —
          // the event flows to downstream listeners with the anomaly attached)
          event.anomaly = result;
          this.anomalyCount++;

          // Call the anomaly callback
          this.onAnomaly?.(event, result);

          // Only one anomaly per event (the first detected wins)
          break;
        }
      } catch {
        // Never crash on detector failure — detectors are advisory
      }
    }
  }

  getAnomalyCount(): number {
    return this.anomalyCount;
  }

  resetAll(): void {
    for (const detector of this.detectors) {
      detector.reset();
    }
    this.anomalyCount = 0;
  }
}
