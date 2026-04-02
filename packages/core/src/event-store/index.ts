/**
 * @module @sentinelflow/core/event-store
 *
 * The governance event store — an append-only ledger of everything
 * AI agents do at runtime, optimized for governance queries.
 *
 * Architecture:
 *
 *   ┌─────────────────┐     ┌──────────────┐     ┌──────────────────┐
 *   │  Interceptors    │────▶│ EventStore   │────▶│  Dashboard /     │
 *   │  (Claude Code,   │     │ Writer       │     │  Anomaly Det /   │
 *   │   LangChain)     │     │ (append-only)│     │  CLI queries     │
 *   └─────────────────┘     └──────┬───────┘     └──────────────────┘
 *                                  │                       ▲
 *                                  │                       │
 *                           ┌──────▼───────┐     ┌────────┴─────────┐
 *                           │   events     │     │  EventStore      │
 *                           │   (raw,      │────▶│  Reader          │
 *                           │    immutable) │     │  (query API)     │
 *                           └──────┬───────┘     └──────────────────┘
 *                                  │
 *                           ┌──────▼───────┐
 *                           │ daily_rollups│
 *                           │ (precomputed │
 *                           │  aggregates) │
 *                           └──────────────┘
 *
 * Usage:
 *
 *   // Writer (interceptor side)
 *   const writer = new EventStoreWriter({ projectDir: "./my-project" });
 *   writer.ingest(createGovernanceEvent({
 *     agent_id: "security-auditor",
 *     framework: "claude_code",
 *     session_id: "session-123",
 *     event_type: "tool_call_blocked",
 *     outcome: "blocked",
 *     severity: "high",
 *     tool_name: "Bash",
 *     action: "rm -rf /tmp/build",
 *     policy_id: "AC-005",
 *   }));
 *   writer.flush();
 *   writer.computeTodayRollup();
 *   writer.close();
 *
 *   // Reader (dashboard / CLI side)
 *   const reader = new EventStoreReader({ projectDir: "./my-project" });
 *   const blocked = reader.getBlockedToolCalls("2026-04-01");
 *   const costs = reader.getTokenSpendByAgent({ since: "2026-03-01" });
 *   const sessions = reader.getSessionSummaries("security-auditor");
 *   reader.close();
 */

// Event envelope contract
export {
  type GovernanceEvent,
  type GovernanceEventType,
  type EventOutcome,
  type EventSeverity,
  type DailyRollup,
  createGovernanceEvent,
} from "./schema";

// Writer (append-only, batch inserts, WAL mode)
export {
  EventStoreWriter,
  type EventStoreConfig,
} from "./writer";

// Reader (query API with governance-specific methods)
export {
  EventStoreReader,
  type EventFilter,
  type TimeRange,
  type PaginationOptions,
  type AgentCostSummary,
  type ToolUsageSummary,
  type SessionSummary,
} from "./queries";
