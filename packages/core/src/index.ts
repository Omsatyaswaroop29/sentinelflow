// Schema exports
export * from "./schema/agent";
export * from "./schema/finding";
export * from "./schema/event";

// Registry exports
export type { IRegistry, RegistryQueryOptions } from "./registry/interface";
export { LocalRegistry } from "./registry/local";

// Event Store exports (Phase 2.2)
export {
  type GovernanceEvent,
  type GovernanceEventType,
  type EventOutcome,
  type EventSeverity,
  type DailyRollup,
  createGovernanceEvent,
  EventStoreWriter,
  type EventStoreConfig,
  EventStoreReader,
  type EventFilter,
  type TimeRange,
  type PaginationOptions,
  type AgentCostSummary,
  type ToolUsageSummary,
  type SessionSummary,
} from "./event-store/index";
