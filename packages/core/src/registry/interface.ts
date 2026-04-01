/**
 * @module @sentinelflow/core/registry
 *
 * The agent registry stores discovered agents, scan findings, and
 * telemetry events. The interface allows swapping between local
 * SQLite (for individual developers) and Postgres/cloud (for teams).
 */

import type { SentinelFlowAgent, GovernanceStatus, RiskLevel } from "../schema/agent";
import type { Finding, ScanReport } from "../schema/finding";
import type { AgentEvent } from "../schema/event";

export interface RegistryQueryOptions {
  framework?: string;
  status?: GovernanceStatus;
  risk_level?: RiskLevel;
  owner?: string;
  team?: string;
  limit?: number;
  offset?: number;
}

export interface IRegistry {
  // ─── Agent CRUD ───────────────────────────────────────────
  upsertAgent(agent: SentinelFlowAgent): Promise<void>;
  getAgent(id: string): Promise<SentinelFlowAgent | null>;
  getAgentByName(name: string, framework: string): Promise<SentinelFlowAgent | null>;
  listAgents(options?: RegistryQueryOptions): Promise<SentinelFlowAgent[]>;
  deleteAgent(id: string): Promise<void>;
  countAgents(): Promise<number>;

  // ─── Findings ─────────────────────────────────────────────
  storeScanReport(report: ScanReport): Promise<void>;
  getLatestScanReport(): Promise<ScanReport | null>;
  listFindings(agentId?: string): Promise<Finding[]>;

  // ─── Events (Phase 2) ────────────────────────────────────
  ingestEvents(events: AgentEvent[]): Promise<void>;
  queryEvents(agentId: string, limit?: number): Promise<AgentEvent[]>;

  // ─── Lifecycle ────────────────────────────────────────────
  initialize(): Promise<void>;
  close(): Promise<void>;
}
