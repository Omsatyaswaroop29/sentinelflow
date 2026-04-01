/**
 * @module @sentinelflow/core/registry/local
 *
 * JSON-file-backed local registry with atomic writes and proper error handling.
 * Lives at .sentinelflow/ in the project root.
 *
 * Design decisions:
 * - JSON files over SQLite for zero native dependencies (enterprise portability)
 * - Atomic writes via write-to-temp-then-rename (prevents corruption on crash)
 * - Typed errors throughout (no bare catch blocks)
 * - Separate files per concern (agents, reports, events) to reduce contention
 */

import * as fs from "fs";
import * as path from "path";
import type { IRegistry, RegistryQueryOptions } from "./interface";
import type { SentinelFlowAgent } from "../schema/agent";
import type { Finding, ScanReport } from "../schema/finding";
import type { AgentEvent } from "../schema/event";

const SF_DIR = ".sentinelflow";
const AGENTS_FILE = "agents.json";
const REPORTS_FILE = "reports.json";
const EVENTS_FILE = "events.json";
const MAX_REPORTS = 50;
const MAX_EVENTS = 10_000;

/**
 * Write a file atomically: write to a temp file first, then rename.
 * This prevents data corruption if the process crashes mid-write.
 */
function atomicWriteSync(filePath: string, data: string): void {
  const tmpPath = filePath + ".tmp." + process.pid;
  try {
    fs.writeFileSync(tmpPath, data, "utf-8");
    fs.renameSync(tmpPath, filePath);
  } catch (error: unknown) {
    // Clean up temp file on failure
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {
      // Ignore cleanup errors
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to write ${filePath}: ${message}`);
  }
}

/**
 * Safely read and parse a JSON file. Returns fallback value if file
 * doesn't exist or contains invalid JSON.
 */
function safeReadJSON<T>(filePath: string, fallback: T): T {
  try {
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    const raw = fs.readFileSync(filePath, "utf-8");
    if (raw.trim() === "") {
      return fallback;
    }
    return JSON.parse(raw) as T;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`Warning: Could not read ${filePath}: ${message}. Using defaults.`);
    return fallback;
  }
}

export class LocalRegistry implements IRegistry {
  private readonly basePath: string;
  private agents: Map<string, SentinelFlowAgent> = new Map();
  private reports: ScanReport[] = [];
  private events: AgentEvent[] = [];
  private initialized = false;

  constructor(projectRoot: string) {
    this.basePath = path.join(projectRoot, SF_DIR);
  }

  // ─── Lifecycle ────────────────────────────────────────────

  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Create directory if it doesn't exist
    if (!fs.existsSync(this.basePath)) {
      fs.mkdirSync(this.basePath, { recursive: true });
    }

    // Load existing data
    const agentsData = safeReadJSON<SentinelFlowAgent[]>(
      path.join(this.basePath, AGENTS_FILE),
      []
    );
    for (const agent of agentsData) {
      this.agents.set(agent.id, agent);
    }

    this.reports = safeReadJSON<ScanReport[]>(
      path.join(this.basePath, REPORTS_FILE),
      []
    );

    this.events = safeReadJSON<AgentEvent[]>(
      path.join(this.basePath, EVENTS_FILE),
      []
    );

    this.initialized = true;
  }

  async close(): Promise<void> {
    if (!this.initialized) return;
    this.persistAll();
    this.initialized = false;
  }

  // ─── Persistence ──────────────────────────────────────────

  private persistAgents(): void {
    atomicWriteSync(
      path.join(this.basePath, AGENTS_FILE),
      JSON.stringify([...this.agents.values()], null, 2)
    );
  }

  private persistReports(): void {
    atomicWriteSync(
      path.join(this.basePath, REPORTS_FILE),
      JSON.stringify(this.reports, null, 2)
    );
  }

  private persistAll(): void {
    this.persistAgents();
    this.persistReports();
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error(
        "Registry not initialized. Call initialize() before using the registry."
      );
    }
  }

  // ─── Agent CRUD ───────────────────────────────────────────

  async upsertAgent(agent: SentinelFlowAgent): Promise<void> {
    this.ensureInitialized();
    agent.updated_at = new Date().toISOString();
    this.agents.set(agent.id, agent);
    this.persistAgents();
  }

  async getAgent(id: string): Promise<SentinelFlowAgent | null> {
    this.ensureInitialized();
    return this.agents.get(id) ?? null;
  }

  async getAgentByName(
    name: string,
    framework: string
  ): Promise<SentinelFlowAgent | null> {
    this.ensureInitialized();
    for (const agent of this.agents.values()) {
      if (agent.name === name && agent.framework === framework) {
        return agent;
      }
    }
    return null;
  }

  async listAgents(options?: RegistryQueryOptions): Promise<SentinelFlowAgent[]> {
    this.ensureInitialized();
    let agents = [...this.agents.values()];

    if (options?.framework) {
      agents = agents.filter((a) => a.framework === options.framework);
    }
    if (options?.status) {
      agents = agents.filter((a) => a.governance.status === options.status);
    }
    if (options?.risk_level) {
      agents = agents.filter(
        (a) => a.governance.risk_level === options.risk_level
      );
    }
    if (options?.owner) {
      agents = agents.filter((a) => a.owner === options.owner);
    }
    if (options?.team) {
      agents = agents.filter((a) => a.team === options.team);
    }

    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? 100;
    return agents.slice(offset, offset + limit);
  }

  async deleteAgent(id: string): Promise<void> {
    this.ensureInitialized();
    if (!this.agents.has(id)) {
      throw new Error(`Agent not found: ${id}`);
    }
    this.agents.delete(id);
    this.persistAgents();
  }

  async countAgents(): Promise<number> {
    this.ensureInitialized();
    return this.agents.size;
  }

  // ─── Findings ─────────────────────────────────────────────

  async storeScanReport(report: ScanReport): Promise<void> {
    this.ensureInitialized();
    this.reports.push(report);
    // Keep only the most recent reports
    if (this.reports.length > MAX_REPORTS) {
      this.reports = this.reports.slice(-MAX_REPORTS);
    }
    this.persistReports();
  }

  async getLatestScanReport(): Promise<ScanReport | null> {
    this.ensureInitialized();
    if (this.reports.length === 0) return null;
    return this.reports[this.reports.length - 1] ?? null;
  }

  async listFindings(agentId?: string): Promise<Finding[]> {
    this.ensureInitialized();
    const latest = await this.getLatestScanReport();
    if (!latest) return [];

    if (agentId) {
      return latest.findings.filter((f) => f.agent_id === agentId);
    }
    return latest.findings;
  }

  // ─── Events (Phase 2) ────────────────────────────────────

  async ingestEvents(events: AgentEvent[]): Promise<void> {
    this.ensureInitialized();
    this.events.push(...events);
    if (this.events.length > MAX_EVENTS) {
      this.events = this.events.slice(-MAX_EVENTS);
    }
    // Events are not persisted to disk in v0.1 (in-memory only)
    // Phase 2 will add SQLite for durable event storage
  }

  async queryEvents(agentId: string, limit = 100): Promise<AgentEvent[]> {
    this.ensureInitialized();
    return this.events
      .filter((e) => e.agent_id === agentId)
      .slice(-limit);
  }
}
