/**
 * @module @sentinelflow/core/schema/agent
 *
 * The universal agent identity schema. Every AI agent — regardless of
 * framework — gets normalized into this format when registered with
 * SentinelFlow.
 *
 * Design influences:
 * - ECC's agent YAML frontmatter (name, description, tools, model)
 * - Ruflo's agent YAML schema (type, permissions, swarm_role)
 * - Microsoft Entra Agent ID (unique identity, lifecycle governance)
 * - Forrester's Agent Control Plane definition (inventory, govern, orchestrate, assure)
 */

// ─── Agent Frameworks ───────────────────────────────────────────────

export type AgentFramework =
  | "claude-code"
  | "cursor"
  | "codex"
  | "opencode"
  | "kiro"
  | "langchain"
  | "langgraph"
  | "crewai"
  | "autogen"
  | "copilot-studio"
  | "agentforce"
  | "bedrock-agents"
  | "vertex-agents"
  | "custom"
  | "unknown";

// ─── Governance Types ───────────────────────────────────────────────

export type GovernanceStatus =
  | "discovered"    // Auto-discovered, not yet reviewed
  | "registered"    // Added to registry, pending approval
  | "approved"      // Approved for production use
  | "restricted"    // Approved with limitations
  | "suspended"     // Temporarily disabled
  | "archived"      // Decommissioned
  | "shadow";       // Discovered but not sanctioned (shadow AI)

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type SwarmRole =
  | "orchestrator"  // Coordinates other agents
  | "worker"        // Executes delegated tasks
  | "reviewer"      // Reviews work of other agents
  | "specialist"    // Domain-specific expert agent
  | "standalone";   // Operates independently

export type TopologyType =
  | "hierarchical"  // Tree structure with clear delegation
  | "mesh"          // Peer-to-peer collaboration
  | "ring"          // Sequential pipeline
  | "star"          // Central coordinator with workers
  | "standalone";   // Single agent, no coordination

export type DataClassification =
  | "pii"           // Personally Identifiable Information
  | "phi"           // Protected Health Information
  | "financial"     // Financial data (PCI-DSS scope)
  | "legal"         // Legal/privileged information
  | "confidential"  // Business confidential
  | "internal"      // Internal use only
  | "public"        // Public information
  | "unknown";      // Not yet classified

// ─── Sub-interfaces ─────────────────────────────────────────────────

export interface AgentTool {
  name: string;
  type:
    | "bash"
    | "file_read"
    | "file_write"
    | "web_search"
    | "web_fetch"
    | "api_call"
    | "database"
    | "mcp"
    | "code_execution"
    | "custom";
  risk_level?: RiskLevel;
  description?: string;
}

export interface MCPServer {
  name: string;
  url?: string;
  tools_exposed?: string[];
  risk_level?: RiskLevel;
}

export interface DataSource {
  name: string;
  type: "database" | "api" | "file_system" | "cloud_storage" | "saas" | "unknown";
  classification?: DataClassification[];
  access_level?: "read" | "write" | "admin";
}

export interface FileAccess {
  read_paths?: string[];
  write_paths?: string[];
  blocked_paths?: string[];
}

export interface NetworkAccess {
  allowed_domains?: string[];
  blocked_domains?: string[];
  unrestricted?: boolean;
}

export interface ModelRoute {
  condition: string;
  model: string;
  tier: number;
  estimated_cost_per_1k_tokens?: number;
}

export interface TokenBudget {
  monthly_limit?: number;
  daily_limit?: number;
  current_usage?: number;
  cost_estimate_usd?: number;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ─── Governance Metadata ────────────────────────────────────────────

export interface GovernanceMetadata {
  status: GovernanceStatus;
  risk_level?: RiskLevel;
  compliance_tags?: string[];
  last_scan?: string;
  last_audit?: string;
  findings_count?: FindingsCount;
  approved_by?: string;
  approval_date?: string;
  policies_applied?: string[];
  token_budget?: TokenBudget;
}

// ─── Runtime Metadata (populated by Phase 2 interceptors) ───────────

export interface RuntimeMetadata {
  last_active?: string;
  total_invocations?: number;
  avg_latency_ms?: number;
  error_rate?: number;
  tokens_consumed_30d?: number;
  cost_30d_usd?: number;
  anomalies_detected?: number;
  tools_used_30d?: string[];
  novel_tool_calls?: string[];
}

// ─── The Universal Agent Identity ───────────────────────────────────

export interface SentinelFlowAgent {
  // Identity
  id: string;
  name: string;
  description: string;
  framework: AgentFramework;
  framework_id?: string;

  // Ownership
  owner?: string;
  team?: string;
  created_at: string;
  updated_at: string;
  source_file?: string;
  repository?: string;

  // Capabilities
  tools: AgentTool[];
  allowed_tools?: string[];
  blocked_tools?: string[];
  model?: string;
  model_routing?: ModelRoute[];
  mcp_servers?: MCPServer[];

  // Data Access
  data_sources: DataSource[];
  data_classification?: DataClassification[];
  file_system_access?: FileAccess;
  network_access?: NetworkAccess;

  // Relationships
  delegates_to?: string[];
  delegated_from?: string[];
  swarm_role?: SwarmRole;
  topology?: TopologyType;

  // Governance
  governance: GovernanceMetadata;

  // Runtime (Phase 2)
  runtime?: RuntimeMetadata;
}

// ─── Factory ────────────────────────────────────────────────────────

/**
 * Create a new agent with sensible defaults.
 * The minimum required fields are name, framework, and source_file.
 */
export function createAgent(
  params: Pick<SentinelFlowAgent, "name" | "framework"> &
    Partial<SentinelFlowAgent>
): SentinelFlowAgent {
  const now = new Date().toISOString();
  return {
    id: params.id ?? generateId(),
    name: params.name,
    description: params.description ?? "",
    framework: params.framework,
    framework_id: params.framework_id,
    owner: params.owner,
    team: params.team,
    created_at: params.created_at ?? now,
    updated_at: params.updated_at ?? now,
    source_file: params.source_file,
    repository: params.repository,
    tools: params.tools ?? [],
    allowed_tools: params.allowed_tools,
    blocked_tools: params.blocked_tools,
    model: params.model,
    model_routing: params.model_routing,
    mcp_servers: params.mcp_servers,
    data_sources: params.data_sources ?? [],
    data_classification: params.data_classification,
    file_system_access: params.file_system_access,
    network_access: params.network_access,
    delegates_to: params.delegates_to,
    delegated_from: params.delegated_from,
    swarm_role: params.swarm_role ?? "standalone",
    topology: params.topology ?? "standalone",
    governance: params.governance ?? {
      status: "discovered",
    },
    runtime: params.runtime,
  };
}

// Simple UUID v4 generator (replaced by uuid package in production)
function generateId(): string {
  return "sf-" + crypto.randomUUID();
}
