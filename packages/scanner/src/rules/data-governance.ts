/**
 * Category 4: Data Governance & PII Protection
 *
 * GDPR Article 25 — Privacy by design.
 * HIPAA §164.502(b) — Minimum necessary access to PHI.
 * EU AI Act Article 10 — Data governance for AI systems.
 *
 * Agents create transitive data paths between systems that bypass
 * network segmentation and trust boundaries.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_DG = [
  { framework: "GDPR" as const, reference: "Article 25", description: "Data protection by design" },
  { framework: "EU_AI_ACT" as const, reference: "Article 10", description: "Data and data governance" },
  { framework: "NIST_AI_RMF" as const, reference: "MAP 3", description: "AI data governance" },
];

export const noDataClassification: ScanRule = {
  id: "SF-DG-002",
  name: "No Data Classification on Agent Data Sources",
  description: "Agent accesses data sources without classification metadata, making it impossible to enforce data flow policies.",
  category: "data_governance",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_DG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => a.data_sources.length > 0)
      .filter((a) => a.data_sources.some((ds) => !ds.classification || ds.classification.length === 0))
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" accesses unclassified data sources`,
        description:
          `Agent "${agent.name}" accesses ${agent.data_sources.filter((ds) => !ds.classification || ds.classification.length === 0).length} ` +
          `data source(s) without classification metadata. Without classification, data flow ` +
          `policies cannot be enforced — PII could flow from a confidential source to a public channel.`,
        recommendation:
          "Add data classification metadata (pii, phi, financial, confidential, internal, public) " +
          "to each data source in the agent configuration.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        remediation_effort: "medium",
      }));
  },
};

export const crossEnvironmentAccess: ScanRule = {
  id: "SF-DG-006",
  name: "Agent Bridges Production and Non-Production Environments",
  description: "Agents with tool access spanning production and development environments can copy sensitive data across boundaries.",
  category: "data_governance",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_DG,
    { framework: "SOC2" as const, reference: "CC6.1", description: "Logical access security" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const prodIndicators = /\b(prod|production|live|main)\b/i;
    const devIndicators = /\b(dev|development|staging|test|sandbox|local)\b/i;

    for (const agent of ctx.agents) {
      if (!agent.mcp_servers || agent.mcp_servers.length < 2) continue;
      const hasProd = agent.mcp_servers.some((s) => prodIndicators.test(s.name) || (s.url && prodIndicators.test(s.url)));
      const hasDev = agent.mcp_servers.some((s) => devIndicators.test(s.name) || (s.url && devIndicators.test(s.url)));
      if (hasProd && hasDev) {
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-${agent.id}`,
          title: `Agent "${agent.name}" bridges production and non-production environments`,
          description:
            `Agent has MCP servers connecting to both production and development/staging ` +
            `environments. This creates a data path that bypasses environment isolation controls.`,
          recommendation:
            "Separate agents by environment. Use distinct agent configurations for production " +
            "and non-production, with no cross-environment tool access.",
          agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
          remediation_effort: "medium",
        }));
      }
    }
    return findings;
  },
};

export const unrestrrictedFileWrite: ScanRule = {
  id: "SF-DG-003",
  name: "Unrestricted File System Write Access",
  description: "Agent can write to the file system without path restrictions, creating uncontrolled data copies.",
  category: "data_governance",
  severity: "critical",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_DG,
    { framework: "HIPAA" as const, reference: "§164.312(a)(1)", description: "Access control" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => a.tools.some((t) => t.type === "file_write"))
      .filter((a) => !a.file_system_access?.write_paths || a.file_system_access.write_paths.length === 0)
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has unrestricted file system write access`,
        description:
          `Agent can write to any path with no restrictions. This enables overwriting ` +
          `configuration files, injecting code, creating unaudited data copies, or ` +
          `exfiltrating data to accessible filesystem locations.`,
        recommendation:
          "Define explicit write_paths restricting writes to the project directory. " +
          "Block .env, .git/, .claude/, and system configuration paths.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        location: agent.source_file ? { file: agent.source_file } : undefined,
        cwe: "CWE-732",
        remediation_effort: "low",
      }));
  },
};

export const DATA_GOVERNANCE_RULES: ScanRule[] = [
  noDataClassification,
  crossEnvironmentAccess,
  unrestrrictedFileWrite,
];
