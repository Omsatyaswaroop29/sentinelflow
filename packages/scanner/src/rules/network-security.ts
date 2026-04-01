/**
 * Category 10: Network & Infrastructure Security
 *
 * Defense-in-depth controls that limit blast radius when other controls fail.
 * HIPAA §164.312(e)(1) — Transmission security.
 * SOC 2 CC6.7 — Encryption at rest.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_NS = [
  { framework: "SOC2" as const, reference: "CC6.6", description: "System boundaries and network security" },
  { framework: "NIST_AI_RMF" as const, reference: "GOVERN 6", description: "Infrastructure security" },
];

export const unrestrictedNetworkAccess: ScanRule = {
  id: "SF-NS-003",
  name: "No Network Egress Filtering for Agent Environment",
  description: "Agents that can make network requests have no domain restrictions, enabling data exfiltration.",
  category: "network_security",
  severity: "medium",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_NS,
    { framework: "HIPAA" as const, reference: "§164.312(e)(1)", description: "Transmission security" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => a.tools.some((t) => t.type === "web_search" || t.type === "web_fetch" || t.type === "api_call"))
      .filter((a) => !a.network_access || (!a.network_access.allowed_domains && !a.network_access.blocked_domains))
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has unrestricted network egress`,
        description:
          `Agent has network tools (${agent.tools.filter((t) => ["web_search", "web_fetch", "api_call"].includes(t.type)).map((t) => t.name).join(", ")}) ` +
          `with no domain allowlist or blocklist. An attacker exploiting prompt injection ` +
          `could exfiltrate data to any external endpoint.`,
        recommendation:
          "Define network_access.allowed_domains restricting outbound connections to " +
          "approved API endpoints. Block known data exfiltration services.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        location: agent.source_file ? { file: agent.source_file } : undefined,
        cwe: "CWE-441",
        remediation_effort: "medium",
      }));
  },
};

export const noSandboxing: ScanRule = {
  id: "SF-NS-004",
  name: "Code Execution Not Sandboxed",
  description: "Agents executing code in the host process without containerization or VM-based sandboxing.",
  category: "network_security",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_NS,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasSandbox = ctx.config_files.some(
      (f) => f.content.includes("docker") || f.content.includes("container") ||
             f.content.includes("sandbox") || f.content.includes("isolat") ||
             f.content.includes("vm") || f.content.includes("firecracker")
    );
    const hasCodeExec = ctx.agents.some(
      (a) => a.tools.some((t) => t.type === "bash" || t.type === "code_execution")
    );

    if (hasCodeExec && !hasSandbox) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "Agent code execution with no sandboxing detected",
        description:
          "Agents can execute code (bash/code_execution tools) but no containerization " +
          "or sandboxing configuration was found. Code execution in the host process " +
          "means a prompt injection → code execution chain has full system access.",
        recommendation:
          "Run agent code execution in sandboxed environments: Docker containers, " +
          "Azure Container Apps dynamic sessions, or VM-based sandboxes. " +
          "At minimum, use Linux namespaces or chroot to restrict file system access.",
        remediation_effort: "high",
      }));
    }
    return findings;
  },
};

export const unencryptedMCPTransport: ScanRule = {
  id: "SF-NS-001",
  name: "MCP Server Using Unencrypted Transport",
  description: "MCP servers connected via HTTP (not HTTPS) or unencrypted WebSocket.",
  category: "network_security",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_NS,
    { framework: "HIPAA" as const, reference: "§164.312(e)(1)", description: "Transmission security" },
    { framework: "SOC2" as const, reference: "CC6.7", description: "Encryption in transit" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const agent of ctx.agents) {
      if (!agent.mcp_servers) continue;
      for (const server of agent.mcp_servers) {
        if (server.url && server.url.startsWith("http://") && !server.url.includes("localhost") && !server.url.includes("127.0.0.1")) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${agent.id}-${server.name}`,
            title: `MCP server "${server.name}" uses unencrypted HTTP`,
            description:
              `MCP server "${server.name}" connects via ${server.url} (HTTP, not HTTPS). ` +
              `Tool definitions, agent data, and potentially credentials are transmitted in plaintext.`,
            recommendation:
              "Switch to HTTPS for all non-local MCP server connections. " +
              "Configure TLS 1.2+ with valid certificates.",
            agent_id: agent.id, agent_name: agent.name,
            cwe: "CWE-319",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const NETWORK_SECURITY_RULES: ScanRule[] = [
  unrestrictedNetworkAccess,
  noSandboxing,
  unencryptedMCPTransport,
];
