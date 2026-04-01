/**
 * Category 3: Supply Chain Integrity
 *
 * OWASP LLM03:2025 — Supply Chain Vulnerabilities.
 * MITRE ATLAS AML.T0010 — ML Supply Chain Compromise.
 *
 * MCP tool poisoning, rug-pull mutations, framework CVEs, and
 * model supply chain attacks are all documented real-world vectors.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_SC = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM03", description: "Supply Chain Vulnerabilities" },
  { framework: "MITRE_ATLAS" as const, reference: "AML.T0010", description: "ML Supply Chain Compromise" },
  { framework: "NIST_AI_RMF" as const, reference: "GOVERN 5", description: "AI supply chain management" },
];

const INJECTION_PATTERNS_IN_TOOL_DESC = [
  /\bignore\b.*\bprevious\b.*\binstructions?\b/gi,
  /\byou\s+(?:are|must|should|will)\b/gi,
  /\bdo\s+not\b.*\btell\b.*\buser\b/gi,
  /<!--[\s\S]*?-->/g,
  /\u200B|\u200C|\u200D|\uFEFF/g,  // Zero-width characters
];

export const mcpNoIntegrity: ScanRule = {
  id: "SF-SC-001",
  name: "MCP Server Connected Without Integrity Verification",
  description: "No tool definition hashing, signing, or pinning exists for connected MCP servers. Servers can mutate tool definitions between sessions.",
  category: "supply_chain",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_SC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const agent of ctx.agents) {
      if (agent.mcp_servers && agent.mcp_servers.length > 0) {
        for (const server of agent.mcp_servers) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${agent.id}-${server.name}`,
            title: `MCP server "${server.name}" connected without integrity verification`,
            description:
              `MCP server "${server.name}" on agent "${agent.name}" has no tool definition ` +
              `hashing or pinning configured. The base MCP specification provides no integrity ` +
              `verification — a server can silently change tool definitions between sessions ` +
              `(rug-pull attack documented by Invariant Labs, 2025).`,
            recommendation:
              "Hash all tool definitions at approval time and verify on each connection. " +
              "SentinelFlow's Phase 2 interceptors will provide automatic tool definition monitoring.",
            agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
            mitre_atlas: "AML.T0010",
            remediation_effort: "medium",
          }));
        }
      }
    }
    return findings;
  },
};

export const toolDescriptionPoisoning: ScanRule = {
  id: "SF-SC-003",
  name: "Tool Description Contains Prompt Injection Patterns",
  description: "MCP tool descriptions, SKILL.md files, or command definitions contain hidden instructions, Unicode manipulation, or references to credentials.",
  category: "supply_chain",
  severity: "critical",
  frameworks: "all",
  compliance: COMPLIANCE_SC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    let counter = 0;
    const skillFiles = ctx.config_files.filter(
      (f) => f.path.includes("SKILL.md") || f.path.includes("/skills/") ||
             f.path.includes("/commands/") || f.path.includes("mcp")
    );
    for (const file of skillFiles) {
      for (const pattern of INJECTION_PATTERNS_IN_TOOL_DESC) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${counter++}`,
            title: `Potential prompt injection in tool definition: ${file.path}`,
            description:
              `Suspicious pattern found at line ${line}: "${match[0].substring(0, 50)}". ` +
              `Tool descriptions are injected into the agent's context and can override ` +
              `system instructions. This is the tool poisoning attack documented by Invariant Labs.`,
            recommendation:
              "Review the flagged content manually. Remove any instructional language from " +
              "tool descriptions. Tool descriptions should be purely descriptive, not prescriptive.",
            location: { file: file.path, line, snippet: match[0].substring(0, 80) },
            mitre_atlas: "AML.T0010.001",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const mcpNoAuth: ScanRule = {
  id: "SF-SC-007",
  name: "MCP Server Lacks Authentication",
  description: "HTTP-transport MCP servers should require OAuth 2.0 or bearer token authentication.",
  category: "supply_chain",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_SC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const agent of ctx.agents) {
      if (!agent.mcp_servers) continue;
      for (const server of agent.mcp_servers) {
        if (server.url && (server.url.startsWith("http://") || server.url.startsWith("https://"))) {
          const mcpConfigs = ctx.config_files.filter((f) => f.path.includes("mcp") || f.path.includes("settings"));
          const hasAuth = mcpConfigs.some(
            (f) => f.content.includes("auth") || f.content.includes("token") ||
                   f.content.includes("bearer") || f.content.includes("oauth")
          );
          if (!hasAuth) {
            findings.push(createEnterpriseFinding(this, {
              id: `${this.id}-${agent.id}-${server.name}`,
              title: `MCP server "${server.name}" has no authentication configured`,
              description:
                `HTTP-transport MCP server "${server.name}" (${server.url}) has no authentication. ` +
                `Unauthenticated MCP servers can be accessed by any process on the network.`,
              recommendation:
                "Configure OAuth 2.0 or bearer token authentication for all HTTP-transport MCP servers.",
              agent_id: agent.id, agent_name: agent.name,
              cwe: "CWE-306",
              remediation_effort: "medium",
            }));
          }
        }
      }
    }
    return findings;
  },
};

export const frameworkCVE: ScanRule = {
  id: "SF-SC-009",
  name: "Agent Framework Has Known Critical CVEs",
  description: "Check for usage of agent frameworks with documented critical vulnerabilities.",
  category: "supply_chain",
  severity: "critical",
  frameworks: ["langchain", "crewai", "autogen"],
  compliance: COMPLIANCE_SC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const KNOWN_VULNERABLE_PATTERNS = [
      { pattern: /langchain[<>=]*0\.0\./g, name: "LangChain 0.0.x", cves: ["CVE-2023-29374", "CVE-2023-36258", "CVE-2023-36188"] },
      { pattern: /allow_dangerous_deserialization\s*=\s*True/g, name: "LangChain unsafe deserialization", cves: ["CVE-2024-21511"] },
      { pattern: /load_chain|load_agent/g, name: "LangChain unsafe chain loading", cves: ["CVE-2023-44467"] },
    ];
    for (const file of ctx.config_files) {
      for (const { pattern, name, cves } of KNOWN_VULNERABLE_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(file.content)) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${findings.length}`,
            title: `${name} pattern detected in ${file.path}`,
            description:
              `Pattern associated with known critical vulnerabilities found. ` +
              `Related CVEs: ${cves.join(", ")}. These vulnerabilities enable arbitrary ` +
              `code execution via prompt injection chains.`,
            recommendation:
              "Update to the latest framework version. Replace deprecated APIs with safe alternatives.",
            location: { file: file.path },
            cve: cves,
            remediation_effort: "medium",
          }));
        }
      }
    }
    return findings;
  },
};

export const configInPublicRepo: ScanRule = {
  id: "SF-SC-008",
  name: "Agent Configuration Committed to Version Control",
  description: "Settings files containing MCP configs, hooks, or credentials committed to repository.",
  category: "supply_chain",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_SC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const fs = require("fs");
    const path = require("path");
    const gitignorePath = path.join(ctx.root_dir, ".gitignore");
    if (!fs.existsSync(gitignorePath)) return findings;
    const gitignore = fs.readFileSync(gitignorePath, "utf-8");
    const sensitiveFiles = [
      ".claude/settings.local.json",
      ".mcp.json",
      ".env",
    ];
    for (const file of sensitiveFiles) {
      if (!gitignore.includes(file) && !gitignore.includes(file.replace("/", ""))) {
        const fullPath = path.join(ctx.root_dir, file);
        if (fs.existsSync(fullPath)) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${findings.length}`,
            title: `Sensitive file "${file}" may be committed to version control`,
            description:
              `"${file}" exists but is not in .gitignore. Agent configuration files ` +
              `containing MCP server configs, local settings, or environment variables ` +
              `should not be committed to version control.`,
            recommendation:
              `Add "${file}" to .gitignore. If already committed, rotate any exposed credentials ` +
              `and use git filter-branch or BFG to remove from history.`,
            location: { file: ".gitignore" },
            cwe: "CWE-540",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const SUPPLY_CHAIN_RULES: ScanRule[] = [
  mcpNoIntegrity,
  toolDescriptionPoisoning,
  mcpNoAuth,
  frameworkCVE,
  configInPublicRepo,
];
