/**
 * Category 7: Multi-Agent Orchestration Security
 *
 * Multi-agent systems create attack surfaces that scale combinatorially.
 * A single prompt injection can cascade through an entire agent network.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_MA = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM06", description: "Excessive Agency" },
  { framework: "MITRE_ATLAS" as const, reference: "AML.T0051.002", description: "Indirect prompt injection" },
  { framework: "NIST_AI_RMF" as const, reference: "MANAGE 1", description: "AI risk management" },
];

export const noDelegationDepthLimit: ScanRule = {
  id: "SF-MA-001",
  name: "Delegation Chain Has No Depth Limit",
  description: "Multi-agent delegation with no maximum hop count enables infinite loops and authorization erosion.",
  category: "multi_agent",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_MA,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasMultiAgent = ctx.agents.some((a) => a.delegates_to && a.delegates_to.length > 0) ||
      ctx.agents.filter((a) => a.swarm_role !== "standalone").length > 1;

    if (hasMultiAgent) {
      const hasDepthLimit = ctx.config_files.some(
        (f) => f.content.includes("max_depth") || f.content.includes("max_hops") ||
               f.content.includes("delegation_limit") || f.content.includes("ttl")
      );
      if (!hasDepthLimit) {
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-global`,
          title: "Multi-agent delegation chain has no depth limit",
          description:
            "Multiple agents with delegation relationships detected but no maximum " +
            "delegation depth configured. Each hop may lose authorization context, " +
            "and unbounded chains enable infinite loops.",
          recommendation:
            "Configure a maximum delegation depth (recommended: 3-5 hops). " +
            "Implement TTL counters that decrement with each delegation step.",
          remediation_effort: "medium",
        }));
      }
    }
    return findings;
  },
};

export const privilegeEscalationViaDelegate: ScanRule = {
  id: "SF-MA-003",
  name: "Delegation to Higher-Privilege Agent",
  description: "An agent delegates to another agent with broader tool access or data permissions.",
  category: "multi_agent",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_MA,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const agentMap = new Map(ctx.agents.map((a) => [a.id, a]));

    for (const agent of ctx.agents) {
      if (!agent.delegates_to) continue;
      for (const delegateId of agent.delegates_to) {
        const delegate = agentMap.get(delegateId);
        if (!delegate) continue;
        if (delegate.tools.length > agent.tools.length) {
          const extraTools = delegate.tools.filter(
            (dt) => !agent.tools.some((at) => at.name === dt.name)
          );
          if (extraTools.some((t) => t.risk_level === "high" || t.risk_level === "critical")) {
            findings.push(createEnterpriseFinding(this, {
              id: `${this.id}-${agent.id}-${delegateId}`,
              title: `"${agent.name}" delegates to higher-privilege "${delegate.name}"`,
              description:
                `Agent "${agent.name}" can delegate to "${delegate.name}" which has access ` +
                `to high-risk tools not available to the delegating agent: ` +
                `${extraTools.map((t) => t.name).join(", ")}. This is a confused deputy vulnerability.`,
              recommendation:
                "Ensure delegated agents have equal or lesser permissions than the delegator. " +
                "Implement authorization checks that propagate the original user's scope.",
              agent_id: agent.id, agent_name: agent.name,
              cwe: "CWE-441",
              remediation_effort: "medium",
            }));
          }
        }
      }
    }
    return findings;
  },
};

export const noOutputValidationBetweenAgents: ScanRule = {
  id: "SF-MA-006",
  name: "No Output Validation Between Agent Steps",
  description: "In multi-agent workflows, one agent's output becomes the next agent's input without validation, enabling prompt injection cascades.",
  category: "multi_agent",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_MA,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const multiAgentCount = ctx.agents.filter((a) => a.swarm_role !== "standalone").length;
    if (multiAgentCount >= 2) {
      const hasValidation = ctx.config_files.some(
        (f) => f.content.includes("output_validator") || f.content.includes("output_parser") ||
               f.content.includes("validate_output") || f.content.includes("schema_validation")
      );
      if (!hasValidation) {
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-global`,
          title: `${multiAgentCount} agents in pipeline with no inter-agent output validation`,
          description:
            "Multi-agent workflow detected but no output validation between agent steps. " +
            "A prompt injection in one agent's output will propagate to downstream agents " +
            "— the 'prompt infection' vector demonstrated in 2024 research.",
          recommendation:
            "Add schema validation or output sanitization between each agent step. " +
            "Use structured output formats (JSON Schema, Pydantic) rather than passing raw text.",
          remediation_effort: "high",
        }));
      }
    }
    return findings;
  },
};

// ─── SF-MA-007: CrewAI Hierarchical Process Without Limits ──────

export const crewaiHierarchicalNoLimits: ScanRule = {
  id: "SF-MA-007",
  name: "CrewAI: Hierarchical Process Without Delegation Limits",
  description: "CrewAI crew uses hierarchical process with a manager agent that can delegate tasks to workers, who may further delegate — creating recursive chains without depth limits.",
  category: "multi_agent",
  severity: "high",
  frameworks: ["crewai"],
  compliance: [
    { framework: "OWASP_LLM_2025" as const, reference: "LLM06", description: "Excessive Agency via hierarchical delegation" },
    { framework: "OWASP_LLM_2025" as const, reference: "LLM10", description: "Unbounded Consumption from recursive delegation" },
    { framework: "EU_AI_ACT" as const, reference: "Article 9", description: "Risk management for multi-agent systems" },
  ],
  phase: "static",
  lifecycle: "stable",
  since: "0.2.0",
  auto_fix: {
    description: "Add max_delegation_depth or set allow_delegation: false on worker agents in crew.yaml.",
    suggested_config: "researcher:\n  role: Senior Researcher\n  allow_delegation: false  # Prevent recursive delegation",
  },
  known_false_positives: [
    {
      condition: "Small crews (2-3 agents) where delegation is intentionally flat",
      recommended_action: "Suppress with: # sentinelflow-ignore: SF-MA-007 -- Flat crew, 2 agents only",
    },
  ],
  framework_compat: [{ framework: "crewai", min_version: "0.30.0" }],

  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];

    for (const file of ctx.config_files) {
      if (!file.path.match(/crew\.ya?ml$|agents\.ya?ml$/)) continue;

      const hasHierarchical = /process:\s*["']?hierarchical["']?/i.test(file.content);
      if (!hasHierarchical) continue;

      const delegatingAgents = ctx.agents.filter(
        (a) => a.framework === "crewai" && a.delegates_to && a.delegates_to.length > 0
      );

      if (delegatingAgents.length > 0) {
        const line = file.content.substring(0, file.content.indexOf("hierarchical")).split("\n").length;
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-${findings.length}`,
          title: "CrewAI hierarchical process with unrestricted delegation",
          description:
            `Crew uses hierarchical process with ${delegatingAgents.length} agent(s) that can delegate ` +
            `(${delegatingAgents.map(a => a.name).join(", ")}). In hierarchical mode, the manager agent ` +
            "delegates to workers who may further delegate, creating recursive chains that consume " +
            "tokens unboundedly and can escalate privileges through delegation.",
          recommendation:
            "Set allow_delegation: false on worker agents that should not sub-delegate. " +
            "Only the manager agent should have delegation privileges in a hierarchical crew. " +
            "See https://sentinelflow.dev/rules/SF-MA-007",
          location: { file: file.path, line, snippet: "process: hierarchical" },
          remediation_effort: "low",
          auto_fix: this.auto_fix,
        }));
      }
    }
    return findings;
  },
};

// ─── SF-MA-008: Multi-Framework Config Drift ────────────────────

export const multiFrameworkConfigDrift: ScanRule = {
  id: "SF-MA-008",
  name: "Multi-Framework: Permission Scope Divergence",
  description: "Multiple agent frameworks configured in the same repository have divergent permission scopes — the least restrictive configuration determines actual risk.",
  category: "multi_agent",
  severity: "medium",
  frameworks: "all",
  compliance: [
    { framework: "OWASP_LLM_2025" as const, reference: "LLM06", description: "Excessive Agency via inconsistent permissions" },
    { framework: "EU_AI_ACT" as const, reference: "Article 15", description: "Consistent cybersecurity measures" },
    { framework: "NIST_AI_RMF" as const, reference: "GOVERN 1.1", description: "Uniform governance policies" },
  ],
  phase: "static",
  lifecycle: "experimental",
  since: "0.2.0",
  known_false_positives: [
    {
      condition: "Intentionally different permission scopes for different frameworks (e.g., Cursor for review-only, Claude Code for development)",
      recommended_action: "Suppress with: # sentinelflow-ignore: SF-MA-008 -- Intentional scope difference documented in SECURITY.md",
    },
  ],

  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];

    const frameworkSet = new Set(ctx.agents.map((a) => a.framework));
    if (frameworkSet.size < 2) return findings;

    const frameworkToolRisks = new Map<string, Set<string>>();
    for (const agent of ctx.agents) {
      if (!frameworkToolRisks.has(agent.framework)) {
        frameworkToolRisks.set(agent.framework, new Set());
      }
      const riskSet = frameworkToolRisks.get(agent.framework)!;
      for (const tool of agent.tools) {
        if (tool.risk_level === "high") riskSet.add(tool.name);
      }
    }

    const withHighRisk: string[] = [];
    const withoutHighRisk: string[] = [];
    for (const [fw, risks] of frameworkToolRisks) {
      if (risks.size > 0) withHighRisk.push(fw);
      else withoutHighRisk.push(fw);
    }

    if (withHighRisk.length > 0 && withoutHighRisk.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-0`,
        title: "Permission scope divergence across frameworks",
        description:
          `This project configures ${frameworkSet.size} agent frameworks with different permission levels. ` +
          `${withHighRisk.join(", ")} grant(s) high-risk tool access (bash, shell, code execution) ` +
          `while ${withoutHighRisk.join(", ")} do(es) not. The least restrictive configuration ` +
          "determines the project's actual risk surface.",
        recommendation:
          "Align permission scopes across all configured frameworks to the principle of least privilege. " +
          "If different scopes are intentional, document the rationale in SECURITY.md and suppress this finding. " +
          "See https://sentinelflow.dev/rules/SF-MA-008",
        remediation_effort: "medium",
      }));
    }

    return findings;
  },
};

export const MULTI_AGENT_RULES: ScanRule[] = [
  noDelegationDepthLimit,
  privilegeEscalationViaDelegate,
  noOutputValidationBetweenAgents,
  crewaiHierarchicalNoLimits,
  multiFrameworkConfigDrift,
];
