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

export const MULTI_AGENT_RULES: ScanRule[] = [
  noDelegationDepthLimit,
  privilegeEscalationViaDelegate,
  noOutputValidationBetweenAgents,
];
