/**
 * Category 5: Cost & Resource Governance
 *
 * OWASP LLM10:2025 — Unbounded Consumption.
 * Documented AutoGPT incidents of $1,000+ API costs in hours.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_CG = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM10", description: "Unbounded Consumption" },
  { framework: "NIST_AI_RMF" as const, reference: "MANAGE 2", description: "Resource management" },
];

export const noTokenBudget: ScanRule = {
  id: "SF-CG-001",
  name: "No Token Budget Configured",
  description: "Agent has no token or cost budget, allowing unlimited API consumption.",
  category: "cost_governance",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_CG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => !a.governance.token_budget)
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has no cost budget`,
        description:
          `No token or cost budget defined. Runaway agent loops and unexpected usage ` +
          `spikes can result in thousands of dollars in API costs. Multiple documented ` +
          `incidents of AutoGPT instances accumulating $1,000+ in hours.`,
        recommendation:
          "Define token_budget with monthly_limit and daily_limit in the agent's governance configuration.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        remediation_effort: "low",
      }));
  },
};

export const noIterationLimit: ScanRule = {
  id: "SF-CG-002",
  name: "No Maximum Iteration Limit on Agent Loops",
  description: "Agent framework has no max_iterations or equivalent configured.",
  category: "cost_governance",
  severity: "high",
  frameworks: ["langchain", "crewai", "autogen"],
  compliance: COMPLIANCE_CG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasIterLimit = ctx.config_files.some(
      (f) => f.content.includes("max_iterations") || f.content.includes("max_iter") ||
             f.content.includes("maxIterations") || f.content.includes("max_turns") ||
             f.content.includes("iteration_limit")
    );
    if (!hasIterLimit && ctx.agents.some((a) => ["langchain", "crewai", "autogen"].includes(a.framework))) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No iteration limit detected for agent execution loops",
        description:
          "No max_iterations, max_turns, or equivalent configuration found. Without " +
          "iteration limits, an agent in a reasoning loop can make unlimited API calls.",
        recommendation:
          "Set max_iterations in your agent framework configuration. Recommended: " +
          "10-25 for simple tasks, 50-100 for complex multi-step tasks.",
        remediation_effort: "low",
      }));
    }
    return findings;
  },
};

export const noTimeout: ScanRule = {
  id: "SF-CG-003",
  name: "No Circuit Breaker or Timeout Configured",
  description: "Agent tasks have no wall-clock time limits or deadman's switch.",
  category: "cost_governance",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_CG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasTimeout = ctx.config_files.some(
      (f) => f.content.includes("timeout") || f.content.includes("max_time") ||
             f.content.includes("deadline") || f.content.includes("circuit_breaker")
    );
    if (!hasTimeout && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No timeout or circuit breaker configured for agent execution",
        description:
          "No timeout, deadline, or circuit breaker configuration detected. " +
          "Agent tasks could run indefinitely consuming resources.",
        recommendation:
          "Configure timeouts for all agent tasks. Add hook-based deadman switches " +
          "that require human confirmation after N minutes of continuous execution.",
        remediation_effort: "low",
      }));
    }
    return findings;
  },
};

export const expensiveModelForSimpleTasks: ScanRule = {
  id: "SF-CG-004",
  name: "Expensive Model Used Without Routing Strategy",
  description: "All agent tasks route to a single expensive model without tiered model routing.",
  category: "cost_governance",
  severity: "low",
  frameworks: "all",
  compliance: COMPLIANCE_CG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const expensiveModels = ["opus", "gpt-4", "gpt-4o", "claude-3-opus"];
    for (const agent of ctx.agents) {
      if (agent.model && expensiveModels.some((m) => agent.model!.toLowerCase().includes(m))) {
        if (!agent.model_routing || agent.model_routing.length === 0) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${agent.id}`,
            title: `Agent "${agent.name}" uses expensive model "${agent.model}" with no routing`,
            description:
              `All tasks route to ${agent.model} without tiered model routing. The cost ` +
              `difference between Opus/GPT-4 and Haiku/GPT-3.5 is 30-100x for simple tasks.`,
            recommendation:
              "Implement tiered model routing: simple tasks → Haiku/Flash, " +
              "moderate tasks → Sonnet, complex tasks → Opus.",
            agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
            remediation_effort: "medium",
          }));
        }
      }
    }
    return findings;
  },
};

export const noCostAttribution: ScanRule = {
  id: "SF-CG-007",
  name: "No Cost Attribution or Monitoring",
  description: "Agent API costs are not tagged by team, project, or task type.",
  category: "cost_governance",
  severity: "low",
  frameworks: "all",
  compliance: COMPLIANCE_CG,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasCostTracking = ctx.config_files.some(
      (f) => f.content.includes("cost") || f.content.includes("budget") ||
             f.content.includes("billing") || f.content.includes("usage_tracking")
    );
    if (!hasCostTracking && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No cost attribution or monitoring infrastructure detected",
        description:
          "No evidence of cost tracking, budget monitoring, or usage attribution found. " +
          "Without attribution, cost overruns cannot be traced to specific agents or teams.",
        recommendation:
          "Configure SentinelFlow's cost governance module or integrate with your cloud " +
          "provider's cost management tools. Tag API calls by agent, team, and project.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const COST_GOVERNANCE_RULES: ScanRule[] = [
  noTokenBudget,
  noIterationLimit,
  noTimeout,
  expensiveModelForSimpleTasks,
  noCostAttribution,
];
