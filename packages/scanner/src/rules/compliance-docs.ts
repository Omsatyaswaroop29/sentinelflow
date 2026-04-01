/**
 * Category 9: Compliance Documentation
 *
 * EU AI Act penalties: up to €35M or 7% of worldwide annual turnover.
 * High-risk AI system obligations take effect August 2, 2026.
 * ISO 42001 requires documented AI management systems.
 */

import * as fs from "fs";
import * as path from "path";
import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_CD = [
  { framework: "EU_AI_ACT" as const, reference: "Articles 9-15", description: "High-risk AI system requirements" },
  { framework: "ISO_42001" as const, reference: "Clause 6-10", description: "AI management system requirements" },
  { framework: "NIST_AI_RMF" as const, reference: "GOVERN", description: "AI governance documentation" },
];

export const noRiskAssessment: ScanRule = {
  id: "SF-CD-001",
  name: "No AI Risk Assessment Documented",
  description: "EU AI Act Article 9 requires continuous risk assessment for high-risk AI systems.",
  category: "compliance_docs",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_CD,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const riskDocPatterns = [
      "risk_assessment", "risk-assessment", "ai_risk", "risk_register",
      "threat_model", "threat-model", "risk_analysis",
    ];
    const hasRiskDoc = ctx.config_files.some(
      (f) => riskDocPatterns.some((p) => f.content.toLowerCase().includes(p))
    );
    const riskFiles = ["RISK_ASSESSMENT.md", "risk-assessment.md", "AI_RISK.md", "threat-model.md"];
    const hasRiskFile = riskFiles.some((f) => fs.existsSync(path.join(ctx.root_dir, f)));

    if (!hasRiskDoc && !hasRiskFile && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No AI risk assessment documentation found",
        description:
          "No risk assessment, threat model, or risk register found for the AI agents " +
          "in this project. EU AI Act Article 9 requires continuous risk assessment and " +
          "management for high-risk AI systems. ISO 42001 Clause 6.1.2 requires " +
          "AI-specific risk assessment. Enforcement deadline: August 2, 2026.",
        recommendation:
          "Create a risk assessment document covering: agent capabilities, data access, " +
          "potential failure modes, and mitigation measures. Use NIST AI RMF's " +
          "MAP-MEASURE-MANAGE lifecycle as a framework.",
        remediation_effort: "high",
      }));
    }
    return findings;
  },
};

export const noTechnicalDocumentation: ScanRule = {
  id: "SF-CD-002",
  name: "No Technical Documentation for AI System",
  description: "EU AI Act Article 11 requires comprehensive technical documentation before deployment.",
  category: "compliance_docs",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_CD,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasAgentsMd = fs.existsSync(path.join(ctx.root_dir, "AGENTS.md"));
    const hasClaudeMd = fs.existsSync(path.join(ctx.root_dir, "CLAUDE.md"));
    const hasArchDoc = ["ARCHITECTURE.md", "docs/architecture.md", "docs/ARCHITECTURE.md", "SYSTEM_DESIGN.md"]
      .some((f) => fs.existsSync(path.join(ctx.root_dir, f)));

    if (!hasAgentsMd && !hasArchDoc && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No technical documentation found for the AI agent system",
        description:
          "No AGENTS.md, ARCHITECTURE.md, or system design documentation found. " +
          "EU AI Act Article 11 and Annex IV require comprehensive technical documentation " +
          "including system architecture, design specifications, and cybersecurity measures " +
          "BEFORE deployment to the market.",
        recommendation:
          "Create AGENTS.md describing: system architecture, agent roles, tool access, " +
          "data flows, security controls, and human oversight measures. " +
          "SentinelFlow's /governance-scan command can generate a starting template.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const noHumanOversightDocs: ScanRule = {
  id: "SF-CD-004",
  name: "No Human Oversight Documentation",
  description: "EU AI Act Article 14 requires documented human oversight measures including ability to intervene and override.",
  category: "compliance_docs",
  severity: "medium",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_CD,
    { framework: "EU_AI_ACT" as const, reference: "Article 14", description: "Human oversight" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const oversightTerms = [
      "human_oversight", "human-oversight", "human_review", "human-in-the-loop",
      "hitl", "approval_workflow", "approval-workflow", "kill_switch", "emergency_stop",
    ];
    const hasOversight = ctx.config_files.some(
      (f) => oversightTerms.some((t) => f.content.toLowerCase().includes(t))
    );
    const hasHooks = ctx.config_files.some(
      (f) => f.path.includes("hooks") && f.content.includes("PreToolUse")
    );

    if (!hasOversight && !hasHooks && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No human oversight measures documented or configured",
        description:
          "No human oversight mechanisms (approval workflows, PreToolUse hooks, kill switches) " +
          "or documentation found. EU AI Act Article 14 requires that high-risk AI systems " +
          "include measures enabling human oversight, including the ability to understand, " +
          "interpret, correctly use, and override the AI system.",
        recommendation:
          "Configure PreToolUse hooks for high-impact actions. Document oversight procedures " +
          "including: how operators can intervene, what actions require approval, and how to " +
          "shut down agent operations in an emergency.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const noIncidentResponsePlan: ScanRule = {
  id: "SF-CD-005",
  name: "No AI Incident Response Plan",
  description: "No dedicated playbook for AI-specific incidents (prompt injection breaches, agent manipulation, model compromise).",
  category: "compliance_docs",
  severity: "low",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_CD,
    { framework: "NIST_AI_RMF" as const, reference: "MANAGE 4.1", description: "Incident response" },
    { framework: "SOC2" as const, reference: "CC7.3", description: "Incident response procedures" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const irFiles = [
      "INCIDENT_RESPONSE.md", "incident-response.md", "IR_PLAN.md",
      "docs/incident-response.md", "SECURITY.md",
    ];
    const hasIR = irFiles.some((f) => fs.existsSync(path.join(ctx.root_dir, f)));
    const hasIRContent = ctx.config_files.some(
      (f) => f.content.includes("incident_response") || f.content.includes("incident-response") ||
             f.content.includes("security incident")
    );

    if (!hasIR && !hasIRContent && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No AI-specific incident response plan found",
        description:
          "No incident response documentation for AI-specific threats found. " +
          "Prompt injection breaches, agent manipulation, and model compromise require " +
          "dedicated response playbooks beyond traditional IT incident response.",
        recommendation:
          "Create an AI incident response plan covering: prompt injection detection and " +
          "response, agent credential rotation, model rollback procedures, and " +
          "communication templates for stakeholders.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const COMPLIANCE_DOCS_RULES: ScanRule[] = [
  noRiskAssessment,
  noTechnicalDocumentation,
  noHumanOversightDocs,
  noIncidentResponsePlan,
];
