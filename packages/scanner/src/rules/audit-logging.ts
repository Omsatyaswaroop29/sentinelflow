/**
 * Category 8: Audit Logging & Observability
 *
 * EU AI Act Article 12 — Automatic recording of events, min 6-month retention.
 * HIPAA §164.312(b) — Audit controls for all PHI access.
 * SOC 2 CC7.1-CC7.2 — Activity monitoring and configuration change detection.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_AL = [
  { framework: "EU_AI_ACT" as const, reference: "Article 12", description: "Record-keeping / automatic logging" },
  { framework: "SOC2" as const, reference: "CC7.1", description: "Detection of configuration changes" },
  { framework: "HIPAA" as const, reference: "§164.312(b)", description: "Audit controls" },
];

export const noAuditLogging: ScanRule = {
  id: "SF-AL-001",
  name: "Agent Actions Not Logged",
  description: "No evidence of audit logging for agent tool invocations, decisions, or data access.",
  category: "audit_logging",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_AL,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasLogging = ctx.config_files.some(
      (f) => f.content.includes("log") || f.content.includes("audit") ||
             f.content.includes("observe") || f.content.includes("trace") ||
             f.content.includes("PostToolUse") || f.content.includes("sentinelflow") ||
             f.content.includes("langfuse") || f.content.includes("langsmith") ||
             f.content.includes("arize") || f.content.includes("helicone")
    );
    if (!hasLogging && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "No audit logging detected for agent actions",
        description:
          "No evidence of audit logging, observability tools, or PostToolUse hooks found. " +
          "EU AI Act Article 12 requires automatic recording of events throughout an AI system's " +
          "lifetime with minimum 6-month retention. Without logging, incident response and " +
          "compliance auditing are impossible.",
        recommendation:
          "Integrate an observability platform (SentinelFlow interceptors, Langfuse, LangSmith) " +
          "or add PostToolUse hooks that log every tool invocation with agent identity, " +
          "action type, input/output summary, and timestamp.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const noSIEMIntegration: ScanRule = {
  id: "SF-AL-004",
  name: "Agent Logs Not Integrated with SIEM",
  description: "Agent audit logs should stream to centralized security monitoring for correlation with other security events.",
  category: "audit_logging",
  severity: "medium",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AL,
    { framework: "SOC2" as const, reference: "CC7.2", description: "Activity monitoring" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasSIEM = ctx.config_files.some(
      (f) => f.content.includes("sentinel") || f.content.includes("splunk") ||
             f.content.includes("datadog") || f.content.includes("siem") ||
             f.content.includes("elastic") || f.content.includes("chronicle")
    );
    if (!hasSIEM && ctx.agents.length > 0) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "Agent logs not connected to SIEM/SOAR platform",
        description:
          "No evidence of SIEM integration (Microsoft Sentinel, Splunk, Datadog, etc.). " +
          "Isolated agent logs miss attack patterns spanning multiple systems.",
        recommendation:
          "Stream agent telemetry to your centralized SIEM. SentinelFlow's interceptors " +
          "support webhook output to Splunk, Datadog, and Microsoft Sentinel.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const sensitiveDataInLogs: ScanRule = {
  id: "SF-AL-006",
  name: "Sensitive Data May Appear in Agent Logs",
  description: "Agent traces and conversation logs may contain PII, credentials, or classified data without redaction.",
  category: "audit_logging",
  severity: "medium",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AL,
    { framework: "GDPR" as const, reference: "Article 5(1)(c)", description: "Data minimisation" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasLogRedaction = ctx.config_files.some(
      (f) => f.content.includes("redact") || f.content.includes("sanitize") ||
             f.content.includes("mask") || f.content.includes("scrub") ||
             f.content.includes("pii_filter")
    );
    const handlesData = ctx.agents.some(
      (a) => a.data_classification?.some((dc) => ["pii", "phi", "financial"].includes(dc)) ||
             a.data_sources.some((ds) => ds.classification?.some((c) => ["pii", "phi", "financial"].includes(c)))
    );
    if (!hasLogRedaction && handlesData) {
      findings.push(createEnterpriseFinding(this, {
        id: `${this.id}-global`,
        title: "Agents handling sensitive data with no log redaction configured",
        description:
          "Agents access PII/PHI/financial data but no log sanitization or PII redaction " +
          "is configured. Agent traces may contain the sensitive data itself, creating " +
          "uncontrolled data copies in log storage.",
        recommendation:
          "Configure PII scrubbing in your logging pipeline. SentinelFlow interceptors " +
          "include automatic PII detection and redaction in telemetry events.",
        remediation_effort: "medium",
      }));
    }
    return findings;
  },
};

export const AUDIT_LOGGING_RULES: ScanRule[] = [
  noAuditLogging,
  noSIEMIntegration,
  sensitiveDataInLogs,
];
