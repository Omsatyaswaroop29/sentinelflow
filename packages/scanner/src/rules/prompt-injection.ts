/**
 * Category 1: Prompt Injection & Input Validation
 *
 * OWASP LLM01:2025 — Prompt injection remains the #1 risk.
 * MITRE ATLAS AML.T0051 — Prompt injection as initial access vector.
 *
 * These rules detect configurations that leave agents maximally
 * exposed to direct and indirect prompt injection.
 */

import type { ScanRule, RuleContext, EnterpriseFinding, createEnterpriseFinding as createFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_PI = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM01", description: "Prompt Injection" },
  { framework: "MITRE_ATLAS" as const, reference: "AML.T0051", description: "LLM Prompt Injection" },
  { framework: "NIST_AI_RMF" as const, reference: "MEASURE 2.4", description: "Input validation measures" },
];

export const noSystemPrompt: ScanRule = {
  id: "SF-PI-001",
  name: "No System Prompt Defined",
  description: "Agent operates without a system prompt, lacking any instruction boundary against prompt injection.",
  category: "prompt_injection",
  severity: "high",
  frameworks: "all",
  compliance: COMPLIANCE_PI,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => !a.description || a.description.trim().length < 10)
      .filter((a) => {
        const hasClaudeMd = ctx.config_files.some(
          (f) => f.path.endsWith("CLAUDE.md") && f.content.trim().length > 50
        );
        return !hasClaudeMd;
      })
      .map((agent) =>
        createEnterpriseFinding(this, {
          id: `${this.id}-${agent.id}`,
          title: `Agent "${agent.name}" has no system prompt or project guidance`,
          description:
            `No CLAUDE.md, AGENTS.md, or substantial agent description found for "${agent.name}". ` +
            `Without a system prompt, the agent has no instruction boundary, making it fully ` +
            `susceptible to prompt injection from any input source.`,
          recommendation:
            "Create a CLAUDE.md file with clear behavioral boundaries, or add a detailed " +
            "description to the agent definition. Include explicit instructions about what " +
            "the agent should and should NOT do.",
          agent_id: agent.id,
          agent_name: agent.name,
          framework: agent.framework,
          mitre_atlas: "AML.T0051",
          remediation_effort: "low",
        })
      );
  },
};

const SENSITIVE_PATTERNS_IN_PROMPTS = [
  { pattern: /(?:internal|private|confidential)\s*(?:url|endpoint|api|server)[:=\s]+\S+/gi, name: "internal URL" },
  { pattern: /(?:database|db)\s*(?:host|server|connection)[:=\s]+\S+/gi, name: "database endpoint" },
  { pattern: /(?:admin|root|superuser)\s*(?:password|credential|secret)[:=\s]+\S+/gi, name: "admin credential" },
  { pattern: /(?:vpn|ssh|rdp)\s*[:=\s]+\S+\.(?:com|net|org|io)/gi, name: "infrastructure endpoint" },
];

export const sensitiveDataInPrompts: ScanRule = {
  id: "SF-PI-002",
  name: "System Prompt Contains Sensitive Data",
  description: "System prompts containing internal URLs, credentials, or infrastructure details are extractable via prompt injection techniques (OWASP LLM07).",
  category: "prompt_injection",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_PI,
    { framework: "OWASP_LLM_2025" as const, reference: "LLM07", description: "System Prompt Leakage" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    let counter = 0;
    const promptFiles = ctx.config_files.filter(
      (f) => f.path.endsWith("CLAUDE.md") || f.path.endsWith("AGENTS.md") ||
             f.path.includes("/agents/") || f.path.includes("/.claude/agents/")
    );
    for (const file of promptFiles) {
      for (const { pattern, name } of SENSITIVE_PATTERNS_IN_PROMPTS) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(
            createEnterpriseFinding(this, {
              id: `${this.id}-${counter++}`,
              title: `${name} found in prompt file ${file.path}`,
              description:
                `A potential ${name} was found at line ${line} in a system prompt file. ` +
                `System prompts can be extracted via prompt injection, exposing this data.`,
              recommendation:
                "Remove sensitive infrastructure details from system prompts. Use environment " +
                "variables or secrets managers for endpoints and credentials. Refer to " +
                "resources by abstract names rather than actual URLs.",
              location: { file: file.path, line, snippet: match[0].substring(0, 60) },
              cwe: "CWE-200",
              remediation_effort: "low",
            })
          );
        }
      }
    }
    return findings;
  },
};

export const noOutputValidation: ScanRule = {
  id: "SF-PI-005",
  name: "No Output Validation Before Tool Execution",
  description: "Agent passes LLM outputs directly to tools without schema validation, enabling injection chains.",
  category: "prompt_injection",
  severity: "high",
  frameworks: ["langchain", "crewai", "autogen", "custom"],
  compliance: [
    ...COMPLIANCE_PI,
    { framework: "OWASP_LLM_2025" as const, reference: "LLM05", description: "Improper Output Handling" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const file of ctx.config_files) {
      const dangerousPatterns = [
        { pattern: /eval\s*\(/g, name: "eval()" },
        { pattern: /exec\s*\(/g, name: "exec()" },
        { pattern: /subprocess\.(?:run|call|Popen)\s*\(/g, name: "subprocess execution" },
        { pattern: /os\.system\s*\(/g, name: "os.system()" },
        { pattern: /PythonREPLTool|ShellTool/g, name: "unrestricted code execution tool" },
      ];
      for (const { pattern, name } of dangerousPatterns) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(
            createEnterpriseFinding(this, {
              id: `${this.id}-${findings.length}`,
              title: `Dangerous ${name} pattern in ${file.path}`,
              description:
                `${name} found at line ${line}. LLM outputs passed to code execution functions ` +
                `without validation enable prompt-to-RCE chains. LangChain CVE-2023-29374, ` +
                `CVE-2023-36258, and CVE-2024-21511 all exploited this pattern.`,
              recommendation:
                "Add schema validation between LLM output and tool execution. Use structured " +
                "output parsing (Pydantic models, JSON Schema validation) rather than passing " +
                "raw LLM text to execution functions. Sandbox all code execution.",
              location: { file: file.path, line, snippet: match[0] },
              cwe: "CWE-94",
              cve: ["CVE-2023-29374", "CVE-2023-36258", "CVE-2024-21511"],
              remediation_effort: "medium",
            })
          );
        }
      }
    }
    return findings;
  },
};

export const longContextWithoutSummarization: ScanRule = {
  id: "SF-PI-008",
  name: "Large Context Window Without Summarization Strategy",
  description: "Agents using maximum context windows are vulnerable to many-shot jailbreaking (Anthropic, April 2024).",
  category: "prompt_injection",
  severity: "medium",
  frameworks: "all",
  compliance: COMPLIANCE_PI,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const hasCompaction = ctx.config_files.some(
      (f) => f.content.includes("compact") || f.content.includes("summariz") ||
             f.content.includes("context_window") || f.content.includes("max_tokens")
    );
    if (!hasCompaction && ctx.agents.length > 0) {
      findings.push(
        createEnterpriseFinding(this, {
          id: `${this.id}-global`,
          title: "No context window management or compaction strategy detected",
          description:
            "No evidence of context window management (compaction, summarization, " +
            "or token limits) found in the project configuration. Long context sessions " +
            "are vulnerable to many-shot jailbreaking and increase prompt injection surface area.",
          recommendation:
            "Implement a context compaction strategy. Use Claude Code's /compact command, " +
            "set max_tokens limits, or implement conversation summarization. ECC's " +
            "suggest-compact hook provides a reference implementation.",
          remediation_effort: "medium",
        })
      );
    }
    return findings;
  },
};

export const PROMPT_INJECTION_RULES: ScanRule[] = [
  noSystemPrompt,
  sensitiveDataInPrompts,
  noOutputValidation,
  longContextWithoutSummarization,
];
