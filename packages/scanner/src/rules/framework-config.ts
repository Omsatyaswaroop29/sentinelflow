/**
 * Category 6: Agent Framework Configuration
 *
 * Framework misconfigurations are the lowest-hanging fruit for attackers.
 * Each rule targets a specific documented vulnerability in a specific framework.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_FC = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM06", description: "Excessive Agency" },
  { framework: "NIST_AI_RMF" as const, reference: "GOVERN 1", description: "Governance policies" },
];

export const dangerouslySkipPermissions: ScanRule = {
  id: "SF-FC-001",
  name: "Claude Code: Permission Checks Disabled",
  description: "The --dangerously-skip-permissions flag disables all interactive permission checks, allowing unrestricted system access.",
  category: "framework_config",
  severity: "critical",
  frameworks: ["claude-code"],
  compliance: COMPLIANCE_FC,
  phase: "static",

  // ─── Lifecycle (Phase 1.5) ────────────────────────────────
  lifecycle: "stable",
  since: "0.1.0",
  auto_fix: {
    description: "Remove dangerouslySkipPermissions from settings.json and use granular tool allowlists instead.",
    file_pattern: ".claude/settings.json",
    find: '"dangerouslySkipPermissions": true',
    replace: "",
    suggested_config:
      '{\n  "allowedTools": [\n    "Read",\n    "Bash(npm test)",\n    "Bash(npm run build)",\n    "Bash(git diff)"\n  ]\n}',
  },
  known_false_positives: [
    {
      condition: "CI/CD sandboxed environment with no production access, no secrets, and ephemeral compute",
      recommended_action: "Suppress with: # sentinelflow-ignore: SF-FC-001 -- CI sandbox per SEC-XXXX",
    },
    {
      condition: "Documentation or example files that reference the flag without actually enabling it",
      recommended_action: "Suppress with policy file: exclude docs/ and examples/ directories",
    },
  ],
  framework_compat: [
    { framework: "claude-code", min_version: "1.0.0" },
  ],
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const file of ctx.config_files) {
      if (file.content.includes("dangerously-skip-permissions") || file.content.includes("dangerouslySkipPermissions")) {
        const line = file.content.substring(0, file.content.indexOf("dangerously")).split("\n").length;
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-${findings.length}`,
          title: "--dangerously-skip-permissions detected",
          description:
            "The --dangerously-skip-permissions flag removes all interactive approval gates. " +
            "The agent can execute arbitrary bash commands, modify any file, and access " +
            "any network resource without user confirmation. Only acceptable in fully " +
            "sandboxed CI/CD environments with no access to production systems.",
          recommendation:
            "Remove --dangerously-skip-permissions. Configure granular tool permissions " +
            "in .claude/settings.json instead. Use PreToolUse hooks for approval workflows.",
          location: { file: file.path, line },
          cwe: "CWE-862",
          remediation_effort: "low",
        }));
      }
    }
    return findings;
  },
};

export const wildcardBashPermissions: ScanRule = {
  id: "SF-FC-002",
  name: "Claude Code: Wildcard Bash Permissions",
  description: 'Configurations with "Bash(*)" remove all command-specific approval gates.',
  category: "framework_config",
  severity: "high",
  frameworks: ["claude-code"],
  compliance: COMPLIANCE_FC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const file of ctx.config_files) {
      const patterns = [/Bash\(\*\)/g, /Bash\(true\)/gi, /"Bash"/g];
      for (const pattern of patterns) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          if (match[0] === '"Bash"' && file.content.includes("allowedTools")) {
            const line = file.content.substring(0, match.index).split("\n").length;
            findings.push(createEnterpriseFinding(this, {
              id: `${this.id}-${findings.length}`,
              title: `Unrestricted Bash access in ${file.path}`,
              description:
                'Bash listed in allowedTools without command restrictions. This grants ' +
                'the agent ability to execute any shell command. Use granular permissions: ' +
                '"Bash(npm test)", "Bash(git diff)" instead of "Bash" or "Bash(*)".',
              recommendation:
                "Replace unrestricted Bash access with specific command allowlists: " +
                '"Bash(npm test)", "Bash(npm run build)", "Bash(git diff)".',
              location: { file: file.path, line, snippet: match[0] },
              remediation_effort: "low",
            }));
          }
        }
      }
    }
    return findings;
  },
};

export const gitHookBypass: ScanRule = {
  id: "SF-FC-003",
  name: "Git Safety Bypass Patterns",
  description: "Detects --no-verify, force push, and hook skip patterns that bypass git safety controls.",
  category: "framework_config",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_FC,
    { framework: "SOC2" as const, reference: "CC8.1", description: "Change management" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    const GIT_BYPASS = [
      { pattern: /--no-verify/g, name: "--no-verify flag", sev: "high" as const },
      { pattern: /--force-push|git\s+push\s+.*(?:--force|-f)\b/g, name: "force push", sev: "high" as const },
      { pattern: /GIT_HOOKS_SKIP|HUSKY\s*=\s*0/g, name: "hook skip env var", sev: "high" as const },
      { pattern: /pre-commit\s+.*(?:disable|skip|uninstall)/g, name: "pre-commit disable", sev: "medium" as const },
    ];
    for (const file of ctx.config_files) {
      for (const { pattern, name } of GIT_BYPASS) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${findings.length}`,
            title: `Git ${name} detected in ${file.path}`,
            description:
              `${name} at line ${line} allows bypassing git hooks that prevent ` +
              `committing secrets, enforce formatting, and run tests.`,
            recommendation: "Remove git hook bypass patterns. If agents need to commit, ensure they go through standard git hooks.",
            location: { file: file.path, line, snippet: match[0] },
            cwe: "CWE-693",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const unsafeDeserialization: ScanRule = {
  id: "SF-FC-005",
  name: "Unsafe Deserialization Enabled",
  description: "Loading serialized agents/chains from untrusted sources with pickle format enables remote code execution.",
  category: "framework_config",
  severity: "critical",
  frameworks: ["langchain", "custom"],
  compliance: COMPLIANCE_FC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const file of ctx.config_files) {
      const patterns = [
        { pattern: /allow_dangerous_deserialization\s*=\s*True/g, name: "dangerous deserialization flag" },
        { pattern: /pickle\.load|torch\.load|joblib\.load/g, name: "unsafe deserialization call" },
        { pattern: /\.pkl\b|\.pickle\b|\.pt\b|\.pth\b/g, name: "pickle file reference" },
      ];
      for (const { pattern, name } of patterns) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${findings.length}`,
            title: `${name} in ${file.path}`,
            description:
              `Unsafe deserialization at line ${line}. Pickle-format files enable arbitrary ` +
              `code execution during loading. JFrog found ~100 malicious models on Hugging Face ` +
              `using this exact vector.`,
            recommendation:
              "Use safe serialization formats (safetensors, JSON, GGUF). Never load pickle " +
              "files from untrusted sources. Set allow_dangerous_deserialization=False.",
            location: { file: file.path, line, snippet: match[0] },
            cwe: "CWE-502",
            cve: ["CVE-2024-21511"],
            remediation_effort: "medium",
          }));
        }
      }
    }
    return findings;
  },
};

export const unrestrictedDelegation: ScanRule = {
  id: "SF-FC-006",
  name: "Unrestricted Agent Delegation",
  description: "Agent can delegate tasks to any other agent without restrictions (CrewAI allow_delegation=True default).",
  category: "framework_config",
  severity: "medium",
  frameworks: ["crewai", "autogen", "custom"],
  compliance: COMPLIANCE_FC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const file of ctx.config_files) {
      if (file.content.includes("allow_delegation") && !file.content.includes("allow_delegation=False") && !file.content.includes("allow_delegation: false")) {
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-${findings.length}`,
          title: `Unrestricted delegation enabled in ${file.path}`,
          description:
            "Agent delegation is enabled without restrictions. Any agent can delegate to any " +
            "other agent, enabling privilege escalation and prompt injection propagation.",
          recommendation:
            "Set allow_delegation=False by default. Enable selectively with explicit " +
            "delegation targets and scope restrictions.",
          location: { file: file.path },
          remediation_effort: "low",
        }));
      }
    }
    return findings;
  },
};

export const noDescription: ScanRule = {
  id: "SF-FC-007",
  name: "Agent Has No Description or Purpose",
  description: "Agent lacks a description, making governance review and compliance documentation impossible.",
  category: "framework_config",
  severity: "low",
  frameworks: "all",
  compliance: [
    { framework: "ISO_42001" as const, reference: "A.6.2", description: "AI system documentation" },
    { framework: "EU_AI_ACT" as const, reference: "Article 11", description: "Technical documentation" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => !a.description || a.description.trim() === "")
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has no description`,
        description: "Agent lacks a purpose statement. For governance and EU AI Act compliance, every agent needs clear documentation of what it does.",
        recommendation: "Add a description field to the agent definition.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        location: agent.source_file ? { file: agent.source_file } : undefined,
        remediation_effort: "low",
      }));
  },
};

export const FRAMEWORK_CONFIG_RULES: ScanRule[] = [
  dangerouslySkipPermissions,
  wildcardBashPermissions,
  gitHookBypass,
  unsafeDeserialization,
  unrestrictedDelegation,
  noDescription,
];
