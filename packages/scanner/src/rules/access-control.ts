/**
 * Category 2: Agent Identity & Access Control
 *
 * OWASP LLM06:2025 — Excessive Agency.
 * Microsoft Zero Trust for AI — every agent needs a distinct managed identity.
 * EU AI Act Article 14 — Human oversight requirements.
 */

import type { ScanRule, RuleContext, EnterpriseFinding } from "./interface";
import { createEnterpriseFinding } from "./interface";

const COMPLIANCE_AC = [
  { framework: "OWASP_LLM_2025" as const, reference: "LLM06", description: "Excessive Agency" },
  { framework: "NIST_AI_RMF" as const, reference: "GOVERN 2", description: "Identity and access management" },
  { framework: "SOC2" as const, reference: "CC6.1", description: "Logical access security" },
];

const SECRET_PATTERNS = [
  { pattern: /(?:sk-|pk_live_|pk_test_)[a-zA-Z0-9]{20,}/g, name: "API key" },
  { pattern: /sk-ant-[a-zA-Z0-9-]{80,}/g, name: "Anthropic API key" },
  { pattern: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}/g, name: "GitHub token" },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key ID" },
  { pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi, name: "AWS Secret Key" },
  { pattern: /AIza[0-9A-Za-z_-]{35}/g, name: "Google API key" },
  { pattern: /glpat-[a-zA-Z0-9_-]{20,}/g, name: "GitLab token" },
  { pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/g, name: "Slack token" },
  { pattern: /(?:hooks\.slack\.com\/services\/)[A-Z0-9/]+/g, name: "Slack Webhook" },
  { pattern: /(?:mongodb(?:\+srv)?:\/\/)[^\s"']+/g, name: "MongoDB connection string" },
  { pattern: /(?:postgres(?:ql)?:\/\/)[^\s"']+/g, name: "PostgreSQL connection string" },
  { pattern: /(?:mysql:\/\/)[^\s"']+/g, name: "MySQL connection string" },
  { pattern: /(?:redis:\/\/)[^\s"']+/g, name: "Redis connection string" },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi, name: "Password" },
  { pattern: /(?:secret|token|api_key|apikey|auth_token)\s*[:=]\s*["'][^"']{8,}["']/gi, name: "Secret/Token" },
  { pattern: /Bearer\s+[a-zA-Z0-9._~+/=-]{20,}/g, name: "Bearer token" },
];

const IGNORE_FILE_PATTERNS = [/\.example$/, /\.template$/, /\.sample$/, /SKILL\.md$/, /node_modules/, /\.git\//];

function maskSecret(s: string): string {
  if (s.length <= 8) return "****";
  return s.substring(0, 4) + "****" + s.substring(s.length - 4);
}

/**
 * Extract the actual secret VALUE from a raw regex match.
 *
 * Several SECRET_PATTERNS match a whole `key: "value"` assignment, so match[0]
 * looks like `password: "Wq7rZ9kLmP2xY"` — the key word (`password`, `secret`,
 * `token`) is part of the match. If we hand that whole string to the precision
 * guards, the KEY word itself (which is in FAKE_TOKENS) makes the guard treat a
 * real secret as a placeholder and suppress it. So before guarding, pull out
 * the quoted value if there is one; otherwise fall back to the whole match
 * (patterns like AKIA... / sk-... match the bare secret already).
 */
function extractSecretValue(rawMatch: string): string {
  const quoted = rawMatch.match(/["']([^"']+)["']/);
  if (quoted && quoted[1]) return quoted[1];
  // Unquoted `key=value` form (e.g. AWS_SECRET=...): take the part after : or =.
  const assigned = rawMatch.match(/[:=]\s*(.+)$/);
  if (assigned && assigned[1]) return assigned[1].trim();
  return rawMatch;
}

/**
 * Returns true when a matched "secret" is obviously a placeholder or teaching
 * example rather than a live credential. This is the single biggest driver of
 * false positives for SF-AC-001: docs, security guides, and .env examples are
 * full of fake values like `sk-proj-xxxxx`, `user:password@localhost`, and
 * `mypassword123`. Flagging those as critical leaks destroys trust in the rule.
 *
 * Kept deliberately conservative — every entry here is a value no real
 * production credential would take, so the false-negative risk is low.
 */
export function isPlaceholderSecret(value: string): boolean {
  const v = value.toLowerCase();

  // Local / non-routable / documentation hosts in a connection string.
  // NOTE: bare `host` and `db` were removed deliberately — they are common
  // real service names (e.g. Docker Compose `@db:5432`), so suppressing them
  // would hide real internal-credential leaks (a false negative). Only keep
  // hosts that are unambiguously non-production.
  if (/(?:@|\/\/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.com|example\.org|your-host|your_host|hostname|<[^>]+>)\b/.test(v)) {
    return true;
  }

  // The universal "put your credentials here" placeholder pair.
  if (/\buser:password@/.test(v) || /:\/\/user:pass\b/.test(v)) return true;

  // Structural placeholder markers: <KEY>, {{key}}, ${ENV}, ellipsis.
  if (/[<>{}]|\$\{|\.\.\./.test(value)) return true;

  // A run of the SAME character that dominates the value (xxxxxxxx, 00000000).
  // Tightened from {3,} to a dominant-run test: a real 40–80 char base64/hex
  // secret can contain 4 repeated chars BY CHANCE, so the old /(.)\1{3,}/
  // suppressed real secrets. Require either a long run (6+) or that a single
  // repeated char makes up most of a short value.
  const longRun = /(.)\1{5,}/.test(v);
  const dominatedByRun = v.length <= 24 && /(.)\1{3,}/.test(v);
  if (longRun || dominatedByRun) return true;

  // Dictionary placeholders. CRITICAL: match these as WHOLE TOKENS, not as
  // substrings of a longer high-entropy value — otherwise a real key that
  // merely *contains* "foo"/"bar"/"test" (common by chance in 40+ char random
  // strings) gets silently suppressed. That false negative is worse than the
  // false positive we're preventing. So: split the value into word-tokens and
  // require an exact token match (or a very short whole value).
  const FAKE_TOKENS = new Set([
    "xxxx", "xxxxx", "abc123", "changeme", "change_me", "yourkey", "your_key",
    "your_api_key", "placeholder", "redacted", "example", "sample", "dummy",
    "fake", "test", "foobar", "foo", "bar", "baz", "mypassword", "password",
    "password123", "secret", "secret123", "hunter2", "123456", "todo",
    "replace", "replaceme",
  ]);
  const PREFIX_TOKENS = ["your_", "your-", "my_", "my-"];

  // Split on non-alphanumeric boundaries so `sk-proj-xxxxx` → [sk, proj, xxxxx].
  const tokens = v.split(/[^a-z0-9]+/).filter(Boolean);
  if (tokens.some((t) => FAKE_TOKENS.has(t))) return true;
  if (PREFIX_TOKENS.some((p) => v.startsWith(p))) return true;

  // Very short whole values that are obvious fakes (e.g. the entire value is
  // "test123" / "mypassword123"): treat a short value made only of a dictionary
  // word + trailing digits as a placeholder.
  if (v.length <= 16 && /^[a-z]+\d*$/.test(v)) {
    const wordPart = v.replace(/\d+$/, "");
    if (FAKE_TOKENS.has(wordPart)) return true;
  }

  return false;
}

const EXAMPLE_CONTEXT_MARKERS = [
  "// bad", "//bad", "# bad", "#bad", "<!-- bad", "❌", "🚫", "✗",
  "don't", "dont", "do not", "never", "avoid",
  "example", "e.g.", "eg:", "for instance", "wrong", "incorrect",
  "instead of", "anti-pattern", "antipattern", "bad:", "bad practice",
];

/**
 * Returns true when the matched line — or the line immediately above it — is
 * marked as a teaching / "don't do this" example. Catches cases like
 * `const apiKey = "sk-abc123"; // BAD` where the value looks real-ish but the
 * surrounding text makes clear it is an illustration, not a live secret.
 */
export function isInExampleContext(content: string, matchIndex: number): boolean {
  const before = content.substring(0, matchIndex);
  const lineStart = before.lastIndexOf("\n") + 1;
  const prevLineStart = before.lastIndexOf("\n", lineStart - 2) + 1;
  const lineEndIdx = content.indexOf("\n", matchIndex);
  const currentLine = content
    .substring(lineStart, lineEndIdx === -1 ? content.length : lineEndIdx)
    .toLowerCase();
  const prevLine = content.substring(prevLineStart, lineStart).toLowerCase();
  const haystack = prevLine + "\n" + currentLine;
  return EXAMPLE_CONTEXT_MARKERS.some((m) => haystack.includes(m));
}

export const hardcodedCredentials: ScanRule = {
  id: "SF-AC-001",
  name: "Hardcoded Credentials in Agent Configuration",
  description: "Agents using hardcoded API keys, tokens, or passwords instead of managed identities or secrets managers.",
  category: "access_control",
  severity: "critical",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AC,
    { framework: "HIPAA" as const, reference: "§164.312(d)", description: "Person or entity authentication" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    let counter = 0;
    for (const file of ctx.config_files) {
      if (IGNORE_FILE_PATTERNS.some((p) => p.test(file.path))) continue;
      for (const { pattern, name } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          // Precision guards: skip obvious placeholders and teaching examples.
          // A secrets scanner that flags `sk-proj-xxxxx` or `// BAD` snippets as
          // critical leaks gets uninstalled on day one — precision is the product.
          // IMPORTANT: guard on the extracted VALUE, not match[0]. Patterns like
          // `password: "..."` include the key word in match[0]; passing that to
          // isPlaceholderSecret would let the key word `password`/`secret`/`token`
          // (all in FAKE_TOKENS) wrongly suppress a real secret.
          const secretValue = extractSecretValue(match[0]);
          if (isPlaceholderSecret(secretValue)) continue;
          if (isInExampleContext(file.content, match.index)) continue;

          const line = file.content.substring(0, match.index).split("\n").length;
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${counter++}`,
            title: `${name} found in ${file.path}`,
            description:
              `A potential ${name} was detected at line ${line}. Hardcoded credentials ` +
              `in agent configs can be exfiltrated via prompt injection, leaked through ` +
              `version control, or exposed in agent traces and logs.`,
            recommendation:
              "Use managed identities (Azure Managed Identity, GCP Workload Identity) or " +
              "a secrets manager (Infisical, Vault, AWS Secrets Manager). Reference secrets " +
              "via environment variables: $ENV_VAR_NAME.",
            location: { file: file.path, line, snippet: maskSecret(match[0]) },
            cwe: "CWE-798",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const excessivePermissions: ScanRule = {
  id: "SF-AC-002",
  name: "Agent Permissions Exceed Least Privilege",
  description: "Agent has broad tool access without explicit restrictions, violating the principle of least privilege.",
  category: "access_control",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AC,
    { framework: "EU_AI_ACT" as const, reference: "Article 15", description: "Accuracy, robustness, cybersecurity" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => a.tools.length > 0 && (!a.allowed_tools || a.allowed_tools.length === 0) && (!a.blocked_tools || a.blocked_tools.length === 0))
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has no explicit tool allowlist`,
        description:
          `Agent "${agent.name}" has ${agent.tools.length} tools available with no explicit ` +
          `allowlist or blocklist. This grants implicit access to all tools, including ` +
          `potentially dangerous ones. Microsoft's Copilot oversharing incident showed how ` +
          `excessive permissions amplify data exposure across the entire tenant.`,
        recommendation:
          "Define an explicit allowedTools list with only the tools this agent needs. " +
          "For Claude Code, use granular Bash permissions: 'Bash(npm test)' instead of 'Bash(*)'.",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        location: agent.source_file ? { file: agent.source_file } : undefined,
        remediation_effort: "low",
      }));
  },
};

export const noHumanInTheLoop: ScanRule = {
  id: "SF-AC-005",
  name: "No Human-in-the-Loop for High-Impact Actions",
  description: "Agent can perform irreversible actions (file writes, bash execution, network calls) without human approval gates.",
  category: "access_control",
  severity: "high",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AC,
    { framework: "EU_AI_ACT" as const, reference: "Article 14", description: "Human oversight" },
    { framework: "NIST_AI_RMF" as const, reference: "MANAGE 3", description: "Human oversight of AI" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const agent of ctx.agents) {
      const highRiskTools = agent.tools.filter(
        (t) => t.type === "bash" || t.type === "file_write" || t.type === "api_call" || t.type === "database"
      );
      if (highRiskTools.length === 0) continue;
      const hasDangerousSkip = ctx.config_files.some(
        (f) => f.content.includes("dangerously-skip-permissions") || f.content.includes("dangerouslySkipPermissions")
      );
      const hasApprovalHook = ctx.config_files.some(
        (f) => f.content.includes("PreToolUse") && (f.content.includes("block") || f.content.includes("approve"))
      );
      if (hasDangerousSkip || !hasApprovalHook) {
        findings.push(createEnterpriseFinding(this, {
          id: `${this.id}-${agent.id}`,
          title: `Agent "${agent.name}" can execute high-impact actions without approval`,
          description:
            `Agent "${agent.name}" has access to ${highRiskTools.map((t) => t.name).join(", ")} ` +
            `(high-impact tools) with ${hasDangerousSkip ? "permissions explicitly skipped" : "no PreToolUse approval hooks detected"}. ` +
            `EU AI Act Article 14 requires human oversight for high-risk AI systems.`,
          recommendation:
            "Add PreToolUse hooks that gate high-impact actions. For Claude Code, remove " +
            "--dangerously-skip-permissions and configure approval hooks in settings.json.",
          agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
          remediation_effort: "medium",
        }));
      }
    }
    return findings;
  },
};

export const privilegeEscalation: ScanRule = {
  id: "SF-AC-007",
  name: "Agent Can Escalate Its Own Privileges",
  description: "Agent's tool set includes capabilities that could modify its own permissions or create new credentials.",
  category: "access_control",
  severity: "critical",
  frameworks: "all",
  compliance: COMPLIANCE_AC,
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    const findings: EnterpriseFinding[] = [];
    for (const agent of ctx.agents) {
      const hasBash = agent.tools.some((t) => t.type === "bash");
      const hasFileWrite = agent.tools.some((t) => t.type === "file_write");
      if (hasBash && hasFileWrite) {
        const canModifyConfig = !agent.file_system_access?.blocked_paths?.some(
          (p) => p.includes(".claude") || p.includes("settings")
        );
        if (canModifyConfig) {
          findings.push(createEnterpriseFinding(this, {
            id: `${this.id}-${agent.id}`,
            title: `Agent "${agent.name}" can modify its own configuration`,
            description:
              `Agent has both bash execution and file write access without blocked paths ` +
              `for configuration directories. It could modify .claude/settings.json, ` +
              `install new MCP servers, change its own allowedTools, or create credentials.`,
            recommendation:
              "Block write access to .claude/, .sentinelflow/, hooks/, and any configuration " +
              "directories. Add these paths to file_system_access.blocked_paths.",
            agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
            cwe: "CWE-269",
            remediation_effort: "low",
          }));
        }
      }
    }
    return findings;
  },
};

export const noOwner: ScanRule = {
  id: "SF-AC-008",
  name: "Agent Has No Declared Owner",
  description: "Unowned agents are shadow AI — no one is accountable for their behavior, security, or compliance.",
  category: "access_control",
  severity: "medium",
  frameworks: "all",
  compliance: [
    ...COMPLIANCE_AC,
    { framework: "ISO_42001" as const, reference: "Clause 5.3", description: "Roles, responsibilities, authorities" },
  ],
  phase: "static",
  evaluate(ctx: RuleContext): EnterpriseFinding[] {
    return ctx.agents
      .filter((a) => !a.owner && !a.team)
      .map((agent) => createEnterpriseFinding(this, {
        id: `${this.id}-${agent.id}`,
        title: `Agent "${agent.name}" has no declared owner`,
        description:
          `No owner or team assigned. Microsoft's Cyber Pulse report found that organizations ` +
          `often don't know how many agents exist or who owns them — this is the governance gap.`,
        recommendation:
          "Add an owner field to the agent definition or register it with: " +
          "sentinelflow registry update <id> --owner <n>",
        agent_id: agent.id, agent_name: agent.name, framework: agent.framework,
        location: agent.source_file ? { file: agent.source_file } : undefined,
        remediation_effort: "low",
      }));
  },
};

export const ACCESS_CONTROL_RULES: ScanRule[] = [
  hardcodedCredentials,
  excessivePermissions,
  noHumanInTheLoop,
  privilegeEscalation,
  noOwner,
];
