/**
 * @module @sentinelflow/interceptors/compliance
 *
 * Runtime control → compliance framework mapping.
 *
 * This module answers the question a security architect asks:
 * "What risks does SentinelFlow reduce, and how can I prove it?"
 *
 * Every runtime control (policy, detector, governance feature) is mapped to:
 *   - OWASP LLM Top 10 2025 risks it mitigates
 *   - EU AI Act articles it supports
 *   - NIST AI RMF functions it implements
 *   - SOC 2 Trust Service Criteria it addresses
 *
 * Each mapping includes:
 *   - A short "evidence snippet" suitable for an AI impact assessment
 *   - The specific control mechanism SentinelFlow uses
 *   - What the control does NOT cover (honest limitations)
 */

// ─── Compliance Framework Types ─────────────────────────────────────

export interface ComplianceMapping {
  /** SentinelFlow control identifier */
  control_id: string;
  /** Human-readable control name */
  control_name: string;
  /** Which SentinelFlow module implements this */
  module: string;
  /** What the control does */
  description: string;
  /** What the control does NOT do (honest limitations) */
  limitations: string[];
  /** OWASP LLM Top 10 2025 risks mitigated */
  owasp_llm: OwaspLlmMapping[];
  /** EU AI Act articles supported */
  eu_ai_act: EuAiActMapping[];
  /** NIST AI RMF functions */
  nist_ai_rmf: NistMapping[];
  /** SOC 2 Trust Service Criteria */
  soc2: string[];
  /** Evidence snippet for AI impact assessment */
  evidence_snippet: string;
}

export interface OwaspLlmMapping {
  /** e.g., "LLM01", "LLM09" */
  id: string;
  /** Risk name */
  name: string;
  /** How this control mitigates the risk */
  mitigation: string;
}

export interface EuAiActMapping {
  /** e.g., "Article 9", "Article 14" */
  article: string;
  /** Article topic */
  topic: string;
  /** How this control supports the requirement */
  support: string;
}

export interface NistMapping {
  /** e.g., "Govern 1.4", "Map 1.5" */
  function_id: string;
  /** Function name */
  name: string;
}

// ─── Complete Compliance Mappings ────────────────────────────────────

export const RUNTIME_COMPLIANCE_MAPPINGS: ComplianceMapping[] = [
  // ═══════════════════════════════════════════════════════════════
  //  1. Dangerous Command Detection
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-001",
    control_name: "Dangerous Command Detection",
    module: "handler-codegen policy evaluator (generated handlers) + central pattern registry",
    description:
      "Intercepts shell tool calls in real-time, applies lightweight command normalization to reduce " +
      "simple obfuscation, and matches against 18 dangerous patterns " +
      "including rm -rf, curl|bash, chmod 777, sudo, git push --force, npm/yarn/pnpm publish, " +
      "fork bombs, and PATH manipulation.",
    limitations: [
      "Cannot resolve shell variables ($VAR) or dynamic command construction",
      "Cannot decode base64/hex obfuscation embedded in variables",
      "Cannot trace multi-step attacks where each step is individually benign (see RT-005)",
      "Not a sandbox — determined attackers with shell access can bypass regex-based detection",
    ],
    owasp_llm: [
      {
        id: "LLM01",
        name: "Prompt Injection",
        mitigation:
          "When prompt injection causes an agent to execute dangerous commands, " +
          "the policy blocks execution before damage occurs. The agent receives " +
          "feedback that the command was blocked, reducing exploitation success.",
      },
      {
        id: "LLM09",
        name: "Excessive Agency",
        mitigation:
          "Prevents agents from executing commands beyond their intended scope. " +
          "Even if an agent has shell access, dangerous patterns are blocked.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 9",
        topic: "Risk Management System",
        support:
          "Provides automated risk mitigation for known dangerous operations, " +
          "with documented patterns, severity levels, and remediation guidance.",
      },
      {
        article: "Article 15",
        topic: "Accuracy, Robustness, Cybersecurity",
        support:
          "Reduces the impact of adversarial inputs by blocking dangerous " +
          "command execution regardless of how the command was generated.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Manage 2.2", name: "Mechanisms to track identified AI risks over time" },
      { function_id: "Manage 2.4", name: "Mechanisms to ensure risks are managed" },
    ],
    soc2: ["CC6.1 (Logical Access Controls)", "CC7.2 (System Monitoring)"],
    evidence_snippet:
      "SentinelFlow intercepts shell execution across 4 AI coding platforms (Claude Code, Cursor, GitHub " +
      "Copilot, Codex CLI) and evaluates commands against 18 dangerous patterns with handler-safe " +
      "normalization. In enforce mode, dangerous commands are blocked before execution (Claude/Copilot/Codex " +
      "block via exit code 2; Cursor blocks via stdout JSON), and the blocking reason is fed back to the model. " +
      "In monitor mode, the same matches are recorded as flagged events. All events are logged to an append-only " +
      "event store (JSONL + optional SQLite).",
  },

  // ═══════════════════════════════════════════════════════════════
  //  2. Network Egress Control
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-002",
    control_name: "Network Egress Control",
    module: "NetworkEgressPolicy",
    description:
      "Detects outbound network activity (curl, wget, Python requests, Node.js fetch, ssh, scp, netcat) " +
      "in shell commands and enforces domain-level allowlists/denylists. Supports wildcard patterns " +
      "(*.corp.internal) for internal domains.",
    limitations: [
      "Only inspects shell commands — cannot intercept network calls made by the AI model itself",
      "Cannot detect DNS-based exfiltration or ICMP tunneling",
      "Cannot inspect encrypted payloads — only controls the destination domain",
      "Does not provide deep packet inspection",
    ],
    owasp_llm: [
      {
        id: "LLM02",
        name: "Sensitive Information Disclosure",
        mitigation:
          "Prevents AI agents from exfiltrating sensitive data to unauthorized external domains. " +
          "Domain allowlists ensure data only flows to approved endpoints.",
      },
      {
        id: "LLM06",
        name: "Excessive Agency",
        mitigation:
          "Restricts agents' ability to make arbitrary outbound network connections, " +
          "limiting the blast radius of compromised agent sessions.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 10",
        topic: "Data and Data Governance",
        support:
          "Controls where AI-processed data can be sent, supporting data governance " +
          "requirements for high-risk AI systems.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Govern 1.5", name: "Organizational data governance" },
      { function_id: "Manage 3.2", name: "Pre-deployment testing and risk management" },
    ],
    soc2: ["CC6.6 (System Boundaries)", "CC6.7 (Transmission Security)"],
    evidence_snippet:
      "SentinelFlow's NetworkEgressPolicy detects 7 categories of outbound network activity " +
      "in shell commands, extracts target domains, and enforces configurable allowlists/blocklists. " +
      "This control is enforced in generated hook handlers (Claude Code, Cursor, GitHub Copilot, Codex CLI) " +
      "using the central network egress pattern registry and per-install domain allow/block lists. " +
      "It addresses OWASP LLM02 (Sensitive Information Disclosure) by preventing AI agent-initiated data " +
      "exfiltration to unauthorized endpoints and OWASP LLM06 (Excessive Agency) by constraining outbound egress.",
  },

  // ═══════════════════════════════════════════════════════════════
  //  3. Secrets Detection
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-003",
    control_name: "Secrets and Credential Detection",
    module: "SecretsLeakPolicy",
    description:
      "Scans tool input arguments for 15 credential patterns including API keys (OpenAI, GitHub, AWS, " +
      "Anthropic, Google, Stripe, Slack, npm), database connection strings, Bearer tokens, basic auth " +
      "in URLs, private key material, and password/token command flags. Block reasons are deliberately " +
      "vague to avoid echoing the secret back.",
    limitations: [
      "Pattern-based — cannot detect arbitrary high-entropy secrets without known format",
      "Cannot scan environment variables that are expanded before reaching the hook",
      "Cannot detect secrets encoded in base64, hex, or other obfuscation",
      "Does not rotate or revoke detected credentials — only blocks the tool call",
    ],
    owasp_llm: [
      {
        id: "LLM02",
        name: "Sensitive Information Disclosure",
        mitigation:
          "Detects credentials being passed through tool arguments and blocks execution " +
          "before the secret can be logged, transmitted, or exposed in model context.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 10",
        topic: "Data and Data Governance",
        support:
          "Prevents credentials from being processed as regular data by AI systems, " +
          "supporting the requirement for appropriate data quality and protection measures.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Govern 1.5", name: "Organizational data governance" },
    ],
    soc2: ["CC6.1 (Logical Access Controls)", "CC6.5 (Secure Authentication)"],
    evidence_snippet:
      "SentinelFlow's SecretsLeakPolicy scans tool inputs for 15 credential patterns across " +
      "major cloud providers, SaaS platforms, and common authentication mechanisms. When a " +
      "credential is detected, the tool call is blocked with a deliberately vague reason " +
      "(to avoid echoing the secret), and the event is logged for security team review. " +
      "This addresses OWASP LLM02 by preventing agent-mediated credential exposure.",
  },

  // ═══════════════════════════════════════════════════════════════
  //  4. File Write Governance
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-004",
    control_name: "Sensitive File Write Governance",
    module: "handler-codegen sensitive path enforcement + central sensitive path registry",
    description:
      "Blocks writes to sensitive file paths including SSH keys, GPG keys, .env files, .npmrc, " +
      "system directories (/etc, /usr/local/bin), supply chain files (package.json, Dockerfile, " +
      ".github/workflows), and .netrc. Also detects shell redirect operators (>, >>, tee) " +
      "targeting sensitive paths.",
    limitations: [
      "Cannot block writes that bypass the hook system (e.g., direct syscalls)",
      "Pattern-based path matching — custom sensitive paths need explicit configuration",
      "Cannot verify the content being written, only the destination path",
    ],
    owasp_llm: [
      {
        id: "LLM09",
        name: "Excessive Agency",
        mitigation:
          "Prevents agents from writing to files that grant system privileges or modify " +
          "the supply chain, even if the agent has general file write access.",
      },
      {
        id: "LLM08",
        name: "Insecure Plugin Design",
        mitigation:
          "Limits the damage from compromised or misbehaving tools by blocking writes " +
          "to security-critical file paths regardless of which tool initiated the write.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 15",
        topic: "Accuracy, Robustness, Cybersecurity",
        support:
          "Protects system integrity by preventing AI agents from modifying authentication " +
          "files, CI/CD pipelines, and package manifests.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Manage 2.4", name: "Mechanisms to ensure risks are managed" },
    ],
    soc2: ["CC6.1 (Logical Access Controls)", "CC8.1 (Change Management)"],
    evidence_snippet:
      "SentinelFlow prevents AI agents from writing to 12 categories of " +
      "sensitive file paths including SSH keys, environment files, system directories, and " +
      "CI/CD pipelines. The policy applies to both Write/Edit tools and shell redirect " +
      "operators. This addresses OWASP LLM09 (Excessive Agency) by enforcing file-level " +
      "least-privilege for AI agent actions.",
  },

  // ═══════════════════════════════════════════════════════════════
  //  5. Multi-Step Sequence Detection
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-005",
    control_name: "Multi-Step Attack Sequence Detection",
    module: "SequenceDetector",
    description:
      "Correlates events within a session using a sliding window to detect attack chains: " +
      "script injection (write→chmod→execute), data exfiltration (read sensitive→network call), " +
      "persistence probing (repeated blocked attempts), and privilege escalation chains " +
      "(write auth config→reload). Each detection includes the full event chain for investigation.",
    limitations: [
      "TypeScript detector exists but is not yet embedded into generated hook handlers (planned parity work)",
      "Only detects known sequence patterns — novel attack chains require new rules",
      "Window is time-bounded (5 min default) — slow attacks may evade detection",
      "Cannot correlate across sessions or across different agents",
      "Detection is post-hoc — the final step may execute before the sequence is flagged",
    ],
    owasp_llm: [
      {
        id: "LLM01",
        name: "Prompt Injection",
        mitigation:
          "Catches multi-step exploitation chains that result from prompt injection, " +
          "where each individual step passes single-call policy checks but the chain " +
          "constitutes an attack.",
      },
      {
        id: "LLM09",
        name: "Excessive Agency",
        mitigation:
          "Detects when an agent's sequence of actions exceeds its intended scope, " +
          "even when each individual action appears benign.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 9",
        topic: "Risk Management System",
        support:
          "Provides behavioral-level risk detection beyond single-action analysis, " +
          "addressing the requirement for continuous risk identification.",
      },
      {
        article: "Article 12",
        topic: "Record-Keeping",
        support:
          "Logs complete attack chains with event IDs, timestamps, and tool details, " +
          "enabling post-incident analysis and regulatory reporting.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Measure 2.6", name: "Continuous monitoring of AI risks" },
      { function_id: "Manage 4.1", name: "Post-deployment incident response" },
    ],
    soc2: ["CC7.2 (System Monitoring)", "CC7.3 (Detection and Alerting)"],
    evidence_snippet:
      "SentinelFlow's SequenceDetector implements session-level behavioral analysis using a " +
      "per-session sliding window that correlates events to detect 4 multi-step attack patterns: " +
      "script injection chains, data exfiltration sequences, bypass probing, and privilege " +
      "escalation chains. This goes beyond single-call policy checks to address OWASP LLM01 " +
      "(Prompt Injection consequences) and LLM09 (Excessive Agency) at the behavioral level. " +
      "Every detection includes the complete event chain for forensic analysis.",
  },

  // ═══════════════════════════════════════════════════════════════
  //  6. Identity and Role-Based Access Control
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-006",
    control_name: "Identity and Role-Based Access Control",
    module: "IdentityResolver + RoleBasedAccessPolicy + EnvironmentPolicy",
    description:
      "Links every agent action to a human owner, team, role, and environment. Enforces " +
      "role-based tool access (readers can't write, writers can't execute, etc.) and " +
      "environment restrictions (production agents can't use shell tools, external-facing " +
      "agents are read-only). Identity is resolved from policy config, environment variables, " +
      "and CI/CD context.",
    limitations: [
      "TypeScript policies exist but are not yet embedded into generated hook handlers (planned parity work)",
      "Identity relies on configuration — a misconfigured role grants incorrect access",
      "Cannot verify the actual human behind the session (no MFA integration yet)",
      "Environment detection is heuristic-based (environment variables, CI markers)",
      "Does not implement approval workflows — blocks are immediate, not escalated",
    ],
    owasp_llm: [
      {
        id: "LLM09",
        name: "Excessive Agency",
        mitigation:
          "Enforces least-privilege per agent role: each agent can only use tools " +
          "appropriate to its assigned role, reducing the scope of damage from " +
          "any single compromised agent.",
      },
      {
        id: "LLM08",
        name: "Insecure Plugin Design",
        mitigation:
          "Ensures that tools requiring elevated privileges (shell, deploy) are only " +
          "available to agents with the appropriate role and privilege level.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 14",
        topic: "Human Oversight",
        support:
          "Every agent action is linked to a human owner, enabling accountability " +
          "and the ability to trace any AI action back to a responsible person.",
      },
      {
        article: "Article 12",
        topic: "Record-Keeping",
        support:
          "Identity context (owner, team, environment, role) is attached to every " +
          "event for comprehensive audit trails.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Govern 1.4", name: "Organizational roles and responsibilities" },
      { function_id: "Map 1.5", name: "AI risk management integration" },
    ],
    soc2: ["CC6.1 (Logical Access Controls)", "CC6.3 (Role-Based Access)"],
    evidence_snippet:
      "SentinelFlow's identity system resolves a human owner, team, role, and environment " +
      "for every agent session, attaching this context to all runtime events. The " +
      "RoleBasedAccessPolicy enforces least-privilege by mapping agent roles (reader, writer, " +
      "executor, deployer, admin) to tool privilege levels. The EnvironmentPolicy adds " +
      "environment-specific restrictions (e.g., production agents cannot use shell tools). " +
      "This addresses EU AI Act Article 14 (Human Oversight) by ensuring every AI action " +
      "has a traceable human authorization chain.",
  },

  // ═══════════════════════════════════════════════════════════════
  //  7. Data Classification and Boundary Enforcement
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-007",
    control_name: "Data Classification and Boundary Enforcement",
    module: "EnhancedDataBoundaryPolicy + PathClassifier",
    description:
      "Classifies file paths into 4 sensitivity levels (public/internal/restricted/system) " +
      "using 30+ configurable rules. Enforces per-agent clearance levels that determine which " +
      "classification tiers each agent can access. Extracts paths from structured tool inputs, " +
      "not just string summaries.",
    limitations: [
      "TypeScript policy exists but is not yet embedded into generated hook handlers (planned parity work)",
      "Path-based classification only — cannot inspect file contents",
      "Does not cover network resources, databases, or API endpoints",
      "Classification rules are static — no ML-based content classification",
      "Cannot detect data that flows through intermediate files or pipes",
    ],
    owasp_llm: [
      {
        id: "LLM02",
        name: "Sensitive Information Disclosure",
        mitigation:
          "Prevents agents from accessing files classified as restricted or system-level, " +
          "reducing the risk of exposing credentials, keys, and configuration secrets.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 10",
        topic: "Data and Data Governance",
        support:
          "Implements data classification and access control for AI agent operations, " +
          "supporting the requirement for appropriate data governance measures.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Govern 1.5", name: "Organizational data governance" },
      { function_id: "Map 1.1", name: "Identify intended purposes and context of use" },
    ],
    soc2: ["CC6.1 (Logical Access Controls)", "CC6.5 (Data Classification)"],
    evidence_snippet:
      "SentinelFlow's EnhancedDataBoundaryPolicy classifies every file path accessed by AI " +
      "agents into 4 sensitivity tiers (public, internal, restricted, system) using 30+ " +
      "configurable rules. Per-agent clearance levels enforce least-privilege data access: " +
      "for example, a 'reader' agent can only access public files, while a 'deployer' agent " +
      "can access restricted files like .env. This addresses OWASP LLM02 (Sensitive Information " +
      "Disclosure) and EU AI Act Article 10 (Data Governance).",
  },

  // ═══════════════════════════════════════════════════════════════
  //  8. Unified Audit Trail
  // ═══════════════════════════════════════════════════════════════
  {
    control_id: "RT-008",
    control_name: "Unified Multi-Framework Audit Trail",
    module: "JSONL event log + SQLite event store",
    description:
      "Every tool call across all 4 supported frameworks is logged to an append-only event store " +
      "with a unified schema. Events include: timestamp, agent_id, session_id, framework, tool_name, " +
      "decision, reason, identity context (owner, team, environment, role), and the full governance " +
      "evaluation result. Dual-written to JSONL (for tail/grep) and SQLite (for indexed queries).",
    limitations: [
      "Append-only — no retention policy or automatic cleanup yet",
      "Local storage only — no centralized log aggregation or SIEM integration",
      "Event schema is SentinelFlow-specific — requires mapping for external systems",
      "No tamper-evidence (signing, chaining) — logs can be modified by someone with file access",
    ],
    owasp_llm: [
      {
        id: "LLM09",
        name: "Excessive Agency",
        mitigation:
          "Complete audit trail of all agent actions enables post-incident investigation " +
          "and detection of scope violations that individual policy checks may have missed.",
      },
    ],
    eu_ai_act: [
      {
        article: "Article 12",
        topic: "Record-Keeping",
        support:
          "Provides automatic logging of AI system operation throughout its lifecycle, " +
          "including the specific actions taken, decisions made, and human owner responsible.",
      },
      {
        article: "Article 14",
        topic: "Human Oversight",
        support:
          "Audit trail enables human reviewers to examine any AI agent session in detail, " +
          "supporting the requirement for meaningful human oversight capability.",
      },
    ],
    nist_ai_rmf: [
      { function_id: "Measure 2.6", name: "Continuous monitoring" },
      { function_id: "Manage 4.1", name: "Post-deployment monitoring and incident response" },
    ],
    soc2: ["CC7.2 (System Monitoring)", "CC7.3 (Detection and Alerting)", "CC4.1 (Monitoring)"],
    evidence_snippet:
      "SentinelFlow maintains a unified, append-only audit trail across all 4 supported AI coding " +
      "platforms (Claude Code, Cursor, GitHub Copilot, Codex CLI). Every tool call is logged with " +
      "its governance decision, identity context (human owner, team, environment, role), and " +
      "the policy evaluation result. This directly supports EU AI Act Article 12 (Record-Keeping) " +
      "and Article 14 (Human Oversight), as well as SOC 2 CC7.2 (System Monitoring).",
  },
];

// ─── Query Helpers ──────────────────────────────────────────────────

/** Get all controls that mitigate a specific OWASP LLM risk */
export function getControlsForOwaspRisk(owaspId: string): ComplianceMapping[] {
  return RUNTIME_COMPLIANCE_MAPPINGS.filter((m) =>
    m.owasp_llm.some((o) => o.id === owaspId)
  );
}

/** Get all controls that support a specific EU AI Act article */
export function getControlsForEuArticle(article: string): ComplianceMapping[] {
  return RUNTIME_COMPLIANCE_MAPPINGS.filter((m) =>
    m.eu_ai_act.some((a) => a.article === article)
  );
}

/** Get the evidence snippet for a specific control */
export function getEvidenceSnippet(controlId: string): string | undefined {
  return RUNTIME_COMPLIANCE_MAPPINGS.find((m) => m.control_id === controlId)?.evidence_snippet;
}

/** Generate a compliance summary for an AI impact assessment */
export function generateComplianceSummary(): string {
  const lines: string[] = [
    "SentinelFlow Runtime Governance — Compliance Control Summary",
    "=".repeat(60),
    "",
  ];

  for (const mapping of RUNTIME_COMPLIANCE_MAPPINGS) {
    lines.push(`${mapping.control_id}: ${mapping.control_name}`);
    lines.push(`  Module: ${mapping.module}`);
    lines.push(`  OWASP: ${mapping.owasp_llm.map((o) => o.id).join(", ") || "N/A"}`);
    lines.push(`  EU AI Act: ${mapping.eu_ai_act.map((a) => a.article).join(", ") || "N/A"}`);
    lines.push(`  NIST: ${mapping.nist_ai_rmf.map((n) => n.function_id).join(", ") || "N/A"}`);
    lines.push(`  SOC 2: ${mapping.soc2.join(", ") || "N/A"}`);
    lines.push("");
  }

  return lines.join("\n");
}
