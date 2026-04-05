/**
 * @module @sentinelflow/interceptors/patterns
 *
 * Central pattern registry — the SINGLE SOURCE OF TRUTH for all
 * dangerous command detection, secrets scanning, and file governance.
 *
 * Every handler script and every TypeScript policy class reads from
 * this registry. Adding a pattern here adds it everywhere.
 *
 * WHY THIS EXISTS:
 * Before this file, dangerous command patterns were duplicated across
 * 4 handler scripts + 1 policy class = 5 files. Adding a new pattern
 * required updating all 5. This file eliminates that drift risk.
 */

// ─── Dangerous Command Patterns ─────────────────────────────────────

export interface DangerousPattern {
  /** Unique identifier for this pattern */
  id: string;
  /** Human-readable description */
  description: string;
  /** The regex pattern string (will be compiled at runtime) */
  regex: string;
  /** Regex flags (default: none) */
  flags?: string;
  /** Severity: critical, high, medium, low */
  severity: "critical" | "high" | "medium" | "low";
  /** OWASP/CWE/compliance mapping tags */
  tags: string[];
  /** Suggested safe alternative */
  remediation?: string;
}

/**
 * All dangerous command patterns. Used by:
 *   - DangerousCommandPolicy (TypeScript)
 *   - All 4 handler scripts (baked in at generation time)
 *   - Golden path tests
 */
export const DANGEROUS_COMMAND_PATTERNS: DangerousPattern[] = [
  // ── Filesystem destruction ────────────────────────────────
  {
    id: "DC-001",
    description: "rm -rf outside /tmp",
    regex: "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*\\s+-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*\\s+-[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*rf[a-zA-Z]*|-[a-zA-Z]*fr[a-zA-Z]*)\\s+/(?!tmp)",
    severity: "critical",
    tags: ["OWASP-LLM09", "CWE-732", "filesystem"],
    remediation: "Use targeted deletion with specific paths, or move files to trash instead of rm -rf.",
  },
  {
    id: "DC-002",
    description: "dd to block device",
    regex: "\\bdd\\b.*\\bof=/dev/",
    severity: "critical",
    tags: ["CWE-732", "filesystem"],
    remediation: "Block device writes should never happen from an AI agent context.",
  },
  {
    id: "DC-003",
    description: "filesystem format command",
    regex: "\\bmkfs\\.",
    severity: "critical",
    tags: ["CWE-732", "filesystem"],
  },
  {
    id: "DC-004",
    description: "write to raw block device",
    regex: ">\\s*/dev/sd[a-z]",
    severity: "critical",
    tags: ["CWE-732", "filesystem"],
  },

  // ── Remote code execution ─────────────────────────────────
  {
    id: "DC-010",
    description: "curl piped to shell",
    regex: "curl\\s+.*\\|\\s*(bash|sh|zsh|source)",
    severity: "critical",
    tags: ["OWASP-LLM09", "CWE-94", "remote-code-exec"],
    remediation: "Download the script first, review it, then execute. Never pipe directly to shell.",
  },
  {
    id: "DC-011",
    description: "wget piped to shell",
    regex: "wget\\s+.*\\|\\s*(bash|sh|zsh|source)",
    severity: "critical",
    tags: ["CWE-94", "remote-code-exec"],
  },
  {
    id: "DC-012",
    description: "eval with curl/wget",
    regex: "eval\\s+[\"']?\\$\\(.*(?:curl|wget)",
    severity: "critical",
    tags: ["CWE-94", "remote-code-exec"],
  },
  {
    id: "DC-013",
    description: "base64 decoded and piped to shell",
    regex: "base64\\s+(-d|--decode).*\\|\\s*(bash|sh|zsh|source)",
    severity: "critical",
    tags: ["CWE-94", "obfuscation"],
    remediation: "Base64-decoded content piped to shell is a common obfuscation technique.",
  },
  {
    id: "DC-014",
    description: "python/node used for shell escape",
    regex: "(python3?|node)\\s+-[ce]\\s+.*(?:subprocess|exec|system|child_process)",
    severity: "high",
    tags: ["CWE-94", "shell-escape"],
  },

  // ── Privilege escalation ──────────────────────────────────
  {
    id: "DC-020",
    description: "chmod 777 (world-writable)",
    regex: "chmod\\s+777",
    severity: "high",
    tags: ["CWE-732", "privilege-escalation"],
    remediation: "Use minimal permissions (e.g., chmod 644 for files, 755 for executables).",
  },
  {
    id: "DC-021",
    description: "write to /etc",
    regex: ">\\s*/etc/",
    severity: "high",
    tags: ["CWE-732", "privilege-escalation"],
  },
  {
    id: "DC-022",
    description: "chmod +s (setuid/setgid)",
    regex: "chmod\\s+[+][sg]",
    severity: "critical",
    tags: ["CWE-732", "privilege-escalation"],
  },
  {
    id: "DC-023",
    description: "chown root",
    regex: "chown\\s+root",
    severity: "high",
    tags: ["CWE-732", "privilege-escalation"],
  },
  {
    id: "DC-024",
    description: "sudo used by agent",
    regex: "\\bsudo\\b",
    severity: "high",
    tags: ["CWE-269", "privilege-escalation"],
    remediation: "AI agents should not use sudo. Run with appropriate permissions instead.",
  },

  // ── Source control ────────────────────────────────────────
  {
    id: "DC-030",
    description: "git force push (--force or -f, excluding --force-with-lease)",
    regex: "git\\s+push\\b.*(?:--force(?!-with-lease)|-f)(?:\\s|$)",
    severity: "high",
    tags: ["CWE-829", "source-control"],
    remediation: "Use git push --force-with-lease instead, which is safer.",
  },

  // ── Package publishing ────────────────────────────────────
  {
    id: "DC-040",
    description: "npm/yarn/pnpm publish",
    regex: "\\b(?:npm|yarn|pnpm)\\s+publish\\b",
    severity: "high",
    tags: ["CWE-829", "supply-chain"],
    remediation: "Package publishing should happen through CI/CD, not through an AI agent.",
  },

  // ── Fork bomb / denial of service ─────────────────────────
  {
    id: "DC-050",
    description: "fork bomb",
    regex: ":\\(\\)\\{\\s*:\\|:&\\s*\\};:",
    severity: "critical",
    tags: ["CWE-400", "denial-of-service"],
  },
  {
    id: "DC-051",
    description: "infinite loop patterns",
    regex: "while\\s+true\\s*;\\s*do\\s+.*done.*&",
    severity: "medium",
    tags: ["CWE-400", "denial-of-service"],
  },

  // ── Environment manipulation ──────────────────────────────
  {
    id: "DC-060",
    description: "overwriting PATH or LD_PRELOAD",
    regex: "(?:export\\s+)?(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH)\\s*=",
    severity: "high",
    tags: ["CWE-426", "environment-manipulation"],
    remediation: "AI agents should not modify PATH or dynamic linker variables.",
  },
];

// ─── Shell Tool Name Variants ───────────────────────────────────────

/**
 * All known names for shell/terminal tools across frameworks.
 * Used to determine when to apply dangerous command detection.
 */
export const SHELL_TOOL_NAMES = new Set([
  "Bash", "bash", "shell", "Shell",
  "terminal", "Terminal",
  "exec", "Exec",
  "RunCommand", "run_command",
  "execute", "Execute",
]);

// ─── Secrets Patterns ───────────────────────────────────────────────

export interface SecretPattern {
  id: string;
  description: string;
  regex: string;
  flags?: string;
  severity: "critical" | "high" | "medium";
  tags: string[];
}

/**
 * Patterns that detect credentials and secrets in tool arguments.
 * Used by SecretsLeakPolicy and handler scripts.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // ── API Keys ──────────────────────────────────────────────
  {
    id: "SK-001",
    description: "OpenAI API key",
    regex: "sk-[a-zA-Z0-9]{20,}",
    severity: "critical",
    tags: ["OWASP-LLM06", "credentials"],
  },
  {
    id: "SK-002",
    description: "GitHub token (classic or fine-grained)",
    regex: "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}",
    severity: "critical",
    tags: ["credentials"],
  },
  {
    id: "SK-003",
    description: "AWS access key",
    regex: "AKIA[0-9A-Z]{16}",
    severity: "critical",
    tags: ["credentials", "cloud"],
  },
  {
    id: "SK-004",
    description: "AWS secret key (high entropy after aws_secret)",
    regex: "(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*[A-Za-z0-9/+=]{30,}",
    severity: "critical",
    tags: ["credentials", "cloud"],
  },
  {
    id: "SK-005",
    description: "Anthropic API key",
    regex: "sk-ant-[a-zA-Z0-9-]{20,}",
    severity: "critical",
    tags: ["credentials"],
  },
  {
    id: "SK-006",
    description: "Google Cloud API key",
    regex: "AIza[0-9A-Za-z\\-_]{35}",
    severity: "critical",
    tags: ["credentials", "cloud"],
  },
  {
    id: "SK-007",
    description: "Stripe key",
    regex: "(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{20,}",
    severity: "critical",
    tags: ["credentials", "payment"],
  },
  {
    id: "SK-008",
    description: "Slack token",
    regex: "xox[baprs]-[0-9a-zA-Z-]{10,}",
    severity: "high",
    tags: ["credentials"],
  },
  {
    id: "SK-009",
    description: "npm token",
    regex: "npm_[A-Za-z0-9]{30,}",
    severity: "high",
    tags: ["credentials", "supply-chain"],
  },

  // ── Connection Strings ────────────────────────────────────
  {
    id: "SK-020",
    description: "Database connection string with credentials",
    regex: "(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@",
    severity: "critical",
    tags: ["credentials", "database"],
  },

  // ── Auth Headers ──────────────────────────────────────────
  {
    id: "SK-030",
    description: "Bearer token in command/header",
    regex: "(?:Bearer|Authorization:\\s*Bearer)\\s+[A-Za-z0-9._\\-]{20,}",
    severity: "high",
    tags: ["credentials", "auth"],
  },
  {
    id: "SK-031",
    description: "Basic auth in URL",
    regex: "https?://[^:]+:[^@]+@",
    severity: "high",
    tags: ["credentials", "auth"],
  },

  // ── Private Keys ──────────────────────────────────────────
  {
    id: "SK-040",
    description: "Private key material",
    regex: "-----BEGIN\\s+(?:RSA\\s+)?PRIVATE\\s+KEY-----",
    severity: "critical",
    tags: ["credentials", "crypto"],
  },

  // ── Generic High-Entropy ──────────────────────────────────
  {
    id: "SK-050",
    description: "Password flag in command",
    regex: "(?:--password|--passwd|-p)\\s*[=\\s]\\s*[^\\s]{8,}",
    severity: "high",
    tags: ["credentials"],
  },
  {
    id: "SK-051",
    description: "Token flag in command",
    regex: "(?:--token|-t)\\s*[=\\s]\\s*[A-Za-z0-9._\\-]{20,}",
    severity: "high",
    tags: ["credentials"],
  },
];

// ─── Sensitive File Paths ───────────────────────────────────────────

export interface SensitivePathPattern {
  id: string;
  description: string;
  /** Regex matching dangerous write targets */
  regex: string;
  severity: "critical" | "high" | "medium";
  tags: string[];
}

/**
 * File paths that are dangerous to write to.
 * Used by FileWritePolicy and handler scripts.
 */
export const SENSITIVE_WRITE_PATHS: SensitivePathPattern[] = [
  // ── SSH / Auth ────────────────────────────────────────────
  {
    id: "FW-001",
    description: "SSH config and keys",
    regex: "(?:~|\\.)?/?\\.ssh/",
    severity: "critical",
    tags: ["CWE-732", "auth", "privilege-escalation"],
  },
  {
    id: "FW-002",
    description: "GPG keys",
    regex: "\\.gnupg/",
    severity: "critical",
    tags: ["CWE-732", "auth"],
  },

  // ── Environment / Config ──────────────────────────────────
  {
    id: "FW-010",
    description: ".env files (may contain secrets)",
    regex: "(?:^|/)\\.env(?:\\..*)?$",
    severity: "high",
    tags: ["credentials", "config"],
  },
  {
    id: "FW-011",
    description: ".npmrc (may contain npm tokens)",
    regex: "(?:^|/)\\.npmrc$",
    severity: "high",
    tags: ["credentials", "supply-chain"],
  },
  {
    id: "FW-012",
    description: ".netrc (may contain credentials)",
    regex: "(?:^|/)\\.netrc$",
    severity: "high",
    tags: ["credentials"],
  },

  // ── System Directories ────────────────────────────────────
  {
    id: "FW-020",
    description: "/etc/ system configuration",
    regex: "^/etc/",
    severity: "critical",
    tags: ["CWE-732", "system"],
  },
  {
    id: "FW-021",
    description: "/usr/local/bin (system binaries)",
    regex: "^/usr/local/bin/",
    severity: "high",
    tags: ["CWE-732", "system"],
  },

  // ── Supply Chain ──────────────────────────────────────────
  {
    id: "FW-030",
    description: "package.json (postinstall script injection)",
    regex: "(?:^|/)package\\.json$",
    severity: "medium",
    tags: ["supply-chain"],
  },
  {
    id: "FW-031",
    description: ".github/workflows (CI/CD pipeline modification)",
    regex: "\\.github/workflows/",
    severity: "high",
    tags: ["supply-chain", "ci-cd"],
  },
  {
    id: "FW-032",
    description: "Dockerfile (container supply chain)",
    regex: "(?:^|/)Dockerfile",
    severity: "medium",
    tags: ["supply-chain", "container"],
  },
];

// ─── Network Egress Patterns ────────────────────────────────────────

export interface NetworkEgressPattern {
  id: string;
  description: string;
  /** Regex to detect outbound network commands */
  regex: string;
  /** Group index that captures the URL/domain (0 = full match) */
  urlGroupIndex?: number;
  tags: string[];
}

/**
 * Patterns that detect outbound network activity in commands.
 * Used by NetworkEgressPolicy to extract target domains.
 */
export const NETWORK_EGRESS_PATTERNS: NetworkEgressPattern[] = [
  {
    id: "NE-001",
    description: "curl with URL",
    regex: "\\bcurl\\b[^|]*\\s+(https?://[^\\s'\"]+)",
    urlGroupIndex: 1,
    tags: ["network", "http"],
  },
  {
    id: "NE-002",
    description: "wget with URL",
    regex: "\\bwget\\b[^|]*\\s+(https?://[^\\s'\"]+)",
    urlGroupIndex: 1,
    tags: ["network", "http"],
  },
  {
    id: "NE-003",
    description: "fetch/httpie/requests in Python",
    regex: "(?:requests|httpx|urllib)\\.(?:get|post|put|delete|patch)\\s*\\(\\s*['\"]?(https?://[^\\s'\"]+)",
    urlGroupIndex: 1,
    tags: ["network", "python"],
  },
  {
    id: "NE-004",
    description: "PowerShell web requests",
    regex: "(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\\s+.*?(https?://[^\\s'\"]+)",
    urlGroupIndex: 1,
    tags: ["network", "powershell"],
  },
  {
    id: "NE-005",
    description: "Node.js fetch/http",
    regex: "(?:fetch|axios|got|http\\.get|https\\.get)\\s*\\(\\s*['\"`]?(https?://[^\\s'\"`]+)",
    urlGroupIndex: 1,
    tags: ["network", "node"],
  },
  {
    id: "NE-006",
    description: "ssh/scp outbound",
    regex: "\\b(?:ssh|scp)\\b.*?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)",
    urlGroupIndex: 1,
    tags: ["network", "ssh"],
  },
  {
    id: "NE-007",
    description: "netcat / ncat / nc",
    regex: "\\b(?:nc|ncat|netcat)\\b\\s+.*?([a-zA-Z0-9._-]+)\\s+(\\d+)",
    urlGroupIndex: 1,
    tags: ["network", "raw-socket"],
  },
];

// ─── Helper: Compile Patterns ───────────────────────────────────────

/**
 * Compile pattern strings into RegExp objects.
 * Used by policy classes at initialization time.
 */
export function compilePatterns<T extends { regex: string; flags?: string }>(
  patterns: T[]
): Array<T & { compiled: RegExp }> {
  return patterns.map((p) => ({
    ...p,
    compiled: new RegExp(p.regex, p.flags ?? ""),
  }));
}

/**
 * Export patterns as a JSON-safe format for embedding in handler scripts.
 * The handler scripts can't import TypeScript modules, so they get
 * the patterns baked in as JSON at generation time.
 */
export function patternsToHandlerJSON(patterns: DangerousPattern[]): string {
  return JSON.stringify(
    patterns.map((p) => ({
      id: p.id,
      pattern: p.regex,
      label: p.description,
      severity: p.severity,
    }))
  );
}

export function secretPatternsToHandlerJSON(patterns: SecretPattern[]): string {
  return JSON.stringify(
    patterns.map((p) => ({
      id: p.id,
      pattern: p.regex,
      flags: p.flags ?? "",
      label: p.description,
      severity: p.severity,
    }))
  );
}

export function sensitivePathsToHandlerJSON(patterns: SensitivePathPattern[]): string {
  return JSON.stringify(
    patterns.map((p) => ({
      id: p.id,
      pattern: p.regex,
      label: p.description,
      severity: p.severity,
    }))
  );
}

export function networkPatternsToHandlerJSON(patterns: NetworkEgressPattern[]): string {
  return JSON.stringify(
    patterns.map((p) => ({
      id: p.id,
      pattern: p.regex,
      urlGroup: p.urlGroupIndex ?? 0,
      label: p.description,
    }))
  );
}
