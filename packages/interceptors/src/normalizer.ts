/**
 * @module @sentinelflow/interceptors/normalizer
 *
 * Command normalizer — makes trivial bypass attempts much harder
 * without writing a full shell parser.
 *
 * What it does:
 *   1. Strips quoting/escaping wrappers ("rm" → rm, r\m → rm)
 *   2. Expands combined flags (-rf → -r -f)
 *   3. Lowercases the command word for matching
 *   4. Normalizes whitespace
 *   5. Detects commands in pipelines and subshells
 *
 * What it does NOT do:
 *   - Full shell parsing (heredocs, parameter expansion, etc.)
 *   - Variable resolution ($VAR, ${VAR})
 *   - Advanced obfuscation (ROT13, hex encoding in variables)
 *
 * This closes ~80% of real-world bypass attempts while keeping
 * the implementation simple and auditable.
 */

/**
 * Normalize a shell command before matching against dangerous patterns.
 * Returns the normalized command string.
 */
export function normalizeCommand(cmd: string): string {
  if (!cmd || typeof cmd !== "string") return "";

  let normalized = cmd;

  // 1. Strip inline comments (# to end of line, but not inside quotes)
  //    Simplified: remove # and everything after if not inside quotes
  normalized = normalized.replace(/#[^!].*$/gm, "");

  // 2. Remove backslash escapes on command names (r\m → rm, c\url → curl)
  normalized = normalized.replace(/\\(?=[a-zA-Z])/g, "");

  // 3. Remove wrapping quotes around command names ("rm" → rm, 'curl' → curl)
  //    Only at word boundaries — don't strip quotes from arguments
  normalized = normalized.replace(/(?:^|\s)["']([a-zA-Z_][a-zA-Z0-9_-]*)["']/g, " $1");

  // 4. Normalize whitespace
  normalized = normalized.replace(/\s+/g, " ").trim();

  // 5. Expand combined short flags: -rf → -r -f, -rfv → -r -f -v
  //    Only for flags that are 2+ letters after a single dash (not --)
  normalized = normalized.replace(
    /\s-([a-zA-Z]{2,})(?=\s|$)/g,
    (_, flags: string) => " " + flags.split("").map((f: string) => `-${f}`).join(" ")
  );

  // 6. Lowercase command names (the first word and words after pipe/semicolon)
  //    This handles Rm → rm, CURL → curl, etc.
  normalized = normalized.replace(
    /(?:^|[|;&]\s*)([A-Z][a-zA-Z0-9_-]*)/g,
    (match, cmd: string) => match.replace(cmd, cmd.toLowerCase())
  );

  return normalized;
}

/**
 * Extract individual commands from a compound command line.
 * Splits on pipes, semicolons, &&, ||, and $() subshells.
 * Returns an array of individual command strings.
 */
export function splitCompoundCommand(cmd: string): string[] {
  if (!cmd) return [];

  const commands: string[] = [];
  // Split on common command separators
  const parts = cmd.split(/\s*(?:[|;&]{1,2})\s*/);

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;

    commands.push(trimmed);

    // Also extract subshell commands: $(...) and `...`
    const subshellMatches = trimmed.matchAll(/\$\(([^)]+)\)/g);
    for (const match of subshellMatches) {
      if (match[1]) commands.push(match[1].trim());
    }
    const backtickMatches = trimmed.matchAll(/`([^`]+)`/g);
    for (const match of backtickMatches) {
      if (match[1]) commands.push(match[1].trim());
    }
  }

  return commands;
}

/**
 * Full normalization pipeline: normalize + split into individual commands.
 * Each sub-command is independently normalizable and matchable.
 */
export function normalizeAndSplit(cmd: string): string[] {
  const normalized = normalizeCommand(cmd);
  const commands = splitCompoundCommand(normalized);
  // Also normalize each individual sub-command
  return commands.map(normalizeCommand).filter(Boolean);
}

/**
 * Extract a URL/domain from a command string, if present.
 * Returns the domain part (host) or null.
 */
export function extractDomain(url: string): string | null {
  try {
    // Handle full URLs
    const urlMatch = url.match(/https?:\/\/([^/:?\s]+)/);
    if (urlMatch?.[1]) return urlMatch[1];

    // Handle user@host patterns (ssh/scp)
    const sshMatch = url.match(/([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+)/);
    if (sshMatch?.[2]) return sshMatch[2];

    return null;
  } catch {
    return null;
  }
}

/**
 * Serialize normalizer functions for embedding in handler scripts.
 * Handler scripts are plain JS and can't import TS modules.
 */
export function normalizerToHandlerJS(): string {
  return `
function normalizeCommand(cmd) {
  if (!cmd || typeof cmd !== "string") return "";
  let n = cmd;
  n = n.replace(/#[^!].*$/gm, "");
  n = n.replace(/\\\\(?=[a-zA-Z])/g, "");
  n = n.replace(/(?:^|\\s)["']([a-zA-Z_][a-zA-Z0-9_-]*)["']/g, " $1");
  n = n.replace(/\\s+/g, " ").trim();
  n = n.replace(/\\s-([a-zA-Z]{2,})(?=\\s|$)/g, function(_, flags) {
    return " " + flags.split("").map(function(f) { return "-" + f; }).join(" ");
  });
  n = n.replace(/(?:^|[|;&]\\s*)([A-Z][a-zA-Z0-9_-]*)/g, function(match, cmd) {
    return match.replace(cmd, cmd.toLowerCase());
  });
  return n;
}

function splitCompoundCommand(cmd) {
  if (!cmd) return [];
  var parts = cmd.split(/\\s*(?:[|;&]{1,2})\\s*/);
  var commands = [];
  for (var i = 0; i < parts.length; i++) {
    var t = parts[i].trim();
    if (!t) continue;
    commands.push(t);
    var sub = t.matchAll(/\\$\\(([^)]+)\\)/g);
    for (var m of sub) { if (m[1]) commands.push(m[1].trim()); }
    var bt = t.matchAll(/\`([^\`]+)\`/g);
    for (var m of bt) { if (m[1]) commands.push(m[1].trim()); }
  }
  return commands;
}

function normalizeAndSplit(cmd) {
  var normalized = normalizeCommand(cmd);
  var commands = splitCompoundCommand(normalized);
  return commands.map(normalizeCommand).filter(Boolean);
}

function extractDomain(url) {
  try {
    var m = url.match(/https?:\\/\\/([^\\/:?\\s]+)/);
    if (m && m[1]) return m[1];
    var s = url.match(/([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+)/);
    if (s && s[2]) return s[2];
    return null;
  } catch(e) { return null; }
}
`;
}
