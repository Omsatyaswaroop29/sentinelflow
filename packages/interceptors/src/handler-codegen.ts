/**
 * @module @sentinelflow/interceptors/handler-codegen
 *
 * Shared code generator for handler scripts.
 *
 * Generates SELF-CONTAINED JavaScript policy evaluation code that gets
 * baked into every handler script at install time. All patterns come from
 * the central registry via JSON.stringify → new RegExp(), which handles
 * escaping correctly across all nesting levels.
 *
 * DESIGN: No regex literals in generated code. All regexes are compiled
 * from JSON strings at handler startup via new RegExp(). This eliminates
 * the template literal double-escaping problem that caused handler crashes.
 */

import {
  DANGEROUS_COMMAND_PATTERNS,
  SECRET_PATTERNS,
  SENSITIVE_WRITE_PATHS,
  SHELL_TOOL_NAMES,
} from "./patterns";

export function generatePolicyEvaluationCode(enforcementMode: string): string {
  // All pattern data goes through JSON.stringify, which correctly
  // handles regex special characters. Patterns are compiled at handler
  // startup via new RegExp(string), not regex literals.

  const dangerous = JSON.stringify(DANGEROUS_COMMAND_PATTERNS.map((p) => ({
    id: p.id, regex: p.regex, flags: p.flags ?? "", label: p.description,
  })));

  const secrets = JSON.stringify(SECRET_PATTERNS.map((p) => ({
    id: p.id, regex: p.regex, flags: p.flags ?? "", label: p.description,
  })));

  const sensitivePaths = JSON.stringify(SENSITIVE_WRITE_PATHS.map((p) => ({
    id: p.id, regex: p.regex, label: p.description,
  })));

  const shellTools = JSON.stringify([...SHELL_TOOL_NAMES]);

  // Build the code as a plain string, NOT a template literal.
  // This avoids all escaping issues.
  const lines: string[] = [];
  const L = (s: string) => lines.push(s);

  L(`// --- Self-contained summarizer ---`);
  L(`function _sfSummarize(input) {`);
  L(`  if (!input) return "";`);
  L(`  if (typeof input === "string") {`);
  L(`    try { var p = JSON.parse(input); return _sfSummarize(p); } catch(e) { return input.slice(0, 500); }`);
  L(`  }`);
  L(`  if (typeof input.command === "string") return input.command.slice(0, 500);`);
  L(`  if (typeof input.file_path === "string") return "file: " + input.file_path;`);
  L(`  if (typeof input.filePath === "string") return "file: " + input.filePath;`);
  L(`  if (typeof input.path === "string") return "path: " + input.path;`);
  L(`  if (typeof input.file === "string") return "file: " + input.file;`);
  L(`  try { var raw = JSON.stringify(input); return raw.length > 500 ? raw.slice(0, 500) + "..." : raw; }`);
  L(`  catch(e) { return ""; }`);
  L(`}`);
  L(``);

  L(`// --- Minimal command normalization (handler-safe) ---`);
  L(`function _sfNormalizeCommand(cmd) {`);
  L(`  if (!cmd) return "";`);
  L(`  var s = String(cmd);`);
  L(`  try { if (s.normalize) s = s.normalize("NFKC"); } catch(e) {}`);
  L(`  // strip common zero-width/invisible characters`);
  L(`  s = s.replace(/[\\u200B-\\u200D\\u2060\\u2063]/g, "");`);
  L(`  // normalize whitespace (newlines/tabs) to single spaces`);
  L(`  s = s.replace(/\\s+/g, " ").trim();`);
  L(`  return s;`);
  L(`}`);
  L(``);

  L(`// --- Pattern compilation (from central registry via JSON) ---`);
  L(`var SHELL_TOOLS = new Set(${shellTools});`);
  L(``);
  L(`var _sfDangerous = ${dangerous}.map(function(p) {`);
  L(`  try {`);
  L(`    var flags = (p.flags || "");`);
  L(`    if (flags.indexOf("i") === -1) flags += "i";`);
  L(`    return { id: p.id, re: new RegExp(p.regex, flags), label: p.label };`);
  L(`  }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(``);
  L(`var _sfSecrets = ${secrets}.map(function(p) {`);
  L(`  try { return { id: p.id, re: new RegExp(p.regex, p.flags), label: p.label }; }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(``);
  L(`var _sfSensitivePaths = ${sensitivePaths}.map(function(p) {`);
  L(`  try { return { id: p.id, re: new RegExp(p.regex, "i"), label: p.label }; }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(``);
  L(`var WRITE_TOOLS = new Set(["Write","write","Edit","edit","MultiEdit","multiedit","Create","create","FileEdit","file_edit","create_file","write_file","edit_file","NotebookEdit","TodoWrite"]);`);
  L(``);

  L(`// --- Enterprise Policy Evaluation ---`);
  L(`function evaluatePolicy(toolName, toolInput) {`);
  L(`  if (TOOL_BLOCKLIST.has(toolName))`);
  L(`    return { block: true, flag: true, reason: "Tool \\"" + toolName + "\\" is in the blocklist", id: "tool_blocklist" };`);
  L(`  // Tool allowlist semantics: if allowlist is configured, deny everything not explicitly allowed.`);
  L(`  // In monitor mode we do not block, but we still return a reason/id for logging parity.`);
  L(`  if (TOOL_ALLOWLIST.size > 0 && !TOOL_ALLOWLIST.has(toolName)) {`);
  L(`    var enforce = ENFORCEMENT_MODE === "enforce";`);
  L(`    return { block: enforce, flag: true, reason: "Tool \\"" + toolName + "\\" is not in the allowlist", id: "tool_allowlist" };`);
  L(`  }`);
  L(`  if (TOOL_ALLOWLIST.size > 0 && TOOL_ALLOWLIST.has(toolName))`);
  L(`    return { block: false, flag: false };`);
  L(``);
  L(`  var enforce = ENFORCEMENT_MODE === "enforce";`);
  L(`  var summary = _sfSummarize(toolInput);`);
  L(``);
  L(`  // Dangerous command detection (all shell tool variants)`);
  L(`  if (SHELL_TOOLS.has(toolName) && toolInput) {`);
  L(`    var rawCmd = "";`);
  L(`    if (typeof toolInput === "string") {`);
  L(`      try { rawCmd = JSON.parse(toolInput).command || ""; } catch(e) { rawCmd = toolInput; }`);
  L(`    } else { rawCmd = toolInput.command || ""; }`);
  L(``);
  L(`    if (rawCmd) {`);
  L(`      var cmdForDangerous = _sfNormalizeCommand(rawCmd);`);
  L(`      var cmdForSecrets = _sfNormalizeCommand(rawCmd);`);
  L(`      // Reduce obvious wrappers and absolute-path command forms for matching`);
  L(`      cmdForDangerous = cmdForDangerous.replace(/^(?:\\\\?command)\\s+/i, "");`);
  L(`      cmdForDangerous = cmdForDangerous.replace(/\\b\\/[\\w.+-]+(?:\\/[\\w.+-]+)+\\b/g, function(m){ return m.split('/').pop(); });`);
  L(`      for (var i = 0; i < _sfDangerous.length; i++) {`);
  L(`        if (_sfDangerous[i].re.test(cmdForDangerous)) {`);
  L(`          return { block: enforce, flag: true, reason: "Dangerous [" + _sfDangerous[i].id + "]: " + _sfDangerous[i].label + " -- " + rawCmd.slice(0, 100), id: "dangerous_commands" };`);
  L(`        }`);
  L(`      }`);
  L(``);
  L(`      // Secrets in shell commands`);
  L(`      for (var s = 0; s < _sfSecrets.length; s++) {`);
  L(`        if (_sfSecrets[s].re.test(cmdForSecrets)) {`);
  L(`          return { block: enforce, flag: true, reason: "Secret detected [" + _sfSecrets[s].id + "]: " + _sfSecrets[s].label, id: "secrets_leak" };`);
  L(`        }`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(``);
  L(`  // File write governance (Write/Edit tools)`);
  L(`  if (WRITE_TOOLS.has(toolName) && toolInput) {`);
  L(`    var fp = "";`);
  L(`    if (typeof toolInput === "string") {`);
  L(`      try { var pp = JSON.parse(toolInput); fp = pp.file_path || pp.filePath || pp.path || pp.file || ""; } catch(e) { fp = toolInput; }`);
  L(`    } else { fp = toolInput.file_path || toolInput.filePath || toolInput.path || toolInput.file || ""; }`);
  L(`    if (fp) {`);
  L(`      for (var w = 0; w < _sfSensitivePaths.length; w++) {`);
  L(`        if (_sfSensitivePaths[w].re.test(fp)) {`);
  L(`          return { block: enforce, flag: true, reason: "Write to sensitive path [" + _sfSensitivePaths[w].id + "]: " + _sfSensitivePaths[w].label, id: "file_write" };`);
  L(`        }`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(``);
  L(`  // Secrets in any tool input`);
  L(`  if (summary) {`);
  L(`    for (var k = 0; k < _sfSecrets.length; k++) {`);
  L(`      if (_sfSecrets[k].re.test(summary)) {`);
  L(`        return { block: enforce, flag: true, reason: "Secret detected [" + _sfSecrets[k].id + "]: " + _sfSecrets[k].label, id: "secrets_leak" };`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(``);
  L(`  return { block: false, flag: false };`);
  L(`}`);

  return lines.join("\n");
}
