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
  NETWORK_EGRESS_PATTERNS,
  SECRET_PATTERNS,
  SENSITIVE_WRITE_PATHS,
  SHELL_TOOL_NAMES,
} from "./patterns";
import { DEFAULT_CLASSIFICATION_RULES, type DataClassification } from "./data-boundary";
import { DEFAULT_ROLE_PRIVILEGES, DEFAULT_TOOL_PRIVILEGES } from "./identity";

// ─── Advanced policy config (data boundary, identity/RBAC, sequence) ──

export interface DataBoundaryCodegenConfig {
  enabled: boolean;
  enforcementMode: "monitor" | "enforce";
  defaultMaxClassification: DataClassification;
  agentClearances: Array<{ agent: string; max_classification: DataClassification }>;
  customRules: Array<{ pattern: string; classification: DataClassification; label?: string }>;
}

export interface IdentityCodegenConfig {
  enabled: boolean;
  enforcementMode: "monitor" | "enforce";
  defaultRole: string;
  defaultPrivilege: number;
  environment: string;
  externalFacing: boolean;
  agentRoles: Record<string, string>;
  agentPrivileges: Record<string, number>;
}

export interface SequenceDetectionCodegenConfig {
  enabled: boolean;
  enforcementMode: "monitor" | "enforce";
  windowMinutes: number;
  minConfidence: number;
}

export interface AdvancedPolicyCodegenConfig {
  dataBoundary?: DataBoundaryCodegenConfig;
  identity?: IdentityCodegenConfig;
  sequenceDetection?: SequenceDetectionCodegenConfig;
}

const DEFAULT_DATA_BOUNDARY: DataBoundaryCodegenConfig = {
  enabled: true,
  enforcementMode: "monitor",
  defaultMaxClassification: "internal",
  agentClearances: [],
  customRules: [],
};

const DEFAULT_IDENTITY: IdentityCodegenConfig = {
  enabled: true,
  enforcementMode: "monitor",
  defaultRole: "executor",
  defaultPrivilege: DEFAULT_ROLE_PRIVILEGES.executor,
  environment: "development",
  externalFacing: false,
  agentRoles: {},
  agentPrivileges: {},
};

const DEFAULT_SEQUENCE_DETECTION: SequenceDetectionCodegenConfig = {
  enabled: true,
  enforcementMode: "monitor",
  windowMinutes: 5,
  minConfidence: 0.7,
};

export function generatePolicyEvaluationCode(
  enforcementMode: string,
  advanced?: AdvancedPolicyCodegenConfig
): string {
  const dataBoundary = { ...DEFAULT_DATA_BOUNDARY, ...advanced?.dataBoundary };
  const identity = { ...DEFAULT_IDENTITY, ...advanced?.identity };
  const sequenceDetection = { ...DEFAULT_SEQUENCE_DETECTION, ...advanced?.sequenceDetection };
  // All pattern data goes through JSON.stringify, which correctly
  // handles regex special characters. Patterns are compiled at handler
  // startup via new RegExp(string), not regex literals.

  const dangerous = JSON.stringify(DANGEROUS_COMMAND_PATTERNS.map((p) => ({
    id: p.id, regex: p.regex, flags: p.flags ?? "", label: p.description,
  })));

  const secrets = JSON.stringify(SECRET_PATTERNS.map((p) => ({
    id: p.id, regex: p.regex, flags: p.flags ?? "", label: p.description,
  })));

  const networkEgress = JSON.stringify(NETWORK_EGRESS_PATTERNS.map((p) => ({
    id: p.id, regex: p.regex, urlGroupIndex: p.urlGroupIndex ?? 0, label: p.description,
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

  L(`function _sfStripQuotes(s) {`);
  L(`  if (!s) return "";`);
  L(`  var t = String(s);`);
  L(`  if ((t[0] === '"' && t[t.length - 1] === '"') || (t[0] === "'" && t[t.length - 1] === "'")) {`);
  L(`    return t.slice(1, -1);`);
  L(`  }`);
  L(`  return t;`);
  L(`}`);
  L(``);

  L(`function _sfExtractWriteTargets(cmd) {`);
  L(`  var out = [];`);
  L(`  if (!cmd) return out;`);
  L(`  var tokens = String(cmd).split(" ");`);
  L(`  var seenTee = false;`);
  L(`  for (var i = 0; i < tokens.length; i++) {`);
  L(`    var tok = tokens[i];`);
  L(`    if (!tok) continue;`);
  L(``);
  L(`    // tee writes to files (e.g. tee -a ~/.ssh/authorized_keys)`);
  L(`    if (tok === "tee") { seenTee = true; continue; }`);
  L(`    if (seenTee) {`);
  L(`      if (tok[0] === "-") continue;`);
  L(`      out.push(_sfStripQuotes(tok));`);
  L(`      // keep scanning: tee can take multiple file operands`);
  L(`      continue;`);
  L(`    }`);
  L(``);
  L(`    // redirections: > file, >> file, 2>file, &>file, etc.`);
  L(`    if (tok === ">" || tok === ">>" || tok === "1>" || tok === "1>>" || tok === "2>" || tok === "2>>" || tok === "&>" || tok === "&>>") {`);
  L(`      if (i + 1 < tokens.length) out.push(_sfStripQuotes(tokens[i + 1]));`);
  L(`      continue;`);
  L(`    }`);
  L(``);
  L(`    var gt = tok.lastIndexOf(">");`);
  L(`    if (gt !== -1 && gt + 1 < tok.length) {`);
  L(`      var tail = tok.slice(gt + 1);`);
  L(`      // ignore cases like "->" or "=>" by requiring a plausible path start`);
  L(`      if (tail[0] === "/" || tail[0] === "." || tail[0] === "~") out.push(_sfStripQuotes(tail));`);
  L(`    }`);
  L(`  }`);
  L(`  return out;`);
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

  L(`var _sfNetworkEgress = ${networkEgress}.map(function(p) {`);
  L(`  try { return { id: p.id, re: new RegExp(p.regex, "i"), urlGroupIndex: p.urlGroupIndex, label: p.label }; }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(``);

  L(`function _sfExtractDomain(s) {`);
  L(`  if (!s) return "";`);
  L(`  var t = _sfStripQuotes(String(s));`);
  L(`  var at = t.lastIndexOf("@");`);
  L(`  if (at !== -1 && at + 1 < t.length) t = t.slice(at + 1);`);
  L(`  var scheme = t.indexOf("://");`);
  L(`  if (scheme !== -1) t = t.slice(scheme + 3);`);
  L(`  var slash = t.indexOf("/");`);
  L(`  if (slash !== -1) t = t.slice(0, slash);`);
  L(`  var colon = t.indexOf(":");`);
  L(`  if (colon !== -1) t = t.slice(0, colon);`);
  L(`  t = t.replace(/^\\[|\\]$/g, "");`);
  L(`  t = t.toLowerCase().replace(/[^a-z0-9._-]/g, "");`);
  L(`  return t;`);
  L(`}`);
  L(``);

  L(`function _sfIsDomainAllowed(domain) {`);
  L(`  if (!domain) return true;`);
  L(`  var allowed = Array.isArray(EGRESS_ALLOWED_DOMAINS) ? EGRESS_ALLOWED_DOMAINS : [];`);
  L(`  var blocked = Array.isArray(EGRESS_BLOCKED_DOMAINS) ? EGRESS_BLOCKED_DOMAINS : [];`);
  L(`  var blockedSet = new Set(blocked.map(function(d){ return String(d || "").toLowerCase(); }));`);
  L(`  if (blockedSet.has(domain)) return false;`);
  L(`  var allowExact = new Set();`);
  L(`  var allowWild = [];`);
  L(`  for (var i = 0; i < allowed.length; i++) {`);
  L(`    var d = String(allowed[i] || "").toLowerCase();`);
  L(`    if (!d) continue;`);
  L(`    if (d.indexOf("*.") === 0) allowWild.push(d.slice(2));`);
  L(`    else allowExact.add(d);`);
  L(`  }`);
  L(`  if (allowExact.size === 0 && allowWild.length === 0) return true;`);
  L(`  if (allowExact.has(domain)) return true;`);
  L(`  for (var w = 0; w < allowWild.length; w++) {`);
  L(`    if (domain === allowWild[w] || domain.endsWith("." + allowWild[w])) return true;`);
  L(`  }`);
  L(`  return false;`);
  L(`}`);
  L(``);

  L(`var _sfSensitivePaths = ${sensitivePaths}.map(function(p) {`);
  L(`  try { return { id: p.id, re: new RegExp(p.regex, "i"), label: p.label }; }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(``);
  L(`var WRITE_TOOLS = new Set(["Write","write","Edit","edit","MultiEdit","multiedit","Create","create","FileEdit","file_edit","create_file","write_file","edit_file","NotebookEdit","TodoWrite"]);`);
  L(`var READ_TOOLS = new Set(["Read","read","ReadFile","read_file","View","view","Cat","cat","ListDir","list_dir"]);`);
  L(``);

  // ─── Data boundary classification ──────────────────────────────
  const classificationRulesData = JSON.stringify([
    ...DEFAULT_CLASSIFICATION_RULES.map((r) => ({ pattern: r.pattern, classification: r.classification, label: r.label })),
    ...dataBoundary.customRules.map((r) => ({ pattern: r.pattern, classification: r.classification, label: r.label ?? "Custom rule" })),
  ]);
  const agentClearancesData = JSON.stringify(dataBoundary.agentClearances);

  L(`// --- Data boundary classification (public/internal/restricted/system) ---`);
  L(`var DATA_BOUNDARY_ENABLED = ${JSON.stringify(dataBoundary.enabled)};`);
  L(`var DATA_BOUNDARY_MODE = ${JSON.stringify(dataBoundary.enforcementMode)};`);
  L(`var DATA_BOUNDARY_DEFAULT_MAX = ${JSON.stringify(dataBoundary.defaultMaxClassification)};`);
  L(`var _sfClassLevel = { public: 0, internal: 1, restricted: 2, system: 3 };`);
  L(`var _sfClassRules = ${classificationRulesData}.map(function(r) {`);
  L(`  try { return { re: new RegExp(r.pattern, "i"), classification: r.classification, label: r.label }; }`);
  L(`  catch(e) { return null; }`);
  L(`}).filter(Boolean);`);
  L(`var _sfClearanceExact = {};`);
  L(`var _sfClearanceWild = [];`);
  L(`(function() {`);
  L(`  var list = ${agentClearancesData};`);
  L(`  for (var i = 0; i < list.length; i++) {`);
  L(`    var c = list[i];`);
  L(`    if (c.agent.indexOf("*") !== -1) {`);
  L(`      try { _sfClearanceWild.push({ re: new RegExp("^" + c.agent.split("*").join(".*") + "$"), max: c.max_classification }); } catch(e) {}`);
  L(`    } else { _sfClearanceExact[c.agent] = c.max_classification; }`);
  L(`  }`);
  L(`})();`);
  L(``);
  L(`function _sfClassify(p) {`);
  L(`  for (var i = 0; i < _sfClassRules.length; i++) {`);
  L(`    if (_sfClassRules[i].re.test(p)) return _sfClassRules[i];`);
  L(`  }`);
  L(`  return { classification: "public", label: "Source code / general" };`);
  L(`}`);
  L(``);
  L(`function _sfIsPathLike(s) {`);
  L(`  if (!s || s.length < 2 || s.length > 500) return false;`);
  L(`  return /^(?:\\/|\\.{0,2}\\/|~\\/|[a-zA-Z]:[\\\\/])/.test(s) || /\\.[a-zA-Z0-9]{1,10}$/.test(s);`);
  L(`}`);
  L(``);
  L(`function _sfExtractPaths(toolName, toolInput) {`);
  L(`  var paths = [];`);
  L(`  if (!toolInput) return paths;`);
  L(`  var obj = toolInput;`);
  L(`  if (typeof toolInput === "string") { try { obj = JSON.parse(toolInput); } catch(e) { obj = null; } }`);
  L(`  if (obj && typeof obj === "object") {`);
  L(`    var pathKeys = ["file_path","filePath","path","file","target","source","destination","filename"];`);
  L(`    (function scan(o, depth) {`);
  L(`      if (!o || typeof o !== "object" || depth > 2) return;`);
  L(`      for (var key in o) {`);
  L(`        var val = o[key];`);
  L(`        if (typeof val === "string") {`);
  L(`          if (pathKeys.indexOf(key) !== -1 || _sfIsPathLike(val)) paths.push(val);`);
  L(`        } else if (val && typeof val === "object" && !Array.isArray(val)) {`);
  L(`          scan(val, depth + 1);`);
  L(`        }`);
  L(`      }`);
  L(`    })(obj, 0);`);
  L(`    if (SHELL_TOOLS.has(toolName) && typeof obj.command === "string") {`);
  L(`      var tokens = obj.command.split(/\\s+/);`);
  L(`      for (var t = 0; t < tokens.length; t++) {`);
  L(`        var tok = _sfStripQuotes(tokens[t]);`);
  L(`        if (_sfIsPathLike(tok)) paths.push(tok);`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(`  return paths;`);
  L(`}`);
  L(``);
  L(`function _sfAgentMaxClassification(agentId) {`);
  L(`  if (_sfClearanceExact.hasOwnProperty(agentId)) return _sfClearanceExact[agentId];`);
  L(`  for (var i = 0; i < _sfClearanceWild.length; i++) {`);
  L(`    if (_sfClearanceWild[i].re.test(agentId)) return _sfClearanceWild[i].max;`);
  L(`  }`);
  L(`  return DATA_BOUNDARY_DEFAULT_MAX;`);
  L(`}`);
  L(``);
  L(`function evaluateDataBoundary(agentId, toolName, toolInput) {`);
  L(`  if (!DATA_BOUNDARY_ENABLED) return { block: false, flag: false };`);
  L(`  var paths = _sfExtractPaths(toolName, toolInput);`);
  L(`  if (!paths.length) return { block: false, flag: false };`);
  L(`  var highest = null, highestLevel = -1;`);
  L(`  for (var i = 0; i < paths.length; i++) {`);
  L(`    var c = _sfClassify(paths[i]);`);
  L(`    var lvl = _sfClassLevel[c.classification];`);
  L(`    if (lvl > highestLevel) { highestLevel = lvl; highest = { classification: c.classification, label: c.label, path: paths[i] }; }`);
  L(`  }`);
  L(`  if (!highest || highestLevel <= 0) return { block: false, flag: false };`); // public paths never trigger
  L(`  var agentMax = _sfAgentMaxClassification(agentId);`);
  L(`  var agentLevel = _sfClassLevel[agentMax] !== undefined ? _sfClassLevel[agentMax] : _sfClassLevel[DATA_BOUNDARY_DEFAULT_MAX];`);
  L(`  if (highestLevel > agentLevel) {`);
  L(`    var enforce = DATA_BOUNDARY_MODE === "enforce";`);
  L(`    return { block: enforce, flag: true, reason: "Data boundary [" + highest.classification + "]: " + highest.label + " -- " + highest.path + " (agent clearance: " + agentMax + ")", id: "data_boundary" };`);
  L(`  }`);
  L(`  return { block: false, flag: false };`);
  L(`}`);
  L(``);

  // ─── Identity / RBAC / environment policy ──────────────────────
  const rolePrivilegesData = JSON.stringify(DEFAULT_ROLE_PRIVILEGES);
  const toolPrivilegesData = JSON.stringify(DEFAULT_TOOL_PRIVILEGES);
  const agentRolesData = JSON.stringify(identity.agentRoles);
  const agentPrivilegesData = JSON.stringify(identity.agentPrivileges);

  L(`// --- Identity / role-based access control / environment policy ---`);
  L(`var IDENTITY_ENABLED = ${JSON.stringify(identity.enabled)};`);
  L(`var IDENTITY_MODE = ${JSON.stringify(identity.enforcementMode)};`);
  L(`var IDENTITY_DEFAULT_ROLE = ${JSON.stringify(identity.defaultRole)};`);
  L(`var IDENTITY_DEFAULT_PRIVILEGE = ${JSON.stringify(identity.defaultPrivilege)};`);
  L(`var IDENTITY_ENVIRONMENT = ${JSON.stringify(identity.environment)};`);
  L(`var IDENTITY_EXTERNAL_FACING = ${JSON.stringify(identity.externalFacing)};`);
  L(`var IDENTITY_AGENT_ROLES = ${agentRolesData};`);
  L(`var IDENTITY_AGENT_PRIVILEGES = ${agentPrivilegesData};`);
  L(`var _sfRolePrivileges = ${rolePrivilegesData};`);
  L(`var _sfToolPrivileges = ${toolPrivilegesData};`);
  L(``);
  L(`function _sfResolvePrivilege(agentId) {`);
  L(`  if (IDENTITY_AGENT_PRIVILEGES.hasOwnProperty(agentId)) return IDENTITY_AGENT_PRIVILEGES[agentId];`);
  L(`  if (IDENTITY_AGENT_ROLES.hasOwnProperty(agentId)) {`);
  L(`    var role = IDENTITY_AGENT_ROLES[agentId];`);
  L(`    return _sfRolePrivileges.hasOwnProperty(role) ? _sfRolePrivileges[role] : IDENTITY_DEFAULT_PRIVILEGE;`);
  L(`  }`);
  L(`  return IDENTITY_DEFAULT_PRIVILEGE;`);
  L(`}`);
  L(``);
  L(`function _sfResolveRole(agentId) {`);
  L(`  return IDENTITY_AGENT_ROLES.hasOwnProperty(agentId) ? IDENTITY_AGENT_ROLES[agentId] : IDENTITY_DEFAULT_ROLE;`);
  L(`}`);
  L(``);
  L(`function evaluateIdentity(agentId, toolName) {`);
  L(`  if (!IDENTITY_ENABLED || !toolName) return { block: false, flag: false };`);
  L(`  var enforce = IDENTITY_MODE === "enforce";`);
  L(`  var role = _sfResolveRole(agentId);`);
  L(`  var privilege = _sfResolvePrivilege(agentId);`);
  L(`  var required = _sfToolPrivileges.hasOwnProperty(toolName) ? _sfToolPrivileges[toolName] : 1;`);
  L(`  if (privilege < required) {`);
  L(`    return { block: enforce, flag: true, reason: "RBAC: agent \\"" + agentId + "\\" (role: " + role + ", privilege: " + privilege + ") used tool \\"" + toolName + "\\" requiring privilege " + required, id: "role_based_access" };`);
  L(`  }`);
  L(`  if (IDENTITY_ENVIRONMENT === "production" && SHELL_TOOLS.has(toolName)) {`);
  L(`    return { block: enforce, flag: true, reason: "Environment policy: tool \\"" + toolName + "\\" is blocked in production for agent \\"" + agentId + "\\"", id: "environment_policy" };`);
  L(`  }`);
  L(`  if (IDENTITY_EXTERNAL_FACING && (SHELL_TOOLS.has(toolName) || WRITE_TOOLS.has(toolName))) {`);
  L(`    return { block: enforce, flag: true, reason: "Environment policy: external-facing agent \\"" + agentId + "\\" cannot use tool \\"" + toolName + "\\"", id: "environment_policy" };`);
  L(`  }`);
  L(`  return { block: false, flag: false };`);
  L(`}`);
  L(``);

  // ─── Sequence detection (SQLite-backed session history) ────────
  L(`// --- Sequence detection: multi-step attack chains via SQLite history ---`);
  L(`// Each handler invocation is a fresh process (frameworks spawn one per`);
  L(`// tool call), so in-memory sliding windows don't persist across calls.`);
  L(`// History is reconstructed from the events table on every check instead.`);
  L(`var SEQUENCE_ENABLED = ${JSON.stringify(sequenceDetection.enabled)};`);
  L(`var SEQUENCE_MODE = ${JSON.stringify(sequenceDetection.enforcementMode)};`);
  L(`var SEQUENCE_WINDOW_MINUTES = ${JSON.stringify(sequenceDetection.windowMinutes)};`);
  L(`var SEQUENCE_WINDOW_MS = SEQUENCE_WINDOW_MINUTES * 60 * 1000;`);
  L(`var SEQUENCE_MIN_CONFIDENCE = ${JSON.stringify(sequenceDetection.minConfidence)};`);
  L(`var _sfSeqWriteTools = new Set(["Write","write","Edit","edit","MultiEdit","multiedit","Create","create","FileEdit","file_edit","create_file","write_file","edit_file"]);`);
  L(`var _sfSeqReadTools = new Set(["Read","read","ReadFile","read_file","View","view","Cat","cat","ListDir","list_dir"]);`);
  L(``);
  L(`function _sfDetectScriptInjection(w) {`);
  L(`  var current = w[w.length - 1];`);
  L(`  if (!SHELL_TOOLS.has(current.tool_name)) return null;`);
  L(`  var cmd = (current.input_summary || "").toLowerCase();`);
  L(`  for (var i = w.length - 2; i >= 0; i--) {`);
  L(`    var prev = w[i];`);
  L(`    if (!SHELL_TOOLS.has(prev.tool_name)) continue;`);
  L(`    var chmodMatch = (prev.input_summary || "").match(/chmod\\s+(?:\\+x|[0-7]*[1357][0-7]*)\\s+(\\S+)/);`);
  L(`    if (!chmodMatch) continue;`);
  L(`    var targetFile = chmodMatch[1];`);
  L(`    if (cmd.indexOf(targetFile.toLowerCase()) === -1 && cmd.indexOf("./" + targetFile.toLowerCase().replace(/^\\.\\//, "")) === -1) continue;`);
  L(`    for (var j = i - 1; j >= 0; j--) {`);
  L(`      var wr = w[j];`);
  L(`      var isWrite = _sfSeqWriteTools.has(wr.tool_name) || (SHELL_TOOLS.has(wr.tool_name) && /(?:>>?|tee)\\s/.test(wr.input_summary || ""));`);
  L(`      if (!isWrite) continue;`);
  L(`      if ((wr.input_summary || "").toLowerCase().indexOf(targetFile.toLowerCase()) !== -1) {`);
  L(`        return { type: "script_injection", confidence: 0.92, description: "file \\"" + targetFile + "\\" was written, made executable, and executed within " + SEQUENCE_WINDOW_MINUTES + " min" };`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(`  return null;`);
  L(`}`);
  L(``);
  L(`function _sfDetectDataExfiltration(w) {`);
  L(`  var current = w[w.length - 1];`);
  L(`  if (!SHELL_TOOLS.has(current.tool_name)) return null;`);
  L(`  var cmd = current.input_summary || "";`);
  L(`  if (!/\\b(curl|wget|fetch|http|requests\\.|nc\\b|netcat|scp\\b|ssh\\b)/i.test(cmd)) return null;`);
  L(`  for (var i = w.length - 2; i >= 0; i--) {`);
  L(`    var prev = w[i];`);
  L(`    var isRead = _sfSeqReadTools.has(prev.tool_name) || (SHELL_TOOLS.has(prev.tool_name) && /\\b(cat|head|tail|less|more|grep)\\b/.test(prev.input_summary || ""));`);
  L(`    if (!isRead) continue;`);
  L(`    var readPath = prev.input_summary || "";`);
  L(`    var isSensitive = false;`);
  L(`    for (var k = 0; k < _sfSensitivePaths.length; k++) { if (_sfSensitivePaths[k].re.test(readPath)) { isSensitive = true; break; } }`);
  L(`    if (!isSensitive && /\\.(env|pem|key|secret|credential|token|password)/i.test(readPath)) isSensitive = true;`);
  L(`    if (!isSensitive && /\\/\\.(ssh|aws|gnupg)\\//i.test(readPath)) isSensitive = true;`);
  L(`    if (isSensitive) {`);
  L(`      return { type: "data_exfiltration", confidence: 0.85, description: "read of a sensitive path followed by outbound network call within " + SEQUENCE_WINDOW_MINUTES + " min" };`);
  L(`    }`);
  L(`  }`);
  L(`  return null;`);
  L(`}`);
  L(``);
  L(`function _sfDetectPersistenceProbe(w) {`);
  L(`  var current = w[w.length - 1];`);
  L(`  if (current.outcome !== "blocked") return null;`);
  L(`  var blocked = w.filter(function(e) { return e.outcome === "blocked"; });`);
  L(`  if (blocked.length < 3) return null;`);
  L(`  var counts = {}, maxTool = "", maxCount = 0;`);
  L(`  for (var i = 0; i < blocked.length; i++) {`);
  L(`    var t = blocked[i].tool_name;`);
  L(`    counts[t] = (counts[t] || 0) + 1;`);
  L(`    if (counts[t] > maxCount) { maxCount = counts[t]; maxTool = t; }`);
  L(`  }`);
  L(`  if (maxCount < 3) return null;`);
  L(`  var confidence = Math.min(0.95, 0.7 + (maxCount - 3) * 0.05);`);
  L(`  return { type: "persistence_probe", confidence: confidence, description: maxCount + " blocked attempts on tool \\"" + maxTool + "\\" within " + SEQUENCE_WINDOW_MINUTES + " min" };`);
  L(`}`);
  L(``);
  L(`function _sfDetectPrivilegeChain(w) {`);
  L(`  var current = w[w.length - 1];`);
  L(`  if (!SHELL_TOOLS.has(current.tool_name)) return null;`);
  L(`  var cmd = (current.input_summary || "").toLowerCase();`);
  L(`  var isReload = /\\b(source|reload|restart|systemctl|service\\s+\\S+\\s+(start|restart)|npm\\s+install|pip\\s+install)\\b/.test(cmd) || /\\.\\s+(\\.bashrc|\\.profile|\\.zshrc|\\.bash_profile)/.test(cmd);`);
  L(`  if (!isReload) return null;`);
  L(`  var privFiles = [/\\.ssh\\/authorized_keys/i, /sudoers/i, /\\.bashrc|\\.profile|\\.zshrc|\\.bash_profile/i, /\\.npmrc/i, /\\.netrc/i, /docker.*\\.json/i, /\\.kube\\/config/i, /\\.aws\\/credentials/i];`);
  L(`  for (var i = w.length - 2; i >= 0; i--) {`);
  L(`    var wr = w[i];`);
  L(`    var isWrite = _sfSeqWriteTools.has(wr.tool_name) || (SHELL_TOOLS.has(wr.tool_name) && /(?:>>?|tee)\\s/.test(wr.input_summary || ""));`);
  L(`    if (!isWrite) continue;`);
  L(`    for (var p = 0; p < privFiles.length; p++) {`);
  L(`      if (privFiles[p].test(wr.input_summary || "")) {`);
  L(`        return { type: "privilege_chain", confidence: 0.88, description: "write to a privilege-granting file followed by reload/restart within " + SEQUENCE_WINDOW_MINUTES + " min" };`);
  L(`      }`);
  L(`    }`);
  L(`  }`);
  L(`  return null;`);
  L(`}`);
  L(``);
  L(`function evaluateSequence(sessionId, currentToolName, currentSummary, currentOutcome) {`);
  L(`  if (!SEQUENCE_ENABLED || !db || !sessionId) return { block: false, flag: false };`);
  L(`  try {`);
  L(`    var cutoff = new Date(Date.now() - SEQUENCE_WINDOW_MS).toISOString();`);
  L(`    var rows = db.prepare("SELECT tool_name, tool_input_summary, outcome, ts FROM events WHERE session_id = ? AND ts >= ? ORDER BY ts ASC LIMIT 50").all(sessionId, cutoff);`);
  L(`    var w = rows.map(function(r) { return { tool_name: r.tool_name || "", input_summary: r.tool_input_summary || "", outcome: r.outcome || "allowed" }; });`);
  L(`    w.push({ tool_name: currentToolName || "", input_summary: currentSummary || "", outcome: currentOutcome || "allowed" });`);
  L(`    var m = _sfDetectScriptInjection(w) || _sfDetectDataExfiltration(w) || _sfDetectPersistenceProbe(w) || _sfDetectPrivilegeChain(w);`);
  L(`    if (!m || m.confidence < SEQUENCE_MIN_CONFIDENCE) return { block: false, flag: false };`);
  L(`    var enforce = SEQUENCE_MODE === "enforce";`);
  L(`    return { block: enforce, flag: true, reason: "Sequence [" + m.type + "]: " + m.description, id: "sequence_" + m.type };`);
  L(`  } catch (e) { return { block: false, flag: false }; }`);
  L(`}`);
  L(``);

  L(`// --- Enterprise Policy Evaluation ---`);
  L(`function evaluatePolicy(toolName, toolInput, agentId) {`);
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
  L(``);
  L(`      // Network egress governance (domain allow/block lists)`);
  L(`      for (var ne = 0; ne < _sfNetworkEgress.length; ne++) {`);
  L(`        var m = cmdForSecrets.match(_sfNetworkEgress[ne].re);`);
  L(`        if (m) {`);
  L(`          var urlOrHost = m[_sfNetworkEgress[ne].urlGroupIndex] || m[0] || "";`);
  L(`          var domain = _sfExtractDomain(urlOrHost);`);
  L(`          if (domain && !_sfIsDomainAllowed(domain)) {`);
  L(`            return { block: enforce, flag: true, reason: "Network egress [" + _sfNetworkEgress[ne].id + "]: " + _sfNetworkEgress[ne].label + " — domain: " + domain, id: "network_egress" };`);
  L(`          }`);
  L(`        }`);
  L(`      }`);
  L(``);
  L(`      // Sensitive file write governance for shell redirections and tee`);
  L(`      var writeTargets = _sfExtractWriteTargets(cmdForSecrets);`);
  L(`      if (writeTargets && writeTargets.length) {`);
  L(`        for (var t = 0; t < writeTargets.length; t++) {`);
  L(`          var target = writeTargets[t];`);
  L(`          if (!target) continue;`);
  L(`          for (var wp = 0; wp < _sfSensitivePaths.length; wp++) {`);
  L(`            if (_sfSensitivePaths[wp].re.test(target)) {`);
  L(`              return { block: enforce, flag: true, reason: "Write to sensitive path [" + _sfSensitivePaths[wp].id + "]: " + _sfSensitivePaths[wp].label, id: "file_write" };`);
  L(`            }`);
  L(`          }`);
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
  L(`  // Data boundary classification (governs reads, not just writes)`);
  L(`  var boundaryResult = evaluateDataBoundary(agentId, toolName, toolInput);`);
  L(`  if (boundaryResult.block || boundaryResult.flag) return boundaryResult;`);
  L(``);
  L(`  // Identity / role-based access control / environment policy`);
  L(`  var identityResult = evaluateIdentity(agentId, toolName);`);
  L(`  if (identityResult.block || identityResult.flag) return identityResult;`);
  L(``);
  L(`  return { block: false, flag: false };`);
  L(`}`);

  return lines.join("\n");
}
