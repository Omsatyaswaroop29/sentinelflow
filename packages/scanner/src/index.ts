export { scan, type ScanOptions, type ScanResult } from "./engine";
export {
  formatTerminal,
  formatJSON,
  formatMarkdown,
  formatSARIF,
} from "./reporter";
export { BUILT_IN_RULES, getRuleById, getRulesByCategory } from "./rules/index";
export type { ScanRule, RuleContext } from "./rules/index";
export {
  applySuppressions,
  parseInlineSuppressions,
  loadPolicyFile,
  PRESETS,
  type SuppressionRecord,
  type SuppressionResult,
  type PolicyFile,
  type ScanPreset,
} from "./suppression";
