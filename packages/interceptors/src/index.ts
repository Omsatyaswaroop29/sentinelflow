/**
 * @module @sentinelflow/interceptors
 *
 * Runtime interceptors for AI agent governance.
 *
 * This package provides the "runtime agent firewall" — hooks that sit between
 * AI agents and their tools, evaluating every tool call against governance
 * policies before allowing execution.
 *
 * Supported frameworks:
 *   - Claude Code (.claude/settings.local.json)
 *   - Cursor (.cursor/hooks.json)
 *   - GitHub Copilot (.github/hooks/*.json)
 *   - Codex CLI (.codex/hooks.json)
 */

// --- Core Interfaces ---
export type {
  Interceptor,
  InterceptorConfig,
  InterceptorStats,
  EventListener,
  PolicyProvider,
  PolicyDecision,
  PolicyEvaluationResult,
} from "./interface";

// --- Base Class ---
export { BaseInterceptor } from "./base";

// --- Framework Interceptors ---
export {
  ClaudeCodeInterceptor,
  type ClaudeCodeInterceptorConfig,
  type ClaudeCodeHookInput,
  type ClaudeCodeHookDecision,
} from "./claude-code";

export {
  CursorInterceptor,
  type CursorInterceptorConfig,
  type CursorHookInput,
  type CursorHookResponse,
  type CursorBeforeShellPayload,
  type CursorBeforeMCPPayload,
  type CursorBeforeReadFilePayload,
  type CursorAfterFileEditPayload,
  type CursorStopPayload,
} from "./cursor";

export {
  CopilotInterceptor,
  type CopilotInterceptorConfig,
  type CopilotHookInput,
  type CopilotPreToolUsePayload,
  type CopilotPostToolUsePayload,
  type CopilotSessionStartPayload,
  type CopilotSessionEndPayload,
} from "./copilot";

export {
  CodexInterceptor,
  type CodexInterceptorConfig,
} from "./codex";

// --- Built-in Policies (8 enterprise-grade policies) ---
export {
  ToolAllowlistPolicy,
  ToolBlocklistPolicy,
  DangerousCommandPolicy,
  CostBudgetPolicy,
  DataBoundaryPolicy,
  NetworkEgressPolicy,
  SecretsLeakPolicy,
  FileWritePolicy,
} from "./policies";

// --- Central Pattern Registry ---
export {
  DANGEROUS_COMMAND_PATTERNS,
  SECRET_PATTERNS,
  SENSITIVE_WRITE_PATHS,
  NETWORK_EGRESS_PATTERNS,
  SHELL_TOOL_NAMES,
  compilePatterns,
  patternsToHandlerJSON,
  secretPatternsToHandlerJSON,
  sensitivePathsToHandlerJSON,
  networkPatternsToHandlerJSON,
  type DangerousPattern,
  type SecretPattern,
  type SensitivePathPattern,
  type NetworkEgressPattern,
} from "./patterns";

// --- Command Normalizer ---
export {
  normalizeCommand,
  normalizeAndSplit,
  splitCompoundCommand,
  extractDomain,
  normalizerToHandlerJS,
} from "./normalizer";

// --- Built-in Listeners ---
export {
  ConsoleListener,
  JsonlFileListener,
  CallbackListener,
  AlertListener,
  EventStoreListener,
  type AlertChannel,
  type AlertPayload,
} from "./listeners";

// --- Anomaly Detection ---
export {
  type AnomalyDetector,
  NovelToolDetector,
  CostSpikeDetector,
  ErrorRateDetector,
  PrivilegeEscalationDetector,
  AnomalyEngine,
} from "./anomaly";

// --- Multi-Step Sequence Detection ---
export {
  SequenceDetector,
  type SequenceDetectorConfig,
  type SequenceType,
  type SequenceMatch,
} from "./sequence";

// --- Enhanced Data Boundary ---
export {
  PathClassifier,
  EnhancedDataBoundaryPolicy,
  extractPaths,
  DEFAULT_CLASSIFICATION_RULES,
  type DataClassification,
  type ClassificationRule,
  type AgentClearance,
} from "./data-boundary";

// --- Identity and Delegation Governance ---
export {
  IdentityResolver,
  RoleBasedAccessPolicy,
  EnvironmentPolicy,
  type IdentityConfig,
} from "./identity";

// --- Compliance Mappings ---
export {
  RUNTIME_COMPLIANCE_MAPPINGS,
  getControlsForOwaspRisk,
  getControlsForEuArticle,
  getEvidenceSnippet,
  generateComplianceSummary,
  type ComplianceMapping,
  type OwaspLlmMapping,
  type EuAiActMapping,
  type NistMapping,
} from "./compliance";
