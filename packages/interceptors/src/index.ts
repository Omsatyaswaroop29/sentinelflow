/**
 * @module @sentinelflow/interceptors
 *
 * Runtime interceptors for AI agent governance.
 *
 * This package provides the "runtime agent firewall" — hooks that sit between
 * AI agents and their tools, evaluating every tool call against governance
 * policies before allowing execution.
 *
 * Quick start (Claude Code):
 *
 *   import { ClaudeCodeInterceptor, DangerousCommandPolicy, ConsoleListener } from "@sentinelflow/interceptors";
 *
 *   const interceptor = await ClaudeCodeInterceptor.install({
 *     projectDir: "./my-project",
 *     enforcement_mode: "monitor",  // Start with monitor, graduate to enforce
 *     policies: [new DangerousCommandPolicy()],
 *     listeners: [new ConsoleListener({ verbose: true })],
 *   });
 *
 *   // Later, when done:
 *   await interceptor.stop();
 */

// ─── Core Interfaces ────────────────────────────────────────────────
export type {
  Interceptor,
  InterceptorConfig,
  InterceptorStats,
  EventListener,
  PolicyProvider,
  PolicyDecision,
  PolicyEvaluationResult,
} from "./interface";

// ─── Base Class ─────────────────────────────────────────────────────
export { BaseInterceptor } from "./base";

// ─── Framework Interceptors ─────────────────────────────────────────
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

// ─── Built-in Policies ──────────────────────────────────────────────
export {
  ToolAllowlistPolicy,
  ToolBlocklistPolicy,
  DangerousCommandPolicy,
  CostBudgetPolicy,
  DataBoundaryPolicy,
} from "./policies";

// ─── Built-in Listeners ─────────────────────────────────────────────
export {
  ConsoleListener,
  JsonlFileListener,
  CallbackListener,
  AlertListener,
  EventStoreListener,
  type AlertChannel,
  type AlertPayload,
} from "./listeners";

// ─── Anomaly Detection ───────────────────────────────────────────
export {
  type AnomalyDetector,
  NovelToolDetector,
  CostSpikeDetector,
  ErrorRateDetector,
  PrivilegeEscalationDetector,
  AnomalyEngine,
} from "./anomaly";
