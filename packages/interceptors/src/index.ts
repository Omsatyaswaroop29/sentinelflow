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
  type ClaudeCodeHookEvent,
  type ClaudeCodeHookDecision,
} from "./claude-code";

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
  type AlertChannel,
  type AlertPayload,
} from "./listeners";
