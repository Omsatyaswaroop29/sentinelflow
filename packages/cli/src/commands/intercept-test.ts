/**
 * sentinelflow intercept test — Run a fixture through the handler pipeline.
 *
 * Usage:
 *   sentinelflow intercept test --fixture <path> [project-path]
 *   sentinelflow intercept test --tool Bash --input '{"command":"rm -rf /"}' [project-path]
 *
 * This command simulates a Claude Code hook event without requiring a
 * running Claude Code session. It feeds a JSON payload through the same
 * policy evaluation pipeline the handler uses, and shows:
 *   - The parsed event
 *   - The policy decision (allow/block)
 *   - What would be written to the event store
 *
 * Use this to validate your policy configuration before going live.
 */

import * as path from "path";
import * as fs from "fs";
import { ClaudeCodeInterceptor, type ClaudeCodeHookInput } from "@sentinelflow/interceptors";

export async function interceptTestCommand(
  targetPath: string,
  options: {
    fixture?: string;
    tool?: string;
    input?: string;
    phase?: string;
    mode?: string;
    blocklist?: string;
    allowlist?: string;
  }
): Promise<void> {
  const projectDir = path.resolve(targetPath);

  // Build the hook event from either a fixture file or CLI flags
  let hookEvent: ClaudeCodeHookInput;

  if (options.fixture) {
    const fixturePath = path.resolve(options.fixture);
    if (!fs.existsSync(fixturePath)) {
      console.error(`\n  ❌ Fixture file not found: ${fixturePath}\n`);
      process.exit(1);
    }
    try {
      const raw = fs.readFileSync(fixturePath, "utf-8");
      hookEvent = JSON.parse(raw) as ClaudeCodeHookInput;
    } catch (err) {
      console.error(`\n  ❌ Failed to parse fixture JSON: ${err}\n`);
      process.exit(1);
    }
  } else if (options.tool) {
    // Build a synthetic PreToolUse event from flags
    let toolInput: Record<string, unknown> | undefined;
    if (options.input) {
      try {
        toolInput = JSON.parse(options.input);
      } catch {
        // Treat as a simple command string for Bash tool
        toolInput = { command: options.input };
      }
    }
    hookEvent = {
      hook_event_name: options.phase ?? "PreToolUse",
      tool_name: options.tool,
      tool_input: toolInput,
      session_id: "test-session",
      cwd: projectDir,
    };
  } else {
    console.log("\n  Usage:");
    console.log("    sentinelflow intercept test --fixture <path>");
    console.log("    sentinelflow intercept test --tool Bash --input 'rm -rf /'");
    console.log("");
    console.log("  Options:");
    console.log("    --fixture <path>    JSON fixture file with a hook event");
    console.log("    --tool <name>       Tool name (e.g., Bash, Read, Write)");
    console.log("    --input <json>      Tool input as JSON or plain string");
    console.log("    --phase <phase>     Hook phase: PreToolUse, PostToolUse (default: PreToolUse)");
    console.log("    --mode <mode>       Enforcement mode: monitor, enforce (default: monitor)");
    console.log("    --blocklist <tools>  Comma-separated tools to block");
    console.log("    --allowlist <tools>  Comma-separated tools to allow\n");
    process.exit(1);
  }

  // Create a temporary interceptor with the test config
  const mode = (options.mode ?? "enforce") as "monitor" | "enforce";
  const toolBlocklist = options.blocklist
    ? options.blocklist.split(",").map((t) => t.trim())
    : undefined;
  const toolAllowlist = options.allowlist
    ? options.allowlist.split(",").map((t) => t.trim())
    : undefined;

  const interceptor = new ClaudeCodeInterceptor({
    projectDir,
    enforcement_mode: mode,
    toolBlocklist,
    toolAllowlist,
    log_level: "silent",
  });

  // We start the interceptor in a way that doesn't install hooks
  // (we just need the processHookEvent method)
  // Actually, we need to call start() to initialize, but we'll clean up after
  // To avoid installing hooks, we'll just process the event directly
  // The processHookEvent method works even without start() because
  // it doesn't depend on the hook being installed

  console.log("");
  console.log("  SentinelFlow Interceptor Test");
  console.log("  " + "─".repeat(50));
  console.log("");

  // Show the input
  console.log("  📥 Input Event:");
  console.log(`     Hook type:  ${hookEvent.hook_event_name}`);
  console.log(`     Tool:       ${hookEvent.tool_name ?? "(none)"}`);
  console.log(`     Session:    ${hookEvent.session_id ?? "(none)"}`);
  if (hookEvent.tool_input) {
    const inputStr = JSON.stringify(hookEvent.tool_input);
    console.log(`     Input:      ${inputStr.slice(0, 100)}${inputStr.length > 100 ? "..." : ""}`);
  }
  console.log("");

  // Process through the policy engine
  console.log("  ⚡ Policy Evaluation:");
  console.log(`     Mode:       ${mode}`);
  if (toolBlocklist) console.log(`     Blocklist:  ${toolBlocklist.join(", ")}`);
  if (toolAllowlist) console.log(`     Allowlist:  ${toolAllowlist.join(", ")}`);

  try {
    const decision = await interceptor.processHookEvent(hookEvent);

    console.log("");
    if (decision) {
      const decisionStr = decision.decision ?? "allow";
      const isBlock = decisionStr === "block";
      console.log(`  ${isBlock ? "🚫" : "✅"} Decision: ${decisionStr.toUpperCase()}`);
      if (decision.reason) {
        console.log(`     Reason:     ${decision.reason}`);
      }
      console.log("");
      console.log("  📤 Claude Code Response:");
      console.log(`     Exit code:  ${isBlock ? 2 : 0}`);
      if (isBlock) {
        console.log(`     stderr:     ${decision.reason}`);
      } else {
        console.log(`     stdout:     (empty — allow)`);
      }
    } else {
      console.log("  ℹ️  No decision returned (PostToolUse/Stop events are observe-only)");
    }
  } catch (err) {
    console.log(`  ❌ Error processing event: ${err}`);
    console.log("     In production, this would fail open (exit 0).");
  }

  console.log("");

  // Check event log for what was written
  const eventLogPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  if (fs.existsSync(eventLogPath)) {
    const lines = fs.readFileSync(eventLogPath, "utf-8").trim().split("\n").filter(Boolean);
    if (lines.length > 0) {
      const lastLine = lines[lines.length - 1]!;
      try {
        const lastEvent = JSON.parse(lastLine);
        console.log("  📝 Last event written to log:");
        console.log(`     Type:       ${lastEvent.type ?? lastEvent.event_type}`);
        console.log(`     Agent:      ${lastEvent.agent_id}`);
        console.log(`     Timestamp:  ${lastEvent.timestamp}`);
      } catch { /* skip */ }
    }
  }

  console.log("");

  // Clean up — stop will try to remove hooks, but since we never started
  // properly, catch any errors silently
  try { await interceptor.stop(); } catch { /* expected */ }
}
