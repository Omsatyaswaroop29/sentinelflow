/**
 * sentinelflow intercept test — Test the handler with synthetic events.
 *
 * Pipes a JSON payload through the ACTUAL generated handler script —
 * the same code path that Claude Code or Cursor uses in production.
 *
 * Auto-detects which handler is installed (handler.js for Claude Code,
 * cursor-handler.js for Cursor) and generates the correct event format.
 */

import * as path from "path";
import * as fs from "fs";
import { execFile } from "child_process";

type DetectedFramework = "claude-code" | "cursor" | "copilot" | null;

function detectHandler(projectDir: string): { framework: DetectedFramework; handlerPath: string | null } {
  const ccHandler = path.join(projectDir, ".sentinelflow", "handler.js");
  const cursorHandler = path.join(projectDir, ".sentinelflow", "cursor-handler.js");
  const copilotHandler = path.join(projectDir, ".sentinelflow", "copilot-handler.js");

  if (fs.existsSync(ccHandler)) return { framework: "claude-code", handlerPath: ccHandler };
  if (fs.existsSync(cursorHandler)) return { framework: "cursor", handlerPath: cursorHandler };
  if (fs.existsSync(copilotHandler)) return { framework: "copilot", handlerPath: copilotHandler };
  return { framework: null, handlerPath: null };
}

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
  const { framework, handlerPath } = detectHandler(projectDir);

  if (!handlerPath) {
    console.log("\n  No handler found. Install hooks first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  // Build the hook event JSON
  let eventJson: string;

  if (options.fixture) {
    const fixturePath = path.resolve(options.fixture);
    if (!fs.existsSync(fixturePath)) {
      console.error(`\n  Error: Fixture file not found: ${fixturePath}\n`);
      process.exit(1);
    }
    eventJson = fs.readFileSync(fixturePath, "utf-8");
  } else if (options.tool) {
    let toolInput: Record<string, unknown> | undefined;
    if (options.input) {
      try {
        toolInput = JSON.parse(options.input);
      } catch {
        // Treat as a plain command string
        toolInput = { command: options.input };
      }
    }

    // Generate framework-appropriate JSON
    if (framework === "cursor") {
      eventJson = JSON.stringify(buildCursorEvent(options.tool, toolInput, projectDir));
    } else if (framework === "copilot") {
      eventJson = JSON.stringify(buildCopilotEvent(options.tool, toolInput, projectDir));
    } else {
      eventJson = JSON.stringify(buildClaudeCodeEvent(options.tool, toolInput, options.phase, projectDir));
    }
  } else {
    console.log("\n  Usage:");
    console.log("    sentinelflow intercept test --tool Bash --input 'rm -rf /'");
    console.log("    sentinelflow intercept test --fixture fixtures/event.json\n");
    process.exit(1);
  }

  // Parse for display
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(eventJson);
  } catch {
    console.error("\n  Error: Could not parse event JSON\n");
    process.exit(1);
  }

  const hookName = (parsed.hook_event_name as string) ?? "unknown";
  const toolName = (parsed.tool_name as string) ?? (parsed.command ? "Shell" : "(none)");

  console.log("");
  console.log("  SentinelFlow Interceptor Test");
  console.log("  " + "-".repeat(50));
  console.log("");
  console.log(`  Framework: ${framework}`);
  console.log(`  Hook:      ${hookName}`);
  console.log(`  Tool:      ${toolName}`);
  if (parsed.command) console.log(`  Command:   ${(parsed.command as string).slice(0, 80)}`);
  if (parsed.tool_input) {
    const inputStr = typeof parsed.tool_input === "string" ? parsed.tool_input : JSON.stringify(parsed.tool_input);
    console.log(`  Input:     ${inputStr.slice(0, 80)}`);
  }
  console.log("");
  console.log(`  Running: .sentinelflow/${framework === "cursor" ? "cursor-handler.js" : "handler.js"}`);

  // Pipe through the actual handler
  const result = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve) => {
    const child = execFile(
      "node",
      [handlerPath],
      { timeout: 10000, cwd: projectDir },
      (error, stdout, stderr) => {
        const exitCode = error
          ? typeof (error as any).code === "number" ? (error as any).code : 1
          : 0;
        resolve({ stdout: stdout.toString(), stderr: stderr.toString(), exitCode });
      }
    );
    if (child.stdin) {
      child.stdin.write(eventJson);
      child.stdin.end();
    }
  });

  console.log("");

  // Display result based on framework
  if (framework === "cursor") {
    displayCursorResult(result);
  } else {
    // Claude Code and Copilot share the same exit-code-based blocking
    displayClaudeCodeResult(result);
  }

  // Show last logged event
  const jsonlPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  if (fs.existsSync(jsonlPath)) {
    const lines = fs.readFileSync(jsonlPath, "utf-8").trim().split("\n").filter(Boolean);
    if (lines.length > 0) {
      try {
        const last = JSON.parse(lines[lines.length - 1]!);
        console.log("");
        console.log("  Event logged:");
        console.log(`     Type:       ${last.event_type}`);
        console.log(`     Outcome:    ${last.outcome}`);
        console.log(`     Framework:  ${last.framework}`);
        if (last.reason) console.log(`     Reason:     ${last.reason}`);
      } catch { /* skip */ }
    }
  }

  console.log("");
}

// ─── Framework-specific event builders ──────────────────────────────

function buildClaudeCodeEvent(
  tool: string,
  toolInput: Record<string, unknown> | undefined,
  phase: string | undefined,
  projectDir: string
): Record<string, unknown> {
  return {
    hook_event_name: phase ?? "PreToolUse",
    tool_name: tool,
    tool_input: toolInput ?? {},
    session_id: "test-session",
    cwd: projectDir,
  };
}

function buildCursorEvent(
  tool: string,
  toolInput: Record<string, unknown> | undefined,
  projectDir: string
): Record<string, unknown> {
  // Map tool names to Cursor hook event names
  const normalizedTool = tool.toLowerCase();

  if (normalizedTool === "bash" || normalizedTool === "shell") {
    return {
      hook_event_name: "beforeShellExecution",
      conversation_id: "test-conversation",
      generation_id: "test-generation",
      command: toolInput?.command ?? "",
      cwd: projectDir,
      workspace_roots: [projectDir],
    };
  }

  if (normalizedTool === "read" || normalizedTool === "readfile") {
    return {
      hook_event_name: "beforeReadFile",
      conversation_id: "test-conversation",
      generation_id: "test-generation",
      file_path: (toolInput?.file_path as string) ?? (toolInput?.path as string) ?? "unknown",
      content: "",
      workspace_roots: [projectDir],
    };
  }

  // Default: treat as MCP tool
  return {
    hook_event_name: "beforeMCPExecution",
    conversation_id: "test-conversation",
    generation_id: "test-generation",
    tool_name: tool,
    tool_input: JSON.stringify(toolInput ?? {}),
    command: "unknown-server",
    workspace_roots: [projectDir],
  };
}

/**
 * Build a GitHub Copilot format event.
 * Key difference: toolArgs is a JSON STRING (not an object).
 * Uses camelCase fields: toolName, toolArgs, hookEventName, sessionId.
 */
function buildCopilotEvent(
  tool: string,
  toolInput: Record<string, unknown> | undefined,
  projectDir: string
): Record<string, unknown> {
  return {
    timestamp: Date.now(),
    cwd: projectDir,
    sessionId: "test-session",
    hookEventName: "PreToolUse",
    toolName: tool.toLowerCase() === "shell" ? "bash" : tool,
    toolArgs: JSON.stringify(toolInput ?? {}),  // Copilot sends toolArgs as a JSON STRING
  };
}

// ─── Framework-specific result display ──────────────────────────────

function displayCursorResult(result: { stdout: string; stderr: string; exitCode: number }): void {
  let parsed: Record<string, unknown> | null = null;
  try {
    if (result.stdout.trim()) parsed = JSON.parse(result.stdout.trim());
  } catch { /* not JSON */ }

  if (parsed?.permission === "deny") {
    console.log("  BLOCKED");
    console.log("     Cursor sees: { permission: \"deny\" }");
    if (parsed.userMessage) console.log(`     User msg:  ${parsed.userMessage}`);
    if (parsed.agentMessage) console.log(`     Agent msg: ${(parsed.agentMessage as string).slice(0, 80)}`);
  } else if (parsed?.permission === "ask") {
    console.log("  ESCALATED TO USER");
    console.log("     Cursor sees: { permission: \"ask\" }");
    if (parsed.userMessage) console.log(`     User msg:  ${parsed.userMessage}`);
  } else {
    console.log("  ALLOWED");
    console.log("     Cursor sees: { permission: \"allow\" }");
  }
}

function displayClaudeCodeResult(result: { stdout: string; stderr: string; exitCode: number }): void {
  if (result.exitCode === 2) {
    console.log("  BLOCKED");
    console.log(`     Exit code:  2 (Claude Code blocks this tool call)`);
    console.log(`     Reason:     ${result.stderr.trim()}`);
  } else if (result.exitCode === 0) {
    console.log("  ALLOWED");
    console.log(`     Exit code:  0 (Claude Code proceeds with the tool call)`);
    if (result.stderr.trim()) console.log(`     Note:       ${result.stderr.trim()}`);
  } else {
    console.log("  ERROR (fail-open)");
    console.log(`     Exit code:  ${result.exitCode}`);
    if (result.stderr.trim()) console.log(`     stderr:     ${result.stderr.trim()}`);
  }
}
