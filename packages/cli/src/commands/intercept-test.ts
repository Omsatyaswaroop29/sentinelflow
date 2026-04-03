/**
 * sentinelflow intercept test — Test the handler with synthetic events.
 *
 * This command pipes a JSON payload through the ACTUAL generated handler
 * script (.sentinelflow/handler.js) — the same code path that Claude Code
 * uses in production. This ensures that policy evaluation, event persistence,
 * and exit code behavior are identical to what happens in a real session.
 */

import * as path from "path";
import * as fs from "fs";
import { execFile } from "child_process";

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
  const handlerPath = path.join(projectDir, ".sentinelflow", "handler.js");

  if (!fs.existsSync(handlerPath)) {
    console.log("\n  No handler found. Install hooks first:");
    console.log("    sentinelflow intercept install\n");
    process.exit(1);
  }

  // Build the hook event JSON from either a fixture file or CLI flags
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
        toolInput = { command: options.input };
      }
    }
    const event = {
      hook_event_name: options.phase ?? "PreToolUse",
      tool_name: options.tool,
      tool_input: toolInput ?? {},
      session_id: "test-session",
      cwd: projectDir,
    };
    eventJson = JSON.stringify(event);
  } else {
    console.log("\n  Usage:");
    console.log("    sentinelflow intercept test --tool Bash --input 'rm -rf /'");
    console.log("    sentinelflow intercept test --fixture fixtures/pre-tool-read.json");
    console.log("");
    console.log("  Options:");
    console.log("    --tool <name>       Tool name (Bash, Read, Write, Edit, etc.)");
    console.log("    --input <json>      Tool input as JSON or plain command string");
    console.log("    --phase <phase>     Hook event: PreToolUse, PostToolUse (default: PreToolUse)");
    console.log("    --fixture <path>    JSON fixture file\n");
    process.exit(1);
  }

  // Parse the event for display
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(eventJson);
  } catch {
    console.error("\n  Error: Could not parse event JSON\n");
    process.exit(1);
  }

  console.log("");
  console.log("  SentinelFlow Interceptor Test");
  console.log("  " + "-".repeat(50));
  console.log("");
  console.log("  Input:");
  console.log(`     Hook:     ${parsed.hook_event_name ?? "unknown"}`);
  console.log(`     Tool:     ${(parsed.tool_name as string) ?? "(none)"}`);
  console.log(`     Session:  ${(parsed.session_id as string) ?? "(none)"}`);
  if (parsed.tool_input) {
    const inputStr = JSON.stringify(parsed.tool_input);
    console.log(`     Input:    ${inputStr.slice(0, 80)}${inputStr.length > 80 ? "..." : ""}`);
  }
  console.log("");
  console.log("  Running handler: .sentinelflow/handler.js");

  // Pipe the JSON through the actual handler script
  const result = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve) => {
    const child = execFile(
      "node",
      [handlerPath],
      { timeout: 10000, cwd: projectDir },
      (error, stdout, stderr) => {
        const exitCode = error ? (error as NodeJS.ErrnoException).code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
          ? 1
          : typeof (error as any).code === "number" ? (error as any).code : 1
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

  // Display result
  const isBlock = result.exitCode === 2;
  if (isBlock) {
    console.log("  BLOCKED");
    console.log(`     Exit code:  2 (Claude Code will prevent this tool call)`);
    console.log(`     Reason:     ${result.stderr.trim()}`);
  } else if (result.exitCode === 0) {
    console.log("  ALLOWED");
    console.log(`     Exit code:  0 (Claude Code will proceed with the tool call)`);
    if (result.stderr.trim()) {
      console.log(`     Note:       ${result.stderr.trim()}`);
    }
  } else {
    console.log("  ERROR (fail-open)");
    console.log(`     Exit code:  ${result.exitCode}`);
    console.log(`     stderr:     ${result.stderr.trim()}`);
  }

  // Show the event that was written
  console.log("");
  const jsonlPath = path.join(projectDir, ".sentinelflow", "events.jsonl");
  if (fs.existsSync(jsonlPath)) {
    const lines = fs.readFileSync(jsonlPath, "utf-8").trim().split("\n").filter(Boolean);
    if (lines.length > 0) {
      const lastLine = lines[lines.length - 1]!;
      try {
        const lastEvent = JSON.parse(lastLine);
        console.log("  Event logged:");
        console.log(`     Type:       ${lastEvent.event_type}`);
        console.log(`     Outcome:    ${lastEvent.outcome}`);
        console.log(`     Agent:      ${lastEvent.agent_id}`);
        if (lastEvent.reason) {
          console.log(`     Reason:     ${lastEvent.reason}`);
        }
      } catch { /* skip */ }
    }
  }

  console.log("");
}
