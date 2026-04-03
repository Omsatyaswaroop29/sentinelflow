# Phase 2 — Golden Path Validation Guide

This guide walks you through validating the SentinelFlow runtime layer against a real Claude Code session. Complete every step in order. If any step fails, stop and investigate before continuing.

---

## Prerequisites

Before starting, confirm the build is green and all tests pass:

```bash
cd ~/Downloads/sentinelflow
pnpm build && pnpm test
```

Expected outcome: all 5 packages build successfully and all tests pass (approximately 54 interceptor tests, 42 core tests, 79+ scanner tests).

---

## Part 1: Validate the CLI commands locally

These commands don't require a real Claude Code session — they test the CLI itself.

### 1a. Install hooks into the SentinelFlow project itself

```bash
cd ~/Downloads/sentinelflow
node packages/cli/dist/bundle.js intercept install . --mode enforce --blocklist NotebookEdit
```

Verify the output shows:
- `.claude/settings.local.json` created with hooks config
- `.sentinelflow/handler.js` created as the event handler

Then check the files exist:

```bash
cat .claude/settings.local.json | head -20
ls -la .sentinelflow/handler.js
```

The settings file should contain a `hooks` object with `PreToolUse`, `PostToolUse`, and `Stop` entries, each pointing to the handler script.

### 1b. Test the interceptor with a fixture

```bash
node packages/cli/dist/bundle.js intercept test . --tool Read --input '{"file_path":"/src/index.ts"}'
```

Expected: Decision shows ALLOW (exit code 0).

```bash
node packages/cli/dist/bundle.js intercept test . --tool Bash --input 'rm -rf /home/user'
```

Expected: Decision shows BLOCK (exit code 2) with reason mentioning "rm -rf".

```bash
node packages/cli/dist/bundle.js intercept test . --tool NotebookEdit --input '{}'
```

Expected: Decision shows BLOCK with reason mentioning "blocklist".

### 1c. Check status

```bash
node packages/cli/dist/bundle.js intercept status .
```

Expected: Shows hooks as installed, event log present (if test wrote events).

### 1d. Uninstall hooks

```bash
node packages/cli/dist/bundle.js intercept uninstall .
```

Verify: `.sentinelflow/handler.js` removed. `.claude/settings.local.json` cleaned up (hooks removed from it, or file removed if empty).

---

## Part 2: Validate the handler script directly

This simulates what Claude Code does — piping JSON to the handler via stdin.

### 2a. Install hooks (to generate the handler script)

```bash
cd ~/Downloads/sentinelflow
node packages/cli/dist/bundle.js intercept install . --mode enforce
```

### 2b. Run the handler directly with stdin

Test a safe tool call:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/src/index.ts"},"session_id":"manual-test-001","cwd":"/tmp"}' | node .sentinelflow/handler.js
echo "Exit code: $?"
```

Expected: exit code 0, no stderr output.

Test a dangerous command:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /home/user"},"session_id":"manual-test-001","cwd":"/tmp"}' | node .sentinelflow/handler.js
echo "Exit code: $?"
```

Expected: exit code 2, stderr contains "SentinelFlow: Dangerous command".

Test invalid JSON (fail-open):

```bash
echo 'not valid json' | node .sentinelflow/handler.js
echo "Exit code: $?"
```

Expected: exit code 0 (fail open), stderr mentions "Failed to parse".

### 2c. Verify events were written

```bash
cat .sentinelflow/events.jsonl | python3 -m json.tool | head -40
```

Should show events with `event_type`, `outcome`, `tool_name`, `session_id` fields.

If better-sqlite3 is available, check the SQLite database too:

```bash
sqlite3 .sentinelflow/events.db "SELECT event_type, outcome, tool_name, reason FROM events ORDER BY ts DESC LIMIT 10;"
```

### 2d. Query events via CLI

```bash
node packages/cli/dist/bundle.js events tail .
node packages/cli/dist/bundle.js events blocked .
node packages/cli/dist/bundle.js events stats .
```

---

## Part 3: Live Claude Code integration

This is the real test. You need Claude Code installed and a project to test with.

### 3a. Pick a test project

Use a throwaway project — not your main codebase:

```bash
mkdir /tmp/sf-golden-test && cd /tmp/sf-golden-test
git init && echo "# Test" > README.md && git add -A && git commit -m "init"
```

### 3b. Install SentinelFlow hooks

```bash
cd /tmp/sf-golden-test
npx sentinelflow intercept install . --mode enforce
```

Or if testing locally:

```bash
node ~/Downloads/sentinelflow/packages/cli/dist/bundle.js intercept install . --mode enforce
```

### 3c. Start a Claude Code session

```bash
cd /tmp/sf-golden-test
claude
```

Then ask Claude to do a few things:
1. "Read the README.md file" (should be allowed)
2. "Run `ls -la`" (should be allowed)
3. "Run `npm test`" (should be allowed, even if the command fails)
4. "Run `rm -rf /etc/passwd`" (should be BLOCKED by SentinelFlow)

When Claude tries the dangerous command, you should see SentinelFlow's block message appear as feedback to Claude. Claude should acknowledge the block and try a different approach.

### 3d. Verify events after the session

```bash
cd /tmp/sf-golden-test

# Check JSONL log
cat .sentinelflow/events.jsonl | wc -l
cat .sentinelflow/events.jsonl | python3 -m json.tool | head -60

# Check SQLite (if available)
sqlite3 .sentinelflow/events.db "SELECT event_type, outcome, tool_name FROM events ORDER BY ts;"

# Use the CLI
node ~/Downloads/sentinelflow/packages/cli/dist/bundle.js events tail .
node ~/Downloads/sentinelflow/packages/cli/dist/bundle.js events blocked .
node ~/Downloads/sentinelflow/packages/cli/dist/bundle.js events stats .
```

### 3e. Expected outcomes

After a successful session, you should see:
- Multiple `tool_call_attempted` events with `outcome: "allowed"`
- At least one `tool_call_blocked` event with `outcome: "blocked"` and a reason mentioning the dangerous command
- A `session_ended` event at the end
- All events have `framework: "claude_code"` and a consistent `session_id`
- The `events tail` command shows a human-readable table of events
- The `events blocked` command shows the blocked event with the policy reason

### 3f. Clean up

```bash
node ~/Downloads/sentinelflow/packages/cli/dist/bundle.js intercept uninstall .
rm -rf /tmp/sf-golden-test
```

---

## Part 4: Validation checklist

Copy this checklist and check off each item as you verify it:

- [ ] `pnpm build` succeeds for all 5 packages
- [ ] `pnpm test` passes all tests (54+ interceptor, 42 core, 79+ scanner)
- [ ] `intercept install` creates `.claude/settings.local.json` with correct format
- [ ] `intercept install` creates `.sentinelflow/handler.js`
- [ ] Handler allows safe tool calls (exit 0)
- [ ] Handler blocks dangerous commands (exit 2, stderr has reason)
- [ ] Handler blocks blocklisted tools (exit 2)
- [ ] Handler fails open on invalid JSON (exit 0)
- [ ] Events are written to `.sentinelflow/events.jsonl`
- [ ] Events are written to `.sentinelflow/events.db` (if SQLite available)
- [ ] `events tail` shows recent events in a readable table
- [ ] `events blocked` shows blocked events with policy reasons
- [ ] `events stats` shows aggregate counts
- [ ] `intercept uninstall` cleanly removes hooks and handler
- [ ] No secrets or tokens in the repo (`git grep -i "npm_"`, `git grep -i "token"`)
- [ ] No junk directories (`packages/{core` removed)
- [ ] Live Claude Code session works with hooks installed (Part 3)
