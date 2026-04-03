# Phase 2 — Step 1 Code Audit & Safety Report

**Date:** 2026-04-03  
**Auditor:** SentinelFlow Runtime Engineer  
**Status:** CRITICAL ISSUES FOUND — handler does not match Claude Code hooks contract

---

## 1. Critical Finding: Hooks Format Mismatch

Our current implementation has **three fundamental mismatches** with the real Claude Code hooks system, confirmed against the official docs at `code.claude.com/docs/en/hooks`.

### 1a. Wrong hooks config location

**What we do:** Generate `hooks/hooks.json` at the project root.  
**What Claude Code expects:** Hooks in `.claude/settings.json` (project, committed) or `.claude/settings.local.json` (local, gitignored).

### 1b. Wrong hooks config format

**What we generate:**
```json
{
  "hooks": {
    "PreToolUse": [{ "type": "command", "command": "node handler.js pre" }]
  }
}
```

**What Claude Code actually expects:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node \"$CLAUDE_PROJECT_DIR/.sentinelflow/handler.js\"",
            "timeout": 10000
          }
        ]
      }
    ]
  }
}
```

Key differences: nested `matcher` + `hooks` array structure, `$CLAUDE_PROJECT_DIR` env var for path resolution, `timeout` field.

### 1c. Wrong stdin JSON parsing

**What our handler expects:** The hook phase from `process.argv[2]` (e.g., `node handler.js pre`).

**What Claude Code actually sends:** The hook event name in the **stdin JSON** itself, in the `hook_event_name` field:
```json
{
  "session_id": "abc123",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "npm test" }
}
```

Our handler would fail silently on real Claude Code events because it reads `process.argv[2]` for the phase, not `hook_event_name` from stdin.

### 1d. Decision JSON format

Claude Code supports structured JSON decisions on stdout (exit 0):
```json
{ "decision": "block", "reason": "Dangerous command detected" }
```

Or simply exit 2 with stderr message. Both work. Our handler correctly uses exit 2 for blocks, which is fine, but the JSON decision approach is more informative.

---

## 2. Package Inventory

### Phase 2 packages and files:

| File | Purpose | Status |
|------|---------|--------|
| `packages/interceptors/src/interface.ts` | Core contracts: Interceptor, PolicyProvider, EventListener | ✅ Clean |
| `packages/interceptors/src/base.ts` | BaseInterceptor abstract class | ✅ Clean |
| `packages/interceptors/src/claude-code.ts` | Claude Code interceptor + handler generator | ❌ **WRONG HOOKS FORMAT** |
| `packages/interceptors/src/policies.ts` | 5 built-in policies | ✅ Clean |
| `packages/interceptors/src/listeners.ts` | 5 listeners (incl. EventStoreListener bridge) | ⚠️ Bridge untested |
| `packages/interceptors/src/anomaly.ts` | 4 detectors + AnomalyEngine | ✅ Clean |
| `packages/interceptors/src/__tests__/interceptors.test.ts` | 23 tests | ✅ Passing |
| `packages/interceptors/src/__tests__/anomaly.test.ts` | 16 tests | ⚠️ Not verified |
| `packages/core/src/event-store/schema.ts` | GovernanceEvent envelope (15 types) | ✅ Clean |
| `packages/core/src/event-store/writer.ts` | SQLite writer (WAL, batch, rollups) | ✅ Clean |
| `packages/core/src/event-store/queries.ts` | Reader with governance query methods | ✅ Clean |
| `packages/core/src/__tests__/event-store.test.ts` | 15 tests | ⚠️ TS strict fixes applied, not verified |
| `packages/cli/src/commands/intercept.ts` | CLI install/uninstall/status/tail | ❌ **Uses wrong hooks location** |

### Junk directories to clean up:
- `packages/{core` — garbled directory name, must delete before push.

### Secrets:
- Two npm tokens were shared in conversation history. **Must be revoked at npmjs.com/settings/tokens.**
- No hardcoded secrets found in source code.

---

## 3. Build Status

| Package | Last confirmed | Notes |
|---------|---------------|-------|
| `@sentinelflow/core` | Needs rebuild | Event store added since last green |
| `@sentinelflow/parsers` | ✅ Green | No changes |
| `@sentinelflow/scanner` | ✅ Green | No changes |
| `@sentinelflow/interceptors` | Tests passing (23) | Anomaly tests (16) not verified |
| `sentinelflow` (CLI) | ✅ Green | But uses wrong hooks location |

---

## 4. What Must Be Fixed (Checklist)

### P0 — Blocks shipping
- [ ] **Fix handler to read `hook_event_name` from stdin JSON** instead of `process.argv[2]`
- [ ] **Fix hooks config to use `.claude/settings.local.json`** format with `matcher` + `hooks` array
- [ ] **Fix handler path to use `$CLAUDE_PROJECT_DIR`** for reliable path resolution
- [ ] **Fix CLI `intercept install` to write to `.claude/settings.local.json`** instead of `hooks/hooks.json`
- [ ] **Move handler script to `.sentinelflow/handler.js`** (not `hooks/sentinelflow-handler.js`)
- [ ] **Confirm build green:** `pnpm build && pnpm test` with all Phase 2 code
- [ ] **Delete junk directory:** `rm -rf "packages/{core"`
- [ ] **Push to GitHub** on branch `feature/runtime-phase-2`

### P1 — Required for real-world use
- [ ] **Add integration test:** Feed real Claude Code stdin JSON through handler
- [ ] **Test EventStoreListener bridge** with end-to-end event flow
- [ ] **Validate against live Claude Code session**
- [ ] **Revoke compromised npm tokens**

### P2 — Quality
- [ ] **Align package versions** across all 5 packages
- [ ] **Add `sentinelflow events tail` and `sentinelflow costs` CLI commands**
- [ ] **Add golden-path validation checklist** to docs

---

## 5. Recommended Branch & Commit Plan

```
Branch: feature/runtime-phase-2

Commit 1: fix: correct Claude Code hooks format and handler stdin parsing
Commit 2: feat: hardened handler with dual-write (JSONL + SQLite)
Commit 3: feat: event store with append-only SQLite, rollups, query API
Commit 4: feat: anomaly detection (4 detectors + engine)
Commit 5: feat: CLI intercept install/uninstall/status/tail + events/costs commands
Commit 6: test: integration tests for handler → event store pipeline
Commit 7: docs: Phase 2 Runtime Beta section in README
```
