# Phase 2 — Runtime Agent Governance

**Goal:** Move SentinelFlow from a point-in-time scanner to a continuous governance platform that intercepts, logs, and enforces policies on AI agent tool calls in real-time.

---

## Phase 2.1 — Runtime Interceptors ✅

**Status:** Complete  
**Package:** `@sentinelflow/interceptors`

### What was built

A new package that hooks into AI agent frameworks at runtime and emits normalized `AgentEvent` objects. The Claude Code interceptor is the first implementation.

**Core interfaces:**
- `Interceptor` — Base contract for all framework interceptors
- `PolicyProvider` — Evaluates tool calls and returns allow/block decisions
- `EventListener` — Reacts to events (logging, alerting, storage)

**Claude Code interceptor:**
- Generates `hooks/hooks.json` and a self-contained handler script
- Handler reads `PreToolUse` events from stdin, evaluates policies, returns decisions to stdout
- Supports `monitor` mode (log only) and `enforce` mode (actually block)
- Writes all events to `.sentinelflow/events.jsonl`

**5 built-in policies:**
1. `ToolAllowlistPolicy` — Only allow explicitly listed tools
2. `ToolBlocklistPolicy` — Block specific tools
3. `DangerousCommandPolicy` — 12 dangerous bash patterns (rm -rf, curl|bash, chmod 777, git push --force, etc.)
4. `CostBudgetPolicy` — Block when session cost exceeds budget
5. `DataBoundaryPolicy` — Block access to sensitive paths/patterns

**4 built-in listeners:**
1. `ConsoleListener` — Color-coded terminal output
2. `JsonlFileListener` — Append-only event log with rotation
3. `CallbackListener` — Custom function for integrations
4. `AlertListener` — Triggers on blocks/anomalies/error spikes

**CLI commands:**
- `sentinelflow intercept install [path]` — Install hooks
- `sentinelflow intercept uninstall [path]` — Remove hooks
- `sentinelflow intercept status [path]` — Check status and stats
- `sentinelflow intercept tail [path]` — View recent events

---

## Phase 2.2 — Event Store & Queries (Next)

**Status:** Not started  
**Goal:** Persistent storage with time-windowed queries for events.

Extend the existing `LocalRegistry` (SQLite) with an `events` table:
- Store `AgentEvent` records with indexed timestamps
- Time-windowed queries: "all tool calls from agent X in last 24h"
- Aggregation: "total tokens consumed this week", "tools used per agent"
- Export API for feeding dashboards and alerting systems

**Schema:**
```sql
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  type TEXT NOT NULL,
  tool_name TEXT,
  tool_status TEXT,
  cost_usd REAL,
  blocked INTEGER DEFAULT 0,
  raw_json TEXT NOT NULL
);
CREATE INDEX idx_events_agent_time ON events(agent_id, timestamp);
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_type ON events(type);
```

---

## Phase 2.3 — Policy Engine (Runtime)

**Status:** Not started  
**Goal:** Declarative runtime policies in `.sentinelflow-policy.yaml`.

Extend the policy file format with runtime rules:
```yaml
runtime_policies:
  enforcement_mode: monitor  # or enforce
  
  tool_allowlist:
    - Read
    - ListDir
    - Grep
    - Bash(npm test)
    - Bash(npm run build)
  
  tool_blocklist:
    - Bash(rm *)
    - Write(/etc/*)
  
  cost_budget:
    per_session_usd: 5.00
    per_day_usd: 50.00
  
  data_boundaries:
    blocked_paths:
      - /etc/shadow
      - /var/secrets/*
      - ~/.ssh/*
    blocked_patterns:
      - "\\d{3}-\\d{2}-\\d{4}"  # SSN
      - "\\d{16}"               # Credit card
```

---

## Phase 2.4 — Anomaly Detection

**Status:** Not started  
**Goal:** Pattern-based alerting on the event stream.

Detectors:
- **Novel tool:** Agent calls a tool never seen in its baseline
- **Cost spike:** Usage > 2σ from 7-day moving average
- **Error rate:** > 5 errors in 5 minutes
- **Privilege escalation:** Agent delegates to higher-privilege agent
- **Unusual pattern:** Tool call sequence anomaly detection

Each detector runs as a post-processor on events in the store, annotating events with `anomaly` fields.

---

## Phase 2.5 — Live Dashboard

**Status:** Not started  
**Goal:** Web UI for agent visibility.

Pages:
- **Agent Inventory** — All registered agents with risk levels and last scan
- **Event Stream** — Real-time tool call feed with filtering
- **Cost Tracker** — Token usage and cost over time, per agent
- **Anomaly Alerts** — Recent anomalies with confidence scores
- **Scan History** — Past scan reports with trend lines

Tech: React + Recharts served by a local Express server (`sentinelflow dashboard`).

---

## Phase 2.6 — GitHub Actions Marketplace

**Status:** Not started  
**Goal:** `uses: sentinelflow/scan@v1` in any workflow.

```yaml
- uses: sentinelflow/scan@v1
  with:
    preset: standard
    format: sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinelflow-results.sarif
```

---

## Success Metrics (90-day)

- Runtime interceptor installed in 50+ projects
- 10K+ events processed without data loss
- < 5ms policy evaluation overhead per tool call
- Zero false-positive blocks in monitor mode
- Dashboard used by 20+ organizations
