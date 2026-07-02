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

**Enterprise policy engine (current):**
- **Central pattern registry** with 18 dangerous command patterns, 15 secret patterns, 12 sensitive file write patterns, and 7 network egress patterns.
- **8 policy classes** implemented in TypeScript (`packages/interceptors/src/policies.ts`).
- **Production handler scripts** embed a self-contained subset via `handler-codegen.ts` (no regex literals; patterns compiled at runtime).

**4 built-in listeners:**
1. `ConsoleListener` — Color-coded terminal output
2. `JsonlFileListener` — Append-only event log with rotation
3. `CallbackListener` — Custom function for integrations
4. `AlertListener` — Triggers on blocks/anomalies/error spikes

**CLI commands (runtime):**
- `sentinelflow intercept install [path]` — Install hooks
- `sentinelflow intercept uninstall [path]` — Remove hooks
- `sentinelflow intercept status [path]` — Check status and stats
- `sentinelflow intercept tail [path]` — View recent events
 - `sentinelflow events tail/blocked/stats [path]` — Query the unified event store
 - `sentinelflow costs [path]` — Token spend report from the event store
 - `sentinelflow anomalies [path]` — Batch anomaly detection over event history (Phase 2.4)

---

## Phase 2.2 — Event Store & Queries ✅

**Status:** Complete (v0.3.x)  
**Goal:** Persistent storage with time-windowed queries for events.

Implemented in the runtime layer as dual-write:
- Append-only JSONL log: `.sentinelflow/events.jsonl`
- SQLite store: `.sentinelflow/events.db`

CLI supports:
- `sentinelflow events tail`
- `sentinelflow events blocked`
- `sentinelflow events stats`

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

## Phase 2.3 — Policy Engine (Runtime) ✅

**Status:** Complete  
**Goal:** Declarative runtime policies in `.sentinelflow-policy.yaml`.

`intercept install` loads the `runtime_policies` section as defaults, with CLI flags taking precedence. The shipped schema (see `.sentinelflow-policy.example.yaml` for the full reference) differs from the early sketch that used to live in this doc — it exposes the actual classification/RBAC/sequence systems built in `packages/interceptors`, not a flat blocked-paths list:

```yaml
runtime_policies:
  blocked_tools: [NotebookEdit]
  allowed_tools: []
  max_cost_per_session: 5.00   # recorded, not enforced -- see honest limitation below
  enforcement_mode: monitor
  egress_allowed_domains: ["*.corp.internal"]
  egress_blocked_domains: [evil.example.com]

  data_boundary:
    enabled: true
    enforcement_mode: monitor   # independent of the core enforcement_mode above
    default_max_classification: internal
    agent_clearances:
      - agent: "deploy-*"
        max_classification: restricted

  identity:
    enabled: true
    enforcement_mode: monitor
    role: executor
    agent_roles:
      reviewer-agent: reader

  sequence_detection:
    enabled: true
    enforcement_mode: monitor
    window_minutes: 5
    min_confidence: 0.7
```

Parsing lives in `packages/scanner/src/suppression.ts` (`loadPolicyFile`/`RuntimePoliciesConfig`, using the real `yaml` package — the original hand-rolled regex parser couldn't handle nested arrays/objects). Each advanced policy defaults to enabled + monitor mode, independent of the core subset's `enforcement_mode`, so enabling this feature never silently starts blocking things an existing "enforce" install didn't block before.

**Honest limitation:** `max_cost_per_session` is recorded and queryable (`sentinelflow costs`) but not enforced in real time — no supported framework exposes token/cost data in hook payloads yet.

---

## Phase 2.4 — Anomaly Detection ✅ (batch, not live post-processing)

**Status:** Complete, as an on-demand CLI command rather than an automatic post-processor  
**Goal:** Pattern-based alerting on the event stream.

`sentinelflow anomalies [path] --since 7d` runs a batch pass over SQLite event history:
- **Novel tool:** Agent calls a tool never seen in its baseline
- **Cost spike:** Usage > 2σ from a rolling per-agent average
- **Error rate:** Sustained failure rate over a sliding window
- **Privilege escalation:** Included automatically once `identity.agent_roles`/`agent_privileges` are configured — without real per-agent data its built-in default would flag nearly every Bash/Write call, and real-time RBAC (Phase 2.3) already covers that concern with a better-calibrated default.

This ships as a batch/on-demand command rather than "a post-processor on events in the store, annotating events with `anomaly` fields" as originally sketched here: cost-spike and error-rate detection need many events to build a baseline, which is a better fit for periodic analysis than synchronous per-event annotation. Sequence/pattern anomaly detection (the fifth original detector type) is handled separately and *is* live/per-call — see Phase 2.3's `sequence_detection` policy, which reconstructs session history from SQLite on every tool call rather than running as a batch job.

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
