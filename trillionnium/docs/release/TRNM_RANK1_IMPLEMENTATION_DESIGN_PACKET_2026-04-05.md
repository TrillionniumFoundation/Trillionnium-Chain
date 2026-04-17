# TRNM Rank 1 Implementation Design Packet (2026-04-05)

## Truth-source snapshot

This document is the first concrete implementation design packet for **Rank 1** on the **current local integrated `main`**.

Snapshot evaluated:
- local `main = a99620066`
- `origin/main = 35da4109e92321ecfdd9aa86b0738b968ea519d9`
- local `main` vs `origin/main`: **ahead 615**

Read together with:
- `RELEASE_READINESS.md`
- `trillionnium/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`
- `trillionnium/docs/release/TRNM_MAINNET_CLOSURE_EXECUTION_BOARD_2026-04-05.md`
- `trillionnium/docs/release/TRNM_RANK1_FIRST_EXECUTION_SLICE_2026-04-05.md`
- `trillionnium/docs/release/TRNM_RANK1_DURABLE_BOUNDARY_DECISION_MEMO_2026-04-05.md`
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`
- `trillionnium/docs/runbooks/explorer-service-scaffold.md`

Boundary:
- this packet is an **implementation design**, not a proof that Rank 1 is closed;
- it defines the **first concrete build shape** for a non-placeholder durable read service;
- it does not yet claim production readiness, HA, or archive-grade universal chain history.

---

## Design objective

Implement the shortest honest bridge from the current placeholder explorer scaffold to a **non-placeholder durable read service** that can durably serve the frozen Day-1 public read surface:

1. `GET /query-task/:taskId`
2. `GET /query-events/:taskId`
3. `GET /query-capability-audit/:subjectOrToken`
4. `GET /query-normalized-audit-events?...`

The chosen durable-boundary direction, already frozen in the decision memo, is:
- `ingestion_source = rpc-pull`
- `checkpoint_store = sqlite`
- `replay_start_anchor = genesis`
- `retention_scope = durable-archive` (for the frozen Day-1 surface only)
- `archive_owner = trnm-core-protocol-ops`
- `lag_slo = <= 2 blocks or <= 30s while healthy`

So this packet answers a narrower engineering question:

> **How should TRNM build the first durable Day-1 read service from the existing rpc-read surface without inventing a larger data platform first?**

---

# 1. Proposed service shape

## Service role
Introduce a new **single-process durable read service** with three internal responsibilities:

1. **ingestor**
   - polls the existing `trnm-rpc` Day-1 endpoints;
   - performs genesis-to-tip replay and ongoing catch-up;
   - writes durable state into SQLite.

2. **materializer**
   - normalizes rpc responses into append-stable local tables;
   - keeps the frozen Day-1 read surface queryable without depending on current rpc retention.

3. **query server**
   - serves the same Day-1 contract from SQLite-backed projections instead of directly from ephemeral rpc state.

## Deployment posture for first implementation
- single host
- single process
- SQLite file on local durable disk
- one background ingestion loop
- one HTTP read server
- one health/lag endpoint family

This is intentionally smaller than a final production read plane.

---

# 2. Data flow

## 2.1 Bootstrap flow

### Initial state
- no checkpoint exists
- SQLite database exists or is created empty
- replay start anchor = `genesis`

### Bootstrap sequence
1. Initialize SQLite schema.
2. Insert one row in `ingest_checkpoint` with:
   - `replay_start_anchor = genesis`
   - `last_completed_height = 0`
   - `last_completed_block_ts = null`
   - `last_poll_finished_at = null`
3. Start rpc-pull replay from height 1 upward.
4. For each height, poll the Day-1-relevant rpc/read sources needed to derive:
   - task state
   - task events
   - capability audit
   - normalized audit events
5. Materialize that height into SQLite in one transaction.
6. Advance checkpoint only after the transaction commits.
7. Continue until the service reaches near-tip and can switch to steady-state polling.

## 2.2 Steady-state flow

1. Poll current tip / latest visible height from rpc-visible signals.
2. Compare to `last_completed_height`.
3. If new heights exist, ingest sequentially.
4. If no new heights exist, sleep for the poll interval and measure lag.
5. Expose health as:
   - `healthy/current`
   - `healthy/lagging`
   - `degraded/replaying`
   - `down`

## 2.3 Crash/restart flow

1. Open SQLite.
2. Read `ingest_checkpoint`.
3. Resume from `last_completed_height + 1`.
4. Re-run materialization from that point.
5. Do not advance checkpoint past partially committed work.

---

# 3. SQLite schema

The schema is intentionally minimal and scoped only to the frozen Day-1 read surface.

## 3.1 `service_meta`

Purpose:
- static service identity and schema versioning.

Suggested columns:
- `key TEXT PRIMARY KEY`
- `value TEXT NOT NULL`

Required keys:
- `schema_version`
- `service_mode` = `non-placeholder-durable-read-service`
- `read_contract_source` = `rpc-pull-materialized-day1-surface`
- `ingestion_source` = `rpc-pull`
- `checkpoint_store` = `sqlite`
- `replay_start_anchor` = `genesis`
- `retention_scope` = `durable-archive` (bounded to the frozen Day-1 surface only)
- `archive_owner` = `trnm-core-protocol-ops`
- `lag_slo` = `<= 2 blocks or <= 30s while healthy`

This lets the SQLite durable boundary persist the full frozen anchor tuple locally instead of relying on the design objective section alone.

## 3.2 `ingest_checkpoint`

Purpose:
- the single durable cursor for replay/resume.

Suggested shape (single-row table):
- `id INTEGER PRIMARY KEY CHECK (id = 1)`
- `replay_start_anchor TEXT NOT NULL`
- `last_completed_height INTEGER NOT NULL`
- `last_completed_block_ts TEXT`
- `last_poll_started_at TEXT`
- `last_poll_finished_at TEXT`
- `last_successful_replay_at TEXT`
- `last_error_at TEXT`
- `last_error_reason TEXT`
- `current_mode TEXT NOT NULL`  -- `bootstrap-replay` / `steady-state`

## 3.3 `task_projection`

Purpose:
- latest task view for `query-task`.

Suggested columns:
- `task_id TEXT PRIMARY KEY`
- `status TEXT NOT NULL`
- `owner TEXT NOT NULL`
- `name TEXT`
- `created_at TEXT NOT NULL`
- `updated_at TEXT`
- `metadata_json TEXT NOT NULL`
- `source_height INTEGER NOT NULL`
- `source_event_seq INTEGER NOT NULL`
- `source_updated_at TEXT NOT NULL`

Notes:
- `metadata_json` stores the schema-preserving object payload.
- `source_height` and `source_event_seq` give deterministic replay ordering.

## 3.4 `task_events`

Purpose:
- append-only event log for `query-events/:taskId`.

Suggested columns:
- `event_id TEXT PRIMARY KEY`
- `task_id TEXT NOT NULL`
- `type TEXT NOT NULL`
- `level TEXT NOT NULL`
- `timestamp TEXT NOT NULL`
- `payload_json TEXT NOT NULL`
- `source_height INTEGER NOT NULL`
- `source_order INTEGER NOT NULL`

Indexes:
- `idx_task_events_task_height_order (task_id, source_height, source_order)`
- `idx_task_events_task_ts (task_id, timestamp)`

## 3.5 `capability_audit_projection`

Purpose:
- stable materialization for `query-capability-audit/:subjectOrToken`.

Suggested columns:
- `subject TEXT NOT NULL`
- `capability TEXT NOT NULL`
- `granted INTEGER NOT NULL`
- `reason TEXT`
- `checked_at TEXT NOT NULL`
- `source_height INTEGER NOT NULL`
- `source_order INTEGER NOT NULL`
- `PRIMARY KEY (subject, capability, checked_at, source_order)`

Index:
- `idx_capability_audit_subject_checked (subject, checked_at DESC, source_order DESC)`

## 3.6 `normalized_audit_events`

Purpose:
- durable surface for `query-normalized-audit-events`.

Suggested columns:
- `row_id INTEGER PRIMARY KEY AUTOINCREMENT`
- `source TEXT NOT NULL`
- `event_type TEXT NOT NULL`
- `actor TEXT`
- `object_id TEXT`
- `related_id TEXT`
- `amount TEXT`
- `reason TEXT`
- `note TEXT`
- `checked_at TEXT`
- `timestamp TEXT`
- `subject TEXT`
- `source_height INTEGER NOT NULL`
- `source_order INTEGER NOT NULL`
- `cursor_key TEXT NOT NULL UNIQUE`

Indexes:
- `idx_norm_audit_source_type_order (source, event_type, source_height DESC, source_order DESC)`
- `idx_norm_audit_cursor (cursor_key)`

Cursor rule:
- `cursor_key` should be a deterministic composite derived from
  - `source_height`
  - `source_order`
  - stable tie-breaker material

This keeps pagination mechanical instead of ad hoc.

## 3.7 `height_ingest_manifest`

Purpose:
- idempotent replay bookkeeping per height.

Suggested columns:
- `height INTEGER PRIMARY KEY`
- `ingested_at TEXT NOT NULL`
- `task_projection_rows INTEGER NOT NULL`
- `task_event_rows INTEGER NOT NULL`
- `capability_audit_rows INTEGER NOT NULL`
- `normalized_audit_rows INTEGER NOT NULL`
- `content_hash TEXT NOT NULL`

This table exists so later replay verification can detect unexpected drift for an already materialized height.

## 3.8 `materialization_watermark`

Purpose:
- fail-closed linkage between the checkpoint cursor and the 4 Day-1 materialized surfaces.

Suggested columns:
- `projection_name TEXT PRIMARY KEY`
- `last_materialized_height INTEGER NOT NULL`
- `last_manifest_hash TEXT NOT NULL`
- `last_materialized_at TEXT NOT NULL`

Required `projection_name` values:
- `task_projection`
- `task_events`
- `capability_audit_projection`
- `normalized_audit_events`

Bootstrap rule:
- initialize one row per required projection with `last_materialized_height = 0` before replay starts.

Consistency rule:
- `ingest_checkpoint.last_completed_height` may advance to height `h` only after all 4 watermark rows also advance to `h` in the same SQLite transaction.
- health/status output should treat any mismatch between checkpoint height and watermark minimum as `degraded/replaying`, not `healthy/current`.

Why this table exists:
- `height_ingest_manifest` proves what was materialized for a given height;
- `materialization_watermark` proves every required Day-1 projection has caught up to the checkpoint cursor;
- together they keep checkpoint advancement from silently outrunning one missing projection family.

## 3.9 Checkpoint/materialization invariants

The first implementation should keep the schema mechanically fail-closed around three invariants:

1. **checkpoint parity**
   - `ingest_checkpoint.last_completed_height` must equal the minimum `last_materialized_height` across all rows in `materialization_watermark` before the service reports steady-state health.
2. **manifest parity**
   - every `materialization_watermark.last_manifest_hash` for height `h` should match `height_ingest_manifest.content_hash` for the same height.
3. **single-height atomicity**
   - all row deletes/reinserts for height `h`, the manifest rewrite, the 4 watermark updates, and the checkpoint advance must commit or rollback together.

These invariants are the smallest schema-level guardrail that keeps the SQLite durable boundary consistent with the design packet's replay/resume claims.

---

# 4. Materialization strategy by endpoint

## 4.1 `query-task/:taskId`

### Source of truth
- rpc-visible task view already exposed by `trnm-rpc`

### Durable materialization rule
- keep exactly one latest row in `task_projection` per `task_id`
- update only when `(source_height, source_event_seq)` advances
- do not silently merge incompatible schemas into `metadata_json`

### Query behavior in durable service
- `SELECT ... FROM task_projection WHERE task_id = ?`
- return `404` / equivalent contract error if missing

---

## 4.2 `query-events/:taskId`

### Source of truth
- rpc-visible task event history

### Durable materialization rule
- append events into `task_events`
- order by `(source_height, source_order)`
- retain full history for the frozen Day-1 surface

### Query behavior in durable service
- accept same `limit` contract as current surface
- enforce the frozen defaults/max:
  - default `100`
  - max `500`
- return newest-first or contract-consistent order exactly as frozen by current read contract / frontend expectations

---

## 4.3 `query-capability-audit/:subjectOrToken`

### Source of truth
- rpc-visible capability audit projection

### Durable materialization rule
- append immutable audit facts
- do not collapse rows that differ in `checked_at` or source order
- later query layer may return contract-specific grouped/latest view if needed

### Query behavior in durable service
- preserve subject-scoped result shape already used by frontend schemas

---

## 4.4 `query-normalized-audit-events?...`

### Source of truth
- rpc-visible normalized audit page

### Durable materialization rule
- append immutable normalized audit rows
- generate stable `cursor_key`
- preserve source/type filters and pagination semantics
- keep deterministic ordering stable across replay

### Query behavior in durable service
- support current filter set:
  - `source`
  - `eventType`
  - `limit`
  - `cursor`
- preserve current page semantics:
  - `events`
  - optional `nextCursor`
  - optional `hasMore`
  - optional `total`

---

# 5. Ingestion loop design

## 5.1 Poll cadence

Initial candidate values:
- replay mode: tight loop with no artificial sleep except backoff on error
- steady-state mode: poll every `1s`
- degraded mode: exponential backoff capped at `10s`

Rationale:
- current lag SLO is `<= 2 blocks or <= 30s while healthy`
- a 1s steady-state poll interval is consistent with that goal without overdesigning the first implementation

## 5.2 Per-height ingest transaction

For each height `h`:
1. fetch the rpc-visible material needed for the frozen Day-1 endpoints;
2. derive materialized rows;
3. open one SQLite transaction;
4. insert/replace all rows derived for `h`;
5. write `height_ingest_manifest(height=h, ...)`;
6. update all 4 `materialization_watermark` rows to `last_materialized_height = h` with the same manifest hash;
7. update `ingest_checkpoint.last_completed_height = h`;
8. commit transaction.

Fail-closed rule:
- if any step fails, rollback the transaction;
- do not advance `last_completed_height`;
- record `last_error_at` and `last_error_reason`.

## 5.3 Idempotency rule

Re-ingesting an already materialized height should be safe and deterministic.

Implementation rule:
- either delete-then-reinsert all rows for that height inside one transaction,
- or upsert using deterministic row IDs / content hashes.

The simpler first implementation is:
- **delete existing rows for height `h`, then reinsert, then rewrite manifest and watermark rows**.

This is easier to verify than partial row-level conflict logic.

---

# 6. Genesis replay bootstrap design

## 6.1 Why genesis replay first
The decision memo already froze `replay_start_anchor=genesis`.
That means the first durable service must be able to build its retained Day-1 read surface from an empty store using only the chosen ingestion path plus replay logic.

## 6.2 Bootstrap command shape

Suggested future command family:
- `trnm-read-service bootstrap --from genesis`
- `trnm-read-service replay --from-height <h>`
- `trnm-read-service serve`
- `trnm-read-service status`

This packet does **not** require the binary to exist yet.
It freezes the shape future implementation should target.

## 6.3 Bootstrap completion condition
Bootstrap replay is complete when:
- `last_completed_height == current observed tip`
- all Day-1 tables are populated consistently
- `current_mode` transitions from `bootstrap-replay` to `steady-state`

---

# 7. Lag measurement formula

## Frozen lag target
- `<= 2 blocks` **or** `<= 30s while healthy`

## Proposed measured fields
The durable service should expose at least:
- `chain_tip_height`
- `materialized_height`
- `height_lag = chain_tip_height - materialized_height`
- `chain_tip_ts`
- `materialized_tip_ts`
- `freshness_lag_seconds = now - materialized_tip_ts`
- `service_health_state`

## Health formula

### Healthy/current
- `height_lag <= 2`
- `freshness_lag_seconds <= 30`
- no outstanding ingest error

### Healthy/lagging
- service still making forward progress
- but either lag bound is temporarily exceeded

### Degraded/replaying
- bootstrap replay active, or repeated ingest errors present

### Down
- service cannot answer health probe truthfully or SQLite/open/poll loop is broken

## Fail-closed rule
Do not report `healthy/current` when only one of the two lag dimensions is known.
If timestamp evidence is missing, health should degrade rather than silently assuming freshness.

---

# 8. Retention/materialization policy

## What is retained durably
The durable service should durably retain the full history needed to answer the frozen Day-1 read surface:
- all materialized `task_projection` latest states
- all retained `task_events`
- all retained `capability_audit_projection` rows needed for audit history
- all retained `normalized_audit_events` rows used by the public filter/page contract

## What is NOT claimed
The durable service does **not** yet claim to retain:
- arbitrary full block payloads
- arbitrary tx body archive
- arbitrary account history outside the frozen Day-1 contract

## Why this matters
This keeps Rank 1 honest:
- durable for the Day-1 public promise,
- not falsely “universal archive” before the repo has actually built one.

---

# 9. Query server design

## Contract rule
The durable service should mirror the current Day-1 public surface, not redefine it.

That means:
- same endpoint names
- same path params
- same supported filters
- same default/max limits where already frozen
- same top-level response shapes expected by frontend schemas

## Suggested implementation boundary
- keep a thin HTTP layer in front of SQLite queries
- validate incoming query shape before hitting SQLite
- preserve fail-closed parsing semantics already established in `trnm-rpc`

## Explicit non-goal for first packet
Do **not** mix in:
- new read endpoints
- write endpoints
- block/tx/account archive expansion
- generic analytics endpoints

---

# 10. Operational files / evidence expected from the implementation

The first implementation packet should eventually produce these artifacts:

## Runtime/config artifacts
- service config file
- SQLite DB path and schema version marker
- health endpoint contract
- log path

## Replay artifacts
- bootstrap transcript from genesis
- replay resume transcript from non-zero checkpoint
- one manifest proving checkpoint advancement
- one status snapshot proving watermark parity with the checkpoint cursor

## Lag artifacts
- one status output containing:
  - chain tip
  - materialized height
  - height lag
  - freshness lag seconds
  - health state

## Closure boundary artifacts
- explicit packet showing placeholder scaffold is no longer the serving path
- explicit packet carrying all 6 durable-read anchors with real values

---

# 11. Out-of-scope for this first implementation packet

This packet intentionally does **not** require, yet:
- Postgres
- replicas
- multi-host HA
- shard/partition strategy
- global search index
- full block/tx/account archive
- cross-region deploy
- public multi-tenant rate-limiter productization

Those may come later, but should not delay the first honest durable service packet.

---

# 12. Minimal definition of done for this design packet to become implementation-ready

This packet should be considered implementation-ready once an engineer can start from it and produce:

1. one SQLite schema migration file,
2. one rpc-pull ingest loop,
3. one bootstrap-from-genesis command,
4. one steady-state poller,
5. one health/lag status surface,
6. one query server implementing the frozen Day-1 endpoints from SQLite,
7. one checkpoint/materialization parity check proving the checkpoint cursor cannot outrun any Day-1 projection.

If an implementation still needs to re-decide:
- ingest source,
- checkpoint store,
- replay anchor,
- retention boundary,
- owner,
- lag formula,

then this packet has failed its purpose.

---

## Final judgment

The shortest honest Rank 1 implementation on the current local `main` is:

> **a single-process SQLite-backed durable read service that rpc-pulls the frozen Day-1 read surface, bootstraps from genesis, materializes only the promised Day-1 projections durably, and reports freshness by <=2 blocks or <=30s while healthy.**

That is the smallest non-placeholder shape that can turn the current scaffold into a real implementation path without pretending the entire long-term explorer/indexer platform is already solved.
