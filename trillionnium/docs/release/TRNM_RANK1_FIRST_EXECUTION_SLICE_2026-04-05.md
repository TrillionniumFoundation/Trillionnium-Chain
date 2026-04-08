# TRNM Rank 1 First Execution Slice (2026-04-05)

## Truth-source snapshot

This document is the **first execution slice** for Rank 1 on the **current local integrated `main`**.

Snapshot evaluated:
- local `main = 5a28fe5f9`
- `origin/main = 35da4109e92321ecfdd9aa86b0738b968ea519d9`
- local `main` vs `origin/main`: **ahead 614**

Read together with:
- `RELEASE_READINESS.md`
- `trillionnium/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`
- `trillionnium/docs/release/TRNM_MAINNET_CLOSURE_EXECUTION_BOARD_2026-04-05.md`
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
- `trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`
- `trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`
- `trillionnium/docs/runbooks/explorer-service-scaffold.md`

Boundary:
- this document does **not** close Rank 1;
- it freezes the **first executable slice** for Rank 1 on the current local `main`;
- it is meant to turn Rank 1 from “large blocker” into “concrete next packet with clear exit boundaries”.

---

## What this first slice is trying to achieve

This slice is intentionally narrower than full Rank 1 closure.
It is trying to close the following gap first:

> **Freeze what TRNM can honestly promise today as a Day-1 public read surface, and freeze the mechanical boundary between placeholder scaffold evidence and future durable-read evidence.**

In practical terms, this first slice covers:
- **R1-01** Day-1 public read surface freeze
- the most concrete part of **R1-02** query/error contract freeze
- the boundary-gating part of **R1-06** operator handoff closure

It does **not yet** claim to close:
- durable indexer implementation
- historical read-model implementation
- stable production explorer backend
- archive/read-replica closure
- read-lag SLO closure

---

## First-slice judgment

### Status
**Executable now**

### Why this slice is the right next move
Because the current repository already has enough material to freeze:
- the minimum public read endpoints,
- the frontend/client/schema correspondence,
- the path/query fail-closed parsing shape in `trnm-rpc`,
- and the placeholder-vs-durable handoff boundary.

What it does **not** yet have is a real durable indexer packet.
So the shortest honest move is:

1. freeze the public promise,
2. freeze the boundary between placeholder and durable,
3. then force future durable work to satisfy that frozen contract instead of redefining it ad hoc.

---

# Slice A — Freeze the Day-1 minimum public read surface

## Decision frozen by this slice
The only endpoints that should currently be treated as **Day-1 public read surface candidates** are:

1. `GET /query-task/:taskId`
2. `GET /query-events/:taskId`
3. `GET /query-capability-audit/:subjectOrToken`
4. `GET /query-normalized-audit-events?...`
5. `GET /healthz` / health probe path (**ops-only; not product read surface**)

This is consistent with:
- frontend client calls in `web4-frontend/lib/api-contract/client.ts`
- frontend schemas in `web4-frontend/lib/api-contract/schemas.ts`
- current `trnm-rpc` path handlers and parsing logic in `trillionnium/crates/trnm-rpc/src/main.rs`

## Explicitly NOT in Day-1 freeze
The following remain out of scope for the Day-1 public promise:
- block query
- tx query
- account query
- archive-backed historical explorer promises
- durable explorer backend SLO claims
- index lag / checkpoint / archive ownership as already-closed public contract

Interpretation rule:
- if a reviewer needs durable history, archive guarantees, or stable explorer backend semantics, Rank 1 is still open;
- this slice only freezes the **minimum honest public read promise** on the current mainline.

---

# Slice B — Freeze the query / parsing / fail-closed boundary for the Day-1 surface

## Decision frozen by this slice
For the Day-1 surface above, current path/query semantics should be treated as append-stable enough to freeze at the contract level.

### Strongest current evidence points
The current `trnm-rpc` mainline already has explicit parsing/validation hardening around:
- `parse_query_events_limit_from_path(...)`
- `parse_query_normalized_audit_events_query_from_path(...)`
- `parse_query_capability_audit_subject_from_target(...)`
- `is_health_probe_path(...)`

This means the first slice can freeze not only endpoint names, but also the rule that:

> **query parsing and path resolution for the Day-1 read surface are fail-closed by default, not guess-and-recover by default.**

## What this slice freezes
- no silent promotion of extra query keys into supported contract
- no silent downgrade from malformed path/query to “best effort” interpretation
- no implicit expansion from the 4 product read endpoints into block/tx/account promises
- no placeholder handoff wording that implies durable read closure

## What this slice deliberately leaves open
- final public error-code table
- rate-limit / timeout / retry SLO promises
- historical replay guarantees
- index freshness SLO

Those remain later Rank 1 work, but they must build on this frozen Day-1 surface instead of redefining it.

---

# Slice C — Freeze the placeholder vs durable handoff boundary

## Decision frozen by this slice
Current TRNM still has **two distinct evidence classes** for Rank 1:

### 1. Placeholder scaffold evidence
Allowed when:
- the deployment is still scaffold/static/operator-facing placeholder only;
- `deployment_evidence_scope=placeholder-only`;
- `service_mode=operator-facing-static-scaffold`;
- durable anchors are still missing.

### 2. Durable-read evidence
Allowed only when:
- the deployment is truly non-placeholder;
- the packet is explicitly marked durable;
- all 6 durable-read anchors are filled with real values;
- replay / restore / lag / checkpoint evidence is present.

## The 6 durable-read anchors remain mandatory
Future durable closure may not hand-wave these away.
The packet must carry real values for:
1. `ingestion_source`
2. `checkpoint_store`
3. `replay_start_anchor`
4. `retention_scope`
5. `archive_owner`
6. `lag_slo`

## Mechanical fail-closed rule
This slice freezes the rule that:

> **placeholder scaffold evidence may not be “upgraded” into durable-read closure by manual wording alone.**

If the evidence still originates from scaffold status/capture artifacts, it remains placeholder-only.

That boundary is already encoded across:
- `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`
- `TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`

This slice elevates that from “good template discipline” to “first-slice Rank 1 gating rule”.

---

# Slice D — What must exist before this slice can be called complete

This first slice should be considered complete only if all of the following are true:

## D1. Public read surface freeze is explicit
- the 4 product endpoints + ops health probe remain the only Day-1 promise;
- no doc/runbook/frontend text silently expands the promise to block/tx/account history.

## D2. Contract correspondence is explicit
- frontend client + schemas + adapter + `trnm-rpc` paths all point to the same Day-1 surface;
- no extra read surface is treated as “basically supported” only because code exists somewhere else.

## D3. Placeholder/durable template selection remains mechanical
- placeholder evidence is still explicitly placeholder-only;
- durable template cannot be used unless all 6 anchors + replay/restore/lag evidence exist.

## D4. One implementation decision memo is created for the next slice
This first slice should leave behind one concrete decision memo for the *next* Rank 1 step:
- chosen candidate `ingestion_source`
- candidate `checkpoint_store`
- candidate `replay_start_anchor`
- candidate `retention_scope`
- candidate `archive_owner`
- candidate `lag_slo`

Important: the decision memo may initially contain **candidate choices**, but it must not pretend those anchors are already implemented.

---

# Deliverables for the next immediate step after this slice

Once this slice is accepted, the next document/work artifact should be:

## Rank 1 durable-boundary decision memo
Purpose:
- choose the concrete durable-read direction instead of keeping it as a generic placeholder gap.

This artifact now exists as:
- `trillionnium/docs/release/TRNM_RANK1_DURABLE_BOUNDARY_DECISION_MEMO_2026-04-05.md`

Frozen fields in that memo:
- `ingestion_source`
- `checkpoint_store`
- `replay_start_anchor`
- `retention_scope`
- `archive_owner`
- `lag_slo`
- one-sentence rationale for each
- what remains implementation-only vs already contract-frozen

That memo is the shortest honest bridge from:
- “placeholder scaffold + frozen Day-1 contract”

to:
- “real durable-read closure work has actually begun”.

---

## What this slice intentionally does NOT claim

This slice does **not** claim:
- Rank 1 is closed
- a durable indexer already exists
- historical read-model is already implemented
- explorer backend is already production-ready
- archive/replay policy is already operationally closed
- public mainnet is now GO

It only claims that current `main` is now ready to stop re-arguing the Day-1 read promise and start executing against one frozen boundary.

---

## Final judgment

For the current local integrated `main`, the correct next move for Rank 1 is:

> **freeze the minimum Day-1 read promise + freeze the placeholder/durable evidence boundary + immediately choose the durable-read anchor direction.**

That is the shortest first slice because it converts Rank 1 from a broad blocker into one concrete execution line without pretending the durable indexer problem is already solved.
