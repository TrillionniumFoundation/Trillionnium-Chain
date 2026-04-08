# TRNM Rank 1 Durable Boundary Decision Memo (2026-04-05)

## Truth-source snapshot

This memo chooses the **candidate durable-boundary direction** for Rank 1 on the **current local integrated `main`**.

Snapshot evaluated:
- local `main = 8703364b2`
- `origin/main = 35da4109e92321ecfdd9aa86b0738b968ea519d9`
- local `main` vs `origin/main`: **ahead 615**

Read together with:
- `RELEASE_READINESS.md`
- `trillionnium/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`
- `trillionnium/docs/release/TRNM_MAINNET_CLOSURE_EXECUTION_BOARD_2026-04-05.md`
- `trillionnium/docs/release/TRNM_RANK1_FIRST_EXECUTION_SLICE_2026-04-05.md`
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`
- `trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`
- `trillionnium/docs/runbooks/explorer-service-scaffold.md`

Boundary:
- this memo does **not** claim durable read closure is already implemented;
- it chooses the **candidate anchor values** that should guide the next implementation packet;
- if these choices later change, they should be changed explicitly by a successor memo rather than silently by implementation drift.

---

## Why this memo exists

The first Rank 1 execution slice froze two things:
1. the minimum honest Day-1 public read promise;
2. the mechanical boundary between placeholder scaffold evidence and future durable-read evidence.

The next shortest honest move is to stop leaving the 6 durable-read anchors as generic placeholders and instead choose one concrete direction for each.

Without that decision, implementation work will tend to sprawl across multiple incompatible future read-service models.

This memo therefore answers a narrower question:

> **Given the current local `main`, what is the shortest durable-boundary direction that can evolve the existing rpc-read scaffold into a non-placeholder read service without pretending a full public archive is already solved?**

---

## Current-reality constraints

The current repository state strongly suggests the following constraints:

1. The explorer scaffold is still explicitly placeholder-only.
   - `service_mode=operator-facing-static-scaffold`
   - `deployment_evidence_scope=placeholder-only`
   - `durable_indexer_status=not-implemented-in-this-scaffold`

2. The current Day-1 public read surface is still deliberately narrow.
   - `query-task/<task_id>`
   - `query-events/<task_id>?limit=<n>`
   - `query-capability-audit/<subject-or-token>`
   - `query-normalized-audit-events?...`

3. The scaffold still points at an rpc-read boundary today.
   - `read_contract_source=rpc-read-surface`
   - `historical_query_scope=rpc-retention-bounded`
   - `durability_boundary=ephemeral-rpc-window-only`

4. The repository already has replay-shaped evidence and smoke paths around emitted events / replay behavior.
   - `scripts/check_event_replay_smoke.sh`
   - release/run logs around event replay smoke

Interpretation:
- the shortest next step is **not** to invent a wholly separate public data plane first;
- it is to pick a durable boundary that can start from the existing rpc-read surface and turn it into a durable Day-1 read service in the smallest number of architectural jumps.

---

# Candidate durable-boundary decisions

## Summary table

| Anchor | Candidate value | Why this is the shortest honest choice |
| --- | --- | --- |
| `ingestion_source` | `rpc-pull` | Current read surface already terminates at `trnm-rpc`; this is the shortest path from placeholder scaffold to durable service without first inventing a new event bus contract. |
| `checkpoint_store` | `sqlite` | Current deployment shape is still single-host / single-service scaffold; SQLite is the smallest honest durable checkpoint boundary before multi-host HA is actually required. |
| `replay_start_anchor` | `genesis` | Current Day-1 surface is narrow enough that replay-from-genesis is simpler and more honest than pretending a stable intermediate durable checkpoint lineage already exists. |
| `retention_scope` | `durable-archive` **for the frozen Day-1 read surface only** | The durable service should retain the frozen 4 product read endpoints across the full chain history it ingests, even though TRNM is not yet promising a full generic archive for block/tx/account history. |
| `archive_owner` | `trnm-core-protocol-ops` | A concrete owner must exist before Rank 1 can close; the shortest current choice is to keep archive ownership with core protocol ops until a separate SRE/data platform owner is explicitly created. |
| `lag_slo` | `<= 2 blocks or <= 30s while healthy` | Tight enough to be meaningful for Day-1 read freshness, loose enough to be credible before full production read-plane tuning exists. |

---

## Anchor 1 — `ingestion_source=rpc-pull`

### Decision
Choose:
- `ingestion_source=rpc-pull`

### Why
This is the shortest honest bridge from the current scaffold to a durable service because:
- the current Day-1 read contract already hangs off `trnm-rpc` semantics;
- the scaffold already records `read_contract_source=rpc-read-surface`;
- the frontend/client/schema surface is already oriented around those read endpoints.

The point of this choice is **not** that rpc-pull is the forever-perfect architecture.
The point is that it is the smallest step that:
- preserves the current public promise,
- avoids inventing a new unsupported surface,
- and lets a durable store start ingesting immediately from the same contract users already see.

### Explicit non-claim
This does **not** mean:
- rpc-pull is the final permanent architecture;
- internal event-stream ingestion is forbidden later;
- block-replay cannot later become a stronger backfill path.

### Alternatives rejected for this slice
- `event-stream`: rejected for now because there is no frozen durable event-bus contract yet.
- `mixed`: rejected for the initial decision memo because it complicates the first implementation packet before one primary ingestion path exists.
- `block-replay`: attractive for later correctness/backfill, but not the shortest first durable service step from the current scaffold.

---

## Anchor 2 — `checkpoint_store=sqlite`

### Decision
Choose:
- `checkpoint_store=sqlite`

### Why
The current read-plane shape is still closest to:
- single-host
- single-service
- operator-local / scaffold-adjacent deployment

SQLite is therefore the smallest honest checkpoint boundary because it gives:
- one real durable cursor/checkpoint state,
- low operational overhead,
- a concrete persistence target,
- and a clear upgrade story later if Postgres becomes necessary.

### Explicit non-claim
This does **not** mean SQLite is forever sufficient for:
- HA,
- replicas,
- multi-writer coordination,
- or long-term data platform scale.

It means only:
- SQLite is the shortest credible first durable checkpoint store for the frozen Day-1 surface.

### Alternatives rejected for this slice
- `postgres`: rejected for now because it adds ops/deployment complexity earlier than needed for the first durable-boundary closure packet.
- `object-store`: rejected because it is not the shortest path to a resumable local replay/checkpoint loop.

---

## Anchor 3 — `replay_start_anchor=genesis`

### Decision
Choose:
- `replay_start_anchor=genesis`

### Why
At the current stage, replay-from-genesis is the cleanest honest choice because:
- the chain is still prelaunch / late-RC-prep rather than long-lived public-mainnet scale;
- the Day-1 read surface is narrow;
- and pretending a stable durable checkpoint lineage already exists would be false.

Choosing genesis as the first replay anchor prevents two classes of ambiguity:
1. hidden reliance on whatever the node/RPC currently happens to retain;
2. hand-wavy “start somewhere recent” behavior that breaks durable-read claims.

### Explicit non-claim
This does **not** mean future durable recovery must always replay from genesis in production.
It means the **first** durable-boundary packet should be anchored to genesis unless and until a real checkpoint lineage is created.

### Alternatives rejected for this slice
- `checkpoint:<id>`: rejected because no durable checkpoint lineage exists yet.
- `block:<height>`: rejected because it creates an arbitrary partial-history boundary too early.

---

## Anchor 4 — `retention_scope=durable-archive` (for Day-1 surface only)

### Decision
Choose:
- `retention_scope=durable-archive`

with one explicit boundary note:

> this durable archive claim applies only to the **frozen Day-1 public read surface**, not to a full generic chain archive for block/tx/account history.

### Why
If the durable service is going to ingest from genesis and claim to close Rank 1 for the Day-1 read surface, then that surface should not stay retention-bounded in the same way the rpc-only scaffold is today.

Otherwise the project would still only have:
- an rpc-retention-bounded scaffold,
- plus a second service that is also effectively bounded.

That would not materially close Rank 1.

### Explicit non-claim
This does **not** mean TRNM is promising:
- a universal archive node,
- unlimited full-block history for every future query family,
- or generic public archive semantics outside the frozen Day-1 read contract.

### Alternatives rejected for this slice
- `bounded`: rejected because it would leave the durable service too close to the scaffold’s current limitation.
- `tiered`: rejected because tiered archival policy is a later optimization/ops concern, not the shortest first durable boundary.

---

## Anchor 5 — `archive_owner=trnm-core-protocol-ops`

### Decision
Choose:
- `archive_owner=trnm-core-protocol-ops`

### Why
Rank 1 cannot honestly close while archive/read retention ownership is unassigned.
The shortest current answer is to assign ownership to the team already closest to:
- protocol releases,
- launch packets,
- and current mainline operational decisions.

This prevents the memo from hiding behind “owner TBD”.

### Explicit non-claim
This does **not** mean the long-term owner can never move to:
- a dedicated SRE team,
- data platform,
- or explorer/indexer ops team.

It only means Day-1 ownership cannot remain blank.

### Alternatives rejected for this slice
- `TBD` / `future-sre`: rejected because a blank owner is not a closure path.
- `community` / `validators`: rejected because accountability would remain ambiguous.

---

## Anchor 6 — `lag_slo<=2 blocks or <=30s while healthy`

### Decision
Choose:
- `lag_slo=<= 2 blocks or <= 30s while healthy`

### Why
This is the narrowest credible SLO shape for the first durable service packet because it is:
- concrete,
- bounded,
- user-meaningful,
- and not obviously overpromised.

It also preserves a useful distinction:
- freshness can be stated in both block and wall-clock terms;
- the SLO is conditioned on the service being healthy;
- the threshold is tight enough to matter, but not so tight that the first durable packet is guaranteed to fail by construction.

### Explicit non-claim
This does **not** mean:
- the SLO is already achieved today,
- the alerting/dashboard plane already enforces it,
- or the service has already been validated under real public load.

It means future durable evidence must either meet this bound or explicitly revise it with a new memo.

### Alternatives rejected for this slice
- unset / placeholder lag SLO: rejected because it keeps Rank 1 non-mechanical.
- sub-block / near-real-time claims: rejected as premature.
- `>5 blocks / >60s`: rejected as too weak for a credible Day-1 read freshness promise.

---

# What this memo now freezes for implementation

## Implementation target for the next packet
The next concrete Rank 1 implementation packet should assume:
- `ingestion_source=rpc-pull`
- `checkpoint_store=sqlite`
- `replay_start_anchor=genesis`
- `retention_scope=durable-archive` (for the frozen Day-1 surface only)
- `archive_owner=trnm-core-protocol-ops`
- `lag_slo<=2 blocks or <=30s while healthy`

## The next packet must NOT do
- quietly switch to `event-stream` or `mixed` without a successor decision memo;
- quietly swap SQLite for Postgres and pretend the durable boundary did not change;
- quietly narrow retention back to bounded while still claiming Rank 1 closure;
- leave archive ownership blank;
- leave lag/freshness unmeasured or undefined.

---

# Required follow-on artifact

The preferred next artifact now exists as:

- `trillionnium/docs/release/TRNM_RANK1_IMPLEMENTATION_DESIGN_PACKET_2026-04-05.md`

That design packet defines:
- SQLite schema for checkpoints / ingested rows / replay cursor
- rpc-pull ingestion loop
- replay-from-genesis bootstrap flow
- lag measurement logic
- retained Day-1 surface materialization strategy

Minimum acceptable fallback (if the full packet had not existed) would have been:
- polling cadence
- cursor/checkpoint row shape
- replay bootstrap command
- retention table boundary
- lag measurement formula

---

## What this memo intentionally does not claim

This memo does **not** claim:
- durable read closure is complete;
- a durable indexer is already implemented;
- a historical read-model is already production-ready;
- explorer backend is already non-placeholder;
- Rank 1 is now closed.

It only claims that the project should stop treating the six durable anchors as undefined.

---

## Final judgment

For the current local integrated `main`, the shortest honest durable-boundary direction is:

> **rpc-pull into a SQLite-backed durable store, replayable from genesis, retaining the frozen Day-1 read surface durably, owned by core protocol ops, with a Day-1 lag target of <=2 blocks or <=30s while healthy.**

That is the clearest next bridge from:
- placeholder scaffold / rpc-retention-bounded evidence

to:
- a real non-placeholder Rank 1 implementation packet.
