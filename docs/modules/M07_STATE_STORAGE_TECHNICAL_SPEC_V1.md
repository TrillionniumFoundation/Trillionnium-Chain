# M07 Branch roots, schema and owner-controlled persistence

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Distinct fresh native-development and reference revision3 SQLite namespaces; each has one writer. Neither silently upgrades or writes the other namespace.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M07.OpenNamespace

Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation. Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Atomic/commit boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

### M07.StageBranch

BEGIN IMMEDIATE, insert immutable block, insert changed-key deltas, COMMIT. Any failure rolls back the transaction. A restart reads complete old/new state, not partially visible rows.

**Atomic/commit boundary:** blocks+deltas one transaction; active pointer separate M08 publication.

## M07.OwnedInitialization

**Invariant:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Scope:** Distinct fresh native-development and reference revision3 SQLite namespaces; each has one writer. Neither silently upgrades or writes the other namespace.

**Atomic boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Failure schedule:** Intent persisted; Schema staged; Before initialization commit; After commit before marker removal; Unexpected trigger and unmarked empty database.

**Expected result:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Resource and retention rule:** Ordinary append writes only changed keys; one physical state slot, separate logical generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_every_initialization_cut_recovers_only_our_exact_intent`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_unmarked_empty_database_is_not_reinitialized`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_injected_trigger_rejects_before_writable_open`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_append_retains_one_physical_state_slot`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Initialization gaps, trigger/schema substitution, disk full, path replacement and unbounded full-state copies.

Full descriptor/sidecar fencing, incremental authenticated native persistent state and physical power-loss tests remain pending.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M07` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

Node is now a native single-writer fresh-namespace SQLite owner for blocks/deltas, staged KV, snapshots and active generation. Existing Python storage remains a separate oracle. Descriptor/sidecar races, physical power loss, long-run growth and incremental persistent roots remain unqualified.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Actual-state cancellation and statement reuse

The [history/state resource contract](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md) preserves the actual KV/root check and adds cancellation every256 rows, a final tip/generation/slot check and reused delta statements. The SQLite schema and atomic transaction boundary remain unchanged. Complete root construction and retained history still have their stated growth costs.

The [authenticated account/state research companion](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md#authenticated-complete-state-companion)
computes a separate full-parent-bound commitment and checks proof-derived prologue
and successor aggregates. It never stores that commitment as the Node state root,
publishes an archive branch or changes this module's schema or atomic boundary.
The existing branch owner and complete native State root remain authoritative.
Integrating persistent authenticated updates still requires explicit root/profile
selection, migration/recovery rules, complete obligation discovery and retained
witness-data responsibility.

## Explicit authenticated-state archive

The [durable research archive](../protocol/pon-nakamoto-v1/details/AUTHENTICATED_STATE_ARCHIVE_V1.md)
uses its own namespace and explicit caller operation. It imports actual native genesis,
reexecutes an admitted block through complete authenticated-state inputs and checks
full state/receipts before atomically publishing checkpoint, delta and optional selection.
CAS generations do not rewind when selecting an older branch. Missing data, altered
records, stale selection, quota exhaustion and cancellation refuse without partial
publication. Reads and reopen reconstruct complete states and compare actual native
branch data. This separate reference-backed store adds no ordinary startup selection,
installed state root, public proof service, pruning or rollback of local operation facts.
