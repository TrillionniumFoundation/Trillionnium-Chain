# M05 Admission, nonce and branch-aware lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed transactions in native M06 execution; mempool product wiring remains distinct.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M05.ValidateTransaction

Require exact network, signature, nonce=current+1, height<=expiry and sufficient fee/funds before applying command. Invalid input leaves the original parent unchanged; decoded bytes are not reserved balance.

**Atomic/commit boundary:** M06 returns a new state; only M07 can commit it.

### M05.ReconsiderAfterReorg

Invalidate branch-relative inclusion; rerun nonce/grant/funds checks against new state. Never replay an irreversible operation because chain nonce vanished. The native bounded local pool reconciles against the current active branch; local removal history stays outside chain undo.

**Atomic/commit boundary:** Persistent local effect tombstones stay outside chain undo.

## M05.CanonicalNonce

**Invariant:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Scope:** Signed transactions in native M06 execution; mempool product wiring remains distinct.

**Atomic boundary:** Validate exact key reads and prefix-scan results immediately before canonical patch commit.

**Failure schedule:** Sixteen ordered same-sender nonces; Independent sender and recipient pairs; Speculation sees insufficient preceding funds.

**Expected result:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Resource and retention rule:** Retries at most transaction count; inflight at most configured workers.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_sender_degrades_to_serial_without_speculation`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_independent_senders_commit_without_false_conflicts`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_recipient_conflict_reexecutes_once_in_canonical_order`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Nonce contention, stale reservations, replay after reorg and hidden shared sponsor keys.

Future-nonce parking and replacement policy remain unimplemented. Public pool fairness and sustained capacity remain unaccepted.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M05` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Block-scoped execution continuation

The existing native executor now bounds thread creation per block and preserves a private
verified main envelope across canonical state replay. This is a computational fact, not
work validity or local permission. Capacity/range state transitions remain ordered and
consumer signatures still bind actual quota state. See the exact algorithm, errors and
counterexamples in [EXECUTION_PARALLEL](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md).
Complete-state root construction, full native node assembly and Hepta ownership remain
separate work; worker counts do not establish throughput or independent acceptance.

## Native bounded queued owner continuation

The existing Node SQLite owner now provides explicitly enabled local PNX1 queue/group
submission, M05 typed metadata, exact M06 prefix preview, fenced mining batches and
branch-relative reconciliation. Queue success is not execution, inclusion, confirmation
or external permission. All pending and archived rows/bytes plus local removal digests
are bounded; local removal history is not rewound by reorg. See the exact interfaces,
limits and actual native selectors in
[LOCAL_MEMPOOL_LIFECYCLE](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md).
The explicit V2 local profile adds admission-triggered wholly terminal cache eviction;
operator removal digests remain monotonic and separately finite. See
[LOCAL_MEMPOOL_CACHE_V2](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_CACHE_V2.md).
Public-v2 transport operations and acceptance flags are unchanged by this local owner.

Within one immutable actual-parent owner operation, pool prefixes can reuse a private
successful M05 main-envelope fact. Exact raw bytes and position, actual State and
complete Config reference identities, parent ID and height bind that fact; all M05
state-dependent gates still execute on the entire prefix. Facts publish only after
full M05/M06 success, and cancellation, unwind or refusal cannot advance them. Every
new owner operation and independent batch preview performs fresh checks. The paired
component counter/timing test compares complete outputs and retains both control and
reuse costs; it is not a claim of linear total pool cost or endpoint throughput.


The explicit [operator actor context](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
uses the existing module owner and fresh public descriptor/signature-bound N/P/G.
This changes development bootstrap custody and role pins only; native admission,
execution and confirmation remain required, and no independent/public flag is accepted.
