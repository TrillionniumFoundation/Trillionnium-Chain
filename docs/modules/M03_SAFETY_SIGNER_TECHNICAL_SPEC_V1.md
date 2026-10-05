# M03 Work attempts, independent local effects and custody

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native bounded development mining plus the separate reference local-effect experiment. Its two SQLite connections demonstrate local entry linearization, not physical effect cancellation or a durable continuous miner.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M03.RunWorkAttempt

Freeze all header bytes before work; evaluate full challenge transcript; retry a different nonce with a new computation; cap local reference attempts4096. Parent changes do not relabel an old transcript. Durable mining-attempt recovery is a native integration obligation, not implemented by the CLI.

**Atomic/commit boundary:** Reference mining is in-memory; no claim of durable miner. External publication uses exact idempotent BlockId.

### M03.EnterExternalEffect

If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash. BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Atomic/commit boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

## M03.RevokeEntryLinearization

**Invariant:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Scope:** Native bounded development mining plus the separate reference local-effect experiment. Its two SQLite connections demonstrate local entry linearization, not physical effect cancellation or a durable continuous miner.

**Atomic boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Failure schedule:** Revoke commits first; Revoker scheduled between checks and insertion; Crash after entry commit.

**Expected result:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Resource and retention rule:** Fixed operation and payload identity, bounded lock wait, explicit generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoke_committed_first_prevents_entry`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoker_cannot_commit_inside_entry_transaction`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_crash_after_entry_commit_rejects_replay`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Check/use races, ACK loss, owner takeover and coherent rollback of all evidence.

Normal Hepta final-use token, independent rollback frontier and target-side reconciliation remain unjoined.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M03` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

Node::make uses a bounded prepared-task producer and commits no chain state before validation. CLI output is create-new and synced before local publication. The [finite native miner](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md) provides cooperative stop and stale parent/generation rejection. Durable in-progress search recovery, wallet custody and provider/effect reconciliation remain unimplemented.

Preparation may share its first checked actual parent state with task eligibility
and execution within that operation, as specified by [M06](M06_EXECUTION_TECHNICAL_SPEC_V1.md).
That parent authority is dropped before unlocked proof search. Full native admission
after search still checks actual state, current parent/generation and the exact pool
batch; a task registered in the candidate cannot authorize that candidate's work.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Explicit continuity maintenance work

[Continuity v1](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md) adds a genesis-committed maintenance material and an explicit native mining choice. It grants zero useful-output credit, preserves full W1 verification and does not fabricate an external lease or override an owner withdrawal. The original profile remains unchanged.

## Actual producer alternatives and task reuse

The [W1 comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md)
adds separate complete tiled-classical and one-level Strassen producers, including
fixed-product setup, both noise products and every required transcript boundary.
They are diagnostic alternatives; Node's selected miner and proof relationship
remain unchanged. The repeated-search example executes cold-per-search and one
actually reused setup with identical challenge streams and complete proof/ticket
commitments. Exhaustion and unsupported cases remain observations. Its extra
stream-hashing cost is explicit, so measurements from older harness schemas are
not interchangeable. Fewer field multiplications do not establish a faster miner
or a lower bound on the cheapest valid work.

The separate strict-zero producer keeps only small prefix factors and one current
tile while emitting the same complete proof. Its dedicated locality cost schema
compares all three zero-capable implementations, including every failed target
attempt and actual setup. A signed native V4/continuity lifecycle regression checks
that real zero-material registration, proof verification, renewal, revocation,
expiry and parent changes still require their ordinary checks. This diagnostic
producer is not installed as the Node's default miner or a source of verified types.

## Complete one-zero rank-one transcript experiment

The separate `BlockedOneZeroRankOnePreparedTask` accepts exactly one zero operand
and one complete canonical nonzero rank-one operand. It derives and checks the
factors before retaining them, and emits all32,768 canonical transcript words in
the original order. `pon_one_zero_io` supports independent complete49188-byte
comparison; `pon_one_zero_locality_cost` owns a fresh raw-cost schema with both
orientations, cold/reused setup and complete winning/losing streams. See the
[W1 implementation comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md).
This diagnostic does not replace native mining selection or independently qualify
task cost, proof hardness, actual checkpoint utility or hardware efficiency.

## Fixed maintenance producer research

The separate `PairedPreparedTask` computes the same complete W1 relation using
canonical paired products and separately charged row/column factors. Its fixed
maintenance experiment compares generic, classical, Strassen and paired strategies
under cold/reused setup; complete-stream commitments, full winning proofs and every
search outcome, including exhaustion, are retained. Losing proof arrays are not
stored separately. [W1 comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md)
defines the algebra, actual genesis material, independent Python byte relation and
balanced sample order. The default producer/verifier and task qualification remain
unchanged; lower multiplication counts are not measured runtime or a work lower bound.

The separate `MaintenancePeriodicPreparedTask` accepts only both exact public
maintenance operands and computes their fixed product with integer row-prefix and
sawtooth suffix sums. Actual checks, plans, sums, product and proof-prefix construction
belong to its setup call. Every challenge delegates to the ordinary complete
`PreparedTask` transcript and its cancellation checkpoints. The retained object
contains exact material and product bytes, without parent, lease or admission
authority. Its source-defined equivalence and rejection checks do not establish
runtime savings, a cheapest-producer bound or a new mining selection.

The separate `MaintenanceIntegerPairedPreparedTask` and
`MaintenancePrefixPreparedTask` share that exact fixed-product constructor. The first
uses exact raw integer-pair dots; the second derives challenge-dependent periodic
prefixes while retaining every W1 transcript word, tile-order hashing and proof
byte. The prefix producer additionally constructs a64-column plan inside its
charged setup call. Complete setup and per-challenge search costs are reported
separately; shared fixed-product code does not imply identical setup costs.
The v3 maintenance cost suite keeps all
seven producers in fourteen balanced cold/reused positions and preserves v1/v2
observations under their original contracts. Neither new method has an established
general-multiplication-count advantage over the other; actual timings, including
slower and exhausted observations, must decide the measured comparison. No default
Node selector, work relation or acceptance flag changes.
