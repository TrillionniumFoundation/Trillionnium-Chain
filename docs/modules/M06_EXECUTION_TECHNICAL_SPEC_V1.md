# M06 Deterministic application execution and reversible deltas

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native implementation inside existing trnm-mvcc-fee and separately coded Python reference.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M06.ExecuteCandidate

Run deterministic due expiry and maturity before txs; execute exactly12 closed commands; transfer exact fees, stage subsidy; verify global conservation and size bounds. Remote calls, floats and evaluator programs never run inside state transition.

**Atomic/commit boundary:** Return complete state/delta intent; caller M07 owns persistence.

### M06.DeriveBranchDelta

For sorted union of keys compare canonical values; emit only changed entries, encode absence as NULL and empty value as real bytes. Detach verifies after then restores before; attach checks before then writes after.

**Atomic/commit boundary:** Same atomic commit as admitted block row.

## M06.TwelveCommandEquivalence

**Invariant:** All twelve commands produce identical state, receipts, fees and root at one, two, four and eight workers.

**Scope:** Native implementation inside existing trnm-mvcc-fee and separately coded Python reference.

**Atomic boundary:** Mandatory transitions first, parallel local proposals, canonical read-set validation, one re-execution on conflict, then final conservation and subsidy.

**Failure schedule:** Tasks, cancel, receipt and accept; Contribute, evaluate, publish and claim; Quota reserve/use and work registration; Missing native backend.

**Expected result:** All twelve commands produce identical state, receipts, fees and root at one, two, four and eight workers.

**Resource and retention rule:** 256 transactions; tracked prefix reads detect phantoms; explicit native bridge is bounded to16MiB and30 seconds.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_all_twelve_tags_match_for_1_2_4_8_workers`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_missing_native_binary_is_not_reference_fallback`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Incorrect conflict sets, receipt order changes, unbounded retries and successful fallback masking missing implementation.

A native application engine is not a complete native consensus/persistence/Hepta host.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

The [current measured package](../../evidence/pon-v3/README.md) includes exact source,
raw command exits and concrete invariant test results. Its verifier distinguishes
runtime byte identity from documentation edits and cannot grant independent acceptance.
Module-specific limitations above remain in force even when the referenced local test
passes. The development plan, not this link or a count of procedures, selects next work.

## Block-scoped execution continuation

The existing native executor now bounds thread creation per block and preserves a private
verified main envelope across canonical state replay. This is a computational fact, not
work validity or local permission. Capacity/range state transitions remain ordered and
consumer signatures still bind actual quota state. See the exact algorithm, errors and
counterexamples in [EXECUTION_PARALLEL](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md).
Complete-state root construction, full native node assembly and Hepta ownership remain
separate work; worker counts do not establish throughput or independent acceptance.

Exact continuation selectors (each must appear as actually executed in a current receipt):

- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_block_scoped_workers_and_no_duplicate_main_signature_on_conflict`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_funding_dependency_replays_state_not_main_signature`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_capacity_prefix_commands_do_not_speculate_unbounded_snapshots`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_later_invalid_signature_does_not_change_canonical_error`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_single_signature_context_cannot_be_reused_for_another_payload`
