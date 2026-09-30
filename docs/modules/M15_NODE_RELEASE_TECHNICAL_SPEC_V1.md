# M15 Single host composition and bounded lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native development CLI/loopback composition and a separate reference ledger with explicit native compute bridge. The bridge-specific invariant below is not a claim of a complete native public host.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M15.StartExecutableSpecPeer

Acquire exclusive store owner, verify parameters, recover unfinishedintent, then bind127.0.0.1 and announcegenesis. No network admission before recovery. This is not the native production node assembly.

**Atomic/commit boundary:** Own one ledger writer perprocess; private directory; current schemaonly.

### M15.StopAndReconcile

Stop admission, requestchild stop, wait bounded5seconds, kill+reap ifunresponsive; retain DB intent and local effect identity. No global service or external credentials are touched.

**Atomic/commit boundary:** Child owner acquired immediately; finally paths clean startedchildren.

## M15.ExplicitBackend

**Invariant:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Scope:** Native development CLI/loopback composition and a separate reference ledger with explicit native compute bridge. The bridge-specific invariant below is not a claim of a complete native public host.

**Atomic boundary:** Backend choice before execution; bounded subprocess response; independently recompute returned root.

**Failure schedule:** Missing or inaccessible binary; Failed native transaction; Restart with persisted higher-work tip; Stderr fills before stdin is consumed; Stdout exceeds32MiB configured boundary; Child times out while holding pipes.

**Expected result:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Resource and retention rule:** 16MiB bridge input,32MiB stdout,64KiB stderr,30-second deadline; both pipes drained while writing; only the owned child session is terminated.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_missing_native_binary_is_not_reference_fallback`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_admitted_before_activation_is_selected_on_restart`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_wrong_native_context_rejects_even_an_empty_block`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_concurrent_pipe_drain_before_large_input`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_stdout_flood_is_killed_and_reaped`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_timeout_reaps_own_child`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Fallback masking missing modules, startup before recovery, task starvation and authority conflation.

Same-operator SSH test peers are not native host integration. Ordinary Hepta entry, persistent miner and signed production owner resources are not claimed.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/main.rs`](../../trillionnium/crates/trnm-pon-node/src/main.rs).
- [`trillionnium/crates/trnm-pon-node/src/ingress.rs`](../../trillionnium/crates/trnm-pon-node/src/ingress.rs).
- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`formal/pon-nakamoto-v1/bounded_process.py`](../../formal/pon-nakamoto-v1/bounded_process.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M15` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_multiple_selected_backends_reject_before_starting_cache`.
- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_changed_selected_binary_cannot_reuse_previous_success`.

## Native development continuation and remaining scope

The new M15 composition binary trnm-pon-node starts/recover/admit/mine/export/sync/confirm/serve without Python fallback. It reuses M00/M01/M06 and owns one fresh native branch namespace. Public P2P, persistent miner/mempool lifecycle and ordinary Hepta/resource integration are still absent.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Explicit evaluation-profile selection

The ordinary `trnm-pon-node` development CLI accepts `--evaluation-policy closed-round-all-eligible-min-v1` on a fresh namespace. Omission keeps revision3;
unknown values reject. The network, parameters, plan and genesis are bound before store
open. A node never opens an old namespace under successor semantics, and cross-network
packets reject. The actual CLI regression also mines a heavier fork, reopens storage and
replays the original signed candidate under the surviving state.

Selector: `formal/pon-nakamoto-v1/test_evaluation_round.py::ClosedRoundTests.test_ordinary_native_cli_uses_successor_and_reopens_only_its_namespace`.
This is a bounded native development path, not authenticated public P2P, ordinary Hepta
resource ownership or production activation.
