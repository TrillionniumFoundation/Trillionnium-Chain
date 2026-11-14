# M15 Single host composition and bounded lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Existing ledger with explicit native application bridge; not a complete native public host.

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

**Scope:** Existing ledger with explicit native application bridge; not a complete native public host.

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

- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`formal/pon-nakamoto-v1/bounded_process.py`](../../formal/pon-nakamoto-v1/bounded_process.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
