# M15 Single host composition and bounded lifecycle

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Existing ledger with explicit native application bridge; not a complete native public host.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M15.StartExecutableSpecPeer

Acquire exclusive store owner, verify parameters, recover unfinishedintent, then bind127.0.0.1 and announcegenesis. No network admission before recovery. This is not the native production node assembly.

**Atomic/commit boundary:** Own one ledger writer perprocess; private directory; current schemaonly.

### M15.StopAndReconcile

Stop admission, requestchild stop, wait bounded5seconds, kill+reap ifunresponsive; retain DB intent and local effect identity. No global service or external credentials are touched.

**Atomic/commit boundary:** Child owner acquired immediately; finally paths clean startedchildren.

## M15.ExplicitBackend

**Invariant:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Backend choice before execution; bounded subprocess response; independently recompute returned root.

**Failure schedule:** Missing or inaccessible binary; Failed native transaction; Restart with persisted higher-work tip.

**Expected result:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Resource and retention rule:** 16MiB bridge input,30-second execution limit, fixed worker choices.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_missing_native_binary_is_not_reference_fallback`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_admitted_before_activation_is_selected_on_restart`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Fallback masking missing modules, startup before recovery, task starvation and authority conflation.

Normal Hepta entry, native persistence/consensus assembly, ongoing miner and multi-host deployment remain distinct work.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.

Context regression: `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_wrong_native_context_rejects_even_an_empty_block`. Both request and response bind installed Network and Parameters, including empty blocks.
