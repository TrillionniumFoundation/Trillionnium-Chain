# M14 Client currentness, model loading and user results

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Closed receipt before quota-use signing, distinct from a local capability.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M14.QueryCurrentState

Read active pointer and generation kv in one snapshot and recompute root; return no unconditional finalized flag. A production confirmation adds depth/work evidence and freshness; localhost ACK is not independent proof.

**Atomic/commit boundary:** Indexer is derived; cursor(generation,ordinal), no new balanceauthority.

### M14.ConsumePublishedModel

Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service. Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

**Atomic/commit boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

## M14.ServiceReceiptBinding

**Invariant:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

**Failure schedule:** Replace every receipt field; Missing expected identities; Extra authority field; Noncanonical bytes.

**Expected result:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Resource and retention rule:** Fixed digest identities, positive bounded counters and no hidden reduced deployment profile.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_every_service_identity_is_bound`

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_duplicate_or_implicit_receipt_fields_reject`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Stale confirmation, input/model substitution, cross-genesis signatures and unsafe remote-result authority.

Public client confirmation verification and normal Hepta final-use integration remain unimplemented.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/inference_receipt.py`](../../formal/pon-nakamoto-v1/inference_receipt.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
