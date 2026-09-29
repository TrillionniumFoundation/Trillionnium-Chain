# M14 Client currentness, model loading and user results

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Closed receipt before quota-use signing, distinct from a local capability.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M14.QueryCurrentState

Read active pointer and generation kv in one snapshot and recompute root; return no unconditional finalized flag. A production confirmation adds depth/work evidence and freshness; localhost ACK is not independent proof.

**Atomic/commit boundary:** Indexer is derived; cursor(generation,ordinal), no new balanceauthority.

### M14.ConsumePublishedModel

Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service. Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

**Atomic/commit boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

## M14.ServiceReceiptBinding

**Invariant:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Scope:** Closed receipt before quota-use signing, distinct from a local capability.

**Atomic boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context.

**Failure schedule:** Replace every receipt field; Missing expected identities; Extra authority field; Noncanonical bytes.

**Expected result:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Resource and retention rule:** Fixed digest identities, positive bounded counters and no hidden reduced deployment profile.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_every_service_identity_is_bound`

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_duplicate_or_implicit_receipt_fields_reject`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Stale confirmation, input/model substitution, cross-genesis signatures and unsafe remote-result authority.

Public client confirmation verification and normal Hepta final-use integration remain unimplemented.

## Current source and verification

- [`formal/pon-nakamoto-v1/inference_receipt.py`](../../formal/pon-nakamoto-v1/inference_receipt.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

The [current measured package](../../evidence/pon-v3/README.md) includes exact source,
raw command exits and concrete invariant test results. Its verifier distinguishes
runtime byte identity from documentation edits and cannot grant independent acceptance.
Module-specific limitations above remain in force even when the referenced local test
passes. The development plan, not this link or a count of procedures, selects next work.
