# M01 Strict identity and exact neural-work verification

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Actual strict native signatures and unchanged experimental transcript verification.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M01.VerifyWork

Check length/magic/field bounds; recompute TaskId; apply cheap ticket filter; replay challenge-noised tiled transcript and exact decoded product; return no verified type on any mismatch.

**Atomic/commit boundary:** No authoritative store; cache key must include complete context.

### M01.VerifyTransactionSignature

Strict Ed25519 over H(tx-sign,unsigned). Reject weak/malformed keys or mismatching signatures before copying mutations into a committed state. Signed scores remain attestations, not work.

**Atomic/commit boundary:** No key material copied from fixtures into deployment.

## M01.VerificationAuthority

**Invariant:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work. Both verification languages reject small-order public keys/R, noncanonical points and scalars outside the group-order bound.

**Scope:** Actual strict native signatures and unchanged experimental transcript verification.

**Atomic boundary:** Signature verification precedes speculative patches; only full transcript verification creates work authority.

**Failure schedule:** Bad signature at every worker count; Changed transcript, product and challenge; Small-order sender with R identity and zero scalar; Noncanonical point or S plus group order; Weak quota consumer identity.

**Expected result:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work. Both verification languages reject small-order public keys/R, noncanonical points and scalars outside the group-order bound.

**Resource and retention rule:** 49188-byte work certificate; failed proof still requires substantial computation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_bad_signature_rejects_entire_block_without_parent_mutation`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_native_rejects_changed_context_and_output`

`formal/pon-nakamoto-v1/test_work_backend.py::NativeWorkBridgeTests.test_proof_bytes_and_verified_product_equal_oracle`

`formal/pon-nakamoto-v1/test_work_backend.py::NativeWorkBridgeTests.test_wrong_statement_and_bad_trace_reject_without_fallback`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_native_and_reference_reject_weak_sender_without_state_change`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_weak_consumer_cannot_authorize_quota`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_rfc8032_known_vector`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_all_declared_order_eight_points_reject`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Cheap forgery amplification, structured-input shortcuts, hardware advantage and weak-key disagreement.

The native work bridge and structured-input costs are executable; fastest-adversary cost, public proof admission and independent work security are still unqualified.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
- [`trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).
- [`formal/pon-nakamoto-v1/work_backend.py`](../../formal/pon-nakamoto-v1/work_backend.py).
- [`trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs`](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs).
- [`formal/pon-nakamoto-v1/strict_signature.py`](../../formal/pon-nakamoto-v1/strict_signature.py).
- [`trillionnium/crates/trnm-crypto-primitives/src/lib.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/lib.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

The [current measured package](../../evidence/pon-v3/README.md) includes exact source,
raw command exits and concrete invariant test results. Its verifier distinguishes
runtime byte identity from documentation edits and cannot grant independent acceptance.
Module-specific limitations above remain in force even when the referenced local test
passes. The development plan, not this link or a count of procedures, selects next work.
