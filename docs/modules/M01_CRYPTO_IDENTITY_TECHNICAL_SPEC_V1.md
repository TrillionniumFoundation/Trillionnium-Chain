# M01 Strict identity and exact neural-work verification

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Actual strict native signatures and unchanged experimental transcript verification.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M01.VerifyWork

Check length/magic/field bounds; recompute TaskId; apply cheap ticket filter; replay challenge-noised tiled transcript and exact decoded product; return no verified type on any mismatch.

**Atomic/commit boundary:** No authoritative store; cache key must include complete context.

### M01.VerifyTransactionSignature

Strict Ed25519 over H(tx-sign,unsigned). Reject weak/malformed keys or mismatching signatures before copying mutations into a committed state. Signed scores remain attestations, not work.

**Atomic/commit boundary:** No key material copied from fixtures into deployment.

## M01.VerificationAuthority

**Invariant:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Signature verification precedes speculative patches; only full transcript verification creates work authority.

**Failure schedule:** Bad signature at every worker count; Changed transcript, product and challenge.

**Expected result:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work.

**Resource and retention rule:** 49188-byte work certificate; failed proof still requires substantial computation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_bad_signature_rejects_entire_block_without_parent_mutation`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_native_rejects_changed_context_and_output`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Cheap forgery amplification, structured-input shortcuts, hardware advantage and weak-key disagreement.

Cost hardness and public Sybil-safe proof admission are not established by queue limits.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
- [`trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
