# M00 Protocol bytes and state commitments

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native and Python wire codecs, not application acceptance.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M00.DecodeHeader

Require PNH1/version1 and exactly318 bytes; decode the twelve fixed fields at the published offsets; compute challenge only from those bytes; no field normalization.

**Atomic/commit boundary:** None; codec has no database.

### M00.DecodeTransaction

Read 95-byte prefix, match exact tag-specific payload length and bounded proof/list count, require nonce>0 and fee cap, then separate final64 signature bytes. Signature verification belongs to admission.

**Atomic/commit boundary:** None; decode success cannot reserve nonce or funds.

## M00.CanonicalBytes

**Invariant:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Decode is pure and bounded; signature verification and state publication are later independent boundaries.

**Failure schedule:** Every header field mutation; Truncation, trailing bytes, zero nonce, unknown tag.

**Expected result:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority.

**Resource and retention rule:** 318-byte header, 2048-byte envelope, closed twelve tags.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_contracts.py::CodecTests.test_header_mutations_bind_all_fields`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_rejection_vectors`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Encoding ambiguity, cross-genesis replay and unsafe unversioned upgrades.

Third-party verifier and production upgrade policy remain unaccepted.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`trillionnium/crates/trnm-protocol/src/pon_wire.rs`](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs).
- [`formal/pon-nakamoto-v1/contract_wire.py`](../../formal/pon-nakamoto-v1/contract_wire.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
