# M00 Protocol bytes and state commitments

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native and Python wire codecs, not application acceptance.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M00.DecodeHeader

Require PNH1/version1 and exactly318 bytes; decode the twelve fixed fields at the published offsets; compute challenge only from those bytes; no field normalization.

**Atomic/commit boundary:** None; codec has no database.

### M00.DecodeTransaction

Read 95-byte prefix, match exact tag-specific payload length and bounded proof/list count, require nonce>0 and fee cap, then separate final64 signature bytes. Signature verification belongs to admission.

**Atomic/commit boundary:** None; decode success cannot reserve nonce or funds.

## M00.CanonicalBytes

**Invariant:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority.

**Scope:** Native and Python wire codecs, not application acceptance.

**Atomic boundary:** Decode is pure and bounded; signature verification and state publication are later independent boundaries.

**Failure schedule:** Every header field mutation; Truncation, trailing bytes, zero nonce, unknown tag.

**Expected result:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority.

**Resource and retention rule:** 318-byte header, 2048-byte envelope, closed twelve tags.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_contracts.py::CodecTests.test_header_mutations_bind_all_fields`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_rejection_vectors`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Encoding ambiguity, cross-genesis replay and unsafe unversioned upgrades.

Third-party verifier and production upgrade policy remain unaccepted.

## Current source and verification

- [`trillionnium/crates/trnm-protocol/src/pon_wire.rs`](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs).
- [`formal/pon-nakamoto-v1/contract_wire.py`](../../formal/pon-nakamoto-v1/contract_wire.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
