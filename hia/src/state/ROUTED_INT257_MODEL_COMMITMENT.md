# Private Int257 model commitment

This fixed-extent kernel mirrors the unchanged public Rust
[`PreparedModel::new(...).commitment()`](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs)
for literal Int257 matrices. It has no model JSON, batch, time, prepared
batch identity or authority. It does not expose original private cached
merged coefficients or modify any inference kernel.

The three disjoint loans of `f0` are input, output, and scratch. The input
must be exactly 15,452 bytes: opaque model version (32 bytes), then five
row-major matrices in `base, router, delta-0, delta-1, delta-2` order.
Each matrix contains three 257-coordinate rows of signed LE32. The valid
range of every coefficient is [-32767,32767]. It checks every coefficient
before constructing any bytes or accepting capacity. The 32-byte output
is the original SHA-256 digest. Scratch requires 32,272 bytes, including
the native SHA engine and exact canonical transcript.

The transcript begins with ASCII `trnm.domain.hash.v1`, followed by each
part prefixed by its own BE64 byte length, in this order:

1. `pon-routed-int257-grouped-model-v0` (34 bytes);
2. `pon-routed-int257-grouped-research-v0` (37 bytes);
3. `signed-i32-coeff-i64-accum-bias8-lowest-argmax` (46 bytes);
4. the complete 30,896-byte prescribed model body: verbatim version,
   BE64 dimensions 257, 3, 3, then each signed coefficient widened to
   I64 and encoded BE in its original position.

Private framing (100) and capacity (102), and the original coefficient
refusal (3), leave both result and scratch unchanged. Internal SHA
failure (103) cannot publish output. Input, result tail, and scratch
above the declared extent remain untouched on success as well.

[The differential](../../tests/test_routed_int257_model_commitment.py)
builds the real locked original crate and calls only the original setup
constructor and result accessor. Both stock emitters are checked for
digest equality, the whole transcript, matrix positions, signed bounds,
version sensitivity, exact capacities, and the original frozen golden
case. This does not exercise trust, signing, proof or W1.
