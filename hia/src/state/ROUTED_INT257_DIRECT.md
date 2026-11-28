# Private Int257 direct arithmetic diagnostics

The [direct kernel](routed_int257_direct.hepta) mirrors the public
[`PreparedModel::direct`](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs)
arithmetic and diagnostic `Product`, without an observation or statement.
It reads the exact same input layout and numerical domain as
[ordinary arithmetic](ROUTED_INT257_ORDINARY.md). The immutable literal
data has no prepared-batch identity, proof, time, commitment or authority.

The native kernel uses the published ordinary matrix/feature checks and
dot/argmax helpers. Its single-row continuation is mechanically derived
from the exact ordinary arithmetic: it also stores the original three
router scores and forwards the chosen expert index to the private group
builder. The ordinary source and ABI remain unchanged. Both router and
prediction ties prefer the lowest original index. Groups append per-row
indices in input encounter order, so indices are strictly increasing
within each group; empty groups keep zero count.

The result begins with six LE64 numbers: original useful dense MAC
positions (`1542 * N`), original padded MAC positions (zero), count of
nonempty expert groups, then the three expert group lengths in expert
order. These are arithmetic metadata, not benchmarked cost, qualified
work or a proof. Then come (N) 50-byte rows in input order. Each is the
ordinary 26-byte record followed by three signed LE64 router scores.
Finally come (N) one-byte original row indices packed by expert 0, 1, 2
in stable order. The caller sees exactly `48 + 51*N` result bytes (99
through 3,312); scratch requires 195 bytes. A private shape or capacity
failure (100 or 102) and original errors (3, 4 or 5) never mutate input,
result, or scratch. Output tail and scratch beyond 195 are untouched.

The [differential](../../tests/test_routed_int257_direct.py) builds the
unchanged locked original Rust crate, calls only public model construction,
batch preparation with synthetic fixed IDs/time, then `direct`. It
compares exact result bytes on both stock emitters and checks skipped
expert groups, encounter order, counts, signed bounds and late-input
refusal. This is independent of W1, proofs, observation, verification,
training, deployed inference, and any production authority.
