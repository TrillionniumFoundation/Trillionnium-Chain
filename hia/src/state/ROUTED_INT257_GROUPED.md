# Private Int257 grouped arithmetic diagnostics

The [grouped kernel](routed_int257_grouped.hepta) follows the public
[`PreparedModel::grouped`](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs)
arithmetic on the same private immutable frame as
[ordinary inference](ROUTED_INT257_ORDINARY.md). It validates the whole
model and batch first. Each input row is routed once using the shared
ordinary dot/argmax; expert memberships are the same stable, append-only
indices as [the direct product](ROUTED_INT257_DIRECT.md).

Each nonempty expert is evaluated in order. For width (b_e), gather
writes precisely (257 b_e) LE32 values, feature-major with local
columns in encounter order. For each class and feature it loads the
merged coefficient once and updates the expert's contiguous (b_e)
signed 64-bit accumulators. These three local result rows are scattered
to original input order before prediction with the same lowest-index
tie rule. No padded columns are evaluated. The grouped output is the
same deterministic Product representation as Direct. Rust `PhaseNs`
timing is not returned or compared.

The three disjoint loans of private `f0` are input, output, and scratch.
Scratch is exactly bounded by 67,536 bytes: offsets 0–194 track
stable groups, offset 200 starts the three local accumulators, and
offset 1,744 starts the packed features. The same region is reused across
experts. The caller reserves the fixed upper bound, but smaller widths
do not populate or evaluate any padded columns.
Output size remains `48+51N` with (1 le N le 64). All private and
original typed errors leave output and scratch untouched. Scratch
beyond the contract and spare output are left unchanged.

[The differential](../../tests/test_routed_int257_grouped.py) uses the
unchanged locked original public `grouped` implementation with synthetic
fixed unsigned preparation and compares deterministic Product bytes on
both stock emitters. It also checks the complete final scratch
against independent gather and scatter expectations, including unequal
expert widths, unused capacity canaries, and the full 64-row tile.
The public Ordinary and Direct source, ABI and machine artifacts remain
independent. No W1, proof, statement, authority or service timing is
observed.
