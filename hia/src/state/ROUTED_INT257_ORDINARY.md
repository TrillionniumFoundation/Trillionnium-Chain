# Private Int257 ordinary routed arithmetic

This bounded kernel implements the pure arithmetic of the public Rust
[`PreparedModel::ordinary`](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs).
Each row uses all 257 coordinates, including the fixed final bias of 8.
It computes the three signed router dot products, selects the first
maximum, and evaluates only the selected expert. Its three signed logits
are dot products with the corresponding exact `base + delta` coefficients.
Prediction uses the same lowest-index tie rule. It neither consumes prior
Cell memory nor performs stochastic sampling, training, or a tool action.

The ordinary arithmetic uses the same fixed shape in both stock HIA
emitters. The three disjoint loans of `f0(readbuf, mutbuf, mutbuf) -> u32`
are literal input data, result bytes, and unused scratch. The input is an
LE32 batch count, followed by the five model matrices in `base, router,
delta-0, delta-1, delta-2` order, then the input feature rows. Every matrix
has three rows of 257 signed LE32 values; every feature row contains 257
signed LE32 values. Batch size is 1 through 64, matrix values are in
[-32767,32767], features are in [-8,8], and the last feature is 8. These
bounds keep absolute selected logits at most 134,737,904; there is no
wrapping behavior in the admitted integer domain. The accepted sizes are
16,452 through 81,216 input bytes.

Output rows are 26 bytes: three signed LE64 logits, one route byte, and
one prediction byte. Statuses 3, 4, and 5 correspond to the original
coefficient, batch-size, and input range/bias errors, in that order for
typed data. Statuses 100 and 102 are private framing and output-capacity
errors. The kernel checks the complete batch before producing any row,
and preserves the input, scratch, and unused result capacity.

The [comparison](../../tests/test_routed_int257_ordinary.py) builds the
unchanged locked original Rust library and runs its literal public
`PreparedModel::new`, `prepare_batch`, and `ordinary` APIs. Original
preparation receives fixed synthetic unsigned request identifiers and
a caller-supplied fixed time solely to expose the original arithmetic.
The kernel port has no request IDs, clocks, model commitments, prepared
batch interchange, proof, W1, signed input, acceptance, or authority.
This is not a migration of the complete Cell execution or model loop.
