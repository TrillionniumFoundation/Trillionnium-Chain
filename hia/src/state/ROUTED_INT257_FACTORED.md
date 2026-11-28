# Private Int257 factored arithmetic

This bounded offline kernel borrows one immutable frame. It validates the
actual model coefficients and all three B×A-to-delta relations on that same
frame before evaluating any request. No prepared token, clock, auth,
routing service, proof, statement or data outside this frame is used.
The fixed-width typed model and expert prefix is identical to
[Factor preparation](ROUTED_INT257_FACTOR_PREPARATION.md), then comes a LE32
row count and that many 257-coordinate LE32 rows. Exact shape precedes model
and factor refusals; batch size and feature/bias checks follow them as in the
test's original constructor sequence. IDs/times are fixed harmless fixture
details in the original caller only, not part of this mathematical format.

The staged row kernel computes the literal router dot products, selects
the lowest-index maximum, forms A×x only for the selected expert, and
adds B×(A×x) to the original base dot product. It does not read a dense
merged panel as a substitute. The validated rank, coefficient and feature
bounds give an absolute hidden-state bound of at most
`257 × 32767 × 8` and bound every factor-product partial sum by
`8 × 32767 × 257 × 32767 × 8`, safely inside i64. Matching B×A equality
proves the final logits are within ±134,737,904; a defensive bound still
precedes result publication. Lowest-index maximum is also used for logits.

For `n` rows, require `88 + 51n` output bytes and `264 + 50n` scratch
bytes (106,256/3352/3464 bytes max input/output/work). Scratch begins with
group counts and ordered group indexes, then a 64-byte hidden panel at 200
and rows at 264. Result is six LE64 Product fields (useful count, zero
padded count, nonempty count, three group sizes), then per row three
router LE64 i64s, three logit LE64 i64s, route and prediction U8, then
all U8 original row indices grouped in expert order. The final five LE64
fields are the unchanged diagnostic router, base, adapter, output-addition
and execution counts. They are not actual runtime cost or authorization.
Frame, validation and capacity refusals preserve all loans; a defensive
range refusal (12) cannot expose a partial result. Successful outputs
preserve the tail. Factor statuses 3/8/9/10/11 follow the existing
preparation; 4=batch size, 7=feature or bias, 100/102=private framing/capacity.

Both stock emitters are tested against unchanged offline public
`new → prepare_factors → prepare_batch → factored` with the frozen locked
crate. No observation/proof, model identity, production route, or execution
certificate is exposed.
