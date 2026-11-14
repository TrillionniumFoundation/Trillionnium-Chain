# Independent wire-shape count review

Reviewed root's `w1-bounded-proposal/src/proof_wire.rs` read-only against exact P3 0.8.0 proof structs, uni-STARK batch construction, FRI group construction and Goldilocks binary serde. No source changes were made by this reviewer.

## Result

The reviewed formulas and three-input-batch order match this frozen non-ZK, binary-FRI profile. The exact independently recomputed counts are:

| Count | SHA | Arithmetic |
|---|---:|---:|
| Trace degree bits / FRI rounds | 13 | 17 |
| Fixed base-field elements excluding Merkle frontiers | 529292 | 37650 |
| Fixed vector headers | 1338 | 1540 |
| Fixed bytes, with empty frontiers | 4245061 | 313541 |
| Input frontier maximum digests | 2880 | 3648 |
| FRI frontier maximum digests | 6656 | 10880 |
| Total frontier maximum digests | 9536 | 14528 |
| Maximum bytes | **4550213** | **778437** |

The fixed overhead is 21 bytes: eight-byte magic, five one-byte option tags, and eight-byte degree. Each canonical Goldilocks element is eight bytes, each vector length is an eight-byte fixed integer, and each digest is four field elements (32 bytes).

The input order follows uni-STARK's `round0.into_iter().chain([round1,round2]).chain(round3)`. With ZK disabled, `round0` is absent and the order is trace, quotient, preprocessing. Widths are respectively 7728, two width-two quotient matrices, 27 for SHA; 516, one width-two quotient matrix, 18 for arithmetic. All are at LDE height 2^(degree_bits+2).

Before a binary FRI fold, `RowMajorMatrix::new(folded, arity)` groups adjacent extension elements into width-two rows. Therefore its committed tree has log height `degree_bits + 2 - round - 1`. SHA heights are 14 through 2; arithmetic heights are 18 through 2. A pruned multiproof frontier is a subset of the union of the requested complete paths. With 64 requested indices, each frontier consequently contains at most 64 times that log height digest siblings, even with repeated indices. The total FRI bounds are 64 times the sums of those heights.

Five option tags agree with the actual serialized `OpenedValuesRepr`, which flattens preprocessing into separate local and next options. `ExtensionMmcs` flattens each quadratic extension element into two base elements; it adds no vector prefix for the fixed two-element coefficient array. The Goldilocks serializer emits canonical eight-byte little-endian representatives and its deserializer rejects integers at least p, matching the scanner's field check.

This review establishes neither exact frontier lengths nor proof validity. Empty or otherwise transcript-inconsistent frontiers can pass the admission syntax and must still be rejected by P3. The formula is a deliberately loose admission ceiling, not an attained maximum honest proof size, a global malicious cost theorem, or a total process-memory bound. Parameter changes require recomputing this frozen shape.

The review did not execute root's Rust guard; root's retained-proof positive run is separate evidence. No discrepancy was found in the requested numerical limits, FRI-height expression or batch order.
