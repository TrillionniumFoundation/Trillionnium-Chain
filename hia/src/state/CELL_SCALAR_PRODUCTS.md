# Held Cell scalar products

`cell_scalar_products.hepta::f0` reads a typed, immutable model-weight and
prepared-feature frame and returns all 15 original signed scalar products
for every row. It reuses the unchanged stock ordinary Int257 coefficient,
feature, signed LE32 and dot helpers, with the dot's merged flag **false**.
There is no router, argmax, merged-logit, action, memory, training, state,
W1 proof, approval, clock, loader, or identity input. A numerical product is
not a proof or independent prepared-feature provenance.

The input uses the [ordinary typed arithmetic encoding](ROUTED_INT257_ORDINARY.md):
a little-endian u32 row count followed by 15×257 little-endian signed i32
weights and exactly that many rows of 257 signed i32 features. Weight lanes
are the three base classes, three router scores, then three ordered
three-class delta groups, expert first. The count must be 1–64. Weight
coordinates must be in ±32,767. Features are in ±8, with coordinate 256
exactly +8 and absolute sum of the first 256 at most 1,024. That last fence
follows from the original 1,024-token preparation; clipping and masking
cannot increase the absolute sum. This restricts the held numeric domain,
but does not verify actual input sourcing or a feature mask. The integer
widening to the Cell owner's i64 operands is exact.

The output is exactly 120 bytes per row: 15 little-endian signed i64 values
in the order above. This is the stated row-major transpose of the original
`products[lane][row]`, suitable as the held product section of an offline
[CTRW](CELL_HELD_ROWS.md) fixture; it is not a full CTRW frame and does not
advance or infer that fixture's route, masks, memory, inputs or actions.
The maximum frame is 81,216 input bytes and 7,680 output bytes. The largest
possible signed magnitude on the tuned input domain is
`32767 * (1024 + 8) = 33815544`; the unchanged native signed accumulation
also fits the original looser full-coordinate bound.

Status 100 is malformed physical extent, 3 is bad coefficient, 4 is
unsupported row count, 5 is feature coordinate/bias/absolute-sum refusal,
and 102 is short output after the whole input has validated. All failures
leave output untouched. Input, output beyond the result, and scratch are
unchanged; no scratch or allocation is used.

Qualification executes exact source-extracted original Cell `weights` and
scalar expression, and the exact original routed `dot` on the same held
values, compiled with the repository-pinned Rust compiler. The isolated
source includes no W1 owner, proof code, or proof-bearing crate. It compares
both stocks across all lanes and all admitted rows, including the final
bias coordinate, signed extremes and the full row cap.
