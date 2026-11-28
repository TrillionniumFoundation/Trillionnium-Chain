# Immutable CRC1 codeword value

This private standalone composition implements unchanged public Rust
`CellManifestV1::decode`,
`CellRs46ChunkBindingV1::from_pinned_manifest`, and
`CellRs46CodewordV1::{decode_pinned,encode,id}` on immutable declarations.
It is separate from CRS1 shard shape, erasure coding, repair, placement,
custody, actual shard reads, storage or authority.

One bounded read-only loan contains `RCB1`, a big-endian u32 selected
chunk index, the independently supplied expected TCM1 ID (32 bytes) and
expected CRC1 ID (32 bytes), a u8 family length followed by the family
and five 32-byte context fields in TCM1 order, a big-endian u32 TCM1
extent, its exact canonical bytes, and the remaining CRC1 wire. The
combined extent is at most 1 MiB. Output and scratch are disjoint:
1,240 scratch bytes and at least 300 output bytes are required. On
acceptance the first 300 bytes are computed CRC1 ID and the exact
canonical 268-byte value. Only scratch may change on refusal.

The original order is canonical TCM1 syntax, expected original context,
native recomputed manifest ID, and a valid selected original chunk row;
then exact CRC1 length, tag, native recomputed CRC1 ID matched against
the independent expected ID, original manifest/index/source size/source
SHA-256 equality, and six nonzero distinct opaque shard IDs in their
exact original slots. The complete TCM1 contents are rechecked. The
chunk length and digest are compared directly against the same immutable
TCM1 bytes; a caller-provided row or hash cannot replace them. The
original CRC1 ID is SHA-256 of its 27-byte domain
`trnm.cell-rs46-codeword.v1\0` followed by its complete canonical wire.
Canonical wire contains no optional or alternate tag/field encoding.

Both real pinned stock emitters are compared against the unchanged
public methods from the locked original Cargo crate. Owned deterministic
fixtures include all 16,384 declared rows, maximal and partial final
chunk size, independent pin and first-rejection ordering, and
six-slot uniqueness. Matched declarations and digest never establish
that any shard exists, that a provider is trusted, or that data is
recoverable.

```sh
python3 -B -m unittest -v hia.tests.test_da_rs46_codeword_value
```
