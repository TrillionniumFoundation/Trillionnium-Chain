# Standalone Safetensors JSON tensor span index

This candidate validates the original standalone `TensorHeader` semantics
for a raw header up to 1 MiB, with at most 16,384 tensors and 1,024 metadata
keys. The old full-value JSON projection and immutable Safetensors readers
are unchanged. This entry neither returns the full decoded projection nor
changes the stock ABI to accommodate projections above 1 MiB.

The output is a little-endian u64 count followed by one little-endian u64
per tensor, in strict decoded UTF-8 name order. Each record has three unsigned
21-bit absolute offsets into the exact original read-only input: the opening
quote of the name, the opening brace of its value and the exclusive end of
that value. Bit 63 is zero. The output is at most 131,080 bytes. A consumer
must retain the same immutable header; the output is a compact index, not a
digest or authority. Nothing is published until complete validation and
output capacity succeed.

The same frozen metadata kernel validates the original key/value limits.
The tensor visitor checks each name and exact decoded duplicate relation before
the member value; the frozen member grammar validates dtype strings, unsigned
64-bit dimensions and two offsets, field identity and rank. Original UTF-8
ordering is applied without normalization or hashing. A tensor slot is added
only after the member's complete validation. Later comparisons decode at most
255 bytes of an already validated raw name; no host-supplied index, string or
verdict is accepted. A power-of-two sorted-run forest uses binary search for
duplicate detection and bounded run merges, not all-pairs scans.

Caller scratch is 840,192 bytes: the first 446,976 bytes support the previous
grammar and 1,024-key metadata table, then three disjoint 131,072-byte areas
hold the packed span records, sorted indices and merge indices. The fixed
tensor-value temporary is reused during parsing; the already checked raw
spans are the sole retained per-tensor value reference. All buffers retain
their existing stock per-loan size bound.

Both stock native outputs are decoded only by the test against the *same*
immutable original raw header; the reconstructed ordered canonical records
are compared byte-for-byte with genuine original locked Rust. The exact
1 MiB case has 16,384 rank-five F32 entries and all 1,024 metadata keys; its
original expanded projection exceeds a single 1 MiB mutable loan. Tests also
cover 16,385 tensors, escaped duplicates, dtype Unicode escapes, u64 bounds,
non-power-of-two rosters and refusal atomicity. No payload/layout reader,
storage, deployment, model activation or production integration is claimed.
