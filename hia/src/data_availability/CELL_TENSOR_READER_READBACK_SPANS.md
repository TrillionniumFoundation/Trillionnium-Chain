# Full-count immutable Safetensors readback

This independent value-only candidate retains the three-loan reader's exact
declared content comparison and original 114-byte output. It allows the
original 16,384 tensors and 1,024 metadata keys in a raw JSON header of up
to 1 MiB, under the same 2 MiB total private frame cap. Direct borrows
declarations plus LE64, the full raw header, and the full actual data section
as independent buffers no bigger than 1 MiB each. Selfhost borrows the same
frame contiguously with the existing private fixture bound. Older candidates
and all stock per-loan caps are unchanged.

The same native call validates the header and creates its own compact sorted
name index using the exact published comparison and merge helpers. Enclosed
raw name and value span positions fit in 21 bits; the private value-end
field is inclusive to represent a contiguous header whose exclusive
endpoint is 2 MiB. Each accepted span is replayed within its exact bounded
extent into one reused 120-byte typed row and compared with the genuine
declarations. Byte widths, ranks, ranges, and refusal order are checked
before native final digest equality. Neither a host-provided index nor a
prevalidated digest is accepted.

Numeric intervals are ordered with a power-of-two merge forest, not the
older 128-row insertion sort. Each pair stores start and end in 22 bits
each; classification is by complete per-row comparison, then interval
coverage, then actual SHA. The SHA consumes the original LE64, raw header,
and body exactly once in order. No full decoded projection is published.

Scratch remains 840,192 bytes. The live declared digest locator now uses
[159480,159488), before the two name comparison temporaries. Once metadata
validation has completed, interval sort reuses the expired table range
[160256,422400), separate from the retained packed name spans and order.
The live tensor row and original SHA state are separate in time wherever
their earlier grammar workspace is reused. No return bytes are written
until exact layout, actual SHA and output capacity all pass.

The frozen public Rust reader is exercised with synthetic in-memory
`Cursor` bytes. It is compared with both native paths at a full 2 MiB frame,
1 MiB header, 16,384 F32 tensors (including rank eight) and 1,024 metadata
keys. Tests inspect both stock scratch lifetimes, reversed numeric interval
placement, original too-many/roster/dtype/coverage precedence, independent
same-size edits to header and body, and atomic refusals. No live file
reader, clock, loader, storage, activation, trust or production claim.
