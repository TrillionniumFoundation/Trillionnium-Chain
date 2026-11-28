# Immutable Safetensors range values

This independent entry adds the original private `verify_reader_layout`
value for the selected declaration's file to the existing 4 MiB immutable
reader. The previous 114-byte readback stays unchanged in existing entries.
This private output is that exact 114-byte value followed by all validated
pairs in canonical declaration tensor-name order, not physical interval order.
Each pair contains little-endian u64 absolute **container** offset
(`8 + header_bytes + start`) and little-endian u64 byte length. Maximal
output is 262,258 bytes for 16,384 tensors. No data bytes, owner, view,
handle, pin, or storage capability are returned.

Both stock emitters retain the published 4 MiB logical, 1 MiB Direct
per-loan and raw header, 1,024-key metadata, and 3 MiB body limits. The
same immutable operands are fully checked and native SHA-256 is compared
before any output, including with a too-small output buffer. The output
capacity check reserves every pair before publishing the prefix. No
caller-selected range, alternate parse, rejected layout, or already
verified marker can reach publication.

Scratch remains 840,192 bytes. Canonical packed pairs reuse the expired name
merge table [709120,840192) after the original name index is fully merged;
the independent physical-coverage table is still ordered in existing
workspace. The raw header's validated data base lives in the eight bytes
preceding the original selected digest locator, outside both name
temporaries. Both logical orders remain separate at full count. The
input buffers stay immutable and the output is a distinct stock loan.

A real frozen original test-only `verify_reader_layout` call uses an inert
Cursor in an isolated exact Cargo copy. The disclosed `cfg(test)` child
only serializes the observed original ranges and readback. Tests verify
source identities, link the original non-test library before and after
temporary qualification, check exact all-range sequence on both stock
emitters, and distinguish file-relative offsets from frame coordinates.
No live file reader, deadline equivalence, loading, storage, owner
verification, execution or production integration is in scope.
