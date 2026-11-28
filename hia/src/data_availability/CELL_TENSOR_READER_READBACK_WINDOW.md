# Immutable name-selected tensor byte windows

This private value operation copies a bounded logical byte window of one
name-selected tensor. The complete selected contract/root, roster, range
coverage and raw-container SHA-256 are verified on the original immutable
reader frame before the name is resolved. The supplied offset is relative
to **that tensor**, never to the file or frame. The caller does not supply
the tensor's coordinates, verification state, or an authority token.

The request is LE64 tensor-relative offset, LE64 requested byte count, then
a 1–255-byte exact UTF-8 tensor name. The contiguous stock `f0` receives
the existing immutable reader frame followed by this request and its LE16
size. The suffix consumes at most 273 bytes and is never included in the
file hash; Selfhost's physically measured maximum is 4 MiB plus this
suffix, and Direct `f0` keeps its 1 MiB complete-loan guard. Direct `f1`
uses the existing five reader loans plus a sixth read-only request loan
and the two unchanged mutable loan types. The reader's 4 MiB logical
window, body/header/roster and existing per-loan caps are unchanged.

After verification and name lookup, the original `copy_bytes` rule
requires `offset <= tensor_length` followed by
`requested <= tensor_length - offset`. No multiplication or normalization
occurs. Empty copies at the exact end are legal, and an out-of-range empty
copy is not. The result is LE64 copied length followed by the exact copied
bytes in logical order, even across all three existing body loans. Byte
windows at most 1 MiB minus 8 can be emitted from much larger selected
tensors. Original reader failure precedes name rejection (226), an out-of-tensor
window (243), and short output (102). The complete capacity and
validated bounds are checked before writing; every refusal preserves
output and successful calls leave its suffix untouched. The private
request copy needs 16 extra scratch bytes within the stock 1 MiB limit
(840,472 bytes total); it cannot replace a checked source range.

The Rust comparator uses a fresh inert Cursor under the actual unchanged
`verify_reader_layout`. An isolated test-only child of the frozen original
resident tensor module binds the checked ranges to ordered immutable Arc
chunks of those same synthetic bytes, then invokes the genuine original
`tensor(name).copy_bytes`. It never creates a resident manager or accesses
a store; the before/after non-test library is byte-identical. Both stock
backends are checked against those results and exact canaries, including
the exact output maximum, oversized original acceptance, the tail of a
2,968,908-byte tensor, and nonphysical name/interval order. This does not
add F32 conversion, a handle, live file, store, loader, owner authorization,
network, deadline integration, or production use. Previous entrypoints
and machine code are unchanged.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_tensor_reader_readback_window
```
