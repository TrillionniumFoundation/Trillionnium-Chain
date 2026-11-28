# Immutable TCX1 chunk delta value

The native entry consumes one borrowed canonical `CellChunkDeltaV1` TCX1
wire value, not a base manifest or object reader. It applies the original
public `decode` checks in order: outer length (44 to 1,114,156 bytes), tag,
nonzero declared base ID, bounded target extent, full nested TCM1 admission,
then exact ordered u32 source-vector length and allowed source indices.
No trailing bytes are accepted. The original public Rust oracle checks
that every accepted input re-encodes to the exact input bytes.

Only then does the native entry emit the original 32-byte SHA-256 identity
over the domain `trnm.cell-chunk-delta.v1\0` and the exact canonical wire
in one borrowed input. The caller supplies 1,240 bytes of separate scratch
and at least 32 output bytes. It preserves output and scratch on input
refusal or inadequate capacity, and leaves the output suffix unchanged.

This is the value codec and identity, not `between` or `verify`.
An in-range index, repeated index, or sentinel is only a decoded
declaration. The caller has not established an actual base manifest,
the first matching base index, source coverage, or authority. No file,
store, network, loader, pin or retention action is involved.

The largest canonical positive uses 16,384 target rows and 16,384 source
entries; it fits the unchanged 1 MiB Direct fixture boundary. The original
and private Selfhost fixture additionally compare a rejected value one
byte beyond the outer TCX1 length bound without widening Direct.

Run the actual public original and both pinned backends:

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_chunk_delta_value
```
