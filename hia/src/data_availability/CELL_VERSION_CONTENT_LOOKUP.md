# Native TCV2 declared-entry lookup

`trnm_cell_version_content_lookup_v2.f0` takes 32 query bytes (the manifest
ID) followed by the exact original TCV2 wire in the same immutable loan.
Their total is at most 1,048,576 bytes. Supply disjoint output and scratch;
scratch must be at least 16,032 bytes for a structurally valid declaration.

The function fully validates TCV2 using the published TCV3 entry's private
TCV2 subspan helper before looking up the ID. It searches the validated,
strictly ordered declaration rows. Success copies only the selected row:
32-byte manifest ID, 64-byte declared payload SHA-512, big-endian u32
chunk count, then the declared chunk SHA-512 array. The result length is
`100 + 64 * chunk_count`. A missing declaration, invalid TCV2, or insufficient
output never writes output. Scratch can change on refusal.

Both pinned native emitters are checked against unchanged Cargo-locked
`CellVersionContentV2::decode`, `file` and the public file getters, including
a later malformed row when the query matches the first row, all 512 declared
slots, and an exact 1 MiB envelope. A one-byte-larger ordinary lookup succeeds
in Rust but is outside this shared native scope. The returned digest claims
are metadata, not proof of reads, payload availability, an owner pin, model
loading, or authorization to use content.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_content_lookup
```
