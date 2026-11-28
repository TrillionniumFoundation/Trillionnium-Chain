# Native selection of declared TCV3 root commitments

`trnm_cell_version_content_root_commitments_v3.f0` takes a single immutable
original TCV3 envelope of at most 1 MiB (the unchanged Rust decoder accepts
up to 32 MiB). It executes the exact published TCV3 validation body and
helpers before returning any selection. The per-node TCV2 commitments are
computed in the same call, within private scratch; no trusted root list,
precomputed digest, or earlier success token is an input.

With disjoint buffers, provide 133,280 scratch bytes and at least
`4 + 64 × root_count` output bytes. Success writes the little-endian u32
root count followed by the unmodified 64-byte TCV2 commitments in the
original strictly ascending **root index order**. Refusal never writes
output, including the count; scratch may change. The function outputs
neither the TCV3 outer commitment nor actual payload bytes.

A source-bound test checks the mechanically selected validation and failure
blocks. Both pinned native emitters are compared with unchanged locked
Rust `CellVersionContentClosureV3::decode` and `root_commitments` over
1–16 selections, including sparse roots, nontrivial DAGs, exact 1 MiB,
the native bound's Rust-only +1 byte case, and late refusal ordering.
These are declared commitments only. This entry does not select CURRENT,
read a store, grant use, or authenticate a lineage or owner pin.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_content_root_commitments
```
