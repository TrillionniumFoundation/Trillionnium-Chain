# Bounded native TCV2 declared content

`trnm_cell_complete_version_content_v2.f0` takes an immutable canonical TCV2
loan of at most 1,048,576 bytes. It reuses the published read-only TCV1 nested
validator at offset 8; the earlier TCV1/CTS1 sources and native entry points
are unchanged. The content record count must match the validated TCV1. Each
record's manifest ID and chunk count are compared with independently computed
TCM1 values in the same loan. The complete record structure, identity, and
trailing-byte checks happen before checking zero declared SHA-512 values, as
in the original Rust decoder.

The caller provides three disjoint buffers: the read-only loan, at least 68
bytes of output, and 131,232 bytes of private scratch. After all checks, the
entry writes the manifest count as little-endian u32 followed by the 64-byte
SHA-512 of `TRNM/Cell/CompleteVersionContent/v2\0` followed by the canonical
TCV2 wire. It leaves the input and the output suffix unchanged and does not
write output on refusal. Scratch is not a result and can change during a
refused call.

The differential calls the unchanged Cargo-locked public
`CellVersionContentV2::decode`, `encode`, `contents`, and `commitment` on
synthetic metadata. The shared bound is smaller than Rust's 24 MiB wire
bound. The tests distinguish a 1 MiB accepted case on both pinned native
backends and Rust's acceptance one byte above the native ABI. The result
commits to *declared* digests. It does not read, verify, or store any actual
payload, validate an owner or loader, authenticate a content pin, match a
lineage, or authorize production use.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_complete_version_content
```
