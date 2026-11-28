# Immutable TMT1 tensor-spec lookup

`trnm_cell_tensor_declared_spec_lookup_v1.f0` accepts a single immutable
borrow of at most 1 MiB: a BE16 file index, BE16 query byte count, that many
UTF-8 name bytes, then the exact TMT1 declaration. It validates the complete
declaration through the published TMA1 private TMT1 parser before looking
up a file or tensor. Exact bytewise UTF-8 matching preserves the original
name relationship without case folding or normalization.

Success writes LE64 computed tensor byte length followed by the selected
canonical TMT1 tensor record: BE16 name length, the name bytes, dtype u8,
rank u8, and BE64 dimensions. A missing file/name, invalid declaration or
insufficient output writes nothing. Input and unused scratch are unchanged.
This is declared metadata; the codec sees no safetensors bytes and provides
no admission, load, storage access, authority or execution capability.

The test compares unchanged public locked Rust `CellTensorContractV1::decode`
and `files` on immutable declarations (up to 16,384 tensors and 256 files).
A matching declared contract is also obtained from the previously qualified
owned synthetic residency fixture, with actual resident `tensor` and its
name/dtype/shape/byte_length getters compared on both stock emitters.
That same disposable example adds a four-chunk segment/copy/F32 comparison
against the unchanged, already-generalized TVB1 artifact. There is no new
TVB1 ABI and no SQLite path in the new native entry.
