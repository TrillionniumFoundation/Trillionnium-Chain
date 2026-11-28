# M09 TMT1 declared tensor metadata

This private candidate mirrors the pure declaration parser and domain ID from
[`CellTensorContractV1`](../../../trillionnium/crates/trnm-data-availability/src/cell/tensor.rs).
It accepts only an immutable TMT1 metadata record. No tensor container,
safetensors header, payload, weights, owner pin, model execution, loader,
authorization, storage or adoption is consulted. Rust production callers
remain unchanged.

The syntax pass validates the original version, profile, codec, bounded
counts and exact consumed extent, decoding every UTF-8 name, dtype, rank and
shape word before reporting later semantic conditions. The semantic pass
checks original nonzero declared model root, global file order, per-file
canonical byte name order, reserved/control-character rules and integer
shape/dtype size computations, preserving dimension, overflow, individual
tensor-bound and aggregate per-file order. It does not compare such declared
sizes against on-disk data. The original 1 MiB/256-file/16,384-tensor/8-rank
and 64 GiB per-file boundaries are unchanged.

Private entry `f0(readbuf, mutbuf, mutbuf) -> u32`: success writes exactly
40 bytes (original domain SHA-256 ID, LE32 declared file and tensor counts);
both input and output remain unchanged on refusal. All parse/semantic
refusals and private capacity 102 occur before caller scratch is used;
the hash needs 1,240 scratch bytes. Status 103 is an internal hash failure.

The genuine Rust differential isolates unchanged declaration types, original
pure methods and their exact helpers out of `tensor.rs`, records both source
and extraction hashes, and links the existing trusted Cargo-locked SHA-256
without building tensor runtime or external services. Both pinned emitters
reproduce original accepted re-encoded bytes' domain identity and exact
bounded refusal precedence. It includes exact 1 MiB/16,384 entries, all
256 file indices, UTF-8 octet order, Unicode control refusal, overflow
and tensor-vs-file byte bounds. The ordinary loan cap prevents exercising
one byte past 1 MiB natively; that input is retained as Rust-only evidence.
