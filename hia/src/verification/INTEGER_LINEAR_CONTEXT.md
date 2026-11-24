# Exact integer-linear context codec

This pure HIA entry implements
[`IntegerLinearContextV1::new`, `decode`, `canonical_bytes`, and `contract_id`](../../../trillionnium/crates/trnm-verification-profiles/src/exact_integer_linear_v1.rs).
It accepts the single original versioned family and slots 0 through 2.
The 32-byte parent artifact is an opaque identifier, including all zero
bytes. The caller must independently authenticate and bind any actual
parent artifact elsewhere. This component computes and serializes
ordinary deterministic values; it does not accept factors or verify
arithmetic, model behavior, model adoption, or any external authority.

The JSON mode accepts only the exact 372-byte canonical grammar:
original property order and values, lowercase unescaped hexadecimal
digests, and a single decimal slot followed by the final brace. Over
that fixed grammar the original error ordering is length, noncanonical
syntax, wrong family, then invalid slot. For instance, a validly encoded
but wrong family is reported before slot 9. A wrong family does not
override a structurally malformed context.

The context ID uses the original SHA-256 transcript: the ten bytes
`TRNM-PON1\0`, little-endian u16 domain length, the full ASCII domain
`integer-linear-insertion-contract-v1`, little-endian u32 canonical
length, and all canonical JSON bytes. The native entry assembles these
bytes and hashes them itself, rather than consuming a precomputed digest.

## Private local representation

The input begins with four bytes `ILC1`, then mode as a little-endian
u32. Mode 0 carries 32 family bytes, 32 parent bytes, and a u8 slot.
Mode 1 carries the raw JSON. A successful output occupies 469 bytes:
family, parent, u8 slot, 32-byte context ID, and 372 canonical JSON
bytes. Input and output beyond the returned extent are unchanged. The
1,632-byte scratch includes the complete original hash transcript.
No output is written on any refusal. This is not a wire, model, or
production verification API.

Codes 1, 2, 3, and 4 are original context length, canonical encoding,
family, and slot errors. Codes 100, 102, and 103 represent private
frame, capacity, and internal computation failures. The scratch bound
is checked before reading semantic fields when a complete frame is present.

The [differential](../../tests/test_integer_linear_context.py) compiles
the unchanged original methods with pinned Rust and a system SHA-256
seam, then compares both pinned independently emitted native images.
It checks full canonical bytes and context ID in both directions,
all u8 slots, every JSON byte position, typed error priority, and
input, output, and scratch canaries.
