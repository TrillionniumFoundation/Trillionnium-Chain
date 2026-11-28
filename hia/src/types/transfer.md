# Native TransferTx methods

`transfer.hepta` implements the four public `TransferTx` methods from
`trillionnium/crates/trnm-types/src/transfer.rs` as HIA machine code:

| Operation | Original method | Result |
| --- | --- | --- |
| 0 | `signing_message` | Exact message bytes, with full-width decimal `u128` amounts and fees and `u64` nonce |
| 1 | `derive_address_from_ed25519_pubkey` | `trnm1` followed by the lowercase hex of the first 20 SHA-256 digest bytes |
| 2 | `sign_with_private_key_hex` | `ed25519:<public key hex>:<signature hex>` |
| 3 | `validate_basic` | Original six errors in their original precedence, or success |

The signature message remains
`trnm-transfer-v1|from=…|to=…|amount=…|fee=…|nonce=…`. String bytes are preserved,
including delimiters, NUL and Unicode. Signing does not first validate the
transaction: the original method signs those exact fields after decoding its
32-byte private key. Validation uses Rust's Unicode whitespace set for the three
emptiness checks, exact sender/recipient comparison, lowercase address matching,
fixed-width hex decoding with upper- and lowercase input, and strict Ed25519.

The implementation selects shared HIA SHA-256, SHA-512, Ed25519 field/group/scalar,
Unicode and integer routines through `components.json`. Signing and verification
feed the complete message into one continuous SHA-512 context. Message length is
not restricted to the older SHA-512 arena's 128 KiB input window. Address derivation
uses the same SHA-256 compression and context with the complete byte-message
domain, up to `2^61 - 1` bytes. The original transport SHA-256 entry points retain
their 2,098,176-byte service limit and original refusal order. Ordinary Ed25519
keys contain 32 bytes.

## Local call envelope

The sole exported entry is `f0(input:readbuf, output:mutbuf, scratch:mutbuf) -> u32`.
All integers in this local envelope are little-endian. The envelope is a method
call interface; it introduces no new transaction wire or signed domain.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | `TRNMTX1` followed by NUL |
| 8 | 8 | Operation, 0 through 3 |
| 16 | 8 | Sender byte length |
| 24 | 8 | Recipient byte length |
| 32 | 8 | Signature byte length |
| 40 | 8 | Private key hex byte length |
| 48 | 16 | Amount |
| 64 | 16 | Fee |
| 80 | 8 | Nonce |
| 88 | Variable | Sender, recipient, signature, private key hex, concatenated |

Lengths must account for the entire input without trailing bytes. The four
strings must be UTF-8. Operation 1 instead takes arbitrary raw public-key bytes
in the sender field; all other lengths and numeric fields must be zero.

Operations 0, 1 and 2 publish `length:u64` followed by the exact result bytes.
Their output suffix remains unchanged. Operation 3 publishes no bytes. Every
refusal preserves the complete output buffer.

Scratch must contain at least 143,504 bytes for operation 1. Other operations
require at least `143504 + sender_bytes + recipient_bytes` bytes. The extra
144 bytes beyond message offset 143,360 cover the exact worst-case message:
46 fixed text bytes, two 39-digit `u128` values and one 20-digit `u64` value.
Scratch is private working memory and may change during a failed operation.
After a completed signing attempt has expanded the private key, all 141,568 bytes
of the private crypto work area are zeroed before returning, on success or error.
Caller-owned input bytes are read-only.

## Results and qualification

| Result | Meaning |
| --- | --- |
| 0 | Success |
| 1 | `EmptyFrom` |
| 2 | `EmptyTo` |
| 3 | `SameSenderAndRecipient` |
| 4 | `ZeroAmount` |
| 5 | `MissingSignature` |
| 6 | `InvalidSignature` |
| 100 | Invalid local envelope |
| 101 | A method string is not UTF-8 |
| 102 | Insufficient output/scratch or shared hash input capacity |
| 103 | Internal shared-primitive refusal |

`hia/tests/test_transfer.py` compiles the actual original crate adapter and the
self-hosted HIA artifact, then compares the four methods. It requires
`TRNM_HIA_RUST_TYPES_RLIB` to name the exact original `trnm-types` library; its
adjacent `deps` directory and matching `rustc` must be available. Missing original
code or a failed compiler invocation is an error.

The controls include full-width integers, all 25 Unicode whitespace characters,
all ASCII nonhex characters in private-key/public-key/signature positions,
canonical scalar and weak-point refusals, tampering, output canaries, private
work erasure and exact scratch boundaries. Address inputs of 2,098,177 and
4,194,561 bytes match the actual original crate and independent SHA-256; the
old transport entry separately accepts its exact limit and rejects one byte more. Complete messages with recipients of
131,009 and 262,177 bytes exercise signing, verification and tampering beyond the
older arena limit. `TRNM_HIA_TRANSFER_REPORT_DIR` retains the executed native and
original binaries, their source identities and every comparison observation.

This component ports the four method bodies. Generic Serde traits, the remaining
`trnm-types` objects, durable private-key ownership and live Node consumption
belong to their separate migration entries. The original package remains in the
workspace until its complete replacement and dependent call sites are qualified.
