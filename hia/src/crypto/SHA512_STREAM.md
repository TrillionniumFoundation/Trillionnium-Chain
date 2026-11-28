# Incremental SHA-512

`sha512_stream.hepta` hashes successive byte ranges with one continuous SHA-512
state. The four product entry points are `s512_init`, `s512_update`,
`s512_update_work`, and `s512_final`. Their successful return value is zero.
Messages are checked against their actual borrowed-buffer extents; there is no
131,168-byte message limit in the incremental interface.

The constants, initial state and compression rounds have one canonical source in
`sha512_arena.hepta`. Its `sha512_state_init(arena, base)` and
`sha512_compress(arena, base)` helpers serve both interfaces. Shared bytewise
`sha512_load64` and `sha512_store64` accept the same explicit base. The original
`f0`, `sha512_arena`, `sha512_work_load64` and `sha512_work_store64` signatures,
capacity refusals, input preservation and digest location remain unchanged.

## Product interface

| Function | Operation |
| --- | --- |
| `s512_init(arena: mutbuf) -> u64` | Install the SHA-512 constants and initial state, clear the partial block and counters, and start a fresh context. |
| `s512_update(input: readbuf, offset: u64, length: u64, arena: mutbuf) -> u64` | Hash the selected input range into the existing context. |
| `s512_update_work(arena: mutbuf, offset: u64, length: u64) -> u64` | Hash a range in the same arena; its starting offset must be at least 1,512 so that it cannot overlap the mutable context. |
| `s512_final(arena: mutbuf) -> u64` | Append SHA-512 padding and the full 128-bit bit length, publish the 64-byte digest, and mark the context finalized. |

An arena must contain at least **131,232 bytes**. The context occupies only
`[0, 1512)`. Successful finalization writes the digest to `[131168, 131232)`,
matching the original SHA-512 ABI. Every byte outside those two ranges remains
unchanged. Initialization and updates also leave the digest slot unchanged.

This layout preserves the existing Ed25519 group workspace beginning at
133,120, signing state at 140,160 and later offsets, and messages beginning at
143,360. A caller may feed its prefix and message with separate updates; the
result is SHA-512 of their byte concatenation with one final padding operation.
The helpers require exclusive ownership of the mutable context for the whole
operation. The context is private working memory, not an authenticated serialized
checkpoint.

| Context range | Contents |
| --- | --- |
| `[0, 640)` | 80 SHA-512 round constants, little-endian u64 words |
| `[640, 1280)` | 80-word message schedule |
| `[1280, 1344)` | Eight chaining-state words |
| `[1344, 1472)` | One partial 128-byte input block |
| `[1472, 1480)` | Total byte count, low u64 |
| `[1480, 1488)` | Total byte count, high u64 |
| `[1488, 1496)` | Buffered byte count, from 0 through 127 |
| `[1496, 1504)` | Context tag `SH512STR` |
| `[1504, 1512)` | Finalized flag |

The total byte count is a checked 128-bit pair. Its high word must be below
`2^61`, giving the SHA-512 byte-input domain below `2^125` bytes. An update
checks the complete count addition before writing any context byte. Finalization
encodes `(total_high << 64 | total_low) * 8` as a 128-bit big-endian bit length.
The tests exercise real practical input sizes and separately test the counter
carry, padding representation and overflow refusal with explicit synthetic
counter states.

## Refusals and publication

| Return value | Meaning |
| --- | --- |
| `0` | Completed operation |
| `100` | Insufficient arena capacity |
| `101` | Invalid input range or an overlapping same-arena range |
| `102` | Missing, corrupt or finalized context; inconsistent buffered count |
| `103` | Total SHA-512 byte length would overflow its permitted domain |

Range checks use subtraction after checking the starting offset, so an unsigned
end offset cannot wrap into an accepted range. Input-range checks precede context
checks in the two update functions. Context checks verify the tag, finalized
flag, count bound and `buffered == total_low mod 128`. Every refusal leaves the
entire arena unchanged. Repeated finalization and updates after finalization
refuse; an explicit `s512_init` starts another independent message.

The caller owns secret erasure after using the hash. The incremental interface
preserves the caller's unrelated bytes and does not erase Ed25519 private state.

## Native qualification entry

The file's first `f0(readbuf, mutbuf, mutbuf) -> u32` is a finite test entry for the
pinned compiler's existing borrowed-buffer ABI. Its output must have at least
64 bytes. All descriptor words are unsigned little-endian u64 values:

| Operation | Input descriptor |
| --- | --- |
| `0` | `0, chunk_size` followed by the message; positive chunk size; initialize, stream and finalize |
| `1` | The single word `1`; initialize |
| `2` | `2, offset, length` followed by input bytes; offsets address the complete descriptor buffer |
| `3` | Exactly `3, offset, length`; update from the arena |
| `4` | The single word `4`; finalize |

Only operations 0 and 4 publish the digest to the output buffer. All operations
preserve its suffix. Malformed descriptors return 101; short output/arena buffers
return 100 before any write. This descriptor is a qualification interface, not a
new blockchain wire format.

`hia/tests/test_sha512_stream.py` executes the pinned self-hosted compiler and
compares returned digests with Python's independent `hashlib.sha512`. Coverage
includes every length through 259, padding boundaries, different chunk sizes,
separate prefix/message updates, same-arena ranges, real unaligned pointers,
inputs through 4 MiB + 257 bytes, capacity/state/range failures, 128-bit length
controls, and complete output/arena suffix preservation. The large-input child
uses the same emitted entry directly because the shared Python test transport
has a 1 MiB cap. It does not relax a product limit or use a host hash as the
implementation. The unchanged original SHA-512 and Ed25519 suites remain
required regression checks for the shared compression extraction.
