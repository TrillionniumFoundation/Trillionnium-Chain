# BEP52 declared piece binding

The private immutable `f0(readbuf,mutbuf,mutbuf) -> u32` derives the piece
root and exact single-file v2 info bytes from one independently pinned
TCM1. It reads a `BPB1` tag, a 32-byte expected TCM1 digest, the expected
TCM1 context (a u8 family length, family bytes, and five 32-byte identities),
and the complete canonical TCM1 to the end of the buffer. The native path
validates TCM1, then checks the expected context, the recomputed TCM1
digest, and the 16 KiB piece geometry in the original order.

The native tree accepts the original bound of 16,384 declared leaves.
A single leaf is its own root. Larger rosters preserve declared order, pad
to the next power of two with zero **digests**, and hash each pair as
`SHA256(left || right)`. Padding does not hash fictional payload bytes.
The one in-place tree arena uses 1,760 bytes plus 32 bytes per padded
leaf, up to 526,048 bytes. All mutable and immutable loans remain within
both stock profiles. Canonical bencoding of the fixed `cell.bin` name,
decimal payload extent and piece length is emitted by HIA, not by the
observer.

Success emits the 32-byte pieces root, the 32-byte SHA-256 of the exact
info bytes, the big-endian u16 info extent, and those info bytes. Output
canaries and scratch beyond the declared arena remain untouched.
Failure never publishes output. Status 0 is success; 1–12 are exact
TCM1 errors; 14–17 cover context, manifest, piece size and leaf count.
TCM1 already prevents out-of-range leaf counts. ABI statuses 100, 102
and 103 distinguish malformed framing, insufficient buffers, and
internal hash failure.

This is a declared immutable metadata relationship. It neither reads
referenced payload data nor validates its whole-payload digest. It does
not emit metainfo, locate peers, perform I/O, or grant any form of
authority or availability. Qualification observes the unchanged
locked public Rust `CellBep52BindingV1` methods against both stock
native backends.
