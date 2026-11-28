# BEP52 companion proof value

The private stock `f0(readbuf,mutbuf,mutbuf) -> u32` accepts exactly two
envelopes, chosen by the final mode byte:

- **Generate (1)**: the complete [BPB1 request](BEP52_BINDING_VALUE.md),
  the requested index as big-endian u32, and mode 1. Native HIA revalidates
  the complete canonical TCM1 and its independent context and digest pins,
  checks original piece geometry and the index, derives the exact infohash,
  and captures the canonical sibling at each level before the shared
  in-place reduction overwrites that level.
- **Structural readback (0)**: the complete CBP1 encoding followed by mode
  0. Native HIA checks original size, namespace, leaf count, index, depth
  and exact extent in order. Entirely padded siblings must be zero digests
  at height zero and the correct recursively pair-hashed zero subtrees at
  greater heights. Nonpadding sibling bytes and the two pins remain opaque
  in this mode.

Both modes emit only exact canonical CBP1 on success: its four-byte tag,
32-byte manifest ID, 32-byte infohash, big-endian u32 index and leaf count,
one depth byte, and bottom-up 32-byte siblings. Depth is 0–14, with exact
output extent 77–525 bytes. No output is published on rejection. Readback
uses 1,344 scratch bytes. Generation needs 1,760 plus 32 bytes per padded
leaf plus 32 bytes per sibling (at most 526,496 bytes). The original
published [binding value](BEP52_BINDING_VALUE.md) retains its own unchanged
ABI and independent scratch bound.

Status 0 is success; original BPB1 errors remain unchanged; 31–36 distinguish
CBP1 size, tag, leaf count, index, depth and padding respectively. Invalid
ABI framing, insufficient buffers and internal hashing return 100, 102
and 103 respectively.

These are immutable metadata and descriptor operations. Structural readback
does not bind a proof to a trusted root, test piece payloads, or authorize
anything. No file, provider, storage, peer, or network operation is called.
