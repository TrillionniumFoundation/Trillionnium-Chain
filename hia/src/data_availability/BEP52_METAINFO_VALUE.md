# BEP52 metainfo value and exact byte comparison

The private `f0(readbuf,mutbuf,mutbuf) -> u32` borrows one immutable envelope:
a [BPB1 binding request](BEP52_BINDING_VALUE.md), optional supplied canonical
bytes, then a big-endian u32 BPB1 extent and one mode byte. The modes are:

- **0** emits canonical metainfo and admits no supplied suffix. The first
  four bytes of output are its big-endian length, followed by exact bytes.
- **1** compares the supplied bytes to original canonical info bytes.
- **2** compares the supplied bytes to original canonical metainfo.

All three use the existing native TCM1 and independent context/manifest
pin checks, the original 16 KiB geometry, and the same native piece tree
and info value. Metainfo includes the exact original bencoded `info` and
`piece layers` fields, including an empty layer dictionary for one leaf.
Larger layers include exactly the declared piece hashes in order; balanced
tree padding never becomes a layer member. There is no general metadata
parser, normalizing round trip or tolerance for extra bytes.

Scratch needs 1,760 bytes plus the full padded leaf arena for mode 1.
Modes 0 and 2 reuse that arena after reduction and require 1,760 plus the
larger of the padded arena and 1,024 plus 32 bytes per declared leaf.
The maximum generation/verification scratch is 527,072 bytes. Direct
generation handles the complete 16,384-leaf declaration under its existing
1 MiB loan. A loan containing both BPB1 and metainfo is subject to that same
Direct limit. Stock Selfhost also qualifies the full combined 16,384-leaf
envelope without changing Direct, compiler, or stock bounds.

Verification success and failure leave the output untouched. Generation
does not publish any output on failure. BPB1 statuses are unchanged;
30–33 are original info-size, info-equality, metainfo-size, and
metainfo-equality refusal statuses. Status 100 is invalid framing, 102
insufficient buffers, and 103 an internal hash failure.

This is a declared immutable value comparison only. It does not access
referenced payload, prove possession or availability, resolve any link,
contact a peer, operate storage, or confer authority.
