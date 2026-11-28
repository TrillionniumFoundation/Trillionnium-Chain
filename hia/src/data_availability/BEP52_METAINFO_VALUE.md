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
1 MiB loan. The combined Direct `f0` keeps its existing loan bound.
Stock Selfhost `f0` qualifies the full combined 16,384-leaf envelope.

Direct `f1(readbuf,readbuf,mutbuf,mutbuf) -> u32` takes the unmodified BPB1
request and raw metainfo as two independent immutable loans, with no
trailer or cross-loan copy. It runs the exact same native mode-2 derivation
and comparison as `f0`, measures both physical lengths itself, and publishes
no output. The full 16,384-leaf case has a 590,268-byte BPB1 loan and a
524,510-byte metainfo loan, each below the existing 1 MiB per-loan bound.
Neither backend, existing export nor compiler limits changed.

Verification success and failure leave the output untouched. Generation
does not publish any output on failure. BPB1 statuses are unchanged;
30–33 are original info-size, info-equality, metainfo-size, and
metainfo-equality refusal statuses. Status 100 is invalid framing, 102
insufficient buffers, and 103 an internal hash failure.

This is a declared immutable value comparison only. It does not access
referenced payload, prove possession or availability, resolve any link,
contact a peer, operate storage, or confer authority.
