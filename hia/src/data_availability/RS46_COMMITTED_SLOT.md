# RS46 committed single-slot readback

The private `f0(readbuf,mutbuf,mutbuf) -> u32` checks supplied bytes only. It
takes one immutable loan:

1. One complete [RCB1 request](RS46_CODEWORD_VALUE.md), including caller pins,
   the complete TCM1, original chunk index, and complete CRC1.
2. One complete [canonical CRS1 wire](RS46_SHARD_VALUE.md).
3. A five-byte trailer: the big-endian u32 extent of RCB1 and the separately
   supplied u8 requested slot.

The native path uses the same CRC1 validator as the standalone value. Its
result is a validated offset within the original input loan, not a
caller-supplied or host-reencoded chunk. The CRC1 validator first decodes and
hashes the complete TCM1, checks independently supplied context and manifest
pins, derives the indexed source row, and recomputes CRC1's ID and six
nonzero unique identities. The CRS1 shape also uses the standalone validator.
Only then does the relation compare the requested slot, manifest, chunk
index, source length, and source digest, and stream the exact CRS1 wire
under its original SHA-256 domain. The rederived ID must match that
validated CRC1 slot.

On success the first 113 output bytes are the 32-byte CRS1 identity and its
81-byte canonical header; the unchanged payload remains borrowed. Rejection
writes no output. Scratch requires 1,240 bytes. Status 0 is success; RCB1
statuses are unchanged, 31–35 are exact CRS1 shape classes, and 36 is the
typed original readback mismatch. Malformed ABI framing returns 100;
insufficient output or scratch returns 102. Status 103 denotes internal
hash failure.

The joint Direct/Selfhost ABI is subject to Direct's existing 1 MiB loan
cap, including framing. Stock Selfhost's private contiguous profile also
admits a canonical full 1 MiB shard payload plus framing and does not
widen the Direct profile. The protocol's original TCM1/CRC1 and shard
bounds remain unchanged. The exact original `verify_input` is observed
through its own lexical module in an isolated test-only crate copy.
This returns a byte relationship against input pins, not proof of
retrieval, repair, storage, custody, ownership, authority, or availability.
