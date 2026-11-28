# BEP52 inert descriptor value

The private stock `f0(readbuf,mutbuf,mutbuf) -> u32` treats the final byte
as a mode tag.

- **0** parses the preceding UTF-8 text in the exact original 88-byte
  BEP52 descriptor grammar, including 64 canonical lowercase hexadecimal
  digits. The output is the 32-byte parsed identity followed by the 88
  canonical bytes, re-encoded from that identity.
- **1** checks equality with the declared binding. The input is a
  complete [BPB1 request](BEP52_BINDING_VALUE.md), the text, a big-endian
  u32 BPB1 extent, and the mode. HIA first checks the whole canonical
  TCM1 and independent context and digest pins, then checks the exact
  text grammar and compares its parsed identity to the canonical
  infohash independently derived by the native binding. No output is
  published in this mode.

Original error ordering is preserved for UTF-8 input: BPB1 checks
precede descriptor grammar; exact length and fixed prefix precede the
lowercase digit check and the final independent identity equality.
Codes 30, 31 and 32 represent those three kinds of refusal. The private
frame uses 100 for malformed envelope or exact-length non-UTF-8 bytes
outside the original Rust string domain; 102 is insufficient ABI space,
and 103 an internal hash failure.

Mode 0 uses 1,312 scratch bytes. Mode 1 uses the existing binding bound
of 1,760 plus 32 bytes per padded leaf, at most 526,048 bytes. The
16,384-leaf binding with the complete descriptor fits an unchanged 1 MiB
loan on both stock backends. Refusal leaves the output untouched; no
function writes beyond its own reported output or scratch extent.

These are byte-only value operations. They neither resolve a descriptor,
dial nor contact a peer, download, retrieve or disclose payload, nor
confer any authority. Qualification calls the unchanged public original
methods through the frozen locked Rust crate using local inert fixtures.
