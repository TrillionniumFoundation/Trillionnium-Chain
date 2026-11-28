# Wide immutable tensor readback

This is a separate candidate for the same readback value and rejection order
as the bounded one-loan immutable reader. The logical input is the same
canonical private frame: supplied TMT1 content digest, selected file index,
length-prefixed TMT1 and TMR1, and original Safetensors container bytes.
No byte, digest or success indication is obtained from a live store or trusted
caller instead of the actual immutable input.

The 2 MiB logical cap includes the entire frame. The JSON caps remain 128 KiB,
128 tensors and 64 metadata keys; private scratch remains 293,256 bytes.
The existing one-loan modules and emitted binaries are unchanged.

- Direct's stock `f1(readbuf, readbuf, mutbuf, mutbuf)` accepts at most two
  disjoint immutable 1 MiB spans. The first must contain the declarations and
  the entire LE64-prefix plus JSON header. It may also carry any initial part of
  the actual tensor body. The second is exactly the remaining body, or empty
  when the first contains the whole logical frame.
- Selfhost's stock `f0(readbuf, mutbuf, mutbuf)` accepts the same logical
  bytes contiguously with the existing private larger-input qualification
  facility. The Direct wrapper's normal `f0` 1 MiB loan remains unchanged.
  The new HIA artifact independently rejects contiguous inputs over 2 MiB.

The combined *actual* lengths must match the selected original TMR1 file
length. Length comes from both borrowed extents, not a caller-declared split
size. Both borrowed spans are checked by the same HIA parser and geometry
route. Original status order holds once the qualified physical shape is
satisfied. 225 is a private refused split inside the LE64 prefix or the JSON
header. 210 means this private envelope/extent; a valid original object
outside the physical profile is not claimed to be an original error.

The original public 114-byte readback is emitted only after the same checked
TMT/TMR/pin, real JSON, canonical per-tensor checks and sorted interval
coverage, and the same final pure container SHA-256 comparison. For Direct's
split entry SHA-256 first consumes the entire original container prefix,
header and initial data in the first loan, then the remaining actual bytes in
the second loan, with a single HIA-owned SHA state. No host digest/offset
certificate, mutable file or continuation across invocations exists. All
successful outputs and refusal canaries are compared with the unchanged
locked public Rust `verify_reader` over synthetic in-memory bytes. No storage
stream, live I/O, reader/clock semantics, loader, trust, or production claim.
