# Full-height immutable Safetensors readback

This separate candidate composes the published one-loan readback's TMT1/TMR1,
layout and interval coverage with the published wide JSON visitor. It returns
the original public 114-byte reader projection only after comparing the
selected declaration's SHA-256 with the bytes actually inspected. It accepts
raw JSON headers up to 1 MiB, with the same qualified 128 tensor and 64 metadata
key limits. The entire private frame, including declarations, is capped at 2 MiB;
scratch requires 293,256 bytes. No previous entry or compiler is changed.

- Stock Direct `f1(readbuf, readbuf, readbuf, mutbuf, mutbuf)` takes three
  independent immutable physical loans, each at most 1 MiB: declarations plus
  the container's entire 8-byte little-endian header length, the entire raw
  JSON header, and the entire tensor data section, in that order. No arbitrary
  fragmentation or trailing bytes in the first two loans are accepted.
- Stock Selfhost `f0(readbuf, mutbuf, mutbuf)` uses the same logical frame
  contiguously with the existing private qualification facility. The stock
  Direct one-loan `f0` continues to enforce 1 MiB. The new candidate itself
  enforces a 2 MiB logical cap in both paths.
- HIA derives the span boundary from the prefix and physical loans and checks
  the total against the original selected file length. It validates the
  original ordered JSON, tensor names, dtype/shape, individual ranges and
  sorted coverage before final SHA equality. The split path hashes the raw
  8-byte prefix, header and data sequentially in a single internal SHA state.
  A declared digest is not a shortcut for file or layout verification.

Private statuses 210 and 225 distinguish the native frame extent and split
geometry from the original reader's errors on a valid physical profile.
Capacity or semantic refusal does not publish any output. Exact tests exercise
the real original public Rust `verify_reader` over synthetic in-memory
`Cursor` inputs, both pinned stock emitters, a physically full 1 MiB dense
header at the 2 MiB total cap, and independent digest refusals. A valid original
object just beyond 2 MiB is a native-profile refusal, not an original error.
No live reader, clock/deadline equivalence, storage, loader, owner, model
activation, or production authority is in scope.
