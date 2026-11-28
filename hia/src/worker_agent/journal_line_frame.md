# Worker journal framing from an immutable byte snapshot

`journal_line_frame.hepta` ports the framing shared by the active
[Worker journal reader](../../../trillionnium/crates/trnm-worker-agent/src/worker_journal.rs)
and its typed decoder. It receives already borrowed raw bytes and
returns each nonblank logical source line's original byte range and
ordinal. It does not construct, rewrite, select, or trust any record.

## Private WJF1 entry

`f0(snapshot: readbuf, output: mutbuf, scratch: mutbuf) -> u32` takes
disjoint live buffers. The input is exactly the raw byte snapshot,
with no in-band envelope. The input stays immutable and scratch is
unused. This candidate bounds input to 65,536 bytes and nonblank lines
to 64; it does not change the original reader's 64 MiB and 100,000
nonblank-record limits or the project toolchain's buffer ceiling.

The snapshot must be valid UTF-8 across its full extent. It is
either empty or ends in LF, matching the original disk reader even
though the internal Rust `decode` helper in isolation also accepts
an unterminated last line. LF is the only line delimiter, with
exactly one preceding CR removed as part of CRLF. Bare CR anywhere
else, including an extra preceding CR, remains in the raw range.
Rust `str::trim` is used only to decide whether the line is entirely
whitespace; retained lines are not trimmed, even at the edges.
Unicode whitespace is not a line delimiter.

On success the function emits ASCII `WJF1`, a little-endian `u32`
nonblank count, then exactly that many triples of little-endian
`u32` logical ordinal, original byte offset and original byte
length. Ordinals run from 0 in decoder input order before any
JSON deserialization or status selection. Offsets and lengths are
byte-based, exclude the terminator, and refer to the borrowed
snapshot. Empty and all-blank inputs produce only the eight-byte
header; maximal output is 776 bytes.

The first pass checks terminal LF, complete UTF-8, framing and count
without changing output. The second pass writes only after the exact
output capacity check. Success returns the byte count and preserves
the unused output tail. `0xffffffff` means invalid UTF-8 or missing
terminal LF on nonempty input. `0xfffffffe` means a private byte/count
limit or inadequate output capacity. Both refusals preserve output
and scratch.

## Exact Rust geometry and CLI observation

```sh
python3 -B -m unittest -v hia.tests.test_worker_journal_line_frame
python3 -B -m hia.tests.test_worker_journal_line_frame --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

Pinned Rust 1.95.0 compiles a small standard-library probe using the
source-extracted original `from_utf8().lines().filter(...trim...)`
iterator and reader EOF guard. It emits original slice offsets and
logical ordinals, not expected bytes calculated by a host parser.
No Cargo runs. The original locked CLI is independently bound to the
same tracked source and lock identities, then run on private
synthetic snapshots both as supplied and reconstructed solely from
the native ranges. Reconstruction appends a fresh CRLF to each
retained span. This preserves a trailing CR that belonged to a span,
including an original CR+CR+LF case; trailing CR therefore needs no
fixture exclusion. Both backends preserve the original complete JSONL,
Markdown and index files, including original export selection from
the nonblank candidates.

Controls cover all 25 Rust whitespace codepoints, embedded Unicode,
incomplete final bytes, invalid UTF-8, exact byte/line capacity and
unchanged refusing output. A nonblank line with leading NBSP is
returned untrimmed by HIA, then rejected by actual original Serde
both before and after reconstruction. Good line framing is not JSON
or typed-record admission.

Opening, locking, ownership and validation of a real journal or
path, JSON parsing and status extraction, file publication, and
production routing remain unchanged. The file observation is a
test-only replay of local synthetic bytes; the entry takes no
path, descriptor, service, or credential.
