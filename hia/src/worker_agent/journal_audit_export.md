# One-call audit export from a bounded ordinary raw Worker journal

`journal_audit_export.hepta` accepts the entire already-borrowed raw
journal, not a host-selected or decoded row stream. The HIA call
returns the original JSONL, Markdown and index byte streams in one
[WAO1 packet](audit_export_transaction.md). It exposes no custody or
filesystem operations and does not replace the production Worker.

## WQX1 entry and admission

`f0(snapshot: readbuf, output: mutbuf, scratch: mutbuf) -> u32` accepts
three independent borrowed buffers. The snapshot stays immutable.
Input is the entire raw journal without a marker, with the unchanged
[WJF1 limits](journal_line_frame.md): at most 65,536 raw bytes, at most
64 nonblank candidates, a final LF on nonempty input and valid UTF-8.
Only the exact two [WJD1 line profiles](journal_audit_dto.md) are
admitted (all nine required fields in declaration order, and either no
optional suffix or the exact complete null suffix). In particular every
raw candidate is admitted first, even if its status will be excluded.
The equivalent WAT2 typed frame extent cannot exceed 65,536 bytes.
Output stays within 1 MiB, including the unchanged 16-byte WAO1 header.

HIA takes raw WJF1 byte spans, measures all WJD1 values, and materializes
one WJL1 row into scratch at a time. It invokes the existing WAT2
literal selector once per valid candidate and keeps a 64-bit
attendance mask. The same actual WJL1 JSONL row writer and WMA1
Markdown row writer measure the selected rows; no candidate output
has been written. The mask then drives all three outputs, preserves
source order/duplicate rows, and indexes compact selected positions.
The existing WIG1 grouping and WIX1 writer produce the eight maps.
This WJD1 profile has no non-null optional fields, so only task/status/
phase can be nonempty. The exact decoded word `rejected` yields
`terminal`; the other admitted WAT2 literals yield `active`.

A malformed raw/profile input returns `0xffffffff`. A limit or
insufficient output or scratch returns `0xfffffffe`. Both preserve
every output byte. Success returns the full packet byte count and
leaves the remaining output unchanged. The caller's scratch prefix
may change on both paths.

## Scratch bounds and borrow sequence

The first 102,400 bytes of caller scratch may be used; a larger scratch
tail is never written. There are no allocations, subviews or changes
to existing caps. Ranges below are half-open:

| Range | Use |
|---|---|
| [8, 776) | initial WJF spans (at most 64 × 12 bytes) |
| [30000, 30768) | relocated original raw line spans |
| [30768, 32304) | 64 × 24-byte task/request/status descriptors |
| [32768, 98412) | transient WJL row, at most 65,536 + 108 bytes |
| [32768, 102400) | WIG key table, used only between row phases |
| [0, 29736) | staged WIX frame, at most the existing worst case |

Scratch changes role only at fixed phase boundaries. Raw span and
value descriptors lie outside every reusable region. The WIG table
is cleared after measuring rows, before constructing groups; no
prior staged WJL bytes enter the index. WIX1 reads the table-derived
frame only via a read loan ending before scratch is re-used.
Only after **all** raw/typed checks and all three output sizes fit
does WIX write, move its prefix to the final index position, and then
the zero-based Markdown header uses the now-dead WIX prefix in
scratch. That loan ends before staging rows again. Rows are then
emitted at their measured packet offsets, with no new selection.
The length table is written last. These operations are atomic
refusal under exclusive output ownership, not filesystem atomicity.

## Original qualification

```sh
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_export
python3 -B -m hia.tests.test_worker_journal_audit_export --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The unchanged locked Rust CLI reads each synthetic original snapshot
and independently emits all three raw oracles. Each native emitter
receives precisely that original whole raw buffer in **one** call.
The observer does not split lines, feed DTOs, build typed framing,
classify status or derive indices. Tests cover both admitted shapes,
blank and empty input, 64 candidates including a large staged row and
selected row 63, exact byte and capacity boundaries, scratch reuse
and unmodified refusal outputs. A separate original-valid but
out-of-profile late excluded row demonstrates the intentional whole
refusal boundary.

WJF1, WJD1 and WAT2 remain separately callable with their original
ABIs. Nothing here broadens the supported DTO grammar, implements
generic Serde or metadata policy, opens/locks files, authorizes
anything, or changes CLI production dispatch.
