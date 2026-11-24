# Worker audit JSONL batch

`audit_jsonl_batch.hepta` takes already-typed candidate records in journal order.
In one native call it validates the batch, selects the exact four original
status strings, and emits selected rows as a single JSONL byte stream.
Order and duplicates are preserved. The component imports the existing
`ws_selected` predicate and the same WJL field renderer used by the single-row
encoder. No selected-row mask or individual serialization request goes back
to the caller.

## Private WJB1 ABI

Export: `f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
Use disjoint borrowed regions and keep the request immutable. Scratch is
unused. The frame is:

- ASCII `WJB1`, then a little-endian `u32` number of candidate records.
- For each record, a little-endian `u32` byte count and exactly that many
  bytes of the full [WJL1 typed row](audit_jsonl_row.md).
- No trailing bytes. Maximum 100,000 candidate records, matching the
  original bounded ingress reader. Request and successful result lengths
  are at most `0xfffffffd` bytes.

The first pass checks every row and computes the aggregate output size.
An invalid late record, including an excluded row, never publishes an earlier
row. A second pass writes directly into the checked output range. Neither
pass allocates a buffer or copies a typed row. The shared WJL renderer takes
an absolute output cursor; internally, the high 32 bits of its input extent
carry the absolute row start and the low 32 bits the exclusive row end.
The standalone WJL1 ABI still uses start zero. The batch validates the
complete WJL extent and header before calling either helper, and a selected
status cannot read beyond that row. Summing the bounded UTF-8 escaping
expansion and fixed framing costs fits a 64-bit output cursor.

Success returns the number of bytes written (zero for no selected rows),
leaving the output tail and scratch untouched. `0xffffffff` is malformed
input; `0xfffffffe` is insufficient output or a length beyond the private
ABI. Neither refusal alters the output.

## Qualification and ownership

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_jsonl_batch
python3 -B -m hia.tests.test_worker_audit_jsonl_batch --output /path/to/new-proof
```

The second command runs the original Rust 1.95.0 locked CLI on isolated
synthetic journals. To reuse its exact already-built executable, supply
`--original-binary` and its `--original-build-receipt`; the test checks the six
original source/lock object identities and the executable digest before and
after running it. The observation transfers every candidate record, including
records not emitted by the CLI. In each of three scenarios, one native call
per emitter must match the original ordered JSONL byte for byte and the
record count printed by original stdout. The surrounding CLI status line,
file paths, and index are not native outputs.

This is an in-memory typed selection and serialization boundary, not
raw-ingress conversion. The host still supplies typed optional fields, including
display and reputation projections and already-produced fingerprint and policy
facts. The isolated WJP/WJR projectors are not invoked by this component.
The Rust production dispatch, journal parsing, identity, index, persistence,
and Markdown behavior remain unchanged.
