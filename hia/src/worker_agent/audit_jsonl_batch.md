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

## Private WJB2 ABI: raw reputation projection

The outer magic is `WJB2`. The candidate count and each typed row's
length and contents follow WJB1. Immediately after each typed row, five
additional bytes carry a presence byte followed by a little-endian i32
reputation delta. Only presence 0 or 1 is valid; absence requires a zero
delta payload. The five bytes do not count toward the row's length.
All seven reputation options in the typed row must be canonically absent:
no presence bits, all six numeric slots zero, and a zero label length.
The original WJB1 and standalone WJL1 encodings are unchanged.

The WJL renderer emits the first eleven fields and checks the exact inner
extent; the WJB2 renderer supplies all seven remaining fields in original
order from `wr_values`, the same canonical mapping used by WJR1.
Known audit labels are fixed ASCII; decimal output reuses WJL helpers.
An absent delta or an unrecognized i32 emits seven nulls. No host-projected
reputation field is accepted in WJB2, including on excluded rows.

## Private WJB3 ABI: raw display projection

The outer magic is `WJB3`. Lengths, candidate limit, and the five-byte
reputation suffix are unchanged from WJB2. The four text slots for
`provenance_schema_version`, `provider`, `model`, and `adapter` instead
contain the original optional UTF-8 inputs; their existing presence bits
and byte lengths describe the **raw** options. Absence requires zero
length; present-empty is legal and normalizes to null. There is no
second channel for a pre-normalized value. All other slots have their
WJB2 meaning, and the seven reputation slots remain canonically absent.

The shared WJP evaluator validates the entire individual UTF-8 option.
It reports null, a span in the original immutable bytes, a canonical
schema alias, or invalid input. The batch emits that value in original
declaration order with the existing JSON quoting rules. Even a raw
label which normalizes to null consumes its full declared extent, and
invalid UTF-8 in an excluded row still invalidates the batch.

## Atomic output

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
python3 -B -m hia.tests.test_worker_audit_jsonl_batch --project-reputation --output /path/to/wjb2-proof
python3 -B -m hia.tests.test_worker_audit_jsonl_batch --project-display --output /path/to/wjb3-proof
```

The observation commands run the original Rust 1.95.0 locked CLI on isolated
synthetic journals. To reuse its exact already-built executable, supply
`--original-binary` and its `--original-build-receipt`; the test checks the six
original source/lock object identities and the executable digest before and
after running it. The observation transfers every candidate record, including
records not emitted by the CLI. In each of three scenarios, one native call
per emitter must match the original ordered JSONL byte for byte and the
record count printed by original stdout. The surrounding CLI status line,
file paths, and index are not native outputs.

This is an in-memory typed boundary, not complete raw-ingress conversion.
The WJB3 comparison supplies raw synthetic reputation and display inputs,
not the original CLI's eleven projected outputs. Any fingerprint or policy
value already produced by Rust is an opaque retained fact, outside both
native projections. No fingerprint, request identity, protocol policy,
or credentials are computed by this component. The Rust production
dispatch, journal parsing, identity, index, persistence, and Markdown
behavior remain unchanged.
