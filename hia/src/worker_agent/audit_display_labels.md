# Worker audit display labels
`audit_display_labels.hepta` projects four optional display fields in the
[active Worker audit export](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs):
`provenance_schema_version`, `provider`, `model`, and `adapter`.
It does not handle provider request IDs, the provenance fingerprint,
protocol and compliance fields, or credentials.

The schema applies ASCII lowercasing and retains only ASCII alphanumeric
characters. Exactly `llmv1` or `llm1` becomes `llm.v1`; `llmv2` or `llm2`
becomes `llm.v2`; all others become absent. The original initial Unicode
trim cannot affect this filtered key, since all its trim characters are
discarded by the ASCII-alphanumeric filter. UTF-8 is still validated before
projecting any input.

The three labels trim the original Unicode whitespace set, using the
existing native trim helpers. After trimming, labels must be nonempty
printable ASCII (bytes `0x20..0x7e`). This preserves case, spaces within a
label, and printable punctuation, but excludes controls, embedded Unicode
whitespace, and invisible or lookalike Unicode characters. Length limits
apply after trim: provider and adapter are limited to 64 bytes, and model
to 128 bytes. Empty or filtered-out labels become absent.

## Private WJP1 entry

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` accepts disjoint
borrowed buffers. The input begins with ASCII `WJP1`, a kind byte
(`0` schema, `1` provider, `2` model, `3` adapter), and a presence byte
(`0` absent, `1` present). The rest is the complete UTF-8 value; absent
input must have no payload.

On success, the written prefix starts with one presence byte. Absent
output is exactly a zero byte. Present output has a one byte followed by
the exact canonical display text, with no terminator. The return is the
byte count. The maximum output is 129 bytes. Malformed shape or UTF-8
returns `0xffffffff`; insufficient capacity returns `0xfffffffe`. Both
refusals preserve the entire output. Success preserves the unused tail.
The source and scratch are never changed.

## Actual original comparison

After preflight, pinned HIA bootstrap, and populating the exact
Rust/Cargo 1.95.0 locked workspace cache:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_display_labels
python3 -B -m hia.tests.test_worker_audit_display_labels --output /absolute/private/observation
```

The standalone observation uses the unchanged locked Worker binary to run
its real `export-audit` command on benign local rows with synthetic display
labels. Both native emitters compare these four observations, then feed
them and the remaining untouched original fields into the [WJL row
encoder](audit_jsonl_row.md) and match the full original output byte for
byte. The test covers every admitted Unicode whitespace code point at
both boundaries, internal controls, valid aliases with filtered
characters, length boundaries, and absence. Rust retains all authority,
other conversion, CLI routing, journal/index, and filesystem writes.
