# Worker audit index serialization

`audit_index_wire.hepta` emits the exact `serde_json::to_string_pretty`
format of an already-typed [Worker audit index](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs).
It owns the version field, record count, map order, JSON quoting and
escapes, decimal offsets, indentation, and final brace with **no trailing
line feed**. It does not derive the index from records.

## Private WIX1 ABI

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` uses live,
disjoint borrowed buffers. The input must stay immutable and scratch is
unused. All integers in the request are little-endian:

- ASCII `WIX1`, then a `u32` total record count, at most 100,000.
  The frame identifies index version 1; the caller supplies no version field.
- Eight maps in this order: `by_task_id`, `by_status`, `by_status_phase`,
  `by_provider`, `by_model`, `by_agent_protocol`, `by_compliance_profile`,
  and `by_provenance_fingerprint`.
- Each map has a `u32` entry count. Each entry has `u32` key byte length,
  `u32` ordinal count, the nonempty UTF-8 key bytes, and that many `u32`
  ordinal values. No trailing bytes.

Keys must already be in strict decoded UTF-8 byte order. This is lexical
rather than numerical order, so a key of `10` precedes `2`. The function
does not sort or rewrite keys. Each populated entry has a nonempty strictly
increasing ordinal list, every ordinal is less than total records, and a
map's combined list lengths cannot exceed total records. These are
structural bounds, not verification that keys or cross-key grouping
correspond to records. Protocol, compliance, fingerprint and other keys
are opaque text; the same common JSON escaping is used for all eight maps.

The first pass validates the complete request and measures exact output
before the second pass writes any bytes. `0xffffffff` means malformed or
invalid typed input; `0xfffffffe` means inadequate output, or input/output
outside this private ABI's `0xfffffffd` maximum. Failure leaves output
unchanged; success returns the byte count and leaves the output tail
unchanged. The direct artifact also keeps its existing 1 MiB borrowed
buffer ceiling. The empty index still returns its complete metadata and
eight empty maps.

## Original observation

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_index_wire
python3 -B -m hia.tests.test_worker_audit_index_wire --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The observation runs the exact source/lock-bound original Worker CLI twice
on each private synthetic journal. The first invocation's
`.jsonl.index.json` is parsed into typed facts; no punctuation or indentation
is transferred. The second invocation's unmodified `.md.index.json` is the
full byte oracle for both native machine emitters. The tests include all
eight original nonempty maps, repeated ordinal groupings, lexical keys,
escaping, double-digit ordinals, empty cases and a malformed final map.

Index construction, file naming and publication, lookup, validation
against real record ownership, journal/path handling, and fingerprints or
policy normalization remain with the original implementation. There is
no change to the named Worker JSONL entry or production dispatch.
