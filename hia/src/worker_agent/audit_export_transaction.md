# Worker dry typed export transaction

`audit_export_transaction.hepta` makes one in-memory operation from the
ordered selected [Worker export rows](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs)
to the complete JSONL, 18-column Markdown and eight-map index JSON byte
streams. One row order and one copy of each typed value drive all three
artifacts. The caller supplies neither pre-rendered output nor separate
keys or index facts.

## Private ABI

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` requires
live, disjoint buffers, an immutable input for the duration of the
call, and 102,400 bytes of disposable scratch as in [WIG1](audit_index_group.md).
It can change that scratch prefix even on refusal, and never writes the
scratch tail. There is no allocation, file descriptor or process handle.

The input is `WAT1`, a little-endian `u32` row count from 0 to 64, and
that many pairs of little-endian `u32` byte length and exact
[WJL1 row bytes](audit_jsonl_row.md). The complete input may not
exceed 65,536 bytes and may not have any unaccounted trailing byte.
The WJL1 row's presence bits, widths, UTF-8 and exact end are
checked using the existing row validator. HIA uses the shared literal
export-status predicate on all supplied rows. An out-of-projection
status is malformed rather than dropped. The existing WIG1 admitted
shape applies to the indexed optional labels: printable ASCII,
byte ceilings 64, 128, 3, 64 and 64 for provider, model, protocol,
compliance and fingerprint respectively. The host still supplies
canonical converted fields from the original active export contract;
there is no protocol, compliance or fingerprint policy in this entry.

The index projection uses WJL1 text descriptor 1 for status; 4 for
fingerprint; 5 and 6 for provider and model; and 8 and 9 for
protocol and compliance. Task ID comes from its original numeric
slot and the status determines the phase. Request ID, provider
request ID, schema version, adapter and reputation label are not
index keys. The numeric and variant cells still render normally.

The successful output is a 16-byte envelope: `WAO1` followed by
three little-endian `u32` byte lengths, then exactly that many bytes
of JSONL, Markdown and index JSON in that order. Embedded artifact
bytes are the original artifacts, without length markers or extra
terminators. An empty batch is not a null transaction: it emits
0 JSONL bytes, the full 446-byte Markdown header, and the 236-byte
empty index. Index JSON has no final newline. The result length
includes the envelope, does not exceed the existing 1 MiB borrowed
extent ceiling, and is returned without modifying the output tail.

## Atomic publication in memory

In its first pass the function admits every row, measures JSONL and
Markdown using the shared row renderers without writes, and derives
all index key spans directly from the same record. It then stages the
bounded WIX1 facts in scratch using the existing WIG1 grouping
primitives and measures the exact index JSON with WIX1. Commit does not
start until all input validation and the sum-of-artifacts capacity
check succeed. This is in-memory atomic refusal under exclusive
borrows, not a filesystem transaction or a concurrent observer contract.

To reuse the zero-based WIX1 renderer without changing any old source or
ABI, the commit first writes the complete index into the accepted output
prefix and moves it to the final index slot with `buffer.move_within`
(an overlap-safe move). Its writable extent is at most the already
checked envelope length. The staging scratch loan then ends; the
unchanged zero-based Markdown header is generated on scratch, reborrowed
read-only, and copied to its final disjoint output slot. JSONL and
Markdown rows are emitted from the unchanged input at their measured
offsets. The 16-byte length table is written last. These writes never
touch the unused output tail. Malformed input returns `0xffffffff`;
insufficient scratch or output, including any result beyond the limit,
returns `0xfffffffe`. Neither refusal modifies any output byte.

## Actual original comparison

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_export_transaction
python3 -B -m hia.tests.test_worker_audit_export_transaction --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The observation binds the unchanged locked Rust CLI and six tracked
source/lock identities. On each private synthetic journal, one original
`export-audit` supplies only ordered typed rows. Two fresh original
invocations produce the full raw JSONL, Markdown and Markdown index
file oracles. No rendered bytes or index grouping flow into the
candidate input. Both HIA emitters return the original byte streams
for a bounded 64-row batch covering all eight maps, duplicate rows,
escaping and absent fields, as well as for empty and all-excluded
journals. Controls exercise exact input and result edges, one byte
short on scratch or output, and a late invalid indexed or nonindexed
field.

Raw parsing, selection and record conversion, filesystem read/write
authority, identity and metadata policies, public query, CLI routing,
deployment, and replacement of the old Worker remain out of scope.
