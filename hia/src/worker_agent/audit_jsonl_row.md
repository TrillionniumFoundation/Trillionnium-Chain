# Worker audit JSONL row
`audit_jsonl_row.hepta` serializes one already-typed
[active Worker record](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs):
the same 18 fields in declaration order as the active JSONL export, plus one
line feed. The whole row, including key names, punctuation and quotes, comes
from HIA. Strings preserve UTF-8 and Rust/Serde escaping. Missing options
emit `null`; empty strings and zero numbers are present values.

## Private WJL1 frame

Export: `f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
The buffers must be disjoint borrowed regions; the input stays immutable
for the call. Scratch is unused. All words in the 108-byte header are
little-endian:

| Offset | Width | Contents |
| --- | ---: | --- |
| 0 | 4 | ASCII `WJL1` |
| 4 | 4 | 15 presence bits for the optional fields in declaration order; higher bits zero |
| 8 | 56 | Seven `u64` slots: task ID, then delta, tier, weight, score, rank and gap |
| 64 | 44 | Eleven `u32` byte lengths: request ID, status, provider request ID, provenance schema version, fingerprint, provider, model, adapter, agent protocol, compliance profile and reputation label |
| 108 | variable | Complete UTF-8 text payloads in the same order as the length slots |

The three required fields are request ID, task ID and status. Mask bits
0–8 cover the nine optional texts; bits 9–14 cover the six optional
numbers. Absent numbers and absent text lengths must be zero. Present
`i32` values carry their low 32 two's-complement bits with a zero high word;
`u8` and `u16` slots must fit their Rust widths. The task ID has the full
`u64` range. UTF-8 cannot cross field boundaries. There is no padding.

The first pass validates all fields and calculates the exact length,
without changing output or scratch. A second pass writes only after the
whole row fits. Success returns the byte length including LF and leaves
the remaining output bytes untouched. `0xffffffff` means malformed
framing or invalid typed values. `0xfffffffe` means inadequate output
capacity or a length outside this private ABI: the maximum request and
successful result lengths are both `0xfffffffd` bytes. Neither refusal
changes output. The calculation needs only a 64-bit size accumulator:
the two fixed framing bytes per string, field keys, numbers and no more
than six encoded bytes per input payload byte cannot overflow it.

## Qualification and remaining ownership

After project preflight, the pinned HIA bootstrap, and populating the
exact Cargo registry cache for the workspace lock, run:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_jsonl_row
```

The test compiles the byte-identical active Rust struct declaration,
including its Serde annotations, with Rust/Cargo 1.95.0 and an offline
locked projection of the workspace's complete Serde dependency graph.
The adapter calls the actual `serde_json::to_string` and appends LF, the
same operation as the production branch. Both machine-code emitters
must return exact original bytes, including string escapes, numeric
extremes, and declaration order; framing/capacity controls check that no
partial row is published.

This is the typed serialization seam, not full Worker CLI equivalence
or cutover. Record conversion, selection, routing, file writes, the index
and query paths still belong to the original Worker implementation. The
test does not execute that CLI, and the private ABI cannot be substituted
for unbounded original values without an explicit caller and resource
policy.
