# One-call ordered-field Worker journal audit export

WQX2 takes the same immutable raw snapshot, separate output and scratch,
and returns the same WAO1 stream and refusal statuses as
[WQX1](journal_audit_export.md). It admits specifically the
[WJD2](journal_audit_dto_ordered_fields_v2.md) profile: the same nine required
known fields in any order and thirteen optional known fields that may be
independently absent or literal null. Literal key spelling, unknown keys,
duplicate keys, non-null options and whole-line typing are checked before
selection. Late refusal leaves the whole output unchanged, even if earlier
lines were selected. No host parser, row frame staging or three-call
coordinator participates.

The original single-line and whole-journal byte caps, 64 candidate cap,
65,536 typed equivalent extent, 102,400 scratch bytes and 1 MiB output
limit have not changed. Raw UTF-8 and physical LF rules, stable selection,
compact index positions, three output formatters (JSONL, Markdown and index
writers), loan sequence and scratch map are exactly WQX1.

## Reproducible source projection

The tracked WQX2 entry source is generated from exactly the three original
functions `f0`, `wq_measure` and `wq_measure_one`. The module name changes;
exactly one call to `wd_record_at` becomes a call to `wd2_record_at`.
The existing explicit manifest imports every other native function from
its actual owner. Qualification compares committed entry bytes to the
projector output and the entire checked Core function structure, substituting
only the declared parser helpers. No universal composer/compiler changes,
dispatch selector or runtime generator are needed. The checked program
contains 79 functions and 2,617 operations. Original WQX1 stays separately
compiled and keeps its original, narrower and named-library behavior.

```sh
python3 -B -m hia.tests.test_worker_journal_audit_export_v2 --print-source
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_export_v2
python3 -B -m hia.tests.test_worker_journal_audit_export_v2 --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

Both the direct and selfhost execution tests pass entire raw synthetic
snapshots to one native call. Their three WAO1 members must match bit for
bit with the original locked Rust files. The original V1 canonical
fixtures must also stay equivalent. A late duplicate and late original-valid
but unsupported data are tested behind an already-selected row.

This candidate does not replace any production interface and has no
filesystem custody, generic Serde coverage, metadata policy or authority.
There is no new named-library or deployment claim.
