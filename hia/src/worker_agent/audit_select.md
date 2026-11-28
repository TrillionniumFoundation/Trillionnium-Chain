# Worker audit record selection
`audit_select.hepta` returns one byte per already-typed ingress status, in
input order. It follows the exact predicate in
[`handle_export_audit`](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs):
`reveal_submitted`, `rejected`, `failed_submission`, and `failed_adapter` are
selected. There is no trimming, case folding, normalization or
deduplication. This predicate is for the audit export, not a Worker
execution or ledger status transition.

## Private WJS1 entry

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` takes disjoint
borrowed buffers. Input is an ASCII `WJS1` tag, a little-endian `u32` count,
then exactly that many `u32` byte lengths followed immediately by the
corresponding UTF-8 status bytes. There is no padding or trailing data.
Zero-length statuses are valid and excluded. Each string must be valid
UTF-8 independently of its neighbors. The count is capped at 100,000, the
[original journal count](../../../trillionnium/crates/trnm-worker-agent/src/worker_journal.rs).
The journal's separate file byte bound remains the file owner's duty.

On success, the output prefix contains exactly one `0` or `1` byte per
status, and the return is the number of statuses, not the number selected.
The unused tail and scratch stay unchanged. The first pass validates the
whole frame before any write. Return `0xffffffff` means invalid shape,
count or UTF-8; `0xfffffffe` means the output is too small. Both refuse
without publishing a partial selector.

## Actual original CLI observation

After project preflight, pinned HIA bootstrap, and fetching the unchanged
Rust/Cargo 1.95.0 workspace lock in the Cargo cache:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_select
python3 -B -m hia.tests.test_worker_audit_select --output /absolute/private/observation
```

The standalone observation builds only the unchanged original Worker
binary via Cargo `--offline --locked`, then invokes its actual
`export-audit` CLI on three owned local journal files: interleaved
selection with repeated IDs, all excluded, and empty. It compares the
native selector's ordered IDs with actual original output, and feeds the
original CLI's typed converted rows to the [native JSONL row
encoder](audit_jsonl_row.md) for exact byte comparison. It retains both
native runs, original JSONL and child receipts; an optional
`--cargo-target` outside the checkout reuses the same locked build
target during a readback.

The original Worker still parses the journal, converts and normalizes
records, handles format/index and filesystem effects, and owns production
dispatch. The observation does not claim a native replacement for those
parts or exercise remote operations.
