# Worker dry export with typed preselection

`audit_export_preselection.hepta` takes **all** ordered typed candidate rows
for a bounded snapshot, decides which rows the active Rust export would
include, and emits its three artifact byte streams in one native call. It
shares the [WAT1](audit_export_transaction.md) transaction internals but
is a separate entry: WAT1 still rejects WAT2 and requires every input row
to be already selected.

## WAT2 framing and dry execution

The contract is the same disjoint `f0(input, output, scratch) -> u32`:
a maximum of 64 input candidates and 65,536 input bytes, exactly
102,400 bytes of used scratch, and a result up to the unchanged
1 MiB bounded extent. Input is `WAT2`, a little-endian `u32` count,
then exact little-endian `u32` length plus [WJL1 row](audit_jsonl_row.md)
for each candidate in positional order. The status slot in each row must
contain the exact source case-sensitive UTF-8 status, with no host
trimming, normalization, or selection flag. There is no trailing data.

Before writing output, the candidate validates WJL framing, presence,
width and UTF-8 for every row, including excluded ones. It uses the
shared WJS predicate **once** on each admitted source status; there is
no second lookup during output. The four included literals are
`reveal_submitted`, `rejected`, `failed_submission`, `failed_adapter`.
Other structurally valid statuses are omitted, never rewritten to
a selected status. Selected candidates must also satisfy the unchanged
canonical-label input projection that WAT1/WIG1 require; excluded
candidate labels do not participate in those checks or the index.
A malformed WJL input still makes the entire transaction refuse, even
if that row's status would otherwise be excluded.

The selector records a 64-bit attendance mask and increments a separate
selected count. The index receives compact selected ordinals, never
positions in the input candidate stream. The emit pass traverses the
unchanged input with the cached mask, preserving order and duplicates.
No retained file or host-generated mask is involved. The same measured
`WAO1` envelope contains full JSONL, Markdown and index JSON. For a
zero-selected result its sections are 0, 446 and 236 bytes
(698 including the 16-byte envelope). All refusals preserve output,
success preserves the unused output tail, and scratch may change
on either path. Status/size error codes and scratch geometry are unchanged
from WAT1.

## Comparison to the original locked CLI

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_export_preselection \
  hia.tests.test_worker_audit_export_transaction
python3 -B -m hia.tests.test_worker_audit_export_preselection --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The actual original Rust export filters before conversion, so it cannot
expose projected fields for excluded records from the unmodified
journal. The test observes the exact locked original binary's converter
on **two test-only shadow copies** of the same private synthetic journal,
both retaining every row and order but replacing only status with
different admitted literals. It compares all other projected fields
between the shadows and verifies that the active pinned Rust
converter only copies the status. The packing adapter restores each
untouched source position's original status verbatim in WJL1. It does
not classify, filter, reorder, derive index keys, or format artifacts.

Two independent real CLI runs on the *unmodified* journal produce the
full raw JSONL, Markdown and index bytes used for comparison. Both
native backends must reproduce all three exactly, with mixed-case and
whitespace exclusions, compact offsets, repeats, bit 63, 64 all
selected, all excluded and empty inputs. Tests also verify malformed
late selected or excluded rows, short output/scratch, and WAT1 refusal
of the other wire version.

This is a bounded **preconverted** snapshot candidate. It does not make
the raw Rust journal decoder, conversion, policy, file IO, verification,
authority, query or production dispatch native. In particular it does not
claim that converting an original journal before selection has
the same admission or resource behavior as the currently active Rust
filter-before-conversion path.
