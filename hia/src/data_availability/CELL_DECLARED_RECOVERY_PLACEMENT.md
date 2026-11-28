# Bounded declared recovery placement

This immutable diagnostic implements the pure original
`evaluate_recovery_placement` on a supplied declaration, not a placement
observer or recovery owner. Input consists of `NRPE0001`; big-endian u16
provider and placement counts; maximum-loss and axis-count bytes;
big-endian u64 maximum steps; axis bytes in typed order; provider rows
with five original 32-byte fields; and 34-byte placement rows.
A placement row holds the provider ID and big-endian u16 part:
zero is a whole copy, and one through six represent original
Reed–Solomon rows zero through five. The physical fixture adapter uses
wider layout for original invalid u8 indices so their error order is
testable. Unknown axis encodings are not original typed values.

The listed providers and placements must be canonical. The exact
original precedence is bounds, axes, provider order, nonzero provider
declarations, placement order, then each placement's part and provider.
The native evaluator sorts unique declared events by axis and identity
and checks the preflight step allowance before constructing event masks
and examining scenarios. Maximums are 16 providers, 112 placements, 48
events, 1,177 scenarios, and 20,777 metered steps. The count comprises
provider/event inspections, provider/scenario inspections, and summaries.
Identical IDs on different axes remain different events. Empty, single,
and paired events follow original ordering, with strict least-support
comparison by (whole-copy present, distinct shards). Ties retain the
first original scenario. No scenario is skipped due to an earlier result.

The result occupies the first 90 output bytes. The initial six bytes are
the original current recoverability, fault survival, minimum shard
count, worst-case shard count, worst-case whole-copy flag, and
worst-case event count. Bytes 6 and 7 are zero. Bytes 8–15 and 16–23 are
the little-endian scenario count and metered steps. Two fixed 33-byte
event slots follow (typed axis followed by original identity); unused
slots are zero. Scratch must be at least 1,328 bytes. Input, output on
refusal, and unused output/scratch suffixes are preserved. A step-budget
refusal may leave the sorted bounded event offsets in private scratch,
but never publishes a report.

No declaration proves identity, independence, possession, current state,
or actual repair capability. No inputs or outputs authorize any live
action or install an allowance. No stores, observation, providers,
networking, credentials, fetching, or reconstruction are involved.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_declared_recovery_placement
```
