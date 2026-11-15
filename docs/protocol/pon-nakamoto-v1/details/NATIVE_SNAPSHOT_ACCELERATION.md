# Bounded authenticated snapshot acceleration

## Runtime contract

The explicitly selected native authenticated backend keeps an ordinary canonical
snapshot for each admitted block. The legacy backend retains its existing
128-height cadence. The original retention query still keeps at most 64
non-genesis snapshots and the genesis anchor. A suppressed pruning write now
fails with `SNAPSHOT_LIMIT` inside the original admission transaction.

This changes a local acceleration policy, not the snapshot encoding, a header,
state commitment, work relation, consensus namespace or admission authority.
Every snapshot read still checks canonical bytes, complete-state rules, the
admitted state root and the authenticated account tree. The existing parent and
new-state readbacks, expected delta comparison, record/history verification,
ancestry checks and final transactional fences remain. A malformed snapshot is
an error, not a silent fallback. Removing optional non-genesis snapshots invokes
the original retained-delta reconstruction path.

The implementation is in `Node::admit_work_checked_with_control`'s original
snapshot insertion block. It does not add a second store or process-global
validity cache. Complete-state reads remain linear in state size. Full history
record verification still walks ancestors; this does not eliminate all cumulative
quadratic history work, bound total persistent history, or accelerate deep forks
whose snapshots have been pruned.

## Why this path

The source-preserving full-capacity phase instrument in PR257 records actual
producer/validator make, admit and activate operations, growth refusal, refund,
reentry/proof, side admission, interrupted reorganization and two cold reopens.
The original x64 source-head and actual-main-merge observations put about 76%
of elapsed time in validator admission plus side admission. These paths otherwise
reconstruct a just-written state from an older snapshot and verify every
intermediate complete account tree. A newer checked snapshot avoids that
reconstruction while the separate full record/history checks remain.

A separate fixed branch-hash packing experiment (PR258) preserved the exact
transcript but showed negligible x64 and about 1.2% ARM64 median microbench gain.
It is not included in this runtime revision and is not a capacity repair.

## Tradeoffs and limits

There are more frequent full-state encodings, snapshot writes and pruning checks.
The previous worst-case retained snapshot count is unchanged, but actual stored
bytes and write amplification can increase relative to sparse snapshots. This
must be measured in complete native admission, not inferred from read latency.
The 65,536-key state bound, 64-snapshot retention, CPU policies, test timeouts and
all consensus/resource/readiness parameters are unchanged. This policy grants no
minimum attack-cost, Sybil fairness, independent operator, model adoption,
physical power-loss, long-term data availability or WAN throughput qualification.

## Native differential and adversarial checks

The original native authenticated owner suite is retained. Five added tests:

- Admit and activate 70 real work blocks, require the exact 64 retained snapshots,
  compare older/pruned states to the legacy reference, cold-reopen, remove optional
  snapshots and reconstruct again without changing the active complete state.
- Suppress snapshot insertion, corrupt the inserted snapshot, or omit the new
  delta via actual SQL triggers; require complete transaction rollback and retry.
- Suppress pruning at the next snapshot beyond the retained bound; require
  `SNAPSHOT_LIMIT`, local-integrity classification and exact rollback.
- Damage an older delta after inserting a newer snapshot; admission must still
  reject through retained history validation and roll back the entire write.
- Alternate complete readback with and without optional snapshots in the same
  original `state_at` implementation. Compare the entire state and every restored
  persistent row. The synthetic fixture adds 1,024 zero-balance accounts; it is
  not the full 65,536-key acceptance experiment or confirmed transaction TPS.

Staged x64/ARM64 qualification ran the original and new owner controls, record
validation, ancestry, migration, cold recovery and strict Clippy. This establishes
candidate-byte evidence only. The final committed source and actual ordered main
merge must run their own four lanes. The original full capacity and 4,105-block
history campaigns and exact Hepta pair remain mandatory. Missing, running,
cancelled and failed results are never inherited as accepted.

See [performance acceptance](PERFORMANCE_ACCEPTANCE.md) for the independent
end-to-end and external-operator requirements.
