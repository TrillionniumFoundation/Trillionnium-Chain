# Native local terminal cache continuation V2

`native-local-queued-pnx1-v2` is the fresh successor of the finite V1 local pool.
The existing Node SQLite owner still composes M05 typed admission and the exact M06
executor. No second ledger, scheduler, signed task, consensus work or public operation
is introduced. The V1 source, patch and historical evidence are unchanged; their4352
maximum record/removal lifetime is not retroactively labelled as this new behavior.

## Namespace and interfaces

Pool context is `H(native-local-queued-pnx1-v2, network, parameters, genesis,
canonical serialized PoolLimits)`. Group IDs use `native-local-pool-group-v2` over the
ordered signed transaction digests. The metadata table adds fixed8-byte little-endian
`gc_groups`, `gc_records`, `gc_bytes` and a32-byte `gc_head`; the DDL hash therefore
selects a fresh native storage identity. Previous V1 schema is rejected by the read-only
schema probe before table changes or queue import. This is not a hot store migration.

`PoolLimits` and Node enable/submit/batch/reconcile/prune method signatures remain
unchanged. `PoolStatus.gc: PoolGcSummary` adds scalar `evicted_groups`,
`evicted_records`, `evicted_raw_bytes` and canonical64-hex `history_head`.
`pool_status_snapshot` reads these fields without M06 execution. Its active versus
checked parent/generation and stale-classification scope remain explicit. A public
adapter may expose these bounded diagnostics; it must not present them as revocation,
transaction inclusion, finality or source fairness.

## Admission and atomic cache GC

1. Enforce submitted group/member/body bounds and reconcile against actual parent.
2. Preserve exact duplicates and explicit per-raw local removal rejection. Reject raw
   overlap/regrouping and queued nonce conflicts.
3. If retained count plus new raws or retained bytes plus new bytes exceeds the
   immutable policy, examine existing groups in insertion order. Select only whole
   SequenceConsumed/Expired groups whose every member independently has either
   `expiry < next_height` or `nonce <= active_chain_sender_nonce`. A group's aggregate
   status alone is insufficient: one member may be consumed while another is live.
4. Stop selecting once both deficits are covered. Queued, Blocked and partly terminal
   groups remain protected. If protection leaves insufficient space, explicitly reject.
5. Strictly verify the proposed complete pending prefix and new group through actual
   canonical signature/nonce/fee/resource M05 admission and authoritative M06 preview.
   This preview installs no chain state.
6. In one immediate SQLite transaction, fence parent/generation, delete the chosen
   whole cached groups, update bounded GC diagnostics, and insert the entire new
   group/raws. A second-row failure rolls back deletion, metrics and every new row.

GC diagnostics accumulate groups, signed raw records and raw-byte counts with checked
u64 addition; overflow rejects instead of wrapping. Each removed group extends
`H(native-local-pool-terminal-cache-eviction-v2, previous_head, context, parent,
generation_le8, group_id, ordered_member_digests, removed_count_le8,
removed_raw_bytes_le8)`. The empty head is32 zero bytes. This is a local monotonic
summary of committed cache observations, not an authenticated chain certificate or an
all-raw retained history. It survives branch changes and restart.

## Cache versus explicit operator removal

SequenceConsumed only describes active account sequence, not proof this exact raw was
included. Expired describes the current branch's next height. Cache eviction creates
no irreversible local drop and no tombstone. It also promises no automatic requeue:
a source retaining original signed bytes may resubmit them after a fork, and normal
signature, expiry, nonce, funds, fee, removal and capacity checks still apply.

Explicit `pool_prune_terminal` keeps the separate original-raw digest removal history.
Those operator tombstones survive cache GC, reorg and restart and reject the same raw
in any regrouping. The4096-digest maximum is not reset or reclaimed; once full, further
operator pruning is refused. Automatic GC does not consume that finite removal budget.

All retained Queued/SequenceConsumed/Expired/Blocked rows and raw bytes continue to
share configured caps (at most256 records/524288 raw bytes). Cache GC permits continued
admission when actual terminal cache is available, rather than exhausting that budget
solely because old valid transactions passed through the chain. It does not guarantee
capacity when protected groups fill the pool. Growing chain/archive/SQLite/WAL/freelist
physical bytes and synchronous prefix-preview CPU remain outside those logical caps.
No indefinite daemon, wall-clock72-hour run, WAN fairness or physical-disk bound is claimed.

## Actual selectors and evidence scope

`tests/local_mempool.rs` exercises actual signed PNX1, M05/M06, native PNW1 packets,
SQLite and heavier branches. New selectors cover cache-GC resubmission after reorg,
partly terminal and pending-full protection, expiry/byte-only eviction, failed signed
admission and needed-GC plus second-row SQL rollback, and predecessor schema refusal
without database-byte changes. Existing explicit-prune/reorg tests remain in force.

Run the ignored selector
`cache_gc_supports_4500_actual_signed_raws_beyond_v1_lifetime_with_bounded_retained_pool`
explicitly. `LOCAL_POOL_V2_EVIDENCE_DIR` names a new directory for exact signed raw JSONL,
563 native packet files, native store, block receipts and summary. It submits4500 valid
consecutive ledger sequences through an eight-record/eight-times199-byte policy,
activates every eight raws (last block has four), reopens once, and checks actual sender
nonce/balance, receiver balance, caps, GC counters and no operator removals. The bootstrap
maintenance task is zero utility; logical5630-second timestamps are not wall-clock
operation qualification. The candidate and observer source bytes must be recorded by
its runner; an uncommitted engineering run is not clean-source release acceptance.
