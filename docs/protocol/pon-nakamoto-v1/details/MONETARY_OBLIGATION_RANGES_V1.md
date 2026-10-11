# Complete monetary obligation ranges — explicit research relation

`pon-monetary-obligation-range-v1` is a separately selected computation relation.
It does not change the sparse state root, the account AAM1 root, any signed
transaction domain, a stored schema, a consensus profile or ordinary Node
admission. The [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
continues to own implementation priorities and external acceptance.

Source owners are
[the range relation](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_execution/obligation_ranges.rs),
[the checked execution owner](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_execution.rs),
[M06](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs), and
[continuity capacity](../../../../trillionnium/crates/trnm-mvcc-fee/src/continuity_v1.rs).
The [native tests](../../../../trillionnium/crates/trnm-pon-node/tests/account_obligation_ranges.rs)
and [independent reader](../../../../formal/pon-nakamoto-v1/obligation_range_oracle.py)
bind actual observations separately from this specification.

## Source authority and the remaining complete-state boundary

The existing state tree hashes keys before constructing its sparse paths. A
membership proof in that tree does not establish that every key with a textual
prefix, or every obligation before a deadline, has been supplied.

This relation first checks the complete parent State, installed context and
archive checkpoint through the existing private `BoundState`. It derives a
separate ordered index over **every non-account row**, including unknown and
retained namespaces. Its order, count and root are rebuilt from those checked
bytes. Raw `RangeProof` fields cannot construct that authority. The parent
`StateCommitment.id` binds network, parameters, genesis, native state root,
account and non-account roots, counts and funds. The proof separately names the
checkpoint, parent branch and parent height.

The new `execute_with_monetary_state_witness` entry accepts AAM1 plus a monetary
range proof. Other non-account rules use the complete immutable parent as an
explicit reference. The owner still constructs the complete non-account
partition for ordinary mandatory cleanup and full-state comparisons. No missing
monetary row is supplied by that reference: the range must verify before M06
starts, and its verified monetary rows become the monetary discovery input.

The anchor is operation-local and not persisted. A supplied index root by itself
has no authority. This is not a partial-State backend or a succinct certificate
of the correctness of an arbitrary index. Full-parent root checks, non-account
index construction, account witness discovery, other cleanup, aggregates and
final roots retain their complete-state costs.

## Exact ordered index

Let the checked non-account rows in ascending UTF-8 key order be
`r[0], ..., r[n-1]`, with `n <= 65,536`. Existing key and canonical value limits
remain 160 and 4,096 bytes. Rank and interval fields below are little-endian
`u32`. Hashing uses the existing length-framed `pon_wire::hash` function:

| Node | Domain | Ordered fields |
| --- | --- | --- |
| Empty index | `monetary-obligation-range-empty-v1` | no fields |
| Leaf at rank `i` | `monetary-obligation-range-leaf-v1` | `i`, key UTF-8 bytes, compact canonical JSON value |
| Interval starting at `first`, length `count > 1` | `monetary-obligation-range-node-v1` | `first`, `count`, left digest, right digest |

Each non-leaf interval splits with `left_count = floor(count / 2)`; the right
interval contains the remainder. There is no padded leaf, duplicate-last rule,
or alternative split. A nonempty full index has `n` leaf hashes and `n-1` branch
hashes. Index insertion can change later ranks and requires a rebuild; no
incremental index-update complexity is claimed.

The untrusted `RangeProof` JSON record has exactly these fields:

```text
schema, parent_checkpoint, parent_id, parent_height, state_commitment,
non_account_count, index_root, rows, frontier
```

Each revealed row contains exactly `rank`, `key`, `value`; each frontier contains
exactly `first`, `count`, `digest`. Hashes use serde's 32-byte arrays. Unknown
fields are refused. Revealed ranks and keys must both strictly increase, without
duplicates. Raw row/frontier counts are checked before full-parent binding;
per-value serialization stops at the existing value bound. The caller remains
responsible for allocations while decoding an untrusted JSON input.

## Completeness includes future and zero obligations

M06 and the proof relation share the four fixed monetary prefixes:

```text
quota:    release:    reward:    task:
```

For each prefix `p`, the proved interval is `[p, upper(p))`, where `upper(p)`
replaces the final `:` with `;`. Every matching row must appear, including rows
that are not yet due, rows whose remaining amount is zero, and immature rewards.
The producer also reveals the immediate predecessor and successor, when they
exist. The union is sorted and each shared boundary leaf appears once.

The verifier establishes consecutive ranks inside every interval and adjacency
to its boundary leaves. Empty intervals require adjacent predecessor/successor
ranks, or the actual first/last edge of the index. No claimed count or absence
flag substitutes for those conditions. Every revealed row must serve a range
or its immediate boundary; extra authenticated rows are refused too.

The frontier is the unique maximal cover of entirely unrevealed subtrees of the
fixed interval tree, in left-to-right traversal order. The verifier refuses
split, overlapping, reordered, duplicate, missing and unused frontier entries,
then reconstructs the source-bound index root. A valid membership proof for an
incomplete subset is insufficient: it still fails the consecutive-range checks.

Proving only the earliest sixteen expiries is deliberately insufficient. Future
tasks, quota/release refunds and reward recipients retain capacity responsibility
even when they produce no immediate account write.

## Actual M06 input and successor responsibility

The private checked range result owns the complete monetary projection. The
explicit `execute_with_authenticated_obligation_input` route passes it to M06.
M06 independently compares that projection to the full original parent before
the first mandatory transition. Thus direct callers of the lower-level API
cannot omit a reward or future obligation by bypassing the range owner.

The verified rows actually supply:

1. The original continuity scan for monetary recipients and the exact reward
   maturity queue, including recipients whose accounts do not yet exist.
2. Escrow expiry discovery, followed by the ordinary `(deadline, key)` ordering
   and installed per-block expiry limit.
3. Reward maturity discovery and the ordinary account-credit operation.

The account gate still requires exact original-parent AAM1 existence or absence
evidence for every semantic account access. Supplied rows select monetary work;
ordinary current-state writes and the checked mandatory callback determine its
actual result. The original full-state route remains the independent comparison.

Contribution/evaluation archives, artifact cleanup, model/factor cleanup and
other non-account rules continue to use their complete State reference. No
prefix allowlist removes those rules. Transactions execute normally after the
checked mandatory callback. The new miner reward is then created normally and
the **complete successor** conservation and continuity-capacity checks still run.
A parent certificate cannot reserve an unchecked new miner, hide new transaction
obligations, enlarge the key limit or waive future archive capacity.

Every old entry passes no monetary range input and emits no new progress events.
The separate relation exposes `ObligationRange { index }` cooperative boundaries
while constructing and verifying its index. Cancellation before output returns
no execution output and publishes no archive or Node change. Hashing and JSON
serialization between boundaries are not preempted.

## Executed fixture and independent verification interface

The retained test `monetary_ranges_execute_signed_expiry_future_capacity_and_reward_maturity_against_native_node`
constructs actual signed transactions under the installed continuity revision12
and native public-evaluation context, mines/admit/activates ordinary Node packets,
and compares the separate research execution against their complete State:

| Height | Transactions and required transition |
| --- | --- |
| 1 | 18 signed transfers fund owners100–117; miner999 has no account and receives an immature reward |
| 2 | 18 signed task reservations; sixteen have deadline3 and two have deadline4 |
| 3 | No transactions; sixteen expiry refunds execute while the two future obligations remain |
| 4 | The remaining two expiries execute |
| 5–20 | Ordinary empty continuation, cleanup and reward-queue transitions |
| 21 | Miner999's first reward matures before its signed nonce1 transfer to owner0 |

There are21 actual blocks and37 signed transactions. These fixture dimensions
are not capacity or throughput measurements. The optional fresh-path environment
variable `TRNM_OBLIGATION_RANGE_VECTORS` exports the complete ordered observations
under `pon-monetary-obligation-range-native-observation-v1`, including original
State, AAM1 bytes, range proof, real mandatory callback State, complete successor,
the packet actually admitted, and source-bound checkpoint/commitment observations.

The independent Python reader rebuilds the full sorted non-account table and
tree without using the supplied membership set, checks complete ranges and the
canonical frontier, independently verifies signed transactions and existing
complete M06 application rules, and compares exact original-parent AAM1 values,
mandatory/final states, roots, deltas, receipts and packet commitments. W1 and
fork choice remain outside that reader's independent scope.

Unit and native negative cases preserve source-valid membership with omitted
due/future/zero/boundary records, empty edge intervals, shared boundaries, hidden
unknown namespaces, non-maximal frontiers, altered ranks/values/order/context,
missing future-account proofs, missing new-miner proof, cancellation and raw M06
projection omission. A separate component fixture checks non-monetary cleanup;
it is explicitly not an injected or admitted Node genesis. The existing
`authenticated_state` libFuzzer target adds the new relation with actual checked
anchors, value/rank/row/frontier/context/JSON mutations and cancellation, while
checking successful execution against its independent complete-state reference.

Execution evidence belongs to the exact tested source, command and artifact.
This document does not establish hosted CI completion, sustained proof serving,
physical data retention, a worst-case time/RAM bound, independent operators,
public availability or production activation.

## Nonempty native quota and release lifecycle regressions

The existing `trnm-pon-node/tests/account_obligation_ranges.rs` fixture now selects
either ordinary or native authenticated Node storage while retaining its independent
complete-State M06 comparison and separate account archive. Original exported task
vectors and their schema are unchanged. Additional ordinary Cargo tests execute:

- Eighteen real signed quota reservations after native funding. Six blocks per
  backend cover sixteen first-height refunds, two following-height refunds, actual
  cleanup and a subsequent signed recipient spend. Omitting a future positive quota
  or a retained zero-balance quota is rejected without changing either store.
- A native attested development evaluation, funded release at height56 and mature
  allocation claim at height76. Seventy-seven blocks per backend compare exact
  packets and state. Both the funded future release and the paid zero release must
  remain in the complete monetary interval; missing rows cannot fall back to the
  checked complete State. The release deadline is not shortened by this test.

Each backend runs actual signatures, work, packet admission, state transitions and
archive projection; no task/quota/release row is injected into a native snapshot.
These fixtures do not establish a full-capacity run, release-deadline expiry, public
model efficacy, independent evaluator custody or prospective gain. The independent
Python task export remains narrower than the added Rust quota/release observations.
