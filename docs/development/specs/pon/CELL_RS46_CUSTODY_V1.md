# Cell RS46 custody and cache recovery v1

## Scope

This component extends the existing [RS(6,4) chunk codec](CELL_RS46_CHUNK_V1.md)
with an independently pinned codeword, explicit declared placement identities,
and bounded recovery from damaged shard readbacks. An optional operation writes
the recovered **original chunk** to the existing local CAS and verifies actual
readback under an independently pinned TCV2 content commitment.

The implementation is in
[erasure/custody.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/custody.rs).
It does not change CRS1, TCM1, GF(256), the generator matrix or the original
codec's rejection of corrupt required or extra shards. It grants no execution,
storage funding or payment authority.

## Fixed codeword commitment

`CellRs46CodewordV1::from_verified_chunk` first validates the original chunk
against `CellRs46ChunkBindingV1`, then encodes all six CRS1 shards and commits
their domain-separated IDs. CRC1 is exactly 268 bytes; integers are big-endian.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 4 | `CRC1` |
| 4 | 32 | Original TCM1 manifest ID |
| 36 | 4 | Original chunk index |
| 40 | 4 | Original chunk length |
| 44 | 32 | Original chunk SHA-256 |
| 76 | 192 | Six complete CRS1 IDs, in shard-index order |

The fixed namespace selects the existing `cell-rs46-chunk-v1` profile. The
codeword ID is SHA-256 of `trnm.cell-rs46-codeword.v1\0` followed by the complete
CRC1 wire; `\0` denotes one zero byte. All six IDs must be nonzero and distinct.
This digest is not a signature or a post-quantum authorization.

`decode_pinned` requires both the original independently pinned TCM1 binding
and the expected complete codeword ID. Exact wire length, namespace, original
source fields and all six shard commitments are checked. A descriptor's own
hash cannot replace the original source pin.

## Repair admission and verification

`repair_chunk` accepts four to six `CellRs46ShardInputV1` readbacks in strictly
ascending request-slot order. Duplicate, reordered and out-of-range request
slots are refused. The request slot is distinct from the untrusted CRS1 header.
Every supplied wire is bounded before copying or hashing untrusted shard bytes.

After admission, each readback must match its request slot, original source
fields and pinned CRS1 ID. Malformed, damaged and wrong-slot readbacks are
recorded as rejected slots. At least four verified shards are required; the
implementation does not search different four-shard subsets to hide corruption.
The existing codec verifies original source SHA-256, zero padding and extra
verified shards. The recovered source is then encoded again, and **all six**
resulting IDs must equal the codeword commitments before a repair result returns.

`CellRs46RepairV1` records verified, rejected and missing slots, exact replacement
CRS1 shards, recovered source bytes and reservation snapshots. Its ordinary
`repair_chunk` path performs no storage write and leaves
`cache_readback_observed()` false.

## Actual CAS publication and strong content checks

`repair_chunk_to_cache` composes recovery with a `CellRs46CacheTargetV1` containing
an existing `CellStoreV1` and a `PinnedCellVersionContentV2`. The latter is created
only by TCV2 `pin_for_owner`, which checks the complete loader metadata context
and independent 64-byte content pin. The pin must come from the actual owner;
constructing this metadata view is not itself a signature or execution grant.

The operation performs these steps under the same original repair budget:

1. Complete the pinned RS46 repair described above.
2. Reserve the full potential CAS write and readback allowance.
3. Call the pinned TCV2 `verify_chunk` for the original manifest ID and chunk
   index. This checks the strong SHA-512 chunk commitment before a CAS write.
4. Call existing `put_chunk_with_deadline` with the original chunk declaration
   and original repair deadline. Existing immutable CAS quotas and transactional
   write rules remain in force.
5. Read actual bytes with `chunk_with_deadline`, using that same deadline.
6. Recheck the actual chunk against the pinned TCV2 record, exact equality with
   the recovered bytes, and the original deadline before returning success.

Only this successful path sets `cache_readback_observed()` true. This is a
historical observation of one local original chunk. It does not publish a
complete manifest/version or write the six CRS1 shards to provider storage.
Future mutation, eviction or loss requires another admitted observation.

A valid CAS write may commit before a later readback or deadline failure.
Such a call returns an error and no successful observation; it does not erase
the valid chunk or roll back unrelated cache data.

## Original deadline and cumulative logical budgets

`CellRs46RepairBudgetV1` has one immutable absolute deadline and cumulative
attempt/input/reconstruction allowances. It has no cloning or reset API.
`new_with_cache` explicitly adds a cumulative cache allowance; ordinary `new`
grants zero cache allowance.

Let `S` be the original chunk length and `W = 81 + ceil(S / 4)` the canonical
CRS1 wire length. A repair reserves one attempt, the sum of supplied wire lengths,
and `S + 6 * W` potential reconstruction bytes before untrusted shard decoding
or hashing. The fixed descriptor/pin and shape prechecks precede this reservation.
CRC1 header bytes are not part of the shard input counter.

After successful reconstruction, CAS publication must additionally reserve
`2 * S` bytes before the strong chunk check or any CAS operation. This covers
one full potential payload write plus readback. A smaller remaining allowance
refuses publication; the completed repair's debits remain spent. Strong-pin,
quota, write or readback failure also retains every admitted debit. Retrying with
the same budget consumes remaining allowances without refreshing the deadline.

These counters measure potential logical work. They do not measure disk sectors,
database keys/pages, WAL/SHM, filesystem overhead, peak RAM, CPU time or network
traffic. They are not durable debits, fees, prepaid capacity or payment receipts.
Existing CAS quotas account for their own storage representation separately.

The deadline is checked between bounded operations and before success. Existing
CAS calls receive that absolute deadline and may apply an earlier writer limit.
Filesystem, SQLite and hashing operations remain cooperative; this is not
preemptive cancellation or an elapsed-time/WAN service guarantee.

## Declared placement policy

`CellRs46PlacementPolicyV1` binds the complete codeword ID and exactly six ordered
placements. Every slot contains provider ID, responsible owner, administrator,
failure domain, domain evidence and repair owner. All identities are nonzero;
provider, responsible owner, administrator and failure-domain IDs must each be
distinct across the six slots.

Its ID is SHA-256 over `trnm.cell-rs46-placement-policy.v1\0`, the codeword ID,
then each one-byte slot index followed by the six 32-byte identities above.
`verify_pin` checks both independent policy and codeword pins. Distinct declared
digests do not prove distinct machines, operators, administrators, networks or
legal entities. No automatic placement or provider authentication occurs here.

## Controls and remaining qualification

The [native tests](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/custody/tests.rs)
include independent CRC1/placement vectors, every four-shard subset, every pair
of damaged shards, three-damage refusal, malformed/wrong-slot responses, original
source and all-six-ID fences, budget/deadline persistence and 4 MiB source bounds.
CAS controls exercise two damaged shards followed by actual write/readback and
close/reopen, a changed strong chunk digest with unchanged legacy IDs refusing
before any write, storage quota refusal retaining debits, and explicit cache
allowance/deadline refusal.

Public independent custody, continuous/background repair, independent owner and
failure-domain evidence, provider shard write/readback, persistent operation and
payment ledgers, long-term capacity and original WAN qualification remain open.
The complete-release lease and continuation observer remains separately governed
by [Cell custody continuation v1](CELL_CUSTODY_CONTINUATION_V1.md); late release
observations cannot produce continuation plans.
