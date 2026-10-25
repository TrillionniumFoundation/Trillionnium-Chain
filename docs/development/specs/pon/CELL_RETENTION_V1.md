# Native-funded Cell retention v1

Status: development implementation, fresh local namespace. Production activation,
independent custody and prospective model qualification remain false. This is an
implementation of I05 and the storage/repair portion of PN4 in the
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); it does
not replace that plan or the PN5 acceptance campaign.

## Owners and authority

`trnm-data-availability::cell::CellRetentionStoreV1` owns physical byte obligations.
The existing `CellStoreV1` remains a disposable chunk cache. The ordinary Cell
peer protocol and pinned TCM1 manifest verification are unchanged. Neither owner
chooses a model, grants `CURRENT`/FinalUse, verifies independent custody or creates
ledger work.

`trnm-service-settlement::native_budget` owns a separate durable local journal for
six resource lanes. `Node::retain_native_cell` and `Node::repair_native_cell`
compose that journal with the native funding owner and the physical retention
owner. Their funding source must be an actual native Task escrow. Arbitrary
reported balances and provider receipts cannot fund these methods. Release
allocation membership is not inferred from an escrow total.

The ordinary native ledger remains the sole monetary ledger. These methods do
not issue transactions, mint rewards, refund a cancelled task or manufacture a
payment from an ACK. The native payment adapter independently verifies a specific
ordinary transition and its current ancestry before recording payment.

## Physical reservation and immutable contract

Creating a store preallocates its payload arena with `fs2::allocate`, fsyncs it,
and checks actual allocated filesystem bytes. A sparse `set_len` alone cannot
satisfy the reservation. Capacity is 4 KiB aligned, from 4 KiB through 64 GiB.
SQLite metadata/WAL are additional bounded-record overhead, not payload capacity.

The arena has one stable exclusive file lock and exact inode identity. Opens
reject symlinks, truncation, changed capacity/configuration and an unexpected
SQLite schema. The database uses STRICT tables, WAL and FULL synchronization.
This is a fresh namespace; old experimental layouts are explicitly rejected.
Opening never creates, migrates, clears or expires obligations.

A contract freezes all of these fields:

| Field | Meaning |
| --- | --- |
| `operation` | Globally bound target operation identity. |
| `funding_operation` | Exact original M12 claim identity. |
| `manifest` | Full validated TCM1 manifest; manifest identity differs from payload SHA256. |
| `retain_from_height`, `retain_until_height` | Original nonempty service interval. A retry cannot shorten it. |
| `maximum_repair_bytes` | Total independently initiated payload rewrite allowance, including interrupted attempts. |
| `successor` | Optional exact successor store and operation, fixed before ACK. |

`commitment(store_id)` hashes the physical store identity and all immutable terms
under `trnm.cell-retention-contract.v1\0`, with fixed-width fields, big-endian
integers and an explicit successor presence byte. It excludes changing counters
and physical allocation statistics. A native Storage task's output/claim subject
must equal this commitment.

An initial claim reserves at least the payload bytes and
`payload_bytes * (retain_until_height - retain_from_height)` byte-blocks, using
checked arithmetic. The policy and claim have independent finite monetary and
resource caps. Acknowledging initial bytes does not assert that the future
retention interval has already been served.

## Physical effect and crash boundaries

| Durable boundary | Permitted recovery |
| --- | --- |
| No native funding/reservation | Refuse new work. |
| Local budget and physical capacity reserved, no effect intent | Retry the same exact contract; no new capacity is created. |
| M12 intent persisted, no target completion known | Read/reconcile the original target only. |
| Initial copy intent persisted before its first write | Full payload initial cost remains committed even if only a prefix was written. |
| Complete target fsynced but ACK lost | Reread and verify exact target bytes, then persist ACK. Source bytes are unnecessary. |
| Partial target after a failed/unknown attempt | Original operation cannot write again; require a new separately funded Repair operation. |
| M12 completion recorded | Fresh target verification is still required on a retry; a prior ACK cannot hide later corruption. |

`acknowledge` writes at most once under the initial obligation identity.
`reconcile_acknowledgement` has no source/cache argument and cannot copy bytes.
Every successful ACK follows full chunk checks and a full payload hash readback
from the arena. A checksum in the SQLite obligation row is not a substitute for
that physical readback.

Each repair has an independent replay identity. Before a new write it atomically
commits the full payload byte cost and a pending repair record. Failure does not
refund the cost. The same repair identity can only reconcile the target later.
A healthy-target repair also records a terminal zero-byte no-op; later corruption
cannot turn that completed identity into a new write. `reconcile_repair` can
persist such a no-op identity from verified complete bytes, but never writes
payload bytes. Repair records and retired obligation identities are retained;
the configured maximum (at most 4,096 each) includes historical records.

The Native bridge records Storage and Repair in separate lanes and binds the
repair task subject to the original contract, repair operation and repair claim.
Funding and the allowed native height interval are checked from the same owner
snapshot before recording a new intent. Historical Pending/Done operations do
not regain dispatch rights when the chain reorganizes.

The physical owner and native ledger are separate durability domains. A native
reorg or cancellation can remove expected funding after a physical effect has
started. Local reservations do not lock native coins or give a provider finality;
they keep the original costs and replay fences, and the provider bears this
explicit risk until its chosen confirmation policy is satisfied.

## Recovery, reuse and service

`populate_cache` rereads the arena, checks the complete payload, and rehydrates
the ordinary Cell cache. Existing TCP peers can then serve the original manifest
and chunks after the original source file and cache have been removed.

`retire_native_cell` obtains the current height through the Node funding-owner
snapshot; callers cannot supply a height to this composition. Capacity is freed
only after the obligation expires. If the immutable contract requires a
successor, retirement directly opens/checks that actual successor owner and
verifies fresh complete bytes, the same manifest and a service interval covering
the current height. A supplied successor receipt is insufficient. Reorganization
does not undo a physical retirement or restore an old operation's capacity.

An initial-copy or repair readback alone does not produce a Positive resource
outcome. This composition retains the complete original reservations. Native
repair requires a positive CPU ceiling and observes the actual Linux thread CPU
clock. The scope covers funding observation, the physical operation, target
readback and the M12 completion write. It checks the same thread identity, a
monotonic CPU sample and the original absolute wall deadline; unavailable,
regressed or cross-thread samples stop the operation. M09 checkpoints surround
complete chunks, bounded metadata operations and synchronous SQL/filesystem
calls. One such interval can overrun before the next check detects exhaustion;
this is cooperative control, not kernel preemption.

The returned CPU observation covers only the current invocation. It labels a
new physical attempt separately from target-only reconciliation. Recovery does
not reconstruct the original attempt's lost measurement, infer network transfer
bytes from a local cache copy, or refund an unknown cost. Continuous retention
accounting and a durable aggregate CPU budget for operator readbacks still need
their own owner observations. The per-invocation ceiling is not a lifetime sum
over arbitrarily many readback calls. No Positive payment is manufactured from
these observations. Expiry/Unknown remains governed by the M12 journal.

## Trust limits and remaining acceptance work

Filesystem reservation is local backing, not a promise against device failure,
administrator deletion, filesystem compression/deduplication changes or full
host rollback. Row hashes detect inconsistency; they are not an external
anti-rollback authority. The configured host and exclusive owner boundary remain
trusted. Independent replicas and repair fault domains must be qualified by PN5.

The API uses a finite local store and bounded replay history. It does not yet
provide unbounded historical record reclamation, a public discovery market,
continuous availability proofs, an independent economic review or automatic
renewal policy. Test operators and multiple keys on one machine cannot establish
independent custody. Source-preserving migration and governed activation remain
separate PN6 gates.

### PN4/PN5 release-wide duty interface — target

Extending a single-manifest duty to a complete model release is existing I05/I09
work, not an implemented field in this v1 contract or TCR1. M10 supplies the
validated versioned closure; M09 owns bytes/duties, M12 owns the original funded
operation and settlement, and M17 records actual readback. A content hash proves
identity, a successful retrieval proves scoped availability, evaluation owns
model quality, and the existing Hepta owners alone admit CURRENT/FinalUse.

| Target message | Required immutable input / observable output |
| --- | --- |
| `ReserveReleaseDuty` | Original operation/funding claim, closure ID and complete reachable object set, provider/failure-domain declaration, physical byte and byte-time reservation, start/expiry, price/currency/rounding and renewal/repair owner. Return the exact committed duty or a typed refusal before ACK. |
| `ReadReleaseDuty` | Original duty and observation window. Return per-object actual retrieval/readback, corruption/missing set, reserved/consumed resources, current funding ancestry and `Observed`, `Degraded`, `Expired` or `Unknown`; an advertisement is insufficient. |
| `RepairReleaseDuty` | Original duty, separately funded repair identity, permitted target set, shared byte/CPU/disk/connection deadline reservation and successor terms. Return exact rewritten/readback bytes and unresolved debt; an interrupted write reconciles its original identity only. |
| `RenewOrRetireDuty` | Exact old duty, current funding/height observation and separately authorized successor. Return durable renewal/retirement status; an unknown effect cannot implicitly free capacity, refund or re-dispatch. |

The target codec must bind lease extension and cancellation separately from
immutable original terms. Define errors for invalid closure/funding, insufficient
physical reservation, expired/conflicting duty, lost replica, integrity failure,
budget/deadline exhaustion and unknown effect. A budget allowance, ACK, local
inventory or historical payment row cannot be reinterpreted as available coins.
Settlement uses the ordinary ledger transition and ancestry readback; the chain
cannot retroactively undo a completed copy or restore an expired physical slot.

GC/archival target roots include every retained release, unexpired acknowledged
duty, pending/unknown effect, successor handoff, and the versions required by the
declared reorg/rollback horizon. Traverse the full dependency closure with checked
bounds, then recheck roots and duty versions atomically before deletion. Unknown
root/funding state refuses deletion. Cache LRU may evict disposable copies, but
cannot reclaim a promised replica or shared base. Revocation prevents admission;
it does not authorize erasing an unexpired storage obligation or published history.

Before PN5, freeze numeric per-release replica threshold (initial target: three
independent complete replicas), retrieval and repair deadlines, probe/sample
schedule, reservation caps, tariff, renewal lead time and maximum repair debt.
Measure two retained versions sharing a base plus one distinct dependency; lose
the author and one provider, interrupt repair, exhaust funding, fail renewal,
restart and reorganize around expiry/GC. A pass requires complete release
retrieval and restoration to three independent domains within the frozen limits,
zero deletion of reachable promised objects, and exact nonduplicated accounting.
Fail/Unknown duties stay explicit even when aggregate stored bytes look healthy.
Byte-time price and growth/archival funding must cover the declared duration;
all-version storage cannot be inferred from a finite cache or indefinite seeding.
Encryption keys, authorized export and key rotation have separate owners; neither
a retention ACK nor repair grants decryption rights or promises remote deletion.

## Verification entry points

The tests exercise actual allocated files, cold opens, native signed task escrows,
three state backends, branch changes, real child process death after fsync,
failed/unknown prefix copies, no-op replay, separate repair funding, actual CPU
exhaustion during a large repair, refusal across threads, and actual TCP download
after source/cache loss:

```sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --lib cell::retention -- --nocapture
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_cell_ -- --nocapture --test-threads=1
```

These commands are verification entry points, not a claim that an arbitrary
future source revision passed. The current-source evidence receipt records
actual source hashes, commands, return codes and retained failures.
