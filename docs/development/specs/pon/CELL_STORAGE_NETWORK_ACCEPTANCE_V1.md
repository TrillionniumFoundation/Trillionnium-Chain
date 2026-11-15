# Cell storage network: complete-version acceptance contract

This contract belongs to the [sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It reconciles the five storage mechanisms against the complete-version source
introduced in [the six-capability record](../../../../evidence/cell-six-capabilities-20261108/README.md).
It does not grant custody, payment, installation, consensus or production
authority. Component conformance and operational acceptance are separate.

## Retain an explicit set of complete versions

At an observed owner generation, let `R` contain precisely the versions whose
retention obligation has been committed and has not been lawfully retired.
For each version in `R`, its complete declared dependency closure must be
recoverable under the original storage contract. The closure includes model
weights, base, adapters/experts, router, tokenizer, tensor schema, quantization
and composition rules, runtime configuration, and declared environment files.
The manifest must distinguish required members from historical lineage.

The [TCV1 contract](CELL_COMPLETE_VERSION_V1.md) binds the model dependency graph,
environment closure and exact manifest union. An archive of several versions
does not by itself define a runnable composition or a common tokenizer/ABI.
The union needed for storage accounting is the set of exact content objects
referenced by `R`; the execution owner still selects one complete version and
its compatible composition and router.

The current archive catalog persists release-root duties. TCV1 custody and
continuation pair model and environment observations, but they do not yet form
a persistent atomic owner of `R`. That owner must bind both components to one
generation, preserve pending operations across restart, retain rollback and
successor obligations, and reconcile unknown outcomes before changing `R`.
A transient list or a signed promise is insufficient evidence that those
transactions have happened.

## Content, delta and snapshot semantics

The existing [TCX1 implementation](../../../../trillionnium/crates/trnm-data-availability/src/cell/delta.rs)
names one exact base manifest, embeds the **complete target manifest**, and
assigns every target chunk either its canonical base index or `NEW_CHUNK`.
The output is fully materialized and checked against the target manifest and
ordered payload hash. It is not an executable arithmetic patch. A target does
not require replaying an unbounded chain of earlier delta programs.

Treat a complete materialized target as the recovery snapshot. Version lineage
does not authorize omitting bytes required by the current target. Any future
multi-delta codec needs a separately versioned maximum dependency depth, maximum
cumulative reconstruction work, snapshot trigger and complete-output binding.
It cannot reinterpret TCX1 or silently turn lineage into an execution program.

Report measured exact-byte reuse: total target bytes, reused chunks/bytes, new
chunks/bytes, metadata, actual transferred bytes and reconstruction cost.
Quantization, tensor reordering, compression and fine tuning may change most
chunks; a training label does not establish a deduplication ratio. Keep logical
payload size, unique stored bytes, physical replication and repair headroom as
different quantities.

## Placement and recovery

The [custody observer](CELL_CUSTODY_CONTINUATION_V1.md) counts a complete version
replica only when model and environment are readable at the same original
store and replica slot. Separate incomplete stores do not sum to a complete
replica. Store IDs, endpoint counts and key counts do not establish independent
operators, power supplies, networks, administrators or recovery procedures.

The [RS(6,4) codec](CELL_RS46_CHUNK_V1.md) validates shards and reconstructs from
four correct shards. Its 6/4 encoded-payload ratio does not include metadata,
repair traffic, backups or operational headroom. A shard lifecycle owner still
needs to assign authenticated placements, track missing/corrupt shards, reserve
repair resources, select replacement failure domains, verify actual repaired
bytes, and close the original repair operation exactly once. The codec alone
does not perform those steps.

An acceptance campaign freezes independent control domains, placement, surviving
paths, workload, deadlines and capacity before faults. Include correlated loss,
corruption, slow suppliers, cancellation, exhausted disk/RAM, restart and repair
owner loss. A typed refusal is safe failure; it is not successful retrieval.

## Economy, retention and retirement

Each retained version needs identified payers, funded intervals, challenge
terms, renewal deadlines, repair responsibility and a retirement disposition.
The existing continuation planner preserves the original terms and records
unfunded or missing-sponsor work. It does not transfer money, manufacture a paid
successor, extend an expired lease or execute a repair by returning a plan.

For the current retained set, calculate capacity from the exact content union
and the declared replication/erasure scheme, with explicit metadata, temporary
reconstruction and repair reservations. Forecast funding and capacity over an
explicit horizon. Permanent retention of every historical upload is a separate
unbounded obligation, not an implication of content addressing or deduplication.

The [TCA2 archive owner](../../../../trillionnium/crates/trnm-data-availability/src/cell/archive.rs)
checks every catalog reference before collecting a shared physical object.
Pending, active and expired-but-unretired roots remain protective references.
Loss or corruption does not authorize bypassing them. A future auditable
loss/retirement disposition must resolve outstanding repairs and successor
requirements before releasing those references; it must retain evidence of the
failed duty rather than label damaged data as successfully retained.

## Discovery

The classic and PQ V1/V2 directories retain permanent replay high water. Their
expiry removes advertisement eligibility but does not refund identity capacity.
The [explicit authenticated epoch V3 profile](CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md)
adds finite signed sequence epochs, separate active/history bounds, authenticated
bootstrap identities and query-bound replies. A deployment must explicitly
select the new profile and a fresh directory; opening an old namespace never
silently migrates or clears its replay state.

Discovery leases are location-hint TTLs, not funded storage leases. Query nonce,
source authentication and bounded source shares prevent specific replay and
allocation attacks; they do not prove honest providers, independent operators
or global eclipse resistance. Preserve the original connection, validation,
response-byte and overall-deadline reservation across discovery and payload
retrieval. Unknown/private objects need an explicitly authorized private
discovery policy; authentication does not make metadata confidential.

## Actual loading and the next task

Authenticated V3 discovery currently cold-fetches one pinned TCM1 payload to a
file. Complete-version verification and the RAM loader remain separately
implemented components; this new entry point does not join them into a Hepta
execution loop. In its own prefetch path, the existing RAM owner checks
incremental byte/reference capacity after metadata and before payload transfer,
then admits a complete task-local working set. Its
[local access API](../../../../trillionnium/crates/trnm-data-availability/src/cell/residency/working_set.rs)
checks task identity, supplied current loader pins, original deadline and latched
cancellation, and has no network or disk fallback during hot reads.

Operational acceptance additionally needs one joined trace from actual cold
retrieval through the restricted loader, binary/library/device/ABI dependency
readback, RAM and device admission, installation, current-generation resource
and FinalUse checks, and ordinary execution of the next task. Bind the task ID,
version commitment, consumed tensor bytes, resource receipt and real result.
An API byte view, a checksum alone or a synthetic forward pass cannot establish
the full Hepta owner path. Failed, cancelled, NoUpdate and unknown outcomes must
remain in the same denominator and reconcile without duplicate effects.

## Acceptance register

| Mechanism | Present component mechanism | Remaining qualification |
| --- | --- | --- |
| Content/version | Immutable TCM1 content, TCX1 complete-target delta, TMR1/TCD1/TCV1 closure and CPV3 binding | Actual loader dependency inventory and persistent complete-version retained-set owner |
| Placement/recovery | Complete-replica intersection/readback; RS(6,4) codec and verified recovery | Audited independent placement, shard lifecycle and executed paid repair |
| Economy/retention | Durable release duties, protected shared-object GC, paired renewal/repair work items | Real funding, successor handoff, unknown-effect reconciliation and sustainable capacity |
| Discovery | Explicit authenticated epoch V3 component, finite recovery and original aggregate budgets | Explicit deployment adoption, independent bootstraps, open-network Sybil model and WAN cohorts |
| Actual use | Complete pinned cold bytes, pre-transfer RAM admission, task-local RAM access | Real restricted loader/device and Hepta CURRENT/resource/FinalUse/next-task trace |

The operational gate remains **HOLD_NO_GO**. The existing PN5 campaign requires
at least three independently administered failure domains and at least 72 hours,
with cohort-specific cold/warm, loss, eclipse/spam, churn, renewal, repair,
restart and flash-crowd observations. Keep the original 4-second service contract
and separate 30-second pressure campaign distinct. Report actual p50/p95/p99,
failure counts and full byte/CPU/storage cost without relaxing either contract.
