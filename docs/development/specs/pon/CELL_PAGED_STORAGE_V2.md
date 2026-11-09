# Cell transport mapping and paged retained storage V2

Status: development candidate; exact-source validation **PENDING** and operational
qualification **HOLD / NO-GO**. This document records implementation contracts,
not successful execution or acceptance. It adds no production activation,
provider payment, independent-custody claim or ordinary Hepta FinalUse authority.
The authoritative work plan remains
[the single project plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

This continuation starts from the storage composition in #836 at
`0746a462e80067b78317597f2fa4bacf5e3db958`. The
[V1 convergence specification](CELL_STORAGE_CONVERGENCE_DEV_V1.md) and its
historical observations retain their original source, scope and results.

## 1. Two distinct limits and two explicit changes

The existing BEP52 V1 binding requires 16 KiB TCM1 chunks. CRP1 separately limits
its complete canonical manifest/chunk union to 128 entries. When every protected
manifest uses that V1 binding directly, their composition can cover at most
`128 * 16 KiB = 2 MiB` of original payload. This is a conditional composition
limit, not CRP1's general payload limit and not its separate 2 MiB metadata limit.

This continuation separates the two responsibilities:

- Derive 16 KiB transport Merkle leaves from actual larger TCM1 storage chunks.
  A larger chunk's ordinary SHA-256 remains its storage identity; it is not
  reinterpreted as a BEP52 subtree root.
- Bind multiple bounded shard-plan pages to one complete protected-set root,
  one exact TCA3 catalog snapshot and the original funding/effect identities.
  Completing a page cannot stand in for completing the protected set.

The existing TCM1, BEP52 V1, CBP1, CRP1, CSP1, TCA3 and M12 encodings and public
meanings remain. New stored/wire data uses explicit profiles and namespaces.

| New profile or envelope | Responsibility | Retained authority |
| --- | --- | --- |
| `cell-bep52-storage-binding-v2` / CBM2 | TCM1-to-BEP52 piece-root mapping | Independently selected manifest, context and mapping pins |
| CBL2 | One 16 KiB leaf and its bounded companion proof | Mapping, manifest, full infohash and exact leaf position |
| `cell-bep52-storage-pinned-tcp-v2` / CBS2, CBA2, CBR2, CBD2 | Explicit peer TCP acquisition of the pinned storage mapping | Original session, owner pins and full payload readback |
| CRR2 | Complete paged-plan root | Current TCA3 inventory, all version commitments, original identities and page pins |
| CRG2 | One canonical range of original shard contracts | Its complete CRR2 root and the original CSP1 slot owners |

The paged family is called CRP2 in API documentation; its actual file magics are
CRR2 for the root and CRG2 for a page. A page is not a CRP1 complete-set claim.

## 2. Actual-byte BEP52 mapping

The implementation is
[bep52_storage.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/bep52_storage.rs).
`CellBep52StorageBindingV2::from_pinned_reader` and `from_pinned_store` check the
owner's TCM1/context pins, every actual storage chunk's length and SHA-256, and
the complete ordered payload SHA-256. The reader also checks exact EOF. Payload
and chunk limits are admitted before reads, and the original deadline covers
construction and final verification. Blocking reader I/O remains cooperative;
this API does not claim kernel preemption.

`from_pinned_mapping` instead imports an independently pinned CBM2 declaration.
It reads no payload. Matching the mapping ID authenticates the selected metadata;
it does not establish that the declared roots were computed from existing bytes.
The acquired storage chunk must still pass its original TCM1 SHA-256 and the
declared BEP52 subtree check before publication.

### Merkle and byte-layout rules

The mapping follows [BEP52](https://www.bittorrent.org/beps/bep_0052.html):

- Leaves hash actual 16 KiB byte ranges with SHA2-256. The final leaf may be
  shorter. Missing leaves are 32-byte zero digests, not the digest of an empty
  input or a zero-filled payload.
- The logical BEP52 piece length equals the TCM1 storage chunk size. It remains
  a power of two between 16 KiB and 4 MiB. Each larger piece root is computed
  from the corresponding transport leaves.
- For a file contained in one storage piece, the file root uses the smallest
  complete binary tree covering the actual leaves. It is not padded to a larger
  declared piece height. Identical file bytes therefore retain the same pieces
  root across supported storage chunk sizes.
- For a multi-piece file, the final piece is padded to the fixed piece height.
  Absent pieces used to balance the upper tree use the zero-leaf subtree root
  at that height. They are not represented by an arbitrary zero piece hash.
- The canonical metainfo contains the `piece layers` dictionary. Files larger
  than one piece include the actual piece roots from the correct layer; purely
  out-of-file padding entries are omitted. A one-piece file has no such entry.
  Exact metainfo comparison checks those roots outside the `info` dictionary.

`leaf_location` derives the payload offset as `leaf_index * 16384`; division and
remainder by the storage chunk size determine the storage index and offset.
The manifest fixes the exact final-leaf length. The peer cannot supply a second
byte layout, an overlapping range or a tensor interpretation.

`verified_storage_chunk` checks one complete original chunk and retains its
small local Merkle tree while borrowing those immutable bytes. Repeated leaf
serving then uses a proof path instead of rehashing the entire chunk per leaf.
CBL2 binds the mapping ID, manifest ID, full infohash, leaf index, leaf count and
the bottom-up siblings. Its shape and zero-padding subtrees are checked.

`CellBep52StorageAssemblerV2` collects verified leaves in original order, keeping
partial bytes private. `finish` verifies both the complete original storage
digest and subtree root. `finish_into_store` publishes only that complete chunk
under the same deadline and existing cache limits. A verified leaf is not a
verified storage chunk, and a verified storage chunk is not a complete authorized
model/environment version. Original complete-content and loader admission still
apply after acquisition.

### Explicit TCP continuation

The separately implemented
[TCP adapter](../../../../trillionnium/crates/trnm-data-availability/src/cell/bep52_storage_peer.rs)
uses `cell-bep52-storage-pinned-tcp-v2`. `fetch_cell_bep52_storage` takes an
already owner-pinned `CellBep52StorageBindingV2` and an explicit bounded peer set.
It never adopts a peer's self-declared CBM2 or treats a magnet as an authorization.

CBS2/CBA2 carry the original operation, manifest, mapping and full infohash.
CBR2 requests one storage index; the response is a sequence of CBD2 frames, each
containing a CBL2 proof and the corresponding actual transport leaf. All leaf
responses for that storage index share one request deadline. Only the complete
verified storage chunk is committed to cache. After acquisition, the original
ordered full payload is read and hashed again before a successful fetch result.
`CellBep52StorageSeedV2::serve_connection` serves a caller-supplied TCP stream;
it does not create a background listener or discovery service.

The non-clone `CellBep52StoragePeerSessionV2` retains the original operation,
mapping scope, deadline, cancellation state and cumulative connection/message/
actual socket-byte allowances. Failed attempts keep their consumed allowance.
Those byte counters include application framing and partial socket reads/writes,
not TCP/IP overhead or bytes never read from the socket. Full download completion
requires the chosen cache to admit the complete payload for ordered verification;
the disposable one-codeword cache below belongs to custody delivery staging.

These Cell frames are distinct from BEP52's native `hashes` peer messages.
Complete BitTorrent interoperability, public swarm discovery, authenticated peer
identity and live WAN behavior are not established by the plaintext adapter.
Exact-source runtime validation remains pending. Local execution is a later
independently authorized step; transport grants no CURRENT, FinalUse, payment or
remote inference right.

## 3. One complete root, multiple bounded pages

The new owner is implemented in
[paged.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged.rs),
with a separate
[codec](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/codec.rs)
and
[file owner](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/file.rs).

`CellPagedRetainedShardPlanFileV2::create` derives the complete protected union
from the actual TCA3 catalog and checks the requested anchor. The root retains
every protected version's original operation, contract and version commitment,
the aggregate retained commitment, the exact canonical manifest union, original
catalog identities, provider configuration, service interval and six original
funding identities for each canonical chunk. Pending or expired-unretired
catalog duties are not dropped to obtain a smaller successful service set.

Chunks are ordered by canonical manifest ID and then original chunk index.
Page index, start and count must partition that one complete sequence without
gaps, duplicates or caller-selected subsets. The root commits every page hash.
Each page also binds a scope digest of the complete root's common fields;
page hashes are excluded from that scope to avoid a circular hash dependency.
The chunk count and page width determine all page ranges.

Construction writes, fsyncs and reads back bounded page files before publishing
the final root. It rejects an existing preparation directory rather than
overwriting partial work with a new plan. Opening an independently pinned root
checks every page and cross-page operation identity. Subsequent page reads
recheck the root and the exact page pin. File and directory checks retain the
original regular-file, no-follow, single-link and opened-identity boundaries.

`read_current` compares the complete root with the current catalog owner. A
catalog change invalidates the previous complete-set assertion; it does not
erase original provider slots, M12 intents, funding identities or Unknown
responsibility. Restoring every owner and external anchor together remains
outside the catalog anchor's rollback protection.

### Bounded acknowledged source reads

New source preparation uses
[the retained-arena chunk reader](../../../../trillionnium/crates/trnm-data-availability/src/cell/retention/payload_read.rs)
through
[the catalog-pinned wrapper](../../../../trillionnium/crates/trnm-data-availability/src/cell/version_retention/chunk_read.rs).
It requires the original acknowledged member, exact manifest and range, reads
the original arena FD, checks the returned chunk bytes and rechecks row/FD and
catalog identity. There is no publisher-cache fallback. This is a fresh check
of that chunk, not a new complete-payload acknowledgement.

Plan construction does not fill a complete source CAS. Native execution uses
`stage_chunk_from_catalog` only when a chunk has an original New effect to
perform; it stages that chunk's six exact codeword payloads. `CellStoreV1` has
hard admission quotas, not automatic eviction. The convenience
`stage_page_from_catalog` accumulates the page's staged contents and therefore
requires sufficient cache allowance; paging alone does not reclaim that space.

The explicit
[CellStoreV1::discard_manifest_until](../../../../trillionnium/crates/trnm-data-availability/src/cell/store/discard.rs)
deletes one supplied manifest ID and the chunk hashes it names, using the
existing TCL4 writer, schema/configuration checks, quota DELETE triggers and WAL
limits. The deletion is one transaction under the caller's original deadline;
missing rows and repeated chunk hashes do not double-decrement counters. Logical
byte and row allowance becomes reusable. SQLite database pages can be reused,
but the database file is not promised to shrink immediately.

This API affects only named disposable cache contents. A named chunk hash can
also be referenced by another cached manifest; that manifest then becomes
incomplete and must reacquire and verify the missing bytes normally. Native
delivery therefore requires a dedicated staging cache. After actual verification
of each chunk's six original provider targets, it explicitly discards that
chunk's staged manifests before proceeding. Original Done reconciliation can
also remove such residue. A failed operation can leave verified cache residue;
discarding it neither erases the original effect nor refunds or renews anything.
No retained arena, funding, lease, repair or retirement record is changed.

## 4. Global native admission and two complete readback passes

The actual entry point is
[Node::retain_native_cell_paged_shard_plan](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged.rs).
It accepts the actual catalog owner, pinned plan file, six original provider
owners, bounded cache, complete canonical native slot requests and the caller's
non-clone `NativeCellRetainedShardVerificationBudgetV1`.

Before the first provider effect, it checks all pages, every original claim,
beneficiary, task source, effect identity and resource lane. Identity and task
source uniqueness are global across pages. M12 preflight checks the whole
composition rather than authorizing the first page before inspecting the last.

Provider admission also checks the complete planned descriptor/history count
and simulates physical first-fit allocations against existing rows, including
fragmentation and unreclaimed promises. Retired rows continue to consume
historical identity capacity. The
[read-only arena preflight](../../../../trillionnium/crates/trnm-data-availability/src/cell/retention/reservation_preflight.rs)
validates the exact schema in its read transaction, clamps SQLite busy waiting
to the original remaining deadline and restores the original busy timeout.
This is an admission observation, not an atomic reservation of every provider;
each actual original reserve still rechecks its state.

For `N` chunks, total encoded shard bytes `I` and total original chunk bytes `B`,
one invocation commits `2*N` verification attempts, `2*I` input bytes and
`2*(I+B)` reconstruction allowance before staging or provider effects. The
commitment is cumulative in the same original budget and remains consumed after
a later failure. These logical codec/read allowances are not measurements of
all SQL work, disk amplification, CPU or WAN traffic.

Execution has two separate complete passes:

1. Stage one needed original codeword at a time and call the existing native
   shard owner for every slot. Only New M12 intents permit source copies.
   Pending/Done intents reconcile original targets. Verify all six returned
   shard bytes and reconstruction of each original chunk, then explicitly free
   its named contents from the dedicated delivery staging cache.
2. Require all original M12 intents to be Done, then independently reread every
   original provider slot and reconstruct every chunk again. Recheck the
   complete catalog and native anchor before returning the full result.

The returned page ranges and slot observations are descriptive results.
No API accepts a caller-constructed page receipt as completion authority.
Final-pass slot observations are Done even on the first successful invocation.
Earlier page success cannot conceal a missing final slot, a changed catalog or
an unresolved original effect. The result describes sequential actual reads,
not simultaneous uptime or a promise of future service.

The complete request/claim metadata and final observation metadata remain in
memory. Payload processing is limited to one source chunk/codeword at a time,
with its six shard buffers and codec working buffers; this is not a claim of
constant total memory or a 4 MiB process RSS ceiling. Existing cache quotas must
admit the currently needed codeword, including its manifests and database/WAL
overhead. Successful explicit disposal makes its logical quota available for
the next codeword. No quota, deadline or source identity is reset when advancing
a page or reopening an owner.

## 5. Actual finite bounds

| Bound | Current value | Interpretation |
| --- | --- | --- |
| BEP52 transport leaf | 16,384 B | Last leaf may be shorter |
| TCM1 storage chunk | 16 KiB through 4 MiB, powers of two | Existing TCM1 semantics retained |
| Storage pieces in one TCM1/mapping | 16,384 | At 4 MiB each, a conditional 64 GiB single-manifest structural ceiling |
| CBM2 bytes | At most 524,340 B | 52-byte header plus 16,384 piece roots; no payload |
| CBL2 bytes | At most 813 B | 109-byte header plus at most 22 sibling hashes |
| Complete CRP2 canonical union | 4,096 chunk entries | Existing TCR1/CSP1 historical admission limits still apply |
| Chunk entries in one page | 1 through 128 | Page width also determines total page count |
| Page count | At most 256 | A narrow page width can become the earlier limit |
| CRR2 root metadata | At most 2 MiB | Independent of page and payload bounds |
| One CRG2 page | At most 2 MiB | Complete encoded original slot descriptors |

The CRP2 union therefore has a conditional payload ceiling of
`4096 * 4 MiB = 16 GiB`, when every counted chunk is full size. It is not a
guarantee that every such union is admissible. Root/page metadata, TCA3 catalog
and contract limits, protected roots, actual arena extents, historical rows,
descriptor history, native funding records, cache quotas and original deadlines
can impose tighter bounds. Paging does not claim support for arbitrarily large
versions and does not enlarge the old CRP1 array limits.

The canonical union deduplicates identical manifests before enumerating their
chunk coordinates. Equal serialized bytes can be reused by the existing CAS;
that does not cancel independently funded slots or prove a physical deduplication
ratio. Fine-tuning, quantization, tensor ordering and container metadata can all
change byte reuse. Report actual unchanged byte/chunk identities and actual
logical/physical allocation for the selected representation.

## 6. Unknown responsibility, repair and operational policy

A lost response, interrupted copy or repair retains its original identity and
irreversible charges. An Unknown or Pending effect cannot obtain another copy
by changing a page number, reopening a plan or supplying a populated cache.
Settlement, renewal, retirement and successor responsibility remain with the
existing native funding and physical owners. New page metadata creates no
escrow, payment, refund, lease extension or retirement authority.

RS(6,4) can reconstruct an original chunk from four distinct validated available
shards. The ratio 6/4 describes encoded payload redundancy only; headers, 4 KiB
allocation, metadata, repair traffic and operational headroom add costs.
Six directories or declared domain identifiers do not establish six independently
administered failure domains.

### Explicit complete paged recovery

`retain_native_cell_paged_shard_plan` requires every original target to be
readable. The separate
[Node::recover_native_cell_paged_shard_plan](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged_recovery.rs)
provides an explicit CRP2 recovery path using the original native single-slot
repair owners. CRP1 recovery retains its existing implementation and limits.
The new call neither generates repair identities nor starts a background repair
policy. Its source and tests are present; exact-source runtime validation remains
**PENDING**.

`NativeCellPagedShardRecoveryRequestV2` contains `storage`, the complete original
canonical slot request set, and `repairs`, one optional original repair request
per slot in the same order. `None` grants no repair authority. Every storage M12
intent must already exist as Pending or Done; recovery cannot initiate original
storage or obtain catalog/publisher bytes as a repair fallback.
`NativeCellPagedShardRecoveryBudgetV2` is a non-clone cumulative owner constructed
from `NativeCellShardRecoveryLimitsV1`, with `usage()` and `codec_usage()`.
`NativeCellPagedShardRecoveryReadbackV2` reports the full plan/catalog/retained
pins, final funding observation, page and slot observations, detected damage,
repair actions, committed allowance, actual codec usage and CPU observation.
Failures return the original usage and completed actions through
`NativeCellShardRecoveryFailureV1`; unknown CPU measurement is `None`, not zero.

The
[global recovery preflight](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged_recovery/preflight.rs)
first checks complete page coverage, all original catalog identities, storage
and repair funding/effect bindings, beneficiaries, distinct task sources,
original replay states and provider descriptor/history/extent capacity. It then
checks the current catalog and funding anchor. Only after this admission does
the caller's original recovery budget commit the complete attempt allowance.

Let `S` be the total original slots, `W` the sum of their encoded shard bytes,
`B` the original source bytes, `A` the number of supplied repair requests and `R`
their total encoded shard bytes. One admitted attempt reserves:

| Allowance | Complete-attempt reservation |
| --- | --- |
| Provider observations | `3*S + A` |
| Target and codec input bytes | `6*W + R` |
| Reconstruction bytes | `3*(W+B)` |
| Possible new repairs and bytes | Every supplied repair whose original M12 state is New, including an authorization that later proves unnecessary |
| CPU | The full original per-attempt ceiling |

The codec capacity admits at most three reconstructions per canonical chunk per
plan attempt. These are cumulative logical reservations, not measured filesystem
or SQL amplification. Admission does not construct another budget at a page
boundary or after reopening owners. A later failure retains its admitted
allowance; a failed preflight or unaffordable projection admits no new attempt.

The
[recovery execution](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged_recovery/execute.rs)
performs three complete target scans:

1. Read every original target on every page. Each chunk needs at least four
   distinct actual valid shards and passes full source/codeword verification.
   Missing authority or insufficient quorum on the last page prevents every
   new repair. Original acknowledgement reconciliation may seal already-written
   bytes during this census; it neither copies payload nor authorizes repair.
2. Before repairing, check the complete census copy set against every provider's
   original repair-byte and history capacity. Then reread each chunk and call
   the existing native single-slot repair owner. Only census-damaged slots with
   independently funded New repair intents may copy reconstructed bytes.
   Pending/Done repair intents take their original target-only path. New damage
   after the census cannot expand the admitted copy set.
3. After all repair actions, independently reread all original slots and verify
   every complete codeword again, including pages that required no repair.
   Then require all original storage M12 intents to read back Done, and recheck
   the complete current catalog and the unchanged funding anchor.

The
[read-only repair-capacity preflight](../../../../trillionnium/crates/trnm-data-availability/src/cell/retention/repair_preflight.rs)
audits exact schema, original extents, repair rows and byte conservation in a
read transaction. Pending charges and zero-byte reconciliation history remain
counted. It clamps and restores the original SQLite busy timeout and reserves
no physical state; each real repair still rechecks the original owner. An
existing physical repair identity never grants a fresh copy.

Reconstruction uses actual original provider shards. At most two missing shard
payloads per chunk enter the dedicated disposable staging cache. Each CSP1
shard manifest names one cache chunk, so two chunk rows and two manifest rows
can serve this path when their byte/database/WAL quotas also suffice. After
each chunk, all six named staging manifests are explicitly discarded, including
residue from an earlier completed repair. Complete request, page and damage
metadata still scales with the protected set; payload processing remains per
chunk. A failed attempt can retain disposable residue and all original charges.

A final slot's `native.replay` can truthfully remain Pending if that final read
reconciled an existing original storage intent. Success depends on the later
durable check that **all storage intents are Done**, plus fresh complete target
verification and the current catalog/funding checks; it does not rewrite a
Pending admission observation to Done. The result establishes sequential current
observations, not future uptime or settlement of omitted historical repair
responsibilities. An old Unknown repair can only reconcile its original target;
an independent new repair authorization never erases that old responsibility.

### Operational qualification

Hot Cell replicas, cold-history erasure coding, batched prefetch, hotspot
replication and bounded caches remain explicit operating-policy choices. This
continuation activates no autonomous placement, renewal, repair or cache policy.
Independent provider administration, offline-publisher retrieval, paid renewal,
repair and exit under one original budget still need their own observations.

As the [IPFS persistence documentation](https://docs.ipfs.tech/concepts/persistence/)
explains, content addressing does not itself guarantee persistent availability;
retention and the continuing cost of pinning remain separate responsibilities.
The same distinction applies to Cell identities and these page commitments.

The immediate execution boundary remains download, complete byte/context
verification and separately authorized local loading. Remote pipeline inference
and transport of intermediate activations are a different communication and
trust problem. They need their own resource model, independent evaluation and
malicious-node assumptions; they are not enabled by successful weight download.

## 7. Validation and unresolved acceptance

Exact-source validation is pending. The added tests specify cross-storage-size
Merkle agreement, short-file and tail padding, independent mapping pins,
complete storage publication, catalog-derived cross-page coverage, original
arena reads, complete native funding preflight, source-free reopening and
Unknown target reconciliation. Disposable-cache tests exercise actual quota
reclamation, repeated hashes, reopening with the original limits, and the safe
reacquisition of a shared chunk made missing by explicit disposal. TCP tests
exercise real loopback streams, original session budgets and refusal paths.
Paged recovery tests exercise actual cross-page target damage and reconstruction,
a two-row staging quota, complete last-page authority/quorum/capacity refusal,
original Pending/Done responsibility, reopening and cumulative/CPU boundaries.
Their presence is not a successful run.

Before changing that status, retain the actual exact-source build/test outcomes,
locked Cargo graphs, original regressions, formatting, strict Clippy and related
source/link checks. Interrupted builds and failed observations remain failures;
they cannot be counted as executed tests or inherited from #836's earlier source.

The original service, pressure, History and independent WAN requirements remain.
Long-term independent custody, actual provider payment/renewal/repair, ordinary
Hepta local authorization and FinalUse, and autonomous CRP2 repair policy remain
separate open obligations. The explicit local recovery implementation does not
establish those operational claims. Component acceptance cannot activate those
capabilities or change production qualification from HOLD / NO-GO.
