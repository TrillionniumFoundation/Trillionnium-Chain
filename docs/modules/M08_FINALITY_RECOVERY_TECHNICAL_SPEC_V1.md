# M08 Finality / Node Commit / Recovery technical specification v1

Status: **strict pre-handoff receipt and bounded first-epoch durable bridge implemented;
multiple-epoch/default-node integration pending; production activation not granted**

Primary module: M08. Producers: M02/M03/M06/M07. Consumers: M02/M03/M13/M14/M15.

## Later checkpoint before joint signatures (M08-LATER-PREHANDOFF-V1)

The later checkpoint must commit before either handoff signer consumes its
role. Requiring a completed joint certificate to commit that checkpoint creates
a cycle with signer retirement's committed-checkpoint prerequisite. The explicit
schema13 candidate splits these durable operations; schema10 bytes and its
existing complete-certificate entry point retain their original meaning.

Migration starts only from an exactly pinned, audited schema10 owner, adds one
closed-schema pre-handoff table, and changes no application head or sequence.
Ordinary open never migrates. The new commit accepts the owner's genuine
prepared checkpoint P, the original two-seal finality bytes, next-configuration
preimages and the exact handoff descriptor. It reconstructs the authenticated
predecessor prefix and committed C-1 ancestry from the local owner; strictly
verifies the contextual proof through M01 with the caller's shared work meter;
joins the full checkpoint/header/P, native roots and deterministic cutoff
selection; then commits P, metadata, active old-epoch context and the original
pre-handoff evidence in one parent/sequence CAS transaction. No handoff signature
or next-epoch anchor is required or synthesized.

The returned non-cloneable receipt binds owner, checkpoint P/artifact/overlay,
commit sequence, full evidence digest and M01's strict contextual pre-handoff
binding. It proves committed native execution and original finality, not signer
custody, Core application acknowledgement or epoch activation. Fresh readback and
cold recovery independently repeat these joins. A foreign owner, stale parent,
different descriptor, proof or configuration, invalid nested signature, missing
row, excessive allocation/work, or ambiguous committed checkpoint rejects.
Exact retry returns the same commit sequence; conflicting retry never repairs
or overwrites evidence. Preparation rows cannot become committed receipts.

Only a later explicit attachment accepts the completed original joint kernel.
It revalidates the retained pre-handoff evidence and both signer roles, derives
the exact successor edge using the existing contextual verifier, and atomically
inserts the existing finality/edge records. It does not reexecute or recommit C,
advance the native sequence, create signatures, or acknowledge Core. An absent
joint kernel leaves a valid committed old-epoch checkpoint with no successor
edge. Original pre-handoff evidence remains immutable after attachment.

The physical record is bounded before blob allocation: at most 32 records,
64 MiB aggregate evidence per record, 4 KiB headers/descriptor/commitment/
parameters, and 1 MiB validator set. M01 admission additionally enforces its
caller-owned aggregate root limit (at most 8 MiB); the physical ceiling cannot
enlarge that cryptographic admission budget. Cold inventory must reject a committed
checkpoint with neither its original complete-certificate record nor an exact
schema13 pre-handoff record, and must reject disagreement when both exist.
Creation/commit/attachment use existing namespace, lock, rollback-journal,
database/directory fsync and immutable readback rules. Actual tests must exercise
commit without joint signatures, recovery before attachment, genuine attachment,
exact retry, altered evidence, foreign ownership and real process-death cuts.
Schema13 read-only export follows M08-PREHANDOFF-EXPORT-V1 below. Import and
default-node activation remain separate consumers until explicitly joined and tested.

### Read-only schema13 compatibility (M08-PREHANDOFF-EXPORT-V1)

The existing finality-path, NHR1 history and current-live exporters accept only
the explicit physical schema10 or schema13 inventories. Schema13 uses the same
audited original-proof ledgers, parent walk, byte/work ceilings, namespace lock
and fresh readback as schema10. The finality path reports its actual physical
schema version; NHR1 and current-live encodings remain unchanged. A migration
must preserve every previously exportable path and its original proof/body
bytes. Missing historical proof rows remain unavailable after migration.

A newly committed pre-handoff checkpoint has no complete checkpoint-finality
ledger row until attachment. Exporting a finality/history path through that
checkpoint therefore rejects; the pre-handoff receipt cannot stand in for its
joint certificate or successor activation. Once attachment has independently
verified both signer roles and retained the existing full records, export uses
those original records. Current-live export is inert state data and may read
the committed old-epoch checkpoint before attachment; it grants no verified
finality, successor context, installation or signing authority.

M15's existing retained-proof consumer accepts exactly schema tags 10 and 13
as local-storage metadata, then runs the same independent M13 anchor and proof
verification. Every other tag rejects before cryptographic work. Required
regressions cover real available history and live-byte preservation across
migration/cold open, unchanged refusal of legacy missing proofs, refusal before
attachment, successful original-proof verification after attachment, and
unsupported schema tags. Schema12 import, protocol bytes and default feature
closure are unchanged.

## Authority

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` first. Frozen
`bft-v0` defines votes and three-chain finality; `pcc1` defines a candidate
composition, not a new wire version. M08 coordinates ordered application commit,
finalized receipt publication and restart convergence. M02/M03 remain the sole
consensus/Safety authorities. M08 cannot choose a fork, create signing authority,
change validity, or replace a verified proof with a stage label.

## Interfaces

The interfaces below are operation requirements, not newly frozen Rust types,
wire tags or constructors. Bind each operation to the selected exact source
symbol and accepted schema before enabling it. The historical candidate
`Prepared` through `OutboundPublished` ledger labels are inert observations;
they are not one production lifecycle for both votes and finalized receipts.

The signing operation binds chain/validator identity, epoch/view/block, exact
SignIntent bytes, Safety decision/revision, generation and signer watermark.
The finalized-application operation separately binds the commissioned proof
context, expected oldest target and parent, pre/post application roots, prepared
execution plan, finality bytes, ledger sequence and checkpoint predecessor.
The strict candidate seam is `trnm-native-execution-v0/src/pcc1_finality.rs`;
its verified proof/target is necessary but is not full checkpoint or publisher
integration. Opaque caller digests and telemetry cannot construct capabilities.

### Owned restart and Order-application packages

| Owned package / exact source APIs | Existing authority and planned integration | Rejection and acceptance contract |
| --- | --- | --- |
| `trnm-core-restart-v0`: `CheckpointCandidateV0::admit_quorum_certificate`, `CheckpointStoreV0::{commit,restart_disposition,verify_current_quorum_certificate,install_state_sync,install_state_sync_after_quorum_recheck}` | Existing narrow boundary verifies a weighted QC against the live set, binds an `ApplicationHeadV0`, appends a hash-linked predecessor-CAS checkpoint and checks the snapshot on reopen. `RestartDispositionV0` is `Empty`, `Ready(record)` or `NeedsStateSync(record)`. Its `QuorumCheckpointProofV0` is QC authority only; `Ready` is readiness for this store, not three-chain finality or node activation. M08's strict finality and independent owner checks remain mandatory. | Preserve `CoreRestartError::{InvalidCertificate,InvalidLog,CasConflict,StateSyncMismatch,EpochTransitionRequired,Io}`. Cross-epoch remains rejected until an explicit authenticated edge adapter exists; never remove this guard merely because height increased. Current limits are chain ID 128 bytes, QC 8 MiB, snapshot 16 MiB and log 64 MiB. Test forged/insufficient QC, exact idempotent commit, stale CAS, corrupt/truncated log, missing snapshot, wrong bundle and stale proof after checkpoint change. |
| `trnm-poco-order-application-v1`: `preview_order_block_v1`, `revalidate_prepared_order_block_v1`, `recover_order_application_parent_v1`, `revalidate_recovered_order_application_parent_v1` and G2 manifest-bound sealing | Inert exact-parent AI-native Order preview accepts empty/no-op or deterministic immutable object-kind-50 creates, derives sparse-JMT application root and seals all eight header roots. `PreparedOrderBlockV1` and `RecoveredOrderApplicationParentV1` are private, non-Clone planning carriers, with no commit method. M07's canonical Order store supplies/reopens parents; M13 proves finality; M15 joins the separate finalization owner before M07 may apply. G2 input commits its manifest before the containing candidate ID exists. | `OrderApplicationErrorCodeV1::{InvalidParent,InvalidBinding,SelfCandidateBinding,NonCanonicalOrder,DuplicateObject,ArithmeticOverflow,RootMismatch,PlanMismatch,RecoveredParentInvalid}` reject the candidate without durable effect. Preserve exact source CEV1 field/order/domain rules from M00. Test empty root/no-op, sorted and duplicate creates, replaced recovered leaf, mismatched eight roots, self-candidate binding and compile-fail clone/commit attempts. v0 sparse C+3 epoch support below does not activate a CEV1 epoch protocol. |

The restart adapter does not upgrade a single QC to a finality certificate.
An integration which advertises finalized recovery must first obtain this
module's exact oldest-target strict proof and committed application readback;
then it may persist the narrower restart checkpoint as one recovery component.
Order preview is bounded by its enclosing authenticated draft execution
profile: validate operation count/total bytes before allocating JMT leaves,
with no production fallback when that profile is absent. Neither package owns
signer custody, SafetyRules or networking.

### Existing strict commit/read surface

`DurableNativeApplicationV0` supplies the methods in
`trnm-native-execution-v0/src/pcc1_finality.rs`:
`commit_poco_finality_bytes_v0` and `read_poco_finalized_bytes_v0`.
They bind `FinalityExpectationV0` to exact block/height/state/receipt/evidence
roots and authenticated parent before accepting `poco-three-chain-v0` proof
bytes through `decode_verify_finality_proof_strict_v0`.
`PocoFinalityCommitErrorV0` preserves strict-proof and durable-store failures;
`PocoFinalizedApplicationReadV0` joins readback with strict finality.
A valid proof for a PREPARED row remains insufficient to return committed state.

### Prepared checkpoint execution readback

`confirm_prepared_checkpoint_execution_v1(&prepared, &NativeExecutedBlockV0)`
returns private, non-Clone `PreparedCheckpointExecutionReceiptV1` only after
fresh actual PREPARED/COMMITTED P readback, exact canonical header/body/receipts,
all roots, owner/path and original bound journal checks. It borrows the live
preparation and exposes `validated_commitments`, `durable_row`, header, old/new
configuration and next commitment. A preview or manually constructed execution
value without an actual matching P fails. M02's existing linear validation/
application-seal authority must consume these facts through its own callback;
this receipt neither votes nor treats PREPARED as committed.

### Implemented pre-certificate receipt; planned persisted retention

M02/M03 need a native checkpoint receipt **before** either handoff role signs.
The existing `PreparedNativePocoCheckpointV0` is not a committed receipt;
`ConfirmedNativePocoCheckpointV0` already requires the joint certificate and
cannot authorize constructing that certificate. The separate owner capability
now exists in `trnm-native-execution-v0/src/poco_checkpoint.rs`:

```text
DurableNativeApplicationV0::confirm_pre_handoff_checkpoint_v1(
  prepared: PreparedNativePocoCheckpointV0,
  raw_checkpoint_two_seal_finality: &[u8]
) -> Result<PreHandoffCheckpointReceiptV1>
```

Construction is private to the commissioned native/application owner; caller-provided JSON,
roots, receipt bytes or proof-status booleans cannot construct the capability.
The call rechecks the actual COMMITTED row, exact checkpoint prepared execution,
canonical body/roots, complete old-set checkpoint→seal1→seal2 proof, finalized
cutoff projection and freshly recomputed next commitment. No joint certificate
is an input. New-only validators reconstruct their own authenticated application
state/readback before obtaining their local capability. The receipt is non-Clone,
retains owner-affine committed readback and exposes shared checkpoint/configuration
facts. The actual signed SQLite test obtains it without supplying any joint
certificate and rejects corrupted old-set proof bytes. It is not a signing permit.

Planned persisted receipt layout, in exact local order:

| Field | Encoding / invariant |
|---|---|
| magic, schema | ASCII `TRNMCHK1`, u16-be 1; local format only. |
| operation_id, namespace_id | Two Hash32; exact commissioned owner and immutable intent identity. |
| genesis_hash, chain_id | Hash32 and CEV0 ConsensusString; independently trusted. |
| old_epoch, checkpoint_height | Two u64-be; checkpoint C derived from old parameters. |
| checkpoint_block_id, prepared_artifact_digest | Two Hash32; exact existing durable P artifact and header. |
| application_version, commit_sequence | Two u64-be; version=C; sequence is the checkpoint's immutable local durable commit ordinal, distinct from consensus height. |
| state_root, receipts_root, evidence_root, payload_root | Four Hash32 matching execution and signed header. |
| runtime_profile_hash | Hash32, epoch-authorized deterministic execution context. |
| cutoff_height, cutoff_block_id, cutoff_state_root | u64-be, Hash32, Hash32; independently finalized exact cutoff. |
| next_commitment | u32 length plus unchanged canonical `NextEpochCommitmentV0` bytes. |
| old_set, old_parameters, checkpoint_finality | Three u32-length-framed exact existing canonical preimages. |
| integrity_checksum | SHA-256 of all preceding local bytes; no new consensus domain. |

This is a planned **local retention format**, not a peer `EpochHandoffProof` or
signature preimage. All framed lengths are bounded by M00's authenticated
limits plus the selected complete-record cap; require EOF and exact re-encoding.
Reopen reconstructs authority only after fresh application/cutoff readback and
strict verification; its checksum cannot establish freshness. Local namespace,
sequence and receipt checksum need not match other validators' local receipts;
their verified consensus/root/configuration facts must match.

### Implemented edge and bounded durable installation

The current construction is
`ConfirmedNativePocoCheckpointV0::into_epoch_application_edge_v1()` after
`confirm_poco_checkpoint_v0(prepared, raw_two_seal_finality, raw_anchor)` verifies
the exact native checkpoint and strict joint handoff. The opaque, non-Clone
`AuthenticatedEpochApplicationEdgeV1` retains the committed checkpoint capability,
old/new configurations, terminal seal2 and checked C/C+2/C+3 coordinates.
`epoch_edge.rs::preview_epoch_block_v1` requires the same live application owner,
fresh checkpoint P digest/sequence and exact current committed head C. Its request
binds both parents and the authorization digest; constructing these raw fields
alone supplies no authority. A preview neither consumes the edge nor writes P.

`confirm_epoch_application_edge_v1(&edge)` now supplies a separate read-only
`ConfirmedEpochApplicationEdgeV1` for host/Core composition. It borrows the
strict edge, owns fresh COMMITTED checkpoint readback, requires current head C,
exact P/artifact/commit sequence and the original retained bound preparation.
It neither executes C+3 nor migrates/writes local state. Its owner/path check
repeats those fresh checks; exposed headers/configuration and authorization
facts are insufficient by themselves to activate Core or retire old signing.

The schema-4 application bridge below now retains evidence and an Installed /
Consumed phase. Its application owner does not claim an independent node checkpoint
CAS. The broader node-checkpoint composition below remains planned. Its proposed
`TRNMEDG1` container is an **unimplemented design format**, not an encoding used by
the schema-4 or schema-8 owners. A schema-8 implementation must use only its exact
SQLite rows and retained CEV0/native bytes described below; it must not emit,
decode, migrate from, or treat `TRNMEDG1` bytes as recovery authority.

```text
confirm_epoch_application_edge(
  checkpoint: PreHandoffCheckpointReceiptV1,
  joint: StrictSameVersionEpochActivationAuthorityV0,
  expected_first_height: Height,
  checkpoint_cas: ConfirmedNodeCheckpoint
) -> Result<AuthenticatedEpochApplicationEdgeV1, FinalityRecoveryFailure>
```

The planned retained edge fields are: complete pre-certificate receipt; old/new epochs;
exact old/new set and parameter hashes; old checkpoint tuple
`(C, block_id, application_version=C, root, commit_sequence)`; complete terminal
seal2 header at C+2 and its block ID; first-new height C+3; exact handoff descriptor
and its frozen digest; strict epoch-activation binding; generation and confirmed
checkpoint predecessor/successor identity. Recompute all derived coordinates
with checked arithmetic and verify full joint evidence, never scalar equality alone.

Its planned local encoding is ASCII `TRNMEDG1`, u16-be 1, then the fields above
in listed order: receipts/headers/descriptor use u32-framed canonical bytes;
epoch/height/version/sequence/generation use u64-be; digests use Hash32;
checkpoint identity uses its existing exact canonical encoding, framed once.
Append SHA-256 of preceding bytes. All retained canonical evidence
preimages are stored separately under their exact strict binding and verified
on reopen; they do not acquire an invented aggregate consensus wire encoding.
A missing evidence object fences recovery even if the edge checksum matches.
This paragraph specifies a future node-checkpoint composition only. No current
producer or consumer may persist these planned bytes, and schema 8 must fail
closed rather than substituting this format for either of its versioned tables.

M07 consumes this edge only to construct its root-only `CarriedRootReaderV1`;
M06 binds the distinct consensus and application parents; M02 installs the
verified handoff ancestry edge. M13 may restore the inert record plus proof but
must ask the same owner to verify it before installation. It is not a public
constructor from a downloaded tuple.

## State machine

Signing and vote publication follow:

```text
Validated -> IntentDurable -> SignatureRecorded -> VotePublished
```

Finalized application and receipt publication follow:

```text
FinalityVerified -> CommitIntentDurable -> ApplicationApplied -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished
```

The signing path MUST NOT wait for the voted block to become final. Before
voting, execute and validate the complete payload into a prepared overlay under
its authenticated parent and exact runtime; an overlay is not canonical state.
M03 persists its authorized Safety decision and exact signing intent before
custody is invoked and records the exact signature before it escapes. Lost
acknowledgement permits only exact intent replay/readback, not a fresh vote.

The finalized path first admits a complete three-chain proof against the
application's commissioned context and the expected oldest target. A single QC,
a newest certified descendant, or a valid proof for another root is insufficient.
Only then may a durable commit intent authorize the exact idempotent application
apply. Record its durable result, confirm checkpoint predecessor/CAS and expose
the finalized receipt, in that order. Readback cannot promote prepared state.

Finality is applied in ancestor order. A child cannot skip an unacknowledged
ancestor. Duplicate requests return the same logical effect; a changed context,
generation, root, intent or predecessor rejects or fences the owner. The two
paths may interleave, but neither grants the other's capabilities. In
particular, vote publication is not receipt publication and a receipt retry
cannot authorize signing.

## Persistence and recovery

The ledger coordinates facts but does not overrule an independent Safety,
application, signer or checkpoint authority. Reopen each named authority and
resolve uncertainty to its exact source or exact target. Do not overwrite newer
Safety decisions from an older ledger projection. Ambiguous or conflicting
records fence dependent signing, commit and publication until resolved.

Crash cuts exist before/after intent durability, custody, signature recording,
vote publication, application apply, ledger result, checkpoint CAS and receipt
publication. HSM success with lost response, disk-full, fsync error, WAL/SHM
failure and owner takeover are uncertainty cases, not proof of no side effect.
Recovery uses fresh authoritative readback and preserves exact replay identity.
Separate durable stores are not a distributed atomic transaction merely because
a process test passes. Whole-store rollback requires an independent external
anchor and device-qualified custody; local hash chains are insufficient.

### Planned epoch commit and exact replay

Maintain two explicit coordinates: latest consensus certified/retained ancestry
and latest committed application execution. At old terminal seal2, these may be
C+2 and C respectively; the committed application sequence has not advanced for
seals. Do not relabel seal2 as ordinarily finalized by the checkpoint proof.

Checkpoint execution is prepared before its vote; QC(seal2) finalizes checkpoint
C; M08 then applies checkpoint C once and issues the pre-certificate receipt.
Old/new role signing follows that receipt. After joint verification, persist the
edge and checkpoint CAS before installing the new anchor. First new block C+3
is prepared speculatively and voted before its own finality; once a new-set
three-chain finalizes it, commit one application transition with JMT label C+3
and one application commit. Children may be prepared under normal speculative-parent
rules while that commit waits. No mixed-old/new three-chain is accepted.

Normal apply expects application height+1. The dedicated epoch-edge apply
variant instead consumes the exact edge, expects application parent C and
consensus parent seal2 C+2, and accepts target C+3. M06 applies the authenticated
new configuration and frozen PoCO usage-bucket rollover before user transactions,
inside this same first-new state transition; historical certificate finalization
epochs are never relabelled. No application mutation occurs at anchor installation.
It preserves all ordinary
root/parent/context checks, changing only the reviewed edge relation. Subsequent
ordinary targets return to +1. `poco_checkpoint::ensure_exact_cutoff` continues
requiring real JMT label equal finalized cutoff consensus height.

An edge is `Installed` until a finality-authorized first-new commit consumes it.
Several competing speculative proposals may reference it; no speculative call
can consume it or prevent a later safe proposal. Commit CAS selects one exact
finalized block. Duplicate edge installation/commit requires byte-identical
binding; mismatched target or descriptor halts. Historical edge/proof retention
continues after consumption for M13 reconstruction and evidence windows.

### Implemented ordinary incremental native owner (schema 5)

The implemented compatible fresh-readback contract adds
`confirm_prepared_incremental_execution_v1(&prepared)` and
`confirm_prepared_epoch_execution_v1(&prepared)`. Neither accepts a caller-built
P summary. Each checks live owner affinity before I/O, reconstructs the actual
durable P and its authenticated ancestry, and returns a private non-Clone
receipt. Its `belongs_to_application_at_path` repeats the exact readback; its
header, source artifact checksum, overlay checksum and P sequence/digest remain
comparison data rather than Core authority. COMMITTED matching requires the
fresh current head, exact P digest and actual commit sequence together. An
unconfirmed recovery inventory or a reused receipt from another/reopened owner
cannot satisfy this contract.

Return types are `ConfirmedPreparedNativeIncrementalExecutionV1` and
`ConfirmedPreparedNativeEpochExecutionV1`. Both expose `prepared()`,
`artifact_checksum()`, `overlay_checksum()`, `commit_sequence()` and exact
`application_payload_and_receipts()`. The nested prepared capability retains
header, application parent, P digest and prepare sequence. Schema4 overlay
checksum remains the snapshot digest. Schema5 uses domain
`trnm.native-application.incremental-overlay.v1` over storage artifact H32,
replay-parent root H32, replay-delta SHA256 H32 and lifecycle SHA256 H32, in that
order. Storage artifact already binds parent/target root, height, delta digest
and storage sequence. These are local comparison digests, with no wire change.
Confirmation of a prepared capability may return its now-COMMITTED phase; an
older confirmation's matcher then fails until the consumer obtains a fresh one.

M07's explicit schema3→5 migration now uses the actual native SQLite owner,
not a shadow write. It retains one native P, state delta and authenticated local
replay delta in the same transaction; ordinary prepare/commit no longer encodes
historical JMT snapshots. The exact closed schema, P/migration/owner digest
preimages, replay codec and finite bounds are specified in M07's "Implemented
ordinary native owner" section. Schema4 sparse migration remains fenced.

`PreparedNativeIncrementalExecutionV1` has private fields/no Clone and carries
actual P/header/parent/target/storage reference/sequence. Its prospective target
is not evidence of commit. `commit_incremental_finality_bytes_v1` first joins
fresh exact P and authenticated parent header to strict signed three-chain
verification, then commits only the oldest exact application predecessor. Native
commit sequence is current durable sequence+1, including speculative prepares.
A committed receipt remains owner-affine and exact retries preserve its sequence.

Recovery audits the immutable migration baseline against the original committed
source P and authenticated replay tree, pins that anchor in the live owner, and
validates current state/replay/root/commit bindings. Pending readback checks exact
P/storage/replay ancestry to the committed head. Missing/corrupt nodes cause
unavailable/error, never successful replay absence. Native recovery inventory
counts schema5 pending P rather than reporting an empty legacy table as "Exact".
The v0 snapshot/preview/state-proof interfaces explicitly reject schema5; their
versioned adapters and Core callback integration remain pending. The separate
schema6 first-new preparation described below does not provide epoch commit.

A real signed test migrates height4, prepares5/6/7 plus sibling5, strictly commits5,
retires only the sibling/pin, then reopens6/7. SIGKILL before/after transaction
commit and after fsync yields only exact pre/post states; replaying finality
returns native sequence14 without duplicate state or replay writes. New P rows
have no historical snapshot and the archival snapshot byte sum is unchanged.

### Implemented dual-parent artifact and schema-4 snapshot bridge

The bounded candidate implementation uses an explicit local application schema 3→4
migration. It keeps schema-3 P/artifact bytes and commissioning pins unchanged;
opening an old database cannot silently migrate it. The commissioned owner
checks the exact source inventory/head, migrates in one SQLite transaction and
freshly audits schema 4 before returning. A schema-3 reader rejects schema 4.
This bounded snapshot bridge enables native epoch recovery before migration to
M07's separate `ni_*` incremental backend; it is not a snapshot-growth fix.

`NativeExecutedEpochBlockV1` is an **inert boundary value** containing
`NativeEpochBlockExecutionRequestV1` and ordered native receipts. Its constructor
checks computed payload/state/receipt/evidence roots against the expected roots,
exact receipt count and gap-free transaction indices. Successful construction
is neither finality nor durable P authority. The artifact encoding is:

| Ordered component | Exact local representation |
|---|---|
| Prefix/version | ASCII `TRNM_NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_V1`, u64-be 1. |
| Chain/genesis | u32-be byte length plus existing valid UTF-8 chain ID; Hash32 genesis. |
| Application parent | u64-be height, Hash32 block ID, Hash32 root, Hash32 commit ID; exact checkpoint C. |
| Consensus parent/edge | u64-be terminal height, Hash32 terminal block ID, Hash32 application handoff authorization binding. |
| Target | Hash32 block ID, u64-be height, u64-be timestamp, Hash32 active new validator-set ID. |
| Transactions | u32-be count; each exact signed native transaction has a u32-be byte length; retain the 4 MiB complete-body bound including lengths. |
| Expected roots | Hash32 payload, state, receipts, evidence, in that order. |
| Receipts | Existing artifact-v0 receipt sequence encoding, including u32-be count/index, gas u64-be, fee u128-be, bounded event/attribute strings and receipt commitments. No CEV0 or runtime receipt field changes. |

Require exact EOF and byte-identical re-encoding; reject an artifact over 16 MiB
before allocation. Artifact digest is SHA-256 over the complete local bytes.
The ordinary artifact domain/version and +1 request constructor remain unchanged.
Both parent coordinates enter the epoch artifact; a fake application head at
seal2 is forbidden. For later ordinary C+4/C+5, retain artifact v0 and its +1
semantics, but use the new durable P family because their stored history is sparse.

Schema 4 adds the following closed tables to the existing schema. `U64` means
length-8 big-endian BLOB, `H32` length-32 BLOB, `BYTES` bounded BLOB, `TAG` INTEGER
with the listed CHECK. All fields are NOT NULL unless explicitly optional.
The migration validates exact declared tables/indexes and rejects unlisted
triggers/views. Each new table uses a primary key and immutable source fields;
only the listed phase/commit fields can transition under owner CAS.

| Table/key | Exact required fields and constraints |
|---|---|
| `native_epoch_edge_v1` / binding H32 | store_id H32; checkpoint_height U64; checkpoint_block/root/commit_id/P_digest H32; checkpoint_commit_sequence U64; terminal_height U64 and block H32; first_height U64; evidence BYTES and evidence_digest H32; phase TAG {0 Installed,1 Consumed}; optional consumed_block H32 and consumed_sequence U64. Terminal=C+2, first=C+3; both optional fields absent at0 and present at1. |
| `native_durable_execution_p_v1` / block_id H32 | store_id H32; p_sequence U64 UNIQUE; status TAG {0 Prepared,1 Committed}; artifact_kind TAG {0 ordinary_v0,1 epoch_v1}; artifact BYTES/digest H32; canonical header BYTES; parent_kind TAG {0 Committed,1 Prepared}; parent_height U64 and parent_block/root/commit_id H32; optional parent_P_digest H32 (required only for Prepared); consensus_parent_height U64 and consensus_parent_block H32; target_height U64; edge_lineage BYTES/digest H32; target_snapshot BYTES/digest H32; replay_commands/nonces/lifecycle BYTES; target_set/parameters BYTES; P_digest H32; optional commit_sequence U64 and commit_id H32. Commit fields absent at0 and present at1; target=parent+1 for kind0 or the exact edge C+3 for kind1. |
| `native_application_epoch_context_v1` / singleton id=1 | store_id H32; head_block/root/commit_id H32; head_height U64; head_commit_sequence U64; active_set/parameters BYTES; edge_lineage BYTES; context_digest H32. Fields must equal the existing metadata head and the exact committed v1 P, with no context row before first consumption. Commissioning genesis/signer-policy pins remain unchanged. |

`edge_lineage` is u32-be count followed by H32 bindings in strictly increasing
first-new height. Duplicate/missing edges reject. It includes every retained
sparse gap needed by the target snapshot; new epoch preparation appends exactly
one authenticated edge, and ordinary descendants inherit the same sequence.
Its digest is SHA-256 of that exact encoding. A Prepared parent must resolve one
immutable P of either family with a smaller p_sequence, matching target root/head;
traversal terminates at an exact committed head within the depth budget. Child
rows bind that parent's P digest, preventing same-height sibling substitution.
Before parent commit, its prospective commit ID remains the
deterministic application identity derived from its P; readback never represents
that identity as evidence that commit occurred.

Both P families share the metadata `durable_sequence` allocator. Each prepare
and each commit advances that local ordinal once; therefore the first-new
commit_sequence is **latest durable_sequence+1**, not checkpoint_commit_sequence+1
when speculative P records intervened. The checkpoint's recorded commit_sequence
remains immutable. The context's head_commit_sequence identifies the committed
head row, independently of newer prepared rows. An independent count of applied
blocks, if exposed as a metric, cannot replace this recovery sequence.

In schema 4, metadata still has its existing snapshot column, but codec dispatch
requires the explicit schema plus authenticated epoch context: before first-new
commit it is codec1, afterward codec2 with the retained complete edge lineage.
Do not merely inspect a version byte and accept an unauthenticated sparse tree.
Old v0 P rows remain codec1; all new sparse-history P rows use family v1/codec2.
The context lineage contains only consumed gaps of the committed snapshot;
an Installed edge is retained in its own table and included in its candidate
P lineage, never prematurely added to the checkpoint's committed lineage.

The v1 P digest uses domain `trnm.native-application.durable-p.v1` and the exact
ordered tuple: store_id, p_sequence, artifact_kind, artifact_digest, parent_kind,
complete application-parent tuple, optional parent_P_digest presence/value,
consensus-parent tuple, target_height, lineage_digest, snapshot_digest, replay
command digest, replay nonce digest, lifecycle digest, target set ID and parameter
hash, then SHA-256 of the complete canonical header. Integers are fixed u64-be, tags u8 and optional presence u8; hashes are raw
32 bytes. Use the repository's length-framed `hash_domain` over these fields.
Commit ID uses domain `trnm.native-application.commit-id.v1` over P_digest,
block_id and target_snapshot_digest. Phase/commit_sequence are excluded from P
digest and covered by the commit transaction/readback identity. Never reuse a
v0 P digest with a changed semantic interpretation.

The implemented owner entry points are:

- `upgrade_epoch_schema_v1(expected_head)`: require all legacy preparations
  resolved, audit the source, migrate explicitly and preserve head/sequence.
- `install_epoch_application_edge_v1(&edge)` and
  `recover_epoch_application_edge_v1(binding)`: persist/reconstruct exact raw
  evidence under the native owner; edge installation advances no application
  height or sequence. Recovery does not recreate a missing preparation journal.
- `recover_incremental_epoch_edge_for_binding_v1(binding)`: schema7's
  binding-aware recovery seam. It audits the singleton owner and rejects any
  binding other than the active persisted authorization before rebuilding the
  strict checkpoint/handoff evidence. The no-argument compatibility recovery
  remains singleton-scoped and is not a multi-edge history API.
- `read_epoch_edge_history_v1()` and
  `recover_epoch_application_edge_at_index_v1(index)`: schema4's versioned,
  owner-affine multi-edge history/readback contract. The history is sorted by
  first-new height, recursively audits every retained lineage, checks consumed
  P identity and phase, and performs a fresh metadata read before returning.
  Recovery selects only a binding already present in that validated history and
  re-reads the history after reconstruction. A second pending edge, duplicate
  height, malformed lineage, missing predecessor, or concurrent mutation is
  rejected. This schema4 carrier is read/recovery state only; schema8 owns the
  separately audited successor-edge row.
- `inspect_later_epoch_checkpoint_context_v1()`: owner-affine, read-only
  planning context for the next checkpoint. It verifies the consumed lineage,
  active context digest, canonical old validator set/parameters, and derives
  the authenticated checkpoint/seal/first-new geometry and cutoff. It does not
  accept proofs or mutate the store. `require_later_epoch_checkpoint_bridge_v1`
  rechecks that context and always returns a fail-closed error; the versioned
  schema8 checkpoint consumer below is a distinct API and grants no new edge.
- `execute_epoch_block_v1(&edge, request, &header)`: recompute the complete M06
  prefix/user plan, check the exact canonical header and all roots, persist P and
  replay/snapshot bytes atomically, synchronize and return private prepared P.
- `preview_epoch_descendant_v1(&prepared, &request)` and
  `execute_epoch_descendant_v1(&prepared, request, &header)`: use the exact
  speculative ancestor, retain ordinary artifactv0, and store it in P familyv1.
- `reopen_prepared_epoch_execution_v1(block_id)`: freshly reconstruct retained
  edge authority and re-read the same P digest before issuing an owner-affine
  capability. It exposes immutable header/parents/artifact/P/persist identities,
  not commit authority.
- `commit_epoch_finality_bytes_v1(&prepared, proof, &mut budget)`: strictly
  verify the exact oldest target; first-new proof uses the retained activation
  preimages and dedicated strict decoder, while ordinary descendants use the
  ordinary new-set decoder. Commit requires current application-parent CAS.
- `prepare_later_epoch_first_new_block_v1(&later_edge, request, &header)`:
  reconstruct the schema-8 successor context from retained authority, enforce
  application parent C, consensus parent C+2 and target C+3, recompute the
  complete execution and roots, and durably prepare the exact family-v1 P. The
  older `execute_later_epoch_first_new_block_v1(&later_edge)` has no request or
  header and intentionally remains fail-closed; it is not the executing seam.
  `commit_epoch_finality_bytes_v1` strictly verifies the prepared later C+3
  proof and atomically updates P, metadata/context and successor edge phase to
  Consumed. The candidate schema-9 ledger retains the exact proof and its
  bound digest for cold re-verification; local positive and three-cut crash
  fixtures pass, while production Core/Safety activation remains open.
- `read_finalized_by_height_v1(height)`: returns private
  `FinalizedNativeEpochApplicationReadV1` only for the unique committed
  schema4 ordinary (`artifact_kind=0`, `Regular`, no next commitment) P at the
  height. Full inventory/lineage/snapshot/replay/receipt validation and a
  second immutable read must agree. Prepared, missing, ambiguous, foreign
  owner and checkpoint/handoff rows fail closed. This carrier is local
  application history, not a consensus proof or public RPC authorization.

The commit transaction updates metadata/snapshot/replay and P status together,
consumes the edge only for its first block, installs active context, prunes only
unrelated prepared forks and advances durable_sequence once. Database/file/
directory synchronization and fresh metadata/P readback precede return. Exact
prepare/commit retries repeat synchronization/readback and keep their immutable
P/commit sequences where the corresponding finality record is retained. The
schema-8 checkpoint/successor ledger is paired with a schema-9
application-finality ledger that preserves bounded proof bytes and exact
retry/recovery digests. Seals produce none of these records. The context digest is
`hash_domain("trnm.native-application.epoch-context.v1", [store_id, complete head
(height/block/root/commit), head_commit_sequence, SHA256(set), SHA256(parameters),
SHA256(lineage)])`, with U64/H32 encoding above.

This bridge currently admits a legacy-v0 committed checkpoint, its first-new
block and ordinary descendants. Schema8 additionally admits a strictly
verified later checkpoint through its explicit proof ledger and has a candidate
request/header-based path that prepares and strictly commits its first-new C+3.
General sparse-history finalized RPC/proof interfaces and independent node
checkpoint/publication ownership are still fenced or pending. Schema4 rejects
ordinary `execute_block` so the legacy +1 path cannot synthesize application
effects for seals. Ordinary C+4 descendants can continue after one later
successor using the mixed legacy/later lineage. Repeated later-to-later
handoffs remain unsupported, so this is not the full multi-epoch default-node
pipeline.

The schema4/schema8 lineage audit now accepts a committed familyv1 checkpoint `P` only
when its artifact kind, target, prepared digest, header kind and next-epoch
commitment match exactly. It recursively audits each predecessor `P` with a
bounded seen-set and rejects cycles, missing predecessors and owner mismatches;
an epoch checkpoint is admitted to descendant preparation but cannot be passed
to ordinary checkpoint finality handling in `commit_epoch_finality_bytes_v1`.
The later checkpoint's first-new C+3 candidate now prepares a real P through
`prepare_later_epoch_first_new_block_v1`, strictly verifies caller finality, and
commits the P, metadata/context and successor phase-1 consumption atomically.
The schema-9 ledger retains that C+3 proof for cold re-verification. The local
positive C21 fixture and three process-kill cuts cover the exact P/edge/proof
retry path. The
checkpoint/handoff schema4 finalized-read mapping and schema7 incremental
multi-edge owner/storage migration remain unimplemented. The full-snapshot
schema10 mixed-prefix owner now supports repeated later handoffs. Schema8 durably commits and strictly reverifies the later
checkpoint proof record and its separate successor-edge row; neither path
silently reuses the predecessor edge.

For an ordinary descendant of the later C+3 P, preview and execution recover
each retained lineage binding into a sealed `EpochExecutionContextV1`.
A legacy binding uses its original audited edge; a later binding resolves its
checkpoint from the successor table and independently recovers that successor
context. Execution inherits the complete ordered lineage and the final
context's new set/parameters, retains ordinary artifact v0 and the exact
application/consensus parent at height−1, and writes its authenticated
snapshot through the same context list. A later binding is never passed to
the legacy-only recovery API. This descendant path and its commit/retry
require schema10; a readable schema8/9 image without the applicable retained
proofs cannot gain write authority through the ordinary path.

Ordinary descendant finality uses the actual immediate parent's timestamp
and the ordinary new-set strict decoder. Only `artifact_kind=1` may consume
the successor or append a schema9 handoff proof; C+4 commit/retry must leave
both the C+3 consumed block and its one proof row unchanged. When the head
has progressed, recovery follows at most 128 committed P rows back to the
consumed C+3 head. Every step requires exact parent head/P digest. Ordinary
steps require +1 height, the actual consensus parent, identical lineage and
identical target configuration. A later handoff requires checkpoint C→C+3,
the selected authenticated terminal C+2, a consumed edge with its retained
first-new proof, and exactly one appended lineage binding/new configuration.
Missing, cyclic, uncommitted or substituted ancestry rejects; this selected
walk consumes already authenticated inventory and cannot re-enter inventory.
The C18 fixture prepares C21 then C22/C23/C24, strictly verifies their signed
ordinary three-chain for C22 and checks exact retry and cold recovery. It does
not by itself establish another later checkpoint/handoff or a public sync protocol.
Schema9 retains the first-new proof only. Schema10 adds the separate ordinary
proof ledger specified below; commit and cold audit both strictly verify its
original signed proof. The proof exporter specified below reads these ledgers and returns their
original evidence. Public transport and complete state-sync installation
remain separate gaps; an application-history projection alone cannot serve
as consensus evidence.

#### Required resolver for repeated later successors

The private `epoch_lineage_v1` resolver uses a bounded prefix walk for lineages
such as `[legacy A, later B, later C]`. It replaces mutually recursive calls
among P, successor and checkpoint-proof audits.
Start with the configured genesis set/parameters and an empty authenticated
prefix. For each of at most 32 distinct bindings, resolve exactly one legacy
or later row; missing or ambiguous ownership rejects. A later row must join a
committed ordinary checkpoint P whose **entire** encoded lineage equals the
already authenticated prefix, not merely its last binding. Its predecessor,
P/head/sequence, geometry, context digests and retained record digest must
agree with that prefix and checkpoint.

Decode and strictly verify the selected retained activation preimages using
the current prefix's active set/parameters directly. Only that result advances
the active set/parameters and appends the binding. The selected-row verifier
must not call the prefix resolver, `validate_p` or whole-table inventory.
The checkpoint-preimage audit, P validation, successor-fact derivation and
execution-context reconstruction must consume this same authenticated result
from one immutable read; mutations still require the existing owner lock,
parent CAS and fresh readback. Required positives include a second later
checkpoint and its first-new/ordinary descendants across cold reopen.
Required negatives are prefix substitution, duplicated/cyclic bindings,
wrong predecessor, forged rehashed retained proof and wrong target
configuration. The authentic
`repeated_later_handoffs_c28_c31_c32_recover_exact_prefix` fixture now covers
C25 cutoff→C28 checkpoint→S29/S30→C31 first-new→C32 ordinary commit. It
reopens Installed, Consumed and progressed states, recovers the historical B
edge across the second later handoff, retries original C22 without changing
its commit sequence, and rejects eight isolated corrupt database copies.
It also exports C18→C32, including both first-new proofs and original ordinary
proofs, with equal bytes after cold reopen. This is bounded native-owner
evidence; production Core/custody, incremental repeated crossings and a
network synchronization/installation path still require separate acceptance.

The shared private prefix result must drive checkpoint-context selection,
successor-fact derivation, first-new snapshot reconstruction, ordinary execution,
reopen and both proof-ledger audits. The existing public indexed legacy history
returns a concrete legacy capability; later entries cannot silently enter that
API. Derive mixed context from the exact committed head's P/context lineage,
with explicit row ownership, rather than treating the last legacy history row
as the active epoch. For each binding retain source kind, phase/consumption,
checkpoint head/P/sequence, coordinates and the sealed audited activation;
do not retain full snapshots in the prefix carrier.

Historical successor recovery must also survive a second application jump.
Walk at most128 distinct committed P rows from the current head toward the
original consumed C+3. Every cursor lineage must extend that original prefix.
An ordinary step requires exact immediate parent head/P digest, +1 height and
identical lineage/configuration to its own parent. A first-new step requires
its authenticated selected edge: exact C→C+3 application jump, actual C+2
consensus parent, parent lineage plus that one binding, authenticated old→new
configuration, and matching consumed block/sequence/proof. This admits
C32→C31→C28→…→C21; generic ancestor reachability is insufficient. Test C28
against its real committed C25 cutoff, C31 strict epoch-first finality, C32
ordinary finality, cold reopen at Installed/Consumed/progressed heads, and
historical B recovery/C22 retry at C32. Mutants must include ambiguous dual
table ownership and substituted jump/terminal coordinates.

### Schema10 ordinary later-descendant finality contract

Primary module: M08. M06 produces the prepared execution/header and M08
consumes the strict finality proof. The candidate implementation follows this
versioned contract; schema9 coverage alone does not satisfy it. It extends the
full-snapshot candidate owner, not the schema7 incremental owner or production
activation policy.

Schema10 adds `native_later_epoch_descendant_finality_v1` as a STRICT table
with exactly seven columns: `block_id BLOB(32) PRIMARY KEY`, `p_digest BLOB(32)`,
`commit_sequence BLOB(8) UNIQUE`, `edge_binding BLOB(32)`, `proof BLOB`,
`proof_digest BLOB(32)` and `record_digest BLOB(32)`. All columns are NOT NULL;
SQL CHECK constraints enforce fixed lengths. Sequence encoding is u64 big
endian. Proof length is 1 through `MAX_CEV0_ROOT_BYTES_V0` (8 MiB), row count
at most `MAX_P_ROWS` (128), and cumulative proof bytes at most 64 MiB. Validate
SQL types, lengths, row count and cumulative length before loading proof blobs;
check prospective capacity before writing. `proof_digest = SHA256(proof)`.
The framed record domain is
`trnm.native-application.later-epoch-descendant-finality.v1`, with ordered
fields `[store_id, block_id, p_digest, BE64(commit_sequence), edge_binding,
proof_digest]`. The P digest binds the full header, parent, lineage, execution
artifact and resulting snapshot. No caller-supplied validator configuration is
stored as a substitute for authenticated history.

Keep exact schema8, schema9 and schema10 inventories distinct. Schema10 retains
the schema9 C+3 table and its one-row-per-consumed-edge invariant unchanged;
ordinary proofs never enter that table. The explicit
`upgrade_later_epoch_schema_v1(expected_head)` targets schema10. Under the
owner lock and an immediate transaction, revalidate the exact source schema,
inventory, expected head and sequence before any table creation or version CAS.
Schema4 can add all later tables. Schema8 requires zero consumed later edges,
because their original C+3 proofs are absent. Schema9 can migrate only when no
Committed artifact-kind-0 Regular P ends in a later successor binding. Such
ordinary history lacks its original proof and cannot be reconstructed from P,
C+3 finality, reexecution or caller replacement evidence. Refusal leaves all
source bytes/logical state unchanged. A committed C+3 with its retained proof
and a Prepared C+4 permit migration. Preserve head and sequence; sync and fresh
audit before success. Exact schema10 retries audit without mutation. Ordinary
open never migrates.

Classify ordinary later descendants independently from `later_application`,
which remains restricted to first-new artifact-kind-1 commits. Preview,
execution and commit of artifact-kind-0 Regular blocks whose last binding is a
later successor require schema10, including locked write/retry checks. Verify
the complete proof before mutation. The same SQLite transaction that commits
P, state/replay data, head and runtime context inserts the exact original proof
and its bindings. A checkpoint uses its checkpoint ledger instead. An exact
committed retry must match the stored proof bytes, P digest, sequence, edge and
both proof/record digests, then sync and freshly audit before returning the
original receipt. A different valid proof for the same finalized header cannot
replace the recorded bytes. C+3 consumption and its proof remain unchanged.

Cold audit first authenticates checkpoint/successor/C+3 records, then requires
an exact bijection between the ordinary ledger and Committed later Regular P
records. Missing, extra, Prepared, first-new or checkpoint rows reject. Join
each row to its exact P/sequence, full lineage, last binding and actual committed
parent header. Derive the new validator set and parameters from strict activation
rooted in previously authenticated history. Do not trust self-reported P
configuration or fall back to genesis configuration. Invoke
`decode_verify_finality_proof_strict_v0` with the full expected target header
and immediate parent's actual timestamp/header, then compare the complete
finalized header. Use internal helpers over the same read snapshot, without
public recovery calls or recursive whole-inventory validation. Keep large
cryptographic frames in non-inlined helpers so default-stack recovery remains
supported.

Required checks include exact commit/retry and cold reopen after a later head;
schema9 C+3/Prepared-C+4 migration; refusal of schema9 committed C+4 without
mutation; deleted proof; forged signature with recomputed proof/record hashes;
wrong target, set, parent or lineage; and a valid byte-distinct proof retry.
Real process kills before SQL commit, after commit and after fsync must recover
either the exact C+3 state or the complete C+4 P/proof/head tuple, preserving
the C+3 consumed edge. A reusable authentic prepared seed may bound fixture
cost, but must copy the database and its owner preparation sidecar together.
These checks do not establish repeated later handoffs, public proof export/sync,
incremental second crossing or multi-host acceptance.

### Schema9 retained later application finality

Primary owner: M08; producers are the M01 strict finality verifier and M06
prepared execution, and consumers are M07 durable recovery and M15 node
composition. This is a local candidate storage contract, not a new wire proof
or authority to activate a validator.

`native_later_epoch_application_finality_v1` has exactly seven columns:
`block_id` H32 primary key, `p_digest` H32, `commit_sequence` U64 encoded as
eight big-endian bytes, `edge_binding` H32, `proof` BYTES, `proof_digest` H32,
and `record_digest` H32. Each proof contains 1..67,108,864 bytes; inventory
admits at most 32 records and checks the SQL type/length before loading proof
blobs. `proof_digest=SHA256(proof)`. The record uses the existing framed
`hash_domain` helper with domain
`trnm.native-application.later-epoch-application-finality.v1` and ordered
inputs `store_id`, `block_id`, `p_digest`, big-endian `commit_sequence`,
`edge_binding`, `proof_digest`. Neither digest authenticates a signature.

Migration is explicit and owner-locked through
`upgrade_later_epoch_schema_v1(expected_head)`. It validates the original
schema, descriptor, metadata and expected application head within an immediate
transaction before creating missing tables and CASing the version. The latest
target is schema10 under the ordinary-proof migration rules above. A schema8
store may migrate only when it has **zero consumed later successor edges**:
schema8 did not retain their application proofs, so an empty new ledger cannot
certify existing consumption. A consumed schema8 image rejects without change;
it requires a separately designed evidence-preserving recovery/import owner.
Ordinary open never migrates. Successful migration and exact current-schema retry
require synchronization and fresh validation with unchanged application head
and durable sequence.

For a later first-new block, strict finality verification precedes mutation.
One transaction commits its P, application snapshot/replay/head/context,
successor phase0→1 with the same block/sequence, and the exact proof record.
The existing parent CAS and fork-retirement rules still apply. The commit
receipt is returned only after synchronization and fresh readback. An exact
retry must reproduce the retained proof bytes and both digests and returns the
original sequence; even another valid proof cannot overwrite this retained
record through retry.

Cold recovery first authenticates the checkpoint and successor ledgers. It
then requires exactly one application proof record for every consumed later
successor, a committed `artifact_kind=1` P with matching digest/sequence and
last lineage binding, and the same consumed block/sequence on that edge.
It reconstructs activation from the retained checkpoint parent, checkpoint
proof, authorization kernel, next commitment and old/new configuration.
`decode_verify_epoch_first_finality_strict_v1` receives the authenticated old
set/parameters as its activation trust root and verifies the first-new
three-chain under the resulting new set. Its expected full header binds the
P's target, roots and consensus parent, including the terminal-old timestamp.
Missing, malformed or substituted authority rejects before any recovered
capability is issued. This pass is read-only and must not recursively invoke
the whole-table inventory while validating a selected successor.

Required regressions include changing a retained signature and recomputing
both local digests, deleting the proof row while leaving the consumed edge,
and attempting schema8 migration with consumed successors. Every case must
reject; restoring the authentic bytes must allow reopen. The process-kill
cuts `later_application_before_commit`, `later_application_after_commit` and
`later_application_after_fsync` must recover either the exact prepared
predecessor or the entire committed P/edge/proof tuple. No cut may recover a
consumed edge without its proof or increment the application sequence twice.
These local checks do not close repeated later handoffs, incremental schema7
migration or independent crash/power acceptance.

### Implemented retained edge evidence and recovery algorithm

`evidence` is local `TRNMEVD1`, u16-be1, followed by u32-framed exact bytes in this
order: checkpoint native artifact v0; cutoff finality proof; cutoff parent header;
checkpoint parent header; checkpoint header; checkpoint two-seal finality proof;
terminal-old/ordinary-QC/handoff-certificate canonical kernel; old validator set;
old parameters; new validator set; new parameters; and next epoch commitment.
These are twelve separately u32-framed canonical preimages. Then append the
bound checkpoint preparation identifier H32 and SHA-256 of all preceding bytes.
The old/new preimages live inside this evidence container, not additional SQL
columns. Exact EOF/re-encoding and the 64 MiB complete-record bound are required.
This is a local retention container, not a new aggregate protocol proof or
signing message. Confirmation retains these exact accepted bytes before the
transient preparation is consumed.

Recovery first validates owner/store/commissioning identity, schema, checksums,
bounded lengths and exact inventory. It then opens the retained committed
checkpoint and cutoff, verifies their JMT roots and P/commit identities, rebuilds
the exact native preparation and next commitment, checks the journal's original
bound header, and reruns strict old-set two-seal plus joint verification from the
retained bytes. A missing cutoff, preparation record, preimage or checkpoint pin
is a recovery error; no boolean or matching root substitutes for it. After fresh
capabilities exist, decode codec2 against the exact lineage and restore current
active configuration only if it matches the committed context and source state.

An Installed edge with head C may prepare C+3 again. A Consumed edge requires
the exact committed C+3 P/sequence and may only restore historical ancestry for
later blocks; it cannot execute the prefix again. Reconstruct Prepared C+4/C+5
through their own immutable ancestry, not the latest unrelated snapshot. Missing
or conflicting parent/P/edge bytes fence that chain without selecting a sibling.
Crash before the atomic transaction leaves source; after it leaves exact target;
lost reply is resolved by fresh row/head/edge-phase readback before any retry.
The pin set includes checkpoint, cutoff, preparation record, raw evidence and
all speculative ancestors until retained descendants and export/recovery users
release them. Neither schema migration nor ordinary fork pruning may delete them.

The explicit development bridge profile limits **all v1 P rows**, including
committed rows, to 128; prepared ancestry depth 8, total P bodies 2 GiB and 32
retained edges. It therefore eventually becomes unavailable until a reviewed
retention/migration extension lands; it does not claim indefinite operation. Additional caps are snapshot
256 MiB, edge evidence 64 MiB, replay set 16 MiB each, lifecycle 1 MiB, and artifact
16 MiB; canonical header 4096 bytes, validator set 1 MiB, parameters 4096 bytes,
lineage 4+32×32 bytes. Counts/lengths and checked aggregate sums are validated before decoding
or writing; three largest admitted prepared descendants plus edge/WAL reserve
must fit the selected budget. A signed deployment profile must provide each
field, fit enabled proof/body limits and retained history, and cover both current
and target SQLite/WAL/sidecar space. No profile silently becomes a mainnet default.
Exceeding a local storage/recovery budget yields unavailable, never peer invalidity.

### Planned durable intent fields and restart matrix

`ApplicationCommitIntentV1` binds immutable operation ID; owner generation;
proof class and verified proof binding; exact oldest target/parent; expected
application head and sequence; prepared artifact/delta digest; expected postroot;
optional epoch-edge binding; expected checkpoint predecessor; bounded output
receipt/outbox identity. Its generated local schema must preserve every field
and be versioned independently of consensus. A role-signing intent is a separate
record and cannot be substituted by this application intent.

| Crash / reopened state | Required action before any dependent effect |
|---|---|
| Prepared only, no verified finality intent | Retain/discard speculative plan under its owner; no apply or receipt. |
| Commit intent exists, application still at exact parent | Revalidate proof/plan and retry identical apply. |
| Application at exact target, ledger result missing | Freshly verify committed target, reconstruct identical result once. |
| Ledger target recorded, checkpoint still predecessor | Retry exact CAS; do not publish receipt early. |
| Checkpoint CAS response lost | Read independent checkpoint; accept exact predecessor/target only. |
| Receipt persisted, publication acknowledgment lost | Republish identical receipt/outbox identity; no new application effect. |
| Installed epoch edge, application at C | Re-verify evidence and pin; restore M07 alias for C+3 only. |
| Consumed edge, application at C+3 | Verify exact target/sequence and resume ordinary recovery; no second edge apply. |
| Root, sequence, descriptor, epoch or external-anchor conflict | Fence signing/commit/publication and retain bounded diagnostic evidence. |

Recovery scans within a qualified profile budget and leaves an explicit pending
state when incomplete. It cannot truncate the oldest unresolved commit to make
startup succeed. No external publisher acknowledgment is consensus authority.

## Resource bounds

Bound proof bytes, total signature work (including failed verification), pending
commits, retained ancestry, record size, recovery scan, replay and rebuild work.
Compaction requires authenticated finalized history and retains every applicable
replay, evidence, slashing and weak-subjectivity horizon. Reaching a local work
limit yields unavailability or a fenced recovery, not deterministic peer guilt.
No resource default may turn incomplete history into an accepted checkpoint.

The native v0 snapshot audit borrows the owner's immutable JMT collections
through a private `TreeReader`. Iteration and each existence proof use the same
snapshot and expected root for the entire borrow. This removes a full historical
store clone from every audit while retaining verification of every live value,
preimage and proof. It does not prune history, change snapshot codec bytes, or
close the separate full-snapshot persistence and cumulative recovery-work gap.

The planned signed recovery profile supplies maximum proof/record bytes,
pending commits, unacknowledged receipt bytes, retained epoch edges, per-reopen
scan/work limits and archive horizons. Validate it against the largest enabled
M00 proof and protocol evidence/trusting/unbonding windows before admitting work.
No deployment default is invented here. Capacity shortfall before effects is
unavailable; uncertainty after possible effects fences the same operation.

## Security

Reject wrong proof class, chain, validator set, epoch, oldest target, root or
parent before modifying the authoritative application or ledger. Generation
regression, same-height conflicting roots, replaced namespaces and inconsistent
signer watermarks fence the operation. An external rollback anchor must be in a
different rollback domain; a local sidecar cannot certify its own history.
No fixture, optimizer, indexer or historical journal tag supplies finality.

Planned local failures are typed: `FinalityTargetMismatch`,
`PreparedNotCommitted`, `CheckpointReceiptMismatch`, `EpochEdgeMismatch`,
`CommitPredecessorConflict`, `RecoveryBudgetUnavailable`, `CommitUncertain` and
`AuthoritativeStoreConflict`. The first four reject without effects; predecessor
conflict requires fresh readback; budget exhaustion does not imply invalid peer
data; uncertain/conflicting authoritative state fences dependent effects.
These do not add v0 peer error codes or new slashable evidence kinds.

## Observability and SLO

Report signing, ordering-finality, durable-receipt and settlement latencies
separately, with p50/p95/p99, fsync/HSM tails, pending depth, oldest pending age,
replay count, ambiguous-stop count and restart convergence. Only finalized,
replay-verified application transactions contribute to committed goodput.
Metrics describe operations; they cannot synthesize stage authority.

## Verification and evidence

Retain tests that permit votes before their own block's finality and prohibit
receipts before finality/checkpoint completion. Reject single-QC/newest-target
substitution and prepared-state promotion by a read. Exhaust independent crash
cuts and lost acknowledgements on both paths, ancestor reorder, exact replay,
corrupt records, coherent rollback, takeover and state-sync rejoin. Verify no
double-sign, conflicting finality or duplicated application effect, plus exact
post-restart roots. Process kills do not stand in for physical controller/cache
loss or HSM evidence. Structural documentation checks are not runtime proofs.

### Additional epoch/storage acceptance

- `M08-PREPARED`: strict proof readback never promotes a PREPARED row.
- `M08-PREHANDOFF`: COMMITTED checkpoint + two-seal finality yields a local
  pre-certificate receipt without a joint certificate; prepared-only, wrong
  cutoff/body/runtime/commitment or a post-certificate substitution rejects.
- `M08-CUT`: actual checkpoint C, seals without application effects, first-new
  JMT C+3, and the next epoch's exact cutoff. The native request/header seam
  supplies a candidate C+3 P and strict commit; the local positive fixture,
  schema-9 proof retention and exact commit_sequence checks pass.
- `M08-EDGE`: wrong terminal seal, descriptor, source receipt, new configuration,
  target height, namespace or expected CAS cannot install or consume an edge.
- `M08-REPLAY`: inject every row of the restart matrix, including receipt
  publication lost acknowledgment and real cross-store process crash cuts.
- `M08-SYNC`: M13 exports/imports a committed checkpoint and exact edge evidence;
  malicious alias-only metadata fails before replacing the active store.

The real signed local test commits checkpoint8, retains P11/P12/P13, reopens,
rejects corrupted new-set proof, commits11 at durable_sequence21 and preserves
P13 across another reopen. Corrupt retained evidence rejects database open;
missing bound preparation/journal rejects capability recovery without recreating
rows or files. SIGKILL tests cover before transaction commit, after commit and
after synchronization, requiring complete head8 or head11 and exact retry21.
These are process-crash tests, not physical device-loss certification.

The C18/S19/S20 fixture now drives a real C21 positive candidate path. The
schema-9 application-finality row, cold-reopen proof check, exact retry and
three SIGKILL cuts pass locally. Independent byte-exact vectors, Core/Safety
activation and signer retirement, and multi-host/device fault evidence remain
required acceptance work.

Freeze byte-exact planned node receipt/edge/local-intent vectors with positive and
negative independent consumers before implementing public restore paths.
The existing strict proof vectors remain unchanged. Acceptance uses actual
Core/Safety/native store/signer owners over two consecutive epochs; a fixture
assigning a future phase or root is not a passing implementation.

## Historical replay verification boundary (M08-HISTORY-V1)

Historical replay uses shared M01-HISTORY-V1 with an independently audited local
application/replay anchor, preserving the M08-to-M01 dependency direction.
M13's verified terminal and M08's complete local replay anchor are separate
requirements; downloaded current-live state cannot supply the missing replay
history. Retain original headers, bodies, terminal proof and eight-root activation
evidence and reverify them on cold recovery. Reuse M06 execution to derive every
committed command-ID and signer/nonce entry. The current executor rejects runtime
failures for the whole block and only constructs Success receipts; it does not
currently commit failed application receipts. If that execution profile changes,
replay must preserve identities for every admitted transaction regardless of its
receipt status. Seal headers are chain records only. An imported base requires its
own provenance and atomic owner contract; do not fabricate committed ancestor
P records or copy the terminal proof into individual ancestor proof ledgers.
This verification contract alone does not enable an importer or schema migration.

### Read-only history export and local transport (M08-HISTORY-EXPORT-V1)

`export_historical_replay_v1(anchor_block, target_block)` accepts exact committed
schema10 epoch-P anchors/targets and returns inert `NativeHistoricalReplayV1`.
It shares the existing retained-finality export's owner lock, immutable read
transaction, SQL type/count/byte screens, complete source audit, bounded ancestry
walk and fresh metadata/namespace recheck. It does not nest public exporters or
relax the source's original per-P proof requirements. Both existing proof export
and history export use one connection-scoped path builder. No SQL mutation occurs.

The DTO contains `anchor_header_cev0`, `terminal_finality_cev0`, ordered `records`
and ordered `activations`. `NativeHistoricalRecordV1` is either Application with
canonical header and application-payload bytes, or Seal with canonical header.
For each actual source P, reconstruct `ApplicationPayloadV0` from the artifact's
exact outer transaction bytes, preserving order. Recheck payload/receipt roots,
active block-size limit and the signed empty evidence root. This first native
profile supports only implicit empty evidence, exactly as the native executor;
reject unsupported evidence rather than dropping it. Obtain seal headers from
the strictly audited original checkpoint proof, and terminal finality bytes from
the exact target ledger. Copy the original eight activation roots in established
order. Local P, artifact, replay sets, commit IDs and sequence numbers are absent
from the transport authority. History does not carry per-ordinary-ancestor proofs.

`encode_v1`/`decode_v1` use local framing `NHR1`, u16-BE revision1, u16-BE profile0,
u32-length-prefixed anchor header and terminal proof, u32 record count, records
with u8 tag0 Application/tag1 Seal followed by a framed header and (only for tag0)
framed payload, u32 activation count, then each activation's eight framed roots.
Root order is old checkpoint proof, next commitment, authorization kernel, old
set, old parameters, new set, new parameters, checkpoint-parent header. Every
frame length is u32-BE; unknown tags/revisions/profiles, incomplete frames and
trailing bytes reject. This is neither a new consensus wire object nor a digest
domain. Decoding a transport cannot mint any verified result.

The entire framing is at most 64 MiB; require 1..256 records and independently
0..32 activations. Source traversal remains limited to 128 application P rows.
Headers and parameter/commitment roots are 1..4096 bytes, sets 1..1 MiB, other
roots 1..8 MiB; application payloads are 4 bytes through 4 MiB, additionally
subject to authenticated block-size semantics. Validate counts against remaining
minimum framed bytes and every length against remaining input before allocation.
Encode computes the complete checked size before allocating. Source row limits
remain independently enforced even when the resulting export is small. The
64 MiB bound describes encoded output, not peak process memory: the audited
source snapshot, retained proof path and bounded artifact/body temporaries have
their own limits. Inert transport framing also does not widen M01's stricter
per-activation aggregate logical-root allowance.

Tests must join genuine C18-to-C32 export to shared M01 and independent M13 trust,
assert original terminal proof and transaction-byte equality, 14 consensus records
versus ten executed bodies, and unchanged source head/sequence across cold export.
Exercise truncation, trailing bytes, unknown tags, each count/length boundary and
uncommitted/disconnected source targets. This suffix export does not claim the
still-missing genesis/archive source join or an execution-ready imported base.

### Imported execution base (M08-HISTORY-INSTALL-V1)

Later checkpoint admission and selected-row cold verification must recompute
the native candidate-selection result from the exact retained cutoff P/JMT
projection, using the already authenticated old prefix. Match the entire
next-epoch commitment, effective validator set and parameters, including fallback
fields. A signed commitment and matching cutoff root alone do not establish
deterministic selection. The pure computation is shared with M06 historical
replay and the existing checkpoint owner path; it creates no preparation permit.
The cold path decodes the selected cutoff snapshot with previously verified
coordinates and must not recursively invoke metadata/P inventory or recovery.
Candidate databases containing a previously unchecked, incorrect selection or
fallback commitment now fail cold recovery. Do not rewrite signed history or
erase the database to make this check pass; retain the rejected evidence.

This contract owns an explicit native storage installation API. Public-node
integration and ordinary post-base execution are separately gated.
The first vertical is a receiver-owned genuine committed C18 schema10 source,
verified history through C32, explicit installation, then original-finality C33
ordinary continuation. A peer database or a peer-computed replay set cannot
commission the receiver's anchor. Genesis/archive joining, incremental schema11
installation, a second rebase and the next imported-base checkpoint/first-new
writer are separate acceptance work and remain fenced in this first revision.

`confirm_historical_replay_anchor_v1(expected_head, expected_sequence,
expected_header)` returns a private-field non-Clone owner-affine
`ConfirmedNativeReplayAnchorV1`. It requires physical schema10, an exact genuine
committed epoch P/header, complete snapshot/replay/signer-policy audit, no pending
P above the anchor, no unresolved source preparation-journal reservation above
it (including a crash before its P row exists), and the pinned path/namespace
identity. Preserve such reservations and reject admission; never erase or
relabel them to make the anchor eligible. Retain the full head,
source P/commit sequence, store/chain/genesis/profile and authorized signer-policy
identities/digests, active old
set/parameters, snapshot and both replay digests, and a typed source-inventory
digest. Compute the latter over exact table names, sorted primary keys and framed
typed raw columns plus required bound preparation records, after SQL size/type
screens. Head/sequence alone is insufficient: edge installation can change the
source inventory without advancing the metadata sequence. After installation,
hash the explicitly reconstructed frozen logical source metadata singleton;
the mutable current schema12 head/schema must not enter this source pin.
The typed source and required journal inventory use the framed local domain
`trnm.native.historical-replay-source-inventory.v1`. The read-only preparation
seam checks this inventory again from a fresh connection before returning its
opaque result. An anchor from another owner, or one invalidated by a new
reservation/edge/P even at an unchanged head and sequence, cannot prepare replay.
Only bound seal reservations that exactly belong to an already audited source
checkpoint/installed edge may lie above the source application height; unresolved
application or checkpoint reservations above it remain disqualifying.

Source confirmation and deterministic read-only preparation are implemented in
`trillionnium/crates/trnm-native-execution-v0/src/historical_replay_owner_v1.rs`
with the bounded typed source/journal inventory in
`trillionnium/crates/trnm-native-execution-v0/src/historical_replay_source_v1.rs`.
These methods require schema10 and never create schema12, change the metadata,
write P, consume an installed edge or sign. Both restore the receiver's complete
local replay sets before execution. The canonical NHR1 byte limit is checked
before retention; source SQLite schema is screened at64 objects/512 KiB before
exact schema verification, and source columns retain their individual fixed or
variable bounds before high-level decoding. Legacy v0 and epoch-v1 P share the
128-row limit. Every original `native_epoch_edge_v1` evidence record requires
its exact preparation ID and bound checkpoint header in the actual journal;
later checkpoints do not manufacture legacy preparation records.

The nonempty fixture captures genuine local C18 before C21 preparation, with a
signed H12 credit and two signed C25 transfers. It compares replayed C32 state
and command/nonce sets to the real sender, checks repeated computation identity,
and leaves source B installed/unconsumed. Explicit install/reopen is implemented
in `historical_replay_install_v1.rs` and `historical_replay_storage_v1.rs`.
`historical_install_is_explicit_atomic_replayed_and_preserves_source` checks
nonempty installation, cold reexecution, exact retry, all nine retained source
tables, source-proof/journal deletion, rehashed target snapshot/replay corruption
and a genuine later journal append. The dedicated
`historical_replay_install_sigkill_cuts_recover_exact_nonempty_base` harness
exercises the three installation cuts below with actual killed subprocesses.
`historical_replay_install_and_confirm_fsync_uncertainty_is_idempotent`
injects database and directory fsync failures into installation, same-owner
retry and cold confirmation; clean readback must retain the same base identity.
`historical_install_serializes_real_checkpoint_preparation_and_rejects_late_write`
schedules genuine checkpoint preparation on both sides of the installation
lock: the write phase holds the lock, and an earlier computation cannot append
a journal row after the physical schema changes.
The receiver continuation described below executes the genuine nonempty C33
body, retains its original proof and rejects imported command/nonce replay.
`historical_receiver_c33_executes_original_body_and_finality_after_cold_prepare`
checks the receiver-local parent, cold Prepared recovery, exact commit retry,
fsync uncertainty, source preservation and independently detected state mutations.
Its separate cold branch prepares genuine C34 above pending C33; committing C33
must preserve that exact pending child. No C34 commit is inferred from this test.

At genuine C18, consumed prefix A and active epoch1 belong to the source P.
Installed successor B remains phase0 with NULL consumption fields. Replay may
authenticate and execute B and C, but must never mark this source B consumed or
create fictitious source C21/C28/C31 P rows. At install the metadata singleton
necessarily changes; freeze its former logical source view through the retained
genuine source P and explicitly pinned old metadata fields. All other source
rows and required preparation records remain exact. Later legitimate preparation
may append records; do not freeze the entire appendable journal indefinitely.

`prepare_historical_replay_base_v1(anchor, history)` verifies M01-HISTORY-V1
from the audited local anchor, validates every Application/Seal tag against its
authenticated header, and reexecutes all application bodies with M06. It returns
private non-Clone `PreparedNativeReplayBaseV1` bound to owner, full source facts,
typed inventory, exact input digest and locally computed target state/replay.
It performs no source writes, P creation, signing or acknowledgement. M15 must
independently join its configured M13 anchor/target to these exact facts; a
matching downloaded digest does not establish either trust requirement.

For deterministic local bookkeeping use new framed local domains
`trnm.native.historical-replay-input.v1`, `.historical-replay-run.v1`,
`.historical-replay-step.v1` and `.historical-replay-base.v1` (each prefixed
`trnm.native`). The input digest covers complete canonical NHR1 bytes. The run
digest binds store ID, full source head/sequence/inventory, target block and input
digest. Its source field is a framed `trnm.native.historical-replay-source-pin.v1`
digest over store/signer policy, Head104, durable/P/commit sequences, P digest,
exact header, snapshot/replay digests, active set/parameters, prefix and inventory
digest. Each step's local commit ID binds run, ordinal, previous local head,
authenticated header ID and computed artifact digest. These values never claim
an original ancestor P/commit. The target head's commit ID is the final replay
step's local commit ID, determined before installation; it is not the base digest.
The base digest additionally binds the actual installation sequence and computed
snapshot/command/nonce digests, avoiding any circular head/base dependency.

Explicit schema10-to-12 installation adds exactly four STRICT tables, preserving
all existing source tables. Non-singletons use WITHOUT ROWID and exact reference
SQL inventories; unknown tables/views/triggers/indexes reject. H32 means an exact
32-byte BLOB; U64 is an exact eight-byte BE BLOB; Head104 is height/block/root/local
commit. Headers are canonical nonempty BLOBs at most4096 bytes. A scalar cannot
be loaded through an unbounded Vec before its SQL type/length check.

| New table | Required fields and invariants |
| --- | --- |
| `native_historical_replay_base_v1` | Singleton1, revision1, source_schema10; source sequence/head/P/commit sequence/header, old metadata identity and snapshot/command/nonce digests, active set/parameters and source-prefix bindings, typed inventory digest; exact NHR1 input digest/count and retained authority roots; target header/set/parameters/head, locally computed snapshot/replay bytes with H32 digests; installation sequence and base digest. Source fields must equal the actual retained source, not merely their own hashes. Installation sequence is source sequence+1. |
| `native_historical_replay_input_v1` | Ordinal U64 primary key, unique block H32, canonical header, Application/Seal tag and exact payload, record digest. Exact ordinals0..count-1 cover every consensus height after source through target; Seal has no payload. Record digest binds input identity, ordinal and all framed fields. No source-local P/commit or peer replay data. |
| `native_replay_execution_p_v1` | Block H32 primary key, base H32, unique P sequence, status0/1, parent_kind0=base/1=this-table-P, full parent Head104 and optional parent-P exactly for kind1; canonical Regular header, artifact, snapshot/replay/lifecycle and component digests, P digest, nullable commit sequence/ID exactly for status1. First revision rejects checkpoint/handoff/seal writes. |
| `native_replay_execution_finality_v1` | Committed post-base block primary key, exact P digest and actual commit sequence, original strict finality bytes and proof/record digests. Exactly one for each committed post-base P and none for pending P; the C32 import proof cannot commit C33. |

The base source fields explicitly retain the audited signer-policy digest and
original terminal-proof bytes, ordered eight-root activations and their count.
Reconstruct exact canonical NHR1 from this authority plus the ordered input rows
to check the input digest and retry identity. Post-base status0 requires both
commit columns NULL; status1 requires both non-NULL with exact widths.
The local authority codec uses `NHA1`, BE revision1/profile0, u32-BE frames for
the source header and terminal proof, then a u32-BE activation count and the
eight NHR1 evidence frames per activation. Record bytes occur only in the input
table. Their domain is `trnm.native.historical-replay-record.v1`, framing input
digest, ordinalBE8, exact header, one-byte tag and payload (empty for a seal).
The journal baseline codec uses `NHJ1`, the same revision/profile prefix, a
u32-BE count of transition H32 keys, then a u32-BE count of preparation keys
(transition H32, block-kind i64-BE, heightBE8, viewBE8). Lists are strictly ordered,
unique and limited to64/1024 keys and64 KiB; every selected preparation requires
its selected transition. Cold audit validates the entire current journal before
rehashing the selected original rows. Added rows cannot hide a halt or malformed
record; removed or changed original rows cannot preserve the baseline.

Post-base P/commit/finality digests use new `trnm.native.replay-execution-p.v1`,
`trnm.native.replay-execution-commit.v1` and
`trnm.native.replay-execution-finality.v1` domains. Never widen old parent_kind
semantics or manufacture an old `PreparedNativeEpochExecutionV1` capability.
Factor shared pure execution/receipt/header/snapshot checks; do not copy the
execution engine or relax old schema10 row/proof bijections.
The installer creates empty post-base tables. Only the explicit ordinary
continuation writer below may populate them; cold admission independently
reexecutes every P and verifies the original proofs and current metadata.

Hard admission bounds: history1..256 consensus records, independently0..32 epoch
transitions, complete retained canonical history/authority at most64 MiB; source
plus new P at most128 rows and2 GiB aggregate bounded blobs; at most8 pending new P;
snapshot at most256 MiB, each replay set at most16 MiB, lifecycle/set at most1 MiB,
artifact at most16 MiB, individual proof at most8 MiB and post-base proofs at
most64 MiB aggregate. Source audit, history, P, proof and temporary decoder limits
are independent. These are resource limits, not a claimed peak-memory SLO.

`install_historical_replay_base_v1(prepared)` is the only schema12 creator;
opening a store never migrates it. Hold owner lock and namespace pin, BEGIN
IMMEDIATE, re-audit and compare all source facts/inventory inside the transaction,
create exact new tables/rows and replace current metadata using a full CAS,
COMMIT, fsync database and parent directory, then perform fresh cold-equivalent
audit before issuing `ConfirmedNativeReplayBaseV1`. A failure after COMMIT is an
uncertain outcome requiring readback, never a fabricated rollback. Exact input
retry identifies the existing installation byte-for-byte. After C33, retry may
acknowledge the historical installation but cannot restore C32 metadata or issue
a current C32 execution capability.
Ordinary `open`, legacy metadata/P readers and all legacy preparation writers
continue to reject schema12. Explicit `open_historical_replay_v1` requires an
existing database and issues no execution or signing capability. Hot rollback
may restore schema10, which must then be opened through its ordinary owner for
a fresh installation retry. Cold installation confirmation reestablishes both
database and directory fsync before fresh replay/readback; a readable image
alone cannot acknowledge a prior process's uncertain COMMIT.
Legacy checkpoint preparation takes the same owner operation lock before its
fresh physical-schema check and retains it through journal reserve/bind. A
checkpoint computed before installation cannot write or return preparation
authority afterward. Read-only checkpoint confirmation releases this lock before
entering other owner reads, then reacquires it for the final journal/owner check.

Cold audit is one bounded nonrecursive pipeline: exact physical schema and SQL
screens, frozen source10 audit, M01 retained-history verification, deterministic
M06 replay, base equality, post-base P/proof audit, current metadata equality.
Pass an explicit private source-read policy and the frozen C18 metadata to shared
source readers. Do not globally add12 to `is_epoch_schema`/`has_later_*`, skip
source proof ledgers on physical12, temporarily alter schema/head, create
compatibility views or clone a temporary database to make old audits pass.
The internal `EpochReadPolicyV1` selects either normal physical reads or a
retained schema10 view with an explicit frozen `MetadataV0`. It is interpretation
data, never a verification capability. Cold reconstruction derives the frozen
head, snapshot, replay sets and sequence from the actual retained committed P and
complete source inventory; serialized base fields only supply comparisons.
Thread the same policy through lineage consumption, installed-edge head checks,
all checkpoint/first-new/ordinary proof ledgers, P validation and metadata-store
validation. Every ordinary entry point keeps physical reads. A policy must not
silently fall back to the mutable imported head or omit a schema10 proof ledger.
Reuse the audited source store/prefix and sequence set once. Source sequences,
installation sequence and new P/commit sequences must be disjoint. Persisted
download/progress state is only a cache; restart re-verifies and reexecutes from
the still-valid local anchor. The first bounded implementation may restart all
256 steps rather than trust a cached private snapshot.

Required acceptance: genuine receiver C18 capture before any C21 preparation;
signed nonempty transactions before and after the anchor; exact state and replay
equality at C32; source B remains installed/unconsumed through C33 and cold open;
typed source rows unchanged; altered source B or deleted original source proof
rejected even after recomputing local hashes; duplicate command/signer-nonce,
wrong body/root/configuration, stale source CAS, alternate local parent commit,
wrong original C33 proof and stale post-C33 import retry rejected. Exercise real
SIGKILL before COMMIT, after COMMIT/before fsync and after fsync/before response,
with cold recovery and exact retry. Existing schema10, anti-double-sign,
persist-before-sign and deterministic execution tests remain mandatory.

### Ordinary continuation from an imported base (M08-REPLAY-EXECUTION-V1)

This candidate owner implements ordinary continuation without public-node or
next-epoch activation. Explicit APIs are `preview_replay_block_v1(request)`,
`prepare_replay_execution_v1(request, header)`,
`reopen_prepared_replay_execution_v1(block_id, P_digest)`,
`commit_replay_finality_bytes_v1(prepared, proof, budget)` and
`confirmed_replay_head_v1()`. Preparation returns a distinct owner-affine,
private-field, non-Clone `ConfirmedPreparedNativeReplayExecutionV1`; commit
returns `CommittedNativeReplayExecutionV1`. Neither type supplies signing or
legacy epoch authority. Preview/head readback grant no durable capability.

Every operation starts with the complete installed-base audit. Its independently
reexecuted store, full local head/header, active configuration and mixed snapshot
coordinates are private computation facts. Source-prefix coordinates retain
their original bindings; replayed activations retain their strict M01 bindings.
Only the shared M06 complete executor applies a new Regular block. The request
must name the exact local parent Head104, chain/genesis, current set and parent+1
height. Reconstruct the canonical payload from the request, bind every header
field/root, enforce active epoch geometry, leader, increasing view and timestamp,
and reject checkpoint/handoff/seal or next-epoch commitments. Apply the executor's
state plan and command/signer-nonce identities together; derive lifecycle from
execution, never from peer state or metadata alone. The existing sparse snapshot
validator checks the combined audited coordinates before serialization.

Parent kind0 names exactly the installed base and has no parent-P digest. Kind1
names an exact earlier row in the new P table, including its stable prospective
local head and P digest; it may be Prepared or Committed. No old source P is a
post-base parent. Preparation allocates current sequence+1 and atomically writes
the complete P plus the sequence CAS. P digest frames base digest, P sequence,
one-byte parent kind, Head104, a tagged optional parent-P digest, and the SHA-256
digests of header, artifact, snapshot, commands, nonces and lifecycle. Commit ID
frames base digest, P digest, block ID and snapshot digest under the new commit
domain; it is independent of the later commit sequence so speculative descendants
retain their exact parent identity. Status and commit fields are not P inputs.

For finality, extend only an ephemeral consensus header path: unchanged source
anchor, original base headers/activations, exact new-P ancestor headers, then the
target header and its original finality proof. Use M01's complete historical
verifier, including epoch-runtime synthetic-anchor TC checks and the caller's
remaining work meter. Match the exact target and parent timestamp. This temporary
path retains the existing256-header/32-transition/64-MiB limits; capacity exhaustion
rejects before mutation. Never replace the base terminal proof or reexecute an
extended NHR1 as a new base: doing so would change its input/run/step commit IDs.

Cold replay audits use one shared `Cev0AdmissionBudgetV0` for every retained
post-base finality proof; they must not create a fresh protocol meter per row.
Admission measures a newly submitted proof with the caller's remaining meter,
then reserves that measured delta against the same aggregate meter before any
P/finality transaction write. If the aggregate reservation would exhaust the
meter, the caller's measured work remains charged and the transaction is
rejected without a new row or status change. An exact committed retry still
measures the proof against the caller's remaining meter, compares the retained
proof bytes, and acknowledges without charging the aggregate meter a second
time. The genuine-proof budget regression measures C33's work, rejects at one
unit below that aggregate cost without changing the database, then commits,
retries and cold-opens at the exact cost. Previously charged caller work remains
separate from this proof's measured increment. The test-only cap is scoped to its
thread; deployed builds always use the fixed protocol cap.

Commit requires the current committed Head104 to equal the P parent. Atomically
allocate sequence+1, change exactly that P to Committed, retain the exact original
proof and replace current snapshot/replay/head using CAS. The finality-record
digest frames base digest, block ID, P digest, actual commit sequence and proof
digest. All source, installation, new-P and new-commit sequences are disjoint;
new allocations form a contiguous suffix after installation. Exact prepare and
commit retries allocate nothing; acknowledged commit retry requires identical
proof bytes. Both writes fsync database and directory and fresh-audit before
issuing receipts. Failed fences return an uncertain result; cold receipt recovery
must reestablish both fences. Historical installation retry after C33 confirms
only the unchanged base and never rolls back current metadata.

Cold audit first reconstructs the base once, then walks new P in sequence order.
Reexecute each row from its previously audited parent snapshot/replay sets and
compare all artifact, root, replay, lifecycle and digest bytes. A committed child
requires a committed parent (or base), and all committed rows form one exact
chain from the base. Verify every original proof, enforce P/proof bijection and
sequence uniqueness/continuity, then derive the current head and complete metadata
from the committed chain and maximum allocated sequence. Pending forks remain
bounded and cannot replace current state. SQL screens enforce combined source/new
P128, pending8, per-proof8 MiB, proof aggregate64 MiB and total2 GiB before row
allocation. No automatic pruning or second import is introduced by this revision.

`historical_replay_continuation_sigkill_six_cuts_preserve_exact_c33` exercises
prepare and commit before COMMIT, after COMMIT/before fsync and after fsync/before
response. Each cut uses a real killed child, cold audit and exact retries over
one genuine nonempty source fixture. `historical_continuation_sql_bounds_reject_combined_pending_and_proof_overflow`
checks SQL admission limits independently of malformed consensus fields. These
local regressions do not supply multi-host or physical power-loss acceptance.

## Retained contextual successor proofs (M08-SUCCESSOR-CONTEXT-V1)

This primary-M08 candidate integration implements the following contract. A later checkpoint
proof may contain a TC referring to the outgoing epoch's synthetic anchor. Its
producer, durable commit, cold recovery, first-new/ordinary proof consumer and
exporter must share the M01-SUCCESSOR-ACTIVATION-V1 verifier. No new wire bytes,
schema migration, signing permission or imported-base checkpoint authority is
introduced by this integration.

The private lineage resolver authenticates predecessors in order. For a later
checkpoint it uses the last audited strict activation and follows the exact
checkpoint-parent P chain back to that activation's terminal seal. The terminal
seal comes from the original verified proof; it is not an application P row.
Every application header comes from an exact block-ID lookup, committed status,
matching store and full lineage, canonical header/height/consensus-parent fields,
and strictly ordered commit sequences. Never select arbitrary rows by height.
Screen SQL type and byte length before copying header or lineage blobs. Bound
the complete interval, including both endpoints, to 256 headers and 1 MiB.
Read only bounded header/identity columns while walking; do not copy every
ancestor's full snapshot and replay sets. Existing outer inventory execution,
P digest, fork and snapshot audits remain mandatory and nonrecursive.

Pass original eight-root evidence, the audited predecessor and the exact forward
interval to M01's strict successor entrypoint. The returned private activation
joins the same prefix used for checkpoint context, consumption, deterministic
cutoff selection and record digests. Retain no serialized authority or alternate
signature algorithm. Cold open rebuilds the prefix from original committed rows
and proofs each time. Missing or modified intermediate ancestry rejects before
any receipt. Context/configuration equality alone never connects histories.

Live checkpoint verification may observe a Prepared checkpoint whose immediate
parent is committed. It must not require the checkpoint itself to be committed
before verification. It retains the owner-bound prepared P check, original cutoff
selection, current context digest and fresh post-verification owner readback.
Only the existing atomic checkpoint commit can record the proof and successor
edge; prefix recovery of an installed successor still requires a committed
checkpoint. No temporary metadata rewrite or public recovery recursion is allowed.

First-new and ordinary proof verification consume the strict runtime context
rebuilt from that exact lineage, preserving the exact header/parent expectation.
The caller meter admits the submitted proof, including pre-existing work charges
and charges retained on failure. Retained owner evidence is reverified separately
under the existing 32-edge inventory bound, each activation's protocol meter and
the bounded ancestry interval. The former first-new path also re-admitted the
selected activation into the caller meter; this integration removes that duplicate
admission and crypto work. It does not reset the submitted-proof meter or weaken
cold prefix verification. They must not pass contextual activation evidence
through a context-free decoder again. Commit, retry and cold proof audit use the
same path; original proof-byte identity, CAS, fsync and fresh readback remain
required. Retained schema10 interpretation under schema12 uses its existing
explicit source-read policy, never the mutable imported head.

Both export formats read one immutable audited transaction. The historical
exporter copies the two original seals from its already verified prefix facts;
it does not reparse valid contextual evidence with the v0 decoder. Exported
activation roots and terminal proof bytes remain unchanged. M13's per-step
consumer retains verified epoch context and the bounded authenticated header
interval needed to verify the next activation; a starting anchor with no prior
activation still cannot authorize an unknown synthetic reference.

Required evidence is a genuine C28 checkpoint whose S30 TC references both
QC(S29) and the verified S20/view0 anchor. Preserve the actual C25 selection and
owner-prepared C28 header, sign S30 at the skipped view and both handoff roles,
then exercise C28 commit/cold open, C31/C32 original proof commit/retry/reopen,
per-step sync verification and NHR1 export/history verification. Keep the old
no-TC regressions. Pin first-new proof-only admission with exact, one-less and
precharged caller budgets. Canonical signature corruption, wrong anchor, missing or
substituted committed ancestry, prepared intermediate rows and mismatched
retained proof bytes must reject without changing head or sequence. This local
result does not close M02 successor journals, public transport, imported-base
next-checkpoint execution or multi-host acceptance.

## Activation boundary

M08 remains candidate until the default node's real producers and consumers
implement both separate paths, arbitrary valid proposals/transactions, bounded
recovery and state-sync rejoin, and independently accepted device, physical-fault
and multi-host evidence is bound to the exact artifact. The local strict-finality
seam and persistent ingress bridge alone do not close these requirements.

### Default-off actual checkpoint fixture

The native crate's `test-fixtures` feature exposes a deterministic producer of
actual SQLite application history through checkpoint C=8, not a receipt
constructor. It returns the real owner, retained executions, prepared checkpoint
handles, signed ordinary headers and strict checkpoint/two-seal bytes so M15
can invoke the normal fresh receipt issuers and replay Core/journal8 with the
same commitments. This fixture explicitly trusts an operator-selected genesis
(application initial BlockId equals genesis hash); it does not establish
CanonicalLabGenesis commissioning. The feature is off by default and must stay
outside production dependency closure. No receipt, Core ACK or signer custody
is synthesized by the fixture.


### Default-off schema6 incremental first-new recovery

M07's explicit schema5-at-C→6 migration accepts only a fresh owner-affine native
edge and retains its exact bounded evidence. `execute_incremental_epoch_block_v1`
atomically writes changed state/replay data and exact first-new P at C+3 without
advancing the committed C head. `PreparedNativeIncrementalEpochExecutionV1` is
non-Clone; its P digest/persist sequence and signed header are comparison data.
Its matcher and `reopen_prepared_incremental_epoch_v1` reconstruct the strict
native edge from actual cutoff/checkpoint/preparation rows, then bind the exact
P to state/replay roots, storage identity and both parents. A missing preparation
journal fails closed and never causes recovery to recreate signing evidence.

Three SIGKILL cuts cover before transaction commit, after commit before fsync,
and after fsync before fresh readback. Native P and storage edge/delta counts
must be all zero or all one; committed head remains C in every case. Legacy
commit/recovery and ordinary ni apply explicitly reject this candidate schema
or sparse artifact. Schema6 itself still rejects finality commit and descendants. The separate
schema7 migration below adds those native operations; whole-node schema7
integration, public proofs/replay and GC remain pending. No prepare-only result
is a committed receipt, Core ACK or production gate.

The fresh at-C `ConfirmedEpochApplicationEdgeV1` exposes
`strict_activation_binding_v1() -> &StrictEpochActivationBindingRefV0`, obtained
by strict decoding/reverification of its exact retained joint evidence. M15
compares this typed digest to journal9's activation binding; the separate native
`authorization_id` uses a different domain and must not substitute for it.
Issuance also explicitly requires checkpoint P sequence>0 and actual commit
sequence>P sequence, plus the existing exact owner/head/P and preparation checks.


### Versioned later checkpoint commit contract (schemas8 through10)

Primary module: M08; producers M06 and M02, storage consumer M07. An explicit
`upgrade_later_epoch_schema_v1(expected_head)` migrates schema4 by atomically
adding `native_later_epoch_finality_v1`, `native_later_epoch_edge_v1`, the
schema9 first-new ledger and schema10 ordinary ledger, then CASing the version
to10. Explicit migration from8 requires zero consumed later edges; migration
from9 requires no already committed ordinary later descendant. Both require
exact table/edge/history checks as specified above. Ordinary open never
migrates. Existing schema4 edge/P/context records remain unchanged.

`commit_later_epoch_checkpoint_finality_v1` consumes the owner-bound strict
observation for the exact prepared checkpoint. Under the owner lock it joins
the committed C-1 P, active configuration and lineage, historical cutoff root,
checkpoint/two-seal proof and old/new handoff signatures. A single transaction
commits the checkpoint P, native metadata/context and checkpoint-keyed proof
record. Seals never execute application state. Fsync and fresh immutable
readback precede the returned commit receipt. Reopen must reverify the strict
proof and its local P/parent/cutoff bindings, not merely its checksum. Missing,
oversized, substituted or detached records reject recovery. Repeated commit
must return the same sequence; a reopened owner obtains recovery readback
from retained evidence rather than reusing an old live-owner token.
Each predecessor edge is single-successor: the ledger rejects duplicate
`predecessor_edge` values, and a later proof is admissible only after the
predecessor edge is durably `Consumed` with its exact handoff P and sequence.
An installed or rolled-back predecessor therefore cannot be promoted by a
proof-row insertion.

Acceptance requires real C18/S19/S20 evidence, explicit migration and reopen,
exact retry, foreign-owner rejection, proof/record corruption, and process
termination before commit, after commit and after fsync. This contract advances
the checkpoint application head and installs the successor-edge ledger row.
First-new C+3 execution has a candidate prepare/strict-commit seam, a retained
application proof, a positive C21 fixture and three crash/recovery cuts. Schema7
incremental multi-edge storage and production Core/signing remain separate open
requirements.

The explicit `inspect_later_epoch_application_edge_requirements_v1(C18)` seam
now makes the successor contract executable. It
reopens and validates the committed checkpoint P, parent P, proof record,
predecessor lineage and strict CEV0 activation authority, then returns the
predecessor binding, independently recomputed successor activation binding,
checkpoint/terminal/first-new heights, and two context digests. The proof
context digest is the pre-C18 context retained by schema8; the successor
context digest is recomputed from the post-C18 head, sequence, target
configuration and lineage. Schema8 persists those fields in
`native_later_epoch_edge_v1`, and `require_later_epoch_application_edge_v1`
returns an owner-affine capability only after a complete cold audit. The
capability's old `execute_later_epoch_first_new_block_v1(&edge)` method still
fails closed because it has no request/header inputs; the new
`prepare_later_epoch_first_new_block_v1` seam performs candidate C+3 execution.
Its strict finality consumer atomically updates the P, metadata/context and
successor edge phase, and the schema-9 application-finality ledger retains and
cold-reverifies the C+3 proof. The local fixture and three crash cuts cover the
real positive C21 path. The current
fixture asserts predecessor H17, successor height 21, distinct non-zero
bindings and distinct context digests, and proves the old H17 edge cannot open
an application store after C18 is committed.

The native fixture now exercises migration, C18 commit, exact retry and cold
recovery. A signature mutation with a recomputed local record digest, a
deleted proof record, and an installed-phase predecessor edge all reject
reopen. The three-cut
`later_checkpoint_sigkill_commit_cuts_recover_exact_native_and_proof_record`
test kills actual subprocesses before SQLite commit, after commit and after
fsync; restart sees only H17 with prepared C18 or fully committed C18, and
recovery retains the exact commit sequence. These are local process-crash
results, not physical power-loss or repeated multi-epoch acceptance.

### Schema10 retained finality path export contract

The read-only producer is
`DurableNativeApplicationV0::export_epoch_finality_path_v1(anchor_block, target_block)`.
Both identifiers must name retained committed application P records, the anchor
must precede the target, and the target must belong to the currently audited
committed chain. The owner holds its operation/namespace guard, rejects SQLite
sidecars, and audits schema, metadata, complete P inventory and both proof
ledgers through one immutable connection. Export changes no sequence, head,
edge phase, preparation, signer state or database schema. Schema10 is required;
missing historical proofs cannot be manufactured from execution artifacts.

`NativeEpochFinalityPathV1` is an inert public data carrier, with canonical
anchor/target headers, target schema version, P digest, commit sequence and
ordered `NativeEpochFinalityStepV1` records. Each record contains its exact
canonical target and consensus-parent headers, retained original proof,
retained record digest and optional `EpochActivationEvidenceBytesV0`. These
fields carry no owner, installation, activation or signing authority. The
eight epoch roots reuse existing canonical encodings; this API allocates no
aggregate protocol wire identifier.

Walk backward through exact committed application parents, at most 128 unique
P records, then reverse the result. An ordinary step advances one height under
the same lineage and configuration. A first-new step advances from checkpoint
C to C+3, takes its consensus parent from the authenticated terminal seal C+2,
and must exactly match the consumed edge, P digest and commit sequence. Its
original proof comes from `native_later_epoch_application_finality_v1`; its
eight evidence roots come from the strictly verified mixed-prefix activation.
Ordinary Regular proofs come only from the schema10 descendant ledger;
checkpoint proofs come from the retained checkpoint-finality ledger. Legacy
first-new/ordinary history without an original retained proof is unsupported.
Every selected row must match its P and exact parent and retain its original
proof/record digests. SQL type/length screens precede blob allocation; exported
headers, proofs and evidence together must fit 64 MiB, with each proof bounded
by the existing 8 MiB CEV0 root ceiling. The final namespace/metadata observation
must still agree with the audited read.

M15 consumes these bytes as untrusted input and M13 strictly verifies every
step from a separately configured `NativeTrustAnchorV1`. Neither the exported
anchor header nor local P/record hashes select trust. The consumer checks full
anchor and terminal headers and derives proof expectations from canonical
headers, with the existing aggregate byte/link/work ceilings. Wrong anchors,
missing/swapped proofs, wrong parents, truncated/duplicate lineage, mismatched
sets/parameters and target substitution must reject. Acceptance requires real
C18→C21→C22 producer-to-consumer evidence, byte-identical export after reopen,
and fail-closed corrupted/downgraded database cases.

This contract initially exports finality only. The private sparse Borsh
snapshot needs a separately specified bounded public state codec, complete
authenticated historical gap coordinates, application-root recomputation,
manifest/chunk binding and atomic installation/recovery. A verified finality
path does not complete a state-sync session or activate a signer. These
requirements remain open until their own positive and negative evidence exists.

### Candidate schema-9 first-new application-finality ledger

The complete fields, bounds, digest domains, migration refusal and atomicity
rules are defined in [Schema9 retained later application finality](#schema9-retained-later-application-finality).
Schema10 preserves that C+3 table and adds the separate ordinary ledger above;
ordinary commits never replace the consumed target or its retained first-new
proof. Repeated later handoffs and multi-host acceptance remain open.

### Implemented schema7 strict commit and pending descendants

The next incremental revision is specified in M07's
[required schema11 multiple-edge owner](M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md#required-schema11-incremental-multiple-edge-owner).
M08 must consume its explicitly migrated per-edge proof inventory and exact
authenticated prefix, preserve every committed first-new/checkpoint/ordinary P
during fork retirement, and retain byte-exact original evidence through C18 and
C21 crash recovery. The current schema7 singleton APIs cannot serve as this
multiple-edge authority. Schema11 implementation and its two new SIGKILL
matrices remain open.

The default-off native candidate now exposes two distinct finality consumers:
`commit_incremental_epoch_finality_bytes_v1(&first_p, bytes, budget)` validates
strict epoch-first finality; `commit_incremental_epoch_descendant_finality_bytes_v1`
validates ordinary three-chain finality under the authenticated new configuration.
Both return `CommittedNativeIncrementalEpochExecutionV1` only after the state,
replay, native P/commit record and current head share one committed transaction,
file/directory sync and fresh owner readback. Their exact retries preserve the
original native commit sequence. A prepared C+4 cannot commit ahead of C+3.

`confirm_prepared_incremental_epoch_execution_v1` and
`confirm_prepared_incremental_epoch_descendant_v1` take the actual owner-affine
capability and re-read its exact persisted P. Returned comparison data includes
full header, actual application parent/target head, artifact/overlay checksum,
exact native payload/receipts, native persist sequence, optional commit sequence,
and native edge identity. The first block's consensus parent remains C+2 while
its application parent remains C. The non-Clone receipt and its live owner/path
matcher must be consumed together; getters alone cannot seal Core or acknowledge
application commit. Fresh committed matchers compare current head, exact P
digest and actual commit sequence, including after a lost-response retry.

Reopen re-verifies strict retained evidence and the original COMMITTED checkpoint
P. The first retained artifact is checked against all signed header commitments,
actual payload/receipts, both parents, native/storage persist identity and exact
command/nonce replay delta. Committed descendants form one bounded chain back
to that first record with strict proofs under the same new configuration. Pending
forks are reauthenticated before use; an inventory row is not a reusable P.

The local signed fixture executes a real credit at11 and eight transfers at12;
serial and1/2/4/8-worker results agree on roots, payload, receipts and duplicate
command failure. Strict commit11 advances C8→11 and preserves prepared12/13;
strict commit12 selects its branch and preserves13/14 while retiring losing
branches. Two three-cut SIGKILL matrices interrupt before SQL commit, after
commit and after fsync: first-new restart yields only head8 or11 with exact
retry sequence21; descendant restart yields only head11 or12 with exact retry25.
Rehashed artifact timestamp, application-parent commit ID and storage-sequence
mutants must fail cold open despite recomputed local P/head/record checksums.
These are actual local process-crash and consistency tests, not device-loss or
independent production acceptance.

Live custody confirmation additionally binds held Unix database, parent-directory,
lock-file and preparation-sidecar identities as specified in M07. Replacing the
DB with byte-identical content cannot preserve the live owner's receipt authority;
identity failure is sticky even if the original file is restored. Cold reopening
creates an independently validated owner, so an old receipt cannot become affine
to it. Current native schema7 support does not claim a joined Core/node adapter,
second epoch transition, state-sync/public proof endpoint or garbage collection.

The candidate closure now has a narrow owner-only bridge:
`CandidateEpochRuntimeV1::ensure_incremental_epoch_commit_owner_v1()` joins the
already recovered full owner cut, calls the native resumable schema7 owner
dispatcher, and confirms all physical cuts again. It does not submit a block,
consume finality, produce a receipt, sign, broadcast, or enable public sync;
schema5→6 migration and strict first-new finality remain explicit preceding and
following operations. The bridge is covered by native cold-reopen and malformed
commit-row fencing tests and remains default-off.

Later checkpoint proof recovery has an explicit strict observation and schema8
commit seam:
`DurableNativeApplicationV0::verify_later_epoch_checkpoint_finality_v1()` joins
the durable C-1 application head, exact checkpoint/two-seal evidence, cutoff
state-root, old/new validator and parameter preimages, and handoff kernel under
one bounded verifier. It reopens the owner context after verification, so a
stale or foreign observation is rejected. The native fixture covers H17 -> C18
-> S19 -> S20 with real signatures and a mutated commitment negative.
The schema8 owner writes the M08 checkpoint ledger and recovers it with fresh
strict verification. It does not issue the second activation certificate or
production finality source; those remain open.

Certificate replay has an explicit no-effect seam: when a verified late TC or
QC is already consumed by Core and produces no persistence effect, the node
returns the unchanged Ready/VoteSigned/TimeoutSigned owner. It does not force a
prepared K to match an older high QC, and it does not clear the persisted
prepared owner. Any certificate that changes Core still goes through the full
preflight, checkpoint CAS, and high-QC path audit above.

### Current native live export boundary

M08 implements the read-only schema10 owner operation specified by
**M06-M13-LIVE-V1** in [M13](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md).
The export is tied to the exact current committed head under the existing owner
lock and one immutable transaction, and uses M06's bounded leaf codec. It emits
no replay authority, historical sparse snapshot or installer capability.
