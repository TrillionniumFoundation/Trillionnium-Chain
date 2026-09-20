# M08 Finality / Node Commit / Recovery technical specification v1

Status: **strict pre-handoff receipt and bounded first-epoch durable bridge implemented;
multiple-epoch/default-node integration pending; production activation not granted**

Primary module: M08. Producers: M02/M03/M06/M07. Consumers: M02/M03/M13/M14/M15.

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
CAS. The broader node-checkpoint composition below remains planned, and its
proposed `TRNMEDG1` container is not the implemented schema-4 encoding.

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

The commit transaction updates metadata/snapshot/replay and P status together,
consumes the edge only for its first block, installs active context, prunes only
unrelated prepared forks and advances durable_sequence once. Database/file/
directory synchronization and fresh metadata/P readback precede return. Exact
prepare/commit retries repeat synchronization/readback and keep their immutable
P/commit sequences. Seals produce none of these records. The context digest is
`hash_domain("trnm.native-application.epoch-context.v1", [store_id, complete head
(height/block/root/commit), head_commit_sequence, SHA256(set), SHA256(parameters),
SHA256(lineage)])`, with U64/H32 encoding above.

This bridge currently admits a legacy-v0 committed checkpoint, its first-new
block and ordinary descendants. Later-epoch checkpoints from familyv1, general
sparse-history finalized RPC/proof interfaces and independent node checkpoint /
publication ownership are still fenced or pending. Schema4 rejects ordinary
`execute_block` so the legacy +1 path cannot synthesize application effects for
seals. It is not the full multi-epoch default-node pipeline.

The schema4 lineage audit now accepts a committed familyv1 checkpoint `P` only
when its artifact kind, target, prepared digest, header kind and next-epoch
commitment match exactly. It recursively audits each predecessor `P` with a
bounded seen-set and rejects cycles, missing predecessors and owner mismatches;
an epoch checkpoint is admitted to descendant preparation but cannot be passed
to ordinary `commit_epoch_finality_bytes_v1`. The later checkpoint's required
second edge, strict two-seal plus handoff finality commit, schema4
`read_finalized_by_height` mapping and schema7 multi-edge history/owner API are
not implemented yet. Their public entry points fail closed with an explicit
bridge-required error, and the schema7 singleton owner must not be weakened to
silently attach a second edge to the first. This boundary is intentional until
the edge-history record and recovery contract are versioned and tested.

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
  JMT C+3, and the next epoch's exact cutoff. Verify both roots and commit_sequence.
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

Freeze byte-exact planned node receipt/edge/local-intent vectors with positive and
negative independent consumers before implementing public restore paths.
The existing strict proof vectors remain unchanged. Acceptance uses actual
Core/Safety/native store/signer owners over two consecutive epochs; a fixture
assigning a future phase or root is not a passing implementation.

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


### Implemented schema7 strict commit and pending descendants

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

Certificate replay has an explicit no-effect seam: when a verified late TC or
QC is already consumed by Core and produces no persistence effect, the node
returns the unchanged Ready/VoteSigned/TimeoutSigned owner. It does not force a
prepared K to match an older high QC, and it does not clear the persisted
prepared owner. Any certificate that changes Core still goes through the full
preflight, checkpoint CAS, and high-QC path audit above.
