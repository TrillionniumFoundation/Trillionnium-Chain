# M02 Order / Consensus Kernel technical specification v1

Status: **frozen ordinary v0 rules plus implemented candidate outgoing epoch-zero
checkpoint/seal owner; new-epoch Core activation remains planned and closed**.
Primary module: M02. Producers/consumers: M00/M01/M03/M04/M06/M07/M08/M13/M15.

## Authority

Specifications `poco-bft-v0/01` through `07` define the protocol. This document
selects a local implementation architecture; it does not alter v0 signing
bytes, quorum, three-chain finality, seal semantics or epoch geometry.
`trnm-consensus-core/src/{model,core,block_tree,safety_state_record,error}.rs`
are current implementation references. `epoch_preparation.rs` currently has
only `EvidenceVerified`. Ordinary schema13 `Core::require_pre_checkpoint_height`
refuses checkpoint and later heights. The explicit strict outgoing owner below
admits the scheduled checkpoint/two seals without opening an epoch anchor.

The target is one pure deterministic owner with explicit durability barriers,
epoch-qualified ancestry and a recoverable checkpoint/seal/handoff path. Removing
the existing fence without implementing that whole path is not this design.

## Interfaces

### Existing event/effect boundary

`Core::step` consumes typed `Input`: Proposal/SyncedProposal, Vote/TimeoutVote,
QC/TC, LocalTimeout, payload completions, StorageAck, SafetyReplayComplete and
SignatureReady. Existing `Effect` includes PersistSafetyState, payload validation,
RequestSignature, Broadcast, ArmViewTimer, sync requests, SafetyHalted, Finalize
and Evidence. Completion generations/owners are part of admission, not advisory.

`CoreConfig` binds local validator, validator set, exact parameters, trusted
genesis timestamp, max_blocks and max_observed_messages. Its validation matches
parameter hash/protocol and local membership. The optional development genesis
application parent is an operator-pinned trust root; it is not committed by the
current synthetic GenesisQC and must not be advertised as peer-authenticated.

Pure kernel code owns no database, sockets, clock, thread pool or signer. M15
routes effects to one designated adapter; callbacks cannot choose a different
Core or reconstitute non-cloneable completion tokens from diagnostics.

### Implemented outgoing owner and bounded migration

`Core::into_old_epoch_boundary_v1(self, owner_generation: u64)` consumes a
quiescent schema13 owner after strict Ed25519 key/state verification and returns
`(OldEpochBoundaryCoreV1, Vec<Effect>)`. Generation must be positive. The no-Clone
wrapper exposes strict `step_v1`, exact application-seal/finalization receipt
callbacks, persistence binding and signature-release callback; no mutable Core
or caller-selected verifier escapes. Migration is rejected after an explicit
SafetyRules authorization was issued, or with unresolved persistence, signature,
application/finality/sync work or unequal finalized/applied tips. The sole
schema13→14 successor is the exact old state plus empty boundary metadata and
revision+1. Existing signer state, QCs, views and roots cannot change in migration.

`OldEpochBoundaryStateV1` retains full authenticated checkpoint proposals with
their exact application parent and full seal proposals. A checkpoint enters this
record only after the existing authorized Valid callback; no public static body
summary creates application authority. Multiple bounded candidates may coexist
until finality; one speculative P is not the chosen checkpoint. Every retained
proposal and parent, QC/TC signature and terminal Valid overlay is checked by
strict persistence validation. The owner uses the existing Core vote, lock,
three-chain and persist-before-sign engine. Journal7 cannot acknowledge the new
record; M03's distinct journal8 is required.

Scheduled seals use `validate_empty_epoch_seal_v1` and `ConsensusSeal` in the
existing block tree: unchanged state/next-commitment roots, exact canonical empty
body/receipts/evidence, direct parent/QC and scheduled old-set geometry. They
never request application execution, create P/overlay/receipt, or become an
application-finalization target. QC(C+2) finalizes the actual checkpoint C;
Core's true finalized/applied tips remain C. Synced seal admission persists the
same bounded evidence without a vote or application request; exact replay is
idempotent. The explicit pure SafetyRules context understands these typed seals;
the ordinary context remains Regular-only.

The implemented outgoing phases are 0..4 only, derived from retained evidence
and applied checkpoint rather than a mutable scalar. `TRNMS14O` is the separate
local codec described in M03. The schema13 frozen codec, ordinary owner fence
and generic recovery rejection of schema14 remain intact. There is no new-set
view reset, anchor-installed Core, ordinary signer retirement, or full cross-epoch
`FinalizedTip` support in this slice. Strict full first-proposal verification in
M01 is a prerequisite, not an activation API.

`Core::prepare_old_epoch_terminal_recovery_v1(record, context,
expected_record_checksum, expected_owner_generation)` strictly revalidates only
the stable `CheckpointApplied` cut, exact full retained checkpoint/two-seal proof,
canonical bytes and independently expected checksum. Pending sign/P/finalization,
sync, halt or foreign cuts reject. The returned `StrictOldEpochTerminalRecoveryV1`
is inert: it cannot step, sign, emit timers or yield a Core. M15 must subsequently
join actual journal8 freshness, native COMMITTED checkpoint and shared signer
custody capabilities; equality of public scalar tuples cannot replace that join.

Acceptance currently combines a full outgoing Core test using the explicit
unit verifier/application fixture, exact codec/migration/replay tests, and
independent real Ed25519 first-proposal tests. A real-signer, native prepared
checkpoint receipt, journal8 ACK and strict live Core joined positive test is
still required before candidate host activation can be claimed.

### Full epoch integration (implemented inert slice; live owner pending)

The pure representation uses `QualifiedFinalizedTipV1` for true finality/application
coordinates and `ConsensusAncestryBaseV1` for the independent graph root. An
installed edge retains the complete old checkpoint proof/configuration, exact
terminal-old header and new view-zero anchor; it never changes an old header's
epoch or view. Before first-new finality, true tips are C/old epoch while graph
ancestry begins at terminal C+2. A first-new application parent explicitly carries
both real checkpoint C and consensus terminal C+2 plus the strict activation
binding. Its overlay/finalization codec must retain both, not reinterpret a v0
single-parent record. Only a genuine new-set three-chain moves true finality to C+3.

`StrictEpochRuntimeContextV1` is the implemented M01 consumer of all eight strict
activation roots for exact QC/TC/proposal/finality admission throughout the new
epoch. Structural decoder context remains inert. Generic genesis/ordinary APIs
retain their anchor rejection. The full local record uses the separate
`TRNMS14E` envelope and exact old/new contexts, while schema13 and outgoing
`TRNMS14O` bytes stay unchanged. Context retention is bounded to those referenced
by active evidence; replacing an edge requires prior application/finality work
to be settled and the new checkpoint independently verified.

`EpochCoreStateV1` retains complete strict evidence and the checkpoint artifact.
`EpochSafetyStateRecordContextV1` and the separate 14E codec are implemented;
their decoder returns only `UnverifiedSafetyStateRecordV0`.
`OldEpochBoundaryCoreV1::prepare_epoch_activation_v1` consumes the old live Core,
requires the exact completed checkpoint and no pending work, preserves global
revision+1, and returns `PreparedEpochCoreActivationV1` with no step, persistence
ACK or signer API. The pure SafetyRules consumer keeps its true old finalized
reference while using a separate graph coordinate, and its state digest binds
the full activation. Frozen epoch-zero behavior and schema13 tests remain.
The Core regression uses real frozen Ed25519 evidence but inert P identifiers;
it is not evidence of an actual native/journal/custody activation join.

Pure Core preparation remains inert until concrete candidate composition joins
fresh journal/external cut, `ConfirmedEpochApplicationEdgeV1` from the live native
owner, and actual retired/new custody owners. Optional std integration belongs
only to `candidate-epoch-activation`; default Core stays no_std and production
closure excludes the feature. Continuing membership consumes the old live Core;
new-only commissioning uses independently trusted old checkpoint state and a
virgin new-role custody namespace; removed validators retire without a new Core.
Retirement precedes old handoff signing and binds the pre-certificate context.
The new ordinary lease follows complete joint verification and binds the exact
phase7 persisted Safety cut; these are distinct, non-circular receipts.

### Planned epoch owner types

Names below are target local APIs, not source symbols currently implemented:

```text
prepare_epoch_checkpoint(ValidatedCheckpointExecution, CoreGeneration)
  -> EpochCheckpointPending
apply_epoch_evidence(EpochInput, ExpectedPhaseRevision)
  -> (EpochQualifiedSafety, bounded Vec<EpochEffect>)
install_epoch_anchor(StrictSameVersionEpochActivationAuthorityV0,
                     AuthenticatedEpochApplicationEdgeV1, StorageCompletion)
  -> AnchoredNewEpoch
```

`EpochQualifiedSafety` retains all existing safety fields/obligations and adds
explicit epoch to finalized/high-QC/lock coordinates, a retained old checkpoint
and terminal seal identity, and the transition record below. No old view is
numerically compared with a new view. The existing `FinalizedTip` lacks this
qualification; planned Safety schema 14 must replace that assumption consistently.

`EpochInput` contains only independently verified completions: checkpoint
prepared/applied, seal QC admitted, role decision persisted, joint certificate
verified, edge persisted, anchor installed or first-block applied. A naked hash,
caller phase number or unverified receipt is not a valid completion.

## State machine

### Ordinary consensus

For weight W, quorum is `floor(2*W/3)+1` with checked u128 arithmetic; count each
signer once. Leader is `(view-1)%N` in canonical validator-ID order, unweighted.
Keep that frozen schedule; adaptive/weighted leader selection is not a local fix.

1. Authenticate proposal context, leader signature, parent/height/timestamp,
   exact justify QC, and required preceding-view TC before scheduling execution.
2. M06 validates the complete body against its authenticated parent/runtime.
   `Unavailable` stays pending; `DeterministicallyInvalid` is a bounded negative
   fact unless a verified QC/TC or durable safety anchor names it, then persist
   a safety halt before any dependent effect.
3. Process the learned justify QC under the frozen lock rules. Vote only if the
   proposal extends locked_qc or justify.view exceeds locked_qc.view, and the
   vote exceeds the durable per-epoch last_voted_view (exact replay excepted).
4. Persist decision, resulting Safety state and exact intent before M03 custody.
   StorageAck/SignatureReady must match the issued generation and request.
5. On a QC, detect conflicting same-epoch/same-view certificates before finalized
   subsumption. Require authenticated ancestry and valid payload before adopting
   highQC/lock or finality. A finalized-subsumed historical QC adds no sync work.
6. A direct three-chain has exact parent/justify digests, consecutive heights and
   increasing views in one epoch/set. QC of the third finalizes the oldest and
   unfinalized ancestors, emitted in order. An anchor itself certifies nothing.
7. A TC advances the view but neither unlocks nor finalizes. Every non-subsumed
   referenced QC's data must become valid before dependent votes; the selected
   highest QC must extend/name the durable finalized tip before proposing.

Timers are advisory generation-tagged inputs. The reference backoff is 3/2 from
1,000 ms to 30,000 ms; a deployment may wait longer. Liveness acceptance requires
post-GST communication plus execution/durability within the configured operating
window. A local timeout never establishes Byzantine guilt or a QC.

### Planned epoch phases and non-circular authorization

Let C be the old checkpoint height. Seals are C+1/C+2; first new block is C+3.
The following tags are planned **local phase tags**, not wire discriminants.
Each transition persists a complete successor record before releasing effects.

| Tag / phase | Required evidence and allowed next effects |
|---|---|
| 0 `Running` | One active configuration; no transition owner. Ordinary rules apply. |
| 1 `CheckpointPrepared` | Authenticated finalized cutoff, recomputed next commitment, exact checkpoint execution/body/roots; retain prepared application plan. Old set may vote checkpoint. |
| 2 `CheckpointCertified` | Exact old-set QC(C). Propose/vote seal 1 with frozen unchanged-state/empty-body rules. |
| 3 `Seal1Certified` | Exact QC(C+1) linked to QC(C). Propose/vote seal 2. No application execution for either seal. |
| 4 `CheckpointApplied` | QC(C+2), complete strict two-seal checkpoint finality, M08 COMMITTED checkpoint readback; obtain `PreHandoffCheckpointReceiptV1`. |
| 5 `HandoffCollecting` | Pre-certificate receipt plus exact descriptor; old/new role admissions independently authorized and durably recorded before their signatures. |
| 6 `JointVerified` | Both role quorums and exact old/new configuration/commitment relation; obtain strict authority and M08 `AuthenticatedEpochApplicationEdgeV1`. |
| 7 `AnchorInstalled` | Safety/app/edge/checkpoint CAS durably agree; new epoch view-0 anchor installed, last_voted_view initialized only here. First proposal at view 1 or exact anchor-aware TC. |
| 8 `FirstNewBlockApplied` | First new ordinary block prepared/voted and later finalized under a new-set three-chain; M08 applies one application effect at C+3. Retire transition only after recovery/evidence references are retained. |

Phase 4 may require several durability attempts but never invents a receipt.
`PreHandoffCheckpointReceiptV1` explicitly does not require a joint certificate;
using existing post-certificate `ConfirmedNativePocoCheckpointV0` here would be
circular. New-only validators must synchronize and verify that receipt and old
finality independently before signing their new role. Membership overlap does
not collapse the two roles or their quorums.

Phase 7 permits ordinary new-epoch progress while phase 8 awaits finality.
That pending application transition must not prevent its child/grandchild from
being prepared and certified against their speculative authenticated parents.
The next epoch's checkpoint cannot begin until the prior edge is committed and
recovery metadata retained; phases describe a transition owner, not an extra
consensus lock invented by this document.

### Exact transition record and ancestry edge

Planned record fields, in this logical order: local schema/version; phase tag;
revision/generation; genesis/chain; old/new epoch; C; old/new validator-set and
parameter hashes; checkpoint header/commitment identities; optional exact
checkpoint prepared artifact; optional QC(C), signed seal1/QC1, signed seal2/QC2;
optional pre-handoff receipt; optional exact descriptor; old/new local role decision IDs;
optional eight-preimage joint evidence; optional authenticated edge; first-new
proposal/application completion identity. Existing canonical object bytes are
length-framed unchanged. Absent fields use explicit option tags; unknown tags
or trailing bytes reject. M03 defines the durable storage envelope and phase
presence checks; no peer decoder accepts this local record as protocol proof.

Phases require every predecessor field and forbid future completion fields:
1 needs checkpoint data; 2 additionally QC(C); 3 seal1/QC1; 4 seal2/QC2+receipt;
5 role decision slots; 6 joint evidence; 7 persisted edge/anchor completion;
8 exact first-new committed completion. Role slots may be absent until that local
role signs; a node outside a role must not create its slot. A phase tag alone
never substitutes for re-verifying its required fields.

Ordinary `edge_coordinates_match` remains unchanged. Add a distinct verified
handoff edge binding old seal2 header (old epoch/view/height) to the exact new
synthetic anchor and first-new parent relation. First-new height is C+3 and its
real parent ID is old seal2; its justify is new view-0 anchor, not a relabelled
old QC. Validate timestamp against the actual seal2 timestamp. A skipped initial
view requires a complete new-set TC selecting that exact anchor. Three-chain
finality never mixes old seals with new-set votes.

### First coherent Safety14 / Core implementation slice (planned)

This is the selected next implementation boundary, not an implemented activation
API. It must connect the existing candidate M08 checkpoint/edge producer,
Core's real Vote/Timeout path, M03 durable recovery and the M15 owner. Adding a
decoded activation token or removing an epoch-zero check alone does not satisfy
this slice. The production entry point stays closed while it is implemented.

Introduce `EpochQualifiedTipV1 { epoch, validator_set_id,
consensus_parameters_hash, height, view, block_id, timestamp_ms }` for every
true finalized and application-applied coordinate. Keep one independent
`ConsensusAncestryBaseV1` with closed variants `Finalized` and
`InstalledEpochAnchor { epoch, validator_set_id, consensus_parameters_hash,
terminal_old_header, anchor_qc, transition_binding }`. The anchor variant is
reconstructed from the exact joint evidence and durable activation completion;
it has the new epoch's logical view 0 and real terminal height C+2. It is not a
`FinalizedTip`, a certified new block, or an application head. Immediately after
installation, true finalized and application-applied remain the old checkpoint
C with their old epoch/view, while ancestry begins at the verified terminal
seal C+2. Never rewrite the old header/QC epoch or view to manufacture this base.

The first new application validation parent needs a closed
`EpochEdge { consensus_parent: terminal_old_header, application_parent:
checkpoint_header, transition_binding, checkpoint_artifact_ref }` carrier in
`PayloadValidationParentV0`. Its request digest binds both coordinates and the
exact edge. The application P/overlay names real application parent C; network
proposal parent/justify names C+2 and the new anchor. A dedicated
`DurableEpochFinalizationV1` carries both parents when C+3 later finalizes.
The ordinary parent/overlay variant still requires exact equality and height+1.
Finalization queue continuity follows application parents, whereas proposal and
timestamp checks follow consensus parents. C+4/C+5 use authenticated speculative
application parents; the pending C+3 application commit cannot fence those votes.

The concrete producer/consumer changes belong together:

| Existing file / boundary | Required implementation in this slice |
|---|---|
| `trnm-consensus-core/src/model.rs` | Add qualified tips, ancestry-base and epoch-parent variants, phase record and versioned finalization carrier. Do not overload `FinalizedTip::new` or a raw `BlockIdOverlayRefV0` with dual meanings. Keep signed objects unchanged. |
| `trnm-consensus-core/src/core.rs` | Replace `require_pre_checkpoint_height` only behind the installed phase owner; dispatch Regular/Checkpoint/Seal/EpochStart by exact `EpochGeometryV0`, frozen kind rules and phase evidence. Extend `validate_runtime`, monotonic transitions, retained-QC verification and the live SafetyRules bridge. |
| `trnm-consensus-core/src/block_tree.rs` | Add private `ConsensusValidatedSealV1` validity alongside application-valid overlay validity. Verify exact empty seal body/roots and checkpoint linkage; a seal never acquires application P/Valid authority. Three-chain construction can use valid seals as checkpoint descendants, but never queues a seal application commit. Ancestry traversal uses the qualified base. |
| `trnm-consensus-safety-rules/src/lib.rs` | Evaluate the same phase/kind/ancestry rules in the pure kernel used by real Core signing. Add an epoch context verified from complete old/new evidence, and permit only the exact installed anchor in proposals and TCs. Do not bypass the current pure-kernel comparison. |
| `trnm-consensus-core/src/safety_state_record.rs` and M03 store | Implement the separate schema14 codec and old/new context table; decode/reverify each proof with its own configuration. Add exact qualified-tip, epoch-parent, seal-validity and phase records; retain the schema13 decoder/tests as an explicit read-only import path. |
| `trnm-poco-node-host/src/handoff_runtime_v1.rs` and M15 owner | Join the existing real committed receipt/edge to the durable phase and shared signer retirement. Neither `EpochPreparationV1` nor a `WholeNodeCheckpointRefV1::EpochActive` alone can open signing. |

Planned Core entry signatures are:

```text
begin_epoch_activation_v1(&mut self, evidence: StrictSameVersionEpochActivationAuthorityV0)
    -> Result<CoreEpochActivationSessionV1, CoreError>
CoreEpochActivationSessionV1::challenge() -> &EpochActivationReadbackChallengeV1
CoreEpochActivationSessionV1::complete_exact(
    &mut self, readbacks: OwnerJoinedEpochReadbacksV1)
    -> Result<EpochActivationPersistenceV1, CoreError>
Core::acknowledge_epoch_activation_persisted_v1(
    &mut self, ack: ConfirmedEpochActivationHeadV1)
    -> Result<Vec<Effect>, CoreError>
Core::begin_epoch_activation_recovery_v1(
    contexts: RetainedEpochContextsV1, record: SafetyStateRecordV14)
    -> Result<CoreEpochActivationRecoveryV1, CoreError>
```

All named completion/session types are planned non-cloneable private-field
owners. `OwnerJoinedEpochReadbacksV1` is issued only by the M15 adapter after
fresh application/Safety/signer/external-checkpoint readbacks; inert decoded
fields or a generic boolean callback cannot construct it. Resolve this bridge
through the existing Core-issued challenge/native-owner adapter pattern; do not
add a Core dependency on native execution. The ordinary generic `recover`
continues rejecting transition records. A new-only validator uses the dedicated
checkpoint/edge recovery path without inventing a local old-role signature;
an old-only validator retires rather than constructing an invalid new CoreConfig.

All view/QC comparisons must first match epoch and set. In particular, retained
old finality proofs and new observed QCs must not be called conflicting merely
because their numeric views match. Ordering active votes/locks uses only the
active epoch. Reset `current_view` to 1 and last Vote/Timeout watermarks to None
only in the exact durable phase6->7 transition; Safety revision and owner
generation never reset. Preserve old watermarks and decision IDs in the retired
epoch cut. Do not weaken ordinary same-epoch monotonic comparisons or allow a
same-block old ordinary QC to become a new synthetic anchor by relabeling.

The first acceptance scenario must run checkpoint C, two seals, committed C
readback, both handoff roles, joint verification, anchor installation, and
real Core preparation/voting of C+3/C+4/C+5 followed by exactly one C+3 commit.
Add a TC-before-first-proposal scenario, changed/new/removed local membership,
same numeric views across epochs, restart at every durable boundary and exact
replay. Rejected/missing readbacks must emit no custody request, timer or network
effect. Physical application rows at C+1/C+2 must remain absent. A later batch
can extend the matrix to the next epoch; it may not advertise full activation
on the strength of an inert record round trip.

## Persistence and recovery

M03 persists schema-14 epoch-qualified Safety plus the exact phase record as one
local authority transaction; M08 coordinates independent application/checkpoint
stores by intent/readback/CAS, not assumed cross-database atomicity.
An acknowledgment advances a phase only if it binds predecessor revision,
operation ID, complete successor and the current owner generation.

Recovery disables signatures and timers, reloads strict configuration/evidence,
reconciles M03 decisions and M08 app/checkpoint/edge state, then resumes the exact
pending phase. Replaying a completion returns its prior outcome without a second
signature/application effect. Conflicting roots/descriptors halt. Schema 13 may
be imported only from a validated single-epoch pre-checkpoint state with no
outstanding uncertain operations; unsupported records remain fenced, never
silently assigned an epoch. Keep immutable migration provenance and old evidence.

## Resource bounds

Existing CoreConfig and `CORE_MAX_*` constants bound blocks, observations,
validation bytes, pending sync/QC/finality queues; M00 bounds each proof.
The epoch owner retains one active transition, plus evidence required by the
configured accountability/weak-subjectivity/recovery horizons.

Planned profile fields: maximum retained transition bytes, cumulative signature
work, pending role signatures, recovery scan bytes and CPU budget. Validate
checked aggregate sizes against all enabled old/new maximum objects and M03
storage capacity before starting a transition. If capacity is insufficient,
return local unavailable before signing; never discard an unacknowledged old
checkpoint or reinterpret a valid next set to fit a smaller local budget.

### Explicit bounded development profile (planned)

The opt-in local test profile `epoch-runtime-dev-v1` uses unsigned checked u64
for every bound (schema u16=1), not production defaults:
`max_active_transitions=1`, `max_retained_transitions=32`,
`max_transition_record_bytes=134217728`, `max_role_shares=200`,
`max_signature_work_per_transition=1000000`,
`recovery_batch_bytes=536870912`, `recovery_batch_operations=4096`.
It does not modify the authenticated consensus parameters; a test chooses those
preimages separately and records their hashes.

Validate `role_shares >= old_validator_count+new_validator_count`,
`retained_transitions >= 1+max(evidence_window,unbonding_delay,trusting_period)`,
and record bytes at least the checked sum of every required local field, receipt,
edge and eight evidence maxima. Prepared artifacts are immutable digest/sequence
references, not unbounded inline snapshots. Required signature work is computed
from both sets and all enabled nested QC/TC/role/first-proposal verifications;
validate against that cost before the transition, charge failed attempts, and
use a separate finite per-peer ingress budget. Recovery is resumable across
bounded batches while live effects remain fenced. An insufficient example
profile rejects; it cannot authorize dropping old evidence or accepting a
partially verified transition. Production values require signed profile selection.

## Security

Existing `CoreError` variants distinguish wrong epoch/view/leader, unsafe proposal,
missing block, unsupported boundary, conflicting certificate and unexpected
acknowledgment. Planned local epoch failures are `EpochPhaseMismatch`,
`EpochBindingMismatch`, `UnsupportedSafetySchema`, `RoleAuthorityMissing`,
`EpochResourceUnavailable`, `EpochCommitUncertain` and `EpochSafetyConflict`.
The first four reject without effects; unavailable retries the same operation;
uncertain fences effects pending readback; a safety conflict durably halts.
No new peer error number or slashing offense follows from these local outcomes.

A copied application root, valid PoP, single QC, preparation row or complete
post-certificate proof alone cannot authorize every phase. Old/new sets each
require the Byzantine-weight bound. If either quorum is unavailable, stop safely;
there is no unilateral emergency set replacement or rollback to a previous epoch.

## Observability and SLO

Separate proposal validation, QC acquisition, three-chain finality, durable apply
and handoff latency. Report phase/revision, pending age, retry/fenced counts,
quorum participation and signature-work budget. Do not label a certificate count
as successful application TPS. Test idle/low-load progress as well as saturation;
SLOs are qualified by the signed deployment profile, not this document's examples.

## Verification and evidence

Existing inputs include QC/TC, anchor/finality, checkpoint-two-seal and joint
handoff vectors, Core simulator scenarios and `epoch_activation_recovery` tests.
`two_plus_two_partition_cannot_finalize_and_heal_restores_progress` is a useful
existing kernel case; it is not multi-host or multi-epoch acceptance.

Required cases: `M02-QUORUM` weighted threshold-1/exact/overflow/duplicates;
`M02-THREECHAIN` oldest-only and exact QC-digest subsets; `M02-TC` missing data,
subsumed reference and skipped views; `M02-LIVE` idle, low load, partition/heal;
`M02-EPOCH` old-only/new-only/dual roles, every phase cut, role/signature replay,
wrong old/new configuration, old-view/new-view comparison and two consecutive
transitions; `M02-EDGE` wrong terminal seal, anchor, timestamp, height or parent.

Acceptance must drive actual Core/Safety/signer/native producers and consumers,
including M07's sparse-label edge and M08 recovery, not assign phase tags in a
fixture. Freeze exact local-record bytes and rejection vectors when implementing
the schema. An independent model checks safety under message reorder/crashes;
independent operators validate post-GST progress under the qualified workload.

## Activation boundary

Keep `EpochBoundaryUnsupported` and existing production gates until the complete
planned path is implemented and accepted. Enabling schema 14 requires the same
release to support M03 role custody, M07 carried-root reads, M08 phase recovery
and M13 authenticated installation. Same-version v0 transition is the target;
unknown protocol upgrades and incomplete codecs remain disabled.
