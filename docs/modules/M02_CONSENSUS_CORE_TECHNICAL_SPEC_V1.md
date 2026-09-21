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

### Retained activation preparation prefix (M02-EPOCH-PROVENANCE-V2)

This primary-M02 contract precedes its implementation. M01 produces strict
activation verification; a future explicitly versioned M03 preparation journal
and Core/Safety record consume the entire retained prefix. This first slice is
I/O-free, with no step, timer, signer, storage acknowledgement or live Core API.
It must not serialize a contextual terminal authority into the old one-entry
TRNMEP01 format and claim that the old decoder can recover it.

`EpochPreparationEntryV2` borrows an expected activation binding, the original
eight CEV0 roots and a canonical predecessor-header interval. Preparation takes
1–32 ordered entries and independently supplied root validator set/parameters,
root binding and terminal binding. The first interval is empty and M01's strict
v0 recovery authenticates the first entry. Each later interval includes both the
previous terminal seal and this entry's checkpoint parent; M01's strict
successor recovery verifies its full geometry, context, signatures and binding.
Only the preceding strict authority is retained while walking. Bindings are
nonzero and unique. No missing history is synthesized from configuration equality.

The local record is `TRNMEP02`, big-endian u16 version 2, u8 phase 0
(EvidenceVerified), root binding[32], terminal binding[32], and u32 entry count.
Each entry is binding[32], u32 header count, each header as u32 byte length plus
canonical CEV0 bytes, then the eight original roots in the unchanged v1 order,
each as u32 byte length plus bytes. There is no recursive nested preparation or
Safety record. Unknown versions/phases, truncation and trailing bytes reject.
Record identity is SHA-256 of the ASCII domain
`trnm.consensus-core.epoch-preparation-provenance.v2`, a zero separator, u64
big-endian record length, then the complete canonical record bytes. The roots
already retain the exact independently verified root set/parameters. This digest
is a local comparison pin, never signature, finality or activation authority.

Complete framing is checked before copying roots or doing signature work. The
whole record, including every prefix and length, is at most 64 MiB. Each entry's
eight roots together are nonempty and at most the existing 8 MiB hard limit;
M02 separately screens the aggregate against authenticated outgoing parameters
(root trust for the first entry, verified predecessor for each successor) and
the caller's smaller admission limit without replacing its work meter. Each successor interval has 2–256 headers, each at most
4096 bytes and together at most 1 MiB. The first interval has exactly zero
headers. Count/length arithmetic is checked before allocation. Full raw roots
are copied only after all entries pass strict verification.

Every entry uses the same mutable caller CEV0 work meter. Pre-existing work and
charges before a later failure are retained. The 64 MiB record cap is separate
from the 8 MiB CEV0 root cap; it must not enlarge or reset a root/work budget.
The returned non-Clone `EpochPreparationV2` privately owns the terminal strict
authority, complete original record and the independently supplied root set/parameters
retained only after the complete strict fold succeeds. Its cloneable record and digest are
inert. Recovery also requires the independently expected record digest, root
and terminal bindings; it rechecks framing and every entry, rather than trusting
serialized verification status. Pin mismatches issue no preparation owner.

TRNMEP01 and its decoder remain byte-exact. Its producer must reject a strict
authority whose checkpoint proof requires a prior synthetic-anchor context,
before emitting a record. The v2 result cannot be implicitly converted into
`EpochCoreStateV1` or codec1: those retain only terminal roots. A later explicit
Core/Safety codec2 must consume complete preparation provenance, and a later
journal version must bind a real settled source and durability before any ACK.
These consumers are separate required work, not acceptance supplied by v2.

Required local evidence uses the existing genuine C28/S30 → C38/S40 fixture,
whose second checkpoint has signed mixed ordinary/S30-anchor timeout references.
Test exact preparation/recovery, canonical record framing/digest, wrong independent
root/terminal/digest pins, reordered/truncated prefixes, missing or substituted
ancestry, canonical bad signatures in the second activation, all framing limits,
and exact/insufficient/precharged shared budgets. Preserve the original v1 and
M01 vectors and reject v1 downgrade of contextual-only evidence. This does not
establish native candidate selection, live repeated handoff or crash durability.

### Contextual full-epoch persistence (M02-EPOCH-SAFETY-PROVENANCE-V2)

The explicit Core persistence slice consumes a strictly recovered preparation V2;
it must retain that exact complete provenance in the epoch state. A terminal
runtime context by itself is insufficient to construct this state. The private
epoch-state representation distinguishes the existing eight-root V1 profile
from a V2 profile holding the complete bounded record, its independently checked
root trust context and its root/terminal/digest bindings. Cloning inert
SafetyState may share immutable provenance bytes; it must not duplicate a live
owner or replace strict recovery with cached scalar assertions.

`TRNMS14E` codec 2 retains SafetyState schema14 and phase7 but uses distinct
`trnm.consensus-core.epoch-safety-context.v2` and
`trnm.consensus-core.epoch-safety-record.v2` local hash domains. The context
reference commits the complete existing Core configuration, owner generation,
checkpoint artifact, independent root binding, terminal binding, preparation
record digest and a codec2 layout discriminator. After the common
magic/codec/schema/context/phase/revision/generation/binding/artifact fields,
codec2 carries one length-delimited complete TRNMEP02 record in place of the
codec1 eight-root list, followed by the existing qualified tips, state payload,
outgoing boundary candidates/seals and domain-separated checksum. The embedded
record must equal the strictly recovered context bytes, not merely its digest.
Codec1 exact decoding and bytes remain unchanged; neither decoder guesses the
other codec or falls back after failure.

The explicit V2 context constructor consumes the non-cloneable preparation,
checks the next Core configuration, actual checkpoint artifact and nonzero
owner generation, and retains the strict terminal runtime. Minimum record
limits account for the actual complete preparation frame, all existing bounded
state slots and arithmetic overhead before opening any persistence owner.
The 64 MiB provenance framing limit is never passed as an eight-root admission
limit. Cold reconstruction rechecks the entire prefix with its retained
independent root context and one bounded verification meter before comparing
all derived checkpoint, terminal, anchor and configuration fields.
`EpochCoreStateV1::recover_preparation_v2` exposes that strict reconstruction to
a future persistence consumer with a caller-owned meter; prior charges and
narrower limits remain effective. It does not infer root trust from raw input.
No unverified decoder result is a live Core.

An outgoing epoch0 terminal owner may prepare the first one-entry V2 state.
A codec1 active source may extend only a V2 prefix whose first entry exactly
matches its retained original activation roots and binding. A codec2 active
source must preserve every entry and ancestry byte in its prior prefix and
append exactly one strict successor entry; its root binding stays fixed.
Source and target configurations must describe consecutive epochs. A V2 source
cannot produce a codec1 successor, even if its newest proof happens to be
context-free. Prefix replacement, truncation, extra transitions and a different
validly signed history are rejected before producing a persistence request.
Extension compares the exact prior entry frames, including every ancestry and
root byte; the outer record count and terminal binding necessarily change.

Both activation and cold recovery remain inert until the exact existing owner
barriers are reconciled. Preparation consumes the prior live Core, or uses a
strictly recovered inert source; requires no pending sign, finalization,
validation, synchronization or halt; requires applied equals finalized at the
exact target checkpoint; and matches the original finality proof and native
artifact. Revision is continuous and generation increases by exactly one.
`PreparedEpochCoreActivationV2` and `StrictEpochCoreRecoveryV2` are distinct
inert owners with no existing candidate-host conversion. They cannot inherit
the journal9 trusted ACK API through a public V1 wrapper. The resulting owner
exposes only its pending initial persistence request;
the durable acknowledgement still gates the view1 timer. M03 must separately
version its journal/source-owner transition and perform fresh source,
native-application and custody joins before any callback or signature. The
existing journal9 epoch0 initializer cannot stand in for this transition.

Acceptance uses the genuine contextual two-activation fixture: encode/reopen
codec2 with original predecessor-anchor TCs, then reject a valid but different
prefix, changed root or record digest, codec confusion, stale generation,
foreign checkpoint artifact, unresolved source cuts and every truncation.
Assert exact round-trip bytes, unchanged codec1 vectors, bounded allocation,
retained work charges, no timer/signature before the matching durable barrier,
and default-stack recovery. Process-crash, real journal transition and resumed
live-owner evidence are additional M03/M15 obligations; this design does not
claim those implementations or promote production activation.

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
revision+1, and returns `PreparedEpochCoreActivationV1` with its exact opaque
initial persistence request and owner-affine binding, but no step, persistence
ACK or signer API. `StrictOldEpochTerminalRecoveryV1` can prepare the same
deterministic record after a crash; this remains inert until the actual source
journal and native/custody owners are joined. The pure SafetyRules consumer keeps its true old finalized
reference while using a separate graph coordinate, and its state digest binds
the full activation. Frozen epoch-zero behavior and schema13 tests remain.
The Core regression uses real frozen Ed25519 evidence but inert P identifiers;
it is not evidence of an actual native/journal/custody activation join.

The implemented pure consumer uses the same complete context in BlockTree
three-chain reconstruction and durable payload obligations. For the first new
block, consensus height/parent/timestamp checks use terminal C+2, while the
application obligation and finalization queue retain committed checkpoint C.
Only the exact edge carrier may bridge this gap; an ordinary single-parent
record cannot be reinterpreted. Later new-epoch blocks use the ordinary direct
parent rule. A withheld or missing intermediate application result withholds
the complete finalization suffix. Its regression uses real Ed25519 proposals
and QCs, verifies a two-block finalization suffix and 14E round trip, and rejects
a single-parent terminal-seal substitution and a first-block overlay lacking
the exact edge. Application result identifiers in this pure-engine fixture
remain synthetic. Persisted-successor validation compares views only within an
identical epoch/set/parameters scope. A scope change requires the exact retained
old checkpoint and first-new dual-parent queue carrier; lower new-epoch views
are not compared numerically with the old checkpoint view. Tests cover first
view1, a TC before first view3, strict successor validation, and rejection after
removing the authenticated edge. This consumer change issues no live owner,
signer lease, or persistence acknowledgement.

A separate default-off SafetyStore `test-fixtures` producer now drives the real
old Core through H1..C8 and seals9/10 using strict Ed25519 proposals/QCs, actual
native speculative P/readbacks and journal8. Each of ten vote callbacks follows
exact Safety persistence; native commits occur only after the Core finalization
queue, and seals have no application P. Its journal7 migration source is actual
unvoted genesis. The caller supplies a durable signer callback for whole-node
custody tests; the fixture's callback comparison hashes are fixture-adapter
facts, not a claim to the legacy application-job/outbox tables. This establishes
the real old-epoch join. Live new-epoch Core release remains a separate boundary.

Pure Core preparation remains inert until concrete candidate composition joins
fresh journal/external cut, `ConfirmedEpochApplicationEdgeV1` from the live native
owner, and actual retired/new custody owners. M15 I/O integration stays under
`epoch-runtime-candidate`; Core's `candidate-epoch-host-v1` remains no_std and
default-off, and production closure excludes both candidate features.
Continuing membership consumes the old live Core;
new-only commissioning uses independently trusted old checkpoint state and a
virgin new-role custody namespace; removed validators retire without a new Core.
Retirement precedes old handoff signing and binds the pre-certificate context.
The new ordinary lease follows complete joint verification and binds the exact
phase7 persisted Safety cut; these are distinct, non-circular receipts.

### Candidate pending driver and concrete initial activation composition

The default-off `candidate-epoch-host-v1` Core seam below is implemented.
M15 supplies the concrete continuing-author initial activation consumer under
`epoch-runtime-candidate`; full ordinary event driving and all-role recovery
remain subsequent work.
Keep the single existing Core state machine and dependency direction
`SafetyStore -> Core`. M15 owns the concrete native, journal9, custody and
independent node-checkpoint stores. No generic registrar, caller-chosen
verification trait, scalar activation constructor, or new capability-only crate
is introduced to work around that direction.

`PreparedEpochCoreActivationV1::into_candidate_host_pending_v1(self)
-> PendingEpochHostDriverV1` is explicitly a trusted-host API, retaining no_std.
The returned driver keeps Core private, retains its exact pending initial request
and affinity, and initially accepts only that request's existing `StorageAck`
transition. All other inputs return `EpochActivationPersistencePending`; no timer,
proposal, vote, callback permit or mutable Core escapes before the ACK. After
ACK the same private driver runs ordinary strict Core inputs. It exposes no raw
SafetyState/configuration constructor and never accepts an epoch number or
checksum as activation proof. This seam has the existing ordinary Core
`StorageAck` trust model: a caller which bypasses the concrete host can lie
about persistence. It must not be described as an intrinsically verified durable
receipt or an independently safe activation entry point.

The exact initial ACK emits one `ArmViewTimer` for new epoch/view1, without a
new Safety revision. Preparation retains this deferred effect behind the same
persistence barrier; an incorrect or repeated ACK cannot arm it. Strict
`step_v1` forwards to the existing transactional Core; application seal/apply
authorities, finalization permits, sealed Valid delivery, finalization receipts
and signature-release persistence all remain gated until that first ACK.
The driver has immutable state/config/request/binding accessors, no Clone,
mutable-Core accessor, selectable verifier, unchecked state constructor or key.

`StrictEpochCoreRecoveryV1::into_candidate_host_initial_pending_v1` is available
under that same explicit trusted-host feature only. It reconstructs exactly the
canonical initial14E state, preserves its revision and remints a fresh process
affinity with the initial timer still deferred. Any progressed obligation,
signing/finalization outbox, changed view or other noninitial field rejects.
M03's actual journal9 recovery helper additionally checks the immutable source
migration's initial revision, fresh exact state/transition and single binding;
decoded state alone is not its physical persistence authority. Recovery of
progressed new-epoch cuts remains fenced pending dedicated cross-store joins.

Regression tests use real strict Ed25519 proposals and public driver inputs:
the first Handoff creates and persists the C/C+2 obligation before issuing its
linear validation permit; a single-parent result rejects; the sealed Valid
result creates a second persistence barrier before the vote signature request.
No private BlockTree insertion substitutes for that path. The pure Core test's
application artifact IDs are synthetic. The store integration uses the actual
native/Core old-epoch fixture and real journal9 reopen, then verifies a real
new-epoch timeout append; its test-only trusted ACK does not claim a complete
M15 checkpoint/custody activation join.

The concrete public initial activation constructor is
`CandidateEpochRuntimeV1::activate_continuing_v1(prepared, journal9, pin, application,
authenticated_edge, retired_original, retired_node_checkpoint, new_ordinary)`.
Each argument is an actual non-Clone owner/capability, not a decoded record.
The method freshly checks journal9's initial state/request/owner binding against
`prepared`, asks the live application to confirm the owned edge at actual C,
checks complete old/new configurations and local key membership, verifies the
original retirement/checkpoint, and confirms the new ordinary journal has the
exact intended new set/author/profile and virgin external watermark. Old/new
ordinary scopes and journal identities must differ. It persists the M15 V1
lineage checkpoint containing all cuts, syncs and rechecks every owner, then
ACKs the still-private driver and installs the new ordinary lease in the same
returned runtime. The runtime keeps all owners. Initial activation returns only a private runtime;
`take_initial_timer_effects_v1` freshly joins all owners before releasing the
one initial `ArmViewTimer`. `confirm_initial_activation_v1` returns comparison
bytes only and permanently fences changed owners. It never returns an activated bare Core or signer.

Failure before/during the V1 CAS consumes the moved owners and returns typed
recovery disposition, never a partially usable runtime. Explicit recovery
reopens all physical owners, checks independently expected V1 lineage/generation,
strictly reconstructs the exact 14E record and native edge/P ancestry, reconciles
the virgin signer cut, then remints private runtime state. Initial-only recovery
rejects progressed Safety/signature cuts; pending-decision reconciliation is
not yet exposed by this consumer. The inert recovery
record never by itself proves that join; using its candidate pending-driver
conversion carries the explicit trusted-host obligation above. Continuing,
new-only and removed roles are separate constructors: the first slice accepts
continuing membership only; new-only requires explicit trusted commissioning
without fabricating an old local Safety owner, and removed nodes get no new
ordinary driver. All three policies must be tested before claiming multi-role
activation complete.

The bounded first-timeout consumer `sign_initial_timeout_v1(self, producer)`
consumes the runtime on failure. It must persist the real `LocalTimeout` request
in journal9, join the still-virgin signer and native C, advance and sync V1, and
only then ACK the signing request. A fresh composite read precedes key access.
The signed journal's exact two-event successor is independently checkpointed
before Core receives `SignatureReady`. Its broadcast stays private until the
cleared pending-sign state crosses its own journal9/V1 persistence and ACK.
Only the verified TimeoutVote may leave. This first timeout does not implement
progressed-cut recovery, generic proposal processing, or another epoch transition.

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
