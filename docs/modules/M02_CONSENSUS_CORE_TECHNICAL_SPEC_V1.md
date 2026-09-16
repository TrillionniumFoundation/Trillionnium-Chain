# M02 Order / Consensus Kernel technical specification v1

Status: **frozen ordinary v0 rules plus a concrete planned epoch integration;
current Core remains pre-checkpoint; no activation or implementation claim**.
Primary module: M02. Producers/consumers: M00/M01/M03/M04/M06/M07/M08/M13/M15.

## Authority

Specifications `poco-bft-v0/01` through `07` define the protocol. This document
selects a local implementation architecture; it does not alter v0 signing
bytes, quorum, three-chain finality, seal semantics or epoch geometry.
`trnm-consensus-core/src/{model,core,block_tree,safety_state_record,error}.rs`
are current implementation references. `epoch_preparation.rs` currently has
only `EvidenceVerified`. `Core::require_pre_checkpoint_height` refuses checkpoint
and later heights, and ordinary admission refuses non-Regular blocks.

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
