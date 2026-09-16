# M08 Finality / Node Commit / Recovery technical specification v1

Status: **existing candidate contract plus planned multi-epoch commit design; semantic acceptance and production activation not granted**

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

### Planned pre-certificate receipt

M02/M03 need a native checkpoint receipt **before** either handoff role signs.
The existing `PreparedNativePocoCheckpointV0` is not a committed receipt;
`ConfirmedNativePocoCheckpointV0` already requires the joint certificate and
cannot authorize constructing that certificate. Add a separate local capability:

```text
confirm_pre_handoff_checkpoint(
  expected: CheckpointCommitExpectation,
  strict_old_checkpoint_finality: StrictFinalityProofV0,
  committed: FreshNativeCheckpointReadback,
  cutoff: AuthenticatedFinalizedCutoff,
  next_commitment: RecomputedNextEpochCommitment
) -> Result<PreHandoffCheckpointReceiptV1, FinalityRecoveryFailure>
```

All names except the existing strict proof type are planned APIs. Construction
is private to the commissioned native/application owner; caller-provided JSON,
roots, receipt bytes or proof-status booleans cannot construct the capability.
The call rechecks the actual COMMITTED row, exact checkpoint prepared execution,
canonical body/roots, complete old-set checkpoint→seal1→seal2 proof, finalized
cutoff projection and freshly recomputed next commitment. No joint certificate
is an input. New-only validators reconstruct their own authenticated application
state/readback before obtaining their local capability.

Planned persisted receipt layout, in exact local order:

| Field | Encoding / invariant |
|---|---|
| magic, schema | ASCII `TRNMCHK1`, u16-be 1; local format only. |
| operation_id, namespace_id | Two Hash32; exact commissioned owner and immutable intent identity. |
| genesis_hash, chain_id | Hash32 and CEV0 ConsensusString; independently trusted. |
| old_epoch, checkpoint_height | Two u64-be; checkpoint C derived from old parameters. |
| checkpoint_block_id, prepared_artifact_digest | Two Hash32; exact existing durable P artifact and header. |
| application_version, commit_sequence | Two u64-be; version=C; sequence is durable local apply ordinal. |
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

### Planned post-certificate application edge

```text
confirm_epoch_application_edge(
  checkpoint: PreHandoffCheckpointReceiptV1,
  joint: StrictSameVersionEpochActivationAuthorityV0,
  expected_first_height: Height,
  checkpoint_cas: ConfirmedNodeCheckpoint
) -> Result<AuthenticatedEpochApplicationEdgeV1, FinalityRecoveryFailure>
```

The private edge fields are: complete pre-certificate receipt; old/new epochs;
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
Append SHA-256 of preceding bytes. The retained eight canonical evidence
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
and commit_sequence+1. Children may be prepared under normal speculative-parent
rules while that commit waits. No mixed-old/new three-chain is accepted.

Normal apply expects application height+1. The sole planned epoch-edge apply
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

Freeze byte-exact planned receipt/edge/local-intent vectors with positive and
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
