# M03 Safety / Signer / Checkpoint technical specification v1

Status: **implementation design with existing v0 interfaces and planned epoch
custody extensions; no device qualification or production promotion**.
Primary module: M03. Producers: M02/M08/M15. Consumers: M02/M04/M08/M13.

## Authority

Frozen v0 specifications 02/03/04 govern persist-before-sign and role preimages.
SafetyRules decides whether signing is safe; a signer journal enforces exact
persistent decisions but does not reconstruct proposal ancestry by itself.
`trnm-consensus-safety-rules`, `trnm-consensus-safety-store`,
`trnm-consensus-signer-journal`, external watermark/checkpoint contracts and
remote-signer protocol/service/adapters remain separate owned components.

Current ordinary signing uses `CanonicalSignIntentV0` and `sign_exact_v0`.
Current handoff code exposes `StrictOldSetHandoffAdmissionV1` and
`sign_old_set_handoff_exact_v1`; its profile rejects a new-set-only author.
The target adds independently authorized new-role custody and M02's durable
phase record. It does not bypass those current restrictions with an old-role token.

## Interfaces

### Owned signer, fencing and persistence adapters

All package paths below are under `trillionnium/crates/`. This inventory is a
contract split, not an assertion that the adapters form an activated runtime.
M01 owns the remote protocol bytes. M03 owns the following local producers and
their composition with Safety. Existing local codec constants remain the
source for record/frame ceilings; the signed M03 profile may tighten them.

| Package and source API | Actual state / invariant to preserve | Failure disposition and required acceptance |
| --- | --- | --- |
| `trnm-consensus-unix-remote-signer`: `UnixRemoteSignerProducer::{new,preflight,sign_intent_exact}`, optional `UnixRemoteProposalSignerProducer` | Bounded Unix `SignatureProducerV0`; checks configured endpoint/bindings and strict response signature. Proposal client is a separate compile-time purpose capability. It owns no Core/Safety authorization, key custody or production activation. | `UnixRemoteSignerError` separates invalid configuration/protocol, unavailable transport and invalid response; a response lost after signing requires journal reconciliation, not a fresh intent. Test non-socket/replaced or unsafe endpoint, overlong frame, wrong profile/nonce/root and invalid signature; proposal bytes must not enter ordinary signing. |
| `trnm-consensus-unix-fleet-signer`: `FleetRootRequestV1`, `DurableFleetRootSignerAuthorityV1::sign_fleet_root_v1`, `UnixFleetRootAuthorityServerV1` | Exact `(purpose, origin, validator_set_id, signing_root, nonce)` request; closed purposes Ready/Start/Relay/Restart/RestartCut/RestartPark/Evidence are distinct replay domains. Durable authority logs admitted requests; client framing alone is not nonce freshness. This fleet authority is not validator safe-vote authority. | Reject invalid purpose/zero identity or digest, nonce/request substitution and corrupt durable log. Retain `FleetRootAuthorityErrorV1` versus transport errors. Test exact replay, conflicting same nonce, every purpose separation and restart before/after durable result; never accept a fleet signature as a consensus vote. |
| `trnm-consensus-external-watermark`: `ExternalWatermarkAuthority::{open_semantic,compare_and_advance_semantic}`, `UnixWatermarkClient`, `ReplayBindingStoreV1` | Independently owned append-only hash chains; immutable semantic scope/journal/capability and lifecycle mode. `SignerJournalPair` requires prepared/signed pairs; `PerReservation` is a separately commissioned namespace. Replay binding retains exact request-to-signature bytes. No private keys or Safety decisions are owned here. | `ExternalWatermarkAuthorityError`/`ReplayBindingErrorV1`: compare conflict rejects stale work; unavailable/ambiguous writes require exact readback; invalid chain or endpoint identity fences the namespace. Test capability challenge, wrong lifecycle, stale CAS, partial/truncated log, replacement and lost response. Source caps include 512-byte authority frames and 64 MiB authority log. Whole-host rollback still requires independent retained authority outside that failure domain. |
| `trnm-consensus-external-node-checkpoint`: `ExternalNodeCheckpointAuthorityV0::{load_checked,compare_and_advance_checked}`, `UnixExternalNodeCheckpointStoreV0` | Separate daemon implements exact whole-node checkpoint load/CAS; client never opens its journal. Endpoint identity and hash-linked predecessor remain bound. The public v0 checkpoint record is not the data-only v1 record below. | `ExternalNodeCheckpointAuthorityErrorV0::{CompareFailed,Unavailable,InvalidLog,Protocol,Io}` map to the existing closed store error contract. Bound frames at source 4,096 bytes. Test stale predecessor, exact retry after response loss, directory/log/lock replacement, partial record and rollback. An adapter success cannot skip owner readbacks. |
| `trnm-consensus-remote-signer-service`: `RemoteSignerService::{open,open_with_external_timeout_authority,process_request,process_request_with_external_authority_v1,process_proposal_request}` | Development Ed25519 key owner with SQLite watermark schema 2, closed `PurposePolicyV1`, explicit bounded external timeout authority path. It lacks full Core/Safety admission, HSM/KMS and production process-generation reconciliation. `both()` means vote plus timeout, excluding proposal. | Preserve `ServiceRejectCodeV1` and `ExternalAuthorityErrorV1`; purpose/claim mismatch rejects before key use, reservation uncertainty requires external readback. Planned production composition must consume this document's durable Safety authorization before custody. Test purpose matrix, monotonic view/revision, duplicate exact response, generation/lease substitution and external outage; a service-only test never proves safe-vote correctness. |
| `trnm-whole-node-checkpoint-types`: `WholeNodeCheckpointV1`, `WholeNodeCheckpointRefV1`, exact decoders, `validate_successor_of` | Inert canonical cumulative cuts for chain, process fences, role bindings, Core/Safety, application validation/application, remote Safety and signer. Builders `commissioned`, `app_validated_successor`, `safety_prepared_successor`, `signature_committed_successor` validate data lineage only. Neither a phase tag nor checksum supplies CAS or an epoch signing-cycle bridge. | `WholeNodeCheckpointTypeErrorV1`/`WholeNodeCheckpointErrorV1` reject malformed IDs, overflow and inconsistent successors. Decode within `MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1`; verify exact reference codec separately. Test reordered/omitted cuts, changed scope/generation, wrong predecessor and maximum generation. M15 must join each claimed cut to live owners before using it. |
| `trnm-durable-file-adapters-v0`: `FileAuthorityCoordinatorV0`, `CandidateAuthorityJournalV0`, `AtomicSnapshotFileTargetV0`; feature-gated candidate transaction/peer journals | Exclusive file locks, fixed 289-byte authority records, hash-linked exact replay, immutable snapshot generations and 120-byte current pointer CAS. M15 consumes authority journal, M13 the non-destructive snapshot target, M05 the transaction journal, M04 the peer replay adapter. Feature enablement grants no production authority. | `DurableFileErrorV0::{Poisoned,RecoveryRequired,CurrentRootCasMismatch,CorruptAuthorityJournal,SequenceOverflow}` requires fenced recovery or exact CAS reconciliation; never reset an uncertain namespace. Test lock contention, partial append, substituted chunk, orphan generation, pointer replacement and commit-directory-sync ambiguity. Process-kill tests do not establish physical power-loss durability. |

The three primary engines named in Authority retain distinct responsibilities:
`trnm-consensus-safety-rules` decides safe authorization,
`trnm-consensus-safety-store` commits and reopens its exact state, and
`trnm-consensus-signer-journal` durably binds the authorized intent to the
external watermark and exact returned signature. Adapter failures must preserve
the persist-before-custody and persist-before-publication sequence below.

### Ordinary signing request

M02 supplies the complete canonical sign intent, not just a digest. It binds
chain/protocol/epoch/set, author, first-authorizing Safety revision, exact
Vote/Timeout preimage, recomputed signing root and intent fingerprint.
M03 also binds signer profile, namespace identity, external watermark scope,
owner generation and expected predecessor. The custody key must resolve to the
exact active validator key for that role; callers cannot select a different key.

Existing `SqliteSignerJournalV0::sign_exact_v0` performs the journal boundary.
`SignatureProducerV0` supplies the selected signature; producer success is not
proof that Safety has authorized another intent. `ExternalMonotonicWatermarkV0`
provides load and compare-and-advance semantics; a same-directory file is a lab
implementation, not an independently administered rollback anchor.

### Planned role-specific handoff request

```text
sign_handoff_exact_v2(
  admission: OldRoleAdmissionV2 | NewRoleAdmissionV2,
  checkpoint: PreHandoffCheckpointReceiptV1,
  intent: CanonicalHandoffSignIntentV1,
  expected: JournalPredecessor,
  owner: CurrentSignerGeneration
) -> Result<RecordedHandoffSignatureV2, HandoffSigningFailure>
```

These v2 names are planned local interfaces; the existing canonical handoff
preimage/role codec remains unchanged. Verify exact type names against M00's
source at implementation; no new peer handoff tag is introduced.
The admission binds both exact sets/parameters, author and role, descriptor,
strict checkpoint/two-seal finality, authenticated checkpoint-parent/cutoff,
and the pre-certificate native receipt defined by M08.

Old role verifies membership under the old set; new role verifies membership
under the new set and independent old-chain trust. A dual member obtains two
admissions and two decisions. The journal uniqueness key is
`(genesis, chain, old_epoch, new_epoch, author, role)`; every retry must name the
same canonical descriptor/preimage. Distinct roles cannot overwrite each other.

`PreHandoffCheckpointReceiptV1` precedes the joint certificate. Existing
post-certificate confirmation or `EvidenceVerified` cannot authorize producing
that same certificate. A new-only signer fetches/replays checkpoint state and
strictly verifies the old finality/context before admitting its role.

### Checkpoint and publication

Whole-node checkpoint CAS binds expected generation/checksum and the complete
successor: Safety revision/digest, signer journal head/watermark, application
head/commit sequence, M08 pending operation and epoch-edge identity.
The checkpoint describes durable authorities; it does not manufacture them.
M04 publishes only bytes from a `RecordedSignature` for the exact request.
A publication acknowledgment may clear an outbox item, not change the decision.

## State machine

Ordinary and role-specific journals use the same durability discipline:

```text
Admitted -> SafetyDurable -> IntentDurable -> ExternalDecisionConfirmed
         -> SignatureDurable -> Publishable -> PublicationAcknowledged
```

SafetyDurable and IntentDurable may be one database transaction when owned by
one store; independent stores require a recoverable intent and authoritative
readback. A local phase label is never a substitute for the missing write.

1. Lock the descriptor-bound private namespace; revalidate owner generation,
   file/sidecar identity, schema and exact profile before each authoritative call.
2. Recompute intent bytes/root/fingerprint and check the author/role/key binding.
   Reject conflicting decisions, non-idempotent vote views at/below watermark,
   stale role descriptor or mismatched first-authorizing Safety revision.
3. Persist the complete Safety transition and intent with the selected FULL
   durability boundary, including necessary directory/metadata synchronization.
4. Compare-and-advance the independently administered decision anchor using the
   exact predecessor/target. Uncertain response leaves the owner fenced.
5. Invoke custody for the exact recorded request; verify returned signature
   locally against the expected key/root. A signature over other bytes rejects.
6. Persist signature and exact result, then fresh-read and verify before return.
   Only after the whole-node checkpoint barrier may the required Core callback
   release the corresponding outbound effect.
7. An exact retry returns the same logical recorded decision; once signature is
   stored it need not call custody again. A changed digest is never a retry.

Vote and Timeout for the same view are distinct permitted kinds; two different
Vote digests or two different Timeout digests for that identity conflict.
Proposal-witness signing uses its separate custody profile and must not invent
a Vote/Timeout intent variant. Handoff decisions retain one descriptor per role.

### Planned Safety14 / epoch record persistence

M02 owns the full field semantics and local phase tags 0..8. M03 stores one
complete epoch-qualified Safety successor and transition record in the same
transaction; there is no separately editable phase column that can advance alone.
Existing schema-13 bytes remain immutable recovery inputs, not a shape to which
new fields are silently appended under the old version.

Planned local envelope layout (not consensus wire), in exact order:
ASCII `TRNMS14E`, u16-be codec=0, u16-be schema=14, Hash32 context_ref,
u64-be revision, u64-be owner_generation, Bytes Safety payload, Bytes epoch
record, then Hash32 SHA-256 of preceding bytes. Bytes is u32-be length plus exact
bytes; identifiers inside the imported state payload retain its u16 lengths.
No varints, implicit defaults or serde field-order inference are allowed.

The Safety payload begins with u32 configuration_count and that many entries in
strict ascending epoch order: epoch u64, Bytes exact ValidatorSet, Bytes exact
ConsensusParameters. Include exactly contexts referenced by active state,
retained evidence and the live epoch edge; duplicates/orphans reject. Follow
with the exact field order and closed tags in current
`safety_state_record.rs::encode_state_payload`, applying these versioned edits:
all `encode_finalized_tip` occurrences prepend their explicit u64 epoch (the
state finalized/application-applied tips, payload parent, durable finalization
parent and sync-anchor parent); nested QCs/proofs decode under their own epoch's
registered context; remove only the schema13 epoch-zero codec restriction after
semantic context validation. Existing signed object bytes are unchanged.
`context_ref` is SHA-256 of ASCII `TRNMS14C` followed by the exact encoded
configuration table, u16-framed local validator ID, verifier-profile Hash32 and
u64 record/blob limits. Outer revision equals the payload revision. This is
local integrity binding, not a new consensus hash/signature domain.

The epoch-record bytes have this exact planned schema: u16=1, u8 phase 0..8,
u64 revision/generation, Hash32 genesis, u16-framed chain, u64 old_epoch/new_epoch/C,
four Hash32 old-set/old-parameter/new-set/new-parameter commitments, then the
following fields in fixed order. Every optional is tag0 absent or tag1 followed
by its payload; a Bytes payload is u32-framed; unknown tags and trailing bytes reject.

| Epoch field | Exact payload encoding when present |
|---|---|
| checkpoint identity | Option of block_id/root/next_commitment_hash, three Hash32. |
| prepared reference | Option of artifact Hash32 and persist_sequence u64; never an inline full snapshot. |
| checkpoint QC | Option of Bytes canonical QC. |
| seal1; seal2 | Two Options, each Bytes signed proposal then Bytes matching QC. |
| pre-handoff receipt | Option of Bytes M08 `TRNMCHK1` record. |
| descriptor | Option of Bytes unchanged canonical HandoffDescriptorV0. |
| local old decision; local new decision | Two Options of journal fingerprint Hash32; own role inferred from its fixed slot, verified against exact retained intent. |
| joint evidence | Option of u32 count=8, then eight Bytes in `EpochActivationEvidencePreimagesV0` order. |
| application edge | Option of Bytes M08 `TRNMEDG1` record. |
| anchor completion | Option of u64 Safety revision, checkpoint checksum Hash32, exact anchor digest Hash32. |
| first-new committed completion | Option of block_id/artifact/root Hash32 and application commit_sequence u64. |

Phase0 has no optional fields; phase1 requires checkpoint identity/prepared ref;
phase2 additionally QC(C); phase3 seal1; phase4 seal2/pre-receipt; phase5 descriptor;
phase6 joint evidence; phase7 application edge/anchor completion; phase8 first-new
completion. Future completion fields are forbidden. The two local decision slots
are optional from phase5, and permitted only for a role the local author owns.
An exact recovery can remain phase5 after a lost role response; it must recover
that journal decision before adding its slot. Configuration/coordinate fields are
cross-checked against immutable parameters and all required nested evidence.
The outer checksum is integrity only; independent store/anchor reconciliation
establishes freshness. No schema13 decoder is reused to accept these new bytes.

The epoch record uses M02's ordered fields and explicit option presence. Required
phase predecessors must all exist and verify; unknown phase/schema, future
fields, trailing bytes or unbounded lengths reject. Migration imports only a
validated quiescent pre-checkpoint schema-13 state, records original bytes/hash
and authenticated active epoch, and writes one schema-14 successor atomically.
Do not infer an epoch for an ambiguous historical FinalizedTip.

## Persistence and recovery

Use the existing SQLite WAL/FULL, private namespace, closed schema and sidecar
identity protections. Descriptor-bound checks and fsync ordering remain even
when performance work changes storage. A cooperating advisory lock does not
prove protection against external/uncooperating writers.

On startup keep all signing/output disabled, acquire one owner generation,
reopen Safety/journal/application/checkpoint independently, and load the external
anchor. For each pending operation compare exact predecessor and target:

| Observed facts | Recovery action |
|---|---|
| All authorities at predecessor; no released decision | Retry the identical admitted operation. |
| Intent exists, custody result absent | Ask exact intent status/replay from the same custody authority. |
| External target committed, local result missing | Verify target context, complete local successor once; never rewind external anchor. |
| Signature durable, publication unknown | Reproduce identical signed bytes/outbox identity; never choose new content. |
| Local target ahead of external | Only the documented one-step authenticated repair protocol may reconcile; otherwise fence. |
| Different descriptor/root/key/generation or unexplained multi-step gap | Durable halt; require independent operator recovery evidence. |

A timeout or HSM error after a possible effect is `Uncertain`, not proof of
failure. Restoring a coherent old disk snapshot must be detected against the
unchanged independent anchor. If that anchor is unavailable, halt signing.
Key non-exportability reduces cloning risk but does not replace decision history.
Never load stale node state over a newer signer decision.

Retain old-epoch role decisions/signatures through evidence, unbonding,
weak-subjectivity and local recovery windows. Archive only with authenticated
checkpoint/floor authority; storage pressure cannot erase double-sign protection.

## Resource bounds

Existing profile constructors validate `maximum_intents`, `maximum_intent_bytes`
and `maximum_database_bytes` against source hard limits and checked storage
products. Use the same rule for new-role and Safety14 records. Bound both encoded
intent size and complete retained evidence; a 32-byte digest is not the budget.

The planned signed deployment profile must specify journal count/bytes,
pending custody operations, request/response/frame bytes, status retry deadline,
recovery scan budget and retained epoch windows. Check that one maximum permitted
intent/proof and its result fit before admitting it. A profile missing a field or
whose retention is shorter than protocol accountability requirements rejects.
Operational timeout/capacity exhaustion returns unavailable before side effects;
after possible persistence/custody it returns uncertain and fences the owner.

Development fixture `signer-dev-v1` (planned, opt-in) selects unsigned u64
`maximum_intents=4096`, `maximum_intent_bytes=16384`,
`maximum_database_bytes=134217728`, `max_pending_custody=1`,
`status_deadline_ms=30000`, `recovery_batch_records=256`; schema is u16=1.
Handoff capacity must satisfy the existing checked formula
`16 MiB + maximum_intents*(maximum_intent_bytes+2048) <= database_bytes` and
all source hard caps. Safety14/epoch proof retention has its separate M02 limits
and storage, not this 16 KiB intent allowance. A fixture can time out unavailable
or uncertain but cannot replace protocol evidence retention or external custody.
Production uses explicitly authenticated values with the same validation.

## Security

Existing errors are `SignerJournalErrorV0`, `SignerJournalConflictV0`,
`ExternalWatermarkErrorV0`, `SignatureProducerErrorV0` and their handoff variants.
Planned epoch-local typed causes are `RoleNotAuthorized`, `DescriptorConflict`,
`CheckpointReceiptMismatch`, `SchemaUnsupported`, `ExternalAnchorUnavailable`,
`DecisionUncertain` and `RecoveryConflict`. Map to reject/unavailable/uncertain/halt
by side-effect status, not by a string or whether a network reply arrived.

Custody requests authenticate client/role/context and response request identity;
replay of a valid response for another signer generation fails. Unix peer UID is
an operational peer check, not a cross-host cryptographic signer identity.
Secrets must not appear in logs, control-plane metrics, manifests or process
arguments. Production key loading cannot fall back to candidate test keys.

## Observability and SLO

Report Safety persist, anchor CAS, custody, signature persist, checkpoint and
publication durations separately; include p99, uncertain-operation age,
blocked-sign count, replay count and recovery lag. Distinguish actual hardware
latency from simulated producers. Monitor capacity before it fences signing;
alerts cannot authorize emergency deletion or bypass an external anchor.

## Verification and evidence

Existing `signature_is_persisted_before_return_and_exact_replay_skips_producer`
and handoff journal tests establish focused source behavior. Extend at actual
Core/Store/custody boundaries, retaining current namespace and corruption tests.

- `M03-PERSIST`: process crash at every arrow; no signature before durable authorization.
- `M03-LOSTACK`: custody applied/response lost; exact replay yields one decision and same bytes.
- `M03-ROLLBACK`: coherent entire local namespace rollback while external anchor stays newer.
- `M03-CAS`: stale predecessor, changed target, duplicate and out-of-order callback.
- `M03-CUSTODY`: key rotation, wrong device/role, revoked session and no candidate fallback.
- `M03-ROLE`: old-only/new-only/dual-role authors, changed descriptor, role swap and missing pre-certificate receipt.
- `M03-S14`: every phase presence rule, unknown tag/schema, migration crash and ambiguous old epoch.
- `M03-RETENTION`: compaction cannot erase any still-slashable or pending decision.

Freeze exact local envelope/payload vectors with independently computed checksum
and rejection results before implementing schema14 readers. Physical controller
cache/power-loss and device custody evidence remain distinct from process kills.
No test or document here claims those external experiments have occurred.

## Activation boundary

Implement and review new-role admission/custody with M02/M08 before enabling it.
A fully specified local record still grants no production authority by itself.
External deployment qualification must show key custody, independent monotonic
recovery and same-artifact fault tests; retain all activation flags until the
repository's authorized governance/release procedure changes them.
