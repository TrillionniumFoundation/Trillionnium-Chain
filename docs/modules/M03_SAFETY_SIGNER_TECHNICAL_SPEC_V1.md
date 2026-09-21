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
The existing old-only handoff profile remains unchanged. The explicit
`HandoffSignerJournalProfileV1::for_epoch_handoff` profile additionally supports
new-only and dual-role authors, with a distinct profile-binding domain.
`StrictOldSetHandoffAdmissionV1` and `StrictNewSetHandoffAdmissionV1` consume M01's
strict pre-certificate context. M02's durable phase record and ordinary new-epoch
vote activation remain separate unfinished work.

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

### Role-specific handoff journal and native receipt join

```text
SqliteHandoffSignerJournalV1::sign_old_set_handoff_exact_v1(intent, old_admission, producer)
SqliteHandoffSignerJournalV1::sign_new_set_handoff_exact_v1(intent, new_admission, producer)
CandidateHandoffRuntimeV1::sign_handoff_exact(application, receipt, descriptor, NewSet, producer) // new-only
CandidateHandoffRuntimeV1::retire_ordinary_before_handoff_v1(application, receipt, descriptor, safety, safety_head, ordinary)
CandidateHandoffRuntimeV1::sign_retired_handoff_exact_v1(application, receipt, descriptor, role, safety, safety_head, retired, confirmed, producer)
```

These are implemented candidate interfaces; canonical handoff bytes and role
domains remain unchanged. Cryptographic admission binds both exact
sets/parameters, author and role, descriptor, strict checkpoint/two-seal finality
and authenticated checkpoint parent. The host wrapper separately joins a
`PreHandoffCheckpointReceiptV1` to its actual application owner, freshly reads its
COMMITTED row/head, and matches artifact/overlay/persist/commit identities and
cutoff-derived configuration before custody. The journal alone does not claim
this application-owner join. Old and continuing members additionally require
fresh journal8 terminal Safety evidence and the real retired ordinary owner;
the host derives all generation/native/Safety retirement fields from those owners.
It rechecks these cuts after custody and before returning the signature. The
new-only path rejects a new ID reusing any old-set consensus key until explicit
key/identity migration custody is implemented; this is a candidate commissioning
constraint, not a new frozen consensus validation rule.

Old role verifies membership under the old set; new role verifies membership
under the new set and independent old-chain trust. A dual member obtains two
admissions and two decisions. The journal uniqueness key is
`(genesis, chain, old_epoch, new_epoch, author, role)`; every retry must name the
same canonical descriptor/preimage. Distinct roles cannot overwrite each other.

Both roles retain the existing prepared SQLite transaction → external decision
CAS → custody → signed SQLite transaction → external signature CAS sequence.
The old ordinary terminal fence still prohibits later ordinary intents. The
explicit epoch-role profile permits audited new-role events after that fence;
the legacy profile retains its final-sequence restriction. A new-only profile's
absent old key is a zero sentinel, never a verification key. Every returned
signature is checked against the actual key for its role.

`recover_old_set_handoff_exact_v1` and `recover_new_set_handoff_exact_v1` require
fresh strict admission and the exact persisted intent. Recovery audits the
whole journal, admits only the expected pending predecessor/target, reconciles
that precise external CAS and rereads it. Ordinary open still fences uncertain
state. It cannot reset or roll back an external anchor. The host's
`recover_exact` is restricted to new-only custody and performs the native receipt
join before external reconciliation. Old and continuing members use
`recover_with_retired_ordinary_exact_v1`, which additionally verifies their
actual retired signer and terminal outgoing Safety owners.

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

### Implemented outgoing schema14 codec and strict inert recovery

This bounded outgoing format is distinct from the full-context inert codec below.
`encode_old_epoch_boundary_safety_record_v1` and
`decode_old_epoch_boundary_safety_record_v1_exact` use existing
`SafetyStateRecordContextV0` with the explicit minimum returned by
`minimum_old_epoch_boundary_record_limits_v1`. Exact local field order is:

1. ASCII `TRNMS14O`; u16-be codec1; u16-be schema14; context Hash32;
   revision u64-be; positive owner generation u64-be; phase u8 in 0..4.
2. Qualified true finalized tip followed by qualified application-applied tip.
   Each is epoch u64-be, validator-set Hash32, parameters Hash32, then the
   unchanged 56-byte finalized-tip encoding. Both remain under the old context.
3. u32-be length plus the unchanged ordered inner Safety payload. No new epoch,
   synthetic anchor or schema13-context substitution is representable here.
4. u32-be checkpoint count, sorted by block ID; each entry is the existing exact
   authenticated parent encoding followed by the complete signed proposal codec.
5. u32-be seal count, sorted by `(height, block ID)`; each entry begins with its actual
   authenticated parent timestamp u64-be followed by the complete signed proposal.
6. Hash32 domain-separated checksum of all preceding bytes under
   `trnm.consensus-core.old-epoch-safety-record.v1`.

The context hash uses `trnm.consensus-core.old-epoch-context.v1`, the existing
immutable Core/verifier/limits binding and a fixed outgoing-only layout marker.
Outer revision/tips/phase must equal the decoded inner state and reconstructed
retained evidence. Both counts and their sum are bounded by max_observed_messages;
retained full proposals share the 64 MiB resource ceiling. Required record
capacity is legacy minimum plus 64 MiB plus `2048*max_observed_messages+1024`,
using checked arithmetic; the maximum individual blob retains its legacy bound.
Sorted duplicates, unknown phases, mismatched qualified contexts, wrong checksum,
overlong/trailing bytes and noncanonical re-encoding reject. Checksums establish
integrity, not durable freshness or signature verification.

The decoder returns `UnverifiedSafetyStateRecordV0`; journal8 must invoke
`Core::validate_persisted_state_v0` and `validate_persisted_successor_v0` with
StrictEd25519. These validate checkpoint P/parent and every retained proposal,
QC/TC, seal root and geometry. Schema13 migration permits only exact unchanged
old state plus an empty outgoing owner and revision+1. It cannot reset views,
remove evidence or alter finalized/applied roots. Old schema13 codec/tests are
retained. Full-context `TRNMS14E` encoding is implemented separately below; a
phase7 record does not itself establish live epoch activation.

Strict terminal recovery accepts only a completed C checkpoint with its exact
retained two seals, no unresolved operation, and independently expected context,
owner generation and record checksum. Its private result is evidence only.
There is deliberately no recovery method that accepts public application/signer
scalar tuples and releases a live owner. Actual M15 owner-affine readbacks are
required before that consumer may be implemented.

### Implemented inert full-context Safety14 codec

`EpochSafetyStateRecordContextV1::new(config, runtime, checkpoint_artifact,
owner_generation, limits)` consumes strict eight-root `StrictEpochRuntimeContextV1`
and requires its new set/parameters to equal config. The artifact and generation
are comparison facts, not native or custody authority. It derives the exact
`EpochCoreStateV1` and a fixed strict-Ed25519 profile; callers cannot substitute a
verifier. `encode_epoch_safety_record_v1` and
`decode_epoch_safety_record_v1_exact` use this distinct closed layout:

1. ASCII `TRNMS14E`; u16-be codec1; u16-be schema14; context Hash32;
   u8 phase=7; u64-be global revision; u64-be positive owner generation;
   activation binding Hash32; exact checkpoint artifact/overlay.
2. Eight u32-be framed canonical roots in `EpochActivationEvidencePreimagesV0`
   order. Each must equal the strictly authenticated expected root; the old
   configuration is retained here and never decoded with the new set.
3. True finalized then application-applied coordinates, each epoch u64-be,
   set Hash32, parameter Hash32, and exact 56-byte FinalizedTip. The checkpoint
   keeps its old scope; an actual new block uses the active scope.
4. Ordered Safety payload from `encode_state_payload`, with the closed extensions
   below. A state-sync h1 carrier is forbidden in this full epoch profile.
5. Upcoming boundary phase u8 in 0..4, bounded sorted checkpoint candidates
   `(parent, full signed proposal)`, and sorted seals `(actual parent timestamp,
   full signed proposal)` using the outgoing candidate retention contract.
6. Hash32 over every preceding byte under
   `trnm.consensus-core.epoch-safety-record.v1`.

Every overlay carries its existing block/application-parent/checksum then a
closed option: tag0 ordinary; tag1 exact consensus-parent BlockId plus activation
binding. Thus the first application overlay stores C as its real parent and
C+2 separately. Payload parent provenance remains Finalized because C really is
finalized; carrier tag3 stores the exact activation binding and reconstructs
both complete headers only from the context's strict roots. Other carrier tags
keep their v0 meanings. A durable finalization prefixes parent-kind tag0/1;
tag1 requires the exact old checkpoint parent, first handoff proof, terminal
consensus parent and same dual overlay. An epoch proposal authorization is a
closed option with its full framed canonical preimage, compared against the
strict context. Nested QC/TC/finality use the explicit V1 exact decoders.

The context digest binds immutable new Core config, fixed verifier, resource
limits, strict activation binding, generation, exact checkpoint artifact and
layout marker under `trnm.consensus-core.epoch-safety-context.v1`. There is no
caller-editable ancestry anchor: `ConsensusAncestryBaseV1` is deterministically
derived from the real tip and authenticated evidence. Old seal header fields
are never rewritten to new epoch/view. Unknown tags, substituted root/config/
generation/artifact, wrong checksum, trailing bytes and noncanonical re-encoding
reject. Schema13 and 14O explicitly reject these epoch fields.

`minimum_epoch_safety_record_limits_v1` applies checked capacity arithmetic:
legacy structural envelope + 64 MiB retained proposal bound + framed evidence
bytes + `(4*max_observed_messages + 6*max_blocks)*(authorization_bytes+512)` +
4096. Maximum blob covers each evidence component and authorization in addition
to the legacy maximum. Limits must fit the local u32 framing before journal open.

Phase7 describes full-context record representation, not permission to run a
node or sign. The pure prepared activation consumes the old Core but exposes no
mutable Core or ACK. Journal9 will own this format in a fresh namespace; journal8
continues to own only 14O. Concrete native COMMITTED readback, external source
cut, actual ordinary retirement and a separately fresh new custody lease remain
mandatory before a live owner can be released. These joins are not implemented
by this codec. Repeated epochs must replace context only after prior obligations
and application finality settle, preserving global revision and original scopes.

### Journal8 ownership and remaining full-epoch activation cut

The first journal8 consumer is the closed **outgoing epoch-zero** subprofile:
Core record `TRNMS14O`, codec1/schema14, phases0..4. Its distinct SQLite
application ID and immutable profile forbid reading it as journal7 or as the
separate `TRNMS14E` journal9 activation namespace. It binds the strict Ed25519 verifier,
exact old Core configuration, resource limits and owner generation. The original
journal7 remains unchanged and locked during explicit migration; journal8 retains
its exact source record, transition context, journal ID and chain checksum.
Migration requires the actual strict Core's opaque phase0 persistence request,
the fresh source owner head and an independently supplied expected source cut.
Only schema/owner metadata and revision+1 may change. Creating this destination
does not retire ordinary signers or select it in an external host watermark.

Within this subprofile each append atomically retains the new and preceding
record, exact typed transition context, source-bound hash-chain head and global
revision. It validates Core's strict successor relation, rejects foreign owner
requests, and accepts an exact retry only at the active head. Before returning
opaque comparison evidence it closes the writer, syncs the actual database/WAL
and directory, opens a fresh read-only connection and verifies the retained
records again. Ordinary open creates no files or replacement metadata and
requires an independently supplied expected head. A commit/response-loss error
fences the live owner until explicit reopen at the independently reconciled cut.
Rollback of the entire namespace remains detectable only through that external
cut; a database checksum alone supplies no freshness. This consumer does not
issue StorageAck, signing leases, native application authority or epoch
activation. Those require the concrete M15 native/signer/readback join below.

The first implementation slice specified in M02 must preserve schema13/journal7
bytes and tests. Use a separate journal8 schema/namespace for schema14; never
rewrite `safety_schema=13` in an existing metadata row or reinterpret its record
layout. The immutable journal8 profile binds genesis/chain, local validator ID,
verifier profile and resource bounds. Each record binds its own exact retained
configuration table through `context_ref`; a fixed epoch-zero CoreConfig hash
must not be substituted with a new hash while decoding the old predecessor.
The independent trusted predecessor cut authorizes the old context. A new context
can become active only through reverified joint evidence, not by appearing in
the decoded table. Revision remains globally monotonic across epoch changes.

The implemented full-context codec derives `ConsensusAncestryBaseV1` from its
strict eight-root evidence instead of persisting a separately editable anchor
field. It yields the exact terminal-old header and new view-zero synthetic
reference while true finalized/applied remain C/old epoch. A seal or synthetic
anchor receives no application P, commit or finalized-reference authority.

The implemented 14E parent encoding keeps provenance tags0/1 unchanged.
Carrier tag3 is allowed only with provenance Finalized=0: it encodes the compact
real application tip C, provenance0, carrier3 and Hash32 activation_binding.
The decoder derives the two complete headers from the exact retained eight-root
context, compares the compact C tip and binding, and constructs the private edge
carrier. It does not accept caller-supplied terminal/header aliases. Tags0/1/2
retain their prior meanings. No provenance tag2 is implemented.

In 14E, each overlay encodes block_id Hash32, real application parent_id Hash32,
overlay_checksum Hash32, then u8 epoch-parent tag. Tag0 has no additional fields;
tag1 appends consensus_parent_id Hash32 and activation_binding Hash32. Tag1 is
admitted for the exact first-new target only at the Core callback/finality join.
The legacy13 and outgoing14O overlay encoders retain their original 96 bytes and
reject a dual-parent overlay.

Each 14E durable-finalization slot starts with closed u8 parent-kind tag0/1,
then compact real application parent tip, the preceding 14E overlay encoding,
and u32-be-length canonical FinalityProofV0 bytes. Tag1 requires the exact old C
tip and reconstructs its C+2 consensus parent from complete retained evidence;
the proof must finalize C+3 wholly under the new set and justify by the exact new
view-zero anchor. It carries no second editable ancestry header. Tag0 follows
ordinary direct-parent semantics and cannot contain an epoch overlay. Top-level
true finalized/applied tips separately encode their full epoch/set/parameter
qualification. Capacity checks include all retained evidence and both parent
headers in live obligation accounting before a transition can become durable.

The implemented journal9 layer is a separate closed SQLite application ID/schema9 and
namespace, preserving journal8 bytes and origin. Its immutable profile binds
the exact 14E codec context, source14O profile, owner generation and byte bounds.
Initialization must read the actual source journal8 at an independent expected
pin, strictly recover its settled checkpoint, and match the exact predecessor
of `PreparedEpochCoreActivationV1`. It persists that preparation's opaque initial
request at global revision+1 and retains source journal ID, exact source record,
transition, chain checksum and profile in every successor hash-chain origin.
The prepared Core remains inaccessible behind its activation persistence
barrier. Fresh reads return non-Clone owner-affine comparison receipts plus
`StrictEpochCoreRecoveryV1`; neither has an ACK/sign/step method. Actual host
composition must consume the fresh receipt together with native application,
retired custody and a fresh new-role lease before any live epoch is released.
A reopened store cannot bind arbitrary scalar state to a new live Core. This
journal is an inert persistence consumer, not completed runtime activation.
`confirm_exact_request_v1(pin, request, transition)` now checks the live Core
affinity and freshly matches the complete persisted state/barrier/transition;
it returns only a fresh non-Clone head. Its `migration_source_v1()` exposes the
audited immutable source8 pin, record checksum, context/profile and exact first
revision, derived again from retained strict source evidence on every read.
Those comparison fields cannot construct a source owner or grant an ACK.

The default-off `candidate-epoch-host-v1` feature forwards Core's same-named
trusted-host seam. `prepare_candidate_host_initial_recovery_v1(expected_pin)`
requires an unbound reopened journal, exactly its immutable initial revision
and Ordinary transition, and the strictly reconstructed canonical initial14E
state. A second fresh read precedes binding the one returned pending driver's
new process affinity. Duplicate binding, stale pin, prior-process requests and
progressed/outbox cuts reject. No revision is appended and no ACK, timer or
signer lease is emitted; M15 must still join the actual native/custody/external
checkpoint owners before the driver's trusted ACK. Default builds remain
read-only after reopen. The actual native/source8 integration test reopens
journal9, checks these affinity/freshness failures, and persists a new-epoch
timeout after a test-only host ACK; the later pending-sign cut cannot use this
narrow initial-recovery helper.

`initialize_from_journal8_v1` takes the exact opaque preparation by reference
and binds its persistence affinity; `persist_exact_v1` accepts only that owner's
opaque requests. Reopen has no persistence binding and no scalar rebinding API.
`ConfirmedEpochSafetyHeadV1` heap-owns its unverified record, freshly compares
owner/path/expected pin/checksum/transition, and is not Clone. Recovery sessions
also heap-own retained state to avoid large caller-stack copies.

SQLite row capacity is checked before namespace creation as
`max(source_record_limit, target_record_limit) + max_transition_bytes + 4096`;
both BLOBs share a metadata/record row. Closed-schema inventory inspects at most
four rows for three expected tables, bounds borrowed names/SQL before copying,
and sorts only that bounded result in memory. Tests use actual source8/native
checkpoint receipts: exact retry, foreign Core affinity, stale independent pin,
changed native artifact/profile, and immutable-origin corruption. Real SIGKILL
at initialization before commit, after commit/before sync, and after sync/before
readback yields either rejection or the exact strict inert record; none releases
a Core or lease. The tests do not establish a complete M15 activation lease,
repeated journal9-to-next-epoch migration, or cross-store rollback recovery.

### Contextual successor journal (M03-EPOCH-JOURNAL-V2; inert persistence implemented)

M02's `TRNMS14E` codec2 and complete `TRNMEP02` preparation prefix require an
explicit journal10 consumer. Existing journal9 remains exactly codec1 and
source-journal8 only. Neither a changed SQLite version nor successful scalar
comparison upgrades an old owner. The V2 Core preparation and recovery types
have no V1 candidate-host conversion.

The new namespace uses application ID `0x54524541`, user_version 10 and lock
magic `TRNMJ10E`. Its closed tables retain the same metadata/head/two-record
roles as journal9, with an additional immutable source-kind tag: 0 is settled
journal8/14O, 1 is journal9/14E codec1, 2 is journal10/14E codec2. Every other tag
rejects before record decoding. Source and target records use their exact
versioned decoders with no fallback. Unknown schema objects, malformed row
cardinality, oversized SQL names/text, sidecar substitution, symlink/hardlink,
foreign process or unexpected writer reject without repair.

`EpochSafetyJournalProfileV2` contains the target Core configuration, limits,
full verified epoch state and owner generation, plus one flat immediate-source
context descriptor and its independently pinned journal profile reference.
It never recursively embeds a preceding journal profile or all preceding
Safety records. The descriptor remains in the independently supplied immutable
profile; SQLite retains the exact immediate source record/transition without
duplicating another full descriptor BLOB. The source descriptor contains its exact Core configuration,
codec, record bounds, generation and, for 14E, its complete verified epoch
state. Prefixes remain flat and retain M02's 32-entry/64-MiB bounds. Recreating
a codec2 context calls the epoch state's metered `recover_preparation_v2` with
one bounded meter for the complete prefix; its 64-MiB framing limit never
becomes an eight-root CEV0 limit.

The profile hash domain is `trnm.journal10.epoch.profile.v2`. It binds source
kind, immediate source profile/context references, exact target codec2 context,
generation and calculated row/database bounds. The origin and record-chain
domains are separately `trnm.journal10.epoch.origin.v2` and
`trnm.journal10.epoch.chain.v2`, retaining journal9's ordered u64-length-prefixed
hash-part framing. Origin commits the target profile and new random journal
ID together with source kind, source journal/head/record/transition pins, exact
original source record/transition, and first target revision. Each successor
hash additionally commits origin, previous chain hash, revision, exact target
record and exact transition bytes. Independent expected head pins remain
necessary to detect whole-image rollback.

Initialization takes an opaque `PreparedEpochCoreActivationV2`, a real source
journal owner of the selected kind and an independently expected source pin.
Before namespace creation it freshly reads and strictly reconstructs that
source, compares its actual immutable profile reference with the flat source
descriptor, matches the preparation's exact predecessor and persistence affinity,
and independently asks the recovered source to prepare this same target.
Both preparations must have identical complete state, barrier and transition
manifest. Their process-local affinities need not be equal: only the original
preparation's opaque request may bind the destination journal.
M02 enforces applied equals finalized at the original checkpoint, no unresolved
sign/finalization/validation/sync/halt, exact proof/overlay, generation + 1,
revision + 1 and exactly one appended activation with unchanged prior entry
bytes. A codec1 source requires the first retained entry to equal its original
eight roots; a codec2 source cannot replace its prefix or downgrade.

Namespace locking, WAL `synchronous=FULL`, immediate transactions, checked
readback and file/directory synchronization preserve the existing ordering.
A second actual source-owner read must match before successful return. Return
only a non-Clone owner-affine `ConfirmedEpochSafetyHeadV2`, never StorageAck,
Core input, a signature or a custody lease. Reopened journals remain unbound;
scalar state cannot rebind a live owner. `confirm_exact_request_v2` requires
actual process affinity, barrier/revision, complete state and transition
manifest to equal a fresh read. `persist_exact_v2` preserves CAS, exact retry,
monotonic revisions and bounded two-record retention. Every fresh read audits
the immutable source and reconstructs the same exact initial successor even
after that target row is pruned.

Source and target record limits are each at most 256 MiB; transition frames
are at most 1 MiB. Compute SQLite row capacity from the larger exact record
limit plus transition and fixed metadata overhead before opening a namespace;
check all arithmetic and SQLite i32 limits. Database capacity includes bounded
source metadata, retained target rows and WAL headroom. No recursive history
or unbounded schema inventory is admitted. Post-write uncertainty fences the
owner; crash recovery either rejects an incomplete namespace or reconstructs
exact committed state. It must not guess a commit outcome or release callbacks.

Until the V2 physical host join exists, a source10 progression test must use a
private test harness producing actual opaque Core requests and actual journal
writes. It cannot fabricate settled scalar rows or add a production activation
shortcut solely to make that test pass.

Required acceptance uses actual journal owners, genuine contextual multi-epoch
proofs and opaque Core requests. Cover source8-to-V2, source9-to-V2 and a second
source10-to-V2 transition; fresh reopen, exact retry, wrong affinity/pin/profile,
valid alternative prefix, changed native artifact, generation/revision skips,
missing/replaced sidecars, corrupt origin after pruning, and real SIGKILL before
commit, after commit/before sync and after sync/before readback. These checks
establish persistence only. M15 must separately join actual committed native
checkpoint state, role-specific retired/new custody and an independent external
watermark before any initial ACK; journal10 must not inherit journal9's existing
trusted-host recovery shortcut or any V1 driver conversion.

#### Exact initial trusted-host binding (M03-EPOCH-INITIAL-HOST-V2)

The separately default-off `candidate-epoch-host-v2` feature forwards only
Core's same-named V2 feature. It does not enable `candidate-epoch-host-v1` or
commission an epoch owner. `prepare_candidate_host_initial_recovery_v2(pin)`
accepts only an unbound existing journal10, its independently expected exact
head, the immutable origin's first target revision, and Ordinary transition.
The complete strict record must equal Core's canonical initial codec2 state;
progressed, pending-sign/outbox, foreign-context and stale cuts reject.

The method obtains an actual fresh read and strict recovery, reconstructs the
opaque `PendingEpochHostDriverV2` without an ACK, then performs a second actual
fresh read. Complete state, record checksum, head pin, context, generation,
transition and immutable origin/source facts must remain identical. Only after
both reads succeed may the journal install that driver's new process-local
persistence affinity. The original process's request, equal scalar state from
a foreign driver, and a second binding attempt cannot bind or confirm work.
No revision is appended by this operation; failed checks leave the journal
unbound. Return only `(ConfirmedEpochSafetyHeadV2, PendingEpochHostDriverV2)`
with the initial persistence gate still closed.

This is trusted-host plumbing, not a durable activation grant: it produces no
StorageAck, timer, signature, custody lease or native callback. M15 must join
the actual committed native checkpoint, old-role retirement, fresh new-role
custody and independent external watermark before supplying the initial ACK.
Tests may explicitly supply a test-only trusted-host ACK to prove the engine
sequence, without claiming that physical M15 join. A real `LocalTimeout` must
first emit only its opaque persistence request; only after journal10 commits,
syncs, freshly confirms the exact request, and receives its separate ACK may
Core emit `RequestSignature`. Reopening that progressed cut cannot use this
initial-only binding method. The default build remains inert and unbound.

Acceptance retains the real source8/native fixture and default thread stack,
checks old/foreign affinity, stale head, repeated binding, pre-ACK input gates,
the actual timeout persist/readback/ACK ordering, and progressed-cut refusal.
Any post-initial crash tests retain actual opaque Core requests and independent
expected cuts; they cannot manufacture progressed SQL records or authorize an
ACK based solely on a self-carried checksum.
The doc-hidden `persist_with_pin_observer_v2` supplies the actual producer's
calculated successor pin at the before-commit, after-commit/before-sync and
after-sync/before-readback cuts. The original observer method remains an
adapter with its existing signature. Test observers may durably retain this
comparison pin before killing the process; neither observation nor a recovered
database's self-reported head provides an ACK or external rollback protection.

The inert journal10 implementation and private physical backend are now present
in `epoch_journal_v2.rs` and `epoch_journal_physical_v2.rs`. The original journal9
codec, SQL layout, hash domains and public API retain their previous behavior.
`tests/epoch_journal_v2.rs` executes an actual native committed checkpoint and
source8 owner, then journal10 migration, original-request retry, foreign-affinity
rejection, source-independent cold recovery, immutable-profile/head/origin
corruption rejection without repair, and all three real SIGKILL initialization
cuts. These tests run with the default thread stack; an ignored child is launched
explicitly by the parent for each death cut. The physical backend and existing
journal8/9 regressions remain required.

Actual progressed source9-to-journal10 and journal10-to-journal10 migrations,
post-initial CAS/pruning/crash cases, role-specific custody and the live physical
host join remain open. The implementation does not close live repeated-epoch or
external acceptance gates.

Use a single M15 owner to route ordinary Vote/Timeout, old handoff and new
handoff requests and to hold all relevant namespaces. The existing
`SqliteHandoffSignerJournalV1` terminal fence only protects its own
`sign_old_epoch_exact_v1` path. It does not retire a separately open
`SqliteSignerJournalV0` or a remote signer. Before recording/releasing an old-role
handoff signature, finish/reconcile any already prepared old ordinary decision,
persist the shared retirement intent, advance its external owner cut and forbid
every old Vote/Timeout/proposal custody route. The handoff request itself may
then proceed through its exact replay-safe journal path. A crash cannot reopen
old custody merely because the handoff signature's response was lost. A new-only
local member needs no old local decision; a removed member receives no new
ordinary signer lease. The profile binds membership/key/epoch for each role.

The exact activation recovery order is:

1. Acquire the new process generation while all custody, timers and output are
   disabled; load the independent external cut before trusting local phase tags.
2. Read old/new journal metadata and Safety predecessor/successor bytes without
   initializing an absent namespace. Reverify complete old checkpoint/two-seal
   and joint proof under the trusted retained old configuration.
3. Fresh-read the real COMMITTED checkpoint and its artifact/commit sequence;
   recreate the owner-affine M08 edge. PREPARED, a root-only snapshot or a missing
   row cannot satisfy this step.
4. Reconcile each pending role decision and old ordinary retirement to its exact
   external predecessor/target. Never resolve uncertainty by resetting a view,
   dropping an intent, signing again under a different descriptor or creating a
   replacement journal. Preflight the new profile's complete old+new evidence
   capacity before making old retirement irreversible.
5. Persist the exact phase6->7 successor containing both context preimages, true
   C tips, terminal C+2 ancestry base, new high/lock anchor and revision+1. Fresh
   readback plus the external whole-node successor CAS records this exact cut.
   Two local databases are coordinated by intent/readback/CAS, not claimed atomic.
6. Only after that CAS and a second matching readback may the owner issue the
   new ordinary signer lease and Core persistence acknowledgment. Exact response
   loss resumes the same cut. Any third state or ahead/foreign external head
   fences the owner. Pending C+3 application commit still permits authenticated
   speculative C+4/C+5 execution and votes.

The full `WholeNodeCheckpointV1` codec currently rejects epoch-transition
phases even though its reference codec admits their tags. Implement the concrete
epoch cut and signing-cycle bridge in a versioned full record before using its
reference as activation completion; an `EpochActive` reference alone proves no
owner readback or CAS. Crash tests must cover every step above with both shared
and separate old/new custody keys, including a separately opened ordinary signer
attempt after the shared retirement cut. Migration keeps the original schema13
bytes/checksum and forbids effects until the external cut selects journal8.

## Persistence and recovery

### Ordinary signer retirement and external terminal cut

The continuing/removed-member path consumes the actual exclusive schema0
`SqliteSignerJournalV0` owner. It first verifies the strict pre-handoff descriptor
and old-role intent against that owner's author/configuration, reconciles its
external head, and requires no PREPARED unsigned intent. A local schema2 retired
image keeps all original schema0 metadata, intents and events byte-identical;
it adds one immutable retirement record and insert-blocking triggers. Both the
original schema0 open and a fresh schema0 signing attempt must fail thereafter.
No ordinary owner is returned on success or uncertainty. Ordinary existing open
never performs this migration.

The fixed retirement record `TRNMSR01`, u16-be version1, contains the source
watermark (scope, journal ID, u64 sequence, chain checksum), u64 owner generation,
pre-handoff binding, descriptor digest, exact old-role intent fingerprint,
source profile checksum, committed native cut digest, u64 Safety revision and
Safety record checksum, followed by its domain-separated checksum. All hashes
are32 bytes; the complete record is354 bytes. Its terminal external watermark
preserves scope/journal, advances sequence by one and commits this exact record
under a separate retirement domain. This is a retirement event, never a fake
Vote/Timeout intent or a fabricated signed event. Native/Safety scalar fields
are comparison bindings; retirement cannot turn them into application authority.

Order: local retirement transaction → SQLite FULL commit and file/directory
sync → independently administered terminal CAS → exact external terminal
readback → fresh local retirement readback. The external authority must reject
every legacy load/CAS/signing reservation for the retired scope, including a
restored pre-retirement local image. Response loss may reconcile only the exact
source or the exact intended terminal cut. A foreign/ahead third state, missing
record, changed descriptor or incomplete local namespace fences recovery.

Retirement precedes the old handoff signature, so it binds the strictly verified
pre-handoff descriptor rather than a not-yet-assembled joint certificate. A
separate new ordinary-custody lease follows complete joint-proof verification,
native checkpoint readback and full new Safety persistence. It binds the full
activation, new epoch/set/parameters/author/key, globally monotonic generation,
source retirement and fresh target namespace. Removed members receive no new
lease. New-only members use an explicit virgin-target path, not a fabricated old
retirement or zero-key evidence. Proposal custody and remote signer paths must
consume the same terminal policy before this contract counts as live activation.

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


### Original ordinary custody selection at the host boundary

M15 now fixes original custody before retirement by consuming actual
`ConfirmedSignerNodeCheckpointFactsV0` from the selected live ordinary journal.
The selection retains process-local affinity, canonical path, journal ID,
external scope, complete profile checksum and initial exact watermark. Fresh
ordinary confirmation must match that owner and cannot move below the selected
sequence. `belongs_to_retired_journal_at_path_v1` checks the same affinity after
owner consumption plus exact identity/profile/source scope/journal; it is only
identity evidence and does not replace fresh local/external retirement readback.
A same-key journal under another scope, or even scalar-identical reopened owner,
cannot borrow that capability. The live constructor is commissioning, not a
retired-record-derived recovery constructor.

Terminal14O recovery now uses M15's concrete independent node-checkpoint
producer/consumer. Its predecessor fixes the original signer before retirement;
fresh readback audits the actual historical signer prefix, exact journal7
migration origin retained by journal8, terminal Safety and committed native C.
Only that producer can issue the owner-affine, non-Clone checkpoint token used
by the new recovery entry. The scalar-only entry remains closed before CAS.
Closing and reopening all local owners regenerates fresh native/Safety receipts
and repeats the exact persisted handoff signature without another key call.
This restores old handoff custody only; full14E activation and a new ordinary
lease still require the separately specified V1 lineage checkpoint and join.
New-only strict admission remains separate.

### External ordinary-signer terminal policy V1

The real semantic watermark authority, in `SignerJournalPair` mode only, retires
its existing scope and journal ID at the exact even source sequence in the
354-byte `SignerRetirementRecordV1`. Its immutable mode marker transitions from
version 1 (140 bytes) to version 2 (494 bytes): original 108-byte mode/binding
prefix, the complete retirement record, then a domain-separated marker checksum.
The version-2 marker is atomically renamed after file fsync, then parent-directory
fsync; success requires a fresh full namespace readback. There is no separate
terminal sidecar and no invented Vote/Timeout event. A legacy daemon rejects this
marker. The ordinary and semantic event histories retain their exact retired source
prefix. After the mode transition, a typed 428-byte `TRNMER01` terminal event is
appended to the existing ordinary authority log and fsynced. It binds the full
retirement record and preceding log hash; it is not an ordinary signing intent.
Only this complete log plus matching mode marker may acknowledge retirement.
Even when startup replay sees a complete terminal tail, exact retry and confirmed
retirement load re-sync the log and directory before fresh preflight/readback.
A process crash can leave readable cache bytes without having completed fsync;
a successful read is not a substitute for that durability barrier. Injected sync
failure returns no confirmation and poisons the live instance; exact reopen can
retry. Startup anchor reads now use exact fixed lengths, private-file/no-follow
checks and bounded reads before decoding; oversized sparse files and symlinks
are rejected before allocating their contents.
The marker commits the next terminal sequence and all host/context comparison
bindings. Rolling back just the mode file is detected by the terminal log suffix;
rolling back the log alone leaves the mode retired. A complete mode without its
terminal suffix accepts only an explicit exact retirement retry, which appends
the missing event before returning confirmation. Partial tails fail closed. The semantic source's latest Safety revision must precede the retirement
revision. Pending odd prepared sequences cannot retire.

After transition, all ordinary load, semantic load, and compare-and-advance paths
reject the scope, including a separately restored old local journal. The authenticated
Unix protocol retains ordinary version 1 and adds closed `EWM2`/`EWR2` version-2
retirement read/CAS frames, within the existing 512-byte limit. Same binding,
capability, lifecycle, full source head and full record are required; an exact retry
returns the same terminal watermark, while any changed field rejects. A response
lost after fsync is recovered by exact retirement read/CAS, never by reviving ordinary
signing. The whole external namespace still requires independent administration;
this is not an HSM or proof against rollback of that independent authority itself.

Fresh semantic ordinary custody uses `initialize_new_prebound_semantic_v1`:
provision the independent authority with its explicit random journal ID, then
create the fresh local schema0 with that exact ID and claim only an empty
semantic pair head. The old initializer chooses its own random ID and cannot
bootstrap an already-bound daemon. A supplied ID is an identity comparison,
not permission to adopt any existing external history or activate an epoch.


The implemented retirement regression covers an actual schema0 owner and a
separate authenticated Unix daemon: strict frozen checkpoint context, real
ordinary Ed25519 signature, local schema2 readback, exact terminal retry after
lost confirmation, whole local snapshot restore while the daemon stays running
and after daemon restart, mode-only rollback against the appended terminal
event, and wrong/pending source rejection. Six real SIGKILL cuts span mode file
write/fsync/rename/directory sync and terminal append/fsync. These are process
crash tests on the test filesystem; they do not claim physical power-cut,
independent administrative custody or a complete activated epoch runtime.
