# M00-M17 implementation and conformance guide v1

Status: **candidate implementation documentation; semantic acceptance and production conformance not assessed**. Primary module: M17; affected producers/consumers: M00-M17. This is a stable technical supplement, not a second plan or a completion report.

## How to use this guide

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` first. The machine trace index is `config/documentation-contracts-v1.json`. Each row names exact normative files, concrete implementation files, regression inputs, package ownership and required review domains. Read the referenced normative layout and error registry with the module's algorithm below; do not infer a wire schema from an English stage name or a Rust type name.

The guide specifies required behavior. A cited source/test means it is a review target, not that the behavior is integrated or its tests pass. `bft-v0` is the frozen implementation target; `pcc1` and `ai-v1` are non-activated candidates. For a mixed-profile module, choose the profile per operation and artifact, not once for the entire crate. Unsupported or undecided production operations remain disabled.

### Common error and evidence vocabulary

The following are documentation outcome classes, **not new wire codes**: `Reject` means the selected protocol/profile deterministically rejects the supplied input; `Unavailable` means a local resource/dependency prevented assessment and may be retried; `Uncertain` means a durable side effect may have happened and fresh authoritative readback is mandatory; `Halt` means signing/commit/publication stays fenced pending recovery or review. Map each requirement to the existing exact error enum, parser offset and external API result before accepting its implementation. Never convert local timeout, disk-full or missing data into a Byzantine invalidity assertion.

For every rejection vector assert the error class/code AND the unchanged authoritative root, sequence, balances, nonce, watermark and outbox applicable to that operation. For uncertainty assert one logical effect after exact replay, not merely successful return. Failed cryptographic work still consumes its declared work budget. Diagnostic counters do not silently change monetary accounting. All additions, multiplications, indices and horizon calculations use the selected checked integer rules.

Each module also has one inspected, representative function/error/regression trace in the registry and below. These traces expose current implementation scope and exclusions; they are not coverage of every requirement or independent acceptance. The gate checks their source bindings and lexical symbol presence, not control-flow equivalence.

Each scenario below has a stable requirement ID (`Mxx-*`). A reference implementation must publish exact input bytes, authenticated pre-state, expected post-state/effects or errors, and an independently produced expected result for each ID. Existing regressions are linked by the registry; scenarios without an independently frozen vector remain unmet acceptance requirements. Source-level examples and model tests are not passed-off as golden wire vectors.

<a id="m00"></a>
## M00 — Protocol / Schema / Codec

**Applicability and inputs.** `bft-v0` controls CEV0 signed/hashed preimages; `ai-v1` controls its separately versioned CEV1 objects. Resolve genesis, chain, protocol, role/domain, active parameter hash and object kind before interpreting bytes. The seven v0 normative imports and their byte vectors remain immutable inputs to PCC1.

**State/admission algorithm.** Start with an authenticated context and its finite byte/count/depth/signature-work ceilings. Bound the outer frame before allocating nested collections. Decode fields in the selected exact order; reject unknown tags, duplicate fields/signers, invalid encodings, arithmetic overflow, noncanonical order and trailing bytes. Validate all semantic identities and parameter bindings. Re-encode the admitted inert value and compare exact bytes where the canonical contract requires it. Only M01 verification can turn a cryptographic claim into a verified capability. Protobuf and transport JSON never replace signing preimages.

**Error and recovery semantics.** A deterministic parser failure returns the selected registry code and exact offset; unknown profile has no fallback decoder. An unavailable parameter/context resolver does not choose defaults. Decoding/encoding has no signing, storage or publication side effect. A disagreement between frozen bytes and code blocks that profile rather than normalizing the input.

**Conformance requirements.** `M00-CANON`: every golden object round-trips with identical bytes/hash. `M00-PREFIX`: each truncated prefix and an appended byte rejects. `M00-BOUND`: exact maximum succeeds and maximum+1 rejects before excessive allocation. `M00-DOMAIN`: identical fields under a different chain/domain/version never authenticate. `M00-REGISTRY`: every reachable boundary error has one registered meaning, including node-local versus peer-visible scope.

**Implementation and consumers.** Inspect all M00 packages in the registry and the exact parser/codec entry points in `trnm-consensus-types`; compare crypto consumer vectors, not just serde snapshots. M01, M02, M05 and M13 must consume the same profile/limits/error meanings. Freeze acceptance needs independent parser and byte-vector review; structural file discovery cannot grant it.


**Exact-source review trace.** For `M00-CANON` under `bft-v0`, inspect `trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs` symbol `decode_consensus_parameters_v0_exact`; the current error definition/literal is `DecodeErrorCode` in `trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs`. Reproduce `consensus_parameters_decoder_round_trips_and_exhausts_the_exact_root` in `trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs`. Exact parameter decoder only; independent coverage of every reachable CEV0/CEV1 object is not established.

<a id="m01"></a>
## M01 — Cryptography / Identity / Capability

**Applicability and inputs.** `bft-v0`/`pcc1` use the imported strict Ed25519 verification and CEV0 domains; AI identity/capability rules are `ai-v1`. Inputs include authenticated context, committed authority set, expected object/target, exact statement bytes, key policy and remaining verification budget. The supplied proof cannot choose its own trust context.

**State/admission algorithm.** Strictly admit every authority key before activating its set. Establish canonical unique member IDs and public keys; count each authorized signer at most once. Bind role, genesis/chain/protocol, epoch or nonce/session generation, target and domain according to the exact statement layout. Charge the work budget before attempting each signature verification, including unsuccessful attempts. Verify the complete proof and required ancestry/justifications before returning a private verified capability. Never expose a constructor or deserializer that converts an untrusted success flag into that capability.

**Error and recovery semantics.** Weak/malformed key, invalid signature, duplicate signer, wrong role/context, target substitution, stale generation or exhausted budget rejects without authority. Missing external key material is unavailable. M01 does not hold signing keys or repair storage; hardware signer uncertainty belongs to M03. Unknown algorithms and verification profiles never downgrade to weaker classes.

**Conformance requirements.** `M01-KEY`: weak/zero/noncanonical key admission negatives. `M01-SIG`: corrupt each signature independently and account for the failed work. `M01-TARGET`: change target/root/parent/context while retaining signatures and reject. `M01-CAP`: external callers cannot construct or clone authority to bypass verification. `M01-REVOKE`: the exact revoked/expired session cannot authorize a fresh action.

**Implementation and consumers.** Trace `trnm-consensus-crypto/src/strict_finality.rs` into `trnm-native-execution-v0/src/pcc1_finality.rs`, and signer-protocol contracts into M03. Existing PCC1 real-signature regressions are concrete inputs, not proof that every epoch/migration consumer has adopted the verifier. Cryptography specialist and consuming proof-owner review are required.


**Exact-source review trace.** For `M01-TARGET` under `pcc1`, inspect `trillionnium/crates/trnm-consensus-crypto/src/strict_finality.rs` symbol `decode_verify_finality_proof_strict_v0`; the current error definition/literal is `StrictFinalityErrorV0` in `trillionnium/crates/trnm-consensus-crypto/src/strict_finality.rs`. Reproduce `rejects_retargeting_to_newest_qc_or_different_root` in `trillionnium/crates/trnm-consensus-crypto/tests/pcc1_strict_finality.rs`. Strict proof admission only; full runtime, epoch and migration consumer adoption remains separate.

<a id="m02"></a>
## M02 — Order / Consensus Kernel

**Applicability and inputs.** The sole kernel is `bft-v0`; PCC1 specifies its target owner/composition. Inputs are authenticated typed events, immutable prior state, the exact epoch validator/parameter commitments, retained certified ancestry and explicit completion generations. No socket, database, wall clock, model output or control-plane decision belongs in the deterministic transition.

**State/admission algorithm.** Recompute checked total weight W and unique signer weight S; quorum is `floor(2*W/3)+1`, with the specified overflow rejection. Validate proposal leader, context, parent, height/view, justification and required TC before the frozen safe-vote/lock predicate. Persist the resulting Safety decision through M03 before its signature escapes. A TC advances view only under the exact high-QC selection rules; it does not unlock or finalize. For three exactly linked certified blocks with consecutive heights and increasing views, learning the newest QC finalizes only the oldest and its ancestors. Apply finality in ancestor order. Epoch transitions require the frozen old/new authorization separately.

**Error and recovery semantics.** Invalid proof or context rejects; missing ancestry/data is unavailable and triggers bounded retrieval, not a guessed vote. Conflicting same-view QCs or inconsistent recovered authority halt. A timeout is an input/effect, not permission to bypass locks. Recovery reconstructs one Core owner from authenticated durable facts before resuming; replays cannot create a second owner.

**Conformance requirements.** `M02-QUORUM`: 5/7/8 members and unequal weights, threshold-1, exact threshold, duplicate signers and checked overflow. `M02-THREECHAIN`: reject a single QC and finalize the oldest valid header only. `M02-TC`: skipped-view TC and exact tie-break tests. `M02-LIVE`: idle blocks, low-load finalization, partition/heal and adequate post-GST timeout. `M02-EPOCH`: test both old and new fault bounds, handoff and incompatible activation.

**Implementation and consumers.** Trace `trnm-consensus-core` Input/Effect transitions to M03 signing and M08 ordered finalization, using frozen conformance vectors and independent state-machine models. PCC1's abstract model does not cover the complete safe-vote/TC/epoch implementation. Consensus specialist review must state this residual scope.


**Exact-source review trace.** For `M02-LIVE` under `bft-v0`, inspect `trillionnium/crates/trnm-consensus-core/src/core.rs` symbol `step`; the current error definition/literal is `CoreError` in `trillionnium/crates/trnm-consensus-core/src/error.rs`. Reproduce `two_plus_two_partition_cannot_finalize_and_heal_restores_progress` in `trillionnium/crates/trnm-consensus-sim/tests/scenarios.rs`. Simulator regression of the kernel, not a real multi-host or complete liveness proof.

**Executable epoch evidence boundary.** `trnm-consensus-types/src/epoch_activation_evidence.rs` decodes eight independently canonical preimages: old-checkpoint finality, next-epoch commitment, joint authorization kernel, both validator sets, both parameter sets, and the authenticated checkpoint-parent header. `recover_epoch_activation_authority_strict_v0` in `trnm-consensus-crypto/src/epoch_transition.rs` checks the independent old trust context, every nested signature and the exact existing strict binding before returning the non-cloneable authority. B2-F leaves aggregate `EpochHandoffProof` CEV0 bytes, digest and signature domain unfrozen; the eight-field recovery input does not define any of them. `epoch_first_proposal_signing_root_v0` calculates the existing proposal signing root without exporting an anchor capability. `verify_first_epoch_proposal_header_strict_v0` uses the full strict authority to verify only the view-1 header, leader and signature. It does not establish payload validity, native execution, a signing permit or live Core activation. A first proposal after skipped views still requires a dedicated complete anchor-aware TC verifier; the generic proposal/TC anchor guards remain closed.

**Remaining live epoch contract.** `trnm-consensus-core/src/epoch_preparation.rs` only represents `EvidenceVerified`, consumed by the actual M08 preparation store below. Main SafetyState remains schema 13. A future explicit Safety schema 14 needs a reviewed closed phase codec and Core input/effect/recovery contract in `model.rs`, `core.rs` and `safety_state_record.rs`, together with matching Safety-store records. It must separately bind the exact committed native checkpoint receipt, old/new configurations, two seals, joint descriptor, new-role signing custody, anchor, and first executed new block. Bind finality/high-QC/lock comparisons to their epochs: an old finalized checkpoint's view cannot be compared numerically with the new view-0 anchor. Preserve the old proof and application head while transitioning consensus ancestry. No existing generic `EpochBoundaryUnsupported` check may be removed merely because strict evidence or a preparation row exists.

**Epoch phase ordering is not yet implemented.** Existing `EvidenceVerified` already requires the complete checkpoint/two-seal finality proof and the joint certificate's old and new quorums. `ConfirmedNativePocoCheckpointV0`, produced by `trnm-native-execution-v0/src/poco_checkpoint.rs::confirm_poco_checkpoint_v0`, also requires the complete joint certificate. Neither is a precondition from which the seals or those handoff signatures can first be produced: that would create circular authorization. Specification 04 sections 6 and 8 require `QC(seal_2)` and complete checkpoint finality before either handoff role signs. The candidate `confirm_poco_checkpoint_for_handoff_v0` now supplies a separate readback of the real COMMITTED checkpoint execution, exact prepared header/body/roots, authenticated cutoff and recomputed commitment, and strict two-seal proof without requiring a joint certificate. Its private `CommittedNativePocoCheckpointForHandoffV0` is not a signing permit or epoch anchor. `complete_poco_checkpoint_handoff_v0` consumes it only for a later full joint-certificate join and rechecks the original native and preparation stores. This removes the joint-certificate prerequisite from this one application read boundary, not from the still-unimplemented live epoch state machine. The Rust candidate and its regressions require compiler execution and independent consumer acceptance before they can be credited as qualified implementation. Old/new handoff signing must then consume independent role-specific admission and persist one exact descriptor per transition and role before custody. `StrictOldSetHandoffAdmissionV1` is an existing pre-certificate old-role boundary; `HandoffSignerJournalProfileV1` still rejects a new-set-only author and `sign_old_set_handoff_exact_v1` rejects the new role. These restrictions cannot be bypassed by reusing a post-certificate token or an old-role admission.

**Cross-epoch ancestry needs a separate verified edge.** `trnm-consensus-core/src/block_tree.rs::edge_coordinates_match` requires a child's view to exceed its parent's view and the justification view to equal that parent view. The first new block instead has a real old-epoch seal-2 parent and a new-epoch view-0 anchor; those views have different epoch contexts. Removing the epoch-zero fence alone still fails this ancestry check. A reviewed handoff edge must bind the unchanged terminal old header to the exact authorized new anchor without relabeling the old header/QC or relaxing ordinary parent, height, view and timestamp checks. `FinalizedTip` currently has no epoch field, and persisted finality/high-QC/lock comparisons also assume one epoch. Safety14, retained ancestry and first-block finality must preserve those contexts and prohibit a three-chain assembled across signing sets; an anchor itself neither certifies nor finalizes a block.

Required `M02-EPOCH` acceptance additions are old-only/new-only/dual-role membership and separate fault bounds; field-by-field proof/configuration/binding substitution; positive view-1 and justified skipped-view proposals; wrong or replayed completion capability without state consumption; interrupted persistence before each seal/new-role signature; schema-13 recovery compatibility and explicit schema-14 phase rejection; old-view/new-view ordering; and two successive epoch transitions. Tests must use the real Core/Store/signer/native producers and consumers. The current `epoch_activation_recovery` regression covers proof recovery and the inert view-1 header capability, not that live matrix.

**Candidate continuous-runtime timer reconstruction (M17 implementation).**
`trnm-poco-lab-validator::GenerationAwarePacemakerV0` binds each private expiry
identity to a checked process-local owner and sequence, not just a counter
which restarts at one. Deadline/generation rejection leaves the existing arm
unchanged. `BoundedConsensusOwnerV1::new` recreates its timer from fresh actual
Core/Safety/signer facts: the larger of failed views after highQC and retained
local timeout decisions, capped at 128 backoff steps. This conservative seed
may overestimate the current streak after earlier successful views; the actual
configured maximum timeout (at most 30 seconds) bounds the wait. A genuine
QC/finality progress event resets it normally; TC-only progress does not.
Old elapsed time and timer JSON are never authority. This is not a durable clock,
full node restart, a new signing capability or live epoch support. The real
four-authority Core/SQLite/signer tests in
`continuous_pacemaker_recovery_tests_v1.rs` replace the timer after successive
TCs and preserve backoff; `pacemaker_recovery_tests_v1.rs` tests stale-owner
expiry, concurrent owner uniqueness and unchanged state at arithmetic/deadline
rejection. Their bounded timer replacement is not physical power-loss evidence.

<a id="m03"></a>
## M03 — Safety / Signer / Checkpoint

**Applicability and inputs.** Frozen v0 Safety/signing contracts plus candidate PCC1 owner convergence. Inputs bind node generation, validator/chain context, exact complete SignIntent, Safety revision, predecessor checkpoint and external anchor. All M03 packages remain individually visible in the ownership inventory; candidate file/Unix adapters are not device-qualified production adapters.

**State/admission algorithm.** Revalidate namespace and owner generation. Check the new decision against durable Safety state and monotonic watermark. Persist the authorized transition and exact complete signing intent before invoking custody. After hardware success or a lost response, resolve the identical intent using authoritative signer readback; record the result before publication. Publish only the same signed bytes through the bounded outbox. Checkpoint compare-and-swap binds its exact predecessor and independent monotonic state. Never create a replacement intent merely because acknowledgement was lost.

**Error and recovery semantics.** Wrong generation, double-sign potential, watermark regression, coherent rollback, conflicting CAS or unsupported platform fences signing. Disk/controller/HSM timeout after a possible effect is uncertain, not failed-with-no-effect. Reopen all authority projections and external anchor; resolve to exact source or exact target, otherwise halt. A local sidecar rolled back with the database is not independent anti-rollback evidence.

**Conformance requirements.** `M03-PERSIST`: crash before/after Safety and intent durability, asserting no early signature. `M03-LOSTACK`: signer applied/response lost produces one logical signature decision. `M03-ROLLBACK`: coherent namespace rollback versus an unchanged external anchor halts. `M03-CAS`: lost acknowledgement, duplicate request and stale predecessor. `M03-CUSTODY`: rotation/revocation, key non-exportability and physical power/controller failure evidence.

**Implementation and consumers.** Trace Safety rules/store, signer journal/service/protocol, watermark/checkpoint types and all adapters into the single M15 owner. `CandidateAuthorityJournalV0` records inert facts under its explicit feature; it does not certify domain operations. Storage-recovery and cryptography specialists must review the boundary separately from the author's process tests.


**Observed old-role signature recovery candidate.** Under the explicit non-default `candidate-handoff-signature-recovery` feature, `SqliteHandoffSignerJournalV1::recover_old_set_handoff_signature_v1` records an already produced old-role handoff signature without invoking a signer. It requires the original exact intent and strict admission, verifies the observed signature before namespace access, locks and audits the complete journal, and accepts only an externally anchored pending intent or the exact already SIGNED tail. For that signed tail alone, the external watermark may be its exact one-event PREPARED predecessor; other lag, forks, missing anchors and unrelated pending intents are rejected. The existing signature/fence/accounting/head transaction and external CAS are reused; exact retry returns the same recorded bytes. Ordinary open, the old-role API's new-role rejection, frozen bytes and production status remain unchanged; the separately named carried-set feature below has its own closed new-role path. Eleven Rust regressions are authored but await the pinned compiler; the separate SQL tests execute production DDL/DML at five process-kill cuts using deliberately non-authoritative shape-only rows. SQL success is not Rust execution, HSM provenance, physical power-loss evidence or whole-node recovery. Host cross-store reconciliation must precede this mutating recovery operation. If authoritative signer readback cannot supply a signature, this API does not retry signing or invent a result.

**Carried-set dual-role journal candidate (not live epoch activation).** The
non-default `candidate-carried-new-set-handoff` feature in
`trnm-consensus-signer-journal` adds
`StrictCarriedNewSetHandoffAdmissionV1::verify`,
`sign_carried_new_set_handoff_exact_v1` and
`recover_carried_new_set_handoff_signature_v1`. It accepts only completely
identical, canonically ordered old/new member IDs, public keys and weights.
The old trust context is independently commissioned. Strict checkpoint/two-seal
verification and the exact committed new context are required before admission;
there is no joint-certificate prerequisite. The old signature over that exact
descriptor must then be present in the real journal and covered by the external
watermark before the new-role operation may prepare or invoke custody.

The journal reuses the unchanged schema1 columns and frozen signing bytes but
admits only one closed suffix: old SIGNED, new PREPARED, new SIGNED. Both new-role
events have their own durable sequence and external CAS. The old terminal fence
remains bound to the old signature; no later ordinary Vote/Timeout or second
handoff is admitted. Reopen audits the entire event chain, exact descriptor,
role-specific admission digest, predecessor, signature and accounting. A default
build still rejects any new-role record. Lost new-signature responses require
actual observed signature bytes and a retained externally anchored intent; that
recovery API has no signer/producer argument. It may reconcile only the exact
signed tail's single-event external lag. Unanchored PREPARED records, other
roles, other authors, changed membership/weights/keys and invalid signatures
remain closed.

The tests in `tests/support/carried_new_handoff.rs` use the existing real-Ed25519
corpus and SQLite journal, including four separate validator journals whose
shares are consumed by the existing `HandoffCertificateV0` verifier and compared
with the frozen certificate bytes. They cover role substitution, lost responses,
external CAS cuts, replay and rejected mutations, but are not execution results
until Cargo runs them. `scripts/ci/test_carried_handoff_reference_v1.mjs` is a
separate standard-library byte/signature reference for the same public test
corpus. In frozen handoff signing, the new role binds `initial_new_view = 1`,
not the later anchor's view 0. This reference does not run Rust or certify an
independent reviewer, HSM or new-key PoP. General new-only membership, key
rotation, real device custody, live seals, Core/Safety phase transitions,
consensus/JMT coordinates and two consecutive epochs remain open.

**Exact-source review trace.** For `M03-PERSIST` under `bft-v0`, inspect `trillionnium/crates/trnm-consensus-signer-journal/src/sqlite.rs` symbol `sign_exact_v0`; the current error definition/literal is `SignerJournalErrorV0` in `trillionnium/crates/trnm-consensus-signer-journal/src/error.rs`. Reproduce `signature_is_persisted_before_return_and_exact_replay_skips_producer` in `trillionnium/crates/trnm-consensus-signer-journal/tests/sqlite_journal.rs`. The journal is not SafetyRules; exact HSM replay and Core/Safety/external-anchor reconciliation require separate acceptance.

**Signer namespace and schema inspection.** Both retained signer-journal schemas
use no-follow metadata inspection when comparing current file/directory entries
with their pinned descriptors. Renaming a pinned object and linking its old name
to the same inode is rejected, not treated as unchanged identity. The read-only
schema classifier explicitly closes SQLite, then repeats database identity,
persisted mode and auxiliary namespace checks while its pins remain alive. Its
private post-close regression seam supplies no public admission bypass. These
checks do not protect unobserved ancestor rename-and-restore, a hostile same-user
process or coherent rollback of the whole namespace and external anchor.

The immutable compiled schema-object map is initialized once per process/schema;
every invocation still reads and compares the current connection's complete
schema inventory. No live-schema acceptance, journal row, watermark or readiness
is cached. Tests inject live schema drift after warming the reference and verify
rejection, plus concurrent reference initialization and post-close substitution.

**Handoff key admission boundary.** The candidate schema-1
`HandoffSignerJournalProfileV1::new` and `StrictOldSetHandoffAdmissionV1::verify`
repeat `validate_validator_set_strict_ed25519_v0` for every member of both sets,
including non-author members. The generic validator-set decoder remains
algorithm-neutral. The real checkpoint corpus is a positive regression control;
weak and undecodable key substitutions exercise the early rejection path in
`trnm-consensus-signer-journal/tests/handoff_key_admission.rs`. Those substituted
sets also alter their commitments, so the tests do not claim the old full proof
would otherwise have accepted them. This is not new-role membership/PoP,
new-role custody, a live epoch transition, or independently accepted signing
qualification. Schema-1 new-set-role and production fences remain unchanged.

<a id="m04"></a>
## M04 — P2P / Session / Dissemination

**Applicability and inputs.** Version-0 consensus payloads remain frozen; authenticated stream/session transport is a separately selected bounded candidate contract, not an invented v0 wire extension. Inputs bind peer identity, negotiated chain/profile/limits, session generation, lease, sequence and exact frame bytes. Production transport operations without an accepted complete transport profile are disabled.

**State/admission algorithm.** Authenticate peer identity and negotiation before admitting payloads. Enforce per-frame and aggregate peer/global byte, item, depth and verification-work limits before decode. Acquire/revalidate the exact generation-bound lease and replay identity. Persist replay admission before forwarding the matching bounded event to the Core owner; preserve uncertain handoff breadcrumbs until authoritative readback resolves them. Acknowledgement cannot outrun the required durable replay/Core boundary. Release only the acquired lease identity. Renewals/rotation cannot let a stale owner clear a successor's reservation.

**Error and recovery semantics.** Authentication/profile/sequence substitution rejects; slow reader, queue-full, connection loss and local CPU pressure are unavailable. Partial write or unconfirmed durable admission is uncertain and retries only the identical request. Never emit deterministic invalidity merely because a local queue is full. Unsupported peer-credential/platform behavior fails closed. Do not advertise candidate process-local replay protection as durable production protection.

**Conformance requirements.** `M04-FRAME`: fragmentation/truncation/trailing data and bounded decode. `M04-LEASE`: replacement, stale release, expiry and same-session retry. `M04-REPLAY`: duplicate/reordered/delayed input across process restart. `M04-DOS`: slow peers, floods and per-peer/global quota contention without Core validity changes. `M04-HANDOFF`: crash at replay admission/Core acknowledgement and verify exactly one durable effect.

**Implementation and consumers.** The registry names `trnm-consensus-peer-lease` and its process replay tests; M15 owns adapter wiring and M02 consumes authenticated events. Exact transport fields/constants and error enum mappings must come from the accepted transport contract and real adapter, not this logical description. Network-security and storage-recovery review are required before calling this independently implementable for production.


**Exact-source review trace.** For `M04-LEASE` under `pcc1`, inspect `trillionnium/crates/trnm-consensus-peer-lease/src/store.rs` symbol `apply`; the current error definition/literal is `PeerLeaseErrorV1` in `trillionnium/crates/trnm-consensus-peer-lease/src/protocol.rs`. Reproduce `journal_restarts_and_fences_stale_generation` in `trillionnium/crates/trnm-consensus-peer-lease/src/store.rs`. Lease authority only; this does not certify a persistent consensus payload transport or full node.

**Candidate continuous mesh availability (M17 implementation).** In
`trnm-poco-lab-validator`, inbound `transport.rs` admission retains error
provenance: remote hello/record rejection and transient socket I/O are
connection-scoped; local configuration, entropy and custody failures stay
terminal, including a local timeout. The mesh creates no lease, generation or
Core input for a rejected handshake. A bounded fixed pause limits immediate
rejection churn without attacker-keyed state. This is not an exemption for
established-session bad frames or a complete flood/peer-isolation policy.

`consensus_runtime.rs::drain_ingress_turn_v1`, called by the actual owner loop,
handles at most 64 events per turn, including no-op/control events; it returns
to timer/proposal work without dropping or reordering unread events. A handler
error still propagates rather than pretending to be progress. This is a local
scheduling bound, not a transaction/block validity rule. The five tests in
`mesh_handshake_isolation_tests_v1.rs` use actual TCP and Ed25519 handshakes to
exercise rejected connections, preserved live streams, local-fault boundaries
and the bounded pump. Payload probes are not business transactions; test leases
are explicitly in-memory. `ingress_fairness_tests_v1.rs` covers always-ready and
no-op ingress, ordering, empty and error cases. Full default-node wiring,
Byzantine multi-host qualification and end-to-end goodput remain open.

<a id="m05"></a>
## M05 — Transaction Admission / Mempool

**Applicability and inputs.** Native transaction lifecycle contracts with explicitly selected v0 or AI-v1 envelopes. Inputs bind canonical transaction bytes/ID, authentication, chain/profile, parent-view version, signer/session generation, nonce lane, fee/resource/access limits, expiry and stable handoff identity.

**State/admission algorithm.** Bound and decode; authorize against the stated view; check replay/nonce, caps, access declaration and fee affordability. Persist one provisional admission/WAL record before returning a durable local acknowledgement. Proposal-time recheck uses the actual authenticated parent, not the prior mempool verdict. Record replacement and handoff atomically under the exact lifecycle identity. A finalized receipt moves the exact transaction into terminal history. Prune/tombstone only when finalized proof and replay-floor authority permit it; expiration alone cannot erase replay protection.

**Error and recovery semantics.** Deterministically malformed input rejects; stale local state can require recheck; overload returns local unavailability. An acknowledged handoff with lost response is uncertain until fresh readback. Reopen distinguishes accepted/reserved, handed-off and terminal records; no automatic rebroadcast that can produce a second effect. Failed admission does not consume canonical application nonce or balance.

**Conformance requirements.** `M05-NONCE`: duplicate/gap/stale generation and overflow. `M05-REPLACE`: concurrent replacement/handoff selects one valid successor. `M05-RESTART`: crash at every WAL/handoff boundary. `M05-GC`: expired or tombstoned entries cannot bypass replay floors. `M05-PARENT`: locally accepted input invalid at the final parent is rechecked without corrupting the batch.

**Implementation and consumers.** Trace `trnm-application-tx-builder-v0`, `trnm-tx-lifecycle-v0` and `trnm-mempool` through M14 submission, M02 proposal selection and M08/M13 finalized readback. Existing lane tests are scheduler regressions, not evidence that production broadcast and GC are fully integrated. Require consumer and application-security review.


**Exact-source review trace.** For `M05-GC` under `bft-v0`, inspect `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs` symbol `collect`; the current error definition/literal is `TxLifecycleErrorV0` in `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs`. Reproduce `full_lifecycle_is_idempotent_and_gc_is_proof_gated` in `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs`. Contract/core fixture, not a production authorization verifier, durable mempool or network lifecycle.

**Durable replay-floor retention after native recovery.** The candidate
`tx-admission-wal` owner in `trnm-poco-node/src/tx_admission_wal.rs` now uses
**local SQLite schema 3**. Schema 2 is rejected before schema repair or WAL-mode
changes; this is not an in-place migration and does not revise protocol bytes.
An old namespace must not be deleted or silently reinitialized to bypass that
boundary. The source/target migration of existing schema-2 stores remains a
separate operation requiring retained state and authenticated replay inputs.

The sealed native floor verifier still authenticates the actual finalized
application nonce prefix and exact canonical signer. Physical tombstone purge
now installs or advances `tx_admission_replay_floor_v1` in **the same
BEGIN IMMEDIATE / WAL-FULL transaction** as deletion. The record binds
namespace, signer, nonce floor, finalized height, root, proof digest, policy and
integrity checksum. Reads decode fixed-width fields without allocating a
peer-sized Rust value. New reservations, including exact retries after reopen,
reject every nonce at or below that stored floor. The old behavior could admit
an already finalized transaction again after all individual tombstones were
deleted; the application still rejected its replay, so this was a local
admission/resource-protection gap, not evidence of double execution or double
spending.

Nonce/height regression, changed same-height root or retention policy, malformed
records and namespace substitution reject. A legitimate alternate certificate
for the same height/root need not have the same proof digest. A floor cannot
resolve or delete a live Reserved/HandedOff obligation. Every floor row counts
toward the existing one-million-row rich+tombstone+floor inventory bound; purge
checks the final transactional inventory, so a full store can exchange one
removed tombstone for its floor without requiring an extra committed slot.

Once floor mutation starts, an error leaves a shared readiness fence on both
the owner and its outstanding reservation tokens. There is no public live reset.
Fresh reopen validates the complete catalog, floor checksums and absence of
active-prefix conflicts before any retry. Process exits after floor insertion,
after deletion and after COMMIT recover either the old tombstone or its floor,
never a deletion without the floor. A checksum is not cryptographic freshness:
coherent rollback or removal of all trusted local state still requires the
separate node/anchor recovery authority. No production activation is changed.

`tx_admission_wal_replay_floor_store_tests_v1.rs` exercises those storage cuts,
monotonicity, alternate proof representation, fixed-width corruption, schema-2
rejection and outstanding-token fencing. Its local sealed-verifier fixture
isolates SQLite behavior and is not cryptographic evidence. The separate
`restored_native_replay_floor_prevents_readmission_after_tombstone_purge_v1`
consumer test replays a real strictly signed finalized block through
`NativeFinalizedCatchupV1`, matches its downloaded native snapshot, consumes the
restored application in the existing Node commit/floor readback APIs, physically
purges, reopens the WAL, and rejects the old signed transaction. This connects
application reconstruction to the Node admission consumer, not to a live
validator, network handshake, Core activation or HSM.

<a id="m06"></a>
## M06 — Execution / MVCC / Meter

**Applicability and inputs.** Native execution is distinct from candidate AI-v1 execution; use the selected runtime/parameter/state schema. Inputs are exact ordered transaction bytes, authenticated immutable parent snapshot, deterministic fee schedule and selected budgets. AI-v1 transactions declare access sets; frozen-v0 native runtime attempts record actual authenticated reads without introducing an AI-v1 envelope or fee profile.

**State/admission algorithm.** Validate context and parent root before execution. Execute into transaction-local tentative deltas; where the selected profile declares access sets, those declarations bound actual accesses. Detect stale versions and conflicts deterministically, re-executing in the prescribed canonical order/wave plan. Discard every delta of a failed transaction before any external apply. Charge the exact selected meter and checked aggregate limits. Seal only a complete verified write/receipt/event plan. M07/M08 alone establish canonical durable commit. Thread timing and worker count never choose fees, roots, order or errors.

**Error and recovery semantics.** Invalid access, stale version under the selected rule, budget/fee overflow or deterministic execution error rejects with the prescribed atomic effect. Disposable native worker failure falls back to the canonical runtime; it does not choose an earlier transaction error or authorize partial writes. Speculative overlays may be discarded/recomputed from exact bytes and parent. A committed row cannot be inferred from a successful preview.

**Conformance requirements.** `M06-WORKERS`: identical root, writes, receipt/event/fee bytes at 1/2/4/8 workers. `M06-HOT`: many transactions sharing one sponsor/object and independent disjoint transactions. `M06-ATOMIC`: error in the last write leaves all earlier tentative writes unpublished. `M06-REEXEC`: conflict/abort storms terminate within qualified bounds. `M06-METER`: exact cap, cap+1, arithmetic overflow and failed-work accounting.

**Implementation and consumers.** Trace native application/runtime/execution and executor packages separately from `trnm-poco-mvcc-fee-v1` and global execution candidates. Use an independent serial oracle and persistent replay comparisons; merely calling the same parallel implementation at different worker counts is insufficient. M07/M08/M12 consume sealed effects; execution and storage-recovery review are required.


**Implemented candidate worker boundary.** In `trillionnium/crates/trnm-poco-mvcc-fee-v1/src/engine.rs`, `execute_block_with_workers` accepts the validated candidate genesis/profile, immutable parent object map, gap-free ordered block and a bounded worker count (1–64; at most 256 transactions). `parallel_speculative_transactions_v1` runs the complete bounded Add/Transfer/Revert computation: resource usage, fee arithmetic, tentative payer/application successors and transaction-local read/write/delta roots. Workers return private `TransactionComputationV1` values or retained errors; neither is a canonical receipt or a durable capability. Every actual access must match the declared, sorted access set.

The canonical loop compares each observed object version **and** value hash against the state produced by earlier transactions. An unchanged dependency set reuses the completed computation; a changed set causes one deterministic re-execution against that canonical state. A failure on the parent snapshot is not rejected prematurely: an earlier transaction can fund a later payer or transfer source. Conversely, a speculative success is discarded when the canonical payer has been exhausted. Pending fee reduction and the complete intermediate state root are assembled only in canonical order; the returned block result contains the final object map and complete receipts/resource/fee/resolution roots. Reverted and OutOfResource receipts retain the selected fee semantics and publish no application writes. A block-level error publishes neither its earlier tentative writes nor its fees to the persistent store.

**Sequential replay boundary.** `engine.rs::execute_block` is a separate sequential scheduler used by the existing durable journal audit; it does not call the worker scheduler. It shares transaction semantics and root codecs with the parallel path. Differential comparison therefore tests scheduling, conflict resolution and publication equivalence, not an independently implemented protocol oracle. `store.rs` still audits the complete journal from genesis and validates exact stored receipts before trusted readback. No audit cache, new checkpoint authority or committed-history pruning is enabled by this change.

**Native frozen-v0 worker boundary.** `trnm-native-execution-v0/src/complete.rs::compute_complete_native_block_v0` now calls the private `native_parallel.rs` scheduler for canonical runtime payloads. After the existing parent, chain, genesis, signer-policy, validator/lifecycle and body-size checks, each batch borrows the immutable authenticated store plus the canonical overlay at that batch's start. Workers validate exact outer envelopes and runtime context provisionally, then call the real `trnm_runtime::try_execute_v0`, producing gas, frozen-v0 fees, events, mutations or a retained typed failure. They neither stage writes nor mint a durable execution artifact. The canonical loop decodes the original envelope and always performs signer-policy and replay admission at the original transaction index. A private, one-use `VerifiedOuterEnvelopeV0` may reuse only a successful strict envelope verification for identical raw bytes, chain ID and timestamp. It is retained only after the worker actually verifies that envelope and is consumed even on mismatch; it supplies no signer-policy, nonce, execution or publication authority. Missing, oversized, failed-allocation or mismatched cache input follows the original strict verifier. Malformed later input or a faster later runtime failure cannot mask an earlier error.

`RecordingViewV0` records every `TryStateViewV0::try_get`, including an absent object. Before reusing an outcome, the owner compares every dependency's full `Option<StateObject>`: absence, object type, version and exact value bytes. Except for the proven transfer fee case below, any changed dependency or failed comparison read causes one execution against the current canonical overlay. This applies to errors as well as successes: prior credit or nonce advancement can repair a parent failure, while a fee-policy update can invalidate a parent success. Runtime mutation validation/staging remains the existing atomic `stage_runtime_mutations_v0`. PoCO and validator-transition operations stay serial and clear queued speculation at their ordered barrier; lifecycle/system writes, receipt order and the final JMT plan retain their original owner and codecs.

**Proven transfer fee exception.** `TransferFeeDeltaV0` is private metadata derived only from a successful real runtime attempt for `CanonicalCommandV1::Transfer`, with both sender and recipient different from the reserved fee collector. The frozen runtime's transfer command then touches the collector only through the mandatory fee credit; its resource estimate, sender/recipient updates and events cannot depend on the collector balance. Construction verifies the recorded collector's type/account identity and the receipt's **unique** collector mutation: exact expected version, checked successor version, unchanged nonce, canonical account encoding and balance equal to the observed balance plus `receipt.fee_charged`. An absent collector is the existing runtime default `(balance=0, nonce=0, version=None)`.

For this sealed case only, `into_reusable_outcome_v0` retains and authenticates the collector dependency while requiring every other read to match exactly. A changed collector must still have the correct type/account identity, the same nonce, a strictly advanced version and a nondecreasing balance. The canonical owner replaces only that mutation's expected/successor versions and value with `current_balance.checked_add(fee_charged)` and `current_version.checked_add(1)`, then uses the unchanged mutation staging validator. Read failure, type/identity/nonce drift, equal/regressed version, balance regression, overflow, or a failed speculative runtime outcome causes complete canonical execution; this helper never manufactures a runtime rejection. Any noneligible canonical transaction that writes the collector clears pending speculation as a barrier, including explicit transfers to it and operator credit/distribution. Thus no collector read is silently omitted, no fee is charged twice, and the exception imports neither a new fee profile nor a wire contract.

| Native scheduling bound | Value and fallback |
|---|---|
| Active workers | Available host parallelism capped at 8; private 1/2/4/8 controls are used by regression tests. |
| Retained jobs | At most 32 transactions per batch, under the existing complete-body transaction/byte admission limits. All started workers are joined before canonical application. |
| Recorded dependencies | At most 64 distinct keys and 256 KiB of retained key/type/value bytes per attempt. Crossing either limit disables reuse and releases the recorded map; authenticated reads retain their original result. |
| Retained outcome payload | At most 256 KiB of mutation and event string/value bytes per attempt. Larger results are discarded for canonical execution. These are scheduling caps, not new transaction-validity rules. |
| Verified outer envelope | At most 64 KiB of exact bytes per retained attempt (at most 2 MiB per 32-job batch, plus bounded context). The cache is private, not serializable or cloneable, and carries no authority. Exceeding the limit disables cryptographic reuse only; the transaction still uses ordinary admission. |
| Single logical worker | The candidate scheduler computes its disposable outcomes on the caller thread instead of spawning an OS thread. An unwinding panic discards the entire worker result, including any successful prefix; missing work uses the existing canonical fallback. This does not add a long-lived pool, change protocol validity, or establish a measured speedup. |
| Thread creation/join failure | The affected chunk has no reusable outcomes and executes in canonical order. A speculative worker failure cannot produce a successful artifact or choose a transaction-invalid code. |

The bounds cover retained speculative data; each active worker still pays the existing runtime's transient decoding/execution cost. The internal zero-worker test mode bypasses speculation entirely and executes each runtime attempt on the canonical state. Comparing it with 1/2/4/8 workers covers scheduling equivalence and exact complete roots/receipts/writes, not an independent semantic implementation. Separate test-only counters record exact reuse, fee rebasing and full canonical execution: eight independent fee-paying transfers must consume all eight worker results (one exact reuse, seven fee rebases, zero runtime re-executions), for both an absent and an existing collector. Other command families remain subject to exact collector conflicts/barriers. This removes a specific forced runtime retry for ordinary transfers; it is not a measured end-to-end throughput gain. The exact-byte cache avoids a second successful envelope verification when present; canonical signer-policy/replay checks and canonical staging/root construction/commit remain. Test-only counters distinguish envelope reuse from ordered strict-verifier calls. The Rust regressions must be compiled and executed on the reviewed source before this optimization is accepted; source presence is not a measured throughput result.

**Bounded native work distribution.** The private runtime scheduler reserves one
initial transaction per started worker and dynamically assigns the remaining
indices from a bounded queue. Results retain their original transaction index;
all started workers are joined before the canonical owner checks dependencies,
replay, signer policy, fees and staged mutations in the unchanged order. Failed
thread creation leaves its reserved work for canonical execution. A panicking
worker loses its retained outcomes; missing work uses the ordinary canonical
fallback, never a fabricated runtime error. The existing 8-worker/32-job and
retained-data caps are unchanged. Scheduler regressions cover exact-once index
assignment, slow-first-job progress, panic cleanup and oversize/zero-worker
fallback. This removes static-chunk idle time, not the final ordered barrier or
a measured end-to-end throughput limit.

**Immutable finalized snapshot pin (M13).**
`DurableNativeApplicationV0::pin_finalized_snapshot_export_v1` consumes an exact
owner-bound finalized export, rechecks its original head/sequence/manifest once,
and retains the authenticated snapshot in private owned bytes.
`PinnedNativeSnapshotExportV1::chunk` then returns bounded immutable slices with
no per-chunk database read or historical re-audit. The retained-image cap is
explicit and at most 512 MiB; it does not bound pre-existing transient audit
allocations or the consumer's decoded JMT. The original current-head export API
still rejects source movement. The pinned API is deliberately historical: once
captured, its exact bytes remain valid if the source advances or closes, without
claiming freshness of the newest head. Consumers still verify their independently
trusted finality/manifest. Tests cover valid source advancement, closure, wrong
owner, stale pre-pin source, bounds and concurrent exact reads. This reduces
repeated export work, not full-state storage or end-to-end finalized latency.

**Native durable inventory boundary (M07/M08 consumers).** In `trillionnium/crates/trnm-native-execution-v0/src/durable.rs`, `map_p_inventory_v0` loads one complete durable P row at a time. `ValidatedPInventoryEntryV0::from_durable_v0` still verifies its artifact, snapshot, replay sets and lifecycle before retaining compact identity/height/sequence/root/commit links. `validate_p_inventory_v0` verifies the complete committed chain and prepared ancestry using those entries. Parent persist sequences must be strictly smaller; their fixed-width big-endian encoding preserves SQL ordering. `commit_block` passes the same validated inventory to `prepared_blocks_not_descending_from_v0`, which resolves prepared descendants in one pass and removes only conflicting prepared forks. It does not reread unaudited SQL links between validation and pruning. The key-only `ORDER BY p_sequence` cursor stays live while each complete row is read with a reused prepared point-lookup statement. This removes the temporary Rust collection of all IDs and repeated SQL preparation, not the N row lookups or full-history scan. It deliberately does not sort complete snapshot BLOBs in an unindexed SQL query. Consumers must neither write through that connection during iteration nor publish partial results. The normal-connection SQLite cursor test checks consistent read snapshots; the native immutable-read owner still relies on its existing namespace/lock/integrity contract and does not gain production WAL support. Full-history validation, complete JMT snapshot encoding/writes and serial commit remain present.

**Typed native failure boundary.** `complete.rs::CompleteNativeExecutionFailureV0` preserves runtime classification through the internal `anyhow` carrier; `durable.rs::complete_execution_failure_result_v0` consumes that private type, not display strings. Authenticated state-read failure returns `Unavailable(AuthenticatedStateUnavailable)` without a prepared row. A classified transaction rejection retains its deterministic runtime code. Runtime `InvariantFault`, explicit `Invariant` from mutation staging/PoCO application/validator-transition invariants, and an unclassified runtime attempt return a `CorruptStore` error rather than transaction invalidity or retryable success. The existing non-runtime body/schema rejection branches retain their existing frozen-v0 rejection handling; this seam does not claim that every generic helper error has a complete independent taxonomy.

**Focused source regressions.** Reproduce the following on the exact reviewed source and selected feature closure; test presence is not an execution result:

| Surface | Existing test symbols and property |
|---|---|
| `trnm-poco-mvcc-fee-v1/src/parallel_execution_tests.rs` | `workers_compute_program_meter_fees_and_successors_on_immutable_parent`: actual completed computations on eight worker threads, immutable parent and 1/2/4/8-worker complete-result equivalence. |
| Same candidate tests | `hotspot_revert_and_resource_exhaustion_match_sequential_journal_oracle`; `speculative_insufficient_funds_is_retried_after_predecessor_funds_payer_or_source`; `stale_speculative_success_cannot_publish_when_canonical_payer_is_exhausted`; `multiple_speculative_failures_report_the_canonical_transaction_error`: shared sponsor, failed-work fees, stale failure/success, atomic rejection, reopen/replay and canonical error selection. |
| `trnm-native-execution-v0/src/native_parallel_tests.rs` | `native_workers_compute_real_runtime_receipts_and_mutations_on_eight_threads`: real runtime receipts/mutations from eight distinct worker threads; 1/2/4/8-worker versus sequential complete roots, receipts, writes, replay identities and lifecycle; immutable source and applied snapshot reopen. |
| Same native parallel tests | `native_parent_failure_is_reexecuted_after_credit_and_nonce_predecessors`; `native_policy_change_invalidates_speculation_without_changing_fee_semantics`; `native_speculative_success_cannot_bypass_canonical_policy_rejection_or_publish_partial_writes`: a 41-transaction dependency chain crossing batch boundaries, fee-policy conflicts, typed rejection and no partial source mutation. |
| Same native parallel tests | `native_validator_transition_is_an_ordered_barrier_with_identical_system_writes`; `native_outer_and_runtime_failures_are_selected_in_canonical_transaction_order`: mixed internal/runtime body with exact system writes, malformed input, nonce rejection and duplicate replay error order. |
| `trnm-native-execution-v0/src/native_parallel_dependency_tests.rs` | `native_dependencies_include_absence_and_full_value_and_type_at_unchanged_version`; `native_unavailable_speculation_is_never_reused_as_absence_or_cached_failure`; `native_speculation_read_limits_disable_reuse_without_fabricating_state_errors`: full dependency matching, unavailable-read retry and scheduling-bound fallback. |
| Same dependency tests | `native_fee_rebase_rejects_collector_type_nonce_identity_and_version_drift`: the actual reuse gate refuses collector type/nonce/identity changes, unchanged version with changed value, balance regression and unavailable reads. |
| `trnm-native-execution-v0/src/native_parallel_fee_oracle_tests.rs` | `independent_fee_paying_transfers_reuse_every_runtime_attempt_with_exact_serial_outputs`; `collector_overflow_falls_back_to_the_same_canonical_error_without_publishing_a_prefix`; `explicit_collector_transfer_and_operator_credit_are_ordered_barriers`: independently authored scheduling differential, explicit 1/7/0 reuse counters, exact applied collector sum/version, checked balance/version exhaustion, source immutability and explicit collector barriers. |
| `trnm-native-execution-v0/src/durable.rs` | `inventory_prunes_interleaved_fork_descendants_after_restart`: interleaved legal forks, restart, exact descendant preservation and reuse of the validated inventory despite a later SQLite writer changing row order. |
| Same native durable tests | `inventory_still_audits_corrupt_committed_history_below_healthy_head`: historical artifact, snapshot, replay and lifecycle corruption remains rejected with a healthy latest head. |
| Same native durable tests | `runtime_failure_classification_preserves_unavailable_and_invariant_faults`; `complete_runtime_nonce_rejection_keeps_typed_code_and_no_prepared_row`: typed unavailable/invariant/reject dispositions and no P row for the rejected execution. |

**Still open.** Native runtime speculation is implemented within the existing complete-body path; it does not establish complete production-node wiring or activation. Collector conflicts outside the proven transfer case, verification outside the narrow exact-byte reuse case, serial staging/root construction/commit and full-history storage remain performance constraints. Independent golden vectors and a separately implemented serial oracle, large-state/long-history cost curves, hostile hotspot/re-execution campaigns, end-to-end committed goodput and finality tails, authenticated checkpoint/anchor-based bounded recovery, source-bound specialist acceptance and production activation remain separate requirements. No worker count, local test or inventory memory reduction closes these gates.


**Exact-source review trace.** For `M06-ATOMIC` under `pcc1`, inspect `trillionnium/crates/trnm-native-execution-v0/src/lib.rs` symbol `stage_runtime_mutations_v0`; the current error definition/literal is `duplicate runtime mutation key` in `trillionnium/crates/trnm-native-execution-v0/src/lib.rs`. Reproduce `later_duplicate_rejects_the_entire_transaction` in `trillionnium/crates/trnm-native-execution-v0/src/overlay_delta_tests.rs`. The current anyhow diagnostic is a local error literal, not a newly frozen external wire code; this case does not prove every worker-count path.

**Native checkpoint authorization trace.** In `trnm-native-execution-v0`, `poco_checkpoint`, `poco_authenticated_candidate`, `poco_epoch_commitment`, `poco_checkpoint_header`, `poco_joint_handoff` and `poco_preparation_journal` form the application-side authorization chain. `prepare_native_poco_checkpoint_v0` joins the committed cutoff JMT/lifecycle, strict H1/H2 and candidate reconstruction to actual native execution and durable exact-header preparation; `confirm_poco_checkpoint_v0` requires the exact COMMITTED P, fresh sidecar reservation readback and strict checkpoint/two-seal/handoff evidence. Four native database regressions exercise the complete chain, reopen and held-token invalidation; 20 journal regressions cover exact post-commit publication, fault injection and local admission caps. See the [native execution README](../../trillionnium/crates/trnm-native-execution-v0/README.md#native-checkpoint-authorization) for API provenance, 64-transition/1,024-preparation/256-MiB audit limits, the 512-MiB database page ceiling and sidecar checks, local `StorageFull`, and the external rollback boundary. These local tests do not advance Core's epoch fence, establish seal-height JMT progression or constitute independent production acceptance.

**Pre-certificate checkpoint readback candidate.** M01's `decode_verify_checkpoint_finality_strict_v0` bounds and decodes the exact checkpoint/two-seal bytes, checks the supplied old/new configuration and exact checkpoint/parent, and uses only strict Ed25519 verification. M06's `confirm_poco_checkpoint_for_handoff_v0` rejects bad proofs before the full native-history read, then reuses the existing fresh committed-row, preparation-owner, cutoff and next-set checks. No PREPARED row is promoted, no seal application is executed, and no joint handoff certificate is an input. The returned receipt derives only the existing frozen handoff descriptor; old/new role-specific admission, persist-before-sign, custody, live seals, Safety14 and multi-epoch JMT progression remain open. The later completion operation repeats fresh storage validation and the full joint-certificate check rather than trusting a held receipt.

The CEV0 certified-header admission budget now charges its proposer signature as well as all justify/certifying QC and optional TC signatures. Each complete three-header proof therefore includes three proposer work units; the existing maximum already reserves them and is unchanged. Admission reserves aggregate work atomically; later signature/binding failure does not refund it. The new native method's supplied budget covers the checkpoint-proof pass only, not a claim that every existing cutoff/native provenance verification is accounted by the same budget. Six strict-crypto and six native regression functions are implementation tests to execute, not recorded passes. The separate Node direct-view frozen-corpus test can compare actual Ed25519 calls to certificate-share counts, but it does not exercise Rust, skipped-view TC paths, native storage or live epoch activation.

**Frozen operation semantic replay.** The existing `operation_sequence_profile_boundary_tests.rs` now invokes the actual private PoCO transition kernel on the unchanged historical corpus: nine named sequences, 18 positive steps and nine typed rejections. Frozen operation IDs/counts/roots, complete namespace writes, mutation roots, manifests/projections and historical JMT roots are checked directly; rejection leaves both the overlay and encoded snapshot unchanged. The four isolated prune sequences remain explicitly isolated. Test-supplied historical context does not pass current-owner policy admission, authenticate outer signatures or supply durable P/ProcessProposal/FinalizeBlock/restart evidence. The retained `frozen_old_operation_profile_cannot_obtain_current_native_authority` regression still requires rejection by the current native owner; full durable corpus admission remains open.

<a id="m07"></a>
## M07 — State / JMT / Storage

**Applicability and inputs.** Native JMT/SQLite state and AI-v1 state-tree contracts are separate profiles; do not equate roots by type name. Inputs include the accepted write plan, parent root/version, chain/store/role/generation, closed-world schema/pragma profile and retention/proof horizons.

**State/admission algorithm.** Open only through the reviewed descriptor-bound namespace capability. Distinguish fresh creation, read-only and read-write modes; verify database and WAL/SHM/journal/lock/anchor identities before and after authoritative operations and after close. Apply a complete plan atomically, recompute its selected root and retain exact receipts/history. Return trusted state only after required durable completion and namespace/schema revalidation. Generate membership/non-membership proofs only under an authenticated committed root. Pruning respects all proof, replay, challenge and retention holds.

**Error and recovery semantics.** Metadata-only/state-only residue, wrong schema, replaced file/sidecar, stale generation and third-state recovery fence the store. An fsync/controller failure is uncertain when writes may have happened; reopen and compare exact durable identity/root/sequence. Never treat a failed read as key absence or a prepared overlay as committed state. Coherent rollback requires an independent anchor check beyond local SQLite integrity.

**Conformance requirements.** `M07-NAMESPACE`: path/link/directory/mount/sidecar replacement. `M07-SCHEMA`: extra/missing table, index, trigger or incompatible pragma. `M07-ROOT`: same state bytes yield the exact selected tree root and proof. `M07-PRUNE`: prune/restart/restore preserves every required proof/replay horizon. `M07-DURABLE`: short write, disk-full and real controller/power interruption recover to exact source or target only.

**Implementation and consumers.** Trace `trnm-state`, `trnm-native-application-sqlite`, native execution's durable store and the separate order-state candidate into M08 and M13. The v1 reference proof has exactly 256 sibling hashes under its own state-tree specification; do not substitute native JMT proof bytes. Require storage-recovery, execution and client-proof review.

**Native snapshot recovery boundary.** `trnm-native-execution-v0/src/store.rs` checks each retained root against its indexed JMT root node rather than merely testing historical root-node presence. Historical root/hash substitution must reject even when the latest head still verifies. The shared live-value verifier retains duplicate-key detection and latest-root membership/preimage checks while letting recovery discard each proven value instead of collecting another full live map. Explicit live-map consumers retain their existing results. The snapshot codec and retained history are unchanged. These checks do not recursively prove every historical leaf, implement incremental persistence/GC or supply an external rollback anchor; M06/M08 consumers and independent storage acceptance remain required.


**Authenticated point consumers.** After the complete durable snapshot has passed
its existing root, preimage and live-value audit, lifecycle extraction proves
only the exact validator-lifecycle key instead of rebuilding and proving the
entire live-value map a second time. The point reader verifies membership or
non-membership under the requested retained root, checks present preimages, and
rejects corrupt values or unknown versions. This is not partial snapshot
validation, authenticated pruning, incremental persistence or bounded-history
recovery.

`prove_raw_key_v0` verifies the generated ICS23 membership/non-membership proof
against the exact requested root before exporting bytes. Comparing a root with
itself is not validation. Regression inputs substitute a retained root and a
historical value below a healthy latest head; both reject before publication.
The proof codec and hash domains are unchanged. Proof consumers still verify
against their independently trusted root; producer checks do not bootstrap trust.

**Exact-source review trace.** For `M07-SCHEMA` under `bft-v0`, inspect `trillionnium/crates/trnm-native-application-sqlite/src/store.rs` symbol `open`; the current error definition/literal is `ValidationStoreErrorCodeV0` in `trillionnium/crates/trnm-native-application-sqlite/src/error.rs`. Reproduce `schema_or_trigger_drift_is_rejected_on_reopen` in `trillionnium/crates/trnm-native-application-sqlite/src/tests.rs`. Local proposal-validation store/schema regression, not whole-node power-loss or coherent-rollback acceptance.

### Native finalized snapshot read/export

Primary implementation owner: M06; consumers M07/M08/M13. This is an additive
read boundary over the unchanged native Borsh/JMT and native manifest domains,
not the generic M13 `TRNMSM01` storage format and not an installation capability.

`DurableNativeApplicationV0::begin_finalized_snapshot_export_v1` first verifies
actual strict PoCO finality for an already COMMITTED application row. It then
freshly audits the native source and binds the exact current head, durable
sequence, store identity and SHA-256 snapshot digest to a private owner-affined
`NativeSnapshotExportV1`. Historical targets and PREPARED rows cannot export.
The manifest producer checks its 4,096-descriptor bound before allocating the
array. `read_snapshot_chunk_v1` accepts that original live owner's token and one
index, freshly validates source identity/head/sequence/snapshot again, and
returns only the exact indexed bytes under the existing native chunk domain.
Reopen, another owner or intervening source movement invalidates the token; the
caller must re-prove/export the current target rather than mixing generations.

`verify_native_snapshot_stream_v1` consumes an independently trusted
`StrictFinalityProofV0`, the local immutable native configuration, exact native
manifest, fallible chunk iterator and local read limits. Manifest metadata never
chooses the trust anchor or validator set. The oldest certified header must
match chain, genesis, profile, epoch, validator/parameter commitments and exact
height/block/root before input is read. Each chunk must match its indexed
length/digest; one look-ahead item detects extra input. Short, reordered,
corrupt or over-budget input cannot yield a result. Original transport errors
are retained separately from local resource exhaustion and invalid snapshots.
These are local read dispositions, not transaction-invalidity codes.

The reader parses the actual native Borsh snapshot field order: node map,
versioned values, preimages, stale-node set and retained roots. It limits
aggregate entries before insertion, checks sorted unique keys, validates length
prefixes before application-value allocation and compares each re-encoded entry
to its exact input. JMT NodeKey nibble lengths/padding are validated in at most
52 stack bytes before the dependency's derived decoder can bypass constructor
invariants. Shared validation in both the original slice decoder and this reader
checks node path/type/count/version invariants, actual child references/hashes,
leaf counts and retained leaf/value hashes at the leaf's own version. It then
runs the existing retained-root, preimage and latest live-value proof audit.
These internal historical checks do not independently finalize old roots.

Before returning, the latest actual JMT version/root and authenticated validator
lifecycle must match the strict target, chain, local signer policy and active
validator projection. The native snapshot manifest digest is recomputed from
the exact streamed SHA-256 and native chunk digests. The private non-Clone
`VerifiedNativeSnapshotReadV1` exposes height/block/root/snapshot/proof digests
and byte count, but deliberately not the local manifest commit ID: that ID is
not independently authenticated by consensus. Decoded replay sets are empty,
the temporary store is discarded, and no Core, signer, install or replay-floor
authority is issued.

Local limits are positive byte/entry/record budgets, with hard admission caps
of 4 GiB encoded bytes, 2,000,000 aggregate entries and 16 MiB encoded record
size; operators must choose budgets appropriate for their actual memory. Only
one transport chunk and one record copy are retained in addition to the decoded
JMT collections. A transport must bound allocations/deadlines before yielding
chunks. The complete decoded JMT remains resident, every source chunk request
still audits full native history/snapshot, and historical roots remain retained.
This is not native incremental persistence, bounded-history recovery, pruning,
a network downloader or an end-to-end throughput improvement.

`pcc1_finality/snapshot_stream_tests.rs` uses actual SQLite native execution and
strict Ed25519 finality to test export/read, owner replacement, PREPARED refusal,
root substitution, corruption, short/extra streams, typed transport errors and
pre-read resource limits. `snapshot_reader_v1.rs` covers bounded/noncanonical
Borsh and malformed JMT metadata, including corruption below a healthy latest
root. Source-bound execution logs are separate from these required properties;
independent acceptance and whole-node state-sync installation remain open.

<a id="m08"></a>
## M08 — Finality / Commit / Recovery

**Applicability and inputs.** `bft-v0` supplies finality meaning; PCC1 supplies candidate composition and publication ordering. The old `Prepared` through `OutboundPublished` journal vocabulary is an inert integration observation, not the lifecycle for publishing both votes and finality receipts.

**State/admission algorithm.** Signing uses `Validated -> IntentDurable -> SignatureRecorded -> VotePublished` and does not wait for the block's finality. Finalized application publication separately uses `FinalityVerified -> CommitIntentDurable -> ApplicationApplied -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished`. Verify complete three-chain bytes against the application's commissioned context and expected oldest target. Confirm exact ancestry/order and prepared application binding. Persist commit intent, apply the exact idempotent plan, record the ledger result, confirm checkpoint predecessor/CAS, then expose the final receipt. No ordinary QC or local stage label supplies finality.

**Error and recovery semantics.** Reject invalid class/proof/target/root/budget before modifying application or ledger. For any uncertain durable completion, reopen and read the named authority, then compare exact source/target records. Duplicate replay may return the same receipt but cannot create a second logical commit. Missing or conflicting intermediate facts halt publication. A read operation does not promote prepared state even when handed a valid proof.

**Conformance requirements.** `M08-SEPARATE`: vote publication is possible before local block finality; receipt publication is not. `M08-OLDEST`: only the oldest header of the certified three-chain commits. `M08-PREPARED`: valid proof cannot turn a read into a commit. `M08-CUT`: crash/lost acknowledgement at every application/ledger/checkpoint/receipt boundary. `M08-BUDGET`: all required cryptographic passes are charged before commit.

**Implementation and consumers.** The real strict seam is `trnm-native-execution-v0/src/pcc1_finality.rs`; recovery/ledger targets include `trnm-core-restart-v0` and the separately profiled order-application candidate. M02/M03 produce authority; M07/M13/M14 consume committed facts. Existing strict commit/read tests do not establish full Core, ancestry, checkpoint or receipt-publisher integration. Require consensus and storage-recovery specialists.


**Exact-source review trace.** For `M08-PREPARED` under `pcc1`, inspect `trillionnium/crates/trnm-native-execution-v0/src/pcc1_finality.rs` symbol `read_poco_finalized_bytes_v0`; the current error definition/literal is `PocoFinalityCommitErrorV0` in `trillionnium/crates/trnm-native-execution-v0/src/pcc1_finality.rs`. Reproduce `readback_never_promotes_prepared_state_even_with_a_valid_proof` in `trillionnium/crates/trnm-native-execution-v0/src/pcc1_finality/tests.rs`. Readback boundary only; it does not drive checkpoint or receipt publication.

### Pre-certificate checkpoint commit

`commit_poco_checkpoint_for_handoff_v1` joins the existing native preparation
and exact executed P to actual old-set checkpoint/two-seal finality before
calling the existing atomic application commit. It needs no joint handoff
certificate and creates no seal application rows. The independently commissioned
old configuration must equal the preparation context. One bounded strict
Ed25519 proof pass verifies the exact prepared header/parent/commitment and all
required shares before storage commit; header/body/receipt equality, the original
preparation namespace and a freshly authenticated exact durable execution row
must also pass. An exact already-COMMITTED replay is allowed only through the
existing current-head/idempotency checks, never by inventing a row or artifact.

After commit, fresh native/preparation readback reconstructs cutoff/next-set
provenance and the exact committed receipt. Only then does the operation return
`CommittedNativePocoCheckpointForHandoffV0` to the later, separately authorized
role-signing path. The immutable strict proof is retained across that operation;
there is no late second proof pass whose work budget could fail after commit.
Existing native/cutoff audits retain their separate bounds. No signature,
checkpoint CAS, publication or epoch activation is performed by this method.

`NativeCheckpointCommitErrorV1::BeforeCommit` means the native commit call was
not reached. It is a local preflight result, not a consensus transaction error.
Every error at or after commit is `Uncertain`; callers must fence dependent
participation and perform fresh readback or retry the identical checkpoint.
Reconstruction uses the original preview request and raw cutoff evidence, not a
new request based on an advanced head. Post-commit sidecar failure cannot be
reported as "nothing happened". This does not establish atomicity between the
native database and preparation journal or independent rollback resistance.

The real SQLite/Ed25519 tests in
`poco_checkpoint/native_authorization_tests/checkpoint_commit_tests_v1.rs` cover
strict commit before handoff, unchanged application state on invalid signatures,
byte/work limits, substituted execution, missing/halted/replaced/foreign
preparation, and database/directory synchronization failures after commit.
Reopen and repeated exact commit must recover one sequence and one application
effect; neither seal height may acquire a dummy application row. This closes
this bounded commit-producer gap, not live seal voting, Safety14, new-epoch
ancestry, consensus/JMT coordinate progression or two continuous epochs.

**Proof-driven ordinary catch-up (M06/M07/M13 consumer).**
`trnm-native-execution-v0/src/finalized_catchup_v1.rs` implements
`NativeFinalizedCatchupV1` with an exclusively held real
`DurableNativeApplicationV0`. `recover` binds an independently strict-verified
target to the commissioned genesis/set/parameters and the locally audited head.
Epoch zero, regular blocks and exact consecutive heights are the only supported
profile here; seal execution, imported h1 bases, epoch changes and signer/Core
activation are not inferred. A non-genesis restart requires a strict proof of
the actual local head, derives its parent timestamp from the durable preceding
execution (or explicit genesis time), and re-establishes exact commit durability.

`apply` charges attempted bytes (including rejected work), bounds the CEV0 list
count before nested allocation, and validates context, height, parent, parent
view, exact payload root and strict three-chain proof. The existing commit
verifier's second signature-work pass is reserved before persistence. New-input
context, canonical-body and cryptographic admission precede the existing
potentially full-history storage audit. The cached predecessor is only a proof
expectation; fresh durable equality still precedes preview or mutation, and
observed source loss fences the session. Read-only
native preview must reproduce all header commitments before durable execution
is called. Execution reconstructs command IDs and nonce sets through the existing
runtime; a peer supplies neither these sets nor a local application commit ID.
The existing durable-P and finality-commit owners then execute and commit the
exact artifact, with fresh committed artifact/head readback before success.
Invalid proofs/bytes, gaps and preflight mismatches create no prepared row.
Once a mutating API is called, any failed or uncertain result fences the session;
reopen and prove the actual source/target rather than guessing rollback. An exact
current-block retry resynchronizes and reads back the existing commit without a
new logical effect. Other historical duplicates are not a replay shortcut.

`finish_with_snapshot` first requires the exact target. It consumes the existing
native streaming verifier and compares the downloaded full JMT image digest with
the freshly audited, locally re-executed image. The native snapshot codec does
**not** encode the separately stored command/nonce replay sets. Those sets are
reconstructed by real execution, not authenticated by pretending the latest JMT
root covers transport metadata. No peer bytes overwrite the local database.
Only after these checks does `RestoredNativeApplicationV1::into_application`
release the actual application owner, usable for the next regular execution.
This is a bounded-session catch-up/restore path, not Core, network listener,
signer, whole-node anti-rollback or constant-history recovery qualification.

Local limits are 1..4096 target blocks, at most 16 GiB attempted input per
session, at most 65,536 declared transactions per block and the existing 4 MiB
payload ceiling. They are configurable local ceilings, not altered consensus
validity. Repeated sessions still require node-level admission quotas. Exact
full-image equality intentionally rejects differently pruned histories even
when they have the same latest root. Full-history audit, complete snapshots and
serial commits remain; this path is not the planned incremental/checkpoint
shortcut. A valid committed prefix survives later rejected input, while the
unfinished session exposes no application-owner completion.

`finalized_catchup_v1/tests.rs` exercises real strict Ed25519 proofs, native
speculative parents, SQLite execution/commits, empty blocks, a second local store
identity, nonce-floor readback, malformed/fully signed wrong-state claims,
pre-persistence verification budgets, repeated synchronization faults, and real
process exits after prepared P and after committed application state. Keys and
certificate generation are controlled fixtures, not live consensus or a
multi-host campaign. The restored real owner also executes and strictly commits
the next regular block. Test results must bind the reviewed source; fixture
signatures do not authorize a live epoch.

**Committed-retry durability.** `durable.rs::commit_block` closes the SQLite
writer before successful-commit synchronization. Its COMMITTED retry branch now
also closes, synchronizes the database and directory, and revalidates the same
head, durable sequence, artifact and commit before returning. A stored committed
row after an earlier sync failure is not by itself a completed durability
barrier. Retained sync-failure regressions reject success without adding a row.
This preserves codecs, sequences and finality rules; physical power-loss and
independent external-anchor evidence remain separate.

**Durable epoch evidence preparation.** `SqliteEpochPreparationStoreV1` in `trnm-consensus-safety-store/src/epoch_preparation_sqlite_v1.rs` consumes a real `EpochPreparationV1`, creates an immutable SQLite record and reopens it through `recover_epoch_preparation_v1`. The local `TRNMEP01` framing has storage schema 1 and exactly one accepted phase, `EvidenceVerified`; it is separate from SafetyState schema 13 and from protocol wire bytes. Creation, `open_existing`, `recover_fresh_v1` and exact idempotent retention keep independent old trust and the expected strict binding. Partial namespaces, different evidence, unsupported schema/phase, invalid signatures, changed file identity, checksum failure or exhausted admission budget cannot reconstruct authority. A host must supply the expected binding from its authenticated context; a self-consistent database/sidecar image cannot prove its own freshness or external rollback resistance. The tests in `tests/epoch_preparation_recovery.rs` include actual process exits at four SQLite transaction/commit/synchronization cuts, strict reopen and exact retry. These are process-crash checks, not power-loss or controller-cache qualification.

Every successful public Store operation leaves no live SQLite connection or page cache. The creation writer closes before file/directory synchronization; each readback uses a new read-only connection, checks exact schema and bounded record/checksum, explicitly closes it, and rechecks pinned namespace identity. WAL/SHM identity is pinned immediately after `BEGIN IMMEDIATE`, before the first initialization cut. Regression mutants cover same-inode persisted byte corruption and both sidecars' replacement at all four cuts. Structural admission reserves the complete signature-work charge before strict verification; invalid signatures, a final binding mismatch or later I/O failure do not refund that work. Core and Store propagate the same budget, and repeated invalid evidence exhausts a shared exact work allowance. A structural or resource rejection before any strict verification does not spend signature work.

**Checkpoint-to-first-block application coordinates.** Frozen bft-v0 specification 04 requires seals at consensus heights C+1 and C+2 to leave application state at checkpoint C; the first new block is at consensus height C+3. Under the present native storage contract, that single application transition advances JMT version V to V+1. `trnm-native-execution-v0/src/complete.rs` currently equates parent consensus height with JMT version and derives the target version from target height; `store.rs`, `durable.rs`, checkpoint/cutoff lookup in `poco_checkpoint.rs`, and Core's applied-transition ordinal checks also rely on this equality. This is an open live boundary. Do not apply dummy seal blocks or weaken ordinary parent/version/height checks.

An implementation candidate is an authenticated, persisted mapping of consensus `(epoch, height, block_id)` to application `(version, root, commit_sequence)`, with a closed epoch-edge execution/commit variant. It requires the controlled coordinate-contract clarification below before activation. A first-new-block native producer must consume the exact post-certificate `ConfirmedNativePocoCheckpointV0` and independently verified handoff evidence; naked roots, caller-generated transition tags and PREPARED rows are insufficient. This does not make that post-certificate receipt suitable for the earlier handoff-signing phase. The first-new-block parent is the terminal seal in consensus ancestry and the committed checkpoint in application ancestry. Core/Safety, durable P inventory, native complete/store plans, finalized historical reads, checkpoint/cutoff queries and restart records must preserve both coordinates and the same binding. M03's new-role signer-journal persist-before-sign operation remains an additional prerequisite, not an effect of storing this mapping.

**Cutoff and storage coordinate compatibility remains unresolved.** `docs/protocol/poco-bft-v0/05-poco-weights-bond-and-slashing.md` section 15 and `schema/poco-snapshot-namespace-v0.json` explicitly require JMT version to equal finalized cutoff consensus height; section 16 defines manifest height as its last mutation/refresh state version and requires exact equality at cutoff. `poco_checkpoint.rs::ensure_exact_cutoff` and `poco_snapshot.rs::bind_poco_snapshot_namespace_to_cutoff_v0` enforce those equalities. The present native `V -> V+1` application-version scheme, with no application transition for either seal, is incompatible with that equality after the first epoch boundary. This is an implementation/contract incompatibility, not proof that specification 04 forbids sparse JMT version labels or that the frozen protocol is intrinsically contradictory. The pinned JMT 0.12.0 `put_value_sets` constructs `TreeCache::new`, which reads the root at `next_version - 1`; merely skipping the target version cannot work without an authenticated storage mechanism for that predecessor root. A sparse-version or carried-root design that preserves cutoff equal-height semantics may avoid a protocol change, but is not implemented or validated here. Consensus, native-state, snapshot-proof and recovery owners must review an explicit native storage contract or controlled protocol interpretation, including predecessor-root authority, manifest semantics, pruning/reopen behavior and two-epoch positive/negative vectors. If the chosen design changes the B2-H2 join or authenticated bytes, that change requires controlled specification/schema versioning; a local mapping cannot silently redefine the existing verifier. Until a complete design and its actual producers/consumers are accepted, multi-epoch live execution remains unsupported. Do not delete the cutoff equalities, alter governance/maturity height meaning or execute dummy seal application transitions to manufacture a passing path.

Required `M08-CUT` additions are exact checkpoint-to-first-block commit and replay under the reviewed coordinate contract (C/V to (C+3)/(V+1) for the continuous application-version candidate); no application P row, state mutation or receipt for either seal; substituted checkpoint receipt, application owner, descriptor, roots or either parent; lost commit acknowledgement and each cross-store crash cut; partial, duplicate, stale and reordered phase completion; bounded recovery over two epochs; and rejection of a forged ordinary height jump. Any carried-root storage metadata must independently prove its authorized unchanged root and must not become application progress. Reopen must prove one application effect and the exact consensus ancestry from authoritative stores before enabling the first new epoch's live effects.

<a id="m09"></a>
## M09 — Data Availability

**Applicability and inputs.** `ai-v1` DA is design/candidate work. Inputs include exact namespace, author/sequence, batch bytes, committee descriptor, policy/limits, funding account and derived retention horizon. TransactionBatch and ArtifactEvidence are never interchangeable.

**State/admission algorithm.** Verify the exact committed committee and author authority, byte/item/chunk/outstanding limits and storage charge. Derive retention end by checked addition of the maximum required committee/policy horizon; do not let the author shorten it. Store bytes and manifest durably before attestation. Verify certificate uniqueness, signatures and threshold under the selected descriptor. For the reference TransactionBatch profile, committee identity/keys/weights project the validator set and threshold is `floor(2W/3)+1`. Retrieve and verify each exact chunk/content binding before reconstructing the batch. Repair uses authenticated content, not another node's unverified assertion.

**Error and recovery semantics.** Invalid sequence/certificate/context/retention rejects; missing bytes or interrupted retrieval is unavailable. Store-before-attest uncertainty requires readback before reissuing. GC is forbidden while any transaction, state-sync, evidence, challenge or settlement retention hold remains. A certificate attests to a retention statement, not current/perpetual retrieval, result correctness, independence or payment.

**Conformance requirements.** `M09-NAMESPACE`: artifact certificate cannot replace transaction availability. `M09-THRESHOLD`: zero/empty/duplicate/overflow/insufficient sets reject. `M09-RETENTION`: derived exact end, overflow and early-delete negatives. `M09-STORE`: crash before/after durable attestation input. `M09-REPAIR`: withheld/corrupt/reordered chunks and reconstruction against exact commitment.

**Implementation and consumers.** Trace `trnm-poco-da-v1` against specification 06, M02 voting prerequisites and M10/M11/M12 retention users. Candidate storage code is not a qualified distributed storage deployment. Require network-security and storage-recovery review plus real multi-host retention/retrieval evidence.


**Exact-source review trace.** For `M09-STORE` under `ai-v1`, inspect `trillionnium/crates/trnm-poco-da-v1/src/store.rs` symbol `prepare_attestation`; the current error definition/literal is `DaErrorCodeV1` in `trillionnium/crates/trnm-poco-da-v1/src/error.rs`. Reproduce `durable_before_attest_survives_reopen_and_rejects_bad_signature` in `trillionnium/crates/trnm-poco-da-v1/src/tests.rs`. Candidate local DA kernel, not production attestation authority or full independent DA interoperability.

<a id="m10"></a>
## M10 — Agent / Task / Market

**Applicability and inputs.** AI-v1 identity/market layouts are draft; PCC1 adds a proposed resource/service discipline, not activated fields. Inputs bind exact identity/controller or session authorization, capability generation, lane/nonce, task revision/attempt, lease, profile hash, budget/escrow and height-based deadlines.

**State/admission algorithm.** Verify identity and scoped authorization against the exact current state. Atomically create task and escrow while reserving funding and all resource dimensions. Consume exact current revision/attempt for each transition and checked-increment the revision; a state name alone is insufficient replay protection. The AI-v1 lifecycle is `Open -> Leased -> Running -> ResultSubmitted -> Verifying -> SettlementPending -> Settled`, with only the explicitly enumerated pause, migration, cancellation, expiry, failure and refund branches in specification 04. Migration to a new lease increments attempt and cannot reuse the old lease's result authority. Mandatory expiry/settlement/retention service is bounded and precedes unbounded new admissions.

**Error and recovery semantics.** Stale authorization/revision/nonce, unsupported scope, overcommit or invalid transition rejects atomically. Missing required evidence is unavailable/inconclusive under the selected profile, not invented success. Retrying the same operation returns its original effect without debiting again. Settled/refunded tasks may still carry retention liability; release active slots only when settlement and retention conditions are both met, while preserving historical replay identities.

**Conformance requirements.** `M10-AGGREGATE`: budget 100, accepted reservation 60, requested 50 rejects with reservation still 60 regardless of workers. `M10-REVOKE`: shared-root/session revocation races cannot reuse stale grants. `M10-TERMINAL`: every legal terminal path conserves assets and resolves obligations. `M10-SERVICE`: no new transactions cannot starve due refunds/settlements. `M10-HISTORY`: repeated refunds, retired IDs and retention releases cannot exhaust diagnostic arithmetic or reopen replay.

**Implementation and consumers.** Trace agent-market and worker packages into M05, M09, M11, M12 and M08. Existing PCC1 model cases are abstract; full Rust state transitions, frozen resource codecs and a bounded historical archive are separate unmet production obligations. Require application-security, execution and economics specialists for the corresponding requirements.


**Exact-source review trace.** For `M10-TERMINAL` under `ai-v1`, inspect `trillionnium/crates/trnm-poco-agent-market-v1/src/store.rs` symbol `execute_order_finalized`; the current error definition/literal is `AgentMarketErrorCodeV1` in `trillionnium/crates/trnm-poco-agent-market-v1/src/error.rs`. Reproduce `task_funded_escrow_bid_lease_and_provider_accept_are_atomic` in `trillionnium/crates/trnm-poco-agent-market-v1/src/tests.rs`. This is the funded task/lease prefix, not all terminal paths or the complete PCC1 multidimensional resource state machine.

<a id="m11"></a>
## M11 — Verification / Challenge

**Applicability and inputs.** `ai-v1` verification profiles and PCC1 resource bindings remain candidates. Pin profile ID/version/hash, task/lease/attempt/result revision, evidence and DA policy, verifier authority, height deadlines and challenge rules at authorization; do not select a more convenient profile at settlement.

**State/admission algorithm.** Validate exact receipt/statement bindings and profile activation. Dispatch only to that verification class; verify its proof/attestation/evidence and independently stated trust assumptions. Record the result and evaluation history as an atomic deterministic transition. Challenges bind the exact challenged result/revision, bond, evidence and response; adjudication and any appeal follow the profile's closed rules. A successful challenge creates a forward finalized state transition; it cannot reorg an already finalized ordering block. Only a mature, challenge-closed result may supply the M12 settlement predicate.

**Error and recovery semantics.** Malformed proof or unauthorized profile rejects; unavailable evidence, inconclusive evaluation and invalid result remain distinct. No ZK/TEE/optimistic-class fallback is implicit. Lost durable acknowledgements require exact history/readback, not duplicate bond debit or a new result revision. Evidence retention lasts through all applicable challenge/appeal/settlement obligations.

**Conformance requirements.** `M11-PIN`: changed profile/version/statement/lease rejects. `M11-CLASS`: unknown or substituted verifier class has no fallback. `M11-STATUS`: unavailable/inconclusive does not become valid or invalid by timeout alone. `M11-CHALLENGE`: concurrent challenges, deadline boundaries, appeal and replay. `M11-MATURE`: open challenge or immature result cannot authorize payment.

**Implementation and consumers.** Trace `trnm-poco-verify-challenge-v1` profile-registry tests and oracle boundary against specification 05. M09 supplies availability, M10 the exact task, M12 settlement and M13 proof views. Cryptography and application-security review must evaluate each actual profile; a signed receipt alone does not establish model correctness.


**Exact-source review trace.** For `M11-PIN` under `ai-v1`, inspect `trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs` symbol `resolve_exact`; the current error definition/literal is `VerificationProfileErrorV1` in `trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs`. Reproduce `disabled_expired_revoked_and_unknown_profiles_do_not_fallback` in `trillionnium/crates/trnm-poco-verify-challenge-v1/tests/profile_registry_v1.rs`. Candidate registry rejection path, not acceptance of every verifier class or economic/order authority.

<a id="m12"></a>
## M12 — Settlement / Economics

**Applicability and inputs.** AI-v1 settlement is candidate work; v0 PoCO effective-weight calculation remains under its frozen rollout rules, initially shadow. Inputs include exact finalized task/result/profile/challenge maturity, escrow assets, price/fee/policy revision, bond, consumption identity and beneficiary.

**State/admission algorithm.** Verify the complete maturity predicate and exact funded escrow before moving any asset. Compute checked fee/payment/refund/slash/burn legs from the pinned policy. For each asset separately, total debits equal total credits plus explicitly accounted burns/fees; no cross-asset cancellation. Atomically consume the settlement identity and write all legs/receipt. Exact replay returns the original receipt without another debit. Consumption rollups are gap-free and duplicate-free. Candidate consumer capacity does not itself grant voting power; activation/membership remains an authenticated epoch decision.

**Error and recovery semantics.** Missing mature proof, wrong beneficiary/policy, insufficient funds or overflow rejects atomically. Partial durable outcome is uncertain and read back as one settlement, never compensated by a second unauthenticated payment. Related-party detection, Sybil independence and mainnet constants are unresolved activation prerequisites where the normative profile says undecided; implementers cannot supply local defaults. Diagnostic saturation cannot be applied to monetary values.

**Conformance requirements.** `M12-CONSERVE`: multi-asset payment/refund/slash matrices preserve exact balances. `M12-DOUBLE`: duplicate result/consumption/settlement cannot pay twice. `M12-PARTIAL`: lost response or crash at every ledger leg resolves exactly once. `M12-POLICY`: pricing revision or maturity substitution rejects. `M12-ECONOMIC`: same-controller identities, subsidized demand, verifier collusion and challenge griefing are analysed before weight/profile activation.

**Implementation and consumers.** Trace consumption-settlement, compatibility-named `trnm-pouw` and settlement-vault contract boundaries into M07/M08/M10/M11/M13. An arithmetic model is not an anti-collusion proof or economic acceptance. Require economics, application-security and storage-recovery review.


**Exact-source review trace.** For `M12-CONSERVE` under `ai-v1`, inspect `trillionnium/crates/trnm-poco-consumption-settlement-v1/src/engine.rs` symbol `apply_transition`; the current error definition/literal is `ConsumptionSettlementErrorCodeV1` in `trillionnium/crates/trnm-poco-consumption-settlement-v1/src/error.rs`. Reproduce `receipt_rollup_and_settlement_are_bilateral_gap_free_and_conserved` in `trillionnium/crates/trnm-poco-consumption-settlement-v1/src/tests.rs`. Candidate one-asset/one-rollup kernel; multi-asset production settlement and anti-collusion economics remain separate.

<a id="m13"></a>
## M13 — State Sync / Light Client / Proofs

**Applicability and inputs.** Select native v0/PCC1 proof meaning or independent AI-v1 envelopes explicitly. Inputs include a trusted earlier anchor/commissioned context, exact target block/root/schema, validator/parameter/epoch path, catalog/chunks, proof class, weak-subjectivity policy and destination namespace.

**State/admission algorithm.** Dispatch by a closed proof class; verify all links, signatures, justifications, required TCs and epoch transitions from the trusted anchor. The proof cannot authenticate its own selected anchor. Distinguish order finality, application membership, artifact availability and result-settlement maturity. For AI-v1 state proofs, verify the specified 256-level sibling order/key bits and exact root rather than native JMT bytes. Download to bounded staging; validate catalog/chunk hashes, schema/root closure and lifecycle permit before installing into a new or safely replaced namespace. Migration uses trusted finalized export and fresh target genesis; never import old signer/WAL state as new authority.

**Error and recovery semantics.** Unknown class, wrong context/schema, stale anchor, conflicting checkpoint, downgrade or self/future anchor rejects or halts as specified. Unavailable history/chunks are retryable only within bounded policy. Partial download/install does not destroy the current authoritative store. Recovery resumes the exact staged identity or discards only uncommitted staging; it cannot select a network-majority trust root.

**Conformance requirements.** `M13-ANCHOR`: supplied self/foreign/stale anchor cannot bootstrap trust. `M13-CLASS`: historical QC cannot become three-chain finality or settlement. `M13-PATH`: long paths, skipped views and multiple epochs under finite work limits. `M13-STAGE`: corrupt/reordered/truncated chunks and interrupted install preserve old state. `M13-MIGRATE`: wrong liabilities, source proof, signer namespace or target root blocks cutover.

**Implementation and consumers.** Trace the finality types/verifiers, cross-plane readback, migration and state-sync crates plus staging/verification-seal tests. M07 supplies authenticated state and M14 displays only the proven class. Require client-proofs, consensus, cryptography and storage-recovery specialists for touched boundaries.


**Native epoch-zero coordinates.** The generic M13 anchor and snapshot shapes
accept a positive finalized height in native epoch `0`; epoch zero is not a
synthetic genesis anchor. Zero height, zero trust digests, backward/skipped epoch
links and same-epoch validator substitution still reject. Every accepted link
still invokes its commissioned proof verifier. `epoch_zero_tests.rs` verifies
those boundaries; its counting verifier is a fixture, not independent
cryptographic acceptance. The existing epoch-one storage golden vector remains
byte-identical, with a separate epoch-zero reference round trip.

**Streaming installation candidate.**
`trnm-state-sync-v0/src/streaming.rs::install_streaming_snapshot_v1` consumes a
previously verified trust path, exact manifest, ordered fallible chunk iterator,
trusted schema-specific incremental root accumulator and real install target.
It validates the manifest before side effects, reserves bounded digest metadata,
opens disposable staging and consumes at most the manifest's chunk count plus
one look-ahead item. Each chunk is index/identity/digest/size checked, absorbed by
the disposable root accumulator and written to staging before the next input
is requested. Final byte totals, existing chunk Merkle root and independently
recomputed application root must all match before CURRENT CAS.

Payloads are not retained in `StateSyncSessionV0` by this new API: its auxiliary
transport memory is one input chunk plus bounded digest/Merkle levels. This does
not bound the iterator's allocations, accumulator scratch space or target's
memory, and it does not implement native JMT incremental decode or a network
downloader. Input/order/length/digest/root/write failure aborts only staging;
both original and cleanup failure are retained. Once CAS starts, any error or
receipt mismatch is uncertain and never calls abort. A panicking adapter leaves
recovery evidence rather than triggering destructive automatic cleanup. The
existing buffered API is unchanged and remains buffered.

`trnm-durable-file-adapters-v0/src/streaming_snapshot_tests.rs` connects the new
installer directly to `AtomicSnapshotFileTargetV0`, with file readback, late
chunk corruption and lost CURRENT-publication response cases. The target still
revalidates persisted complete chunks before publication and on reopen. The
SHA-based root and permissive link verifier used in these tests are explicit
fixtures, not native JMT or independent light-client authority. The ordered
in-memory adapter tests in `trnm-state-sync-v0/src/streaming_tests.rs` cover
short/extra/duplicate/reordered streams, bounded look-ahead, accumulator errors,
write/abort errors and uncertain CAS. The separate native read verifier below does not implement this generic
accumulator trait or convert its domains. Source-bound Rust execution and
independent acceptance are separate; native installation, downloader integration,
resumable transfer and bounded whole-node recovery remain open. No existing runtime, migration or release flag is
changed by introducing this consumer path.

**Exact-source review trace.** For `M13-STAGE` under `bft-v0`, inspect `trillionnium/crates/trnm-state-sync-v0/src/lib.rs` symbol `verify_complete`; the current error definition/literal is `StateSyncErrorV0` in `trillionnium/crates/trnm-state-sync-v0/src/lib.rs`. Reproduce `recomputed_root_mismatch_cannot_issue_a_verified_snapshot` in `trillionnium/crates/trnm-state-sync-v0/tests/verification_seals.rs`. Verified snapshot capability only; real transport, independent light client and migration qualification remain separate.

### Candidate durable snapshot file boundary

Primary source ownership remains M03 for `trnm-durable-file-adapters-v0` under
`config/module-coverage-v1.toml`; M08 recovery and M13 state sync consume this
boundary. The crate's older embedded `module = "M08"` metadata is not a transfer
of primary ownership. The following is a local storage-format/implementation
candidate, not a new protocol wire format or an acceptance of SYNC-PROD-001.

`SnapshotManifestV0::validate_shape` checks canonical manifest bytes and existing
count/byte bounds without issuing trust. `validate` still binds those fields to
an actual verified trust path. `AtomicSnapshotFileTargetV0` repeats shape checks
before storage work. Its `MANIFEST.v0` file now uses storage magic `TRNMSM01` and
contains all manifest fields plus a domain-separated checksum. Exactly 296 bytes
are accepted. The old lossy `TRNMSM00` record cannot authenticate the selected
chunks and is rejected without migration or rewriting. Existing directories,
including partial initialization and missing CURRENT/lock/subdirectory states,
are not implicitly fresh-create inputs. Candidate testing requires a fresh
namespace; retained legacy files require a separately reviewed recovery/export
procedure, never automatic deletion.

| Storage offset | Field and encoding |
|---:|---|
| 0 | 8-byte `TRNMSM01` magic |
| 8, 40 | chain ID, protocol digest; 32 bytes each |
| 72, 80 | height, epoch; big-endian u64 |
| 88, 120 | state root, chunk root; 32 bytes each |
| 152, 156 | chunk count, maximum chunk bytes; big-endian u32 |
| 160 | total bytes; big-endian u64 |
| 168, 200, 232 | schema, checkpoint and manifest digests; 32 bytes each |
| 264 | 32-byte hash of bytes 0..264 under `trnm.snapshot-staging-manifest.v1` |

The hash uses the existing `Digest32V0::hash` length-prefix convention. Original
manifest, chunk and Merkle domains and the 120-byte CURRENT pointer layout are
unchanged. The separate Python stdlib reference in
`scripts/ci/test_snapshot_manifest_reference_v1.py` generates the retained
`tests/vectors/snapshot_manifest_v1.hex` bytes; the Rust codec test compares exact
bytes to that reference. This is a separately implemented byte oracle, not a
qualified independent reviewer or a recorded Rust execution result.

The installer writes private create-new files, synchronizes them, reads back
acknowledged chunk bytes, and counts total staged bytes without charging exact
duplicates twice. Commit re-reads the complete manifest and every chunk, computes
the exact original chunk digests/root, and rejects unknown names, missing chunks,
links, over-bounds reads, wrong totals or same-length byte corruption before
publishing CURRENT. It verifies again after generation publication and after
pointer publication. Reopen verifies the actual selected generation, not only the
CURRENT checksum. Plain `current_*` getters remain last-observed coordinates;
`verify_current_snapshot_v1` is the fresh validation operation. Neither supplies
an independently trusted checkpoint or recomputes application state semantics;
the M13 verified session still owns the original state-root check.

The pointer rename is the local publication boundary. An uncertain rename,
post-rename synchronization failure or failed readback returns an error and
fences the owner. It never returns a durable success receipt or permits abort to
remove the selected generation. Reopen must prove the durable source or target.
Explicit abort and orphan cleanup preflight known contents and any exact
unpublished pointer before deletion. Unknown or partially undecodable evidence
is retained. Cleanup is limited to the next unselected local generation and at
most 1,024 entries per parent; it is not historical pruning, a finalized replay
floor or general node recovery.

This candidate requires Linux no-follow/nonblocking file admission and one
cooperating owner. Parent/lock descriptors detect observed replacement and
permanently fence that handle. New files/directories use 0600/0700; admitted
existing entries must have the same owner and no group/other write permission.
The operations are not all descriptor-relative and do not protect against an
unobserved rename-and-restore race or a continuously malicious same-UID writer.
Owner-controlled ancestors, filesystem synchronization guarantees and an
independently administered anti-rollback anchor remain external assumptions.
A self-consistent whole-namespace rollback is not detected by local checksums.

Verification streams at most one admitted chunk at a time and retains a bounded
list of chunk hashes; it does not scan every old generation at open. The selected
snapshot is still scanned in full, and `StateSyncSessionV0` still retains its
existing in-memory chunks. This is not incremental native JMT persistence,
bounded-history Node Commit Ledger recovery or a throughput result. The actual
file/process regressions live in `snapshot_recovery_tests.rs`, including an
explicit child process exit at generation publication, before pointer rename,
after pointer rename and after pointer synchronization. They must be compiled
and executed on the reviewed source; test source is not a pass and process exits
are not physical power-loss qualification.

<a id="m14"></a>
## M14 — RPC / Indexer / SDK / CLI

**Applicability and inputs.** Query/transaction-builder APIs are versioned separately from consensus. The current Web4 API contract is read-only; the target write/SDK surface is not activated by documentation. Inputs include selected endpoint/schema, bounded parameters, authentication where applicable, requested proof class and freshness requirements.

**State/admission algorithm.** Bound pagination, result size and proof work before serving. Read only committed data at a named height/root; include actual source/finality class and indexer lag. Expose demo, stale, unavailable and unverified states honestly. Builders preserve exact selected bytes and send authorized operations through M05; neither RPC success nor a transaction ID means finality. Simulation discards mutations and uses the same selected meter semantics. Cache keys include chain/profile/schema/height/proof class; index rebuild replays authenticated committed history.

**Error and recovery semantics.** Unknown method/version/class rejects according to the API contract. Missing/lagging local data is unavailable/degraded, not an empty authoritative result or a new finality claim. Timeouts/cancellation bound local work. Replayed submission uses stable transaction identity; clients resolve uncertain submission through exact readback rather than assuming a second transaction is safe. Client displays must not invent settlement from order finality.

**Conformance requirements.** `M14-READONLY`: current Web4 cannot expose an unimplemented write route. `M14-FRESH`: unknown height, lag and blank/malformed root are not canonical success. `M14-PROOF`: all four proof meanings remain distinct in serialized responses and UI. `M14-BOUND`: pagination/proof/cancellation resource limits. `M14-E2E`: real authorized admission to finality/readback for each actually enabled write operation.

**Implementation and consumers.** Trace RPC and CLI crates, Web4 package and `web4-frontend/docs/api-contract.md`; retain its public contract rather than inventing routes here. M05 handles admission, M08/M13 establish authority. Require client-proofs and application-security review, including generated-client compatibility and actual consumer regressions.


**Exact-source review trace.** For `M14-BOUND` under `bft-v0`, inspect `trillionnium/crates/trnm-rpc/src/lib.rs` symbol `validate_trnm_address`; the current error definition/literal is `AccountQueryError` in `trillionnium/crates/trnm-rpc/src/lib.rs`. Reproduce `query_account_state_invalid_input` in `trillionnium/crates/trnm-rpc/src/lib.rs`. Current RPC address/error contract only; it does not establish full write SDK, transaction finality or UI proof verification.

<a id="m15"></a>
## M15 — Node / Packaging / Release

**Applicability and inputs.** Select one of the existing production, devnet, AI-v1-candidate and lab/evidence build closures. Inputs include exact source/tree, Cargo lock/toolchain/features, closed configuration, commissioned identity, adapter ownership, accepted evidence and artifact provenance.

**State/admission algorithm.** Validate configuration and feature/dependency closure before side effects. Construct one generation-fenced Core/Safety owner with versioned ports. Reconstruct/read back all required durable authorities before enabling network participation or publication. Composition only wires: it does not decide validity, create roots or infer finality from opaque digests. Shutdown drains or durably records outstanding work; restart uses the same ownership protocol. Package binaries/containers with source, lock, features, config, SBOM, provenance and signatures; release intake verifies exact bindings.

**Error and recovery semantics.** Forbidden candidate/lab/legacy edges, incompatible platform/configuration, unsafe namespace or unproven recovered authority block the relevant constructor. No flag flips an inert default into production. Uncertain adapter recovery fences dependent participation. Rollback never reuses unsafe signer state. The branch tip and a binary with the expected name do not establish release identity.

**Conformance requirements.** `M15-CLOSURE`: default and explicit feature graphs contain no forbidden dependency edges. `M15-WIRING`: no domain transition/authority constructor is hidden in composition. `M15-START`: cold start/restart/takeover cannot bypass readiness barriers. `M15-ARTIFACT`: changed source/lock/toolchain/config/signature rejects release binding. `M15-NONPROMOTE`: missing external evidence cannot produce an activated release.

**Implementation and consumers.** Trace node boundary/host/IO/authority/CLI/production and release crates separately from lab/bridge helpers; use existing build/decomposition gates. Producers M02/M03/M07/M08 and all consumers must review their real wiring. Require release-supply-chain and storage-recovery specialists; the current incomplete default-node integration remains an explicit blocker.


**Exact-source review trace.** For `M15-WIRING` under `pcc1`, inspect `trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs` symbol `advance_verified`; the current error definition/literal is `AuthoritySessionErrorV0` in `trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs`. Reproduce `production_session_exports_verified_tokens_not_naked_digest_mutators` in `trillionnium/crates/trnm-poco-node-production-v0/tests/public_authority_surface.rs`. Public authority-surface regression; not evidence that default-node producers are fully commissioned.

**Ready/Start journal namespace.** `trnm-poco-node/src/recovery_ready_start.rs` pins its private database and parent directory with shared lifetime descriptors and a parent ownership lock. Fresh connections open existing databases only and reject links or changed identity; detected namespace loss permanently fences every clone of the handle. Read audits use one SQLite snapshot. Successful append and idempotent retry explicitly close the writer, then reopen and audit the exact target; successful reads close before the final namespace check. Initial creation synchronizes its parent directory before readback. The journal requires a same-owner regular single-link database and private database/directory permissions; an existing broadly readable database is rejected rather than silently migrated. Public methods, SQLite schema and 459-byte event records retain their encoding.

This boundary assumes owner-controlled ancestor directories and one live journal owner per private parent. It detects observed deletion/replacement and aliasing; it does not establish protection against unobserved rename-and-restore races, coherent in-place rollback, physical power loss or an independently administered replay floor. The coordinator still does not clear Core's fence, start timers, sign or admit ingress. The feature-enabled older three-store recovery tests still depend on absent application-host interfaces and remain a separate end-to-end implementation blocker.

<a id="m16"></a>
## M16 — Global Control Plane

**Applicability and inputs.** Non-authoritative operational contract/core only. Inputs bind module descriptors, source/contract graph, telemetry workload validity region, bounded proposed tunables, parameter class, generation, expiry, rollback and signer/guard policy. No networked service or rollout daemon is commissioned by the library's existence.

**State/admission algorithm.** Validate descriptor and measurement bindings; reject stale/poisoned data and infeasible constraints. Produce only bounded proposals. A separate node-local guard verifies profile, generation, expiry, limits and allowed parameter class before any apply. ConsensusCritical changes require authorized governance/activation; DeterminismCritical changes require independently evidenced invariance/shadow policy; only the accepted OperationalLocal subset can be locally tuned. Record exact proposal/decision/applied digest and rollback receipt. Optimizing latency/cost cannot precede zero safety, determinism, durability and compatibility violations.

**Error and recovery semantics.** Forged, expired, over-broad or wrong-class proposals reject without mutation. Missing control-plane service/telemetry leaves the last accepted safe local plan in force. It cannot stop consensus merely because optimization is unavailable. Lost acknowledgement requires exact guard/application readback; an optimizer cannot declare its own action accepted. A rollback proposal is subject to the same bounds and authority constraints.

**Conformance requirements.** `M16-CLASS`: ConsensusCritical cannot masquerade as OperationalLocal. `M16-GUARD`: planner cannot invoke voting/signing/root/finality capabilities. `M16-STALE`: source/generation/expiry/measurement substitutions reject. `M16-LOSS`: control-plane outage stops tuning, not consensus. `M16-ROLLBACK`: bounded canary, rejection and rollback receipts reflect real local outcomes.

**Implementation and consumers.** Trace `trnm-control-plane-v0` into M15's versioned guard boundary; descriptors remain observations, not authority. Require application-security, execution and release-supply-chain review; separately qualify any future service adapters.


**Exact-source review trace.** For `M16-GUARD` under `pcc1`, inspect `trillionnium/crates/trnm-control-plane-v0/src/lib.rs` symbol `evaluate`; the current error definition/literal is `ControlPlaneErrorV0` in `trillionnium/crates/trnm-control-plane-v0/src/lib.rs`. Reproduce `forbidden_authority_is_rejected_before_evaluation` in `trillionnium/crates/trnm-control-plane-v0/src/lib.rs`. Non-authoritative local guard fixture, not a deployed planner or automatic production tuning authority.

<a id="m17"></a>
## M17 — Observability / Benchmark / Security / Evidence

**Applicability and inputs.** Read-only evidence tooling for explicitly named profiles and source identities. Inputs bind actual head/tree and prospective merge, exact protocol/plan/module/dependency/toolchain/features/config, commands, topology/workload/faults, raw artifacts, reviewer statements and qualification scope.

**State/admission algorithm.** Verify source and input digests before interpreting results. Preserve each command's real exit status and distinguish passed, failed, skipped, cancelled, queued and not-assessed. Verify artifact availability/digests and authenticated independent statements through the existing trust mechanism. Benchmark only the named workload and report committed business goodput plus ordering, durable receipt and settlement latency separately. Verify the tooling using positive controls and retained false-pass mutants. Generate deterministic reports without mutating the reviewed checkout.

**Error and recovery semantics.** Missing, stale, cross-head, synthetic, unsigned or self-authored acceptance evidence blocks the relevant gate. A test process start or an artifact directory is not a pass. Keep failure logs and invalidate dependent claims; never repair a report by weakening the validator. Simulated time and process-kill tests do not replace multi-host/HSM/power-loss or real wall-clock evidence. Documentation integrity never becomes semantic or production acceptance.

**Conformance requirements.** `M17-SOURCE`: wrong source/merge/toolchain/config artifacts reject. `M17-MUTANT`: remove a module, change a frozen import, launder a proof class, omit a reviewer domain or promote a local status and detect each. `M17-STATUS`: skipped/failed commands cannot be counted as passing. `M17-INDEPENDENCE`: author/fallback contacts cannot self-issue specialist acceptance. `M17-REPRO`: exact commands regenerate matching artifacts and leave source unchanged.

**Implementation and consumers.** Trace benchmark/simulator/research/lab/conformance crates and formal/fuzz/CI auxiliary surfaces. The documentation checker validates links, inventories and non-promotion boundaries only; independent specialists assess the substantive guide and requirement-level vectors. M15 consumes release evidence only after the existing protected and external gates, with no administrative bypass.

## Acceptance boundary

All eighteen sections are implementation/conformance requirements. The machine index supplies concrete starting points, not an exhaustive automatically accepted operation catalog. Before a module is called independently implementable, its reviewers must close each requirement-level schema/state/error/vector/symbol record, including any disabled production transport, AI codec, migration or hardware boundary. Actual people, signatures, independent vector production and execution results cannot be manufactured by editing this guide. They remain visible acceptance prerequisites under `TRNM_INDEPENDENT_REVIEW_V1.md`.

**Exact-source review trace.** For `M17-INDEPENDENCE` under `pcc1`, inspect `scripts/ci/check_documentation_contracts_v1.py` symbol `validate_structure`; the current error definition/literal is `DOC-SELF-ACCEPTANCE` in `scripts/ci/check_documentation_contracts_v1.py`. Reproduce `test_local_accepted_state` in `scripts/ci/test_documentation_contracts_v1.py`. Local navigation-registry anti-self-acceptance test only; authenticated specialist findings still use the external evidence process.
