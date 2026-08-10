# PoCO-BFT v0 Implementation Gap Register

Status: **release-blocking register**

Last audited: 2026-08-09

## Recoverability-first integration reset (2026-08-08)

The six production integration contracts are frozen in
[`../../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](../../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md).
They remain implementation gaps until backed by durable code and crash tests:
SafetyState codec/WAL, complete canonical SignIntent, validation job/callback
outbox, ordered ancestor finalization queue, BlockId-keyed speculative overlay,
and strict separation of consensus parameters from local backpressure. No
additional private carrier closes any of these gaps.

The normative documents in this directory remain ahead of the complete Rust
implementation. `trnm-consensus-types`, `trnm-consensus-core`, and
`trnm-consensus-sim` are P1 engineering scaffolds and MUST NOT be described as
fully wire-conforming, production consensus, or deployment-ready until every
critical item below is closed with vectors and tests. Their package metadata
deliberately reports `wire_conformance = false`.

## Foundation items closed on this branch

- Exact CEV0 prefix, checked `u32` frames/Bytes/Lists, primitive widths, and all
  21 frozen domains now match the independent Python foundation vectors,
  including the handoff-descriptor and three ordered-root domains.
- The complete common signed context binds schema, genesis, restricted-ASCII
  chain ID, protocol version, epoch, validator-set hash, view, and message
  kind.
- Validator IDs are bounded raw CEV0 Bytes with raw-byte lexicographic order;
  validator-set hashes bind genesis and the consensus-parameter hash.
- `BlockHeaderV0`, proposal/vote/timeout signing roots, QC encoding, and the TC
  referenced-QC table are implemented. TC high-QC selection uses the unique
  `(view, block_id, qc_digest)` maximum and rejects same-view/different-block
  QCs.
- Signature values are exactly 64 bytes at the type boundary. The old
  arbitrary-length signing path and the incorrect network `Genesis` proposal
  variant were removed.
- `trnm-consensus-crypto` now provides a `no_std`, verification-only Ed25519
  boundary using `VerifyingKey::from_bytes` followed by `verify_strict`.
  Public vectors cover a valid protocol vote root and wrong-root,
  mutated-signature, undecodable-key, and small-order-key rejection; the crate
  exposes no signing or private-key API.
- The independent B1 `qc-tc-threshold-v0` corpus now covers complete ordinary-
  QC and corrected full-TC CEV0 values with real RFC 8032 Ed25519 signatures,
  unequal powers `4/3/2/1` (`W=10`, exact threshold `7`), exact-threshold
  acceptance, one-below rejection, and certificate/signature/selection
  mutations. Rust reconstructs that public corpus through protocol constructors
  and the strict verifier. This closes the B1 full-object weighted-threshold
  vector gap, not B2 parsing or the complete protocol corpus.
- `ConsensusParametersV0` now covers the frozen 54-field logical value,
  discriminants, fail-closed safety inequalities, and exact 341-byte CEV0/hash
  vector. General v0 validation is separate from the P0 reference
  shadow-profile gate; TOML/wire decoding and governed activation remain open.
- Cargo tests reproduce the independent block ID, validator-set hash,
  proposal/vote/timeout roots, primitive encodings, and domain digests.
- Rust `OrderedRootV0` now implements the indexed-leaf, level-tagged-node,
  duplicate-right, final-count-wrapped construction for payload, receipt, and
  evidence roots. The independent Python/JSON gate fixes all three empty roots,
  0--4 item trees, a public leaf, and kind/order/framing/count mutations. This
  closes the root-construction primitive, not the still-missing execution,
  receipt, and evidence pipelines that must feed it.
- A standard-library Python gate now freezes the exact `GenesisQC`, skipped-
  view genesis proposal/TC, descriptor-domain digest, epoch-anchor nesting,
  complete `CertifiedHeaderV0` encodings, and `FinalityProofV0` digest. Its
  retained negative cases reject a different justify-QC signer-subset digest,
  a deleted proposer signature, and a TC selected-digest mismatch. Composite
  signatures are explicitly shape-only fixtures, so this is not signature or
  quorum-threshold evidence.
- Rust now has separately typed, non-ordinary `GenesisQcV0` and
  `EpochAnchorQcV0`, exact descriptor/handoff/authorization and anchor-aware TC
  values, and complete `CertifiedHeaderV0`/`FinalityProofV0` encoders. Its
  golden tests reproduce the independent proof digest and three retained
  mutations. The production proof verifier explicitly binds the parameter
  preimage, scheduled leader, three-header rule, and checked timestamp bounds.
- `ProposalWitnessV0` and `SignedProposalV0` now retain the exact justify QC,
  optional TC, optional epoch authorization, and proposer signature through one
  shared production-validation path. `CertifiedHeaderV0` reuses that same
  witness and can be constructed from an admitted signed proposal without
  reconstructing or replacing its signed certificate variant. The refactor
  leaves every frozen CertifiedHeader/finality byte and digest unchanged.
- The BlockTree, durable finalization outbox, recovery path, application
  acknowledgement, and simulator now carry exact `FinalityProofV0`; the
  obsolete internal `CommitProof` path has been removed from core/simulator
  finalization. Core bootstrap now accepts only the separately typed
  `GenesisQcV0`, derives the synthetic genesis block ID from `genesis_hash`,
  and rejects an ordinary signed view/height-zero QC.
- `Core::step` now applies the bounded busy gate and verifies the signed
  context/signature of every proposal, synced proposal, vote, timeout vote,
  QC, and TC before cloning transactional core state. Block payload bytes are
  held in immutable `Arc<[u8]>` storage, so authenticated transaction clones
  share bodies rather than copying them. Authenticated handlers still repeat
  cryptographic verification after this admission pass; that CPU cost remains
  open below.
- The epoch-0 TC path now durably records the full verified TC and advances its
  view before requesting missing data. After storage acknowledgement it
  deterministically synchronizes every not-yet-ready ordinary referenced QC,
  processes each through the same high-QC/lock/finality transition as a
  directly received QC, preserves timeout progress while suppressing proposal
  votes, and resumes the target across recovery. A first proposal carrying a
  complete multi-reference TC creates this same full durable obligation,
  including lower references, rather than converting only its selected justify
  QC into standalone sync.
- Standalone missing QCs now cross the same full-state persistence boundary
  before requesting data. The active certificate cannot be preempted; later
  non-conflicting certificates are retained in a bounded canonical backlog,
  and recovery re-verifies and reissues the exact target after any required
  safety replay or TC-priority work. Proposal-carried ordinary QCs with missing
  parent context now create that same exact durable active/backlog obligation.
  Current safety-state schema v6 also retains bounded block-ID-level terminal
  payload facts across crash and volatile block-tree eviction, separately from
  its route/full-ID completion tombstones. Safety-state schema v5 has no
  implicit migration to v6.
- Same-view/different-block QC conflicts are observed and durably halt before
  finalized-height subsumption. Subject to that check, a different-view
  competitor at the durable finalized height is subsumed without a sync or
  safety-state transition; when carried by an independently valid TC, only the
  TC-authenticated view may advance. Direct QC, proposal-carried QC, and
  direct/carried TC conflict probes now have the same authenticated durable-halt
  behavior while signing, finalization, or recovery replay is pending.
- `NextEpochCommitmentV0` now has an exact private-field logical type, checked
  outgoing-epoch geometry, inert same-version context binding, and a bounded
  parser-first exact decoder. The independent B2-C manifest/Node corpus fixes
  the CEV0/protobuf mapping, all 608 incomplete prefixes, three trailing-byte
  variants, 25 parser boundaries, and 21 context relations. Neither the raw
  decoder nor context checker returns an authorization capability.
- B2-E now fixes the complete 54-field `ConsensusParametersV0` preimage and
  one ordinary old-set `checkpoint <- seal-1 <- seal-2` finality kernel.
  Bounded exact Rust decoders consume the raw parameters, each
  `CertifiedHeaderV0`, and the complete `FinalityProofV0`; the specialized
  semantic verifier requires the exact old set/parameters, next-epoch
  commitment, authenticated checkpoint-parent timestamp, and a caller-supplied
  verifier. The committed crypto lane uses `StrictEd25519Verifier` and returns
  only an inert private-field `CheckpointTwoSealKernelV0`.
- B2-F now composes the exact B2-B/B2-C/B2-E witnesses for same-version v0
  `EpochHandoffProof` fields 1--11. The independent Node gate locks 11 transport
  fields, consumes four source corpora and exactly 14 raw objects, rebuilds and
  strictly verifies two positive profiles, and rejects 10 independent failure
  classes. Rust returns only private-field `JointHandoffKernelV0` bound facts;
  there is no aggregate CEV0 object or digest and no anchor, signing,
  activation, or transition capability.
- B2-G now closes deterministic candidate/fallback computation and validator-
  key PoP for one caller-supplied normalized transcript. The independent gate
  and Rust kernel bind exact checked arithmetic, cap hierarchy, selection and
  tie-breaks, rollout weights, successful shadow reason-0 carry, numeric-
  minimum fallback reason, exact fallback identity, and real Ed25519 PoP.
  Rust returns only private-field inert `CandidateSelectionKernelV0` facts.
  The transcript is unauthenticated and is not a full Consumption Certificate
  wire authority or snapshot/runtime provenance proof.
- The epoch-zero core now fences every regular proposal/replay, vote/QC,
  timeout high-QC, direct/carried TC reference, durable sync/finality record,
  and pending sign intent at the mandatory checkpoint height derived from the
  authenticated active parameters. It can finish the last pre-checkpoint
  regular vote pipeline but cannot sign or recover through a checkpoint,
  seal, or handoff.
- Replaced replay generations now cancel only the exact old volatile synced-
  validation request in the core. A wrong generation fails before the busy
  gates and state clone; an overlapping current replay re-registers the exact
  proposal under a fresh ID. Real-obligation regressions cover both event
  orders and prove stale results cannot consume the current scripted outcome,
  leak a pending slot, or complete the replacement replay.
- The completed post-B2-F sweep passes 212 tests: types 74, crypto 15, core 99,
  and simulator 24. The local gate set now includes
  twelve independent parameter/wire/anchor-finality/ordered-root/B1/B2-A/
  B2-B-structure/B2-B-crypto/B2-C/B2-D/B2-E/B2-F gates, four-crate strict
  Clippy, rustfmt, `git diff --check`, the lock-pinned Quint `0.32.0` formal
  gate with retained
  mutants, pinned `protoc 29.3` descriptor compilation, and project preflight.
  `.github/workflows/trnm-poco-bft-v0.yml` now wires that set into GitHub
  Actions, but no remote run exists yet. This remains regression and bounded-
  tranche evidence, not a P0 or P1 exit decision.
- The B2-G schema/Node/Rust gates extend that recorded baseline without a new
  aggregate count in this register. Their closure criterion is shared exact
  artifacts, cross-implementation result equality, strict PoP verification,
  and retained negative cases; no test count substitutes for the missing
  provenance or transition authority.

These closures are necessary but do not imply complete wire conformance.

## Prototype simulator evidence present on this branch

- `trnm-consensus-sim` contains 25 tests: 9 unit tests and 16 deterministic
  scenarios.
- The finality oracle stores complete per-node applied chains, backfills newly
  finalized ancestors, and checks finalized-prefix comparability rather than
  only same-height tip collisions. Dedicated tests reject conflicting tips at
  different heights and accept different-height tips on one prefix.
- Application finality is recorded only after the core accepts
  `FinalizationApplied`; a monotonic simulator watermark records when the
  applied height and cleared finalization outbox have both been durably
  acknowledged.
- After every deterministic event and before run/crash/recovery transitions,
  the finality oracle compares every observable node layer: volatile core
  state, acknowledged durable state, current-incarnation pending persistence,
  queued and durable finality proofs, application-applied chains, and the
  durable application watermark. All pairs must be prefix-comparable;
  malformed or incomplete observations fail the run. Focused tests prove that
  pending effects participate and that a cross-layer fork is rejected before
  another event executes.
- Scenario coverage includes 4-node one-offline progress/recovery, 7-node
  two-offline progress, 7-node three-offline stall followed by recovery, 2+2
  partition stall/heal, unacknowledged-persistence crash rollback, durable
  conflicting-QC halt/restart, and a running crash from nonzero durable state
  through real safety replay and synced-payload validation. Scripted host
  outcomes additionally cover `Unavailable -> Valid` under a fresh generation,
  durable certified-payload invalidity across restart, and replay which cannot
  complete while its exact item is `Unavailable`. Every simulator-created
  `Valid` result is now minted through the real B2-D canonical body capability;
  a wrong-block capability is rejected by the core before its request
  generation is consumed. A bounded short-epoch
  scenario reaches the mandatory checkpoint fence, records the exact proposal
  rejection, and proves that no checkpoint-height vote or QC is produced.
- The seeded fault scenario asserts actual consumption of one proposal drop,
  three vote duplications, two QC delays, and one message reorder. Trace entries
  retain full object identifiers, signatures, signing roots, and safety-state
  digests.
- The deterministic mock verifier is validator-key-aware, while explicit
  equivocation/conflicting-QC injection remains a privileged out-of-model
  Byzantine fixture.

This evidence does not close P1. The simulator remains epoch-0, equal-weight,
and dependent on global in-memory proposal/QC/gossip availability. Its payload
faults are privileged scripted enum results; ordinary retries reuse the same
archived signed proposal and canonical body and do not model distinct sources,
authenticated parent state, authorized-runtime execution, or receipt
provenance. Its trace is diagnostic
rather than a self-contained replay input. The multi-layer oracle reconstructs
nonzero ancestry from that same global archive, so it is not evidence that a
real WAL or state-sync store can recover the chain.

## Pre-activation schema corrections now frozen

- `FinalityProofV0` no longer treats a bare peer-supplied
  `justify_qc_digest` as evidence. Each `CertifiedHeaderV0` now contains the
  header, exact justify QC, optional full TC, optional atomic epoch-anchor
  authorization, proposer signature, and certifying QC.
- `GenesisQC` and `EpochAnchorQC` now have exact empty-signature
  `QuorumCertificateV0` preimages under the existing QC domain. They are valid
  only when reconstructed from trusted genesis or a verified joint handoff and
  never certify/finalize a block.
- Handoff descriptors now have their own frozen domain. The first block of an
  epoch may move past a faulty view-1 leader through a TC selecting the exact
  authorized anchor; `initial_new_view = 1` is not a forced proposal view.

These corrections were made before production activation or an
interoperability promise. Every earlier experimental CommitProof/finality and
handoff digest is invalid and must fail closed; it cannot be upgraded by
filling omitted fields.

## B2-A certificate-kernel boundary (closed)

The next independently closable B2 tranche is intentionally narrower than the
complete logical-object corpus. B2-A covers only CEV0 primitives,
`MessageKindV0`, `CommonConsensusContextV0`, `ValidatorV0`, `ValidatorSetV0`,
`SignatureShareV0`, `VoteSignV0`, `QuorumCertificateV0`, `HighQCSummaryV0`,
`TimeoutSignV0`, `TimeoutEntryV0`, and the corrected
`TimeoutCertificateV0`, plus the validator-set, vote, QC, timeout, and TC
domains. It does not cover Proposal/Block, synthetic-anchor authorization,
epoch/handoff/upgrade, receipts/evidence, Consumption Certificates, or light-
client objects.

B2-A is closed under this exact boundary. The ordered machine-readable
manifest fixes all covered fields, bounds, domains, layered errors, Rust
internal mapping, and protobuf projection roles. The independent standard-
library Node.js decoder consumes eight committed raw B1 objects, round-trips
them byte-identically, recomputes digests and quorum from decoded weights, and
uses an auditable strict RFC 8032 verifier. Its corpus covers 4,486 incomplete
prefixes, 10 boundary cases, 20 generated semantic cases, and all 19 committed
B1 semantic mutations. Rust parser-first exact decoders consume ordinary
validator-set/QC/TC raw bytes before strict Ed25519 verification. The protobuf
projection source-drift gate enforces the declared mapping while the separate
proto gate compiles the descriptor. B2 overall and `wire_conformance` remain
open.

## B2-B anchor/handoff certificate-kernel boundary (closed)

B2-B closes the next narrow parser and certificate-kernel slice. Its extension
manifest covers `BlockKindV0`, `BlockHeaderV0`, `HandoffDescriptorV0`,
`HandoffVoteSignV0`, `HandoffCertificateV0`, and the inert three-part
epoch-anchor kernel shape; it imports, rather than duplicates, the B2-A
ordinary QC and signature-share definitions. The B2-A scoped error taxonomy
plus six B2-B additions is disjoint, complete, and ordered exactly like the
37-code B2-A/B2-B Rust decoder prefix. Four B2-C additions extend the complete
B2-A/B2-B/B2-C prefix to 41 codes; B2-D adds three and B2-E adds four, yielding
the complete current 48-code Rust decoder taxonomy.

The independent Node.js structural decoder consumes six exact raw/derived
objects and rejects 3,435 incomplete prefixes, 13 boundary cases, and 25
semantic/relationship mutations. That fixture intentionally makes no crypto
claim. A separate public corpus supplies 11 artifact classes and 36 stable
negative cases with distinct old/new `4/3/2/1` Ed25519 validator sets
(`W=10`, quorum `7`), exact-threshold and one-below terminal-QC/old-role/new-
role cases, and independently reconstructed signing roots and relations. Rust
exact-decodes those raw objects before strict signature verification.

The three-part Rust decoder returns only a private-field
`EpochAnchorAuthorizationKernelV0`; its verification boundary returns
`Result<()>` and provides no anchor-producing conversion. The committed
candidate `EpochAnchorQC` bytes are therefore an interoperability field/byte
binding, not an authorized synthetic QC. Complete epoch authorization,
authenticated snapshot/state provenance and
committed set/parameter preimage reconstruction, PoP, upgrade/activation
authority, first-new-block rules, Proposal/Block canonical bodies,
evidence/receipts, network admission, light-client proofs, B2 overall, and
`wire_conformance` remain open. B2-C separately closes the exact inert
`NextEpochCommitmentV0` kernel, not those provenance or transition-
authorization obligations. B2-E separately closes only the ordinary old-set
checkpoint/two-seal semantic chain, not those external provenance or
authorization obligations. B2-F composes the exact supplied witnesses for
same-version fields 1--11, but still emits no anchor or activation authority.
B2-G closes exact PoP plus deterministic candidate/fallback calculation over
an unauthenticated transcript, not the missing state provenance.

## B2-C next-epoch commitment kernel boundary (closed)

B2-C closes the exact `NextEpochCommitmentV0` object and same-version v0
context-binding kernel only. Its manifest fixes 15 canonical CEV0 fields, the
derived protobuf digest, optional/nonzero-hash and fallback discriminants,
outgoing-schedule geometry, one projection, and four new stable decoder errors.
The B2-A, B2-B, and B2-C manifests partition their 41-code Rust decoder prefix
without overlap or omission. B2-D and B2-E extend that prefix with three and
four disjoint additions respectively; the complete current taxonomy has 48
codes.

The independent Node.js decoder consumes three committed raw objects, rejects
608 non-complete prefixes and all three trailing-byte variants, covers 25
parser boundaries and 21 context mutations, accepts two complete same-version
contexts, and produces zero authorization outputs. Rust exact-decodes and
byte-identically re-encodes the same raw values before digest comparison. Its
context method receives exact old/new validator-set and parameter preimages,
recomputes their bindings, checks adjacent epochs, immutable v0 epoch length,
snapshot cutoff, activation height, rollout redundancy, and full fallback
identity, then returns only `Result<()>`.

This closure does not authenticate the snapshot/state root, independently
reproduce a complete parameter preimage in the Node lane, prove governance/
upgrade authority, authorize an epoch anchor, or activate a new epoch. B2-G
separately executes candidate selection, lowest fallback reason and exact PoP
for caller-supplied unauthenticated facts. B2-E separately closes one
ordinary old-set checkpoint/two-seal semantic chain, but not authenticated
snapshot/runtime/set/parameter provenance or transition authority.
Certificate-only handoff verification likewise returns no anchor; production
proposal and TC admission remain fail-closed on all epoch anchors. B2 overall
and `wire_conformance` remain open. B2-F later binds those exact supplied
witnesses without adding snapshot provenance, anchor authority, or activation.

## B2-D ordinary block-validation kernel boundary (closed)

B2-D freezes the ordinary epoch-local body slice: exact
`ApplicationPayloadV0`, UTF-8 execution events with raw-key ordering,
execution-derived `ExecutionReceiptCommitmentV0`, mandatory
`DoubleVoteEvidenceV0`, EvidenceId ordering, payload/receipt/evidence ordered
roots, checked logical block size, and ordinary Block/Proposal transport
roles. Rust consumes the committed valid header, payload, receipts, evidence,
and active-set preimage through the complete ordinary commitment capability;
it also exact-decodes the valid ordinary QC and reconstructs the valid
`ProposalWitnessV0` signing root and proposer signature. The independent Node
lane consumes the complete corpus, including all 24 proposal/QC negative
fixtures plus the active-context and size-boundary campaigns. Rust does not
claim to consume every proposal negative, and neither lane is a raw protobuf
`Proposal` decoder: proposal coverage is one next-view logical/projection
fixture only. Real Ed25519 evidence and valid-proposal signatures are checked
against their exact signing roots. Receipt bytes have no peer-supplied
protobuf authority.

Rust exposes bounded exact payload/receipt/evidence decoders and a separate
stable ordinary admission taxonomy. `ValidatedBlockCommitmentsV0` has private
fields and no decoder; it requires a Regular header, active parameter and
validator-set binding, canonical evidence order, acceptance by the
caller-supplied `SignatureVerifier`, caller-supplied receipt-to-payload
relations, all three committed roots, and equality-accepting size bounds. The
token does not attest verifier identity or intrinsically prove strict
Ed25519; production integration must pass
`trnm_consensus_crypto::StrictEd25519Verifier`, whose concrete path is covered
by the crypto corpus. Public receipt constructors mean success does not prove
execution or authorized-runtime provenance. Protocol integration must supply
receipts from the locally authorized deterministic runtime; the token also
does not authenticate parent state, fix or execute a runtime, decide the
still-unfrozen transaction-failure predicate, or authorize a vote or any
epoch/checkpoint capability.

The production prototype core still stores an opaque `Block` payload, but
`PayloadValidationResult::Valid` now carries this capability. Both ordinary
and synced callback paths require its block ID to match the exact request
before consuming the request generation; focused regressions cover both
mismatch paths. The simulator mints the token from its canonical body, typed
receipts, ordered evidence, active parameters/set, and the real B2-D validation
path. Authenticated parent/runtime provenance, canonical durable replay of the
complete body/context, checkpoint/seal bodies, remaining diagnostic evidence,
permanent terminal/conflict journals, transport admission, and B2 overall
remain open.

## B2-E checkpoint/two-seal semantic-kernel boundary (closed)

B2-E closes one ordinary, next-view-only old-set finality slice. The ordered
manifest fixes the complete 54-field, 341-byte `ConsensusParametersV0`
preimage and the `CertifiedHeaderV0`/`FinalityProofV0` forms used by
`checkpoint <- seal-1 <- seal-2`. Rust exposes bounded, exact,
root-exhausting decoders for all three surfaces. The proof decoder requires an
exact caller-supplied old validator set, decoded old parameter preimage,
`NextEpochCommitmentV0`, and authenticated checkpoint-parent timestamp; those
inputs are not inferred from peer bytes. Four B2-E additions extend the
complete stable Rust decoder taxonomy from 44 to 48 codes.

The semantic kernel first runs complete ordinary finality admission and then
requires the exact old-epoch checkpoint/seal geometry and block kinds, direct
ancestry, canonical scheduled leaders, positive bounded timestamp steps,
frozen empty payload/receipt/evidence roots on both seals, preservation of the
checkpoint state root, one repeated exact next-epoch commitment digest, and
the old schedule's snapshot-cutoff and activation-height relations. The shared
raw corpus contains real Ed25519 proposer and ordinary-QC signatures. Rust
exact-decodes it and passes the proof through
`trnm_consensus_crypto::StrictEd25519Verifier` before obtaining the
private-field inert `CheckpointTwoSealKernelV0`. The token has no anchor,
handoff-signing, new-context, vote, or transition-authority method. The corpus
is next-view-only; it adds no B2-E TC semantics, and B2-A remains authoritative
for ordinary TC behavior.

The committed `snapshot_state_root` remains only a consensus-authenticated
claim. B2-E does not prove snapshot ancestry from the cutoff header,
JMT/ICS23 membership, runtime identity/execution or receipt provenance,
governance, validator-set or parameter selection provenance, complete epoch-anchor/handoff/activation
authorization, or checkpoint body execution. The epoch-zero core does not
consume this B2-E token. B2-G separately proves deterministic candidate/
fallback and PoP relations over caller-supplied facts, not their provenance.
Permanent terminal/QC/conflict journals, checkpoint-
grade sync and complete ancestor delivery, transport admission, and light-
client verification remain open. The PoCO gates are wired into
`.github/workflows/trnm-poco-bft-v0.yml`, but have not yet run on GitHub. This
tranche does not complete P0, P1, B2 overall, or `wire_conformance`.

## B2-F same-version joint-handoff composition boundary (closed)

B2-F closes only `EpochHandoffProof` fields 1--11 for a same-version v0
transition composition. Its manifest imports the exact B2-B handoff objects,
B2-C next-epoch commitment, and B2-E parameter/set/finality objects. The
protobuf message is transport composition only: there is no aggregate CEV0
preimage, digest domain, digest field, or aggregate authorization.

Rust's `verify_same_version_joint_handoff_kernel_v0` checks the exact supplied
old/new validator-set and parameter preimages, the commitment, complete
checkpoint/two-seal proof, exact terminal header and certifying-QC digest,
descriptor, and independent old/new handoff roles. It rejects protocol changes
and a present upgrade hash because field 12 is excluded. Successful validation
returns private-field `JointHandoffKernelV0` bound facts. The generic verifier
does not attest its implementation identity; production must supply
`StrictEd25519Verifier`.

The independent standard-library Node gate locks all 11 projection fields,
consumes four source corpora and exactly 14 committed raw objects, constructs,
serializes, reparses, and strictly verifies distinct-set and exact-fallback
positive profiles, and rejects 10 semantic/cryptographic classes. Nine fail in
composition; the one-below-quorum case fails earlier in the exact decoder. The token
cannot mint `EpochAnchorQC`, authorize handoff signing, accept a first-new-epoch
proposal, advance finality, or activate the transition. Snapshot/JMT/runtime
provenance, candidate/fallback state provenance and governance,
checkpoint body execution, fields 12--14, complete anchor/activation authority,
and atomic core transition remain release blockers. B2-G separately supplies
inert deterministic calculation/PoP evidence for caller-supplied facts.

## B2-G deterministic candidate/fallback computation boundary (closed)

B2-G closes only the pure calculation relation over one caller-supplied
normalized snapshot transcript. It freezes exact
`ValidatorKeyProofOfPossessionV0` signing and wrapper bytes, normalized
contribution/candidate/transcript fields, canonical ordering and uniqueness,
maturity/expiry and decay, hierarchical relationship caps, PoCO/bond/raw
ceilings, deterministic bounded selection, rollout-specific weights, full-set
constraints, successful shadow carry-forward, numeric-minimum fallback reason,
and the exact current-configuration fallback.

Every contribution, eligibility/finality, relationship, registration/nonce,
jail, bond, old-set, parameter, rollout/governance, and cutoff fact is
caller-supplied and unauthenticated. B2-G does not decode or authorize the full
`ConsumptionCertificateV0` wire object. Exact PoP proves control of the bound
key under its frozen domain; it does not prove finalized registration,
freshness, eligibility, or cutoff-state membership. Invalid PoP invalidates
the complete tuple under reason `4`; it is not repaired by dropping that
candidate. A successful `shadow` result carries old membership/keys/weights
into the target-epoch wrapper with reason `0` and is not fallback.

The independent standard-library gate consumes the committed transcript/PoP
corpus and reproduces the Rust result under the same positive and retained
negative relations. Its frozen evidence count is 9 exact PoP objects, 1,744
rejected non-complete prefixes, 110 real Ed25519 verification checks, 4
positive rollout cases, 1 full-input permutation, 9 calculation boundaries,
14 atomic fallback cases, 14 retained PoP negatives, and 0 authorization
outputs. The Rust consumer additionally rejects noncanonical `S`,
noncanonical `R`, and a small-order public key through
`StrictEd25519Verifier`. Rust success yields only private-field inert
`CandidateSelectionKernelV0` computation evidence. It cannot mint an
`EpochAnchorQC`, authorize handoff signing or the first new-epoch proposal,
advance finality, activate a set, or transition the core.

The finalized cutoff header and cutoff-rooted JMT/ICS23 manifest projection
are closed by B2-H1/B2-H2. B2-H3a also closes exact kind-specific value
admission and an atomic next-version entry/manifest JMT planning kernel. The
next release-blocking join is production-path runtime/profile plus checkpoint
body/receipt execution provenance over those exact raw values, followed by an
authenticated normalized projection and fresh B2-G run. Only after that join may
the exact candidate/commitment/handoff evidence feed `EpochHandoffProof`
fields 13/14, epoch-anchor/activation authority, and an atomic core epoch
transition. Field 12 governed-upgrade authority remains separate.

## B2-H1 finalized-cutoff and Consumption Certificate wire boundary (closed)

The exact cutoff relation now yields a private-field token only after complete
`FinalityProofV0::verify` succeeds and the finalized ordinary header is at the
active parameter preimage's protocol-derived snapshot cutoff. It binds the
proof ID, header ID, and state root directly.

The complete normative `ConsumptionCertificateV0` logical wrapper is bounded
and exact-decoded. Rust and independent Node code reproduce the same body
CEV0, body digest, strict Ed25519 signature, signature-free certificate ID,
and complete 349-byte object. All 349 incomplete prefixes and trailing data
are rejected, together with intrinsic/context/billing/ID/key/signature
failures.

Application-state authority remains open: consumer-key authorization,
nonce/tuple/ID uniqueness, meter activation, settlement/measurement validity,
acceptance/revocation/challenge state, and complete cutoff namespace
projection are not proven here. JMT/ICS23 membership, non-membership and
namespace completeness plus authorized runtime/checkpoint execution must
close those facts before B2-G can be rerun on authenticated inputs or any
epoch authority can be minted.

## B2-H2 cutoff-rooted JMT/ICS23 namespace boundary (closed)

The existing checksum/lock-pinned AppHash v4 JMT implementation now verifies a
bounded PoCO snapshot manifest at one exact version/root. The manifest commits
the canonical entry count and ordered kind/key/value root. Every manifest
member must carry real ICS23 membership at that same root/version; explicit
absence queries must carry canonical, unique real ICS23 non-membership proofs.
Omission, duplication, reordering, proof substitution, wrong version/root,
manifest count/root drift, and an absence query naming a member fail closed.

`AuthenticatedPocoSnapshotNamespaceV0` can only be produced by joining that
verified namespace to `AuthenticatedFinalizedCutoffHeaderV0`, with exact
version=cutoff-height and JMT-root=cutoff-header-state-root equality. It binds
the finality proof/header facts, manifest root/count and verified absence
count, but exposes no candidate or transition authority.

JMT hashes key preimages, so prefix range proofs cannot establish namespace
completeness. B2-H2 therefore defines the manifest as the authoritative
projection; extra unreferenced leaves are ignored. Runtime write discipline
must still ensure every PoCO mutation atomically updates the manifest and must
decode/validate each raw value. Runtime/checkpoint execution, receipt and
state-transition provenance remain the next ordered blocker.

## B2-H3a semantic-value and atomic transition boundary (closed)

The fifteen snapshot kinds now share a bounded exact envelope and each has a
kind-specific payload layout. The logical key is derived from the exact kind
and identity. Full Consumption Certificate, PoP, validator-set and parameter
payloads reuse their existing exact decoders. Every source and next value is
decoded before a canonical compare-and-set mutation is accepted.

The atomic planner consumes and re-verifies the full B2-H2 bundle in the same
call, preventing token laundering through caller-normalized facts. It rejects
source root/count drift, wrong expected value, duplicate or unordered
mutations, stale target versions, physical-leaf compare-and-set drift, and
generic namespace-8 writes. Creates require revision 1 and updates the exact
successor. Post-state entry writes/deletes and the recomputed manifest share
one JMT `PlannedAuthUpdate`; a bounded planned-tree overlay verifies the
target can be re-proved within the H2 aggregate and per-proof limits without
cloning full tree history. An ordinary no-op carries the last manifest height,
while an explicit scheduled-cutoff refresh rewrites it even when empty.
Application stores only the bounded exact writes, replans them against the
supplied tree history, and requires the recomputed target root to match. An
equal live root/version therefore cannot transplant a history-specific
`TreeUpdateBatch` whose unchanged sibling `NodeKey`s do not exist locally.

This remains a storage kernel, not authorized runtime provenance. It is not
yet sealed into every application/persistent/migration/state-sync path; the
existing runtime does not bind the required protocol/profile/parent context;
checkpoint body/receipt execution is not frozen; and full cross-entry
application-state rules plus authenticated B2-G projection remain open. The
kernel intentionally emits no checkpoint binding: equal height/root values do
not establish chain scope, exact cutoff ancestry, execution, or receipt
provenance and cannot mint handoff, activation, or Core-transition authority.

## B2-H3b1 production persistence and restore boundary (closed)

The in-memory codec, SQLite startup/schema-migration loader, and ABCI snapshot
restore v3/v4 now share one exact namespace-8 projection validator. Before
activation, zero PoCO leaves is valid. Once any namespace-8 leaf exists, the
state must contain exactly one 47-byte manifest and only the manifest-named
physical entries; every key layout and kind-specific value exact-decodes, the
manifest count/root matches the complete physical set, and manifest height is
at most the committed state height. Hidden, duplicate, malformed and
unreferenced namespace leaves are rejected.

SQLite transition and empty-state replacement validate the planned target
projection inside the same `BEGIN IMMEDIATE` transaction after source-head
verification and before any domain or JMT row is written. Invalid plans roll
back without changing the committed head. The shared Node/Rust corpus binds
the physical manifest and entry keys and covers five persistence failures:
missing manifest, hidden leaf, future manifest, trailing semantic value, and
malformed namespace key.

This closes persistence and restore admission, not runtime authorization. No
production PoCO mutation source has yet been authorized, and chain/profile/
parent context, checkpoint execution and receipts, cross-entry application
semantics, and an authenticated B2-G rerun remain open as H3b2. H3b1 cannot
mint checkpoint, handoff, activation or Core-transition authority.

## B2-H3b2a production checkpoint authority boundary (closed)

The authority configuration is now a genesis-authenticated application object,
not an uncommitted local setting. Startup, repeated `InitChain`, and ABCI
snapshot v3/v4 restore reject absence or substitution. At the exact
authenticated epoch checkpoint, both proposal processing and finalization bind
the configured genesis/profile, chain ID, protocol v0, active set/parameters,
live validator lifecycle, contiguous parent AppHash, one sealed historical
scheduled-cutoff version/root/projection plus its manifest root/count,
block hash/time, ordered payload, exact execution
results, and resulting AppHash into one private capability whose canonical
length is `404 + chain_id.length` bytes (405..532); the fixed 21-byte-chain-ID
corpus is 425 bytes. The earlier 389-byte draft omitted the manifest root/count
and is noncanonical. Transaction bytes and encoded receipts are independently
bounded to 8 MiB, count is bounded by `u32`, and checked count/size rejection
precedes encoding and hashing. The checkpoint event and execution ID are
telemetry only and cannot reconstruct or authorize the private capability.
A performance-only four-entry `(JMT version, state_root)` cache rereads the
real root on hit and after load; cache hit/miss/eviction cannot change results.
First-version loading and key indexing remain optional derived-cache
optimizations rather than authority or H3b2b1 closure conditions.

This closes checkpoint context and receipt provenance only. It deliberately
rejects post-cutoff PoCO mutation and cannot authorize certificate admission,
key/nonce/tuple transitions, meter/settlement/evidence/governance updates,
authenticated candidate selection, handoff, activation, or a Core transition.
Those cross-entry rules plus the authenticated B2-G rerun remain H3b2b.

## B2-H3b2b0 pure semantic transition boundary (closed, non-authorizing)

One shared exact decoder now projects every H3a expected/next raw value into a
typed semantic fact before compare-and-set transition validation. The new
machine-readable contract fixes every state discriminant, block-height and
target-epoch boundary, the kind-3 `max_accepted_nonce` monotonic watermark,
immutable consumer-key/meter cores with one-way revoke/retire, and the legal
one-way settlement, registration, lifecycle, and rollout-approval graphs.
Facts without an explicit update graph are create-only, semantic no-op
revision bumps are rejected, and every one of the fifteen kinds rejects
deletion. Keys/meters may only be created unrevoked/unretired;
settlement/registration/lifecycle may only be created in state 1; rollout
governance may only be created proposed. Revision changes use exact create-1
or checked update-`+1`; `u64::MAX` is exhausted. None key/meter upper bounds
remain open through `u64::MAX`, while a billing end at `u64::MAX` cannot have a
strictly later acceptance height.

This kernel returns only a pure validation result. It does not authorize a
production business mutation or prove a funded-and-unused ledger, meter
task/output/caps/evidence, challenge decision ID, governance decision or
approval height, or previous validator registration nonce/history. The
  lifecycle `effective_height` is a monotonic declared value only at this
  boundary; H3b2b1 subsequently binds it to the authenticated transition target
  height. It cannot
produce candidate, handoff, activation, or Core-transition authority. Full
  H3b2b1 has since extended the authenticated data layouts/authorities and
  introduced one coherent operation planner. H3b2b2 derives the transcript from
  that authenticated projection and runs strict Ed25519 PoP verification plus a
  fresh B2-G calculation in the same call. The earlier unauthenticated inert
  B2-G token is not an input to that authority and must never be rebound.

## B2-H3b2b1 authenticated application-authority boundary (closed)

The frozen kinds 1--15 are unchanged. Kind 16 adds one exact
`trnm.poco.application-authority.v0` record to the namespace-8 manifest. Its
exact decoder and bidirectional cross-entry validator, production
`StrictEd25519Verifier` paths, pre-clone capacity admission, and common overlay
seal are implemented and gated. A projection without kind 16 remains
legacy/non-authorizing. Status strings, normalized truth cases, operation
summaries and caller side facts carry no authority; only exact raw state,
operation bytes, proofs and production-authenticated context can enter the
planner.

The application constructs a private operation context from the committed
parent height/AppHash, exact next height, chain/genesis, active epoch and
parameters, and the AppHash-authenticated governance signer-policy commitment.
Only that governance signer can submit a business operation; telemetry and a
generic operator role carry no authority. Operations run in transaction order
inside one block overlay and seal to canonical entry writes plus one manifest
write. They are merged with ordinary authenticated writes into the same single
JMT version/root, while SQLite revalidates the complete target projection
inside `BEGIN IMMEDIATE`. `snapshot_lead_blocks <= 8192` is enforced wherever
active parameters enter production, including genesis/live load, migration and
restore, so a scheduled historical cutoff cannot exceed retained JMT history.

Five non-prune automata are production-reachable through that exact validator/
crypto/capacity/seal path. The frozen shared-corpus schedule is:
two certificate branches with an H1 composite block (consumer-key
authorization, meter definition, provider registration and settlement
funding), H2 acceptance, H3 challenge open and H4 rejected or sustained
resolution; cutoff H6; governance proposal H1 then approval H2; validator
registration H1 then rotation H2; and settlement funding H1, release H2, then
rejection of a new funding attempt at H3 with `writes=0` and the H2 head
unchanged. These are sequence-local heights.

The canonical shared vector now carries the complete active-genesis AppHash/
history, raw operations, exact proofs, every source/successor full-JMT root and
manifest/entries root, and the negative no-write/head-unchanged outcomes.
Independent Node `check-final` and the non-ignored Rust production-store replay
consumer reproduce the same artifact; normalized case/status side facts remain
non-authoritative.

Replay state is a checked-count 256-level sparse-Merkle accumulator with
fourteen domain-separated nullifier families and fixed 8,230-byte exact
non-membership proofs. Generic deletion is still forbidden. Certificate,
consumer-key, meter and validator prune transitions currently exist only as
four isolated prune-transition/real-JMT test kernels.

Their useful retention boundaries cross epochs, but the production application
context cannot yet advance across epochs. Production reachability depends on
Core activation and the authenticated next-epoch configuration transition;
formal, unit or isolated-JMT witnesses MUST NOT be reported as production,
ABCI, or authenticated cross-epoch prune closure.

The lower-layer Node corpus still freezes 210 constraint cases (48 accepted,
162 rejected), while focused Rust tests cover the single-step JMT relation,
atomic rejection, equal-root/different-history replanning and stale-plan
rejection. Closure rests on the nine-sequence artifact: 18 successful
production/JMT steps, nine authoritative no-write/head-unchanged negatives,
independent Node reconstruction and non-ignored Rust production replay. The
formal lane adds eight atomicity invariants, six positive witnesses and two
retained mutants.

H3b2b1 is closed by the canonical nine-sequence raw corpus: 18 successful
production/JMT steps, nine authoritative no-write/head-unchanged negatives,
independent Node `check-final`, and a non-ignored Rust production replay
consumer. Permanent prune replay proves nullifier families 1, 10, 12, and 14
for certificate, consumer-key, meter, and validator identity respectively.
This boundary emits no candidate, B2-G, production cross-epoch prune closure,
handoff, activation or Core-transition authority.

## B2-H3b2b2 application-authenticated candidate boundary (bounded shared and ABCI/restart evidence landed; remaining closure in progress)

The production checkpoint path now holds one exact private historical cutoff
projection while constructing the checkpoint capability and immediately
reconstructing a fresh B2-G transcript. It repeats the full physical/
bidirectional authority audit, hard-codes `StrictEd25519Verifier`, and returns a
private `AuthenticatedPocoCandidateSelectionV0` binding checkpoint bytes,
candidate-parameter hash, canonical transcript/result digests and authorization
ID. Caller transcripts, generic verifiers, earlier B2-G tokens, current-head
state, status/events and normalized side facts are not accepted.

Kind 16 appends a bounded future-candidate registration family while preserving
all H3b2b1 bytes when the family is empty. Old-set membership alone is not
registration authority: proof-free carry requires an exact active,
non-revoked kind-9/history match. New and changed keys target the exact
successor epoch under strict PoP; changed keys retain the exact authenticated
predecessor nonce/history head and new identities have no predecessor.
Historical certificate providers require their exact retained active
registration and the PoP's own authenticated registration epoch, but need not
already be old-set validators.

The raw-to-B2-G mapping is fail-closed: finalized target approval selects its
exact role-2 parameters, absence carries exact active parameters as reason-0 no
change, and pending governance is ignored as authority. Historical certificate
epoch comes from finalized acceptance height. Only independent relationships,
accepted certificates without a pending challenge, and challenge-rejected
certificates contribute. Bond counts only for `active_slashable` with checked
`target_epoch + evidence_window_epochs < locked_until`; absent, unbonding or
insufficiently locked bond is zero. Jail applies while
`target_epoch < jailed_until`, with equality expired.

Retained historical certificates do not authorize stale usage to masquerade as
current. Epoch activation must atomically normalize kind-16 usage: retain only
the current rolling-span meter bucket and exact new-epoch consumer/provider,
task/provider and provider buckets; remove older buckets without relabeling or
copying amounts. The compaction helper/fixture exists, but production Core
activation cannot yet drive the active-configuration/kind-16/manifest/JMT
rollover, and source validation must not demand that a pre-rollover historical
bucket already equal the new epoch. This is an open H3b2b2a production gap.

The machine-readable shared contract and canonical two-scenario corpus now
land with independent Node raw-history/projection reconstruction and a
non-ignored Rust byte-for-byte JMT/one-call reconstruction consumer. The corpus
proves four mature reason-0 candidates, successor-epoch changed/new-key strict
PoPs and an authenticated pending-challenge reason-3 fallback. It does not make
the fixture-only epoch bootstrap production-reachable. A third control freezes
the jail-expiry equality boundary. Node recomputes the complete historical JMT,
requires exact physical namespace membership, exact-decodes every kind payload,
and runs the root-consistent rejection families frozen in the shared schema.

Both canonical outcomes now also pass one non-ignored production-path evidence
test. Independent application instances begin at the exact production-valid
epoch-0 empty-authority genesis, explicitly install the matching canonical
source at height 24 through the labelled test-only epoch bootstrap, and then
use the normal height-25 cutoff refresh, height-27 committed parent and
height-28 checkpoint. The private candidate capability from the execution path
used by `ProcessProposal` equals the independently reconstructed
`FinalizeBlock` capability. Equality also holds after V3 parent restore, after
a real periodic SQLite V4 cutoff-25 restore followed by parent 27, across
SQLite restart and cache miss/hit, and after fresh post-checkpoint restart
reconstruction from retained cutoff 25. A zero checkpoint block hash is
rejected without changing the committed head, pending block or cutoff
projection, and restart observes the same unchanged source. The height-24
bootstrap remains fixture authority only; it is not a production application
operation, Core transition or usage rollover. Targeted retained-history
evidence additionally advances the SQLite query floor with the production
pruning authority, physically removes cutoff 25, and proves rejection/fail-stop
after advancing the retained floor to 26, with head, pending state, source and
the pruned condition unchanged over two restarts.

The bounded mutation partition is closed except for a cache/restart TOCTOU
mutation beyond deterministic replay and a stronger AST/type-aware API-surface
gate. Production atomic configuration/usage rollover remains open. H3b2b3a now
adds crate-private post-execution and cutoff-only pre-header bridges over the
unified lead-3 chain: regular
parent 24, finalized cutoff 25, regular child 26, regular grandchild 27, and the
authenticated candidate produced by height-28 checkpoint execution. It
exact-decodes raw `FinalityProofV0` CEV0 against the authenticated old context
and parent timestamp, then freshly verifies it with strict crypto. Its seal
binds the H2 absence count only and therefore hard-requires that count to be
zero. Both paths derive the same private `NextEpochCommitmentV0`; the
cutoff-only path has no checkpoint block hash. A private two-phase native
checkpoint kernel now freezes payload/state/receipt/evidence roots and that
commitment before header construction, then exact-binds the native body,
receipts and `BlockHeader::id()`. It does not equate the ABCI/Comet header hash
with a native block ID. The pre-header capability retains the strict-H1
certified height-27 parent and consumes an opaque parent/post-state execution
authority rather than a naked state root. A crate-private raw consumer also
exact-decodes and strictly re-verifies checkpoint/two-seal/terminal/handoff
evidence, re-runs B2-F, and binds the result to the native checkpoint under an
application-private replay seal. Its dedicated checkpoint-28 reason-0/reason-3
vector is empty and state-preserving, so it does not claim shared-vector
coverage for non-empty runtime receipts. Its independent Node consumer
recomputes H3a/H2 ICS23, the native private seals, strict B2-E/B2-F, the
descriptor/certificate, and both old/new role signatures and quorums.
A separate application-private SQLite sidecar now stores one immutable
transition binding and checkpoint preparation slots keyed by
`(transition, checkpoint kind, height, view)`. It is independent of the
application store/JMT/snapshot path, uses WAL, `synchronous=FULL` and
`BEGIN IMMEDIATE`, makes exact reserve/bind replay idempotent, and
sticky/durably halts on a changed binding or a conflicting occupied slot.
Replay records are inert comparison material; crate-private durable reserve/
bind wrappers must reconstruct the in-memory authorities. Focused Rust tests
cover same-process reopen, conflicts, higher-view retry, corruption/future
schema, failed halt persistence, path separation and semantic replay; they are
not subprocess restart or external rollback-watermark evidence. This sidecar is not wired
to ABCI startup or the production host, covers checkpoints only rather than
seal 1/2, and is not signer persist-before-sign state. Production host/carrier
and sidecar-lifecycle integration, seal preparation, signer journaling, live
proposal/vote/signing plumbing, fields 12--14, activation, production cross-
epoch prune, and Core transition remain open.

## Release-blocking gaps by phase

### P0 protocol-freeze gaps

1. Obtain an independent consensus-engineer review and resolve every resulting
   normative conflict. The current author/model review is not independent
   exit authority.
2. Extend the closed B2-A/B2-B/B2-C/B2-D/B2-E/B2-F/B2-G/B2-H1/B2-H2/
   B2-H3a/B2-H3b1/B2-H3b2a/B2-H3b2b0/B2-H3b2b1 logical-schema/parser source of truth
   across the remaining
   B2 corpus. B1 full-object QC/TC real-Ed25519 unequal-weight exact-
   threshold vectors, ordinary certificate-kernel parser rejection, the
   narrow anchor/handoff certificate kernel, inert next-epoch commitment, and
   ordinary block-validation kernel, narrow old-set checkpoint/two-seal
   finality kernel, same-version joint-handoff composition, and deterministic
   candidate/fallback/PoP computation are closed;
   complete checkpoint/epoch proposal and block bodies, complete epoch-anchor/
   activation authority, the remaining H3b2b2 mutation/rollover campaign plus
   the remaining H3b2b3 production-host checkpoint/two-seal/handoff bridge,
   `EpochHandoffProof` fields 12--14 and remaining epoch/upgrade,
   non-DoubleVote evidence, network-envelope
   admission, and same-/cross-epoch light-client vectors remain missing. At
   least one implementation independent of both Rust and the current Python
   encoders must reproduce that remaining corpus.
3. Deepen the current bounded/symbolic formal evidence, including the closed
   application cross-entry/prune atomicity model, to the remaining crash
   points, repeated adversarial partitions, multiple skipped anchor views,
   weighted anchor timeouts, complete fallback/epoch transition, and multi-hop
   light-client cases. Retained failing mutants remain required for every
   safety mechanism.
4. Publish and gate a machine-readable source of truth for every frozen
   logical object and decoding bound; prose plus partial protobuf projection is
   not yet a complete interoperability contract.

### P1 deterministic-core gaps

1. The prototype direct-TC and first-arrival proposal-carried full-TC paths now
   persist the same complete multi-reference obligation, synchronize every
   ordinary reference, and apply each complete QC safety transition. Direct
   standalone QCs and proposal-carried ordinary justify QCs with missing parent
   context likewise share the exact immutable active target, bounded canonical
   backlog, persist-before-request, recovery re-verification/reissue, and
   monotonic rotation/clearing contract. At the durable finalized height,
   same-view conflicts halt before subsumption, different-view competitors are
   subsumed without state change, and a TC carrying such a stale competitor may
   advance only its authenticated timeout view. Direct/carrier/TC conflict
   handling is symmetric under pending signing, finalization, and recovery
   replay after full authentication. The remaining catch-up contract has two
   release blockers: gaps beyond `max_blocks` require trusted checkpoint/state
   sync, and coalesced finality must deliver the complete ordered ancestor
   sequence rather than only the latest proof. The historical observed-QC
   pairing cache is also bounded and volatile: a finalized-subsumed certificate
   retained only for diagnostics is not evidence-continuous across crash and
   must be replayed to reconstruct a later same-view conflict pair. Durable
   finality and signing state remain monotonic, but permanent cross-crash
   evidence/audit continuity is not implemented.
2. Signed inputs are now preauthenticated before the transactional core clone,
   and immutable payload storage is shared across clones with `Arc<[u8]>`.
   Production handlers nevertheless repeat the same cryptographic verification
   after admission. Remove that duplicate CPU work without allowing an
   unverified value to enter a safety transition, and finish bounded decode and
   authenticated-cache admission for the node boundary.
3. The specification now freezes `Valid`, retryable `Unavailable`, and
   terminal `DeterministicallyInvalid`, including non-poisoning alternate-
   source retry and durable fail-stop on authenticated/durable or terminal-
   result conflicts. The Rust callback is now the explicit three-result enum:
   `Unavailable` consumes one generation without poisoning the header, while
   terminal conflicts with a QC, full TC carrier, or pending vote cross a
   persist-before-effect safety-halt barrier. Same-token duplicates/conflicts,
   both QC/invalid arrival orders for a known header, TC retry, carried-TC
   collision, signer cancellation, and durable halt recovery have focused
   tests. Bounded block-ID-level terminal
   `Valid`/`DeterministicallyInvalid` facts remain part of safety-state schema
   v6 and survive crash and volatile block-tree eviction. Separately, a
   route/full-ID completion tombstone now persists all three callback results;
   `Unavailable` remains non-terminal and source-generation scoped even though
   its exact generation completion survives restart. This is still not the
   complete host-validation contract:
   `Block` carries an opaque payload rather than the full canonical
   transactions plus objective evidence and authenticated parent/runtime
   context; the bounded
   fact cache can eventually evict an old unprotected terminal result instead
   of retaining a permanent execution log. Authenticated direct/carrier/TC
   conflicts now share the durable halt path even under pending sign/finalize/
   replay work, but permanent cross-restart terminal non-retry, complete
   canonical validation context, and the broader remaining crash-race contract
   remain P1 blockers. An eager terminal `Valid` result received while
   finalization is pending now retains one bounded exact authenticated proposal
   in the live core. `FinalizationApplied` re-verifies every ordinary vote
   predicate and persists the finalization clear plus vote intent atomically;
   only its storage acknowledgement releases the signer, and recovery after
   that write resumes the exact root. The candidate is intentionally volatile:
   a crash before the atomic write cannot reconstruct canonical body, parent
   state, or frozen runtime context from the durable terminal fact, and must
   replay those inputs before retry. That cross-crash host replay contract
   remains a P1 blocker even though uninterrupted progress no longer needs
   leader/network retransmission. The new single-slot retry is intentionally
   finalization-specific; a `Valid` callback blocked by timeout signing or a
   different durable outbox still needs authenticated local proposal replay.
   The active runtime leaf policy is now frozen more narrowly than that
   remaining host gap. `trnm-runtime` exposes an opaque exhaustive
   classification with 21 transaction rejects and 7 authenticated-state or
   internal invariant faults. Transaction rejects are whole-block/no-receipt
   failures; invariant faults require fail-stop, and neither path can carry
   mutations or a failed receipt. `trnm-runtime` now also exposes
   `TryStateViewV0`/`try_execute_v0`: the real call produces either a successful
   receipt or an opaque attempt-failure token with no public constructor, and
   preserves the state view's typed read error instead of manufacturing an
   absent object or `RuntimeError`. The app-private, deliberately unwired
   planning adapter consumes authenticated execution inputs into the real
   attempt and carries the same token in both success and failure; promotion
   therefore accepts no second same-generation body/parent/runtime join. It
   returns the typed state failure unchanged without terminalizing it,
   promotes only the deterministic branch carried by that attempt, and turns
   success only into `AppliedRuntimeAttemptV0`. A separate
   roots-match capability must own that applied attempt before `Valid` exists.
   There is still no production constructor for the authenticated-input or
   roots-match facts. The bounded store slice has landed a typed self-head
   reader and an opaque runtime snapshot that owns one SQLite `Connection`.
   Inside one `BEGIN` transaction it validates the configured bindings,
   canonical committed height and app hash, query floor, latest authenticated-
   root version, and exact head-root/app-hash equality. Multi-key reads share
   that same snapshot, typed `finish` explicitly ends it, and snapshot begin
   uses maintenance `try_lock` rather than waiting behind maintenance.

   This is now bounded production validation-parent authority, not a general
   host/ABCI runtime-view adapter. Core privately freezes the exact positive-height
   parent header in its payload-validation request; the store consumes that
   capability and opens only when the committed height/root match. Synthetic
   genesis stays headerless and speculative/non-head parents return typed
   retryable source mismatch until a canonical overlay store exists. The
   bounded production validation cursor owns a private fallible
   `prior delta -> exact authenticated snapshot` view, while the general
   host/ABCI runtime view remains unwired. Legacy `load_object` has retained its
   old direct-read behavior, and the ABCI outcome policy does not consume the
   new snapshot. Each begin also does
   not repeat the startup full scan which rejects future orphan value/node and
   stale-index rows. The in-memory snapshot pin spans only one cloned
   `ApplicationStore` family, not independently opened handles or processes;
   an external rollback watermark and OS process lock remain absent.

   A legacy test-only inert regular-block traversal now owns an exact compared
   header/body/parent/configuration plus that one parent-bound snapshot. Its
   internal cursor alone derives raw outer transaction bytes, index, target
   height, and target `BlockId` from the retained body/header in order. The same
   snapshot authenticates the validator-lifecycle record and physical singleton
   and joins its active projection to the retained native set. It can
   produce a finished inert value only after the whole body is visited and the
   snapshot finishes successfully. A cursor classification is obtainable only
   by explicitly finishing the consumed traversal, so a finish error outranks
   cursor rejection as well as incompleteness; Drop yields neither a
   classification nor a capability. Each exact outer byte string is decoded as
   `SignedCommandEnvelopeV1` and checked with consensus-app-specific dalek
   `verify_strict` plus the existing chain and retained-header-time semantics against the exact signer list whose
   commitment is bound to the store. The exact inner bytes are decoded as
   `CanonicalTxV1` and joined to payload type, sender and nonce. Neither JSON
   layer is reserialized into authority. Signer-policy admission exact-decodes
   the Ed25519 point and rejects weak keys. Generic `verify_hex`, vote/QC, the
   live-node development oracle, and the PoCO `StrictEd25519Verifier` type stay
   unchanged; retained production history would require an explicit activation
   boundary for the narrower app acceptance set.

   A separate legacy test-only owning runtime session now consumes the same exact
   joined inputs and snapshot. It internally derives `ExecutionContext` from
   retained header/envelope facts, executes the real fallible
   `try_execute_v0` strictly in body order, and uses a `changes -> fixed parent
   snapshot` view. Successful runtime receipts are retained only as native
   receipt shape. Receipt mutations replace the session delta only after an
   atomic cloned-delta pass exhaustively checks account/task/fee/monetary
   canonical key/type/value relations plus unique keys, immutable object types,
   expected versions, and exact successor versions. Task mutations also reuse
   the runtime's complete status/field-group/version/height validator through a
   distinct opaque read-only failure type. The two-transaction positive proves
   that the second call sees the first call's private delta; reversed order, a
   deterministic second-call rejection, or a later state/receipt/mutation
   failure consumes the whole session and destroys every prior change and
   receipt. The failed session retains exact inputs, authenticated lifecycle,
   failed index, and decoded observation/transaction as one non-cloneable
   opaque value with no second input join or standalone-cause conversion. Both
   success and failure require explicit snapshot finish, whose error outranks
   the pending runtime/cursor cause.

   The successful legacy test-only path now encodes its complete private delta and
   plans the exact next JMT version on the same still-open SQLite transaction.
   It first runs the complete parent-state validator, accepts neither a caller
   target/root nor the latest-head planner, and exposes no plan unless explicit
   snapshot finish succeeds. A separate by-value comparator reconstructs
   native receipts from the retained raw body and real `RuntimeReceipt`s,
   hard-codes `StrictEd25519Verifier`, and exact-compares the four header roots,
   retained set/parameters, and `BlockId`. Positive two-transaction and empty-
   write controls, canonical state/receipt-root substitutions, and plan/
   completeness versus finish-error precedence are non-ignored; the query-only
   path leaves committed height/app hash unchanged. A same-path independent
   WAL writer control commits a competing exact-next sibling after the first
   runtime read and proves that the open session's later reads and JMT plan
   remain on the original parent snapshot until finish.

   The preceding legacy test-only finished-plan and root-matched values remain
   a separate evidence path with no production constructor or serialization.
   A bounded production cursor now has process-local finished-plan, matched,
   and owning-mismatch carriers. One consuming private bridge promotes those
   exact owners into `ExecutionOutcomeV0`, deriving generation from the
   retained Core request; a second derives a route/full-ID Core callback input
   for valid or computed-root-invalid outcomes while refusing any input for a
   comparator invariant. Neither bridge calls `Core::step` or provides
   `AuthorizedNativeCheckpointExecutionV0`, checkpoint, or ABCI authority. JMT
   plan application/persistence, non-runtime dispatch, pre-comparator failure
   promotion/deduplication, and host outbox/Core/ABCI callback delivery remain
   open. The Core
   block holder now matches the frozen proto body projection instead of carrying
   one legacy opaque payload: exact application-payload CEV0 plus ordered exact
   evidence-object CEV0 values are retained with the header, and the Core alone
   can construct the opaque validation request, including its exact positive-
   height parent header. A narrow app carrier consumes that request, opens the
   exact committed parent snapshot, loads the complete namespace-8 active set
   and parameters plus lifecycle on the same SQLite transaction, verifies their
   epoch/hash/header joins, and then enforces exact body decode, strict evidence
   verification, payload/evidence roots, and logical size. Application-payload
   exact decode is staged within authenticated `max_consensus_message_bytes`
   before its root is joined to the header. Non-canonical or root-mismatched
   source material is `Unavailable`; only a complete canonical, root-bound
   logical block above authenticated `max_block_bytes` is
   `DeterministicallyInvalid`. It accepts no naked
   set/parameters or caller height/root, opens no cache/second connection, and
   is process-local, non-cloneable, and non-serializable. Foreign parent root,
   configuration splices, and a sibling writer moving the committed head are
   covered; finish failure prevents the carrier from escaping. The exact Core
   request is first wrapped in a private owner. A host failure before snapshot
   begin returns that same owner directly; source or body-admission failure
   after begin closes with it, retaining the complete `ValidationId`, target
   block, and parent without mislabeling rejected body material as authorized.
   A finish failure replaces the pending source/invalid/invariant cause while
   preserving the request owner; no bare ID, generation, block, parent, or
   cause can reconstruct it. The original Core-issued
   `PayloadValidationRequest` and every `Clone` descended from that same object
   graph share one process-local Arc-backed atomic one-shot gate. Exactly one
   claimant in that graph may become the validation owner. Losing clones are
   suppressed/coalesced by the current private native-admission branch before
   snapshot open and before the
   `Unavailable`/`DeterministicallyInvalid`/`InvariantFault` taxonomy; that
   branch produces no classification or callback for them. This does not close
   process-wide full-`ValidationId` duplication: independently started Cores
   from the same obligation-free durable state may accept the same ingress and
   materialize separate request/gate object graphs, and public Core `Input` is
   not a capability callback. Different generations remain independent, while
   an existing old object graph remains suppressed after its one claim. This
   is not cross-instance or cross-restart exactly-once.
   This closes only the same-object-graph clone race and the
   caller/host-supplied configuration and pre-authorization owner-loss gaps for
   committed-head validation only, not execution or terminal authority.

   Core now privately binds `PayloadValidationRouteV0::Proposal` or
   `PayloadValidationRouteV0::Synced` inside each request. The app consumes the
   complete `Effect` and checks that the outer
   `ValidatePayload`/`ValidateSyncedPayload` variant matches that inner route
   before claim or host reads. An outer/inner wrapper splice is a transport
   invariant, does not consume a correctly wrapped clone, and is not a
   duplicate, `Unavailable`, or `DeterministicallyInvalid` outcome. Route is
   retained with the exact owner through open/body/cursor/runtime/post-state/
   comparator/disposition; no constructor accepts a naked bool or route.

   Core `SafetyState` schema v5, which is separate from application-store
   schema v5 below, introduced a canonically ordered
   `DurablePayloadValidationObligationV0` before either direct or synced
   validation effect may escape a `PersistSafetyState -> StorageAck` barrier.
   Each obligation binds the Core-selected route, full `ValidationId`, exact
   `SignedProposalV0`, exact `PayloadValidationParentV0`, and
   `first_recorded_revision`; the live invariant requires generation to equal
   that first revision. The acknowledgement reconstructs the request only from
   that durable record and its exact volatile proposal mirror. Core
   `SafetyState` schema v6 now adds a separately canonically sorted
   `DurablePayloadValidationCompletionV0` keyed by `(route, full
   ValidationId)`. Every direct or synced callback atomically replaces the
   exact obligation with a same-key completion before persistence. That record
   stores all three results, full `ValidatedBlockCommitmentsV0` for `Valid`,
   and `first_recorded_revision`, giving exact same-result replay durable
   idempotence across restart. Opposite-route reuse, source/owner splice,
   result conflict, or a different `Valid` commitment is invariant or a typed
   integration conflict and cannot overwrite the record. `Unavailable`
   completes only its exact generation, so a new generation for the same block
   remains legal. Completion tombstones are distinct from block-ID-level
   terminal facts. Exact synced cancellation removes its obligation behind the
   cleanup barrier without creating a callback completion. Safety halt clears
   obligations while retaining prior completions. There is no automatic
   eviction: registration reserves a future completion slot and the combined
   completion/obligation count is bounded by `max_observed_messages`.
   Complete signed-proposal durable size -- logical block plus exact certified-
   tail witness -- is bounded by authenticated
   `max_consensus_message_bytes`; the aggregate obligation bound additionally
   covers fixed route/ID/revision/parent facts and any exact parent header.
   Recovery validates every schema-v6 obligation and completion and then
   rejects a non-empty obligation set with `InvalidRecovery`; it does not
   reissue pending validation. Schema v5 is not implicitly migrated.
   Completion-only recovery suppresses exact result replay, but this closes
   durable pre-effect capture, cleanup ordering, and callback-result
   idempotence only, not crash replay/liveness, type-level callback authority,
   or callback exactly-once.

   Application-store schema v5 now adds a same-database durable reservation
   table keyed by `(route, full ValidationId)`. After outer/inner route
   congruence and the process-local claim, but before host or snapshot reads,
   one `BEGIN IMMEDIATE` transaction uniquely inserts that key or compares the
   existing row. A versioned, domain-separated raw-source fingerprint binds the
   complete ID and route to the exact target header/application payload/ordered
   evidence and exact parent source. Only a bit-for-bit congruent row
   coalesces/suppresses a duplicate across independently materialized request
   graphs or processes; a route, source, target, or parent splice under the
   same full ID is an invariant. The table is bounded to 65,536 rows with no
   eviction, while an exact duplicate still coalesces at capacity. State-sync
   snapshot creation transactionally clears this journal only in the temporary
   copy before checkpoint/VACUUM and verifies the exported copy is empty; it
   leaves the source database unchanged. This closes durable reservation and
   cross-instance source congruence only. It does not store an evaluated
   artifact/result, grant crash takeover, or provide process-wide callback
   exactly-once.

   The initialized `AppCore` can now privately lend that carrier one canonical
   signer-policy preimage after its commitment matches both store metadata and
   the same snapshot's authenticated lifecycle. A production sequential cursor
   then chooses its own retained-body index, strictly verifies the exact
   envelope, exact-decodes and validates the inner `CanonicalTxV1`, joins
   sender/nonce, and derives target height, native `BlockId`, header timestamp,
   signer id/role, and inner payload length. The prepared transaction owns the
   cursor and open snapshot and exposes no seek/repeat/skip, `into_parts`, or
   caller-supplied tx/index/context/view. A failed decode closes with the exact
   authorized owner, next internal index, private delta, and applied receipts,
   including work completed before a later item failed. A single consuming
   production attempt executes the real fallible runtime over the cursor's
   private delta followed by the same snapshot. Only successful native-receipt
   conversion and atomic full-mutation staging return the cursor at the next
   internal index. Runtime,
   typed state-read, receipt-conversion, or mutation-invariant failure destroys
   all prior delta/receipts but closes with the authorized owner, failed index,
   exact outer/inner bytes, decoded transaction, and derived context. In both
   stages finish failure replaces the pending decode/attempt cause while
   retaining exact ownership. Non-runtime payloads retain the
   open cursor/snapshot, exact bytes, verified envelope, and derived context in
   an opaque routing carrier and do not advance.

   Before complete-body planning, the runtime-only production cursor replays
   each retained real `RuntimeReceipt` mutation set separately and in order
   against the same authenticated snapshot. Cross-transaction repeated keys
   are accepted only through a continuous expected/next object-version chain;
   duplicates within one receipt are rejected. The resulting receipt-only map
   must exactly equal the cursor's canonical private delta, and the only legal
   parent-height-plus-one JMT writes are derived from that replayed map. The
   plan is sealed by an opaque process-local value over its exact version,
   root, nodes, values, stale-node indices, and key preimages. The snapshot then
   closes before returning the sealed finished plan. Incomplete-body,
   receipt-replay, authenticated-read, or planning failure closes with the
   exact authorized owner, next index, private delta, and applied receipts. A
   finish failure discards the pending cause and any successful plan/seal but
   not those owner/cursor facts. A single-input comparator
   rebinds retained receipt -> replayed delta -> exact plan, verifies the seal
   before any root mismatch, rebuilds native receipts, and invokes the ordinary
   commitment kernel with hard-coded strict Ed25519. Root computation, seal, or
   other post-authorization payload/evidence, static-commitment, `BlockId`,
   provenance, or internal drift is invariant/fail-stop. Its only process-local
   owning classifications are `Valid`,
   `DeterministicallyInvalid(State|Receipts)`, and `InvariantFault`, and every
   branch retains the complete owner. `SourceUnavailable` is structurally
   excluded because source admission precedes the comparator; no bare cause can
   reconstruct authority. The open/reservation/decode/runtime/planning failure
   carriers are likewise private, non-cloneable, non-serializable, and expose no
   parts or standalone cause. Exhaustive owner-derived mapping now retains each
   complete failure while classifying typed dependency/source/capacity loss as
   `Unavailable`, verified body/transaction invalidity as whole-block invalid,
   and authenticated/internal drift as fail-stop. It still grants no checkpoint,
   Core callback, persistence, or ABCI authority.

   The exact `BlockId`, peer body, positive-height parent header, and committed-
   head active configuration plus authoritative tx decode/index/context and
   runtime-gated success-only advance, same-snapshot complete-body planning,
   and four-root comparison now come through one bounded production
   join/cursor chain.
   Synthetic genesis/native state authority, speculative-parent overlays,
   non-runtime family write sealing/multi-operation cursor advance, JMT plan
   application/state persistence, durable host
   callback-outbox scheduling/delivery, actual Core callback execution, and
   ABCI wiring
   remain hard gaps before terminal/Core callback and still have no production
   constructor. A consuming dispatcher derives only PoCO application,
   validator transition, or unsupported from the retained verified envelope;
   its consuming semantic step now strict-decodes canonical PoCO operations and
   validator transitions, binds retained envelope/context facts, and preserves
   the exact owner on mismatch. A subsequent consuming attempt constructs the
   PoCO overlay from the pinned authenticated projection and schedules a
   validator transition against the retained authenticated lifecycle, while
   binding the decoded PoCO value back to the exact retained raw bytes. No
   caller-supplied source loader exists. Every semantic/family failure explicitly
   finishes the snapshot before exposing its closed owner, with finish failure
   outranking the pending cause. Authenticated-source loss and independently
   proven deterministic authorization failures are typed. Validator scheduling
   also exposes a closed deterministic/invariant reason set, checks nonce and
   delay overflow, and commits its clone only after postcondition validation.
   PoCO application now exposes a closed deterministic/invariant apply reason
   set: exact owner binding, height/revision, capacity/duplicate, nullifier
   proof, validator-rule, validator-PoP, and signed semantic-change paths are
   typed without diagnostic string matching. A proven missing authority fact
   is deterministic; a present-but-malformed companion, malformed authenticated
   semantic predecessor, or derived CAS/mutation failure is invariant. Unrefined leaf failures remain conservatively classified as
   authenticated-overlay invariants. Decision-ID and cap/window failures are
   deterministic. Nullifier shape/key rejects and an exactly key-bound proof
   that fails its authenticated root check remain distinct deterministic
   reasons, while authenticated nullifier-count exhaustion is invariant;
   counter/epoch/retention arithmetic exhaustion is likewise invariant.
   Consumer-key authorize/revoke signed-shape failures are now deterministic,
   and a missing authenticated key companion is the distinct deterministic
   missing-fact reason. Revocation binds its signed logical key to the body,
   classifies present old semantic/key-authority divergence as an authenticated
   invariant, and retains deterministic signed-successor rejection; existing
   typed failures pass through unchanged, so
   consumer-key prune now shares the pre-clone negative-fact rejection and
   keeps authenticated retention/certificate/nonce failures invariant, while
   signed prune shape and temporal/reference rejection remain deterministic.
   Meter definition now separates signed policy/semantic shape from protocol
   cap rejection and consumes one shared prepared policy/semantic transition
   across capacity admission and execution. For `DefineMeterPolicy` only,
   structural block/raw/aggregate limits and exact owner/context/revision/replay
   remain first; cheap field admission, signed preparation, and authenticated
   nullifier-count arithmetic precede family/defensive-total record caps; late
   nullifier-root verification and all mutation run only against the cloned
   candidate after those caps. Saturated/cap-minus-one collision tests freeze
   cheap-field/signed/counter rejection before record caps, record caps before
   late root rejection, and full-overlay rollback. The same closure now covers
   consumer-key authorization and fund settlement below; all remaining
   operation families still require capacity-order audits before terminal
   failure mapping. Meter prune has a
   typed pre-clone negative-fact reject.
   Meter retirement also splits signed next-state drift and negative/already-
   retired policy facts from authenticated old-fact/authority divergence.
   Meter prune validates signed IDs before its negative-fact lookup, separates
   nullifier and temporal/reference rejection, and keeps authenticated
   retention/certificate faults invariant.
   `FundSettlement` now types all remaining signed-shape failures while
   preserving its nested nullifier/counter/CAS failures unchanged. It also
   carries one prepared reservation/semantic transition across capacity
   admission and execution: structural and exact owner/context/revision/replay
   admission remains first; signed ID/commitment/units/semantic preparation plus
   authenticated duplicate checks and insertion-count arithmetic precede reservation/defensive-
   total record caps; certificate-absence and settlement-decision proofs plus
   mutation remain late on the cloned candidate. Saturated/cap-minus-one
   collisions freeze those boundaries and full-overlay rollback.
   `AuthorizeConsumerKey` now likewise carries one prepared authority/semantic
   transition across capacity admission and execution. Structural and exact
   owner/context/revision/replay plus cheap unsupported-field admission remain
   first; signed height/ID/key/derived-decision and exact-create semantic
   preparation with authenticated nullifier-count `+2` precede consumer-key/
   defensive-total record caps. Both insertion proofs and all mutation remain
   late on the cloned candidate. Canonical H1 apply/seal and saturated/cap-
   minus-one collisions freeze signed/authenticated, proof count/family/ID/root,
   counter, structural, body/carrier, exact-boundary and full-overlay rollback
   behavior; proof-key and encoding faults remain decode-first. The same
   closure also extends to `OpenChallenge` and `ReleaseSettlement` below.
   `ReleaseSettlement` now carries one exact funded-unused reservation/delete
   transition across capacity admission and execution. Structural and exact
   owner/context/revision/replay, signed certificate ID, and exact reservation
   lookup precede reservation-family `-1` and defensive-total record caps.
   Unsupported-field rejection, derived decision, one exact kind-6 delete with
   authenticated reservation/settlement agreement, and accumulator count `+2`
   then construct a carrier freezing the exact slot/value, family-1 certificate
   and family-3 settlement-decision subjects, and semantic delete. Only the two
   chained proofs, reservation removal, and delete mutation remain clone-late;
   cross-family, same-family body, and slot drift fail as derived postconditions.
   A real two-block fixture funds and commits four reservations, then releases
   one from the authenticated next block, proving 4-to-3, count `+2`, kind-6
   deletion, and seal. Its collision matrix covers signed/missing/unsupported/
   decision/authenticated/counter, both proof positions, structural bounds,
   carrier binding, and full rollback. Frozen `release_refund_replay` H2 bytes
   and H3 resurrection rejection remain unchanged; raw proof-key/encoding
   faults remain decode-first.
   `OpenChallenge` now carries one prepared pending record, challenge
   nullifier, and lifecycle semantic transition across capacity admission and
   execution. Structural and exact owner/context/revision/replay plus cheap
   unsupported-field admission remain first; signed/derived decision IDs,
   active-certificate/lifecycle/duplicate companion joins, lifecycle window,
   exact semantic preparation, and authenticated nullifier-count `+1` precede
   pending-challenge/defensive-total record caps. The insertion proof and all
   pending/semantic mutation remain late on the cloned candidate. Missing,
   malformed, or divergent authenticated lifecycle companions fail stop before
   a valid duplicate rejects as protocol; proof-key and encoding faults remain
   decode-first. The canonical H3 exact vector still applies and seals once.
   Saturated/cap-minus-one collisions freeze signed/authenticated, counter,
   cap-versus-proof count/family/ID/root, structural, body/carrier, sorting,
   exact-boundary and full-overlay rollback behavior. Their injected unrelated
   pending rows omit matching certificate, semantic, and nullifier provenance,
   so these are handler-boundary fixtures only and the success case is not
   sealable or authenticated end to end. `RegisterFutureCandidate`
   deliberately retains the schema's bound-before-cryptography rule:
   structural and exact owner/context/revision/replay plus validator-ID/
   duplicate admission precede future-family/defensive-total record caps. Only
   after those caps, but still before clone, come unsupported-field and
   authenticated nullifier-count `+2` bounds, checked successor epoch/target,
   exact strict PoP, active projection/predecessor/history/key joins, derived
   decision, and construction of one prepared record. The two insertion proofs
   and sorted record mutation remain late on the cloned candidate. A test-only
   authoring path builds four distinct exact successor-epoch registrations from
   authenticated epoch-zero configuration: the fifth rejects at cap even with
   later PoP/field/counter/proof faults, while the fourth from three succeeds,
   advances count by two, remains sorted, and seals. H22's two changed/new
   canonical operations remain the shared-vector witness rather than the cap
   witness; raw nullifier proof-key and encoding faults remain decode-first.
   `RegisterValidator` now also has a closed capacity order. Exact validator-
   ID/history absence and one canonical active kind-9 create bound to the body
   identity and a fresh consensus key retain their frozen pre-cap priority.
   This admission exact-decodes the embedded PoP structure without verifying
   its signature; the schema's cryptographic-work boundary here means strict
   Ed25519 and SMT proof verification, not the earlier canonical semantic
   admission. Validator-history/defensive-total record caps precede accumulator
   count `+2`, active epoch/derived decision, semantic CAS preparation, strict
   PoP verification, and one prepared history record. The identity-absence and
   two chained insertion proofs plus history/semantic mutation remain late on
   the cloned candidate. Four distinct active-epoch registrations are authored
   from authenticated epoch-zero state: the fifth rejects at cap over later
   counter/crypto/proof faults, while the fourth from three advances count by
   two, stays sorted, installs its kind-9 companion, and seals. Existing H1 and
   register/rotate vectors remain unchanged. `RotateValidator` now has a
   separate closed replacement path: shallow exact validator-ID/active-kind-9/
   body-identity/fresh-key admission still precedes family and defensive-total
   caps without performing strict signature verification. Rotation has zero
   record delta, so an authenticated four-record history remains admissible.
   Unsupported-field rejection, active-certificate exclusion, exact history
   lookup, revoked-history rejection, checked retired-key `+1`, checked
   accumulator `+2`, epoch, decision, semantic CAS, strict PoP/nonce, and
   predecessor head/nonce/history agreement follow in that order. A prepared
   carrier freezes the replacement record and slot, two nullifier subjects, and
   semantic change; only the chained insertion proofs and mutations run after
   clone. Its test-only witness commits four real registrations in one block,
   starts from the authenticated next block, rotates at the full family bound,
   preserves length/sort order, advances count by two, and seals once. The
   collision matrix freezes unsupported-field, active-reference, missing/
   revoked-history, retired-versus-accumulator counter, epoch/decision/CAS/PoP/
   predecessor, late-proof, structural, body/carrier, and full-overlay rollback
   priorities. The compound active-reference collision injects authority
   metadata only and therefore proves handler ordering, not a second
   authenticated success path. H1 and register/rotate H2 bytes remain
   unchanged. Capacity-order closure is now limited to `DefineMeterPolicy`,
   `FundSettlement`, `AuthorizeConsumerKey`, `OpenChallenge`,
   `ReleaseSettlement`, `RegisterFutureCandidate`,
   `RegisterValidator`, and `RotateValidator`; all other families remain audit-
   open before terminal failure mapping.
   `ResolveChallenge` now types its pre-clone pending/certificate join and
   separates signed resolution from authenticated pending/lifecycle drift.
   Governance proposal/approval now type their signed rules and pre-clone
   proposal join while keeping authenticated parameters/pending-fact drift
   invariant and preserving the exact missing-proposal reason.
   Certificate acceptance pre-clone admission now types signed certificate
   shape/proof, reservation/key/meter negative facts, nonce cap, and
   authenticated rolling-span/counter faults. The reservation/certificate/
   consumer-key/signature execution segment and every later companion join are
   now typed.
   The nonce semantic/provider-watermark join is now also typed. The unique
   tuple and meter-policy/semantic join now separates signed tuple drift,
   deterministic meter window/task/output/cap rejection, and authenticated
   meter companion corruption without string matching. The settlement and
   measurement join now types signed next-state/evidence drift, premature
   consumption, and authenticated funded-settlement/reservation corruption.
   The relationship/provider join now preserves exact authenticated negative-
   fact rejection, types unresolved/expired authority as a protocol rejection,
   and fails stop on malformed facts or registration-history companion drift.
   The lifecycle and four usage-counter joins now type signed lifecycle drift,
   authenticated numeric corruption, deterministic cap rejection, and checked
   usage/prune arithmetic exhaustion. Certificate acceptance has no remaining
   unclassified execution leaf. Future-candidate registration now types its
   pre-cap ID/duplicate admission plus the post-cap, pre-clone predecessor/
   history preparation, preserving validator-rule, cryptographic-proof, and
   authenticated-overlay provenance and determining its insertion slot before
   mutation.
   Validator registration/rotation now likewise types pre-clone semantic/key
   admission plus the registration-history join, preserving the exact active-
   key and missing-history reasons while separating signed validator rules,
   PoP rejection, protocol references/revocation, and authenticated companion
   drift. First registration now additionally moves one fully prepared
   history/create transition across clone after its record-cap boundary.
   Rotation also moves its checked-counter/strict-PoP-prepared full-history
   replacement across clone; only two insertion proofs and its exact slot/
   semantic mutations remain late.
   Validator revocation/history prune now likewise separate missing history,
   signed validator rules, retention/reference protocol rejection, and
   authenticated predecessor/reference corruption.
   Clone-before-capacity admission now checks the first-registration identity
   and both prune identities/targets before record deltas, binds the one active
   kind-9 successor to the body validator identity, and preserves exact replay
   as `DuplicateOperation` before state-dependent checks. The cloned history-
   prune candidate separately rebinds the exact revoked key/nonce/proof
   predecessor and treats signed body/delete-identity mismatch as
   `ValidatorRule`, so malformed, duplicate, or missing facts cannot collapse
   into a cap, checked-subtraction, or authenticated-state invariant.
   Certificate prune now types signed ID/delete-set drift, exact missing active
   authority, retention/live-reference rejection, and authenticated settlement/
   lifecycle companion corruption while preserving nested nullifier and
   postcondition reasons; no unclassified certificate-prune leaf remains.
   Leaf-reason completion remains a hard
   dependency before terminal failure mapping. The success carrier still owns the open
   snapshot and unsealed overlay/scheduled lifecycle. It does not yet seal
   writes, integrate successive family operations into the cursor, advance,
   emit a receipt, or promote a terminal result. The private consuming bridge maps `Proposal` only to
   `PayloadValidated` and `Synced` only to `SyncedPayloadValidated`, but it
   does not call a Core instance, persist state, deliver a callback, or enter
   ABCI. Reservation identity is already
   `(route, full ValidationId)`, but the future validation-time atomic boundary
   still must persist a versioned revalidatable evaluated artifact with its
   callback outbox, and the separate Finalize-time boundary still must
   revalidate exact authority and atomically apply JMT/domain state, persist
   roots/native head, advance the head, and mark the reservation applied.
   Core's completed validation-cleanup `StorageAck` and completion tombstone
   are not a host callback-outbox delivery acknowledgement. Authenticated
   replay tickets, completion retirement after durable host-delivery
   acknowledgement, speculative-parent/BlockTree
   reconstruction, application-reservation takeover, evaluated-artifact
   persistence, host callback-outbox scheduling/delivery acknowledgement,
   crash takeover, Core callback delivery, and those two atomic boundaries
   remain absent. Runtime now exposes a separate
   `try_estimate_resources_v0` call whose opaque estimate-failure token cannot
   be confused with a real execution-attempt failure: it preserves the exact
   typed state error, classifies deterministic failures without diagnostic
   text, never produces receipts or mutations, and keeps operator recovery
   estimation independent of the on-chain fee-policy read. The legacy
   infallible estimator remains the only application caller, so no simulation,
   ABCI, or terminal authority consumes this seam. Historical cutoff/projection
   reads retain their legacy error boundary, and the exact estimate-input
   carrier, runtime/terminal host wiring, and
   speculative-parent store remain absent. The
   current ABCI execution path still erases its errors, `ProcessProposal` has
   no `Unavailable` result, and `FinalizeBlock` has no typed non-success
   channel. Those store, estimate, carrier, and adapter integrations remain
   P1; neither `REJECT` nor `UNKNOWN` may be used to claim they are closed.
4. The exact inert `NextEpochCommitmentV0` object and same-version preimage
   relation checks now exist, and the epoch-zero core has an explicit
   checkpoint-height fence across ingress, signing, pending obligations, and
   recovery. The separate B2-E type/crypto layer validates one inert old-set
   checkpoint/two-seal finality kernel, and B2-F composes it with the exact
   commitment, old/new contexts, descriptor and both handoff quorums into an
   inert field-1-through-11 token. B2-G separately computes the deterministic
   candidate/fallback/PoP result for an unauthenticated caller transcript and
   also remains inert. H3b2b3a adds domain-separated private post-execution and
   cutoff-only derivations from the raw-exact-and-freshly-verified
   finalized-cutoff proof and raw parent/H2 evidence. Native runtime receipt
   mapping, checkpoint roots, a two-phase native header bind and a raw strict
   checkpoint/two-seal/B2-F private join now exist, but the core consumes none
   of these epoch tokens and no aggregate handoff CEV0 exists. A separate
   checkpoint-only SQLite preparation sidecar now durably reserves and binds
   exact checkpoint records, but it is not wired into startup/ABCI/the host,
   covers neither seal block, restores no opaque authority, and is not the
   signer journal. Production host/carrier integration, seal preparation,
   signer persist-before-sign state, seal voting,
   governed upgrade, anchor/activation authority, first-new-block rules,
   fields 13/14,
   and atomic core epoch transition remain unimplemented. Rejecting
   boundary data and epoch anchors is not epoch support.
5. The simulator now compares volatile, persisted, current-incarnation pending
   persistence, queued/durable proof, and application-acknowledged finality at
   every node and exercises the three callback outcomes through a scripted
   enum/effect scaffold. It also preserves standalone/TC replay-request
   identity and binds every replay continuation to a generation, so repeated
   requests continue one target while backlog or priority rotation invalidates
   stale events deterministically. It exercises standalone QC catch-up across
   a crash immediately after the durable acknowledgement releases the request.
   Its ordinary `Valid` path now carries a real private-field B2-D commitment
   capability, and a mismatched token cannot consume the callback generation.
   Its remaining P1 work is a canonical trace decoder/replay API, real
   multi-source/authenticated-parent/authorized-runtime validation jobs, the
   remaining persist/sign/broadcast
   crash points, stale
   storage/signer disagreement, unequal weights, heterogeneous certificate
   races, full epoch-transition campaigns beyond the new fail-closed boundary
   scenario, and checkpoint-backed ancestry recovery
   beyond `max_blocks` without the global in-memory archive.
6. Complete committed-parameter pacemaker behavior; exact evidence encodings,
   IDs, verification, and all conflicting-signature forms; bounded parameter/
   wire decoding before allocation; trusted-checkpoint and same-/cross-epoch
   reference verification; and removal or fail-closed isolation of legacy
   public consensus APIs that can bypass the v0 path.

### P2 real-node gaps

P2 has not started. There is no authenticated network, append-only WAL/signing
journal, remote-signer custody/watermark protocol, catch-up/state sync, or
runtime/JMT execution adapter around this core. Consequently no 4-/7-node
crash, equivocation, or partition/heal result is a real-node result yet.

P2 may begin only after the P1 safety gates are green. Immutable artifacts may
be compiled locally, but every persistent service, signing fixture, LAN/public
campaign, and soak MUST be deployed and exercised through ordinary SSH on the
X230 host named by the delivery runbook; none may run persistently on the
development workstation.

These gaps block network signing, node deployment, interoperability claims,
light-client acceptance, and P0/P1 completion. Passing prototype unit tests
does not waive them.

## Required closure order

1. Close the remaining P0 formal/vector/source-of-truth work and obtain the
   independent consensus review.
2. Extend the proved TC/standalone/carrier pending-sync closure to checkpoint-
   scale gaps and complete ancestor-finalization delivery; then remove duplicate
   authentication work at the bounded node boundary.
3. Extend the present durable Rust trichotomy scaffold with the complete
   canonical body/context contract, a permanent terminal execution log, and
   the runtime-specific transaction-failure predicate; then replace the
   scripted simulator outcomes with source/body-aware crash/replay campaigns.
4. Implement the complete epoch transition, pacemaker, evidence, decoder,
   reference light-client, and legacy-API isolation gates.
5. Only then add the P2 node shell, authenticated transport, append-only
   journal, remote signer, sync, and runtime/JMT adapters and run the remote
   X230 ladder.
6. Reproduce every remaining vector in an implementation independent from the
   Rust node before changing package metadata to `wire_conformance = true`.

## Prototype properties already worth preserving

- `no_std + alloc` and forbidden unsafe code;
- checked-`u128` quorum accumulation and `floor(2W/3)+1`;
- strict signer ordering, duplicate rejection, and weight recomputation;
- explicit `PersistSafetyState -> StorageAck -> RequestSignature` effects;
- transactional core steps, monotonic lock/high-QC/finalized state, validated
  ancestry before finalization, and persistent safety-halt intent;
- retained formal mutants for durable signing, duplicate weight, TC unlock,
  one-sided handoff, and uncommitted light-client sets.
