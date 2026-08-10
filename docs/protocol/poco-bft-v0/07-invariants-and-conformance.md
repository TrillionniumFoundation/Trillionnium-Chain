# 07 — Invariants, Formal Obligations, and Definition of Done

## 1. Status

This document freezes what must be demonstrated; it does not claim that the demonstrations already exist. P0 is not complete merely because prose has been written.

## 2. Safety invariants

The following properties are normative and ordered by safety priority.

### S1. Finalized-prefix agreement

For any two correct validators `A` and `B`, their finalized block sequences are prefix-comparable. Equivalently, correct validators never finalize conflicting blocks. Same-height uniqueness follows as a corollary.

### S2. QC validity and weighted intersection

Every accepted QC contains unique valid votes from the exact active set with recomputed weight at least `floor(2W/3)+1`. Any two such quorums for the same set overlap in more than one third of total effective weight. Under the fault bound, that overlap includes correct weight.

### S3. Durable non-equivocation

A correct validator signs at most one normal vote digest for each `(genesis, chain, protocol_version, epoch, view)`, including across crashes, restores, signer retries, and node/signer restarts.

### S4. Lock monotonicity and safe vote

Within an epoch, a correct validator's locked-QC view never decreases. It votes only for a descendant of its lock or for a proposal justified by a strictly higher QC.

### S5. Three-chain finality soundness

Only a valid direct chain of three certified blocks can trigger ordinary
finality, and it finalizes exactly the oldest block plus its ancestors. Every
certified header retains a verifiable proposer signature over its exact
justify-QC and optional TC/handoff digests; b1 and b2 cannot substitute a
different valid QC signer-subset digest for q0 or q1. Views may skip only with
the exact preceding-view TC, must strictly increase, and heights/parent links
may not skip.

### S6. TC non-finality and non-unlock

A timeout certificate can advance a view and select its maximum referenced valid high QC. It cannot certify, finalize, lower a lock, clear a lock, or authorize a vote that fails the safe-vote rule.

### S7. Certified ancestry

Every correct vote and finalization decision is based on locally verified parent ancestry and the exact justify certificates. Height equality or peer assertion never substitutes for ancestry.

QC ingress applies the same-view conflict rule before any finalized-height
shortcut. Two verified QCs in one epoch and view for different blocks durably
fail stop even if one block is already finalized or pruned. Subject to that
check, a delayed different-view QC for a different block at the finalized
height is finalized-subsumed: it creates no replay obligation and cannot change
`current_view`, `high_qc`, `locked_qc`, or finality. Reusing the finalized block
ID with different QC height or view coordinates is rejected as invalid.

### S8. Epoch isolation and joint handoff

Ordinary QCs and finality do not mix validator sets or protocol versions. The old checkpoint is finalized under the old set; exactly one bridge descriptor obtains both an old-set and a new-set quorum; no new-epoch normal vote occurs before that joint certificate.

### S9. Crash-state monotonicity

Recovery never lowers epoch, view, lock, high QC, finalized height, or the set of durable signing decisions. Ambiguous or corrupt recovery fails closed.

### S10. Deterministic execution roots

Given the same finalized parent state, parameters, and ordered payload, correct validators compute identical validity, state root, receipts root, and evidence root. A validator obtains and executes the full payload before voting.

Every correct host returns the same terminal `Valid` or
`DeterministicallyInvalid` result for one fully available validation context.
`Unavailable` is non-terminal: it neither poisons a header nor terminates its
retryable validation obligation. A source-scoped request token may be retired,
but a durable TC high-QC sync target is not cleared, and the result cannot
update `high_qc`, `locked_qc`, or finality. Once detected, a terminal-result
conflict, or deterministic invalidity colliding with a verified QC/TC reference
or durable safety anchor, is persisted before any further/result-dependent
effect and fails stop; it is diagnostic rather than slash evidence.

Payload, receipt, and evidence roots use the frozen indexed-leaf,
level-tagged-node, final-count-wrapped `OrderedRootV0` construction. Empty,
singleton, odd-width, and duplicate-right cases have one result; changing
item order, bytes, kind, index, level, or final count changes or invalidates
the commitment. Receipts are one-for-one with payload transactions, and only
canonically ordered `DoubleVoteEvidenceV0` values enter the v0 evidence root.

### S11. Light-client soundness

A light client starting from a recent correct trusted checkpoint accepts only descendants finalized according to the exact committed set sequence and joint transitions. It never accepts a set solely because that set signed itself.

### S12. Upgrade atomicity

At a height, all correct validators use the same protocol version and consensus parameters. A change occurs only at the committed epoch activation height through the joint handoff; unknown versions fail closed.

### S13. Canonical parsing and domain separation

Each accepted logical object has exactly one `CEV0` encoding. A valid signature or digest cannot be replayed across genesis, chain, protocol version, epoch, active set, view, message kind, or object domain.

### S14. Bond backing

For every non-shadow active validator, effective weight is no greater than raw PoCO capacity or bond capacity, and the counted bond remains slashable through the active/evidence windows.

### S15. Deterministic snapshot

All correct nodes given the same finalized snapshot state and parameters compute byte-identical next-set candidates, effective weights, fallback result, set hash, and epoch commitment.

### S16. Certificate uniqueness, maturity, decay, and caps

One certificate ID contributes at most once; immature, expired, revoked, challenged, or ineligible certificates contribute zero; hierarchical caps and decay are order-independent checked-integer functions.

B2-G supplies executable evidence for S15/S16 only as a pure function of one
caller-supplied transcript. It does not establish that the transcript is the
complete, authentic projection of the finalized cutoff state. That stronger
claim requires the later cutoff-header/JMT/ICS23 namespace and runtime/
checkpoint-execution provenance join.

### S17. Objective evidence idempotence

All correct nodes agree whether normalized double-vote evidence is cryptographically valid, and any disposition is applied at most once per evidence ID.

## 3. Conditional liveness properties

These properties are required only under the liveness assumptions in the threat model.

### L1. Post-GST view progress

After GST, timeout growth and valid QC/TC processing eventually place enough correct online weight in a common view with a correct leader.

### L2. Post-GST finalization

With a reachable correct quorum, available payload/state, compatible software, and recurring correct leaders, the protocol eventually forms direct three-chains and finalizes blocks.

### L3. Partition stall and heal

A partition lacking quorum may stall without violating safety. Once healed after GST, correct nodes converge on certified ancestry and resume without manual lock deletion.

### L4. Epoch-transition progress

If both the old set and committed new set have reachable correct quorums and
support the authorized versions, the checkpoint finalizes, the joint handoff
forms, and the new epoch progresses. Failure of the new epoch's initial
view-1 leader is recoverable by TC-driven view change while the authorized
view-0 epoch anchor remains the selected high QC.

No liveness property applies when a required new-set quorum is offline or the network remains asynchronous.

## 4. Formal-model obligations

P0 formal work MUST model the protocol independently of Rust implementation details. TLA+ and/or Quint models must cover at least:

- 4- and 7-validator configurations;
- equal and non-equal integer weights, including threshold boundaries;
- Byzantine proposals, votes, timeouts, withholding, and equivocation;
- message loss, duplication, reordering, partitions, and healing;
- crashes and recovery around every persist-before-sign boundary;
- high-QC and lock updates;
- delayed delivery of historical competing QCs at the finalized height,
  including proof that same-view conflict observation precedes finalized
  subsumption and that a different-view stale QC has no safety-state effect;
- TC construction with heterogeneous referenced high QCs;
- TCs carrying finalized-subsumed references, including a selected competing
  stale QC whose only permitted local effect is TC-authenticated view progress;
- skipped views and non-consecutive certified views;
- epoch checkpoint, both seals, joint handoff, fallback set, and first new block;
- a failed initial genesis/epoch leader followed by TC-driven first-block
  progress from the context-authorized synthetic anchor;
- authorized, premature, unsupported, and conflicting upgrades;
- light-client transition verification at the trusting-period boundary.

The model checker must establish at minimum S1–S9 and S12. Arithmetic/snapshot properties S13–S17 require executable property tests or a separate bounded model where appropriate.

Required mutant checks must demonstrate that the suite finds intentional defects, including:

- changing the quorum to `floor(2W/3)`;
- counting duplicate signers;
- allowing a TC to clear a lock;
- allowing two post-crash votes in one view;
- omitting genesis, set hash, view, or message kind from a signing digest;
- activating a new set with only one handoff quorum;
- activating before checkpoint finality;
- rounding PoCO arithmetic upward or applying caps in iteration order;
- accepting a self-signed uncommitted light-client validator set.
- omitting ordered-root kind/index/level/final-count binding or treating an
  odd duplicate-right leaf as an additional real item.

Initial bounded Quint artifacts now live in `formal/quint/poco-bft-v0`. The
four-validator safety kernel admits every nonempty vote batch, including
singletons, while exact quorum batches make legal finality reachable in four
steps. Its normal lock rule passes mutation-calibrated symbolic Apalache
checking through depth 10; disabling that rule exposes conflicting finality at
depth 8. The artifacts also cover an explicit
persist-before-sign crash boundary, and 4-/7-validator weighted-quorum
intersection (including non-equal weights). Small TC-lock and dual-quorum joint
handoff models plus retained negative mutants are also present. A dedicated TC
model now checks complete exact QC references, the
`(view, block_id, qc_digest)` tie-break, benign same-block QC variants, and
same-view/different-block fail-stop. A four-validator partition/heal model
checks safety under loss/delay/drop and includes a finite fair-heal progress
witness. A bounded light-client model rejects a self-signed uncommitted set and
checks the inclusive trusting-period/freshness boundary. The bounded upgrade
model covers finalized notice, checkpoint/two-seal order, both handoff
quorums, supported versions, activation height, and the first new block, with
a retained premature-activation mutant. A dedicated bounded anchor model covers
a failed view-1 leader, timeout quorum over the exact context-authorized anchor,
TC advance, and the view-2 first block at the unchanged activation height. Its
candidate-validation predicates reject a wrong selected anchor and attempts to
use an empty-signature anchor as a certifying/finality QC; this remains a model
of semantic acceptance, not a parser or cryptographic proof. These models do
**not** yet satisfy this section's complete obligation. In particular, no
dedicated Quint ingress model currently checks delayed same-height competing
QCs, same-view-halt-before-subsumption ordering, recovery with a durable
finality proof, or a TC whose selected reference is locally
finalized-subsumed. Deeper 7-node and repeated/adversarial partitions, multiple
skipped anchor views, weighted anchor timeouts, full fallback construction, and
multi-hop light-client sequences also remain required.

## 5. Wire and cryptographic conformance

Before a node claims protocol-v0 interoperability, the project MUST publish machine-readable golden vectors for:

- every `CEV0` primitive boundary and all frozen logical objects;
- all domain-separated digests and valid Ed25519 signatures;
- ordered-root empty/one/two/three/four-leaf cases for all kinds, framing and
  order mutations, odd duplicate-right behavior, and final-count binding;
- validator-set and parameter hashes;
- QC/TC exact-threshold and one-below-threshold cases;
- direct three-chain finality and malformed near-misses;
- checkpoint/seal/handoff/upgrade transitions;
- Consumption Certificate digest, ID, acceptance, maturity, decay, and caps;
- light-client same-epoch and cross-epoch proofs;
- wrong-chain/version/epoch/set/view/kind/domain replays;
- non-canonical, duplicate, overflow, unknown-enum, and trailing-byte rejection.

At least one implementation independent of the Rust node MUST reproduce the vectors.

### 5.1 B2-A certificate-kernel tranche

B2-A is the first independently closable parser tranche, not a claim that B2
is complete. Its exact object set is CEV0 primitives, `MessageKindV0`,
`CommonConsensusContextV0`, `ValidatorV0`, `ValidatorSetV0`,
`SignatureShareV0`, `VoteSignV0`, `QuorumCertificateV0`,
`HighQCSummaryV0`, `TimeoutSignV0`, `TimeoutEntryV0`, and the corrected
`TimeoutCertificateV0`, plus the validator-set, vote, QC, timeout, and TC
domains. Proposal/Block, synthetic-anchor authorization, epoch/handoff/
upgrade, receipts/evidence, Consumption Certificates, and light-client objects
remain outside B2-A and keep B2 overall open.

B2-A is closed only if all of the following are true:

- one ordered machine-readable manifest fixes every covered field, type,
  domain, enum, bound, and protobuf projection role as `canonical`,
  `redundant`, `derived`, or `sidecar`;
- an implementation independent from the Rust and existing Python encoders
  consumes the committed raw B1 bytes, parses exactly to EOF, re-encodes byte-
  identically, recomputes every covered digest, and validates the manifest and
  protobuf field projection;
- stable parser error codes plus byte offsets cover every non-complete prefix,
  trailing bytes, invalid version/enum/length/count, pre-allocation bound
  rejection, duplicate/noncanonical ordering, and the B1 semantic certificate
  mutations. The 128-byte ID and 100-item hard boundaries are accepted, while
  129-byte IDs, 101-item or larger declared counts, and overflowing nested
  capacities are rejected before allocation;
- Rust exact bounded decoders consume ordinary validator-set/QC/TC bytes and
  pass the decoded objects to strict Ed25519 and semantic verification; an
  empty-signature ordinary QC is never inferred to be a synthetic anchor; and
- a protobuf projection source-drift gate enforces the manifest mapping; the
  separate proto gate still compiles the descriptor.

These conditions are met for the listed certificate kernel. The independent
Node.js implementation consumed eight committed raw B1 objects, rejected
4,486 non-complete prefixes, 10 boundary cases, 20 generated semantic cases,
and all 19 committed B1 mutations, and used a strict RFC 8032 verifier that
rejects noncanonical encodings/scalars and small-order forgeries. Rust
parser-first decoders consumed the same validator-set/QC/TC raw bytes before strict Ed25519
verification. This is a B2-A closure only; every exclusion above remains open.

### 5.2 B2-B anchor/handoff certificate-kernel tranche

B2-B extends the closed parser surface only through `BlockKindV0`,
`BlockHeaderV0`, `HandoffDescriptorV0`, `HandoffVoteSignV0`,
`HandoffCertificateV0`, and the inert field/byte shape of
`EpochAnchorAuthorizationV0`. The ordered extension manifest imports the B2-A
certificate objects and fixes seven protobuf projections, four signing/hash
domains, every canonical/redundant/derived/sidecar role, and six additional
stable decoder errors.

The independent structural gate consumes six raw/derived objects, rejects
3,435 non-complete prefixes, 13 boundary cases, and 25 semantic/relationship
mutations. Its source fixture has opaque signatures and explicitly sets
`cryptographic_validity_claimed=false`; it proves exact parsing and mapping,
not quorum authorization. The separate real-cryptography corpus publishes 11
artifact classes and 36 stable negative cases over distinct old/new
`4/3/2/1` validator sets (`W=10`, quorum `7`). It independently reconstructs
and strictly verifies the terminal ordinary QC and both old/new handoff roles,
including exact-threshold and one-below-threshold cases.

Rust exact decoders consume the committed raw header, descriptor, certificate,
and three-part kernel before semantic or strict Ed25519 verification. The
three-part decoder returns only an inert `EpochAnchorAuthorizationKernelV0`
whose verification method returns `Result<()>`; it cannot construct, expose,
or authorize an `EpochAnchorQC`. The corpus fixes exactly one candidate anchor
field/byte binding so independently implemented encoders can agree on its
shape. B2-E separately closes only one ordinary old-set checkpoint/two-seal
semantic chain. Authenticated commitment/runtime/set/parameter provenance,
PoP, activation/upgrade rules, first-new-block authorization, network-envelope
admission, and B2 overall remain open. B2-F later composes the exact supplied
same-version fields 1--11 without producing an anchor or activation authority.

### 5.3 B2-C next-epoch commitment kernel tranche

B2-C extends the closed parser surface by exactly one logical object:
`NextEpochCommitmentV0`. Its manifest fixes all 15 canonical fields, the
derived protobuf digest, one projection, required nonzero hashes,
optional/bool/rollout/fallback discriminants, checked outgoing-epoch geometry,
and four additional stable Rust decoder errors. The 41-code B2-A/B2-B/B2-C
Rust decoder prefix is partitioned exactly across those three manifests;
B2-D and B2-E later extend the complete current taxonomy to 48 codes.

The independent Node.js implementation consumes three raw CEV0 values,
round-trips them byte-identically, recomputes their digests, rejects 608
non-complete prefixes and three trailing-byte variants, exercises 25 parsing
boundaries and 21 context relations, accepts two complete same-version v0
contexts, and yields zero authorization outputs. Rust consumes the same raw
objects through `decode_next_epoch_commitment_v0_exact`, re-encodes and hashes
them, then retains only a private-field inert commitment.

`NextEpochCommitmentV0::validate_same_version_context` receives exact caller-
supplied typed old/new validator-set and parameter contexts and returns only
`Result<()>`; authentication and provenance of those contexts remain external.
It checks their hashes and contexts, adjacent epochs, immutable v0 epoch
length, snapshot cutoff, activation height, rollout redundancy, and exact
fallback identity. It does not authenticate the snapshot, reproduce full
parameter preimages in the independent Node lane, select candidates/fallback
reasons, verify PoP/governance/upgrades, prove checkpoint/two-seal ancestry,
authorize an epoch anchor, or activate a transition. Those obligations keep
B2 overall open. B2-E separately closes one ordinary old-set checkpoint/two-
seal semantic chain, not the external provenance or transition-authority
obligations. B2-F later binds those exact supplied witnesses but does not add
snapshot provenance, anchor authority, or activation.

CEV0 frame and collection bounds govern this logical decoder.
`max_consensus_message_bytes` remains an outer, post-decompression transport-
body admission limit; it is not B2-A logical-object validity and MUST NOT be
used as a substitute for exact CEV0 bounds.

### 5.4 B2-D ordinary block-validation kernel tranche

B2-D extends the exact parser surface through the ordinary epoch-local body:
`ApplicationPayloadV0`, execution events and receipt commitments,
`VoteEvidenceRecordV0`, `DoubleVoteEvidenceV0`, all three ordered-root
families, and checked logical block size. Its projection gate also binds the
existing ordinary `ProposalSignV0` fields to the exact Regular block header,
the exact ordinary QC digest, an absent timeout certificate and digest, an
absent handoff digest, and absent epoch-anchor authorization.

Receipt values are caller-supplied typed commitments intended to come from
the locally authorized deterministic runtime; this kernel checks their exact
shape and payload/root relations but proves no runtime provenance. They are
not a peer transport authority. The standalone B2-D exact payload and receipt
decoders use the authenticated active `max_block_bytes`; the production root-
binding path described below instead stages payload decode within authenticated
`max_consensus_message_bytes` before applying the complete logical-block bound.
The reference-profile value 4 MiB is not promoted into an eternal protocol hard
cap. Declared collection counts
are rejected against both the active bound and remaining minimum encoded bytes
before allocation.

Rust's private-field `ValidatedBlockCommitmentsV0` proves only this static
ordinary commitment kernel: Regular kind, parameter/set context, canonical
body and evidence, acceptance by the caller-supplied `SignatureVerifier`,
caller-supplied typed receipt relations, three roots, and size limits. It does
not attest verifier identity or intrinsically prove strict Ed25519; production
integration must pass `trnm_consensus_crypto::StrictEd25519Verifier`, whose
concrete path is covered by the crypto corpus. It does not authenticate parent
state, execute or authorize a runtime, prove the active success-only receipt
policy, or authorize a vote, checkpoint, seal, handoff, anchor, or transition.
The prototype core still stores its legacy opaque `Block`, but a terminal
`Valid` callback now must carry this capability. Both ordinary and synced
validation paths reject a token for another block before consuming the request
generation, and the simulator mints every ordinary token through the real B2-D
body path. Authenticated parent/runtime/receipt provenance and complete durable
body/context replay remain open.

### 5.5 B2-E checkpoint/two-seal semantic-kernel tranche

B2-E adds one narrowly scoped old-set finality kernel. Its manifest freezes
the complete 54-field, 341-byte `ConsensusParametersV0` preimage and the
ordinary `CertifiedHeaderV0`/`FinalityProofV0` forms needed to express
`checkpoint <- seal-1 <- seal-2`. The Rust lane uses bounded,
root-exhausting exact decoders for the parameter preimage, each certified
header, and the complete proof. The proof entry point requires the exact
caller-supplied old validator set, decoded old parameters, next-epoch
commitment, and authenticated checkpoint-parent timestamp; decoding does not
establish the provenance of those inputs. Four B2-E additions extend the
stable Rust decoder taxonomy from 44 to 48 codes.

After complete ordinary finality validation, the specialized relation requires
the exact checked old-epoch geometry and block kinds, direct ancestry,
canonical scheduled leaders, positive timestamp steps no greater than the
active bound, frozen empty payload/receipt/evidence roots on both seals,
preservation of the checkpoint state root, one exact next-epoch commitment
digest repeated by all three headers, and snapshot-cutoff/activation-height
relations derived from the old schedule. The shared raw corpus carries real
Ed25519 proposer and ordinary-QC signatures. Rust must pass it through
`trnm_consensus_crypto::StrictEd25519Verifier` before receiving the private-
field inert `CheckpointTwoSealKernelV0`. The token cannot authorize an
`EpochAnchorQC`, handoff signature, first-new-epoch proposal or vote, new
validator context, or epoch transition. The fixture is next-view-only and
makes no B2-E TC semantic claim; B2-A remains authoritative for ordinary TC
semantics.

The next-epoch commitment's `snapshot_state_root` is only a consensus-
authenticated committed claim. This tranche does not prove authenticated
snapshot ancestry from the cutoff header, JMT/ICS23 membership, runtime or
receipt provenance, deterministic candidate/fallback selection, PoP,
governance, validator-set or parameter selection provenance, checkpoint body
execution, or complete epoch-anchor/handoff/activation authorization. The
epoch-zero core does not consume this B2-E token. Permanent terminal/QC/conflict
journals, checkpoint-grade sync and complete ancestor delivery, transport
admission, and light-client verification remain open. The PoCO gate set is
wired into `.github/workflows/trnm-poco-bft-v0.yml`, but no remote GitHub run
has yet exercised it. B2 overall, P0, P1, and `wire_conformance` remain open.

### 5.6 B2-F same-version joint-handoff composition tranche

B2-F closes only the same-version-v0 composition represented by
`EpochHandoffProof` fields 1--11. The ordered manifest imports the exact B2-B,
B2-C, and B2-E objects and explicitly defines no aggregate CEV0 preimage,
domain, digest, or authorization for the transport bundle. Every nested value
retains its own exact decoder and frozen hash/signing domain.

Rust's `verify_same_version_joint_handoff_kernel_v0` binds exact supplied old
and new set/parameter preimages, `NextEpochCommitmentV0`, the complete old-set
checkpoint/two-seal proof, terminal seal and exact certifying-QC digest,
handoff descriptor, and independent old/new handoff-role quorums. It rejects a
version change or present upgrade hash because upgrade field 12 is outside the
tranche. Success yields only private-field `JointHandoffKernelV0` facts. The
token has no anchor, signing, first-new-epoch proposal, finality, activation, or
transition method, and its generic verifier parameter does not attest verifier
identity; production must supply `StrictEd25519Verifier`.

The independent Node gate locks 11 protobuf fields, consumes four source
corpora and exactly 14 raw objects, constructs and reparses two positive
profiles (distinct set and exact fallback), verifies every nested digest,
weighted quorum and Ed25519 signature, and rejects 10 independent classes.
Nine negative bundles reach composition; the one-below-quorum bundle is
rejected earlier by the exact decoder under its committed code and offset.
Snapshot/JMT/runtime provenance, candidate/fallback selection provenance, PoP
and governance, checkpoint execution, fields 12--14, epoch-anchor/activation
authority, and the atomic core epoch transition remain outside B2-F.

### 5.7 B2-G deterministic candidate/fallback computation kernel

B2-G closes the pure candidate/fallback and validator-key-PoP relation for one
caller-supplied normalized snapshot transcript. The machine-readable schema
and independent Node lane freeze the contribution/candidate/transcript field
order and bounds, PoP signing preimage and domain, canonical ordering and
uniqueness, maturity/expiry and decay, hierarchical caps, PoCO/bond ceilings,
raw-capacity selection and byte tie-break, phase-specific effective weights,
individual/total/concentration constraints, successful shadow carry-forward,
numeric-minimum fallback reason, and exact current-configuration fallback.
Rust consumes the same committed inputs, verifies real Ed25519 PoP through the
strict verifier, and returns only private-field inert
`CandidateSelectionKernelV0` computation evidence.

The frozen B2-G evidence count is 9 exact PoP objects, 1,744 rejected
non-complete prefixes, 110 real Ed25519 verification checks, 4 positive
rollout cases, 1 full-input permutation, 9 calculation boundaries, 14 atomic
fallback cases, 14 retained PoP negatives, and 0 authorization outputs. The
Rust consumer additionally rejects noncanonical `S`, noncanonical `R`, and a
small-order public key through `StrictEd25519Verifier`.

The exact public input names are `UnauthenticatedSnapshotContributionV0`,
`UnauthenticatedSnapshotCandidateV0`, and
`UnauthenticatedCandidateSelectionTranscriptV0`; their `Unauthenticated`
prefix is a security boundary, not commentary.

The transcript is intentionally named and treated as unauthenticated.
Contribution eligibility/finality, relationship class, registration and
nonce freshness, jail and bond state, old set, parameters, rollout,
governance, target cutoff, and transcript completeness are caller-supplied
facts. B2-G does not exact-decode or authorize a complete
`ConsumptionCertificateV0`; PoP control of one exact key does not prove the
registration's state provenance or eligibility. A valid shadow result carries
the old ordered membership/keys/weights to the target epoch with reason `0`;
it is not fallback.

Success cannot mint an `EpochAnchorQC`, authorize handoff signing, accept the
first new-epoch proposal, advance finality, activate a configuration, or move
the core across an epoch. The next closure must bind the exact finalized
cutoff header to JMT/ICS23 proofs for a frozen snapshot namespace, including
membership/non-membership and completeness, then bind the authorized runtime
and checkpoint execution/state-transition provenance to that same state.
Only after that ordered provenance join may fields 13/14, anchor/activation
authority, and the atomic core transition close. Field 12 governed-upgrade
authority remains a separate open branch.

### 5.8 B2-H3b2b1 application-authority and atomicity kernel (closed)

H3b2b1 appends exact kind 16 without reinterpreting frozen kinds 1--15. Its
exact decoder and bidirectional projection validator, production strict
Ed25519 certificate/PoP paths, pre-clone capacity checks and common overlay
seal are implemented and gated. The private context binds the committed parent
AppHash and exact next height, chain/genesis, active epoch/parameters, and the
AppHash-authenticated governance signer commitment. Status strings, normalized
truth rows, sequence summaries and caller side facts have zero authorization
power.

Five non-prune automata reach production through the exact validator, strict
verifier, capacity gate and common seal. The fixed shared-corpus schedule
uses one H1 composite setup (consumer-key authorization, meter definition,
provider registration and settlement funding), H2 acceptance, H3 challenge
open, and H4 rejected or sustained certificate resolution with cutoff H6;
H1/H2 governance proposal and approval; H1/H2 validator registration and
rotation; and settlement funding at H1, release at H2, then rejection of a new
funding attempt at H3 with `writes=0` and the H2 head unchanged. These are
sequence-local heights.

The committed shared raw full-store evidence carries the complete active-
genesis AppHash/history, canonical raw operations, exact proofs, actual full-
JMT root continuity and successor manifests. It contains 18 successful
production/JMT steps and nine authoritative no-write/head-unchanged negatives;
independent Node `check-final` and the non-ignored Rust production-store replay
consumer reproduce it. A normalized truth case or status field cannot
substitute for that evidence.

The checked 256-level sparse-Merkle replay kernel has fourteen domain-separated
nullifier families and fixed 8,230-byte non-membership proofs. Four prune
transitions exist only as isolated prune-transition/real-JMT test kernels;
generic deletion remains rejected.

Because useful prune retention boundaries cross epochs and the production
application context cannot advance across epochs, production prune reachability
depends on Core activation plus an authenticated next-epoch configuration
transition. Unit, formal and isolated-JMT witnesses MUST NOT be reported as
production, ABCI, authenticated cross-epoch, or H3b2b1 closure evidence.

The 210-case Node constraint gate and focused Rust single-step/JMT tests remain
lower-layer evidence. The nine-sequence raw artifact—not those side facts—
closes the five full-store and four isolated prune-transition automata.

`poco_application_atomicity.qnt` adds eight named invariants:
all-or-nothing commit, exact committed target height, complete accepted-
certificate authority, nonce/registration-history monotonicity, at-most-once
decision/nullifier claims, atomic nullifier insertion before prune, replay
rejection after prune, and unchanged head after failure. Six bounded witnesses
exercise acceptance, challenge resolution, governance approval, validator-key
rotation, prune-then-replay rejection and rollback. CI must continue to expose
`partial_cross_entry_commit` and `prune_without_nullifier` as counterexamples.

H3b2b1 is closed by the canonical nine-sequence corpus, independent Node
reconstruction, and non-ignored Rust production replay. Candidate, production
prune closure, handoff, activation, field 12, fields 13/14 and the atomic Core
epoch transition remain outside H3b2b1.

### 5.9 B2-H3b2b2 application-authenticated candidate reconstruction (bounded shared and ABCI/restart evidence landed; remaining closure in progress)

The implemented production path uses one crate-private call to construct the
checkpoint-execution capability and reconstruct a fresh B2-G calculation from
the same private historical cutoff projection. It repeats the complete
physical/bidirectional authority audit, hard-codes `StrictEd25519Verifier`, and
returns a private result binding checkpoint bytes, candidate-parameter hash,
canonical transcript/result digests and authorization ID. No caller transcript,
generic verifier, earlier kernel, current-head state, status or event is an
input.

The conformance mapping is exact: proof-free old candidates require matching
active, non-revoked registration/history rather than old-set membership alone;
new/changed keys use the append-only successor-epoch future-candidate authority,
with changed keys binding the exact predecessor nonce/history. Finalized target
approval selects the exact role-2 parameters, while no approval carries exact
active parameters as reason-0 no change. Historical certificate epoch derives
from finalized acceptance height. Only independent, accepted-without-pending-
challenge or challenge-rejected certificates contribute. Bond requires
`active_slashable` and checked
`target_epoch + evidence_window_epochs < locked_until`; jail applies exactly
while `target_epoch < jailed_until`.

The shared raw schema and canonical two-scenario vector now exist. Node starts
from continuous physical history plus raw cutoff/head projection and
independently rebuilds strict PoPs, candidates, contributions, B2-G and the
checkpoint/transcript/result/authorization seals. A non-ignored Rust consumer
freshly rebuilds the same JMT fixture and one-call authority and compares the
entire committed vector. The positive covers four mature reason-0 candidates;
the fallback is a complete authenticated pending-challenge reason-3 source.

Both canonical outcomes additionally pass a non-ignored production-path test.
Independent applications start from the exact production-valid epoch-0 empty
authority; a clearly labelled test-only bootstrap installs the matching source
at height 24, after which the normal scheduler refreshes cutoff 25, commits
parent 27 and executes checkpoint 28. The private capability from the execution
used by `ProcessProposal` equals the independent `FinalizeBlock` capability.
The same result is reconstructed after V3 parent restore, after a real periodic
SQLite V4 cutoff-25 restore followed by parent 27, across SQLite restart and
projection-cache miss/hit, and freshly from retained cutoff 25 after checkpoint
commit/restart. Zero-hash rejection leaves committed head, pending block and
cutoff projection unchanged, including after restart.

The Node consumer now recomputes every historical JMT root, requires exact
physical namespace completeness, exact-decodes every kind payload, and executes
the root-consistent cutoff/root/manifest, PoP/nonce/key, lifecycle/relationship/
bond/jail and fallback seal mutations frozen in the shared schema. A targeted
SQLite test advances the retained floor to 26 and physically prunes cutoff 25
through the production pruning authority, proving ProcessProposal rejection,
FinalizeBlock fail-stop, two stable restarts and unchanged head/pending/source.
The remaining bounded
hardening is a cache/restart TOCTOU mutation beyond deterministic replay and an
AST/type-aware API-surface gate. The shared fixture's height-24 epoch bootstrap
is explicitly non-production and
does not prove a production application operation, usage rollover or Core
epoch transition.

Cross-epoch usage normalization is a separate required campaign. Meter usage
retains only the current rolling-span bucket and the three active-parameter
usage families retain only exact new-epoch buckets; historical values are
removed rather than relabeled. The helper and fixture boundary exist, but
production Core activation cannot yet drive the atomic configuration/kind-16/
manifest/JMT rollover. This remains an H3b2b2a production gap.

The current join does not consume the B2-H1 finalized cutoff-header capability,
proof ID or cutoff block ID. It proves application-authenticated candidate or
fallback reconstruction only. Complete finalized-cutoff authority,
`NextEpochCommitmentV0`, fields 12--14, handoff, activation, production cross-
epoch prune and atomic Core transition remain open.

## 6. Deterministic core conformance

The P1 core accepts explicit events and returns deterministic actions. Its trace corpus MUST include:

- proposal before/after lock changes;
- vote then timeout in one view;
- multiple timeout high QCs and deterministic TC selection;
- late QC after timeout;
- direct, proposal-carried, and TC-carried QCs at the durable finalized height:
  different-view competing QCs are operationally subsumed, same-view conflicts
  durably halt before subsumption, and a finalized block ID with mismatched
  coordinates is rejected;
- a TC whose selected QC is a finalized-subsumed competing block advances only
  the authenticated TC view and cannot authorize a proposal on the conflicting
  prefix;
- crash before persist, after persist, after sign, and before broadcast;
- stale disk/signer disagreement fail-stop;
- conflicting proposals and double-vote evidence;
- checkpoint, seals, handoff, first-new-block, and epoch-local reset;
- all three payload-validation results; missing/mismatched bodies and missing
  parent state remain retryable across sources; authenticated invalid-QC/TC/
  anchor collisions and `Valid`/`DeterministicallyInvalid` conflicts durably
  fail stop before effects;
- direct and synced payload-validation registration persists the exact durable
  obligation before `StorageAck` can release its validation effect; every
  callback result atomically replaces that obligation with a same-route/full-ID
  durable completion before persistence, while exact synced cancellation
  persists removal without fabricating a callback result;
- exact same-result callbacks remain idempotent after completion-only recovery;
  opposite-route, result, source, and full-`Valid`-commitment splices fail
  closed; `Unavailable` completes only one generation, and a later generation
  for the same block remains admissible;
- recovery validates schema-v6 obligations and completions but rejects any
  non-empty obligation set rather than reissuing it; safety halt clears every
  obligation while retaining prior completions in the same durable revision;
- the active-v0 success-only receipt policy: every one of the 21 exhaustive
  deterministic runtime transaction rejects invalidates the whole block and
  produces no receipt or mutation, while each of the 7 authenticated-state or
  internal invariant faults requires fail-stop rather than `REJECT`;
- deterministic runtime provenance comes from one real
  `TryStateViewV0`/`try_execute_v0` attempt and its opaque failure token whose
  constructor is private, not from a standalone caller-created `RuntimeError`
  or diagnostic string;
- the still-unwired app planning adapter consumes authenticated execution
  inputs into the real attempt and carries that same token in both success and
  failure, so no second same-generation join can be spliced; it passes a typed
  state-read error through without terminalizing it, promotes only the
  deterministic branch from that attempt, and represents runtime success only
  as an applied attempt; an exact
  roots-match capability must still own that attempt before `Valid` exists;
- host admission preserves the distinction between terminal whole-block
  invalidity and retryable `Unavailable`; in particular, no ABCI `REJECT` or
  `UNKNOWN` value may be used as an `Unavailable` surrogate;
- the authenticated runtime-object store slice has a typed self-head reader
  and an opaque snapshot owning one SQLite connection; one `BEGIN` transaction
  validates bindings, canonical committed height/app hash, query floor, latest
  root version and the exact head root, serves every key from that same
  snapshot, and ends through an explicit typed `finish`; maintenance begin is
  non-blocking through `try_lock`;
- Core privately freezes the exact positive-height parent header together with
  the exact target block in one payload-validation request; the production
  store constructor consumes that capability and opens only an exact committed-
  head height/root, while synthetic genesis remains explicitly headerless and
  a speculative/non-head parent is typed retryable source mismatch;
- the production validation carrier loads the complete namespace-8 projection,
  exact active validator set and parameters, validator lifecycle, and physical
  singleton from that same still-open parent transaction; set/parameter epochs
  and mutual hashes, lifecycle membership, target header commitments, and
  parent `BlockId` MUST all agree before body authority exists;
- that carrier accepts no caller-supplied height/root/version, second parent or
  body, naked set/parameters, generic verifier, cache, or second connection; it
  is private, non-cloneable, non-serializable, has no `From`/`TryFrom` or
  `into_parts` escape, and cannot convert to execution, terminal-result,
  checkpoint, Core callback, vote/finality, or ABCI authority;
- before body admission succeeds, the exact Core request MUST remain in one
  private owner; host failure before snapshot begin MUST return that owner
  directly, while source and body-admission failure after begin MUST close with
  the same complete `ValidationId`, target block, and parent; neither path may
  relabel the rejected body as authorized or be constructible from a bare ID,
  generation, block, parent, or cause, and a request or cause from another
  generation MUST NOT be joinable to that owner;
- the original Core-issued `PayloadValidationRequest` and every `Clone`
  descended from that same object graph MUST share one process-local Arc-backed
  atomic one-shot gate, and exactly one claimant in that graph may enter
  validation; the current private native-admission branch MUST suppress/
  coalesce losing clones before snapshot open and MUST emit neither an
  `Unavailable`, `DeterministicallyInvalid`, or `InvariantFault`
  classification nor a callback for them; this MUST NOT be treated as process-
  wide uniqueness by full `ValidationId`, because independently started Cores
  from the same obligation-free durable state may accept the same ingress and
  materialize separate request/gate object graphs, and public Core `Input` is
  not a capability callback; different generations MUST remain independent,
  while an existing old object graph MUST remain suppressed after its one
  claim; the gate alone MUST NOT imply any cross-instance, durable, or cross-
  restart exactly-once guarantee;
- Core MUST privately bind `PayloadValidationRouteV0::Proposal` or
  `PayloadValidationRouteV0::Synced` inside each request; native app admission
  MUST consume the complete `Effect`, compare the outer
  `ValidatePayload`/`ValidateSyncedPayload` variant with that inner route, and
  MUST perform this check before object-graph claim or any host read; a wrapper
  splice MUST be a transport invariant, MUST NOT consume the correctly wrapped
  clone, and MUST NOT become `Duplicate`, `Unavailable`, or
  `DeterministicallyInvalid`; route MUST remain owned through open/body/cursor/
  runtime/post-state/comparator/disposition, and no naked bool or route may be
  injected into those constructors;
- separately from current application-store schema v8, Core `SafetyState` schema v6
  MUST retain the schema-v5 obligation rule: canonically order and persist one
  `DurablePayloadValidationObligationV0` before either direct or synced
  validation effect escapes `PersistSafetyState -> StorageAck`; each record
  MUST bind the Core-selected route, full `ValidationId`, exact
  `SignedProposalV0`, exact `PayloadValidationParentV0`, and
  `first_recorded_revision`, and the live invariant MUST require generation to
  equal that first revision; acknowledgement MUST reconstruct the request only
  from the durable record and its matching volatile proposal mirror;
- complete signed-proposal durable resource size, comprising logical block plus
  exact certified-tail witness, MUST NOT exceed authenticated
  `max_consensus_message_bytes`; aggregate obligation accounting MUST also
  include fixed route/ID/revision/parent facts and any exact parent header, and
  arithmetic or resource-bound failure MUST occur before a new obligation or
  validation effect is admitted;
- Core `SafetyState` schema v6 MUST separately canonically order durable
  `DurablePayloadValidationCompletionV0` values by `(route, full
  ValidationId)`; every direct or synced callback MUST atomically replace only
  its exact obligation with a same-key completion before persistence, and the
  completion MUST retain its complete three-result value, full
  `ValidatedBlockCommitmentsV0` for `Valid`, and
  `first_recorded_revision`; exact same-result callback replay MUST remain
  idempotent after restart;
- an opposite-route reuse, source/owner splice, different result, or different
  `Valid` commitments under the same full ID MUST fail closed and MUST NOT
  overwrite a completion; `Unavailable` MUST close only its exact generation
  and MUST NOT prevent a new generation for the same block; completion records
  MUST remain distinct from block-ID-level terminal payload facts, which MUST
  retain only cross-generation `Valid`/`DeterministicallyInvalid` semantics;
- exact synced cancellation MUST remove only its matching obligation behind a
  cleanup `PersistSafetyState -> StorageAck` barrier without creating a
  callback completion; safety halt MUST clear the complete obligation set in
  the same durable revision and MUST retain prior completions; automatic
  completion eviction MUST NOT occur, registration MUST reserve the future
  completion slot, and `completions + obligations` MUST NOT exceed
  authenticated `max_observed_messages`;
- recovery MUST validate every schema-v6 obligation and completion and then
  reject a non-empty obligation set with `InvalidRecovery`; it MUST NOT reissue
  pending validation without an authenticated replay ticket, and safety-state
  schema v5 MUST NOT be implicitly migrated; completion-only recovery MAY
  suppress an exact same-result replay but Core cleanup/completion MUST NOT be
  represented as type-level callback authority, host callback-outbox delivery
  acknowledgement, or callback exactly-once;
- historical application-store schema v6 MUST durably reserve one
  `validation_jobs_v0`
  row for `(route, full ValidationId)` after wrapper/route congruence and the
  process-local claim but before host or snapshot reads; one
  `BEGIN IMMEDIATE` transaction MUST freeze the exact target header, strict
  versioned raw body record, parent tip and optional exact parent state,
  configuration references, the currently generation-derived creation
  revision, raw-source fingerprint, and distinct body/immutable/row checksums
  in state `reserved`; schema v6 MUST reject every non-`reserved` row and
  non-empty outbox; a congruent reopen
  MUST return the checksum-verified durable state and MUST NOT remint the
  first-reservation token; route, source, target, parent, configuration,
  revision, framing, state, or checksum drift MUST fail closed;
- application-store schema v7 MUST preserve every valid schema-v6 `reserved`
  row and additionally admit only `callback_pending` deterministic-invalid
  rows produced by the complete mixed-body comparator's computed state-root or
  computed receipts-root mismatch; no other invalid reason, `Valid`,
  `Unavailable`, `InvariantFault`, `evaluated`, `delivered`, `acked`, or
  `applied` state is active in v7;
- the v7 deterministic-invalid artifact MUST canonically bind the route, full
  `ValidationId`, request fingerprint, immutable-job checksum, closed result
  tag, and stable root-mismatch reason; the corresponding callback payload,
  idempotency key, and outbox row MUST bind that same route/full ID, result,
  and artifact checksum under distinct domains; decode/checksum consistency is
  an inert recovery fact and MUST NOT reconstruct Core callback authority;
- one `BEGIN IMMEDIATE` transaction MUST change a matching `reserved` job to
  `callback_pending`, store its deterministic-invalid artifact, insert exactly
  one congruent callback-outbox row, and update row/aggregate accounting; a
  crash or failure before commit MUST leave `reserved` with no outbox, while an
  exact committed retry MUST return the existing callback-pending state without
  double-accounting or reminting reservation authority;
- application-store schema v8 MUST preserve every verified v7 `reserved` and
  `callback_pending` row and additionally admit only two frozen
  deterministic-invalid delivery representations: `delivered` MUST retain its
  exact artifact and congruent outbox with canonical `delivery_attempt >= 1`
  while both accepted-Core fields remain absent; `acked` MUST retain the exact
  artifact, MUST have no outbox, MUST bind an accepted Core revision later than
  the job creation revision, and MUST bind the rederived canonical callback
  payload checksum; both later states MUST use the domain-separated
  `trnm.consensus-app.validation-job-delivery-row.v0` checksum, and their real
  row/outbox/accounting relationships MUST be revalidated at startup and
  recovery;
- schema v8 MUST continue to reject `evaluated`, `applied`, `Valid`, every
  unsupported invalid reason, `Unavailable`, and invariant results; a deeply
  verified `delivered` or `acked` recovery row alone MUST NOT mint a live
  callback owner, reconstruct Core authority, or permit job takeover;
- the process-local deterministic-invalid delivery path MUST consume only the
  live owner retained by the first successful deterministic-invalid seal; its
  app-private, non-cloneable driver MUST keep one designated store, one owned
  Core instance, and one injected safety sink fixed for the whole phase chain.
  It MUST call
  the route-specific real `Core::step`, require the exact
  `PersistSafetyState` barrier/state and matching completion, persist
  `delivered`, confirm that exact state through the same sink, persist `acked`,
  and only then issue the exact `StorageAck`. A completion-only/empty-effect
  callback MUST NOT authorize an artifact because the current Core completion
  tombstone does not bind its artifact or callback checksum. After
  `StorageAck`, the Core SafetyState MUST remain exactly unchanged and the release
  effects MUST be empty when that state has no safety halt or exactly the
  matching `SafetyHalted` effect when it does; every other state/effect
  combination MUST fail closed;
- the validation-job journal MUST be bounded at 65,536 rows and 512 MiB of raw
  request records with no eviction, and exact reopen MUST precede capacity
  rejection; migration MUST advance explicitly and serially through `v3 -> v4
  -> v5 -> v6 -> v7 -> v8`, with one `BEGIN IMMEDIATE` atomic boundary per
  fixed-version step; schema-v5 migration MUST proceed only when the legacy
  reservation table is empty, then advance through the reserved-only v6 format
  before v7 activation; a non-empty v5 table MUST roll back without deleting,
  rewriting, or fabricating replay fields, v6-to-v7 activation MUST fail
  atomically on any non-reserved row, outbox row, checksum, or accounting drift,
  and v7-to-v8 activation MUST deep-validate the complete v7
  reserved/callback-pending journal before changing metadata and MUST preserve
  v7 byte-for-byte on failure; restart
  recovery MUST enumerate all verified jobs in canonical state/identity order
  but MUST NOT treat those facts as reconstructed Core or evaluation authority;
  startup/recovery MUST
  exact-decode and canonically re-encode target and parent headers, rebind all
  duplicated identity/parent/configuration fields, and rederive the frozen
  request fingerprint; checksum-consistent semantic splices MUST fail closed.
  A headerless height-zero parent is only a structurally revalidated inert
  recovery fact: it MUST bind a height-one epoch-zero regular target to the
  target genesis hash, while the trusted genesis timestamp/hash authority
  remains Core-owned and MUST be reauthenticated before executable takeover;
- validation-job admission MUST use an atomically maintained O(1) accounting
  singleton for row/request-byte capacity, while startup MUST independently
  compare it with real `COUNT`/`SUM` facts; accounting drift MUST fail closed,
  and application-compatible parameters MUST have
  `max_block_bytes <= 16 MiB`;
- state-sync snapshot creation MUST transactionally scrub callback-outbox rows
  before validation-job rows from the temporary snapshot copy before
  checkpoint/VACUUM, MUST verify both exported tables are empty, and MUST leave
  the source database unchanged; installation MUST reject a non-empty target
  validation journal rather than silently discard target-local work; the
  raw job/fingerprint/checksums, v7 deterministic-invalid artifact/outbox, and
  v8 delivered/acked recovery facts MUST NOT be treated as signed-proposal
  reconstruction, JMT/terminal authority, recovery-reminted live-owner
  authority, executable crash takeover, SafetyState codec/WAL evidence, or
  process-wide callback exactly-once evidence. The current writable
  delivery/ack path and real `Core::step` integration are process-local test
  boundaries only: no production driver constructor, host/AppCore/ABCI/node
  wiring, durable safety sink, or process-wide Core uniqueness is implied;
- missing/pruned/foreign committed-parent sources remain retryable and distinct
  from authenticated-tree/physical-singleton/configuration invariants; no
  joined fact may escape unless explicit snapshot finish succeeds, and finish
  failure has priority over body/config/read failure; when finish fails it MUST
  replace the pending source/invalid/invariant cause while retaining the exact
  Core-issued owner, and no pending classification may leak alongside it;
- complete namespace-8 manifest membership, duplicate/unreferenced/hidden-leaf
  rejection, parent-root and configuration splices, and a separately opened WAL
  writer moving the committed head are non-ignored tests; the open carrier's
  reads remain fixed to its original parent snapshot;
- production application-payload admission MUST stage exact decode and root
  derivation within authenticated `max_consensus_message_bytes`; a non-
  canonical payload or payload/evidence-root source mismatch MUST remain
  retryable `Unavailable`, and only after the complete canonical body is root-
  bound MAY logical size above authenticated `max_block_bytes` be classified
  `DeterministicallyInvalid`;
- the bounded production validation cursor owns a private fallible
  `prior delta -> exact authenticated snapshot` view, while the general
  host/ABCI runtime adapter remains unwired, legacy `load_object` remains a
  direct read, and no production ABCI/outcome path consumes the carrier;
- a separate legacy test-only inert regular-block traversal owns the exact compared
  header/body/configuration plus that parent-bound snapshot; its only cursor
  derives raw outer bytes, index, target height, and target `BlockId` from the
  retained body/header in order; the same snapshot authenticates the
  validator-lifecycle record/physical singleton and joins its active projection
  to the retained native set; a finished inert value requires both full
  traversal and successful snapshot finish, and a cursor classification is
  obtainable only after explicitly finishing the consumed traversal, so a
  finish error has priority while Drop yields no fact; each item then uses
  command-envelope-specific dalek `verify_strict` plus the existing
  `SignedCommandEnvelopeV1` chain/header-time semantics against the
  exact store-bound signer list and decodes the exact inner `CanonicalTxV1`
  bytes with payload-type/sender/nonce joins, without reserializing either JSON
  layer as authority; signer-policy admission exact-decodes and rejects weak
  Ed25519 keys, while generic `verify_hex`, vote/QC, live-node and the PoCO
  `StrictEd25519Verifier` type remain unchanged; retained production history
  would require explicit activation for this narrower acceptance set;
- a separate legacy test-only owning runtime session consumes that exact joined input
  and snapshot, derives `ExecutionContext` only from retained header/envelope
  facts, executes real `try_execute_v0` calls in body order, and reads session
  changes before the fixed parent snapshot; successful runtime receipts are
  retained only as native receipt shape, and a cloned delta is committed to the
  session only after exhaustive account/task/fee/monetary canonical
  key/type/value validation plus unique-key, immutable-type, expected-version,
  and exact-successor checks all pass; task mutations also reuse the runtime's
  complete status/field-group/version/height validator through an independent
  opaque read-only failure type; the two-transaction control proves the later
  transaction sees the earlier private delta, while reversed order or a later
  cursor/runtime/state/receipt/mutation failure destroys all prior changes and
  receipts; the failed session retains exact inputs, authenticated lifecycle,
  failed index, and decoded observation/transaction in one non-cloneable opaque
  capability without a second join or standalone-cause conversion; explicit
  snapshot finish is mandatory on both success and failure, and its error has
  priority over the pending cause;
- the successful legacy test-only owning session encodes its complete delta and, on
  the same still-open authenticated SQLite transaction, fully revalidates the
  fixed parent before planning the unique `parent + 1` JMT version; neither a
  caller target/root nor the latest-head planner is accepted, and planning or
  completeness yields no finished fact unless snapshot finish succeeds;
- a legacy test-only by-value comparator reconstructs native receipts from retained
  raw body bytes and real runtime receipts, hard-codes
  `StrictEd25519Verifier`, and exact-compares state, payload, receipts, and
  evidence roots together with the retained set, parameters, and `BlockId`;
  positive two-transaction and empty-write controls, state/receipt-root
  substitution negatives, and finish-error priority are non-ignored, while
  the query-only planner leaves the committed height/app hash unchanged; a
  same-path independent WAL writer may commit a competing exact-next sibling
  after the first read without moving the open session's later reads or JMT
  plan off its original parent snapshot;
- before complete-body planning, a runtime-only production cursor replays each
  retained real `RuntimeReceipt` mutation set separately and sequentially
  against the same authenticated snapshot; duplicate keys within one receipt
  are invalid, while a key may recur across transactions only through one
  continuous expected/next object-version chain; the replayed final map MUST
  exactly equal the cursor's canonical private delta, and only that map may
  supply writes to the unique exact-next JMT plan; an opaque process-local seal
  MUST cover the exact plan version, root, nodes, values, stale-node indices,
  and key preimages, and the snapshot closes before the sealed inert finished
  plan can escape; incomplete-body, receipt-replay, authenticated-read, or
  planning failure MUST close with the exact authorized owner, next index,
  private delta, and applied receipts; snapshot-finish failure MUST replace the
  pending plan cause and discard any computed plan/seal without discarding
  those owner/cursor facts;
- the single consuming comparator MUST rebind retained receipt -> replayed
  delta -> exact plan, verify that complete seal before any header-root mismatch
  classification, and hard-code strict Ed25519 for ordinary static commitments;
  root/hash computation, seal, or any post-authorization payload/evidence,
  static-commitment, `BlockId`, provenance, or internal drift MUST be invariant/
  fail-stop; its process-local owning result MUST have only `Valid`,
  `DeterministicallyInvalid(State|Receipts)`, and `InvariantFault`, every branch
  MUST retain the complete owner, and `SourceUnavailable` MUST be structurally
  absent because source admission precedes this comparator; these carriers
  remain non-serializable/non-cloneable and have no conversion to
  `ExecutionOutcomeV0`, authorized-native-block, checkpoint, Core, or ABCI
  authority;
- the production exact-transaction cursor can only borrow its store, chain,
  and canonical signer-policy preimage from initialized `AppCore`; the policy
  commitment matches store metadata and the same snapshot's authenticated
  lifecycle before the cursor exists; index and outer bytes come only from the
  retained body, inner bytes only from that exact strictly verified envelope,
  and height/`BlockId`/time/signer/role/payload length only from the retained
  header and verified signer; the prepared transaction continues to own the
  cursor and snapshot and exposes no seek/repeat/skip, serialization, clone,
  parts conversion, or caller tx/index/context/view; the single production
  runtime attempt reads only `prior delta -> that same snapshot` and advances
  only after runtime success, native-receipt conversion, and atomic validation
  of the complete mutation set; decode failure MUST close with the authorized
  owner, next internal index, private delta, and applied receipts; runtime
  failure destroys all prior delta/receipts but MUST close with the authorized
  owner, failed index, exact outer/inner bytes, decoded transaction, and derived
  context; snapshot-finish failure MUST replace the pending decode/attempt
  cause without discarding those stage facts; non-runtime payloads retain exact
  bytes, verified envelope/context, cursor, and snapshot without advancing or
  becoming terminal invalid; none of these carriers converts into terminal,
  Core-callback, or ABCI authority;
- every open/decode/runtime/planning failed-close carrier MUST be private,
  process-local, non-cloneable, and non-serializable; MUST expose no
  `From`/`TryFrom`, parts, standalone-cause, or public constructor from naked
  authority fields; and MUST have no conversion to `ExecutionOutcomeV0`,
  `PayloadValidationResult`, authorized-native-block, checkpoint, Core, or ABCI
  authority; `SourceUnavailable` MUST remain confined to the owning open
  failure and remain structurally absent from comparator disposition;
- future orphan value/node/stale-index rejection still relies on the startup
  full scan rather than each snapshot begin; an in-memory pin spans one cloned
  store-handle family only, not independent handles or processes, and no
  external rollback watermark or OS lock has landed;
- runtime fallible resource estimation uses a distinct opaque failure token,
  preserves typed state-read failure without text classification, emits no
  receipt or mutation, and does not read the on-chain fee policy for operator
  recovery; the legacy infallible estimator remains the only application
  caller, so this is not production-path or terminal-authority evidence;
- typed historical cutoff/projection reads, the exact estimate-input,
  synthetic-genesis/native-state authority, speculative-parent overlays,
  non-runtime dispatch, JMT plan application/state persistence,
  owning-classification-to-terminal promotion, final typed retryable-versus-
  invariant host mapping, production host/Core callback wiring, and ABCI
  wiring/adapter remain open hard prerequisites and provide no terminal
  production execution-path conformance evidence yet; the object-graph gate
  performs no terminal mapping, and only the current private admission branch
  is proven not to emit a callback for a losing clone. The current consuming
  invalid bridge maps `Proposal` only to `PayloadValidated` and `Synced` only
  to `SyncedPayloadValidated`, and reservation/outbox identity remains
  `(route, full ValidationId)`. V7 closes the validation-time atomic boundary
  only for the two complete-body deterministic root mismatches. V8 adds the
  app-private process-local delivery writer, live-owner chain, real Core
  driver, and injected test sink described above, but no production
  constructor, durable SafetyState sink, recovery remint, or takeover. A
  revalidatable `Valid` artifact and callback-outbox intent remain open; the
  separate Finalize-
  time atomic boundary MUST revalidate exact authority and atomically couple
  JMT/domain apply, root/native-head persistence, head advancement, and applied
  state; authenticated replay tickets, completion retirement after durable
  host-delivery acknowledgement, speculative-parent/BlockTree reconstruction,
  application-reservation takeover, `Valid` evaluated-artifact persistence,
  production callback-outbox scheduling/delivery and SafetyState durability,
  crash takeover,
  process-wide callback exactly-once, and the `Valid` validation-time plus
  Finalize-time atomic boundaries remain open;
- parameter and arithmetic boundary failures.

Repeated runs with the same inputs must produce byte-identical logical outputs and final safety state.

The completed post-B2-F sweep passes 74 type tests, 15 crypto tests,
99 focused core tests, and 24 simulator tests (8 unit and 16 deterministic
scenarios), for 212 total tests across the four consensus crates. Synced replay
generation replacement is covered with real core-issued validation IDs: only
the exact stale volatile mirror and matching durable obligation can be removed
behind the cleanup persistence barrier, an overlapping block receives a fresh
current-generation ID, and neither callback ordering can leak a pending slot or
reuse the stale result.

The separate B2-G schema, independent transcript-computation/PoP gate, and
Rust calculation-kernel tests extend this baseline without changing the core
or simulator boundary. Aggregate counts are intentionally reported only by a
completed full sweep; the B2-G closure claim rests on exact shared artifacts,
cross-implementation output equality, strict PoP verification, and retained
negative cases rather than on a test-count threshold.

Two prototype boundaries remain explicit:

- if a terminal `Valid` callback arrives while durable finalization blocks the
  vote, the same incarnation retains one exact authenticated current-view
  proposal. `FinalizationApplied` re-runs the full proposal/ancestry/lock/
  watermark checks and atomically persists the finalization clear plus vote
  intent; `StorageAck` alone releases the signing request. Recovery after that
  write resumes the exact root. Recovery before it intentionally retains no
  volatile proposal and requires canonical body/context replay before a vote,
  so the complete durable host replay contract remains a P1 boundary. The
  autonomous slot is finalization-specific; timeout-signing and other durable
  outboxes still require authenticated local proposal replay after clearing;
- the historical observed-QC pairing cache is bounded and volatile. A stale
  finalized-subsumed QC retained only there is not evidence-continuous across a
  crash; replay is required to reconstruct a later same-view conflict pair.
  This does not weaken durable finalized/signing monotonicity, but permanent
  cross-crash evidence and audit continuity are not implemented.

## 7. P0 definition of done

P0 is complete only when all of the following are true:

1. The normative documents have no unresolved safety-affecting contradiction or implicit implementation choice.
2. Every `UNDECIDED` item is demonstrably outside the active safety path, causes fail-closed behavior, or is resolved before the phase that needs it.
3. `parameters.toml` parses and all documented cross-parameter inequalities hold.
4. Logical schemas, domains, canonical field order, thresholds, comparisons, and overflow behavior have golden vectors.
5. A TLA+/Quint model satisfies the required invariants and mutant checks in the bounded configurations above.
6. The threat model and safety/liveness assumptions are reviewed by a consensus engineer independent of the author.
7. The Consumption Certificate and weight formula are reviewed for deterministic behavior; no mainnet-economic claim is made.
8. Every normative conflict found by review is either repaired in this version or explicitly blocks P1 entry.

At the current P0 implementation point, bounded Quint models, a
mutation-calibrated depth-10 symbolic result for the four-validator S1 kernel,
independent Python parameter/foundational-wire encoders, and the B1 complete
QC/TC object corpus exist. B1 uses real RFC 8032 Ed25519 signatures, unequal
weights, exact-threshold acceptance, and one-below rejection, with Rust
reconstruction through the strict verifier. B2-A's ordinary certificate kernel
and B2-B's narrow anchor/handoff certificate kernel, B2-C's inert
next-epoch commitment kernel, B2-D's ordinary block-validation kernel, B2-E's
narrow old-set checkpoint/two-seal semantic kernel, plus B2-F's same-version
joint-handoff composition, B2-G's deterministic candidate/fallback/PoP
calculation kernel, and B2-H1 through B2-H3b2b0's cutoff/certificate,
namespace, production persistence/checkpoint and pure semantic boundaries are
closed with machine-readable schemas, independent raw-byte decoders and
corpora, Rust exact decoders/semantic kernels, strict verification, and
protobuf projection source-drift gates. H3b2b1 is closed by its exact kind-16
validator, strict crypto/capacity/common-seal path and canonical nine-sequence
shared raw corpus. H3b2b2 has landed its one-call application-authenticated
candidate implementation, bounded shared reconstruction corpus and canonical
ABCI/SQLite/cache/restart/V3/V4 plus targeted pruned-cutoff evidence. Its
remaining bounded hardening is a cache/restart TOCTOU mutation and a stronger
AST/type-aware API gate; production epoch-usage rollover remains open.
H3b2b3a/H3b2b3b now add the cutoff-only commitment and private native
checkpoint/two-seal/joint-handoff joins under a dedicated checkpoint-28 corpus.
Rust freshly verifies raw H1/H2/B2-E/B2-F, while an independent Node consumer
recomputes every H2 membership, native private authority seal,
descriptor/certificate and both handoff role quorums. These joins remain
outside the live consensus path. A separate application-private SQLite
checkpoint-preparation sidecar now provides WAL + `synchronous=FULL` +
`BEGIN IMMEDIATE`, one immutable transition binding, and
`(transition, checkpoint kind, height, view)` reserve/bind slots. Exact replay
is idempotent; binding or occupied-slot conflict sticky/durably halts; and
stored replay records cannot recreate an opaque authority. Focused Rust tests
cover same-process reopen, conflict, schema/corruption, path-identity, sticky-
halt and semantic-replay checks at that checkpoint-only boundary; they are not
subprocess restart or external rollback-watermark evidence. Production host/carrier and startup
integration, seal-1/seal-2 preparation, the signer-co-located
persist-before-sign journal, and live proposal/vote/signing plumbing remain
open; the sidecar grants none of those authorities.
B2 overall is not
closed. Machine-readable source-of-truth coverage for
complete checkpoint/epoch Proposal and Block bodies, complete epoch-anchor
authorization and activation, the remaining H3b2b2 hardening/rollover work plus
production-host integration for the landed finalized-cutoff and checkpoint-
handoff joins, handoff
fields 12--14, and the remaining epoch/upgrade objects,
non-DoubleVote evidence,
network-envelope admission, and light-client objects, symbolic coverage of
every required invariant/configuration, the remaining formal scenarios,
independent consensus-engineer review, and complete implementation evidence do
not exist. These gaps continue to block P0 completion and MUST remain visible
in project status.

## 8. P1 definition of done

P1 requires a pure deterministic core, reference verifier, fault simulator, crash journal model, property tests, and formal-model agreement. It must have no network, database, system-clock, or signer side effects in the core and must pass all trace/golden-vector obligations relevant to it.

## 9. P2 definition of done

P2 requires authenticated P2P, WAL/sign journal, remote signer, catch-up/state sync, runtime/JMT integration, and reproducible 4-/7-node campaigns covering crash, equivocation, partition/heal, restart, disk-full, corrupt/stale state, invalid chunks, and unavailable payload. Safety violations are zero-tolerance; expected quorum-loss stalls are not failures if recovery is correct.

## 10. P3 and P4 gates

P3 must complete shadow observation, anti-collusion simulation, bond/unbond/jail/slash semantics, economic parameter freeze, and external economic review before staged activation. P4 must complete multi-region 7-to-20-node campaigns, resource/DA/network attacks, 7–30 day soak, independent light-client verification, and external consensus/cryptography/economic audits.

No soak duration or test count substitutes for a failed invariant or unresolved safety ambiguity.
