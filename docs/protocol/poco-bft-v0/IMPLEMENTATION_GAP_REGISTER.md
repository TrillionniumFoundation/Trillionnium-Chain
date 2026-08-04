# PoCO-BFT v0 Implementation Gap Register

Status: **release-blocking register**

Last audited: 2026-08-05

The normative documents in this directory remain ahead of the complete Rust
implementation. `trnm-consensus-types`, `trnm-consensus-core`, and
`trnm-consensus-sim` are P1 engineering scaffolds and MUST NOT be described as
fully wire-conforming, production consensus, or deployment-ready until every
critical item below is closed with vectors and tests. Their package metadata
deliberately reports `wire_conformance = false`.

## Foundation items closed on this branch

- Exact CEV0 prefix, checked `u32` frames/Bytes/Lists, primitive widths, and all
  18 frozen domains now match the independent Python foundation vectors,
  including the review-added handoff-descriptor domain.
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
- `ConsensusParametersV0` now covers the frozen 54-field logical value,
  discriminants, fail-closed safety inequalities, and exact 341-byte CEV0/hash
  vector. General v0 validation is separate from the P0 reference
  shadow-profile gate; TOML/wire decoding and governed activation remain open.
- Cargo tests reproduce the independent block ID, validator-set hash,
  proposal/vote/timeout roots, primitive encodings, and domain digests.
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

These closures are necessary but do not imply complete wire conformance.

## Prototype simulator evidence present on this branch

- `trnm-consensus-sim` currently passes 11 tests: 3 unit tests and 8
  deterministic scenarios.
- The finality oracle stores complete per-node applied chains, backfills newly
  finalized ancestors, and checks finalized-prefix comparability rather than
  only same-height tip collisions. Dedicated tests reject conflicting tips at
  different heights and accept different-height tips on one prefix.
- Application finality is recorded only after the core accepts
  `FinalizationApplied`; a monotonic simulator watermark records when the
  applied height and cleared finalization outbox have both been durably
  acknowledged.
- Scenario coverage includes 4-node one-offline progress/recovery, 7-node
  two-offline progress, 7-node three-offline stall followed by recovery, 2+2
  partition stall/heal, unacknowledged-persistence crash rollback, durable
  conflicting-QC halt/restart, and a running crash from nonzero durable state
  through real safety replay and synced-payload validation.
- The seeded fault scenario asserts actual consumption of one proposal drop,
  three vote duplications, two QC delays, and one message reorder. Trace entries
  retain full object identifiers, signatures, signing roots, and safety-state
  digests.
- The deterministic mock verifier is validator-key-aware, while explicit
  equivocation/conflicting-QC injection remains a privileged out-of-model
  Byzantine fixture.

This evidence does not close P1. The simulator remains epoch-0, equal-weight,
all-payload-valid, and dependent on global in-memory proposal/QC/gossip
availability. Its trace is diagnostic rather than a self-contained replay
input.

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

## Critical open protocol/type gaps

1. The corrected Rust `FinalityProofV0` type/verifier now exists, but the core
   and simulator still emit the obsolete internal `CommitProof`. That witness
   does not carry the signed proposal, exact justify-QC signer subset,
   skipped-view TC, or epoch-anchor authorization. It is hidden, uses a
   non-frozen internal domain, and must be replaced in the BlockTree,
   finalization outbox, replay, and application boundary before P1 closes.
2. Exact descriptor, two-role handoff certificate, epoch authorization, and
   epoch-anchor types now exist. Checkpoint/two-seal finality validation,
   `NextEpochCommitmentV0`, authorized upgrade, complete activation context,
   and core first-new-block/epoch-transition integration remain unimplemented.
3. Trusted synthetic unsigned `GenesisQC` is now separately typed and cannot
   enter an ordinary/certifying-QC slot, but the prototype core still accepts a signed
   quorum at view/height zero and an independently configured genesis block
   ID; the corrected freeze requires `synthetic_genesis_block_id =
   genesis_hash` and the one exact empty-signature QC preimage.
4. Signer, private-key custody, and remote-signer integration remain absent.
   The strict verification-only boundary and public valid/invalid vectors are
   now present, but they do not authorize network signing.
5. Durable rollback protection cannot be proven from a self-consistent safety
   snapshot. P2 still requires an append-only signing journal and remote-signer
   watermark comparison before any signing deployment.
6. Parameter decoding and activation-governance validation, evidence-ID,
   trusted-checkpoint/light-client, Consumption Certificate, and
   validator-key-PoP objects and rejection vectors remain incomplete.

These gaps block network signing, node deployment, interoperability claims,
light-client acceptance, and P0/P1 completion. Passing prototype unit tests
does not waive them.

## High-priority missing surfaces

- Bounded `ConsensusParametersV0` decoder and epoch-committed activation/
  governance validation.
- Core and light-client integration of the exact Rust finality proof, including
  retained signed proposals and transition binding.
- Checkpoint/seal/next-commitment/upgrade types and complete epoch-transition
  validation around the implemented descriptor/handoff/anchor values.
- Objective evidence IDs and all required conflicting-signature forms.
- Trusted checkpoint, same-/cross-epoch light-client verifier, and durable
  rollback protection.
- Consumption Certificate body/signature/ID and deterministic acceptance
  types.
- Cross-language vectors for every frozen logical object and rejection class.
- Complete simulator conformance: canonical trace decoding/replay, crash points
  after durable acknowledgement and around signature/broadcast,
  invalid/unavailable payloads, stale storage/signer disagreement, unequal
  weights, heterogeneous certificate variants, and epoch-transition campaigns.

## Migration order

1. **Completed foundation:** exact CEV0, frozen domains, `Signature64`, common
   context, validator-set commitment, `BlockHeaderV0`, Vote/QC/Timeout/TC, and
   Proposal. Every digest produced by the replaced prototype path is invalid.
2. **Type layer completed; core open:** make BlockTree/finality outboxes retain
   the implemented exact signed proposal justifications and preserve validated
   execution ancestry.
3. **Type layer completed; core open:** replace the core's signed genesis
   fixture with the separately typed trusted synthetic genesis. The strict
   Ed25519 verifier half is completed; signer integration remains a later
   deployment gate.
4. **Partial type layer completed:** integrate the descriptor, joint-handoff,
   authorization, and anchor values; implement checkpoint/seals,
   next-commitment, upgrade, and atomic epoch-transition state.
5. Add evidence, light-client, Consumption Certificate, parameter decoding/
   activation governance, and snapshot types.
6. Reproduce every remaining vector in an implementation independent from the
   Rust node.

Only after this order completes may package metadata change to
`wire_conformance = true`, and only after the remaining P1 gates may a node
shell consume the core.

## Prototype properties already worth preserving

- `no_std + alloc` and forbidden unsafe code;
- checked-`u128` quorum accumulation and `floor(2W/3)+1`;
- strict signer ordering, duplicate rejection, and weight recomputation;
- explicit `PersistSafetyState -> StorageAck -> RequestSignature` effects;
- transactional core steps, monotonic lock/high-QC/finalized state, validated
  ancestry before finalization, and persistent safety-halt intent;
- retained formal mutants for durable signing, duplicate weight, TC unlock,
  one-sided handoff, and uncommitted light-client sets.
