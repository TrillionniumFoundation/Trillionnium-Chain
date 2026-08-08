# PoCO-BFT v0 golden vectors

Status: **partial P0 conformance evidence**

The committed vectors in this directory are reconstructed by implementations
that do not call the Rust consensus crates:

- `parameters-v0.json` freezes the complete reference
  `ConsensusParametersV0` CEV0 value and digest. It is checked by
  `scripts/ci/check_poco_bft_v0_parameters.py` and reproduced by
  `cd trillionnium && cargo test -p trnm-consensus-types`.
- `wire-foundation-v0.json` freezes primitive boundaries, every v0 domain on
  an empty payload, a complete common consensus context, one block header and
  block ID, proposal/vote/timeout signing roots, and a validator-set hash. It
  is checked by `scripts/ci/check_poco_bft_v0_wire_vectors.py`.
- `ed25519-v0.json` freezes an RFC 8032 public key and signature over the
  foundation vote root, plus wrong-root, mutated-signature, undecodable-key,
  and small-order-key rejection cases. The exact bytes are reproduced by
  `cd trillionnium && cargo test -p trnm-consensus-crypto`; the public file
  contains no seed or private key.
- `anchor-finality-v0.json` freezes the exact empty-signature `GenesisQC`, a
  skipped-view genesis `ProposalSignV0`, the independently domain-separated
  `HandoffDescriptorV0`, the nested epoch authorization/anchor, three complete
  `CertifiedHeaderV0` values, and `FinalityProofV0`. It is reconstructed by
  `scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py`, which also proves
  that a substituted justify-QC signer subset, a missing proposer signature,
  and a mismatched TC selection fail the logical relationship checks. Its
  reused `Signature64` bytes are shape-only fixtures; the composite objects do
  not claim valid Ed25519 signatures or quorum thresholds.
- `ordered-roots-v0.json` freezes the indexed-leaf, level-tagged-node, and
  final-count-wrapped payload/receipt/evidence roots for 0–4 items. It includes
  every empty root, odd duplicate-right traces, a public payload-leaf vector,
  kind/order/framing separation, and a retained final-count mutation. It is
  reconstructed by the standard-library-only
  `scripts/ci/check_poco_bft_v0_ordered_roots.py`.
- `qc-tc-threshold-v0.json` freezes complete ordinary-QC and corrected
  `TimeoutCertificateV0` CEV0 values with real RFC 8032 Ed25519 signatures and
  unequal powers `4/3/2/1` (`W=10`, exact quorum `7`). It covers exact-threshold
  acceptance, one-below rejection, duplicate/noncanonical/unknown signers,
  wrong root/context/domain and bad signatures, full TC references,
  strictly-future referenced-QC rejection, same-block coordinate consistency,
  deterministic selected-high-QC choice (including the same-view/same-block
  QC-digest tie-break), and summary conflicts. The
  standard-library-only checker contains a minimal RFC 8032 implementation,
  self-tests it against RFC 8032 test 1, and keeps its deterministic seeds out
  of the public JSON. The Rust crypto integration test reconstructs the same
  public corpus through protocol constructors and `StrictEd25519Verifier`.
- `cev0-parser-certificate-kernel-v0.json` binds the B2-A machine-readable
  logical schema to the committed B1 validator-set/QC/TC raw bytes. Its
  standard-library-only Node gate performs exact bounded decode, byte-identical
  re-encode, digest recomputation, and its own BigInt RFC 8032 strict Ed25519
  admission (it rejects noncanonical points/scalars and small-order forgeries);
  checks every non-complete valid prefix and trailing byte; exercises the
  128-byte ID, 100-item list and
  10,000 nested-share boundaries; and rejects structural, ordering,
  authorization and full-TC relationship mutations under stable error codes.
  It also checks every included protobuf field number/type/cardinality and the
  canonical/redundant/derived/sidecar role mapping, including the two distinct
  uses of `TimeoutVote` as a signing container and as a TC entry.
- `cev0-parser-anchor-handoff-kernel-v0.json` binds the B2-B extension manifest
  to the existing shape-only `anchor-finality-v0.json` bytes. Its independent
  Node gate imports the B2-A CEV0/QC/`SignatureShareV0` definitions, then exact
  decodes and byte-identically re-encodes `BlockHeaderV0`, the handoff
  descriptor/vote/certificate values, and the three-part epoch-anchor
  authorization. It checks 3,435 non-complete prefixes, trailing bytes,
  128-byte IDs, 100-entry old/new lists, nested-vote redundant role scopes,
  descriptor/terminal-header/ordinary-QC linkage, and the context-bound anchor
  candidate bytes across 13 boundary cases under stable decoder,
  Node-admission, and gate error layers.
  `GenesisQC` remains a future trusted output; the epoch fixture is only an
  inert candidate byte binding. Neither receives a bare peer-controlled
  synthetic-QC decoder or is emitted by the B2-B kernel. A usable anchor still
  requires future external complete checkpoint/commitment/quorum/crypto
  authorization. The source signatures are opaque width fixtures and
  `cryptographic_validity_claimed=false`, so this corpus is not a crypto
  positive or proof of either handoff quorum.
- `handoff-certificate-kernel-v0.json` is the separate B2-B cryptographic
  corpus. It publishes 11 complete artifact classes over distinct old/new
  `4/3/2/1` validator sets (`W=10`, quorum `7`) and 36 stable negative cases.
  The standard-library Python gate independently reconstructs all CEV0,
  digests, role-scoped signing roots, real Ed25519 signatures, weighted
  thresholds, descriptor/header/terminal-QC relations, and the single inert
  anchor candidate field/byte binding. Rust consumes the committed raw bytes
  through exact decoders before strict verification. Neither implementation
  emits or authorizes an `EpochAnchorQC`.
- `next-epoch-commitment-kernel-v0.json` closes the B2-C
  `NextEpochCommitmentV0` object only. Its standard-library Node gate imports
  B2-A primitives and validator-set encoding, exact-decodes and byte-identically
  re-encodes three raw values, recomputes the epoch-commitment and supplied
  validator-set digests, rejects all 608 non-complete prefixes plus trailing
  bytes, and covers 25 parsing boundaries and 21 same-version v0
  context/fallback relation mutations. The one present upgrade hash is a
  shape-only Optional-tag fixture and is rejected by the context kernel.
  Validation returns no capability and never emits an epoch authorization or
  `EpochAnchorQC`; snapshot authority, PoP, upgrades, checkpoint/seal finality,
  and complete epoch transition remain open.
- `block-body-kernel-v0.json` closes the B2-D ordinary block-validation
  kernel only. Its standard-library Node gate imports the frozen header,
  validator-set, ordinary-QC, and ordered-root definitions; binds the active
  set to the committed reference parameter digest and equal `1/1/1/1`
  weights; exact-decodes raw `ApplicationPayloadV0`, caller-supplied typed
  receipt commitments, and mandatory `DoubleVoteEvidenceV0` bytes; and
  recomputes all three roots and the checked logical-block size. It exercises
  every non-complete valid prefix, trailing bytes, active byte/count bounds,
  UTF-8/raw-key canonicality,
  receipt/evidence relations, strict Ed25519 point/scalar/subgroup rejection,
  the exact `00000000` empty payload, and equality/plus-one size limits.
  Block/Vote/DoubleVote/ordinary-next-view Proposal protobuf field roles are
  drift-checked, but the proposal artifact is only a logical/projection
  fixture: it does not decode protobuf Proposal presence/defaults or support
  TC/skipped-view, synthetic QC, first-new-block, anchor, checkpoint, handoff,
  runtime, or epoch authorization. Rust independently exact-decodes and
  verifies the valid ordinary QC, then reconstructs the valid
  `ProposalWitnessV0` signing root and proposer signature. The valid view-4
  fixture binds the canonically scheduled `validator-d`; all 24 proposal/QC
  negative fixtures remain Node-only; no Rust all-negative or raw-protobuf-
  Proposal closure is claimed.
  The private Rust commitment token records acceptance by its caller-supplied
  `SignatureVerifier`; it does not attest verifier identity. Production must
  pass `trnm_consensus_crypto::StrictEd25519Verifier`, and this corpus exercises
  that concrete strict path.
  The 4 MiB equality case is the committed reference profile's active
  `max_block_bytes`, not an eternal protocol or production decoder cap.
- `checkpoint-two-seal-kernel-v0.json` closes the B2-E old-set
  checkpoint/two-seal semantic kernel only. Its machine-readable manifest and
  standard-library Node gate bind the complete 54-field, 341-byte
  `ConsensusParametersV0` preimage, old validator set, exact
  `NextEpochCommitmentV0`, parent QC, three ordinary `CertifiedHeaderV0`
  values, and one `checkpoint <- seal-1 <- seal-2` `FinalityProofV0`. The
  corpus rejects all 8,655 non-complete prefixes and eight trailing-byte
  variants, exercises 16 parser-boundary and 33 semantic/cryptographic
  negatives, and validates 21 real Ed25519 signatures. The Node lane alone is
  deterministic fixture evidence; B2-E closure also requires Rust to consume
  the same raw bytes through the exact bounded decoders and
  `StrictEd25519Verifier` before producing only the private-field inert
  `CheckpointTwoSealKernelV0`.
  The kernel fixes old-set geometry, direct ancestry, scheduled leaders,
  bounded timestamp steps, empty seal roots, checkpoint-state preservation,
  one repeated next-epoch commitment digest, and old-schedule cutoff/
  activation relations. Its protocol-version-1 commitment case locks inert
  `u32` preservation only; it does not authorize or execute an upgrade. It
  does not prove snapshot/JMT/runtime/set/parameter
  provenance, deterministic candidate/fallback construction, checkpoint body
  execution, or epoch-anchor/handoff/activation authority. The fixture is
  next-view-only and makes no B2-E TC semantic claim; B2-A remains
  authoritative for ordinary TC semantics. Core integration, permanent
  journals, checkpoint-grade sync, transport admission, light-client
  verification remain outside this corpus. The corpus gate is wired into the
  new PoCO workflow, but that workflow has not yet run remotely on GitHub.
- `joint-handoff-composition-kernel-v0.json` closes the B2-F same-version-v0
  composition of `EpochHandoffProof` fields 1--11 only. Its manifest imports
  the exact B2-B, B2-C, and B2-E objects and freezes the 11-field transport
  projection while explicitly defining no aggregate CEV0 preimage, domain,
  digest, or authorization. The standard-library Node gate consumes four
  committed source corpora and exactly 14 raw objects, then independently
  rebuilds, serializes, reparses, and strictly verifies two positive profiles:
  a distinct new set and the exact fallback set. Ten negative classes cover
  checkpoint, terminal, commitment, context, exact-QC substitution, quorum,
  role, domain, signature, and unauthorized-upgrade failures. Nine reach the
  composition verifier; the one-below-quorum handoff is rejected earlier by
  the exact decoder with its committed code and byte offset.
  Rust's private-field `JointHandoffKernelV0` binds only the exact supplied
  checkpoint/two-seal proof, commitment, old/new set and parameter preimages,
  terminal header/QC, descriptor, and both handoff roles. It cannot construct
  an `EpochAnchorQC`, authorize signing or a first-new-epoch proposal, advance
  finality, or activate a transition. Snapshot/JMT/runtime provenance,
  candidate/fallback selection provenance, PoP/governance, checkpoint body
  execution, and `EpochHandoffProof` fields 12--14 remain open.
- `snapshot-candidate-kernel-v0.json` closes the B2-G deterministic
  candidate/fallback calculation and validator-key-PoP kernel only. Its
  machine-readable schema freezes the calculation transcript, normalized
  contribution/candidate facts, exact `ValidatorKeyProofOfPossessionV0`
  preimage and wrapper, checked arithmetic, hierarchical caps, selection
  order, rollout weight formulas, successful shadow carry-forward, numeric-
  minimum fallback reason, and exact fallback configuration. The independent
  standard-library Node gate must reproduce the same output and reject
  ordering, uniqueness, boundary, arithmetic, PoP domain/context/signature,
  phase, concentration, and fallback mutations. Rust must verify the same PoP
  through `StrictEd25519Verifier` and return only private-field inert
  `CandidateSelectionKernelV0` computation evidence.
  The frozen gate covers 9 exact PoP objects, 1,744 rejected non-complete
  prefixes, 110 real Ed25519 verification checks, 4 positive rollout cases,
  1 full-input permutation, 9 calculation boundaries, 14 atomic fallback
  cases, 14 retained PoP negatives, and 0 authorization outputs. The Rust
  consumer additionally rejects noncanonical `S`, noncanonical `R`, and a
  small-order public key through the strict production verifier.
  Every contribution, eligibility, registration, bond, old-set, parameter,
  governance, and cutoff fact in the transcript is caller-supplied and
  unauthenticated. This vector is not a full Consumption Certificate wire or
  admission corpus. It does not prove finalized-cutoff ancestry, JMT/ICS23
  namespace membership/non-membership or completeness, runtime/checkpoint
  execution provenance, receipt provenance, a committed next-set authority,
  an epoch anchor, handoff signing, activation, or a core transition. Shadow
  carry of old membership/weights is a valid reason-0 result, not fallback.
- `consumption-certificate-v0.json` closes B2-H1 exact logical wire and
  cryptographic admission for the complete normative certificate. It fixes
  one 349-byte object, all sixteen body fields, CEV0 `u128` and optional-root
  encoding, the body digest, a real Ed25519 signature, the independently
  derived signature-free certificate ID, and the complete wrapper. The
  independent Node gate rejects all 349 non-complete prefixes and trailing
  data; Rust exact-round-trips the same raw bytes and verifies them with
  `StrictEd25519Verifier`. It does not authenticate application-state key
  resolution, nonce/tuple uniqueness, meter/settlement/measurement facts,
  acceptance state, JMT namespace completeness, or weight authority.
- `poco-snapshot-namespace-v0.json` closes B2-H2's cutoff-rooted namespace
  contract. It freezes AppHash v4 namespace discriminant 8, fifteen typed
  entry roles, exact length-framed JMT key preimages, three canonical entries,
  one absence query, manifest bytes, and the count-bound ordered entry root.
  Independent Node code reproduces those bytes and rejects omission,
  reordering, and duplication. Rust additionally runs the fixture through
  four real `jmt=0.12.0` membership proofs and one real `ics23=0.12.0`
  non-membership proof, rejecting root/version/proof substitution. This is
  manifest-relative completeness; runtime atomic-write discipline and value
  semantics remain open.
- `poco-snapshot-transition-v0.json` closes B2-H3a's narrow exact-value and
  atomic-transition kernel. It freezes a common identity-bound envelope and
  kind-specific payload layout for all fifteen roles. Its shared raw corpus
  contains 15/15 kind positives, 15 directed per-kind semantic negatives, two
  imported-object drift negatives, and all four rollout phases; the
  independent Node decoder rejects 2,561
  all-kind incomplete prefixes. The original exact consumer-nonce projection
  separately rejects 202 incomplete prefixes and five decoder substitutions.
  Node also anchors the full certificate, PoP, validator-set, and parameter
  payloads to their existing corpora, while Rust consumes the same shared raw
  positives, negatives, and phase boundaries and independently rejects the
  same 2,561 incomplete prefixes. The vector further freezes the
  source/target manifests, mutation root, empty root, and two-/three-leaf tree
  behavior. Rust exercises real JMT update, ordinary manifest carry, explicit
  cutoff refresh, planned overlay proofs, physical-leaf CAS, cross-history
  replan, stale-sibling, token-laundering, and namespace-bypass rejection. This
  file also freezes the B2-H3b1 production-persistence seal: exact physical
  manifest/entry keys, in-memory/SQLite/snapshot-restore admission paths, and
  five fail-closed cases for missing manifest, hidden leaf, future manifest,
  trailing semantic value, and malformed namespace key. H3b1 proves exact
  persistence/restore projection only; it does not yet prove authorized
  runtime/checkpoint execution or B2-G authority and emits no checkpoint
  binding.
- `poco-checkpoint-execution-v0.json` closes B2-H3b2a's production authority
  and checkpoint-execution binding. Independent Node and Rust implementations
  reproduce the ordered transaction and protobuf-result roots, the canonical
  `404 + chain_id.length` capability preimage (405..532, with a 425-byte fixed
  21-byte-chain-ID case), including cutoff manifest root/count, and its
  execution ID. Fixed 1-byte and 128-byte chain-ID cases verify actual `u16`
  framing and total length. Allocation-free boundary cases cover exact/over
  8 MiB transaction and encoded-receipt totals and exact/over `u32` count.
  Genesis, startup, and
  state-sync bind the authority object into AppHash; proposal processing and
  finalization bind the real block/parent/cutoff/result state. Cutoff root,
  manifest root, and manifest count substitutions are executed, not merely
  inventoried. The emitted event/execution ID is telemetry only, and the
  bounded projection cache is performance-only; neither is an authority input.
  The vector does
  not claim the remaining cross-entry state-machine rules or authenticated
  B2-G rerun.
- `poco-business-semantics-v0.json` closes B2-H3b2b0's pure semantic
  transition kernel only. The shared schema/vector gate fixes every v0 enum
  meaning, block-height and target-epoch clock case, the wire-compatible
  `max_accepted_nonce` monotonic watermark, immutable consumer-key/meter cores
  with one-way revoke/retire, the settlement/registration/lifecycle/rollout
  graphs, 16 initial-create cases, create-only updates, and deletion rejection
  for all fifteen kinds.
  Rust uses the same typed fact returned by the H3a exact decoder for CAS
  transition validation. This corpus does not authorize production business
  writes or prove funded-unused ledger state, meter task/output/caps/evidence,
  challenge or governance decisions, approval height, validator registration
  history, candidate selection, handoff, activation, or a Core transition.
  The independent gate covers 28 accepted enum values, 18 unknown-enum
  rejections, 42 exhaustive state edges, 47 clock boundaries, nine nonce
  cases, four revision boundaries, 28 immutability cases, and all 15 delete
  rejections. The added boundaries cover absent key/meter upper limits,
  `u64::MAX` billing/revision behavior, explicit rollout target-epoch
  immutability, and the fact that lifecycle `effective_height` remains a
  declared monotonic value until H3b2b1 binds it to target height.
  H3b2 remains open; the later authenticated B2-G path must reconstruct its
  transcript and perform strict Ed25519 verification plus B2-G in one call,
  never rebind the old inert token.
- `poco-application-authority-v0.json` freezes B2-H3b2b1's independent
  machine-readable application-authority and atomic cross-entry kernel. Its
  required nine-sequence production/isolated corpus is complete: 18 successful
  production/JMT steps and nine no-write/head-unchanged negatives are consumed
  by independent Node `check-final` and the non-ignored Rust production replay.
  Kinds 1 through 15 stay byte-for-byte and semantically frozen;
  kind 16 appends one exact `trnm.poco.application-authority.v0` state to the
  same namespace-8 manifest. The standard-library-only Node gate independently
  rebuilds its canonical JSON payload and value envelope, logical key, source
  and successor manifests, ordered operation/mutation roots, and a two-step
  fixed-depth sparse-Merkle nullifier sequence. Both committed proofs are
  exact 8,230-byte values with big-endian keys, LSB-first paths, and 256
  leaf-to-root siblings; eight mutations cover header, length, key, family,
  sibling, and root substitution. The corpus also fixes all fourteen replay
  families (including consumer-key decisions/identities and nonce summaries,
  meter identities, validator consensus keys, and validator identities),
  checked root/count chaining, and 210 target/context, state,
  decision, meter/cap/evidence, settlement, challenge, governance,
  registration, signer-commitment, reserved-unit, cross-meter aggregate,
  provider/tuple, bidirectional projection-integrity, certificate/key/meter/
  validator prune, funded-subject absence, release tombstones, lifecycle/
  governance/registration provenance, total usage-bucket, batch-atomicity,
  and allocation-order cases. The decision preimage independently binds the
  AppHash-authenticated governance signer/policy commitment; the corpus also
  freezes exact funded `reserved_units`, three cross-meter usage authorities,
  active provider registration, and tuple certificate/height ownership. A private
  prune is accepted only strictly after its checked retention boundary, with
  no live reference, and only for the exact private delete set. Certificate
  and revoked-key nonce-summary nullifiers are inserted in the same
  single-manifest transition; meter/validator identities and key histories
  were permanently nullified before their rich records can be pruned.
  Generic deletes remain rejected. Bounds are checked before clone, sort, proof
  decode, or hashing. This evidence authorizes only application writes. It
  does not authorize B2-G, a candidate, handoff, activation, or a Core epoch
  transition, and it cannot rebind the old unauthenticated B2-G token.
  H3b2b1 keeps governance proposal and approval as distinct target-height-
  bound operations and projection-checks both pending and finalized kind-15
  companions; approval must consume the exact earlier proposal before its
  activation height. Active certificates additionally bind their exact
  lifecycle effective height and decision; finalized governance binds phase
  plus proposal decision/height provenance; validator history binds the
  current PoP digest, registration decision/height, and a checked retired-key
  count while concrete retired keys remain permanently covered by family-13
  nullifiers. Funding requires a family-1 certificate non-membership proof,
  and release atomically inserts the family-1 certificate plus family-3
  release-decision tombstones. The aggregate authenticated usage index admits
  at most 32 actual buckets across all four scopes. The Node truth table
  contains 210 cases: 48 accepted and 162 rejected. Four Rust shared-vector
  tests consume the same raw source,
  canonical kind-16 state/envelope, active parameters, operation and both
  8,230-byte proofs through the production exact decoder and overlay. They
  reproduce the sealed roots/counts/manifest and apply the actual JMT root
  transition
  `7b011208651ac1d1189827f61a56d362a696fa6175012d4d200788ea6201ddd4 ->
  12a0b0685487b2c868032494eac2336dde7b0674c8c3d2b314915c3edfebf281`,
  then cover atomic mutants, equal-root/different-history replanning and stale-
  plan rejection with the source head unchanged.
  `author_poco_bft_v0_application_sequences.mjs` is the fail-closed authoring
  bridge for that closed corpus. It retains the exact raw Rust source
  exports and their SHA-256 digests, derives block-local decisions and sparse
  proofs from production context, and accepts completion only through fixed
  Rust events binding ordered raw operations, complete canonical mutations,
  target projection/manifest/authority, ProcessProposal/FinalizeBlock equality,
  SQLite commit/restart, V3/V4 restore, and both durable store failpoints.
  Required negatives bind the same subject and business intent to actual
  production/kernel classifiers, nonzero error-chain digests, and—where
  applicable—the exact occupied replay nullifier and stale proof source root.
  The replay-lineage digest zeroes decision bindings and, only for pruned
  consumer-key, meter, and validator replay, deletes the operation-derived
  `active_from_height`, policy `active_from_height`, or `target_epoch`
  respectively. Those omissions never alter production operation bytes,
  decision preimages, current target binding, or exact subjects.
  `check-final` independently rebuilds this evidence after private authoring
  metadata is stripped; `scaffold-required` emits all nine source-digest-bound
  next-block skeletons but no scaffold marker is accepted as authority.
  The completed nine-sequence artifact has one canonical location,
  `poco-application-operation-sequences-v0.json`.  Its dedicated gate first
  runs the independent Node `check-final` reconstruction and then the
  non-ignored Rust production replay consumer; the kernel-only authority gate
  does not substitute for either half of that final check.
- `poco-authenticated-candidate-selection-v0.json` is the bounded B2-H3b2b2
  shared reconstruction corpus. It starts from continuous physical JMT history
  plus raw cutoff/head projection and independently derives
  the old-registration and future-candidate universe, exact approved-or-active
  parameter preimage, historical acceptance epoch, relationship/challenge
  eligibility, bond coverage and jail boundary before reproducing strict PoP
  plus fresh B2-G and the checkpoint/transcript/result/authorization seals.
  The positive contains four mature reason-0 candidates; the complete
  authenticated pending-challenge source freezes reason 3. The Node gate
  independently reconstructs both, and a non-ignored Rust test freshly rebuilds
  the same JMT fixture/one-call result and requires exact vector equality.
  A second non-ignored Rust production-path test consumes both canonical
  outcomes. It starts from the exact production-valid epoch-2 authority,
  explicitly installs the matching source through the test-only height-24
  bootstrap, then runs the normal height-25 cutoff refresh, regular heights 26
  and 27, and the height-28 checkpoint. Independent production execution used by
  `ProcessProposal` and `FinalizeBlock` yields the same private capability; V3
  parent restore, a real periodic SQLite V4 cutoff-25 restore followed by parent
  27, SQLite restart, cache miss/hit and fresh post-checkpoint reconstruction
  from retained cutoff 25 reproduce it. Zero-hash rejection preserves the
  committed head, pending block and cutoff projection across restart. A
  targeted call to the existing safe pruning authority physically deletes the
  SQLite height-25 root and advances the query floor to 26; both production
  entrypoints then reject the pruned cutoff while head, pending state, parent,
  floor and two restarts remain unchanged. This proves the production
  read/rejection path, not normal scheduled pruning. The height-24 source
  bootstrap remains fixture-only and does not prove production rollover or a
  Core epoch transition. Before companion/orphan reconstruction, the retained
  Node gate now exact-decodes the payload of every physical kind 1 through 16,
  including independently retained kind-8 relationships. Its root/manifest/JMT/
  checkpoint-consistent malformed independent-kind-8 case closes the former
  raw-payload equivalence gap. The campaign independently recomposes affected
  entries, manifests, physical history, JMT roots and source roots for cutoff-
  version/source-splice/current-head, future-PoP scope/strict-crypto/predecessor,
  lifecycle/relationship/bond/jail, governance and duplicate-entry mutations.
  It also freezes explicit transcript/result/candidate-parameter/fallback/
  authorization seal substitutions and reports 43 fail-closed rejections plus
  one non-rejecting retained-provider eligibility boundary control. H3b2b2
  remains open only for cache/restart TOCTOU rejection mutations and structural
  API enforcement stronger than the landed source-surface gate.
  A separate cross-epoch campaign must prove atomic kind-16 usage
  rollover without relabeling historical buckets; the existing helper/fixture
  does not establish production Core reachability. Until that artifact exists,
  no vector may label H3b2b2 fully closed or claim handoff/activation authority.
- `poco-authenticated-next-epoch-commitment-v0.json` is the bounded H3b2b3a
  test-level commitment corpus. It preserves the unified lead-3 evidence chain:
  regular parent 24, finalized cutoff 25, regular child 26, regular grandchild
  27, then the authenticated candidate produced by height-28 checkpoint
  execution. Rust exact-decodes raw `FinalityProofV0` CEV0 against the
  authenticated old context and parent timestamp, then freshly verifies it
  with `StrictEd25519Verifier`. The parent header is also exact-decoded and H2
  is rerun from raw proof evidence. The private authorization
  seal binds only the verified absence count, so the Rust bridge and both
  canonical scenarios require an empty absence list; non-empty query/proof
  identities are not authorized by this corpus. Because the committed vector
  still carries the post-execution candidate, it does not by itself prove
  commitment placement before checkpoint proposal. Rust now independently
  constructs the cutoff-only candidate from the same authenticated source,
  reruns raw H1/H2, and requires its pre-header commitment to equal the
  vector-backed post-execution commitment under a distinct authorization
  domain. Native receipt/root and two-phase header binding tests have also
  landed.
- `poco-authenticated-checkpoint-handoff-v0.json` is the dedicated H3b2b3b
  checkpoint-28 corpus. It does not splice the epoch-zero B2-E/B2-F vectors:
  both reason-0 and authenticated reason-3 scenarios are rebuilt on the same
  lead-3 H3 history (`25 -> 27 -> 28 -> 29 -> 30`, activation boundary 31).
  Fresh Rust reconstruction retains the strict-H1 certified height-27 parent,
  binds an opaque authenticated execution transition to an empty,
  state-preserving native checkpoint, prepares and exact-binds the native
  header/body/receipts and `BlockHeader::id()`, exact-decodes and strictly
  verifies the checkpoint/two-seal proof, then re-runs B2-F over the exact
  terminal QC and both old/new handoff roles. Its final ID is explicitly an
  application-private replay seal, not a protocol aggregate proof. The first
  vector intentionally has empty native payload/receipts and therefore does
  not claim shared-vector coverage of runtime `u128` fee or event mapping.
  Its independent Node consumer recomputes H3a and every H2 ICS23 membership,
  the native execution/preparation/header/joint private seals, strict B2-E and
  B2-F, the descriptor/certificate, and both old/new role signatures and
  quorums. The vector itself does not prove journal behavior. Separately, an
  application-private SQLite sidecar now freezes one transition binding and
  `(transition, checkpoint kind, height, view)` preparation slots under WAL,
  `synchronous=FULL` and `BEGIN IMMEDIATE`. Exact reserve/bind replay is
  idempotent; conflicting bindings or occupied-slot values sticky/durably halt;
  replay records remain inert; and a focused Rust suite covers same-process
  reopen, conflict, corruption and path-identity behavior at this checkpoint-
  only boundary. This is not subprocess restart or external rollback-watermark
  evidence. The sidecar and its crate-private durable wrappers
  are not wired to ABCI startup or a production host, do not cover seal 1/2,
  and are not a signer persist-before-sign journal. This corpus also does not
  prove any Comet/native-ID mapping, live seal proposal/vote/signing path,
  field-13 anchor/activation, field 14, field 12, Core rollover or production
  cross-epoch pruning.

Run the independent checks from the repository root:

```sh
./scripts/ci/check_poco_bft_v0_parameters.py
./scripts/ci/check_poco_bft_v0_wire_vectors.py
./scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py
./scripts/ci/check_poco_bft_v0_ordered_roots.py
./scripts/ci/check_poco_bft_v0_qc_tc_vectors.sh
./scripts/ci/check_poco_bft_v0_logical_schema.sh
./scripts/ci/check_poco_bft_v0_anchor_handoff_schema.sh
./scripts/ci/check_poco_bft_v0_handoff_vectors.sh
./scripts/ci/check_poco_bft_v0_epoch_commitment_schema.sh
./scripts/ci/check_poco_bft_v0_block_body_schema.sh
./scripts/ci/check_poco_bft_v0_checkpoint_finality_schema.sh
./scripts/ci/check_poco_bft_v0_joint_handoff_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_candidate_schema.sh
./scripts/ci/check_poco_bft_v0_consumption_certificate_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_namespace_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_transition_schema.sh
./scripts/ci/check_poco_bft_v0_checkpoint_execution_schema.sh
./scripts/ci/check_poco_bft_v0_business_semantics_schema.sh
bash scripts/ci/check_poco_bft_v0_application_authority_schema.sh
bash scripts/ci/check_poco_bft_v0_application_operation_sequences.sh
bash scripts/ci/check_poco_bft_v0_authenticated_candidate_selection.sh
bash scripts/ci/check_poco_bft_v0_authenticated_next_epoch_commitment.sh
bash scripts/ci/check_poco_bft_v0_authenticated_checkpoint_handoff.sh
```

These are partial vectors, not complete protocol conformance. B2-A closes the
ordinary validator-set/QC/corrected-TC certificate kernel only. B2-B closes
only the listed anchor/handoff CEV0 shapes, transport projections, terminal
ordinary QC, and dual weighted certificate kernel. The bound candidate anchor
bytes are not authorization. B2-C, B2-D, B2-E, B2-F, B2-G, B2-H1, B2-H2,
B2-H3a, B2-H3b1, B2-H3b2a, B2-H3b2b0, and B2-H3b2b1 respectively close the
inert next-epoch commitment, ordinary block-validation, narrow old-set
checkpoint/two-seal semantic kernel, and same-version field-1-through-11 joint-
handoff composition, and the pure transcript candidate/fallback/PoP
calculation, exact cutoff/certificate-wire, cutoff-rooted namespace,
atomic semantic-value transition, production persistence/restore, checkpoint-
execution binding, pure semantic-transition, and authenticated atomic
application-write kernels under their documented boundaries. B2 overall remains
open. B2-H3b2b2 has landed its application-authenticated one-call Rust path and
bounded shared reconstruction corpus plus canonical ABCI/SQLite/cache/restart/
V3/V4/pruned-cutoff evidence. Its Node campaign now records 43 fail-closed
rejections and one non-rejecting eligibility boundary control, including global
kind-1-through-16 exact payload admission. H3b2b2 remains open only for cache/
restart TOCTOU rejection mutations, stronger structural API enforcement,
production usage rollover, and production host integration. The bounded
H3b2b3a/H3b2b3b corpora join raw-exact-and-freshly-verified B2-H1 and raw H2
to a cutoff-only commitment, then privately prepare and exact-bind that
commitment into a native checkpoint header before strictly re-running the
checkpoint/two-seal and joint-handoff kernels. A checkpoint-only SQLite
preparation sidecar and crate-private durable reserve/bind wrappers have also
landed, with idempotent replay and sticky/durable conflict halt evidence. The
remaining seam is production host/carrier/startup integration of that sidecar,
seal-1/seal-2 preparation and the signer-co-located persist-before-sign
journal, not the private pre-header/header-binding kernel. Remaining
release-blocking obligations include protobuf envelope/framing/admission,
complete epoch-anchor authorization, that narrow candidate/rollover work,
complete anchor/activation authority and handoff fields 12--14,
host-integrated checkpoint/epoch Proposal/Block execution and parent-state
admission, receipt outcome policy,
additional evidence families, and
light-client objects, permanent journals, and checkpoint-grade sync, as tracked
in `../07-invariants-and-conformance.md`. The
PoCO gates are present in `.github/workflows/trnm-poco-bft-v0.yml`, but have
not yet produced a remote GitHub run. The smaller `ed25519-v0.json` still
documents only the raw verification boundary; production signing and key
custody also remain outside this corpus.
