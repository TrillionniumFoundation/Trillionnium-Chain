# 09 — Light clients, state sync, and protocol upgrades

Status: **draft normative target; design-only, not implemented, not frozen, not activated**

This document separates four proof meanings, defines fail-closed state sync,
and specifies the only permitted transition from frozen PoCO-BFT v0 to PoCO
AI-native Stack v1.

## 1. Distinct proof products

A conforming API and client MUST distinguish:

1. `OrderFinalityProofV1`: proves a header/block is finalized by the v1
   three-chain/epoch rules.
2. `ApplicationStateProofV1`: proves membership or non-membership under the
   state root of an order-finalized header.
3. `ArtifactAvailabilityProofV1`: proves an exact DA committee attested to a
   retention statement, or provides a fresh verified retrieval proof.
4. `ResultSettlementFinalityProofV1`: proves an exact result/profile/challenge
   state or settlement receipt is mature and included under a finalized state
   root.

No proof type implies another. An Order QC is not application validity proof,
artifact availability, result correctness, payment, privacy, or perpetual
retention. An availability certificate is not present-time retrieval unless
the retention and retrieval evidence are current.

The four top-level proof envelopes use these exact logical fields:

```text
OrderFinalityProofV1 =
  schema_version:u16=1
  context:ProtocolContextV1
  trusted_anchor:TrustedOrderAnchorV1
  target_block_id:BlockIdV1
  target_height:u64
  target_header:BlockHeaderV1
  certified_chain:List<CertifiedHeaderV1>
  epoch_handoffs:List<EpochHandoffProofV1>

ApplicationStateProofV1 =
  schema_version:u16=1
  context:ProtocolContextV1
  finalized_block_id:BlockIdV1
  finalized_height:u64
  state_root:Hash32
  state_tree_version:u16
  state_schema_hash:Hash32
  object_kind:u16
  object_id:TypedObjectIdV1
  object_version:Option<u64>
  value:Option<Bytes>
  proof:StateTreeProofV1
  order_finality_proof:OrderFinalityProofV1

ArtifactAvailabilityProofV1 =
  schema_version:u16=1
  context:ProtocolContextV1
  namespace:DaNamespaceV1
  batch_id:BatchIdV1
  artifact_id:Option<ArtifactIdV1>
  availability_certificate:AvailabilityCertificateV1
  epoch_descriptor:EpochDescriptorV1
  da_policy:DaPolicyBodyV1
  da_committee_descriptor:DaCommitteeDescriptorV1
  da_committee_set_entries:List<EpochDaCommitteeEntryV1>
  content_item_inclusion:Option<DaContentInclusionProofV1>
  fresh_retrieval_proof:Option<RetrievalProofV1>
  order_finality_proof:OrderFinalityProofV1

ResultSettlementFinalityProofV1 =
  schema_version:u16=1
  context:ProtocolContextV1
  task_id:TaskIdV1
  lease_id:LeaseIdV1
  result_id:ResultIdV1
  result_revision:u64
  verification_profile_id:Bytes
  verification_profile_version:u32
  verification_profile_hash:Hash32
  verification_profile:VerificationProfileBodyV1
  verification_registry_entries:List<VerificationRegistryEntryV1>
  verifier_set_definition:Option<VerifierSetDefinitionV1>
  execution_receipt:ExecutionReceiptV1
  execution_receipt_inclusion:ExecutionReceiptAdmissionProofV1
  result_status:ResultStatusV1
  transition_history_root:Hash32
  challenge_resolution_root:Hash32
  result_transition_history:List<ResultTransitionBodyV1>
  evaluation_results:List<EvaluationResultV1>
  challenge_index:List<ChallengeIndexEntryV1>
  settlement_maturity:SettlementMaturityV1
  settlement_id:Option<SettlementIdV1>
  required_state_proofs:List<RequiredStateProofV1>
  maturity_policy_hash:Hash32
  maturity_height:Option<u64>
  order_finality_proof:OrderFinalityProofV1
```

`TrustedOrderAnchorV1` is the closed union:

```text
0 FreshGenesis {
    genesis_derived_state_hash:Hash32,
    trusted_genesis_header:BlockHeaderV1
  }
1 EpochCheckpoint {
    checkpoint_id:EpochCheckpointIdV1
  }
2 V0Activation {
    activation_statement_id:V0ToV1ActivationStatementIdV1,
    source_terminal_finality_proof_hash:Hash32,
    target_epoch_descriptor_id:EpochDescriptorIdV1
  }
```

`FreshGenesis` is legal only for the first proof path of a chain whose exact
trusted descriptor materializes that header and derived-state hash.
`V0Activation` is legal only for the first v1 proof path and requires the full
frozen v0 terminal/finality/handoff and v1 activation verification in section
8. Every later proof uses a previously authenticated `EpochCheckpoint`. An
`EpochCheckpointV1` may therefore cite the proof that finalizes it without that
proof citing the same checkpoint: the proof anchor is genesis, activation, or
an earlier checkpoint. Unknown variants and a same/future-checkpoint anchor
fail closed.

`MerkleStepV1` is exactly `(level:u32, sibling_side:u8,
sibling_hash:Hash32)`, where `0 Left` means the sibling is left of the running
hash and `1 Right` means it is right; unknown sides, wrong/nonconsecutive levels,
extra steps, and paths inconsistent with document 02's duplicate-final rule are
invalid. `DaContentInclusionProofV1` is exactly `(item_index:u32,
item:DaContentItemCommitmentV1, merkle_path:List<MerkleStepV1>)`.

Application state does **not** use that list-tree proof. Reference v1
`StateTreeVersionV1 = 0` defines a 256-level sparse binary Merkle tree. The
state key is `DigestV1("trnm.poco-ai.state-key.v1", TypedObjectIdV1)`. A present
leaf is `DigestV1("trnm.poco-ai.state-leaf.v1", (state_key:Hash32,
object_kind:u16, object_version:u64, value_bytes:Bytes))`. The empty leaf is
`DigestV1("trnm.poco-ai.state-empty-leaf.v1", (state_tree_version:u16=0))`.
For levels `0..255`, the empty hash is recursively
`DigestV1("trnm.poco-ai.state-node.v1", (level:u16, left:Hash32,
right:Hash32))` over two prior-level empty hashes; nonempty internal nodes use
the same exact node preimage. Key bit index `0` is the most-significant bit of
`state_key[0]`; indices then increase through each byte's bits from MSB to LSB
and through bytes `0..31`. Proof sibling order remains leaf-to-root, so verifier
level `0` uses key bit index `255`, level `255` uses key bit index `0`, and bit
zero selects left while bit one selects right.

`StateTreeProofV1` is the closed union `0 Membership { object_version:u64,
value_bytes:Bytes, siblings:List<Hash32> } | 1 NonMembership {
siblings:List<Hash32> }`. Both variants contain exactly 256 sibling hashes in
leaf-to-root order; the direction is derived only from the state-key bit. A
membership value must equal the envelope value and version; nonmembership
requires both envelope fields absent and starts from the exact empty leaf. The
recomputed root must equal `state_root`. Unknown tree versions/variants,
compressed/default-sibling omission, list-tree `MerkleStepV1`, or an empty
value interpreted as absence fails closed. This exact state-tree contract—not
document 02's `RootKindV1` list tree—defines authenticated application roots.

Each `ApplicationStateProofV1` carries the complete
`OrderFinalityProofV1`; it MUST finalize the same context/block/height/header,
and the header post-state root and schema/tree facts MUST equal this envelope.
Each `ArtifactAvailabilityProofV1` likewise carries a complete order proof to
authenticate the exact epoch descriptor, DA committee set and profile used to
verify the certificate. It does **not** claim that the certificate itself was
ordered or placed in that header; certificate ordering, when required by an
application lifecycle, is separately proven by that object's application-state
proof. The certificate context/epoch/committee/profile must equal the trusted
descriptor on the proof path. A bare proof ID, unresolved content-addressed
reference, or proof selecting another epoch/committee is invalid.

The inline committee-entry list is complete, strictly namespace-ordered, and
recomputes `epoch_descriptor.da_committee_set_root`; its selected entry ID
recomputes from the inline committee descriptor, whose policy/definition facts
equal the inline `DaPolicyBodyV1` and certificate. The descriptor's threshold,
member keys/weights and certificate signer set are therefore independently
verifiable. The order proof authenticates the identical epoch descriptor
ID/context. A hash-only committee/policy reference is invalid.

For `ArtifactEvidence`, `artifact_id` and `content_item_inclusion` are both
mandatory. The item namespace/kind/tag must be ArtifactEvidence/1/Artifact,
its complete commitment and stored bytes must recompute the exact artifact ID
and content digest, and its leaf/path/count must recompute the enclosing
certificate envelope's `content_root` at the exact index. Pairing an artifact
ID with another batch's certificate is invalid. For `TransactionBatch`, both
fields are absent in this proof product; transaction inclusion uses its own
batch/execution proof. A fresh retrieval proof, when present, additionally
proves current returned bytes but never repairs a missing or invalid content
inclusion.

The inline transition history, evaluation-result list, and challenge index are
complete, gap-free, and
recompute document 05's authenticated roots. `challenge_resolution_root =
DigestV1("trnm.poco-ai.challenge-resolution-root.v1",
List<ChallengeIndexEntryV1>)` over the same complete index filtered to terminal
entries; terminal count plus `open_challenge_count` equals the full index.
`evaluation_results` is strictly ordered by the evaluation-decision IDs as
they appear in transition history and contains exactly every operation-22
aggregate referenced by that history. Each complete signed claim, verifier
membership/weight, profile binding, decision and two-record atomic revision
advance is independently replayed; a hash-only decision or omitted claim is
invalid.
`ExecutionReceiptAdmissionProofV1` is exactly `(order_finality_proof:
OrderFinalityProofV1,batch_ref:BatchRefV1,
batch_ref_inclusion:RootListInclusionProofV1,
availability_certificate:AvailabilityCertificateV1,
transaction_item_inclusion:DaContentInclusionProofV1,
agent_transaction:AgentTransactionV1,
transaction_execution_receipt:TransactionExecutionReceiptV1,
transaction_receipt_inclusion:RootListInclusionProofV1,
result_state_delta_entry:StateDeltaEntryV1,
result_state_delta_inclusion:RootListInclusionProofV1,
result_created_object_entry:CreatedObjectEntryV1,
result_created_object_inclusion:RootListInclusionProofV1)`. The finalized
header's RootKind0 path proves the exact BatchRef; its certificate and RootKind7 item
path prove the complete operation-kind-10 transaction. The RootKind2 path
proves a Success transaction receipt at the same gap-free index. The RootKind14
and RootKind15 paths recompute that receipt's state-delta/created-object roots;
both entries name the exact tag-9 ResultId, initial version zero and the exact
ResultV1/ResultStateV1 value hash created by kind10. `RootListInclusionProofV1` is exactly
`(root_kind:u16,item_index:u32,item_kind:u16,item_id:Hash32,
item_commitment:Hash32,item_count:u32,merkle_path:List<MerkleStepV1>)` and uses
document 02's list-root algorithm. Every repeated context/block/batch/
transaction/receipt/result fact agrees.

The complete `execution_receipt` recomputes the Result body's receipt ID and
all task/lease/attempt/input/environment/outcome/output/meter bindings. Its
dedicated inclusion envelope proves the exact historical block/transaction operation
that admitted that receipt and created the Result; it may precede the target
proof height but must descend from the same trusted anchor/epoch handoff chain.
A receipt ID without this retained preimage and inclusion/finality proof is
invalid. Every challenge adjudication's inline signed claims is likewise
replayed from the complete Challenge state proofs/decision entries.

`RequiredStateProofV1` is exactly `(proof_role:u16,
proof:ApplicationStateProofV1)`. Entries are strictly increasing by
`(proof_role, proof.object_id.object_kind, proof.object_id.object_id)` and the
complete tuple is duplicate-free. The closed role/value matrix is:

| Role | Required tag/ID | Decoded value | Cardinality |
|---:|---|---|---|
| 0 Task | `4 TaskIdV1` | `TaskStateV1` | exactly one |
| 1 Lease | `6 LeaseIdV1` | `TaskLeaseStateV1` | exactly one |
| 2 Result | `9 ResultIdV1` | `ResultStateV1` | exactly one |
| 3 Challenge | `14 ChallengeIdV1` | `ChallengeStateV1` | one per complete index entry |
| 4 Escrow | `7 EscrowIdV1` | `EscrowStateV1` | exactly one |
| 5 Rollup | `18 ConsumptionRollupIdV1` | `ConsumptionRollupStateV1` | one per referenced rollup/hold |
| 6 Settlement | `20 SettlementIdV1` | `SettlementStateV1` | exactly one iff maturity Final |

Every ID equals the outer or inline-index fact and all revisions/roots/statuses
cross-check. Selecting favorable challenge/rollup subsets is invalid. For
`SettlementMaturityV1::Final`, the single `SettlementStateV1` must be Final,
carry its immutable intent plus present receipt/applied height, recompute the
settlement ID, and prove applied deltas equal the intent's planned deltas and
conservation root. Pending is not a valid committed reference-v1 proof state;
for NotStarted the settlement ID and proof are absent.

Every nested `ApplicationStateProofV1.context`, `finalized_block_id`,
`finalized_height`, `state_root`, and embedded `order_finality_proof` MUST equal
the outer `OrderFinalityProofV1` byte-for-byte; its target context, block,
height, and header post-state root equal the application envelope exactly.
Multi-height evidence is not accepted in
this envelope; earlier history must be represented by an authenticated history
object included at the target state. The `object_kind` scalar must equal
`object_id.object_kind` and the role must permit the exact tag/value matrix. This
prevents mixing proofs from different finalized heights, profiles, or forks.

`maturity_policy_hash = DigestV1(
"trnm.poco-ai.result-maturity-policy.v1",
(challenge_policy_hash:Hash32,settlement_policy_hash:Hash32,
verification_profile_hash:Hash32))`, using the exact Result body and decoded
profile; all repeated hashes must agree. For `NotStarted`, `maturity_height`
and settlement ID/proof are absent. `Pending` is rejected by the reference-v1
proof verifier because kind 26 is atomic. For `Final`, `maturity_height` equals
the present `SettlementStateV1.applied_height`, is no greater than the target
finalized height, and the Final receipt proof is mandatory.

`VerificationRegistryEntryV1` is exactly `(profile_id:Bytes,
profile_version:u32,profile_hash:Hash32,profile:VerificationProfileBodyV1)`;
entries are strictly ordered/unique by `(profile_id,profile_version)`, every
hash recomputes, and the list is wrapped exactly as
`VerificationRegistryV1=(schema_version:u16=1,entries)` from document 02.
`DigestV1("trnm.poco-ai.verification-registry.v1",
VerificationRegistryV1)` equals the epoch/StackProfile committed registry
hash; hashing the bare list is invalid. The selected entry equals the outer
inline profile. When its
verifier set is present, `VerifierSetDefinitionV1 = (schema_version:u16=1,
set_id:Hash32,members:List<VerifierMemberV1>)`, with `VerifierMemberV1 =
(verifier_id:Bytes,key_scheme:u16,public_key:Bytes,weight:u128)` strictly
ordered/unique and positive; its digest under
`trnm.poco-ai.verifier-set.v1` equals the profile field. This supplies all keys,
weights and rules needed to replay claims/maturity; unresolved hashes fail.

The verifier treats `result_status`, `settlement_maturity`, and
`maturity_height` as claimed summaries. It recomputes them from the finalized
state proofs, exact verification profile, transition/challenge roots, window
policy, receipt, rollup holds, and containing order-finality proof; a summary
that is not uniquely implied by those facts is invalid.

`CertifiedHeaderV1` is exactly `(header:BlockHeaderV1,
block_id:BlockIdV1,certifying_qc:QuorumCertificateV1,
timeout_certificate:Option<TimeoutCertificateV1>)`: IDs recompute and the QC
statement certifies that header/block/context/root exactly. The timeout
certificate is absent for a consecutive-view child and present exactly when
that header names its ID after entering through a verified TC. It is complete
view-entry evidence and never substitutes for any of the three finality QCs.

The proposer-signature boundary is intentionally asymmetric. A full validator
verifies the complete `OrderProposalV1` and proposer signature during proposal
admission under document 07. An `OrderFinalityProofV1` light client does not
receive or reconstruct that proposal: it authenticates the complete header and
`proposer_id` through the weighted QC whose Vote statements bind the recomputed
`BlockIdV1`, and verifies that `proposer_id` belongs to the committed validator
set. Therefore `CertifiedHeaderV1` does not carry a proposer signature. A bare
header without its valid QC is never accepted, and this separation does not
weaken full-node proposal-admission requirements.

`EpochHandoffProofV1` is exactly `(checkpoint:EpochCheckpointV1,
checkpoint_attachment:EpochCheckpointVerificationAttachmentV1,
handoff:EpochHandoffV1,old_epoch_descriptor:EpochDescriptorV1,
new_epoch_descriptor:EpochDescriptorV1,old_validator_set:
ValidatorSetDescriptorV1,new_validator_set:ValidatorSetDescriptorV1)`; every
ID/context/set/role/quorum/activation field verifies under document 07.
`RetrievalProofV1` is the exact alias defined in document 06. The bounded
FreshGenesis/Ordinary/checkpoint kernel below now covers one single-epoch QC/TC
path plus one exact checkpoint -> dual-role handoff -> V1HandoffFirst ->
Ordinary trust progression. It recomputes both authority
sets/parameters/descriptors and verifies both weighted role quorums without
borrowing context, keys, signatures, or weight across roles. More than one
handoff, arbitrary-length trust-path iteration, operator-authenticated
weak-subjectivity selection/general renewal, and an interoperable second
implementation still do not exist, so
`light_client_spec_complete=false` remains truthful.

The versioned `OrderTrustPathV1` candidate closes one narrower composition
gap without changing that global truth. It commits an initial canonical
`TrustedOrderStateV1` and at most three tagged raw steps. If a path is nonempty,
step zero MUST be the exact existing FreshGenesis-only transition carrier.
Every later step MUST be a new `CheckpointAnchoredTransitionStepV1`; the old
FreshGenesis anchor tag MUST NOT be reinterpreted after position zero. Each
later step consumes the exact preceding state ID and certified-head QC ID,
directly extends that certified header with the scheduled checkpoint/seal
chain, verifies the checkpoint and both weighted handoff roles, verifies the
new epoch chain, and derives rather than trusts its output state. Epoch and
finalized height advance strictly. Every `V1HandoffFirst` recomputes root kind
1 from exactly one complete `ProtocolObjectSidecarV1::EpochHandoff` wrapper,
including both signature lists; the remaining ordered roots are empty. All
typed IDs use the global `DigestV1` construction
`SHA256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))`. The current
bounded iterator additionally permits exactly one skipped epoch-start view in
a `CheckpointAnchoredTransitionStepV1`: `V1HandoffFirst` is at
`initial_new_view+1`, carries a complete TC for `initial_new_view`, selects the
identical complete `EpochHandoffV1` as its sole safe parent, has no locked QC,
names the exact latest finalized epoch checkpoint, and targets the immediately
next view. It does not establish general pacemaker-history verification. The current
evidence is intentionally bounded to 0/1/2/3 hops and does not select a
weak-subjectivity anchor, verify v0 activation, admit TC/skipped-view
transitions beyond that single epoch-start case, or establish arbitrary-length/global
light-client completeness.

The separately versioned `OrdinaryFinalityAdvanceV1` candidate closes one
same-epoch continuation boundary. Its input `TrustedOrderStateV1` is derived
from the exact FreshGenesis-to-Ordinary source proof, never accepted as a JSON
summary. Each advance contains exactly three Ordinary certified headers and
targets the first header. The first header directly extends the trusted
certified head and consumes its exact QC ID. A later header may skip exactly
one view only when its complete TC authenticates the immediately prior QC as
both high justification and lock, names the latest finalized checkpoint, and
targets that exact view; all other edges are consecutive and carry no TC. The
output trusted state is derived from verified bytes, and two sequential
advances must be strictly monotonic. The present corpus verifies 40 QC and
eight TC signatures and rejects 52 exact-error mutants. This does not execute
payloads, admit arbitrary history or epoch changes, establish general
pacemaker history, complete wire/crypto coverage, provide a second
implementation, or make the global light client complete.

The candidate `WeakSubjectivityCheckpointRenewalV1` closes one bounded subset
without weakening that statement. It accepts only the exact three-hop
`OrderTrustPathV1`: the prior anchor is the checkpoint authenticated by hop
zero, the renewed anchor is the checkpoint authenticated by the final hop, and
the terminal trusted state and checkpoint must equal the final carrier bytes.
Both anchors bind their checkpoint epoch, context, validator-set hash,
consensus-parameters hash, application root, and state-schema root. The
observed finalized epoch/height must equal the terminal finalized head; the
prior anchor must remain inside positive epoch and block trusting windows; the
renewed anchor must advance epoch and height, meet a positive minimum height
advance, and reject a different checkpoint/block at the same height. The
renewal ID, policy ID, and both anchor IDs use the length-prefixed `DigestV1`
construction. This is deterministic admissibility of a supplied prior anchor,
not permission to trust peer input: wall-clock evidence, operator/governance
authentication, arbitrary checkpoint selection, unbounded history, and global
light-client completeness remain outside the candidate.

Each top-level proof ID is the typed digest of its exact envelope using the
corresponding domain registry entry in document 02. In particular,
`OrderFinalityProofIdV1` is the digest of the complete
`OrderFinalityProofV1`, including its exact trusted anchor and handoff
path; an implementation MUST NOT identify a proof only by its target block.

## 2. Light-client trusted state

`LightClientStateV1` binds:

```text
context, epoch, finalized_height, finalized_header,
epoch_descriptor, validator_set_hash, consensus_parameters_hash,
da_policy_hash, verification_registry_hash, fee_schedule_hash,
state_schema_hash, stack_profile_hash,
latest_epoch_checkpoint, weak_subjectivity_anchor
```

Bootstrap requires a trusted genesis or externally authenticated finalized
checkpoint. The weak-subjectivity anchor is operator trust input and cannot be
silently advanced from unverified network data. The trusting window is
expressed in finalized epochs/heights and validator-set overlap. Any operator
wall-clock age is external trust-input metadata, not a consensus header field.
A client never derives protocol validity from local clock drift or an unsigned
peer timestamp.

Within the bounded renewal candidate, “cannot be silently advanced” means the
operator-supplied prior anchor must exactly equal the first authenticated
checkpoint anchor, while the replacement must exactly equal the latest
checkpoint anchor on the same verified three-hop path and satisfy the committed
age/monotonicity policy. The candidate does not define who authorizes that
operator input or how a production client obtains it.

The verifier is independent from the validator node and rejects unknown object
versions, domains, profiles, algorithms, root kinds, signer encodings, epoch
transitions, or proof paths. It checks canonical encoding, context, unique
signers, checked weight, three-chain finality, exact parent/height links,
epoch seals, and dual-quorum handoffs. A TC never advances finalized state.

## 3. Application and result proofs

Application proofs bind the exact root kind, state schema, object ID/version,
key derivation, value bytes/hash, height, block ID, and finalized-header proof.
Absence proofs are explicit and canonical; an empty value is not absence.

Result/settlement proofs additionally bind task, lease, the exact
`(verification_profile_id: Bytes, verification_profile_version: u32,
verification_profile_hash: Hash32)`, the unique `ResultStatusV1` and
`SettlementMaturityV1` from document
05, complete challenge/appeal index and windows, resolution, rollup holds,
settlement receipt and deltas, and
maturity height/epoch. A client reports the exact result state
`Submitted/Evaluating/ProvisionalValid/ChallengeOpen/FinalValid/FinalInvalid/
Inconclusive` plus exact `NotStarted/Pending/Final` settlement maturity. It never maps “ordered” to
“paid” or “valid”, and never omits invalid or inconclusive terminal results.

## 4. DA proof meaning

A light client verifies a DA certificate using the epoch's exact committee and
policy commitment. The conclusion is limited to “a threshold attested that the
exact bytes were durably stored through the stated retention epoch under this
profile.” A current retrieval proof binds a fresh nonce/request, responder,
certificate/batch/chunk roots, exact bytes, and response window.

Retention expiry, open challenge holds, committee change, repair, and GC are
visible state transitions. A client cannot infer availability after expiry or
privacy/correctness/usefulness from the DA proof.

## 5. State-sync snapshot

`StateSyncManifestBodyV1` is anchored to an order-finalized epoch checkpoint
and has this exact logical field order:

```text
schema_version                u16                 // 1
context                       ProtocolContextV1
height                        u64
block_id                      BlockIdV1
epoch_checkpoint_id           EpochCheckpointIdV1
state_root                    Hash32
state_schema_hash             Hash32
chunking_profile_hash         Hash32
compression_profile_hash      Hash32
chunk_count                   u32
total_uncompressed_bytes      u64
chunk_manifest_root           Hash32
chunk_entries                 List<StateSyncChunkEntryV1>
epoch_descriptor_id           EpochDescriptorIdV1
validator_set_hash            Hash32
da_committee_set_root         Hash32
verification_registry_hash    Hash32
meter_registry_hash           Hash32
fee_schedule_hash             Hash32
evidence_horizon_height       u64
history_start_height          u64
catch_up_start_height         u64
```

`ChunkingProfileV1` is exact and context-free:
`(schema_version:u16=1, algorithm:u8=0,
target_uncompressed_bytes:u64,max_uncompressed_bytes:u64,
split_only_between_state_keys:bool=true)`. Algorithm 0 greedily appends
canonical state-key/value records until adding the next would exceed target,
except one individually bounded record may form its own chunk; it never splits
a record. Its hash domain is `trnm.poco-ai.state-sync-chunking-profile.v1`.
`CompressionProfileV1` is exactly `(schema_version:u16=1, algorithm:u8=0)`;
reference v1 algorithm 0 is Identity, so compressed bytes/hash/size equal
uncompressed bytes/hash/size. Its domain is
`trnm.poco-ai.state-sync-compression-profile.v1`. Any other algorithm is
invalid in this protocol version.

`SnapshotPolicyV1` is exact and context-free: `(schema_version:u16=1,
state_schema_hash:Hash32, chunking_profile_hash:Hash32,
compression_profile_hash:Hash32, max_chunk_uncompressed_bytes:u64,
max_chunk_compressed_bytes:u64, max_chunk_count:u32,
max_total_uncompressed_bytes:u64, evidence_horizon_blocks:u64,
history_retention_blocks:u64, catch_up_window_blocks:u64)`. All bounds/windows
are positive. `snapshot_policy_hash = DigestV1(
"trnm.poco-ai.snapshot-policy.v1", SnapshotPolicyV1)`.

`StateSyncChunkEntryV1` is exactly `(chunk_index:u32,
first_state_key:Hash32,last_state_key:Hash32,uncompressed_bytes:u64,
compressed_bytes:u64,uncompressed_hash:Hash32,compressed_hash:Hash32)`. Entries
are gap-free by index, strictly partition the state-key order without overlap,
and are bounded by the decoded policy. `chunk_manifest_root = DigestV1(
"trnm.poco-ai.state-sync-chunk-manifest-root.v1",
List<StateSyncChunkEntryV1>)`; the manifest's inline `chunk_entries` is that
exact list, and `chunk_count`, total uncompressed bytes, and each
profile hash are recomputed from this list/policy. Decompression is bounded by
the declared uncompressed size before allocation, must consume all compressed
bytes, and must reproduce the exact uncompressed hash and canonical state-key
interval.

The uncompressed payload of one chunk is exactly the CEV1 encoding of
`List<StateSyncRecordV1>`, where `StateSyncRecordV1 =
(state_key:Hash32,object_id:TypedObjectIdV1,object_version:u64,
value:ApplicationObjectValueV1)`. The envelope supplies the immutable admitted
object/key preimage plus mutable state; both must decode under the kind-assigned
schemas and all IDs/contexts/versions must agree.
Records are nonempty, strictly increasing and duplicate-free by `state_key`;
each key MUST recompute as `DigestV1("trnm.poco-ai.state-key.v1",
object_id)`, and each record MUST encode its `value` as the leaf `value_bytes`,
recompute the exact sparse-tree leaf and
eventual manifest state root. The first/last entry keys equal the chunk entry,
adjacent chunks have strictly increasing nonoverlapping intervals, and the
concatenation covers every present state leaf exactly once. Lengths are those
of the complete canonical CEV1 list bytes; concatenated or stream-framed
encodings are not aliases.

The manifest carries no independently asserted live-object/liability/hold
roots; those facts are authenticated inside the complete state snapshot and
validated under owner policies. The manifest's
state/schema/block/epoch/validator/DA/registry/fee facts MUST
equal the exact checkpoint and epoch descriptor values; in particular there is
no `da_descriptor_root` alias. Heights are derived from the decoded policy and
checkpoint with checked arithmetic, never supplied as independent authority.
The manifest `meter_registry_hash` specifically equals the complete decoded
`StackProfileV1.meter_registry_hash` selected by the checkpoint's
`stack_profile_hash`; the checkpoint/header context and epoch descriptor MUST
select that same profile. It is not asserted to equal a nonexistent checkpoint
field or an implementation registry default.

`StateSyncManifestV1` is exactly `(body: StateSyncManifestBodyV1,
manifest_id: StateSyncManifestIdV1)`. Its ID is
`DigestV1("trnm.poco-ai.state-sync-manifest.v1",
StateSyncManifestBodyV1)`. It has no producer signature or certificate and
conveys no authority beyond the finalized checkpoint/proof and recomputed
roots. A peer may authenticate or rate-limit snapshot transport using a
transport-versioned session signature, but that signature is not in this
protocol object, cannot alter its ID, and is not accepted as state authority.
`StateSyncVerificationAttachmentV1` is `(manifest_id:
StateSyncManifestIdV1, checkpoint_attachment:
EpochCheckpointVerificationAttachmentV1)`; it verifies the exact checkpoint
and may use any valid finality path without changing manifest identity.
The complete state snapshot covers task/lease/escrow/result/challenge/
settlement objects and every retained DA obligation still needed by open
lifecycles or sync.

Snapshot bytes are untrusted input. A joining node verifies the finality proof,
all bounds/roots, canonical state reconstruction, object invariants, supply and
escrow conservation, and an application root recomputation before activation.
It then catches up finalized blocks and all required batches/proofs.

Peer state sync MUST NOT import or lower local validator secrets, SafetyState,
signer journal, external HSM/KMS watermark, DA attestation journal, or
whole-node monotonic checkpoint. A validator restored from application state
remains non-signing until local signing stores are independently reconciled and
commissioned. Copying an old machine image is not safe signer recovery.

## 6. Version negotiation

Transport and API negotiation are outside consensus semantics. A peer sends an
exact supported set; the selected transport version cannot change protocol
meaning. Unknown or mismatched `protocol_version`, `stack_profile_hash`, epoch
descriptor, genesis, or network magic fails closed. No downgrade, fallback to
v0, CometBFT compatibility, or “best effort” decoding is allowed after v1
activation.

Adapter, transport, RPC, storage, and verification-backend versions have
independent namespaces. They cannot add a field, alter a signing root, relax a
vote predicate, redefine finality, or change an application transition without
a new consensus protocol version.

## 7. Upgrade plan

`UpgradePlanBodyV1` is authorized and order-finalized before activation. It
binds:

```text
schema_version                 u16                 // 1
context                        ProtocolContextV1
source_protocol_version       u32
target_protocol_version       u32       // 1
source_v0_genesis_hash        Hash32
source_v0_chain_id            ConsensusString
activation_epoch              u64
activation_height             u64
source_terminal_height        u64
target_stack_profile_hash     Hash32
target_runtime_profile_hash   Hash32
source_v0_target_validator_set_hash Hash32
source_v0_target_consensus_parameters_hash Hash32
target_v1_validator_set_hash  Hash32
target_v1_consensus_parameters_hash Hash32
configuration_projection_hash Hash32
target_epoch_descriptor_id    EpochDescriptorIdV1
target_chain_descriptor_hash  Hash32
migration_program_hash        Hash32
conformance_bundle_hash       Hash32
rollback_policy               NoFallback
```

`UpgradePlanIdV1` is
`DigestV1("trnm.poco-ai.upgrade-plan.v1", UpgradePlanBodyV1)`.
`UpgradePlanV1` contains the body, its recomputed typed ID, and the exact
governance authorization/finality evidence. The ID and signatures are not part
of their own immutable preimage.

The two source-v0 hashes use only frozen v0 types/domains. The two target-v1
hashes use only document 02's v1 types/domains. They MUST NOT be compared by raw
hash equality across domains. `V0ToV1ConfigurationProjectionV1` is the exact
cross-version record `(schema_version:u16=1,
source_v0_validator_set_hash:Hash32,
source_v0_consensus_parameters_hash:Hash32,
target_v1_validator_set_hash:Hash32,
target_v1_consensus_parameters_hash:Hash32,
validator_supplement_manifest_hash:Hash32,
parameter_mapping_version:u32, migration_program_hash:Hash32)`. Its hash is
`DigestV1("trnm.poco-ai.v0-to-v1-configuration-projection.v1", body)` and MUST
equal `configuration_projection_hash`.

The independent cross-version verifier decodes the exact frozen
`ValidatorSetV0`/`ConsensusParametersV0` preimages, the exact
`ValidatorSetDescriptorV1`/`ConsensusParametersV1` preimages, and the governed
supplement manifest. It proves a deterministic mapping: validator IDs and
strict Ed25519 keys are equal, v0 positive `u64` effective weights widen
exactly to v1 `u128` weights, order is canonical, and every v1-only network,
safety-policy, and PoCO-economic commitment comes from the supplement. It also
checks protocol version `1`, max-validator/quorum/finality/timeout/bound
relations under an enumerated `parameter_mapping_version`; new v1-only values
come only from the target profile. No omitted value or implementation default
is permitted. The source and target hashes remain separately verifiable even
when their decoded facts project consistently.

Upgrade-plan authority is closed by these equalities: body `context` has target
protocol version `1`, target chain descriptor hash equals
`context.genesis_hash`, and target stack profile hash equals
`context.stack_profile_hash`; the target stack profile has protocol version `1`
and the decoded target `ChainDescriptorV1.origin` MUST be `V0Migration` with
`source_v0_genesis_hash` and `source_v0_chain_id` byte-for-byte equal to this
plan and the finalized source v0 chain. `Fresh` is invalid for migration.
and `activation_epoch` equal to the plan; its runtime and v1 consensus-parameter
hashes equal the plan; the target epoch descriptor has the identical context,
activation epoch, target v1 validator/parameter hashes, runtime profile,
registry, fees, DA policy, leader schedule, and state schema. Source terminal
height equals the migration receipt and finalized v0 proof; activation is the
unique next epoch-boundary height. Any disagreement is invalid rather than an
independent authority choice.

The plan intentionally commits a terminal height and migration program, not a
future terminal checkpoint hash or future application roots. Those values do
not exist when governance approves the plan and cannot be predicted while v0
continues processing transactions. They are bound after the terminal
checkpoint by `MigrationReceiptBodyV1`:

```text
schema_version                 u16                 // 1
context                        ProtocolContextV1
upgrade_plan_id                UpgradePlanIdV1
source_terminal_checkpoint_id  Hash32              // exact v0 typed ID bytes
source_terminal_finality_proof_hash Hash32
source_terminal_height         u64
migration_program_hash         Hash32
migration_input_root           Hash32
migration_output_root          Hash32
migration_receipts_root        Hash32
rejected_objects_root          Hash32
audit_manifest_hash            Hash32
```

`migration_input_root` MUST byte-equal the application-state root decoded from
the exact order-finalized frozen-v0 terminal checkpoint; it is verified with
the v0 state/proof rules and is not rehashed under a v1 list domain.
`MigrationOutputEntryV1` is exactly `(target_object_id:TypedObjectIdV1,
target_object_version:u64,target_value:Bytes)` and is strictly ordered by
typed state key. Running the exact `migration_program_hash` over the complete
authenticated v0 state produces this list; inserting it into document 09's v1
sparse state tree uniquely recomputes `migration_output_root`.

`MigrationObjectReceiptV1` is exactly `(source_key:Bytes,
source_version:u64,source_value_hash:Hash32,decision:u8,
target_object_id:Option<TypedObjectIdV1>,target_value_hash:Option<Hash32>,
reason_code:u16)`, where decision is `0 Migrated` or `1 Rejected` and option
presence is respectively both present or both absent. Receipts are strictly
ordered by source key and cover every live source object exactly once.
`migration_receipts_root = DigestV1(
"trnm.poco-ai.migration-object-receipts-root.v1",
List<MigrationObjectReceiptV1>)`; `rejected_objects_root` is the same ordered
list filtered to decision Rejected and hashed under
`trnm.poco-ai.migration-rejected-objects-root.v1`. No omission/default/drop is
legal.

`MigrationAuditManifestV1` is exactly `(schema_version:u16=1,
upgrade_plan_id:UpgradePlanIdV1,migration_program_hash:Hash32,
source_terminal_checkpoint_id:Hash32,migration_input_root:Hash32,
migration_output_root:Hash32,migration_receipts_root:Hash32,
rejected_objects_root:Hash32,input_object_count:u64,
migrated_object_count:u64,rejected_object_count:u64,
asset_conservation_root:Hash32,configuration_projection_hash:Hash32)`.
Counts are checked projections of the receipt list; the conservation root uses
the exact per-asset migration equation. `MigrationAssetConservationEntryV1`
is exactly `(asset_id:Hash32,source_total:u128,migrated_total:u128,
rejected_retained_total:u128,explicit_mint_total:u128,
explicit_burn_total:u128,rounding_remainder:u128,source_projection_root:Hash32,
target_projection_root:Hash32,receipt_projection_root:Hash32)`. Entries contain
every asset present in source, target, rejection, mint, or burn facts exactly
once, are strictly increasing by raw asset ID, and use checked arithmetic:
`source_total + explicit_mint_total = migrated_total +
rejected_retained_total + explicit_burn_total + rounding_remainder`.
The three projection roots are uniquely derived from the complete authenticated
source state, migration output, and object-receipt list; a rejected asset may
only count as retained when the governed rejection rule proves its source
liability remains represented rather than silently dropped.
`asset_conservation_root = DigestV1(
"trnm.poco-ai.migration-asset-conservation-root.v1",
List<MigrationAssetConservationEntryV1>)`; an assetless migration hashes the
canonical empty list under this same domain. `audit_manifest_hash = DigestV1(
"trnm.poco-ai.migration-audit-manifest.v1", MigrationAuditManifestV1)` and all
repeated fields equal the receipt/plan.

`MigrationReceiptIdV1` is
`DigestV1("trnm.poco-ai.migration-receipt.v1",
MigrationReceiptBodyV1)`. The source checkpoint and finality-proof hashes are
verified with the frozen v0 types and domains; wrapping their 32 bytes in this
v1 record does not reinterpret them as v1 IDs.

Changing a signed field, canonical encoding, object/domain meaning, vote
predicate, DA validity rule, finality rule, state-root semantics, epoch handoff,
or light-client acceptance rule requires a new `protocol_version`. A stack
profile may only select already enumerated semantics and tune explicitly
bounded parameters.

## 8. Frozen v0 to v1 activation

V1 activates either from a fresh v1 genesis or through all steps below:

### 8.0 Exact frozen-carrier compatibility rule

The frozen v0 `EpochHandoffProofV0` layout is not widened in place. For the
v0-to-v1 route its field 12 MUST contain the exact raw CEV0
`UpgradePlanV0`. Fields 13 (`first_block:ProposalV0`) and 14
(`first_block_finality:ThreeChainFinalityProofV0`) are same-version v0
carriers and MUST be absent on a v0-to-v1 transition. A verifier MUST reject
either field if present; it MUST NOT decode, relabel, or hash their bytes as
CEV1.

The first v1 proposal and its finality instead travel in a separately
versioned CEV1 `V0ToV1ActivationProofV1` carrier. The current bounded
candidate binds `(source_handoff_evidence_sha256,
source_upgrade_plan_cev0, frozen_v0_field13_present=false,
frozen_v0_field14_present=false, activation_statement_id,
activation_anchor_id, migration_receipt_id,
first_v1_proposal_cev1, first_v1_finality_proof_cev1, proof_id)`. Its proposal
witness is restricted to the exact empty `V0ActivationFirst` header and the
activation-plan/anchor/receipt bindings; its finality proof is the direct
three-certified-header chain targeting that first block. The proposer
signature and every QC signature are independently verified against the
committed v1 validator set and their exact role domains.

This explicit carrier is a candidate proof kernel, not the full normative
`OrderProposalV1` wire/admission contract. It composes with—not replaces—the
existing exact frozen-v0 fields-1-through-11 verifier and the NoFallback,
unique-boundary, old/new weighted-quorum activation kernel. It still does not
prove governance-state membership/finality for field 12, deterministic
migration execution, complete source authority, signer durability, or
production recovery. Accordingly the complete v0 authority verifier,
migration verifier, upgrade contract, normative freeze, implementation, and
activation remain absent.

1. zero-Comet native dependency and ownership gates pass on a reproducible
   v0 implementation baseline;
2. the complete v1 normative artifacts, schemas, vectors, formal models,
   independent verifier, upgrade program, and review evidence are frozen;
3. governance finalizes the exact frozen `UpgradePlanV0` from v0 document 04;
   its `current_protocol_version = 0`, `target_protocol_version = 1`, and
   activation epoch/height equal the v1 plan, its v0-domain
   `target_consensus_parameters_hash` equals
   `source_v0_target_consensus_parameters_hash`, the finalized
   `NextEpochCommitmentV0.new_validator_set_hash` equals
   `source_v0_target_validator_set_hash`, and its
   `state_migration_hash = Some(migration_program_hash)`;
4. `UpgradePlanV0.artifact_manifest_hash` commits the exact
   `V0ToV1ArtifactManifestBodyV1` below; v0 treats that digest as an opaque
   artifact fact, while the separate cross-version verifier decodes the CEV1
   manifest and recomputes every nested v1 digest;
5. the v0 checkpoint is order-finalized by its certified `seal_1` and
   `seal_2` descendants; `seal_2` is the terminal certified v0 block with its
   valid QC, while neither seal is falsely required to be independently
   finalized beyond that frozen three-chain bridge;
6. the deterministic migration reads the exact committed input root once and
   produces the exact expected v1 genesis/state output root once;
7. old and successor validators durably commission every v1 Safety, signer, DA,
   app, activation-intent, and whole-node checkpoint record required for their
   role; the complete activation statement and configuration projection are
   read back before any v1 activation signature may escape;
8. old and new validator sets then produce and verify the exact frozen
   `HandoffCertificateV0` over `HandoffDescriptorV0`, including the
   `NextEpochCommitmentV0 -> UpgradePlanV0` relation; they then each sign one
   exact v1 activation statement at their own quorum threshold under distinct
   v1 roles;
9. the first v1 block extends the exact terminal/activation parent and commits
   the migration output, target descriptor, and profile, while its proposal
   carries the complete frozen `EpochAnchorAuthorizationV0` plus the v1
   activation statement/certificates; and
10. light clients wait for the v1 three-chain before advancing normal v1
   finalized state.

`V0ToV1ArtifactManifestBodyV1` is context-free and exact:

```text
schema_version                 u16                 // 1
target_protocol_version        u32                 // 1
upgrade_plan_id                UpgradePlanIdV1
protocol_spec_manifest_hash    Hash32
schema_manifest_hash           Hash32
conformance_bundle_hash        Hash32
binary_artifact_manifest_hash  Hash32
sbom_hash                      Hash32
provenance_hash                Hash32
cross_version_verifier_hash    Hash32
```

Its digest is `DigestV1("trnm.poco-ai.v0-to-v1-artifact-manifest.v1",
V0ToV1ArtifactManifestBodyV1)`. The cross-version verifier requires this
digest to equal `UpgradePlanV0.artifact_manifest_hash`, recomputes
`upgrade_plan_id` from the supplied `UpgradePlanBodyV1`, and checks the exact
field projection above. Thus the frozen v0 plan is the old-chain governance
authority and commits the nested v1 design without requiring v0 to decode
CEV1. A bare 32-byte application value that is not the complete finalized
`UpgradePlanV0` is insufficient.

After migration, both validator sets sign one exact
`V0ToV1ActivationStatementBodyV1`:

```text
schema_version                 u16                 // 1
context                        ProtocolContextV1
source_v0_genesis_hash         Hash32
source_v0_chain_id             ConsensusString
source_upgrade_plan_hash       Hash32              // frozen v0 plan hash
upgrade_plan_id                UpgradePlanIdV1
source_terminal_checkpoint_id  Hash32              // frozen v0 typed ID bytes
source_terminal_block_id       Hash32              // frozen v0 typed ID bytes
source_terminal_finality_proof_hash Hash32
migration_receipt_id           MigrationReceiptIdV1
source_v0_old_validator_set_hash Hash32
source_v0_new_validator_set_hash Hash32
source_v0_target_consensus_parameters_hash Hash32
target_v1_validator_set_hash  Hash32
target_v1_consensus_parameters_hash Hash32
configuration_projection_hash Hash32
target_epoch_descriptor_id     EpochDescriptorIdV1
activation_epoch               u64
activation_height              u64
```

`V0ToV1ActivationStatementIdV1` is
`DigestV1("trnm.poco-ai.v0-to-v1-activation-statement.v1",
V0ToV1ActivationStatementBodyV1)`. Old-set and new-set signatures use distinct
`...activation-old-signature.v1` and `...activation-new-signature.v1` domains
and independently meet their own committed quorum thresholds. The statement
binds the finalized, now-known checkpoint and migration roots without a
self-referential pre-approval promise.

Its source v0 genesis/chain fields MUST equal the source plan, the exact
finalized v0 objects, and target `ChainDescriptorV1.origin`; target context
genesis MUST recompute from that descriptor. A mismatch is cross-chain replay
and fails before signature/weight processing.

`V0ToV1ActivationSignatureEntryV1` is exactly `(signer_id:Bytes, role:u8,
signing_set_hash:Hash32, signature_scheme:u16, signature:Bytes)`. Role `0
OldV0Set` uses the old-set domain and requires the frozen source-v0 old set;
role `1 NewV1Set` uses the new-set domain and requires the exact target-v1 set.
`V0ToV1ActivationCertificateV1` is exactly `(statement_body:
V0ToV1ActivationStatementBodyV1, statement_id:
V0ToV1ActivationStatementIdV1,
old_set_signatures:List<V0ToV1ActivationSignatureEntryV1>,
new_set_signatures:List<V0ToV1ActivationSignatureEntryV1>)`. Each list is
strictly ordered by signer ID, duplicate-free, role/set exact, and independently
meets its committed quorum. Every entry signs the recomputed statement ID under
its role domain; signature bytes are not in the statement ID.

Before either role signature escapes, the signer durably journals the entire
statement body/ID, role, signing-set hash, signer ID, source terminal facts,
migration receipt, projection hash, activation epoch/height, and target
descriptor, then binds/read-backs the whole-node monotonic checkpoint. The
anti-equivocation key is `(source_v0_genesis_hash, source_terminal_checkpoint_id,
activation_epoch, role, signer_id)`. Exact replay returns the same signature;
any different statement, set, projection, migration output, target descriptor,
or lower checkpoint under that key fails closed.

The v0 concrete governance-transaction carrier and governed-upgrade authority
remain unimplemented in the present repository. This route therefore stays
unusable until that exact v0-native path, field-12 commitment, terminal seals,
and cross-version verifier are implemented and evidenced; v1 does not add an
opaque shortcut to frozen v0.

The two certificate layers are cumulative, not alternatives. The frozen
`HandoffCertificateV0` authorizes the version/set/parameter transition under
the old protocol and reconstructs the exact synthetic v0 epoch anchor. The
`V0ToV1ActivationStatementV1` binds the post-checkpoint migration receipt and
v1 configuration that v0 cannot express. The first v1 proposal is invalid
unless the frozen `EpochAnchorAuthorizationV0` and the v1 activation statement
both verify and agree on terminal block, sets, versions, epoch, activation
height, and target parameters. A v1 signature cannot replace a required v0
handoff vote, and a v0 handoff cannot invent a migration output.

The transition is atomic and has `NoFallback`. Failure before activation leaves
v0 safely halted at its terminal checkpoint. Failure after activation cannot
restart v0, reinterpret the same height, import an old WAL, or select an
alternate migration output. Recovery resumes the exact durable activation
state or fails closed.

The current v0 verifier MUST NOT be relaxed to accept v1. A separate
cross-version verifier validates the terminal v0 proof, migration commitment,
dual-quorum activation, and first v1 chain.

## 9. In-protocol v1 upgrades

A later v1-to-vN transition uses the same explicit plan, freeze evidence,
epoch-boundary activation, deterministic migration, dual-quorum handoff,
independent client support, and no-fallback rule. Emergency governance may
halt or restrict application operations but cannot bypass BFT quorum,
manufacture migration roots, rewrite finalized history, or silently change a
verification profile already bound to a task.

## 10. Required evidence before freeze

Required evidence includes independent parsers/light clients; positive and
negative multi-hop proofs; duplicate signer, wrong root kind, stale anchor,
TC-finality, QC-as-DA, order-as-settlement, expired-retention, omitted-hold,
snapshot-root, and downgrade mutants; state-sync fuzz and decompression bounds;
v0/v1 cross-decode rejection; deterministic migration vectors; activation
SIGKILL/power-loss/rollback campaigns; old/new-set overlap and non-overlap
handoffs; and interoperability across at least two implementations. These are
not complete today.
