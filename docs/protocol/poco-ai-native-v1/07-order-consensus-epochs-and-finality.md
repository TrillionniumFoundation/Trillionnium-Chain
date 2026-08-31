# 07 — Order consensus, epochs, and finality

Status: **draft normative target; design-only, not implemented, not frozen, not activated**

This document defines the PoCO-Order component of the Coordination plane for
`protocol_version = 1`. It preserves the reviewed weighted chained-HotStuff
safety kernel while changing the ordered unit from a PoCO-BFT v0 full payload
to certified transaction-batch references and versioned coordination objects.
That change is a new protocol version, not a profile of v0.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe the target
conformance contract. They do not describe current node behavior.

## 1. Safety and liveness model

For one epoch, let the committed validator set have positive checked weights
with total `W`. A QC or TC requires unique valid signers with accumulated
weight at least:

```text
quorum(W) = floor(2W / 3) + 1
```

Safety assumes Byzantine validator weight is less than `W/3`, cryptographic
signatures and hashes hold, every honest validator follows the voting and
durability rules, and epoch activation obeys the dual-quorum handoff contract.
Liveness assumes eventual partial synchrony, an honest proposer eventually,
available transaction batches, sufficient storage/compute capacity, and a
working pacemaker. V1 does not claim unconditional asynchronous liveness,
fair ordering, censorship freedom, or MEV elimination.

The reference kernel retains:

- a single proposal per `(epoch, view, proposer)`;
- locked-QC safe voting;
- a TC that advances a view but cannot unlock, certify a block, or finalize;
- three-chain finality over certified parent/child/grandchild links;
- persist-before-sign SafetyRules and independent signer anti-equivocation;
- finalized epoch checkpoints and dual-quorum validator-set handoff.

No new BFT safety theorem is claimed. Jolteon/Fast-HotStuff, asynchronous
fallback, DAG ordering, threshold signatures, weighted proposer selection, or
sharding require a later frozen version/profile and evidence-backed decision.

## 2. Epoch-committed context

Every consensus object embeds the exact `ProtocolContextV1` defined in
document 02, byte-for-byte and field-for-field:

```text
schema_version           u16       // exactly 1
genesis_hash             Hash32
chain_id                 ConsensusString
protocol_version         u32       // exactly 1
stack_profile_hash       Hash32
```

Every Proposal, Vote, Timeout, and handoff signature also embeds the exact
`ConsensusContextV1` from document 02. The message-specific body follows that
context; it never substitutes an abbreviated local context.

An `EpochDescriptorBodyV1` additionally commits:

```text
schema_version           u16                 // 1
context                  ProtocolContextV1
epoch                    u64
validator_set_hash       Hash32
consensus_parameters_hash Hash32
runtime_profile_hash     Hash32
snapshot_policy_hash     Hash32
da_policy_hash           Hash32
da_committee_set_root    Hash32
verification_registry_hash Hash32
fee_schedule_hash        Hash32
state_schema_hash        Hash32
leader_schedule_id       Hash32
upgrade_authority_root   Hash32
```

`EpochDescriptorIdV1` is
`DigestV1("trnm.poco-ai.epoch-descriptor.v1",
EpochDescriptorBodyV1)`. The descriptor deliberately contains no predecessor
checkpoint or handoff ID, so it can be precommitted without a circular digest.
The exact predecessor checkpoint, descriptor ID, activation height, and both
validator-set roles are joined by `EpochHandoffBodyV1` (or the cross-version
activation statement in document 09). `EpochDescriptorV1` contains the body and
its recomputed typed ID; the ID is not part of its own preimage.

`LeaderScheduleDefinitionV1` is exact and context-free:
`(schema_version:u16=1, algorithm:u8=0, seed:Hash32,
validator_order_source:u8=0, same_view_tiebreak:u8=0)`. Algorithm `0` is
unweighted round-robin over the descriptor's validator set in canonical raw
validator-ID order; proposer index is `(seed_u64_be + view) mod
validator_count`, where `seed_u64_be` is the first eight seed bytes and the
addition is modulo `2^64`. `leader_schedule_id = DigestV1(
"trnm.poco-ai.leader-schedule.v1", LeaderScheduleDefinitionV1)`. Unknown
values fail closed.

Upgrade sidecars are disabled in reference v1, so `upgrade_authority_root` MUST
equal `DigestV1("trnm.poco-ai.upgrade-authority-disabled.v1",
(protocol_version:u32=1))`. It grants no authority. Enabling a later in-band
upgrade requires a new protocol version with a complete authority record,
signature wrapper, and vectors; a non-disabled root is invalid here.

`da_committee_set_root` uses the exact context-bound committee descriptors from
document 06, one per enabled namespace, strictly ordered by namespace. It is
`DigestV1("trnm.poco-ai.epoch-da-committee-set-root.v1",
List<EpochDaCommitteeEntryV1>)`, where each entry is exactly `(namespace:
DaNamespaceV1, committee_id:DaCommitteeIdV1)`. The context-bound committee ID
already commits its complete definition; there is no redundant raw definition
hash. The list is nonempty, duplicate-free, and
must equal the committees selected by the decoded `da_policy_hash` preimage;
the policy cannot name a different committee. Every BatchRef, availability
certificate, DA attestation, state-sync manifest, and light-client proof must
resolve its namespace/epoch committee through this exact root and reject an
otherwise well-signed certificate from any uncommitted committee.

These commitments are immutable inside an epoch. Unknown versions, profiles,
algorithms, validator sets, DA policies, verification methods, or fee schedules
fail closed before expensive work or signing.

The chain descriptor commits `schedule_origin_epoch` and
`schedule_origin_height`. Fresh genesis requires origin epoch `0` and the exact
materialized genesis height; v0 activation requires origin epoch/height equal
the approved activation epoch/height. For every `e >= schedule_origin_epoch`,
checked schedule functions are:

```text
epoch_start(e) = schedule_origin_height
               + (e - schedule_origin_epoch) * epoch_length_blocks
checkpoint_height(e) = epoch_start(e) + checkpoint_offset_blocks
seal_1_height(e) = epoch_start(e) + seal_1_offset_blocks
seal_2_height(e) = epoch_start(e) + seal_2_offset_blocks
next_epoch_start(e) = epoch_start(e) + epoch_length_blocks
```

Every multiplication/addition is checked and must stay within the committed
maximum height; `e < schedule_origin_epoch` is invalid in v1. Exactly one block of the matching kind occurs at each special
height. `EpochSeal1` directly extends the checkpoint and `EpochSeal2` directly
extends Seal1; both carry empty ordered/application payloads, preserve the
checkpoint state root, and repeat the next descriptor/upgrade commitments. A
QC for Seal2 creates the certified checkpoint<-Seal1<-Seal2 three-chain and
order-finalizes the checkpoint. The terminal block is certified Seal2 and
`next_epoch_start(e) = seal_2_height(e) + 1`; any parameter set not satisfying
that equality is invalid. This single rebased formula applies equally to fresh
genesis and v0 activation; implementations cannot infer another offset.

## 3. Ordered data model

`BatchRefV1` binds one complete TransactionBatch availability certificate:

```text
schema_version           u16                 // 1
context                  ProtocolContextV1
epoch                    u64
author_id                Bytes
author_sequence          u64
batch_id                 BatchIdV1
content_root             Hash32
item_count               u32
uncompressed_bytes       u64
availability_certificate_id AvailabilityCertificateIdV1
retention_end_epoch      u64
```

A valid reference never substitutes for local retrieval. It is an authenticated
locator plus a durable-storage attestation.

`ParentBlockRefV1` is a closed tagged union:

```text
0 GenesisAnchor {
    genesis_derived_state_hash: Hash32
    application_state_root: Hash32
  }
1 V1Block {
    block_id: BlockIdV1
  }
2 V0TerminalBlock {
    block_id_bytes: Hash32
    handoff_certificate_digest: Hash32
    activation_statement_id: V0ToV1ActivationStatementIdV1
  }
```

`GenesisAnchor` is legal only for the unique first block of a fresh v1 genesis,
at the exact genesis height/epoch/view and with values materialized by document
02; it cannot appear later or after migration. `V1Block` is required for every
ordinary successor. `V0TerminalBlock` is legal only for the first block of an
authenticated v0-to-v1 activation; the proposal MUST
carry and atomically verify the complete frozen `EpochAnchorAuthorizationV0`
and the exact v1 activation statement defined in document 09. Raw v0 ID bytes
never become a `BlockIdV1`.

`BlockHeaderV1` logically binds, in canonical field order. Its
`epoch_descriptor_id` is the same typed value called `EpochDescriptorIdV1`
everywhere; “hash” or “root” is not an alternate wire name:

```text
schema_version           u16                 // 1
context                  ProtocolContextV1
epoch                    u64
view                     u64
height                   u64
block_kind               BlockKindV1
parent                   ParentBlockRefV1
proposer_id              Bytes
epoch_descriptor_id      EpochDescriptorIdV1
justify_qc_id            Option<QuorumCertificateIdV1>
timeout_certificate_id   Option<TimeoutCertificateIdV1>
batch_refs_root          Hash32
protocol_objects_root    Hash32
post_state_root          Hash32
transaction_execution_receipts_root Hash32
evidence_root            Hash32
consumption_rollups_root Hash32
settlement_root          Hash32
resource_usage_root      Hash32
next_epoch_descriptor_id Option<EpochDescriptorIdV1>
upgrade_plan_id          Option<UpgradePlanIdV1>
epoch_handoff_id         Option<EpochHandoffIdV1>
```

V1 has no consensus header timestamp. All protocol deadlines, retention
windows, nonce validity, challenge windows, and activation rules use finalized
heights or epochs. An operator may attach a locally observed wall-clock time to
telemetry or a weak-subjectivity checkpoint, but that observation is not in the
block ID and cannot change consensus validity.

`BlockKindV1` is the closed `u8` enum `0 FreshGenesis`, `1 Ordinary`, `2
EpochCheckpoint`, `3 EpochSeal1`, `4 EpochSeal2`, `5 V0ActivationFirst`, and `6
V1HandoffFirst`.
FreshGenesis and V0ActivationFirst are legal only at the unique first v1 height
with their matching `ParentBlockRefV1` variant and no ordinary predecessor;
FreshGenesis has no justify QC/TC, while V0ActivationFirst requires the complete
`activation_authorization` bundle below. Ordinary requires a V1Block parent. EpochCheckpoint
and seals require the epoch schedule and empty/nonempty payload rules committed
by parameters; a seal carries no transactions or application state change.
V1HandoffFirst is legal only at `next_epoch_start(old_epoch)`, uses a V1Block
parent naming certified old Seal2, and requires `epoch_handoff_id = Some` plus
exactly one matching `EpochHandoffV1` sidecar; its target context/descriptor/set/
parameters and terminal facts must equal the header/parent. Every other block
requires `epoch_handoff_id = None`; omission or substitution is invalid.
Because in-band v1 upgrades are disabled, every v1 header and epoch checkpoint
requires `upgrade_plan_id = None`; the v0-to-v1 plan exists only inside the
cross-version activation evidence and is not retyped as a v1 upgrade.
Every block other than `FreshGenesis`, `V0ActivationFirst`, and
`V1HandoffFirst` requires a verified parent and justify QC; an epoch-start
block instead requires its exact anchor and a TC only when above its initial
view. Unknown kinds or
any parent/justify/height/epoch/view combination outside these rules is invalid.

`ProtocolObjectSidecarV1` is a closed `u8` union: `0 EpochDescriptorV1`, `1
EpochCheckpointV1`, or `2 EpochHandoffV1`. Upgrade plans remain disabled until
their exact governance authorization wrapper and vectors are assigned; they
enter through a later protocol version rather than an opaque v1 sidecar.
The v0-to-v1 activation certificate has exactly one authoritative placement:
inside `activation_authorization`; it MUST NOT also appear as a sidecar or root
item. Objective evidence must enter through an exact
versioned transaction operation until a dedicated sidecar schema is frozen; it
is not an undefined union variant. This union excludes every
user/agent operation and application object, which must arrive inside a
transaction. `AvailabilityCertificateRefV1` is exactly `(certificate_id:
AvailabilityCertificateIdV1, certificate:AvailabilityCertificateV1)`; the ID
must recompute and the list maps one-to-one to ordered batch refs.

`OrderProposalBodyV1` is exact:

```text
schema_version                    u16  // 1
consensus_context                 ConsensusContextV1  // kind OrderProposal
header                            BlockHeaderV1
batch_refs                        List<BatchRefV1>
availability_certificates         List<AvailabilityCertificateRefV1>
protocol_sidecars                 List<ProtocolObjectSidecarV1>
justify_qc                        Option<QuorumCertificateV1>
timeout_certificate               Option<TimeoutCertificateV1>
activation_authorization          Option<V0ActivationAuthorizationBundleV1>
```

`V0ActivationEvidenceV1` is exactly `(upgrade_plan_body:UpgradePlanBodyV1,
upgrade_plan_id:UpgradePlanIdV1,source_terminal_checkpoint_cev0:Bytes,
source_terminal_finality_proof_cev0:Bytes,
migration_receipt_body:MigrationReceiptBodyV1,
migration_receipt_id:MigrationReceiptIdV1,
migration_audit_manifest:MigrationAuditManifestV1,
configuration_projection:V0ToV1ConfigurationProjectionV1,
target_chain_descriptor:ChainDescriptorV1,target_stack_profile:StackProfileV1,
target_epoch_descriptor:EpochDescriptorV1)`. Every ID/hash/root is recomputed;
the frozen-v0 bytes are independently decoded under v0 rules; the receipt,
audit, projection, plan, descriptor/profile/epoch and activation statement must
agree field-for-field. In particular the receipt output root equals the first
v1 header post-state root and its receipt ID equals the certificate statement.

`V0ActivationAuthorizationBundleV1` is exactly `(epoch_anchor_authorization_cev0:
Bytes, handoff_certificate_digest_v0:Hash32,
terminal_qc_digest_v0:Hash32, activation_evidence:V0ActivationEvidenceV1,
activation_certificate:V0ToV1ActivationCertificateV1,
activation_anchor_body:ActivationAnchorBodyV1,
activation_anchor_id:ActivationAnchorIdV1)`. The bytes strictly decode as the complete
frozen `EpochAnchorAuthorizationV0`; no invented hash/domain for that v0
authorization is introduced. The two v0 digests use only their already frozen
handoff-certificate and QC domains and must equal the decoded authorization.
The bundle is present only for
V0ActivationFirst. `ActivationAnchorBodyV1` is exactly `(schema_version:u16=1,
target_context:ProtocolContextV1, activation_statement_id:
V0ToV1ActivationStatementIdV1, handoff_certificate_digest_v0:
Hash32, terminal_qc_digest_v0:Hash32, source_terminal_block_id:Hash32, target_epoch_descriptor_id:
EpochDescriptorIdV1, activation_height:u64, initial_view:u64)`. Its typed hash
`ActivationAnchorIdV1 = DigestV1("trnm.poco-ai.activation-anchor.v1", body)` is
a v1-local safe-parent anchor, not a retyped v0 QC. The bundle contains this
body/ID, and every field must match the verified v0/v1 activation evidence.

Fresh v1 genesis uses a separately typed, non-circular anchor.
`GenesisAnchorBodyV1` is exactly `(schema_version:u16=1,
target_context:ProtocolContextV1, genesis_derived_state_hash:Hash32,
application_state_root:Hash32, target_epoch_descriptor_id:
EpochDescriptorIdV1, initial_height:u64, initial_view:u64)`. Its fields are
uniquely materialized from the verified chain descriptor, bootstrap manifest,
genesis state builder, epoch-zero descriptor, and schedule; `initial_view = 1`
and `initial_height = schedule_origin_height`. `GenesisAnchorIdV1` is
`DigestV1("trnm.poco-ai.genesis-anchor.v1", GenesisAnchorBodyV1)`. It is a
local v1 trust anchor, not a QC and not network-supplied authority.

For every epoch-start proposal (`FreshGenesis`, `V0ActivationFirst`, or
`V1HandoffFirst`), header `justify_qc_id = None`; respectively the exact
`GenesisAnchorV1`, `ActivationAnchorV1`, or target-role `EpochHandoffV1` is the
sole safe-parent justification and initializes `high_justification`, while
`locked_qc = None`. At its committed initial view, `timeout_certificate_id` is
absent. At any higher view before the first QC of that epoch, it is mandatory
and names a TC whose `target_view` equals the header view and whose selected
safe parent resolves to the identical anchor. After the first v1 QC in that
epoch forms, ordinary QC rules replace the epoch-start anchor. This permits
view change without inventing a QC or retyping cross-version bytes. Every
header reference/root must recompute from the exact lists/certificates, and
the justify/TC IDs must equal the header options.

`V0ActivationFirst` carries no batch refs, application transactions, ordinary
protocol sidecars, evidence, rollups, settlements, or resource usage. Every
corresponding list root is the exact empty root, and its `post_state_root` MUST
equal the verified `MigrationReceiptV1.migration_output_root`. The migration
output is therefore the first v1 authenticated application state, not an
implicit pre-state followed by uncommitted transactions. `FreshGenesis` uses
the analogous empty-payload rule with the bootstrap-derived application root;
`V1HandoffFirst` carries no batches, transactions, receipts, evidence, rollups,
settlements, or resource usage and preserves the old terminal post-state root.
It is not empty in root kind 1: its required, unique `EpochHandoffV1` sidecar
MUST produce the exact single-item `protocol_objects_root`, including the
complete wrapper and both role signature lists. The next Ordinary block is the
first that may execute transactions.
`OrderProposalIdV1` is `DigestV1("trnm.poco-ai.order-proposal.v1",
OrderProposalBodyV1)`. `OrderProposalV1` is exactly `(body:
OrderProposalBodyV1, proposal_id:OrderProposalIdV1, proposer_id:Bytes,
signature_scheme:u16, signature:Bytes)`. The proposer signs
`DigestV1("trnm.poco-ai.order-proposal-signature.v1", body)`; body consensus
context, header proposer, epoch set/schedule, and wrapper proposer must all name
the same authorized proposer. Signature bytes are not in the ID.

All list roots
use document 02's exact root construction: header root fields use root kinds
0 through 6 in field order and bind list length, index, object kind, exact
canonical object ID, and content commitment. Empty and
absent are distinct. Duplicate batch IDs, author sequence entries, transaction
IDs, or protocol-object IDs are invalid.

The closed root-item matrix is:

| Root kind | Ordered item | `item_kind` / `item_id` | `item_commitment` and order |
|---:|---|---|---|
| 0 | `BatchRefV1` | `15` / its `batch_id` raw digest | `DigestV1("trnm.poco-ai.batch-ref-content.v1", BatchRefV1)`; proposal list order, which is strictly `(author_id, author_sequence, batch_id)` |
| 1 | `ProtocolObjectSidecarV1` | selected object's exact `ObjectKindV1` / typed object ID | `DigestV1("trnm.poco-ai.protocol-sidecar-content.v1", ProtocolObjectSidecarV1)`; strictly `(object_kind, raw object ID)` |
| 2 | `TransactionExecutionReceiptV1` | `11` / receipt ID | document 08's exact receipt-content commitment; gap-free `transaction_index` |
| 3 | `OrderedEvidenceV1` | `evidence_kind` / evidence ID below | exact evidence commitment below; strictly `(evidence_kind, source object kind, source object ID, evidence ID)` |
| 4 | `ConsumptionRollupV1` | `18` / rollup ID | `DigestV1("trnm.poco-ai.consumption-rollup-content.v1", ConsumptionRollupV1)`; strictly raw rollup ID |
| 5 | `SettlementReceiptV1` | `20` / `settlement_id` | `DigestV1("trnm.poco-ai.settlement-receipt-content.v1", SettlementReceiptV1)`; strictly raw settlement ID |
| 6 | `BlockResourceUsageEntryV1` | usage resource class / usage ID below | exact transaction-bound usage commitment below; `(transaction_index,usage_index)` order |

For sidecar kind 1, the object-kind/ID mapping is `28 EpochDescriptor`, `29
EpochCheckpoint`, or `30 EpochHandoff`. The wrapper and all
signatures remain in the content commitment. No other tag or body is legal.

`OrderedEvidenceV1` is exactly `(schema_version:u16=1, evidence_kind:u16,
source_object_id:TypedObjectIdV1, evidence_bytes:Bytes)`. The draft closed kinds
are `0 ConsensusEquivocation`, `1 DaAuthorEquivocation`, `2
DaAttestorEquivocation`, `3 InvalidSignedRetrieval`, and `4
ApplicationAccountability`. Its evidence ID is `DigestV1(
"trnm.poco-ai.ordered-evidence-id.v1", OrderedEvidenceV1)` and commitment is
`DigestV1("trnm.poco-ai.ordered-evidence-content.v1", OrderedEvidenceV1)`.
Each kind has an exact decoder selected by the active evidence profile; until
those five decoders/vectors are frozen, a profile must set the corresponding
kind's maximum count to zero. Unknown/disabled kinds are invalid, not opaque
bytes accepted by default.

For root kind 6, `BlockResourceUsageEntryV1` is exactly
`(transaction_index:u32,transaction_id:AgentTransactionIdV1,
usage_index:u32,usage:ResourceUsageV1)`. It is projected from every transaction
receipt in gap-free transaction/usage order; each receipt's usage list is
strictly key-ordered, but equal meter keys in different transactions are legal.
`resource_usage_id = DigestV1("trnm.poco-ai.resource-usage-id.v1",
BlockResourceUsageEntryV1)` and `item_commitment = DigestV1(
"trnm.poco-ai.resource-usage-content.v1", BlockResourceUsageEntryV1)`.
The leaf index equals the canonical flattened list position. Every row's
`item_kind` is its usage resource class; ID, commitment, order,
list count, and leaf position is recomputed; a typed-ID digest under another
kind, a body-only shortcut, or reordering is invalid.

The exact typed IDs, domains, and message-kind discriminants are defined in
document 02's registry. The block ID is the typed digest of the canonical
header only. A proposal signature covers its exact `ConsensusContextV1`, header,
body-root/certificate facts, and prevents profile, epoch, or justification
substitution.

## 4. Proposal admission and vote predicate

Before voting, an honest validator MUST perform the following bounded sequence:

1. verify context, epoch, view, height, proposer, parent, and exact profile;
2. verify proposal and justification signatures, signer uniqueness, checked
   weights, QC/TC structure, and the safe-vote/lock predicate;
3. verify canonical ordering, roots, bounds, author sequence windows, and
   availability certificates for every TransactionBatch reference;
4. retrieve every complete referenced TransactionBatch, reconstruct its exact
   canonical content and roots, and reject any mismatch;
5. decode every `AgentTransactionV1` and closed protocol sidecar canonically, reject
   unknown object kinds or trailing bytes, and enforce duplicate/replay rules;
6. execute the complete ordered block through the deterministic Coordination
   state transition described in [08](08-coordination-settlement-execution-and-fees.md);
7. recompute the post-state, transaction-execution-receipt, evidence, rollup,
   settlement, and usage roots and require exact header equality;
8. persist the new SafetyState and exact vote intent, read them back, reconcile
   the independent signer journal and whole-node checkpoint, and only then
   release the signature.

Missing data, local queue pressure, slow verification, unavailable storage,
or transient resource exhaustion is `Unavailable`: the validator does not
vote and MAY retry the exact proposal. It MUST NOT reinterpret local failure as
deterministic block invalidity. A root mismatch, invalid transaction, unknown
profile, violated consensus-visible bound, or non-canonical encoding is
deterministic invalidity and MUST NOT be voted for.

Validators do not need to retrieve every AI model, dataset, prompt, or output
artifact before the Order vote. They retrieve only artifacts explicitly
required by the selected verification profile for the deterministic on-chain
transition. TransactionBatch bytes are always required.

## 5. Votes, QC, locks, and finality

### 5.1 Exact ancestry and safe-vote predicate

Let `P` be an otherwise valid proposal and let `parent(P)` be its exact parent
anchor or block. `extends(P, X)` is true only when the locally verified,
gap-free parent chain beginning at `P` reaches the exact typed ID `X`; a peer's
asserted height/path is never evidence. Every referenced header, proposer
signature, QC/TC, epoch descriptor, context, application result, and required
TransactionBatch along that retained path MUST already be `Valid`. Missing
ancestry is `Unavailable` and produces no vote or SafetyState change.

`EpochStartJustificationV1` is the closed union `0 GenesisAnchor(body,
GenesisAnchorIdV1) | 1 ActivationAnchor(body, ActivationAnchorIdV1) | 2
EpochHandoff(EpochHandoffV1)`. The selected variant is fixed by block kind and
is legal only before the first QC in that epoch. Its authenticated comparison
view is the committed `initial_view - 1` using checked subtraction. A fresh
genesis anchor is reconstructed from trusted bootstrap facts; an activation
anchor verifies document 09; a handoff anchor verifies both role quorums and
the exact old certified Seal2 parent. The exact complete anchor object and ID,
not an enum/view pair alone, enter durable SafetyState.

For an epoch-start proposal with `locked_qc = None`, safe vote is true exactly
when its complete matching `EpochStartJustificationV1` verifies and either it
is at `initial_view` without a TC or it carries a valid TC for the immediately
preceding view whose selected safe parent is that identical anchor. For every
later proposal, `J = P.justify_qc` is mandatory and safe vote is exactly:

```text
extends(P, locked_qc.block_id) || J.statement.consensus_context.view > locked_qc.view
```

where absent `locked_qc` after an epoch-start anchor is legal only until the
first verified QC of that epoch, in which case the exact anchor rule above is
used. `J` MUST certify `parent(P)` and its height/context/epoch/profile/set/
parameter/runtime facts must equal the proposal's authoritative facts. A TC
only permits entry to its `target_view`; it never satisfies the second branch,
unlocks, or substitutes for `J`. `P.view` must be strictly greater than durable
`last_voted_view`; an exact replay of an already committed identical vote
digest may return the same signature, while any other digest for the same
`(genesis_hash, protocol_version, epoch, view)` fails closed.

Proposal view MUST equal durable `current_view`. That value advances only to
`Q.view + 1` after exact QC processing or to a verified TC's `target_view`;
network view numbers do not advance it. The proposal carries
`timeout_certificate = Some(TC)` if and only if its current-view entry was
authorized by that TC rather than the immediately preceding QC/epoch-start
entry. Then TC context/epoch/runtime/set/parameters and `target_view` equal the
proposal, `timed_out_view + 1 = P.view`, and its selected safe parent is
byte-identical to `P.justify_qc` for an ordinary block or the identical
epoch-start anchor for an epoch-start block. Otherwise both timeout options are
absent. This presence/linkage rule is evaluated before safe-vote.

The exact vote statement is:

```text
VoteStatementBodyV1 =
  schema_version                        u16  // 1
  consensus_context                     ConsensusContextV1  // kind Vote
  block_id                              BlockIdV1
  height                                u64
  epoch_descriptor_id                   EpochDescriptorIdV1
  post_state_root                       Hash32
  batch_refs_root                       Hash32
  transaction_execution_receipts_root   Hash32
```

`VoteSignatureEntryV1` is exactly `(voter_id: Bytes, signature_scheme: u16,
signature: Bytes)`, signs `DigestV1("trnm.poco-ai.order-vote-signature.v1",
VoteStatementBodyV1)`, and is not part of the statement. `VoteIdV1` is
`DigestV1("trnm.poco-ai.order-vote.v1", (statement:
VoteStatementBodyV1, voter_id:Bytes))`; `VoteV1` contains that statement, voter
ID, recomputed vote ID, scheme, and signature. The voter must be the exact
epoch member and key selected by `voter_id`. An honest validator emits at most
one Vote statement for an `(epoch, view)` and only after the full vote predicate
and durable barrier pass.

`QuorumCertificateBodyV1` is exactly `(schema_version: u16 = 1, statement:
VoteStatementBodyV1, signatures: List<VoteSignatureEntryV1>)`.
`QuorumCertificateIdV1` is its digest under
`trnm.poco-ai.order-qc.v1`; the enclosing `QuorumCertificateV1` contains the
body and recomputed ID. Signatures are strictly ordered by raw `voter_id` and
unique. Every signature covers the identical statement. Verifiers reject
duplicate identities before checked weight accumulation and require the exact
committed quorum threshold. A QC is not a DA certificate, result
correctness proof, settlement proof, or perpetual retrieval guarantee.

### 5.2 Exact QC ingress, lock update, and finality order

On receipt of a cryptographically valid QC `Q` for block `B`, the validator
performs these logical steps in order and commits their result before using it
to authorize another signature:

1. compare `Q` with every retained/durable QC; a same epoch/view different
   block ID is retained as evidence and causes durable fail-stop;
2. compare with the durable finalized tip; an exact-ID coordinate mismatch is
   invalid, while a lower-height or different-block same-height historical QC
   is finalized-subsumed after the conflict check and has no state effect;
3. otherwise obtain and validate `B`, its complete proposal, parent ancestry,
   justification, batches, execution result, and state; `Unavailable` records
   only a bounded pending dependency, and deterministic invalidity behind a
   valid QC causes durable fail-stop;
4. if `Q.view > high_qc.view`, set `high_qc = Q`; the first verified QC in an
   epoch replaces its `high_justification` epoch-start anchor;
5. if `B.justify_qc` exists and its view is greater than `locked_qc.view`, set
   `locked_qc = B.justify_qc`; absent lock compares below every ordinary QC;
6. evaluate the direct three-chain rule below; and
7. advance `current_view` to at least `Q.view + 1` with checked arithmetic.

Learning `P.justify_qc` is processed by this sequence before safe-vote.
Casting a vote does not itself form a QC or move the lock. Neither a TC nor an
epoch-start anchor becomes `locked_qc`. `high_qc`, `locked_qc`, and finality
never decrease during operation or recovery.

A **direct certified three-chain** is exactly `(B0,Q0),(B1,Q1),(B2,Q2)` in one
protocol context and epoch where each `Qi` certifies the exact complete Vote
statement for `Bi`; `B1.parent = V1Block(B0.id)` and
`B2.parent = V1Block(B1.id)`; `B1.justify_qc_id = Q0.id` and
`B2.justify_qc_id = Q1.id`; heights increase by exactly one; and
`Q0.view < Q1.view < Q2.view`, with each QC view equal to its block/header
view. If a child skipped a view, its complete TC must verify for the immediately
preceding timed-out view and select the identical justify QC. All three
proposals, signatures, contexts, profiles, set/parameter/runtime commitments,
payload results, and QCs verify. Upon validating `Q2`, the validator
order-finalizes `B0` and every unfinalized ancestor of `B0`. The rule never
spans an epoch or protocol transition; checkpoint finality is completed under
the old set before handoff. Finality is monotonic and does not imply AI result,
settlement, privacy, or continuing DA validity.

## 6. Timeout and pacemaker rules

The exact timeout statement is:

```text
TimeoutStatementBodyV1 =
  schema_version                 u16  // 1
  consensus_context              ConsensusContextV1  // kind Timeout
  high_justification             HighJustificationRefV1
  locked_qc_id                   Option<QuorumCertificateIdV1>
  locked_qc_view                 u64
  last_finalized_anchor          FinalizedAnchorRefV1
  pacemaker_generation           u64
```

`HighJustificationRefV1` is the closed union `0 QC {
qc_id:QuorumCertificateIdV1, qc_view:u64 } | 1 EpochStart {
anchor_kind:u8, anchor_id:Hash32, anchor_view:u64 }`. `anchor_kind` is exactly
`0 GenesisAnchor`, `1 ActivationAnchor`, or `2 EpochHandoff`. The raw ID MUST
decode under respectively `GenesisAnchorIdV1`, `ActivationAnchorIdV1`, or
`EpochHandoffIdV1`, and the complete object must verify as the matching
`EpochStartJustificationV1`. EpochStart is legal only before any QC in that
epoch; its view is the committed initial view minus one. TC safe-parent
selection compares authenticated view, then variant/tag, then raw typed ID. A
v0 QC is never either union variant.

`FinalizedAnchorRefV1` is the closed union `0 FreshGenesis {
genesis_derived_state_hash:Hash32 } | 1 V0Activation {
activation_statement_id:V0ToV1ActivationStatementIdV1 } | 2 EpochCheckpoint {
checkpoint_id:EpochCheckpointIdV1 }`. FreshGenesis is legal only before the
first v1 checkpoint of a fresh chain; V0Activation only before the first v1
checkpoint after migration; thereafter the exact latest finalized checkpoint
is mandatory. This gives timeout/view-change a real base case without minting a
synthetic checkpoint ID.

An absent locked QC requires `locked_qc_view = 0`; otherwise its view must
equal the verified QC. `TimeoutSignatureEntryV1` is exactly `(validator_id:
Bytes, statement: TimeoutStatementBodyV1, signature_scheme: u16, signature:
Bytes)`, signing `DigestV1("trnm.poco-ai.order-timeout-signature.v1",
statement)`. `TimeoutIdV1` is the typed digest under
`trnm.poco-ai.order-timeout.v1` of `(statement, validator_id)`; the signature is
not in its ID.

Because honest timeout statements may carry different verified high/locked
QCs, `TimeoutCertificateBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, runtime_profile_hash:Hash32, epoch:u64,
validator_set_hash:Hash32, consensus_parameters_hash:Hash32, timed_out_view:u64,
target_view:u64, justifications:List<HighJustificationObjectV1>,
entries:List<TimeoutSignatureEntryV1>)`. `HighJustificationObjectV1` is the
closed union `0 QC(QuorumCertificateV1) | 1 EpochStart(
EpochStartJustificationV1)` and is strictly ordered by `(view, variant,
anchor_kind, raw typed ID)`, duplicate-free. Every entry reference resolves
to exactly one included object; every included object is referenced by at least
one entry, and its ID/view/body is recomputed. Every entry's
consensus context must match the certificate facts, have kind Timeout and view
`timed_out_view`; `target_view` is exactly `timed_out_view + 1`. Entries are
strictly ordered by validator ID and unique. Its ID is the digest under
`trnm.poco-ai.order-tc.v1`. Checked weight must reach the exact quorum. The
certificate's safe parent is the highest verified `high_justification` among entries,
selected by `(view, variant, anchor_kind, raw typed ID)` with higher view
first, QC before EpochStart, lower anchor kind first, and raw-ID ascending as
the deterministic same-view tiebreak; all entries and complete justification
objects remain in the body.
It authorizes entry
to a later view and carries safe parent evidence; it cannot itself unlock,
form a QC, finalize a block, settle a task, or prove data availability.

The pacemaker uses monotonically increasing generations. Stale timers,
duplicate callbacks, lower-view network input, or a restarted host cannot
cause a second timeout or vote. Queue sizes, peer work, retained views, orphan
blocks, pending fetches, and certificate caches have hard profile bounds and
fail closed or apply deterministic eviction rules that never discard required
SafetyState.

The reference proposer schedule is deterministic unweighted round-robin over
the epoch's canonical validator order. This is a design baseline, not a claim
of optimal weighted fairness. Any weighted or reputation-aware proposer rule
must be epoch committed and tested against manipulation and DoS concentration.

## 7. Persistence and signing ownership

One non-cloneable SafetyRules owner per validator key owns the consensus
SafetyState. Before any Vote or Timeout signature can escape, production must
durably bind and read back:

- epoch, view, last vote/timeout, locked QC, high QC, the exact complete
  `HighJustificationObjectV1` currently authorizing the epoch (including its
  epoch-start anchor before the first QC), and the exact
  `FinalizedAnchorRefV1` plus verified evidence;
- the complete canonical sign intent and its application/DA facts;
- the append-only signer journal and external hardware/KMS watermark;
- the ApplicationStore committed/recovery head;
- every live DA attestation obligation; and
- an independently monotonic whole-node checkpoint over those stores.

Exact replay may return the same signature. A conflicting sign intent, lower
checkpoint, missing lock evidence, store rollback, database-copy rollback, or
unresolved commit result fails closed before signing. Network/WAL host state is
never trusted to reconstruct forgotten locks.

The epoch-start anchor and finalized-anchor evidence/IDs are covered by the
same sign intent and whole-node checkpoint as the lock. Losing, replacing, or
rolling either back before the first ordinary QC/checkpoint is a conflict and
fails closed; recovery cannot synthesize them from a host WAL or peer claim.

## 8. Epoch checkpoints and validator handoff

An `EpochCheckpointV1` is a deterministically derived certificate over an
already order-finalized checkpoint block; it is not inserted into the block it
names. This avoids a block-root -> checkpoint -> block-ID cycle. Its exact body
is:

```text
EpochCheckpointBodyV1 =
  schema_version                    u16  // 1
  context                           ProtocolContextV1
  epoch                             u64
  checkpoint_height                 u64
  checkpoint_block_id               BlockIdV1
  checkpoint_header                 BlockHeaderV1
  epoch_descriptor_id               EpochDescriptorIdV1
  validator_set_hash                Hash32
  consensus_parameters_hash         Hash32
  application_state_root            Hash32
  da_committee_set_root             Hash32
  verification_registry_hash        Hash32
  stack_profile_hash                 Hash32
  fee_schedule_hash                  Hash32
  state_schema_hash                  Hash32
  snapshot_policy_hash               Hash32
  next_epoch_descriptor_id           Option<EpochDescriptorIdV1>
  upgrade_plan_id                    Option<UpgradePlanIdV1>
```

The body is uniquely projected from the exact finalized header, finalized
application state and epoch descriptors/registries. Every repeated root
must equal its authoritative source. `snapshot_policy_hash` commits only the
context-free chunking/compression/bounds/retention policy in document 09; the
independent `application_state_root` is the checkpoint state authority. It is
not a future `StateSyncManifestIdV1`. The manifest is constructed
after finality and points one-way to this checkpoint. `EpochCheckpointIdV1` is
`DigestV1("trnm.poco-ai.epoch-checkpoint.v1", EpochCheckpointBodyV1)` and the
enclosing object contains the body plus recomputed ID.
`EpochCheckpointVerificationAttachmentV1` is the non-identifying pair
`(checkpoint_id:EpochCheckpointIdV1,
order_finality_proof:OrderFinalityProofV1)`. The proof must finalize the exact
checkpoint block/header/state and may be replaced by another valid proof path;
its path/signer subset/trusted anchor never changes checkpoint identity. A
handoff signs the deterministic checkpoint ID only after locally verifying at
least one such attachment.

Reference v1 deliberately carries no redundant live-object/liability/hold
projection roots in the checkpoint. The sole authority is the complete
`application_state_root` plus the epoch/profile policies; snapshot construction
must include every present state leaf. Adding cached projection roots without
an exhaustive state-kind matrix would create a second ambiguous authority and
requires a later protocol version.

For every admitted consensus object, the `validator_set_hash` and
`consensus_parameters_hash` in its exact `ConsensusContextV1` MUST equal the
same-named fields in the epoch descriptor identified by the header. The
signed `runtime_profile_hash` MUST equal both the epoch descriptor's exact
`runtime_profile_hash` and the `runtime_profile_hash` in the complete decoded
`StackProfileV1` selected by `context.stack_profile_hash`. Every nested
`ConsensusContextV1.context` MUST be byte-identical to the authoritative
header/descriptor context; these equalities are checked before signature
verification or weight accumulation. The descriptor's `stack_profile_hash`, DA policy, verification registry, fee
schedule, state schema, and leader schedule MUST equal the corresponding
epoch-committed values used by execution, state sync, and light-client state.
Its `snapshot_policy_hash` MUST equal the complete decoded StackProfile field
and the exact policy preimage used by checkpoint/state-sync construction.
There is no independent `*_root` alias that can select different facts.

The current epoch is sealed before a successor set signs. `EpochHandoffBodyV1`
is exact:

```text
schema_version                    u16  // 1
source_context                    ProtocolContextV1
target_context                    ProtocolContextV1
old_epoch                         u64
new_epoch                         u64
old_epoch_checkpoint_id           EpochCheckpointIdV1
old_epoch_descriptor_id           EpochDescriptorIdV1
new_epoch_descriptor_id           EpochDescriptorIdV1
old_validator_set_hash            Hash32
new_validator_set_hash            Hash32
old_consensus_parameters_hash     Hash32
new_consensus_parameters_hash     Hash32
terminal_block_id                 BlockIdV1
terminal_height                   u64
terminal_view                     u64
activation_height                 u64
initial_new_view                  u64
```

`new_epoch = old_epoch + 1`, `activation_height = terminal_height + 1`, and
`initial_new_view = 1` with checked arithmetic. Source and target contexts must
have identical genesis hash, chain ID, and protocol version `1`; source stack
profile equals the old descriptor/checkpoint profile and target stack profile
equals the new descriptor profile. A profile change is therefore explicit and
covered by both roles, never forced into one ambiguous context. Every repeated
set, parameter, descriptor, checkpoint, block, height, context, and profile
fact must resolve to and equal its authoritative preimage. `EpochHandoffIdV1` is the digest of
the body under `trnm.poco-ai.epoch-handoff.v1`.
`terminal_view` MUST equal the authenticated terminal Seal2 header and QC view;
it is the unique OldSet handoff signing view.

`EpochHandoffSignStatementV1` is exactly `(schema_version:u16=1,
consensus_context:ConsensusContextV1, handoff_id:EpochHandoffIdV1)`. For role
`0 OldSet`, the consensus context uses source context/runtime, old epoch/set/
parameters, `terminal_view`, and message kind EpochHandoffOldSet. For role
`1 NewSet`, it uses target context/runtime, new epoch/set/parameters,
`initial_new_view`, and EpochHandoffNewSet. Every field must equal the handoff
body/descriptors. `EpochHandoffSignatureEntryV1` is exactly `(signer_id:Bytes,
role:u8, statement:EpochHandoffSignStatementV1, signature_scheme:u16,
signature:Bytes)`, where OldSet signs
`DigestV1("trnm.poco-ai.epoch-handoff-old-signature.v1", statement)` and NewSet
signs the corresponding `...epoch-handoff-new-signature.v1` root. Thus every
handoff signature begins with the complete role-specific consensus context;
signing the body or handoff ID alone is invalid. `EpochHandoffV1` is exactly `(body:
EpochHandoffBodyV1, handoff_id:EpochHandoffIdV1,
old_set_signatures:List<EpochHandoffSignatureEntryV1>,
new_set_signatures:List<EpochHandoffSignatureEntryV1>)`; each list is strictly
ordered and unique and its entries have only the matching role. Activation of
a different validator set requires:

1. quorum under the old epoch's weights and keys; and
2. quorum under the new epoch's weights and keys.

Before either role signature escapes, the signing owner commits and reads back
`EpochHandoffSignJournalV1` with exact conflict key `(genesis_hash, old_epoch,
new_epoch, role, signer_id)` and value `(source_context, target_context,
handoff_id, complete EpochHandoffSignStatementV1, signature_scheme,
signing_digest)`. The journal, role-specific signer watermark, commissioned
old/new descriptors, SafetyState, and whole-node checkpoint cross one
persist-before-sign barrier. Exact replay may reproduce the same signature; a
different handoff/body/statement/digest under that key, missing commissioning,
ambiguous commit, or rollback fails closed. Old/new roles are distinct conflict
coordinates even for an overlapping validator.

Overlapping validators sign in each explicitly named role; weight is never
silently reused across sets. Until both certificates and local durable
commissioning exist, the successor epoch cannot vote. A failed handoff stalls
safely; it never falls back to the old set, CometBFT, or an alternate profile.

## 9. Dual finality

V1 exposes distinct statuses:

- **Order finality**: the transaction/protocol-object order and deterministic
  state transition are irreversible under the BFT assumptions.
- **Result finality**: the exact `VerificationProfileV1` has accepted the
  execution result and all challenge/appeal conditions are closed.
- **Settlement finality**: payment, refund, bond, slash, and reward deltas are
  durably applied and order-finalized after result maturity.

A later successful challenge creates forward compensation, refund, slashing,
reputation, and replacement-task transitions. It MUST NOT reorg or erase an
order-finalized block. Clients and light clients must never label an Order QC
as result or settlement finality.

## 10. Required evidence before freeze

Freeze requires independent canonical bytes and negative vectors for every
header, proposal, vote, timeout, QC, TC, checkpoint, and handoff object;
cross-chain/profile/epoch replay rejection; retained duplicate-weight,
TC-unlock, two-chain-finality, sign-before-persist, and single-quorum-handoff
mutants; a state-machine model covering partitions, heal, view changes,
rollback, epoch close, and v0-to-v1 activation; two interoperable decoders; and
multi-host 4/7 validator fault evidence. None of this complete v1 evidence
exists today.
