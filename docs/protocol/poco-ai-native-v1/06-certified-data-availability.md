# 06 — Certified Data Availability

Status: **draft normative target; design-only, not implemented, not frozen, not activated**

This document defines the PoCO-DA plane for `protocol_version = 1`. It does
not amend PoCO-BFT v0. The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY**
describe the target conformance contract; they do not describe current code.

## 1. Purpose and separation

PoCO-DA separates data dissemination from ordering. The Order plane orders
small authenticated references; it does not make a leader retransmit every
transaction or AI artifact. Two namespaces remain semantically distinct:

1. `TransactionBatch`: canonical transaction bytes that every voting validator
   must retrieve and deterministically validate or execute before voting.
2. `ArtifactEvidence`: model, dataset, prompt, output, trace, meter, proof, or
   challenge material whose consumers are selected by the task's exact
   `VerificationProfileV1`.

An availability certificate proves only that a committed quorum signed an
exact durable-retention statement. It does not prove correctness, usefulness,
privacy, fair price, payment, party independence, current retrievability after
the retention window, or order finality.

## 2. Epoch-scoped authority

`DaMemberBodyV1` is exact and context-free:

```text
attestation_key_scheme      u16                 // 0 = strict Ed25519
attestation_public_key      Bytes
weight                      u128                // positive
validator_id                Option<Bytes>
storage_service_commitment  Hash32
slashable_bond_reference    Hash32
```

`DaMemberDefinitionHashV1` is the context-free `Hash32` result of
`DigestV1("trnm.poco-ai.da-member.v1", DaMemberBodyV1)`.
`DaMemberV1` is exactly `(body: DaMemberBodyV1, member_definition_hash:
DaMemberDefinitionHashV1)`;
the definition hash is recomputed and is not part of its own preimage. It is a
context-free content hash, never a `TypedObjectIdV1` or `ObjectKindV1` member.
A committee list is
strictly increasing by raw definition hash and duplicate-free by definition
hash and
attestation public key.

Every epoch commits an exact `DaCommitteeDefinitionV1` body:

```text
schema_version              u16                 // 1
namespace                   DaNamespaceV1
members                     List<DaMemberV1>     // canonical member-id order
threshold_weight            u128
retention_epochs            u32
max_author_bytes             u64
max_batch_bytes              u64
max_batch_items              u32
max_outstanding_sequences    u32
attestation_profile_id       Hash32
```

The definition is always context-free: it never contains `ProtocolContextV1`,
`epoch`, `committee_id`, or a chain-derived object ID. Its exact content hash is
committed by the ChainDescriptor defined in document 02. After genesis/context exists,
`DaCommitteeDescriptorV1` is exactly:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
epoch                       u64
definition                  DaCommitteeDefinitionV1
```

It does not contain its own ID. `committee_id` is
`DigestV1("trnm.poco-ai.da-committee.v1", DaCommitteeDescriptorV1)`. The
context-bound descriptor must project byte-for-byte to the committed bootstrap
definition at epoch zero; this avoids a self-referential digest.

For the reference profile, an envelope's retention end is not author selected:

```text
required_retention_epochs = max(
  committee.retention_epochs,
  namespace == TransactionBatch
    ? policy.transaction_retention_epochs
    : policy.artifact_retention_epochs
)
retention_end_epoch = checked_add(epoch, u64(required_retention_epochs))
```

Overflow is invalid. A later profile may enumerate a paid longer window, but
it MUST commit exact minimum/maximum retention values and the selected duration
in the envelope; it may never be shorter than the committee definition or any
transaction-vote, state-sync, evidence, task, verification, challenge, or
settlement horizon that already references the batch. Both availability
certificate and `BatchRefV1` MUST equal the envelope's derived value exactly.

`DaNamespaceV1` is `0 TransactionBatch` or `1 ArtifactEvidence`. A member has
an immutable epoch-scoped member ID, strict Ed25519 attestation key, positive
checked weight, storage-service commitment, and slashable bond reference.
Duplicate identities, keys, or member IDs are invalid. The committee ID is the
domain-separated ID of the complete descriptor.

The member list is nonempty. `total_weight` is the checked `u128` sum of all
positive member weights and `threshold_weight` MUST satisfy
`1 <= threshold_weight <= total_weight`. For the reference TransactionBatch
committee it MUST equal `floor(2 * total_weight / 3) + 1` using checked
arithmetic and its member IDs, keys, and weights MUST exactly project the
epoch validator set. A certificate has a nonempty signer list; threshold zero,
an empty committee, overflow, or a threshold above total is invalid for every
namespace. ArtifactEvidence profiles must state their own positive threshold
and corruption model and cannot weaken these structural checks.

The reference shadow profile uses the active validator set and the same
effective weights for `TransactionBatch`, with
`floor(2W/3)+1` attestation weight. This makes every valid certificate intersect
every Order QC in honest weight under the reference fault assumption. A future
separate storage committee is a protocol/profile change and MUST independently
state its corruption, intersection, and recovery assumptions.

For the reference TransactionBatch committee, each validator member projects
to exactly one DA member in validator-set order: `validator_id` is `Some` of
the exact validator ID, attestation key scheme/public key and weight equal the
validator consensus key and voting weight, and the bond reference equals the
validator's committed PoCO economic record hash. The storage-service
commitment comes from the epoch DA policy. The `DaMemberDefinitionHashV1` and committee ID
are then recomputed; raw equality between a validator-set hash and committee ID
is neither required nor allowed as a substitute for this projection.

`ArtifactEvidence` MAY use a separately committed bonded committee only after
its profile and light-client rules are frozen. An Artifact certificate never
substitutes for TransactionBatch availability.

`DaAuthorAuthorityV1` is exactly `(author_id:Bytes, author_key_scheme:u16,
author_public_key:Bytes, allowed_namespaces:List<DaNamespaceV1>,
first_sequence:u64, maximum_sequence:u64,
funding_account_id:AccountIdV1,max_storage_charge_per_batch:u128)`, ordered by raw author ID with
unique IDs/keys and strictly ordered unique namespaces.
`DaPolicyBodyV1` is exact and context-free:

```text
schema_version                 u16  // 1
policy_revision               u32
committee_definition_set_hash Hash32
authorities                   List<DaAuthorAuthorityV1>
max_batch_bytes               u64
max_batch_items               u32
max_chunk_bytes               u64
max_chunks_per_batch          u32
max_outstanding_sequences     u32
transaction_retention_epochs  u32
artifact_retention_epochs     u32
retrieval_window_blocks       u64
repair_window_blocks          u64
storage_asset_id              Hash32
storage_price_per_byte_epoch  u128
storage_destination_pool_id   ValuePoolIdV1
allowed_content_profiles      List<DaContentProfileV1>
```

`DaContentProfileV1` is exactly `(namespace:DaNamespaceV1,content_kind:u16,
content_codec_id:Hash32,chunking_profile_id:Hash32)`, strictly ordered/unique
by all four fields. Reference v1 has exactly two entries: TransactionBatch uses
kind 0 and ArtifactEvidence kind 1; both use codec `DigestV1(
"trnm.poco-ai.da-codec.v1",(schema_version:u16=1,codec:u8=0))`. Codec 0 is the
exact CEV1 content list below. The sole chunk profile is
`DaChunkingProfileV1 = (schema_version:u16=1,algorithm:u8=0,
max_chunk_bytes:u64)` under `trnm.poco-ai.da-chunking-profile.v1`. Algorithm 0
greedily takes the next nonempty contiguous slice of canonical content bytes of
length `min(remaining,max_chunk_bytes)`; empty content is invalid. Envelope
values must match one allowlist entry and decoded profile.

Every bound/window is positive, sequence ranges are valid, and values cannot
exceed the component profile/consensus limits. `da_policy_hash = DigestV1(
"trnm.poco-ai.da-policy.v1", DaPolicyBodyV1)`. The epoch descriptor's policy
hash resolves this exact body; its committee-definition set must project
exactly to `da_committee_set_root`, and batch author ID/key/namespace/sequence
must resolve to one exact authority entry. There is no separate local author
registry or committee-selection default.
CertificateMinimum obligation creation computes `charge = checked_mul(
uncompressed_bytes,retention_epoch_count,storage_price_per_byte_epoch)`,
requires it no greater than the author authority maximum, verifies the funding
Account owner/asset/exact version, and atomically moves that charge to the
policy destination pool while creating the obligation. For task/verification/
challenge/settlement/evidence obligations, the owner object's immutable policy
commits a DA budget and its Escrow funding account; the same price formula and
destination apply and the owner transition reserves/debits that exact amount.
StateSync uses its profile-committed system pool. Legal Create names a
governance-authorized Account. Thus every derived obligation has one typed
funding source, checked charge, destination and conserved write; insufficient
budget invalidates its owner/certificate transition.

## 3. Canonical batch envelope

`DaBatchEnvelopeV1` has this logical field order:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
namespace                   DaNamespaceV1
epoch                       u64
committee_id                DaCommitteeIdV1
author_id                   Bytes
author_sequence             u64                 // positive and monotonic
content_kind                u16
content_codec_id            Hash32
item_count                  u32
uncompressed_bytes          u64
content_root                Hash32
chunking_profile_id         Hash32
chunk_count                 u32
chunk_root                  Hash32
retention_end_epoch         u64
task_scope                  Option<TaskIdV1>
verification_profile_id     Option<Bytes>
verification_profile_version Option<u32>
verification_profile_hash   Option<Hash32>
encryption_commitment       Option<Hash32>
```

`TransactionBatch` requires `task_scope`, all three verification-profile
fields, and `encryption_commitment` to be absent. Its content is the exact CEV1
`List<Bytes>` of canonical transaction envelopes in author order.

The three verification-profile option fields MUST be either all absent or all
present; partial identity is invalid. `ArtifactEvidence` requires a recognized
`content_kind`. Its content is one or more exact complete
`ArtifactCommitmentV1`/stored-byte pairs defined by section 4 below; the
`ArtifactIdV1` and stored-content digest are recomputed before attestation. The task and exact
`(profile_id, profile_version, profile_hash)` bindings are present whenever the artifact is task
scoped. Encryption does not relax availability: the certificate binds the
ciphertext bytes and encryption commitment, while key-release semantics belong
to the task/verification profile.

The batch ID is:

```text
DigestV1("trnm.poco-ai.da-batch.v1", DaBatchEnvelopeV1)
```

`DaBatchAuthorStatementV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, namespace:DaNamespaceV1, epoch:u64,
committee_id:DaCommitteeIdV1, author_id:Bytes, author_sequence:u64,
batch_id:BatchIdV1)`. `DaBatchAuthorV1` is exactly `(statement:
DaBatchAuthorStatementV1, author_key_scheme:u16, author_public_key:Bytes,
signature:Bytes)`, signing `DigestV1("trnm.poco-ai.da-batch-author-signature.v1",
statement)`. The epoch DA policy maps each allowed `author_id` to one exact
strict Ed25519 key (or, for a validator author, the exact epoch validator key);
the supplied public key must equal that authority. The envelope is accepted or
attested only with this author wrapper and exact statement equality.

Before an author signature escapes, the author durably journals the full
statement. Its conflict key is `(genesis_hash, protocol_version,
stack_profile_hash, namespace, epoch, author_id, author_sequence)`. Exact replay
returns the same signature; a different envelope/batch, sequence rollback, or
lower durable author watermark fails closed. Only two valid conflicting author
signatures under one key are author-equivocation evidence. Unsigned fields,
network source identity, or a conflicting peer envelope cannot consume another
author's sequence or attribute equivocation.

For one `(context, namespace, epoch, author_id, author_sequence)`, only one
batch ID is valid. Two valid author-wrapped conflicting envelopes are author
equivocation evidence; an unsigned conflict is only invalid peer input.
Sequence zero, gaps beyond the committed admission window, duplicate items,
unknown codecs, or arithmetic overflow are invalid.

## 4. Chunks and roots

The reference profile uses full replication. It MAY transport fixed-size
chunks for bounded I/O and repair, but every attestor stores the entire
canonical batch. Erasure coding and sampling are inactive.

DA list roots use document 02's exact typed-root construction.
`TransactionBatch.content_root` uses root kind 7,
`ArtifactEvidence.content_root` uses kind 8, and `chunk_root` uses kind 9.
`DaContentItemCommitmentV1` is the exact record `(schema_version: u16 = 1,
namespace: DaNamespaceV1, item_kind: u16, item_id: TypedObjectIdV1,
item_bytes: Bytes)`. Its commitment is
`DigestV1("trnm.poco-ai.da-content-item.v1",
DaContentItemCommitmentV1)`. For `TransactionBatch`, `item_kind = 0`, the typed
ID tag is `21 AgentTransactionIdV1`, `item_bytes` is the complete canonical
CEV1 `AgentTransactionV1` including authorization sets, and its body-derived ID
must recompute to `item_id`. For `ArtifactEvidence`, `item_kind = 1`, the tag is
`16 ArtifactIdV1`, and `item_bytes` is the complete canonical
`ArtifactCommitmentV1` plus exact stored artifact bytes as the closed record
`(commitment: ArtifactCommitmentV1, stored_bytes: Bytes)`; both artifact ID and
content digest must recompute. No body-only, transport wrapper, compressed
bytes, detached signature, or alternate admitted-object encoding is an alias.
The Merkle leaf's `item_kind`, raw typed-ID digest, and `item_commitment` are
these exact values. Unknown kinds or a namespace/kind/tag mismatch fail closed.

A chunk cannot bind the final `batch_id`, because `batch_id` already
commits `chunk_root`. Its non-circular coordinate is exactly:

```text
DaChunkCoordinateV1 =
  schema_version       u16  // 1
  context              ProtocolContextV1
  namespace            DaNamespaceV1
  epoch                u64
  committee_id         DaCommitteeIdV1
  author_id            Bytes
  author_sequence      u64
  chunking_profile_id  Hash32
  chunk_index          u32
  exact_byte_length    u64
```

For a chunk, `item_kind` is zero and `item_id` is
`DigestV1("trnm.poco-ai.da-chunk-id.v1", DaChunkCoordinateV1)`. Its
`item_commitment` is
`DigestV1("trnm.poco-ai.da-chunk-bytes.v1", raw_bytes)`.
The envelope separately binds chunk count and uncompressed byte count, so
truncation, duplicate-last padding, reordered chunks, or an alternate chunking
profile cannot reproduce the same accepted envelope. A chunk coordinate MUST
equal the enclosing envelope fields and its index MUST be below `chunk_count`;
the leaf's position equals `chunk_index`. This yields a one-way construction:
chunk coordinates/bytes -> `chunk_root` -> envelope -> `batch_id`, never
`batch_id` -> `chunk_root` -> `batch_id`. `content_root` is computed from the
reconstructed canonical content, not transport compression bytes.

Compression is transport-only. An attestor MUST bound compressed and
uncompressed sizes, reject trailing or non-canonical content, reconstruct the
exact content root, and store the canonical uncompressed bytes or a
profile-authorized lossless representation with deterministic reconstruction.

## 5. Durable-before-attest contract

`DaAttestationBodyV1` binds:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
namespace                   DaNamespaceV1
epoch                       u64
committee_id                DaCommitteeIdV1
batch_id                    BatchIdV1
content_root                Hash32
chunk_root                  Hash32
retention_end_epoch         u64
attestor_id                 DaMemberDefinitionHashV1
author_id                   Bytes
author_sequence             u64
attestation_sequence        u64
storage_record_checksum     Hash32
```

`DaAttestationIdV1` is
`DigestV1("trnm.poco-ai.da-attestation.v1", DaAttestationBodyV1)`.
`DaAttestationV1` is exactly `(body: DaAttestationBodyV1,
attestation_id: DaAttestationIdV1, signature_scheme: u16,
signature: Bytes)`. The attestor signs
`DigestV1("trnm.poco-ai.da-attestation-signature.v1",
attestation_id)`. The ID, scheme, and signature are never accepted from
transport without recomputing the body ID and exact signing root.

Before a signature can leave the attestor, it MUST:

1. validate the envelope, committee, author sequence, bounds, chunks, and exact
   reconstructed roots;
2. reserve the committed retention capacity;
3. durably store every required byte and an exact storage manifest;
4. durably append an anti-equivocation journal entry for the complete
   attestation preimage;
5. fsync the data, manifest, journal, and directory/database boundary required
   by the storage profile;
6. read back and recompute the storage-record checksum; and only then
7. request the strict attestation signature.

The journal conflict key is
`(genesis_hash, protocol_version, stack_profile_hash, namespace, epoch,
attestor_id, author_id, author_sequence)`. Exact replay returns the same
signature. A different batch under the same key, a lower attestation sequence,
a shortened retention end, or a rollbacked storage record fails closed.
`attestor_id` MUST resolve to exactly one member of `committee_id`; its
signature key and positive weight come only from that member body. Membership,
canonical ordering, duplicate rejection, journal identity, and checked weight
accumulation all use the raw context-free `DaMemberDefinitionHashV1`. The optional validator ID is
committed metadata and is never an alias or second weight key. The
attestation's `author_id` and `author_sequence` MUST equal the complete
envelope fields for `batch_id`; a verifier checks that equality before using
the conflict coordinate.

The DA attestation journal is independent of the consensus SafetyState and
signer journal. The whole-node monotonic checkpoint MUST bind all three before
production activation.

## 6. Availability certificate

`AvailabilityCertificateBodyV1` is exact:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
namespace                   DaNamespaceV1
epoch                       u64
committee_id                DaCommitteeIdV1
envelope                    DaBatchEnvelopeV1
author                      DaBatchAuthorV1
attestations                List<DaAttestationV1>
```

`AvailabilityCertificateV1` is exactly `(body:
AvailabilityCertificateBodyV1, certificate_id:
AvailabilityCertificateIdV1)`. Attestations are strictly ordered by
`body.attestor_id`. Every attestation context/namespace/epoch/committee/batch,
roots, author coordinate, and retention end MUST equal the enclosing envelope
and certificate body, and the author statement/signature must verify before any
attestor weight is counted. A verifier MUST reject duplicate
attestors before summing checked weight, recompute every signing root, verify
the exact epoch committee, and require attested weight at least the committed
threshold.

The certificate ID is independent of transport layout and is derived from the
canonical certificate body, including the unique signer set:

```text
DigestV1("trnm.poco-ai.availability-certificate.v1",
         AvailabilityCertificateBodyV1)
```

A valid certificate does not authorize Order inclusion by itself. A
TransactionBatch reference is vote-eligible only after the local validator has
retrieved the complete batch, reconstructed both roots, decoded every
transaction canonically, and completed the deterministic execution predicate
in [07](07-order-consensus-epochs-and-finality.md).

## 7. Retrieval, repair, and retention

Peers retrieve by `(certificate_id, batch_id, chunk_range)`. A successful
request is explicit and signed. `RetrievalRequestBodyV1` is exactly
`(schema_version:u16=1,context:ProtocolContextV1,requester_id:Bytes,
certificate_id:AvailabilityCertificateIdV1,batch_id:BatchIdV1,
first_chunk_index:u32,chunk_count:u32,request_nonce:Hash32,
request_height:u64,request_expiry_height:u64)`. The range is nonempty and in
bounds, `request_expiry_height >= request_height`, and its checked difference
is no greater than the selected epoch `DaPolicyBodyV1.retrieval_window_blocks`.
`request_id = DigestV1("trnm.poco-ai.retrieval-request.v1",
RetrievalRequestBodyV1)`. `RetrievalRequestV1` is exactly `(body:
RetrievalRequestBodyV1,request_id:Hash32,requester_key_scheme:u16,
requester_public_key:Bytes,signature:Bytes)`, whose key resolves to the named
authenticated requester and whose signature covers `DigestV1(
"trnm.poco-ai.retrieval-request-signature.v1",body)`. Request ID, nonce, range,
heights, certificate and batch are never prover-selected aliases.

A successful
`RetrievalReceiptBodyV1` is exact:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
request_id                  Hash32
requester_id                Bytes
responder_id                Bytes
certificate_id              AvailabilityCertificateIdV1
batch_id                    BatchIdV1
first_chunk_index           u32
chunk_count                 u32
returned_chunks_root        Hash32
response_height             u64
```

`DaChunkInclusionProofV1` is exactly `(global_chunk_index:u32,
chunk_item_count:u32,merkle_path:List<MerkleStepV1>)` and recomputes RootKind 9
with the coordinate-derived item ID and exact byte commitment to the certified
envelope `chunk_root`. `ReturnedChunkEntryV1` is exactly `(chunk_index:u32,
coordinate:DaChunkCoordinateV1,chunk_bytes:Bytes,
inclusion_proof:DaChunkInclusionProofV1)`. Entries cover precisely the
requested contiguous global batch indices, are gap-free/increasing, and every
coordinate, length, byte commitment, and RootKind-9 global leaf matches the
certified envelope. `returned_chunks_root` uses RootKind 10 with response-local
leaf index starting at zero, `item_id` equal the coordinate chunk ID, and
commitment equal the exact chunk-byte digest. `RetrievalResponseV1` is exactly
`(body:RetrievalReceiptBodyV1,receipt_id:RetrievalReceiptIdV1,
returned_chunks:List<ReturnedChunkEntryV1>,responder_key_scheme:u16,
responder_public_key:Bytes,signature:Bytes)`. The inline list recomputes the
body range/count/root; responder ID/key resolves to the active committee or
policy-authorized retrieval service, and the signature covers the recomputed
receipt ID. A receipt without returned bytes is not a successful retrieval
proof.

`RetrievalProofV1` is an exact alias for `(request:RetrievalRequestV1,
response:RetrievalResponseV1,certificate:AvailabilityCertificateV1,
da_policy:DaPolicyBodyV1)`. It recomputes every request/response/certificate/
batch ID and signature; response requester/request ID/certificate/batch/range
MUST exactly echo the request, and `response_height` lies in
`[request_height, request_expiry_height]`. It verifies every global chunk path.
The only accepted freshness bound is the checked value
`fresh_until_height = min(request_expiry_height,
checked_add(response_height,da_policy.retrieval_window_blocks))`; it is derived,
not carried by the proof. Proof-validation height MUST be no greater than this
bound. The policy hash/contents MUST be authenticated by the same epoch path as
the certificate; an arbitrary inline policy is invalid.

`RetrievalReceiptIdV1` is
`DigestV1("trnm.poco-ai.retrieval-receipt.v1",
RetrievalReceiptBodyV1)`, and the responder signature uses
`trnm.poco-ai.retrieval-receipt-signature.v1`. A receipt proves the signed
response/root statement, not availability of omitted chunks or future service.
`returned_chunks_root` uses root kind 10 and the same chunk leaf facts.
Responses bind the
request ID, responder, exact batch/chunk roots, indices, and bytes. Nodes MUST
verify before caching or forwarding and MUST bound concurrent requests,
response bytes, decompression, hashing, and per-peer work.

An attestor MAY repair its copy from any valid peer, but repair does not erase
the original durable obligation. Loss, corruption, or rollback before
`retention_end_epoch` latches the attestor unavailable until exact repair and
readback complete. It MUST NOT sign a successor whole-node checkpoint that
pretends the obligation remained continuously satisfied.

Garbage collection is legal only when all are true:

- the finalized epoch is strictly greater than `retention_end_epoch`;
- no open task, verification, challenge, settlement, state-sync, or evidence
  hold references the batch;
- the committed minimum state-sync/evidence horizon has passed;
- an exact GC tombstone is durable before bytes are removed.

Task or challenge retention extensions are forward state transitions. They
cannot silently extend an already-signed storage obligation; a new retention
certificate and funded storage lease are required.

Every retained batch/hold is authenticated as `DaObligationBodyV1 =
(schema_version:u16=1,context:ProtocolContextV1,namespace:DaNamespaceV1,
batch_id:BatchIdV1,certificate_id:AvailabilityCertificateIdV1,
source_object_id:TypedObjectIdV1,reason:u16,obligation_nonce:Hash32)` and
`DaObligationIdV1 = DigestV1("trnm.poco-ai.da-obligation.v1",body)` (kind 49).
`DaObligationStateV1 = (schema_version:u16=1,
context:ProtocolContextV1,obligation_id:DaObligationIdV1,version:u64,
retain_until_epoch:u64,hold_until_height:u64,status:u8,
gc_tombstone_height:Option<u64>)`, with status `0 Active` or `1 Released`.
Reason is `0 CertificateMinimum`, `1 Task`, `2 Verification`, `3 Challenge`,
`4 Settlement`, `5 StateSync`, `6 Evidence`, or `7 Legal`. Creation/extension
is an exact funded operation owned by the source lifecycle and may only raise
deadlines; GC is permitted only after every obligation for the batch is
Released and atomically records the unique tombstone height. Snapshot/state
sync includes these state leaves and derives its fetch/retention set from them;
local indexes cannot omit an obligation.

`DaObligationOperationBodyV1` is the closed carrier `(schema_version:u16=1,
context:ProtocolContextV1,action:u8,obligation_body:DaObligationBodyV1,
expected_version:Option<u64>,requested_retain_until_epoch:u64,
requested_hold_until_height:u64,funding_source_id:TypedObjectIdV1,
funding_amount:u128,authority_object_ids:List<TypedObjectIdV1>)`. Actions are
`0 Create`, `1 Extend`, `2 Release`, or `3 GarbageCollect`. Create requires no
existing state/version, positive policy-priced funding, and deadlines at least
the certificate/policy/lifecycle minimum. Extend requires Active state at the
exact version and may only raise deadlines with incremental funding. Release
requires Active state at the exact version and proof that its source lifecycle
and every dependent hold are terminal; it increments version and leaves the
tombstone absent. GarbageCollect is permissionless only for Released state at
the exact version after every GC predicate; it increments version, records the
unique current-height tombstone, and atomically removes the byte-store
obligation but not the authenticated state leaf. Repetition is invalid.

The closed reason/authority matrix is: CertificateMinimum is uniquely derived
as an atomic state side effect of certificate admission under committee
policy; Task, Verification, Challenge, Settlement and Evidence are uniquely
derived atomic state side effects of their exact owner lifecycle operation;
StateSync creation is derived from a finalized snapshot manifest and committed
snapshot policy. These create actions are not caller-supplied sub-operations:
the owner transition and frozen policy construct their exact state writes.
Standalone kind 28 carries Extend, Release, GarbageCollect, and governance-
timelocked Legal Create only; caller-carried Create for another reason is
invalid. Source/reason,
authority list, funding, deadlines and amount equal the unique policy
projection. Unknown action/reason/authority, stale version, insufficient
funding or a partial write invalidates the whole transaction. No local
maintenance API can substitute for operation kind 28.

## 8. Quotas and backpressure

Consensus-visible limits come only from the epoch-committed stack profile.
They include maximum batch/item/chunk sizes, per-author outstanding sequences,
and namespace retention bounds. Violating them is deterministic invalidity.

Node-local queue, disk, memory, bandwidth, or worker limits MAY delay
admission, fetching, or attestation and return typed `Unavailable`. They MUST
NOT fabricate a certificate, change roots, reorder a batch, classify a
well-formed block as deterministically invalid, or release a signature without
the durable barrier. Capacity MUST be reserved before ownership is accepted.

Control, TransactionBatch, ArtifactEvidence, repair, state-sync, and challenge
traffic use separately bounded authenticated channels. Artifact uploads cannot
starve consensus control or transaction-batch retrieval.

## 9. Withholding and fault evidence

Non-response alone is not objective Byzantine evidence under partial
synchrony. A timeout or failed fetch MAY affect local routing, reputation, and
availability alarms but MUST NOT directly slash.

Objective `WithholdingEvidenceV1` is limited to cryptographically reproducible
facts such as:

- two signed attestations that conflict on one journal conflict key;
- a signed retrieval response whose bytes fail its attested root;
- a signed early-deletion/absence admission from an obligated attestor;
- a whole-node checkpoint or storage manifest that contradicts the signed
  retention obligation.

`WithholdingClaimV1` based on repeated bounded challenges is a provisional
application object. Its adjudication profile MUST define independent
challengers, timing, response route, evidence DA, and outcome. It is not
automatic consensus evidence and cannot retroactively invalidate an
order-finalized block.

## 10. State sync and light-client meaning

Snapshot manifests bind every still-live DA obligation needed to validate the
snapshot history, open tasks, pending challenges, and unsettled rollups. A
restoring validator MUST obtain and verify those manifests before it may attest
or vote. Peer snapshots never lower the local DA attestation journal or
whole-node checkpoint.

A light client can verify the committee commitment and certificate signatures.
It can conclude that a quorum attested to durable storage through the stated
retention epoch under the profile assumptions. It cannot conclude that the
bytes are retrievable now without a fresh retrieval proof, or that their
content is correct, private, useful, or settled.

## 11. Required conformance and failure evidence

Before this document can be frozen, independent vectors and tests MUST cover:

- exact CEV1 bytes, IDs, roots, signatures, certificate signer order, and
  threshold boundaries;
- cross-chain/profile/namespace replay, author and attestor equivocation,
  duplicate weight, alternate compression/chunking, truncation, and overflow;
- crash/SIGKILL/disk-full/short-write/commit-uncertain boundaries before and
  after data, manifest, journal, signature, and whole-node checkpoint commits;
- loss, corruption, repair, restart, retention extension, legal/early GC, and
  rollbacked storage namespaces;
- quota isolation and the inability of artifact load to starve control or
  TransactionBatch traffic;
- state-sync restoration with live holds and rejection of a snapshot that
  omits them;
- retained mutants for sign-before-store, duplicate signer weight,
  QC-as-availability, early GC, and non-response-as-slash.

No such complete evidence exists in the current repository; the status remains
design-only.
