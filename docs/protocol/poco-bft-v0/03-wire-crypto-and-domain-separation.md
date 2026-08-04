# 03 — Wire, Cryptography, and Domain Separation

## 1. Separation of logical schema and transport

The v0 signed and hashed representation is frozen. The P2 transport container, stream framing, RPC schema, and P2P multiplexing are `UNDECIDED`.

A transport may use Protobuf or another bounded binary container, but it MUST decode to exactly the frozen logical fields and MUST reconstruct the same canonical `CEV0` bytes before hashing or signature verification. Transport bytes themselves MUST NOT be signed unless they are byte-for-byte `CEV0`.

Consensus objects have three distinct concepts:

1. a logical value with a frozen field order and types;
2. its single canonical `CEV0` encoding;
3. a domain-separated SHA-256 digest, which is the only value signed by Ed25519.

## 2. `CEV0` canonical encoding

`CEV0` is a schema-driven encoding. No field tags or self-description are added; the schema fixes order and type.

### 2.1 Primitive encodings

```text
u8, u16, u32, u64, u128  fixed width, unsigned, big-endian
bool                     one u8: 0x00 false or 0x01 true
Hash32                    exactly 32 bytes
PublicKey32               exactly 32 bytes
Signature64               exactly 64 bytes
FixedBytes<N>             exactly N bytes
Bytes                     u32 byte_length || raw bytes
ConsensusString           u16 byte_length || restricted ASCII bytes
Optional<T>               u8 tag (0 absent, 1 present) || T when present
List<T>                   u32 element_count || each T in sequence
Struct                    fields concatenated in the frozen schema order
Enum                      one u8 discriminant frozen by that schema
```

`ConsensusString` MUST match:

```text
[a-z0-9][a-z0-9._:-]{0,127}
```

It is used only for machine identifiers such as `chain_id` and domain labels. Human display text is not a consensus string. Opaque application identifiers are `Bytes` with schema-specific bounds.

`CEV0` forbids maps, sets without a prescribed sort order, signed integers, floating point, decimal text, varints, JSON numbers, implicit defaults, duplicate fields, unknown fields, and trailing bytes. A collection that is semantically a set MUST be sorted by the key required by its schema and MUST reject duplicates. Decoders MUST check configured length/count limits before allocation.

There is no alternate “equivalent” encoding. Non-canonical data is rejected rather than normalized.

## 3. Hash construction

Define:

```text
Frame(x) = u32_be(len(x)) || x
HASH_PREFIX = ASCII("trnm.cev0.hash.v0")
Digest(domain, logical_value) =
    SHA-256(
        Frame(HASH_PREFIX) ||
        Frame(ASCII(domain)) ||
        Frame(CEV0(logical_value))
    )
```

All lengths in `Frame` are byte lengths and MUST fit `u32`. `domain` MUST be one of the exact frozen lowercase ASCII strings in this document. Implementations MUST NOT add terminators, whitespace, Unicode normalization, or implementation-specific type names.

An Ed25519 consensus signature is the RFC 8032 Ed25519 signature over the resulting 32-byte `Digest`, not Ed25519ph and not a signature over hexadecimal text or raw transport bytes.

Verifiers MUST use strict Ed25519 verification: canonical encodings, canonical scalar `S`, valid curve points, and rejection of non-canonical or small-order public keys/points according to the selected audited library's strict mode.

## 4. Frozen domains

The exact v0 domains are:

```text
trnm.poco-bft.block.v0
trnm.poco-bft.proposal.v0
trnm.poco-bft.vote.v0
trnm.poco-bft.timeout.v0
trnm.poco-bft.qc.v0
trnm.poco-bft.tc.v0
trnm.poco-bft.handoff-descriptor.v0
trnm.poco-bft.handoff-vote.v0
trnm.poco-bft.handoff-certificate.v0
trnm.poco-bft.validator-set.v0
trnm.poco-bft.validator-key-pop.v0
trnm.poco-bft.parameters.v0
trnm.poco-bft.epoch-commitment.v0
trnm.poco-bft.upgrade-plan.v0
trnm.poco-bft.finality-proof.v0
trnm.poco-bft.double-sign-evidence.v0
trnm.poco.consumption-certificate.v0
trnm.poco.consumption-certificate-id.v0
```

A domain change is a protocol-version change.

## 5. Common consensus context

Every signed consensus message begins with these logical fields in this order:

```text
schema_version          u16       // 0
genesis_hash            Hash32
chain_id                ConsensusString
protocol_version        u32       // 0 for this freeze
epoch                   u64
validator_set_hash      Hash32
view                    u64
message_kind            u8
```

`message_kind` discriminants are:

```text
0 proposal
1 vote
2 timeout
3 old_set_handoff_vote
4 new_set_handoff_vote
```

The domain and `message_kind` are both checked. A signature with a semantically mismatched pair is invalid.

Handoff messages additionally bind both old and new set hashes, both protocol versions, the transition descriptor, and the signer's role. The `validator_set_hash` in their common context is the set under which that particular signature's weight is counted.

## 6. Block header and block ID

The `BlockHeaderV0` field order is:

```text
schema_version                  u16
genesis_hash                    Hash32
chain_id                        ConsensusString
protocol_version                u32
epoch                           u64
view                            u64
height                          u64
block_kind                      u8
parent_block_id                 Hash32
proposer_id                     Bytes
active_validator_set_hash       Hash32
consensus_parameters_hash       Hash32
payload_root                    Hash32
state_root                      Hash32
receipts_root                   Hash32
evidence_root                   Hash32
timestamp_ms                    u64
next_epoch_commitment_hash      Optional<Hash32>
```

`block_kind` discriminants are:

```text
0 regular
1 epoch_checkpoint
2 epoch_seal_1
3 epoch_seal_2
4 epoch_handoff
```

The block ID is:

```text
Digest("trnm.poco-bft.block.v0", BlockHeaderV0)
```

The full block body contains the payload and evidence objects whose deterministic ordered Merkle roots match the header. The exact application transaction serialization is authenticated through `payload_root`; it remains governed by the runtime protocol, not redefined by this consensus envelope.

The header does not include its justify QC. Instead, the proposal signature binds the block ID and the exact certificate digests, preventing a leader from moving the same header between incompatible justifications.

## 7. Proposal signing value

`ProposalSignV0` is:

```text
context                         CommonConsensusContext
height                          u64
block_id                        Hash32
justify_qc_digest               Hash32
timeout_certificate_digest      Optional<Hash32>
handoff_certificate_digest      Optional<Hash32>
```

The proposer signs:

```text
Digest("trnm.poco-bft.proposal.v0", ProposalSignV0)
```

The context view MUST equal the block-header view. The context set hash MUST equal the block's active set hash.

`justify_qc_digest` always names the exact ordinary or context-authorized
synthetic QC carried by the proposal. Optional certificate presence is
canonical: an absent object has an absent digest and a present object has a
present digest equal to the object's canonical digest. For a first
non-genesis-epoch proposal, `handoff_certificate_digest` is derived from the
complete `EpochAnchorAuthorizationV0` below; a bare peer-supplied digest is not
an authorization.

The transport presence matrix is:

| Proposal class | `justify_qc` | timeout certificate | epoch-anchor authorization |
| --- | --- | --- | --- |
| ordinary, next view | signed ordinary parent QC | absent | absent |
| ordinary, skipped view | TC-selected signed ordinary parent QC | present | absent |
| genesis first block, view 1 | exact trusted `GenesisQC` | absent | absent |
| genesis first block, view > 1 | exact trusted `GenesisQC` | present and selects `GenesisQC` | absent |
| epoch first block, view 1 | exact authorized `EpochAnchorQC` | absent | required |
| epoch first block, view > 1 | exact authorized `EpochAnchorQC` | present and selects `EpochAnchorQC` | required |

A synthetic QC is invalid in every other proposal position.

## 8. Vote and QC values

`VoteSignV0` is:

```text
context              CommonConsensusContext  // message_kind = 1
height               u64
block_id             Hash32
```

The validator signs:

```text
Digest("trnm.poco-bft.vote.v0", VoteSignV0)
```

`QuorumCertificateV0` field order is:

```text
schema_version       u16
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32
epoch                u64
validator_set_hash   Hash32
view                 u64
height               u64
block_id              Hash32
signatures           List<(validator_id: Bytes, signature: Signature64)>
```

`signatures` MUST be strictly ordered by `validator_id`. Each signature verifies the reconstructed `VoteSignV0`. The QC digest is:

```text
Digest("trnm.poco-bft.qc.v0", QuorumCertificateV0)
```

The claimed total weight is deliberately absent from the canonical QC. It is always recomputed.

### 8.1 Context-authorized synthetic QCs

Synthetic anchors use the exact `QuorumCertificateV0` CEV0 schema and the
existing QC domain, with an empty signatures list. They do not add a kind byte
and do not change any ordinary QC digest.

The trusted genesis document reconstructs exactly one `GenesisQC`:

```text
schema_version       u16 = 0
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32 = 0
epoch                u64 = 0
validator_set_hash   Hash32 = epoch-0 set hash
view                 u64 = 0
height               u64 = 0
block_id              Hash32 = genesis_hash
signatures            List<SignatureShare> = empty
```

The synthetic genesis block has no `BlockHeaderV0`; its canonical block ID is
exactly `genesis_hash`. The `GenesisQC` digest is
`Digest("trnm.poco-bft.qc.v0", GenesisQCV0)`.

A verified joint handoff reconstructs exactly one `EpochAnchorQC`:

```text
schema_version       u16 = 0
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32 = new_protocol_version
epoch                u64 = new_epoch
validator_set_hash   Hash32 = new_validator_set_hash
view                 u64 = 0
height               u64 = terminal_old_height
block_id              Hash32 = terminal_old_block_id
signatures            List<SignatureShare> = empty
```

Its digest uses the same QC domain. `EpochAnchorAuthorizationV0` is the
following nested logical value and has no independent hash domain:

```text
terminal_old_header       BlockHeaderV0
terminal_old_qc           QuorumCertificateV0
handoff_certificate       HandoffCertificateV0
```

The terminal QC MUST certify the exact terminal header and match the
descriptor's terminal digest. The descriptor, checkpoint/seals, independent
old/new quorums, sets, parameters, versions, and activation height MUST all
verify before the epoch anchor is reconstructed.

An empty-signature QC is accepted only when it byte-for-byte matches the
trusted genesis anchor or a locally verified epoch-anchor authorization. It is
never an ordinary standalone QC, never certifies a block, and is never a
certifying QC in a finality proof. A proposal or TC may carry the exact anchor
QC for reconstruction, but peer transport alone grants it no authority.

## 9. Timeout and TC values

`HighQCSummaryV0` is:

```text
qc_digest           Hash32
qc_epoch            u64
qc_view             u64
qc_height           u64
qc_block_id         Hash32
```

`TimeoutSignV0` is:

```text
context             CommonConsensusContext  // message_kind = 2
high_qc             HighQCSummaryV0
```

The timeout signature is over:

```text
Digest("trnm.poco-bft.timeout.v0", TimeoutSignV0)
```

`TimeoutEntryV0` contains the signer ID, `HighQCSummaryV0`, and signature. `TimeoutCertificateV0` contains:

```text
schema_version              u16
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32
epoch                       u64
validator_set_hash          Hash32
timed_out_view              u64
entries                     List<TimeoutEntryV0>
referenced_qcs              List<QuorumCertificateV0>
selected_high_qc_digest     Hash32
```

Entries are strictly ordered by signer ID. Referenced QCs are deduplicated and
strictly ordered by QC digest. Every entry's summary MUST match one included
valid signed QC or the one context-authorized view-0 synthetic anchor. More
than one QC MAY have the same `(view, block_id)` when its
canonical signature subset, and therefore its digest, differs. The selected
digest MUST name the unique maximum included QC referenced by a counted entry
under `(view, block_id, qc_digest)`. Two QCs at the same epoch/view with
different block IDs remain a safety-assumption violation and invalidate the
TC. The TC digest is:

```text
Digest("trnm.poco-bft.tc.v0", TimeoutCertificateV0)
```

## 10. Validator-set commitment

`ValidatorV0` is:

```text
validator_id          Bytes
consensus_public_key  PublicKey32
effective_weight      u64
```

`ValidatorSetV0` is:

```text
schema_version             u16
genesis_hash               Hash32
chain_id                   ConsensusString
protocol_version           u32
epoch                      u64
consensus_parameters_hash  Hash32
validators                 List<ValidatorV0>
```

Validators are strictly ordered by `validator_id`; IDs and keys are unique; every effective weight is positive. P2P endpoints, display names, commission data, and operator metadata are not consensus-set fields.

The validator-set hash is:

```text
Digest("trnm.poco-bft.validator-set.v0", ValidatorSetV0)
```

## 11. Parameter commitment

`ConsensusParametersV0` has this exact field order:

```text
schema_version                              u16
protocol_version                            u32
production_activation                       bool
max_chain_id_bytes                          u16
max_validator_id_bytes                      u16
max_block_bytes                             u32
max_consensus_message_bytes                 u32
min_validators                              u32
max_validators                              u32
quorum_numerator                            u32
quorum_denominator                          u32
quorum_addend                               u32
finality_certified_chain_length             u8
max_total_voting_power                      u64
max_block_time_step_ms                      u64
leader_schedule                             u8
require_full_payload_before_vote            bool
base_timeout_ms                             u64
timeout_multiplier_numerator                u32
timeout_multiplier_denominator              u32
timeout_max_ms                              u64
epoch_length_blocks                         u64
epoch_seal_blocks                           u8
snapshot_lead_blocks                        u64
joint_handoff_old_quorum                    bool
joint_handoff_new_quorum                    bool
upgrade_notice_epochs                       u64
max_protocol_version_jump                   u32
scale_ppm                                   u64
maturity_epochs                             u64
max_certificate_age_epochs                  u64
decay_step_ppm_per_epoch                    u64
per_certificate_unit_cap                    u128
per_consumer_provider_epoch_unit_cap        u128
per_task_provider_epoch_unit_cap            u128
per_provider_epoch_unit_cap                 u128
units_per_power                             u128
bond_atomic_units_per_power                 u128
min_validator_power                         u64
max_validator_power                         u64
max_validator_share_ppm                     u64
capped_weight_alpha_ppm                     u64
full_weight_alpha_ppm                       u64
rollout_phase                               u8
minimum_shadow_epochs                       u64
minimum_eligibility_only_epochs             u64
minimum_capped_weight_epochs                u64
automatic_promotion                         bool
evidence_window_epochs                      u64
unbonding_delay_epochs                      u64
jail_duration_epochs                        u64
trusting_period_epochs                      u64
require_trusting_period_less_than_evidence  bool
require_evidence_window_le_unbonding_delay  bool
```

Enum values are:

```text
leader_schedule: 0 = canonical-validator-round-robin
rollout_phase:   0 = shadow, 1 = eligibility-only,
                 2 = capped-weight, 3 = full
```

The fixed `CEV0`/SHA-256/Ed25519 choices are protocol-version constants, not negotiable parameters. TOML keys `schema`, `profile`, string descriptions, comments, and the entire `[status]` table are not part of `ConsensusParametersV0`. Every remaining numeric/boolean TOML value maps once to the field above; a missing, duplicate, out-of-range, unknown-enum, or semantically inconsistent value makes the parameter set invalid.

Its hash is:

```text
Digest("trnm.poco-bft.parameters.v0", ConsensusParametersV0)
```

P0 freezes the logical value, not a transport generator. The independent
reference encoder and committed parameter vector live in
`scripts/ci/check_poco_bft_v0_parameters.py` and `vectors/parameters-v0.json`.
Until equivalent vectors exist for every frozen object and another
implementation reproduces them, no implementation may claim complete wire
conformance. Comments, TOML formatting, and non-consensus status text are
excluded from the logical value.

## 12. Epoch, handoff, proof, and evidence digests

The exact logical fields for epoch commitments and handoff objects are
specified in `04-epochs-validator-sets-and-upgrades.md`. A handoff descriptor
is independently hashed as:

```text
Digest("trnm.poco-bft.handoff-descriptor.v0", HandoffDescriptorV0)
```

Handoff votes bind that digest. The enclosing vote and certificate use the
`handoff-vote` and `handoff-certificate` domains respectively; none of these
three domains is reused for another logical schema.

`CertifiedHeaderV0` has this exact nested CEV0 field order:

```text
header                        BlockHeaderV0
justify_qc                    QuorumCertificateV0
timeout_certificate           Optional<TimeoutCertificateV0>
epoch_anchor_authorization    Optional<EpochAnchorAuthorizationV0>
proposer_signature            Signature64
certifying_qc                 QuorumCertificateV0
```

The header supplies proposer ID, view, height, block ID, set, parameters,
chain, genesis, and version, so the verifier reconstructs the exact
`ProposalSignV0` and verifies `proposer_signature`. Block IDs and nested object
digests may appear redundantly in transport but are recomputed and are not
additional CEV0 fields.

`FinalityProofV0` has this exact CEV0 field order:

```text
schema_version                 u16
genesis_hash                   Hash32
chain_id                       ConsensusString
protocol_version               u32
epoch                          u64
validator_set_hash             Hash32
consensus_parameters_hash      Hash32
finalized_block                CertifiedHeaderV0
child                          CertifiedHeaderV0
grandchild                     CertifiedHeaderV0
```

Its digest is
`Digest("trnm.poco-bft.finality-proof.v0", FinalityProofV0)`. Every certifying
QC MUST authenticate its corresponding header. The child's exact
`justify_qc` digest MUST equal the finalized block's certifying-QC digest, and
the grandchild's exact justify digest MUST equal the child's certifying-QC
digest. If either proposal skips a view, its complete TC MUST be present,
verify at `proposal.view - 1`, and select that same exact QC digest. A proof
with only a peer-asserted justification digest and no proposer signature is
invalid. Ordinary finality proofs do not cross an epoch.

Evidence encodes its normalized pair of conflicting signed values and uses
`trnm.poco-bft.double-sign-evidence.v0`.

Consumption Certificate fields and IDs are specified in `../poco-consumption-certificate-v0.md`.

## 13. Timestamp rule

For every non-genesis block:

```text
parent.timestamp_ms < block.timestamp_ms
block.timestamp_ms <= parent.timestamp_ms + max_block_time_step_ms
```

Both comparisons use checked unsigned arithmetic. The genesis timestamp is committed by genesis. Epoch seal blocks follow the same rule.

A node MAY reject or defer a proposal that is too far ahead of its local clock as an admission/DoS policy, but such a local-clock decision MUST NOT be used to produce a conflicting deterministic execution result. Correct validators need an interoperable operational clock-skew profile for liveness; it is not part of consensus validity in v0.

## 14. Size and decoding limits

At minimum, conforming decoders enforce the reference limits for chain ID, validator ID, block, and consensus-message bytes from `parameters.toml`. A protocol object exceeding a committed active limit is invalid.

Decoders MUST:

- reject lengths that overflow host indexing or allocation arithmetic;
- reject collections before allocating beyond their bounds;
- reject duplicate signer IDs, keys, QCs, evidence IDs, or certificate IDs where uniqueness is required;
- verify canonical order instead of sorting attacker-provided data and accepting it;
- reject trailing bytes and unknown enum discriminants;
- perform signature and expensive proof verification only after cheap structural and domain checks where safe.

## 15. Golden-vector requirement

P1 MUST add cross-language golden vectors for every domain, primitive boundary, object digest, valid signature, malformed encoding, threshold edge, and wrong-context replay. At least one independent implementation MUST reproduce the bytes and digests before the wire format is considered implemented.
