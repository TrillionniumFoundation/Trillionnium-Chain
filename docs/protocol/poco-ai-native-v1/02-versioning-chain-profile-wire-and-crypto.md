# 02 — Versioning, chain profile, wire, and cryptography

Status: **DRAFT / design-only / not implemented / not activated**

## 1. Version axes

V1 keeps consensus identity separate from component and storage evolution:

- `protocol_version: u32 = 1` changes consensus-valid signed bytes, state
  transitions, availability predicates, finality proofs, or upgrade semantics.
- `schema_version: u16` is local to one logical object kind. Unknown versions
  are rejected unless protocol version 1 explicitly enumerates them.
- `stack_profile_hash: Hash32` commits the exact enabled plane/profile bundle,
  verification registry, DA mode, runtime profile, meter registry, fee schedule,
  consensus parameters, and referenced schema manifest.
- `runtime_profile_hash: Hash32` selects one deterministic application runtime,
  object schema, transaction-failure semantics, scheduler rules, and state-root
  contract.
- `VerificationProfileRefV1 = (profile_id: Bytes, profile_version: u32,
  profile_hash: Hash32)` selects exact result-verification semantics for one
  task. All three fields are required together; an ID/version without the
  registry-resolved content hash is not a profile reference.
- transport, RPC, adapter, database, WAL, signer-journal, and snapshot-container
  versions are independent. They MUST NOT silently change a consensus object's
  meaning or accepted `CEV1` bytes.

A profile may tune or select only behaviors already enumerated by protocol v1.
It cannot add a signed field, message kind, quorum rule, lock rule, finality rule,
availability predicate, state-transition kind, or proof meaning. Such a change
requires a later `protocol_version`.

## 2. Common protocol context

`ProtocolContextV1` is the common prefix that may be written as one nested
`context` field in a logical schema:

```text
schema_version          u16  // 1
genesis_hash            Hash32
chain_id                ConsensusString
protocol_version        u32  // 1
stack_profile_hash      Hash32
```

When another document uses `context: ProtocolContextV1`, it binds exactly these
five fields in this order. A schema that lists the same five fields inline has
the same semantic context but not the same enclosing record encoding; vectors
must follow the exact schema as written. `ProtocolContextV1.schema_version` is
the version of the context record itself. An outer object that nests `context:
ProtocolContextV1` MAY, and ordinarily does, begin with its own independent
`object_schema_version: u16` (written as `schema_version` in that object's exact
schema) before the nested context. Those are two distinct encoded fields. Only
a schema that inlines the five context fields MUST NOT repeat another copy of
the inline context's `schema_version`. “Containing at least”, a different field
order, `Bytes` in place of `ConsensusString`, or aliases such as `profile_root`
are not equivalent encodings.

For an immutable application object, `stack_profile_hash` is the profile active
at object creation and remains its creation profile for the object's lifetime.
The field is still named exactly `stack_profile_hash`; aliases such as
`creation_stack_profile_hash` change the schema and are forbidden. A mutable
state transition separately checks the current epoch profile and the retained
creation profile under the upgrade rules below.

`VerificationProfileRefV1` has this exact CEV1 field order:

```text
profile_id                Bytes
profile_version           u32
profile_hash              Hash32
```

Where a body lists those three fields consecutively instead of nesting a
`VerificationProfileRefV1`, the bytes are the three inline fields, not a nested
record. The active verification registry MUST map `(profile_id,
profile_version)` to exactly `profile_hash`; partial, unknown, inactive, or
mismatched references fail closed.

### 2.1 Validator-set and consensus-parameter authority

`ValidatorMemberV1` is the exact context-free record:

```text
validator_id                    Bytes
consensus_key_scheme            u16       // 0 = strict Ed25519
consensus_public_key            Bytes
voting_weight                   u128      // positive
network_identity_commitment     Hash32
safety_signer_policy_hash       Hash32
poco_economic_record_hash       Hash32
```

`ValidatorSetDefinitionV1` is exact:

```text
schema_version                  u16       // 1
members                         List<ValidatorMemberV1>
total_weight                    u128
quorum_threshold                u128
```

Members are nonempty, strictly increasing by raw `validator_id`, and
duplicate-free by validator ID and consensus public key. Each weight is
positive; `total_weight` is the checked sum; and `quorum_threshold` MUST equal
`floor(2 * total_weight / 3) + 1` using checked arithmetic. The context-free
definition hash is `DigestV1("trnm.poco-ai.validator-set-definition.v1",
ValidatorSetDefinitionV1)`.

After chain context exists, `ValidatorSetDescriptorV1` is exactly
`(schema_version: u16 = 1, context: ProtocolContextV1, epoch: u64,
definition: ValidatorSetDefinitionV1)`, and:

```text
validator_set_hash = DigestV1(
  "trnm.poco-ai.validator-set.v1",
  ValidatorSetDescriptorV1
)
```

The epoch descriptor and every consensus signature use this context-bound
`validator_set_hash`. Genesis materialization requires the embedded definition
to equal the bootstrap definition byte-for-byte. A member ID, key, weight,
ordering, total, threshold, context, or epoch mismatch fails closed.

`ConsensusParametersV1` is the exact context-free record whose concrete values
must be supplied by the frozen stack profile:

```text
schema_version                    u16       // 1
quorum_numerator                  u16       // 2
quorum_denominator                u16       // 3
finality_chain_length             u8        // 3
execute_coordination_before_vote  bool      // true
max_validators                    u32
max_consensus_string_bytes        u32
max_cev1_nesting                  u16
max_cev1_value_bytes              u64
max_signature_bytes               u32
max_certificate_signers           u32
max_epoch                         u64
max_view                          u64
max_height                        u64
max_retained_views                u32
epoch_length_blocks               u64
checkpoint_offset_blocks          u64
seal_1_offset_blocks              u64
seal_2_offset_blocks              u64
max_block_ordered_bytes           u64
max_batch_refs_per_block          u32
max_protocol_objects_per_block    u32
max_transactions_per_batch        u32
max_transaction_bytes             u64
max_block_execution_units         u128
base_view_timeout_ms              u64
maximum_view_timeout_ms           u64
timeout_multiplier_numerator      u32
timeout_multiplier_denominator    u32
max_evidence_items_per_block      u32
max_evidence_bytes_per_block      u64
```

All maxima, epoch schedule values, and timeout multiplier components are
positive, including `checkpoint_offset_blocks`;
`checkpoint_offset_blocks < seal_1_offset_blocks < seal_2_offset_blocks <
epoch_length_blocks`, and checked arithmetic MUST satisfy
`seal_1_offset_blocks = checkpoint_offset_blocks + 1`,
`seal_2_offset_blocks = seal_1_offset_blocks + 1`, and
`epoch_length_blocks = seal_2_offset_blocks + 1`; base timeout is no
greater than maximum timeout; numerator is at least denominator; the quorum and
finality constants equal the values shown; and every multiplication/addition is
checked. Its hash is
`DigestV1("trnm.poco-ai.consensus-parameters.v1",
ConsensusParametersV1)`. This record controls Order consensus. Additional
application, DA, proof, and state-sync bounds remain separately committed by
their component profiles; before normative freeze document 10 requires a
complete cross-profile bound matrix and concrete values for every field.

## 3. Chain descriptor

`ChainDescriptorV1` is the chain identity trust root:

```text
schema_version                    u16  // 1
chain_id                          ConsensusString
network_magic                     Bytes
protocol_version                  u32  // 1
genesis_time_ms                   u64
schedule_origin_epoch             u64
schedule_origin_height            u64
origin                             ChainOriginV1
genesis_bootstrap_manifest_hash   Hash32
genesis_validator_set_definition_hash Hash32
genesis_consensus_parameters_hash Hash32
genesis_stack_profile_hash        Hash32
genesis_runtime_profile_hash      Hash32
genesis_governance_policy_hash    Hash32
genesis_da_committee_definition_set_hash Hash32
genesis_verification_registry_hash Hash32
genesis_meter_registry_hash       Hash32
genesis_system_agent_seed_set_hash Hash32
genesis_asset_allocation_definition_hash Hash32
genesis_application_object_definition_hash Hash32
genesis_state_schema_hash          Hash32
genesis_builder_hash               Hash32
genesis_stack_component_definition_set_hash Hash32
```

`ChainOriginV1` is the closed union `0 Fresh | 1 V0Migration {
source_v0_genesis_hash:Hash32, source_v0_chain_id:ConsensusString }`. Fresh
genesis MUST use `Fresh`. A migrated chain MUST use the exact source v0
genesis/chain identity already known when governance creates its upgrade plan;
these values never depend on the target descriptor or future terminal state and
therefore introduce no digest cycle. They domain-separate every later v1
object/signature through `genesis_hash` so two v0 source chains cannot converge
on a replay-compatible target identity.

The value committed by `genesis_bootstrap_manifest_hash` is the exact
context-free `GenesisBootstrapManifestV1`:

```text
schema_version                         u16  // 1
protocol_version                       u32  // 1
validator_set_definition_hash          Hash32
consensus_parameters_hash              Hash32
stack_profile_hash                     Hash32
runtime_profile_hash                   Hash32
governance_policy_definition_hash      Hash32
da_committee_definition_set_hash       Hash32
verification_registry_hash             Hash32
meter_registry_hash                    Hash32
system_agent_seed_set_hash              Hash32
asset_allocation_definition_hash        Hash32
application_object_definition_hash      Hash32
state_schema_hash                       Hash32
genesis_builder_hash                    Hash32
stack_component_definition_set_hash     Hash32
```

```text
genesis_bootstrap_manifest_hash = DigestV1(
  "trnm.poco-ai.genesis-bootstrap-manifest.v1",
  GenesisBootstrapManifestV1
)
```

This manifest contains no `genesis_hash`, `chain_id`, context-bound object ID,
validator-set ID, or DA-committee ID. The descriptor fields map exactly as
follows: `genesis_validator_set_definition_hash ->
validator_set_definition_hash`, `genesis_consensus_parameters_hash ->
consensus_parameters_hash`, `genesis_stack_profile_hash -> stack_profile_hash`,
`genesis_runtime_profile_hash -> runtime_profile_hash`,
`genesis_governance_policy_hash -> governance_policy_definition_hash`,
`genesis_da_committee_definition_set_hash ->
da_committee_definition_set_hash`,
`genesis_verification_registry_hash -> verification_registry_hash`, and
`genesis_meter_registry_hash -> meter_registry_hash`,
`genesis_system_agent_seed_set_hash -> system_agent_seed_set_hash`,
`genesis_asset_allocation_definition_hash ->
asset_allocation_definition_hash`,
`genesis_application_object_definition_hash ->
application_object_definition_hash`, `genesis_state_schema_hash ->
state_schema_hash`, and descriptor `genesis_builder_hash` -> manifest
`genesis_builder_hash`. Every pair MUST be equal;
disagreement makes the descriptor invalid. `genesis_builder_hash` identifies the frozen,
deterministic, integer-only materialization transition and its independent
vectors. It is not a mutable executable path or URL.
Descriptor `genesis_stack_component_definition_set_hash` MUST equal manifest
`stack_component_definition_set_hash`.

The complete decoded `StackProfileV1` is a required bootstrap definition. At
genesis its `activation_epoch` MUST be `0`, its `protocol_version` MUST be `1`,
and its hash MUST equal both profile-hash fields above. Its
`consensus_parameters_hash`, `runtime_profile_hash`,
`verification_registry_hash`, `meter_registry_hash`, and `schema_manifest_hash`
MUST equal the corresponding bootstrap/descriptor facts exactly. Its
`fee_schedule_hash`, `snapshot_policy_hash`, schema manifest, and
Agent/Market/Compute/DA/Coordination component-profile hashes must all resolve
through the exact `GenesisStackComponentDefinitionSetV1` committed by the new
manifest/descriptor field. No component may be absent, duplicated, or supplied
only by an implementation default. Thus descriptor, manifest, and stack
profile are redundant consistency commitments to one fact set, never
independently selectable authorities.

`BootstrapDefinitionKindV1` is a closed `u16` enum. Each value fixes both the
decoded definition type and its hash domain:

| Kind | Definition | Hash domain |
|---:|---|---|
| 0 | `ValidatorSetDefinitionV1` | `trnm.poco-ai.validator-set-definition.v1` |
| 1 | consensus parameters | `trnm.poco-ai.consensus-parameters.v1` |
| 2 | `StackProfileV1` | `trnm.poco-ai.stack-profile.v1` |
| 3 | runtime profile | `trnm.poco-ai.runtime-profile.v1` |
| 4 | governance policy | `trnm.poco-ai.governance-policy.v1` |
| 5 | `DaCommitteeDefinitionSetV1` | `trnm.poco-ai.da-committee-definition-set.v1` |
| 6 | verification registry | `trnm.poco-ai.verification-registry.v1` |
| 7 | meter registry | `trnm.poco-ai.meter-registry.v1` |
| 8 | system-agent seed set | `trnm.poco-ai.genesis-system-agent-seeds.v1` |
| 9 | asset-allocation definition | `trnm.poco-ai.genesis-asset-allocations.v1` |
| 10 | application-object definition | `trnm.poco-ai.genesis-application-objects.v1` |
| 11 | state schema | `trnm.poco-ai.state-schema.v1` |
| 12 | genesis builder descriptor | `trnm.poco-ai.genesis-builder.v1` |
| 13 | `GenesisStackComponentDefinitionSetV1` | `trnm.poco-ai.genesis-stack-component-definition-set.v1` |

The remaining bootstrap bodies are exact and context-free:

- `RuntimeProfileV1 = (schema_version:u16=1,protocol_version:u32=1,
  deterministic_executor_hash:Hash32,crypto_suite_hash:Hash32,
  max_decode_depth:u32,max_object_bytes:u64,max_block_execution_units:u128)`;
- `GovernancePolicyV1 = (schema_version:u16=1,authority_set_hash:Hash32,
  threshold_weight:u128,allowed_actions:List<u16>,timelock_blocks:u64)`;
- `VerificationRegistryV1 = (schema_version:u16=1,
  entries:List<VerificationRegistryEntryV1>)`, with the entry grammar in
  document 09;
- `MeterRegistryV1` is the exact document-08 registry;
- `SystemAgentSeedEntryV1 = (agent_class:u8,creation_nonce:Hash32,
  controller_seed_policy:ControllerSeedPolicyV1,
  recovery_seed_policy:RecoverySeedPolicyV1,metadata_commitment:Hash32)` and
  `SystemAgentSeedSetV1 =
  (schema_version:u16=1,entries:List<SystemAgentSeedEntryV1>)`;
- `GenesisAssetAllocationEntryV1 = (allocation_kind:u8,
  owner_seed_index:Option<u32>,asset_id:Hash32,object_nonce:Hash32,
  available:u128,reserved_or_held:u128,pool_kind:Option<u16>,
  authority_hash:Option<Hash32>,bond_purpose:Option<u16>,
  source_allocation_index:Option<u32>)` and
  `GenesisAssetAllocationDefinitionV1 =
  (schema_version:u16=1,entries:List<GenesisAssetAllocationEntryV1>)`;
- `GenesisApplicationObjectSeedEntryV1 = (seed_kind:u16,
  seed_nonce:Hash32,context_free_body:Bytes,context_free_state_seed:Bytes)` and
  `GenesisApplicationObjectDefinitionV1 =
  (schema_version:u16=1,entries:List<GenesisApplicationObjectSeedEntryV1>)`;
- `StateSchemaDefinitionV1 = (schema_version:u16=1,
  state_tree_version:u16,schema_manifest:SchemaManifestV1)`.

System-agent seeds sort by `(agent_class,creation_nonce)`, allocations by
`(allocation_kind,asset_id,object_nonce)`, registry entries by their explicitly defined keys,
and allowed actions numerically; every list is strictly ordered,
duplicate-free and bounded.
Each body hashes under the domain in its table row; Runtime/Governance positive
bounds/thresholds and registry/member rules are checked before materialization.
Reference v1 defines no application-seed dispatch: the kind-10
`GenesisApplicationObjectDefinitionV1.entries` list MUST be empty and any
nonempty list is invalid. The opaque entry type is reserved but has no legal
reference-v1 instance; it cannot be decoded, interpreted, or hashed into a
state object. Adding even one seed kind requires a new protocol version with a
closed kind-to-schema and materialization table. Allocation kind is closed:
`0 Account` requires owner index and forbids pool/bond fields; `1 ValuePool`
requires pool kind/authority and forbids owner/bond fields; `2 Bond` requires
owner index/purpose/source object and forbids pool fields. Unknown kind,
invalid field presence, zero total value, a forward/self source index, or an
unresolved owner/source is
invalid. After deriving genesis/context,
the builder materializes full identity objects using the exact
`AgentIdentityAuthorizationV1::GenesisMaterialized` branch, plus account bodies
and exact Account/ValuePool/Bond bodies, states, and IDs, only from the
closed system-agent and asset-allocation seed definitions. It merges them only when
typed IDs are disjoint, constructs exact `ApplicationObjectValueV1` leaves,
and recomputes the declared state schema/root. No bootstrap hash is an
unresolved implementation default.

The context-free `source_allocation_index` refers only to an earlier ordered
allocation entry; it never contains a chain-scoped typed ID. After genesis is
derived, the materializer substitutes that earlier entry's typed object ID into
the Bond body. This keeps bootstrap hashing acyclic and yields one source ID.

`GenesisBuilderDescriptorV1` is exactly `(schema_version: u16 = 1,
protocol_version: u32 = 1, state_schema_hash: Hash32,
transition_code_hash: Hash32, conformance_vector_bundle_hash: Hash32)`.

The component kinds have protocol-fixed bodies and domains; the schema manifest
does not define or override them:

- `AgentProfileV1 = (schema_version:u16=1,protocol_version:u32=1,
  max_controller_keys:u32,max_recovery_keys:u32,max_capability_depth:u8,
  max_nonce_lanes_per_key:u16,max_session_grants_per_capability:u32,
  authorization_policy_registry_hash:Hash32)` under
  `trnm.poco-ai.agent-profile.v1`;
- `MarketProfileV1 = (schema_version:u16=1,protocol_version:u32=1,
  max_bids_per_task:u32,max_attempts_per_task:u32,
  max_live_tasks_per_agent:u32,lifecycle_policy_registry_hash:Hash32,
  escrow_policy_registry_hash:Hash32)` under
  `trnm.poco-ai.market-profile.v1`;
- `ComputeProfileV1 = (schema_version:u16=1,protocol_version:u32=1,
  max_artifacts_per_object:u32,max_claims_per_result:u32,
  max_challenges_per_result:u32,verification_registry_hash:Hash32,
  challenge_policy_registry_hash:Hash32)` under
  `trnm.poco-ai.compute-profile.v1`;
- `DaProfileV1 = (schema_version:u16=1,protocol_version:u32=1,
  da_policy_hash:Hash32,da_policy:DaPolicyBodyV1,
  max_worker_count:u16,max_inflight_batches_per_author:u32,
  withholding_policy_hash:Hash32,repair_policy_hash:Hash32)` under
  `trnm.poco-ai.da-profile.v1`; the inline policy recomputes
  `da_policy_hash`, and that same hash/value is the sole EpochDescriptor policy
  authority; and
- `SchemaEntryV1 = (object_kind:u16,immutable_schema_version:u16,
  mutable_schema_version:u16,immutable_schema_hash:Hash32,
  mutable_schema_hash:Hash32,max_immutable_bytes:u64,max_mutable_bytes:u64)`;
  `SchemaManifestV1 = (schema_version:u16=1,protocol_version:u32=1,
  entries:List<SchemaEntryV1>)` under `trnm.poco-ai.schema-manifest.v1`.

All maxima are positive. Schema entries contain every admitted state kind
exactly once, strictly increasing by kind; hashes commit the frozen CEV1 grammar
and bounds rather than transport protobuf. A manifest cannot redefine a kind,
component body, digest domain, or CEV1 rule.

`StackComponentKindV1` is the closed `u16` enum `0 AgentProfile`, `1
MarketProfile`, `2 ComputeProfile`, `3 DaProfile`, `4 CoordinationProfile`, `5
FeeSchedule`, `6 SchemaManifest`, and `7 SnapshotPolicy`. `StackComponentDefinitionEntryV1` is
exactly `(component_kind:StackComponentKindV1, definition_hash:Hash32,
definition_bytes:Bytes)`. `GenesisStackComponentDefinitionSetV1` is exactly
`(schema_version:u16=1, entries:List<StackComponentDefinitionEntryV1>)`; it has
exactly one entry for every kind, strictly ordered, with no duplicate. Each
kind selects the protocol-fixed body/domain above or, for kinds 4, 5, and 7,
the exact `CoordinationProfileV1`, `FeeScheduleV1`, and `SnapshotPolicyV1`
defined in documents 08/09. Kind 6 is exact `SchemaManifestV1`; it does not
self-assign its own schema/domain. Kind 7 decodes exact `SnapshotPolicyV1` under
`trnm.poco-ai.snapshot-policy.v1`; the decoded definition bytes must recompute `definition_hash`, and the eight
hashes must equal the corresponding `StackProfileV1` fields. Its own hash uses
the kind-13 domain above. This nested closed set avoids an open or colliding
top-level bootstrap-kind namespace.

Reference v1 has one state-tree authority: decoded
`StateSchemaDefinitionV1.state_tree_version`,
`CoordinationProfileV1.state_tree_version`, every snapshot manifest and every
state proof MUST all equal `0`; mismatch or any other version fails closed.
Likewise `RuntimeProfileV1.max_block_execution_units` MUST equal
`ConsensusParametersV1.max_block_execution_units`. Runtime decode/object bounds
may only be equal to or tighter than the corresponding consensus CEV1 maxima;
they never override a consensus-visible limit.

`DaCommitteeDefinitionSetV1` is the exact context-free record
`(schema_version: u16 = 1, definitions:
List<DaCommitteeDefinitionV1>)`. Definitions are strictly increasing by the
closed `DaNamespaceV1` discriminant, duplicate-free, and include exactly one
definition for each namespace enabled by the referencing stack/DA profile. The set
hash uses the kind-5 domain above in every epoch; there is no genesis-only
alternate type/domain. At genesis it must additionally equal
`genesis_da_committee_definition_set_hash`. Genesis materialization derives every
context-bound committee descriptor from that list; the independently computed
`da_committee_set_root` commits their typed IDs in the same namespace order.

`chain_id` and `network_magic` are nonempty and bounded by the reference
parameters. The descriptor is canonically encoded once; duplicate fields,
unknown fields, alternate text normalization, or an unsupported protocol
version are invalid. Every hash referenced by the descriptor is computed from a
context-free bootstrap definition that MUST NOT contain `genesis_hash` or an ID
derived from `genesis_hash`. This breaks the otherwise circular dependency
between the descriptor and initial state, validator, DA, and registry objects.
After `genesis_hash` is known, the bootstrap manifest deterministically derives
the context-bound height-zero application objects, validator-set descriptor,
DA-committee descriptor, and trusted genesis header/root. Those derived values
must reproduce the bootstrap definitions; they are not inputs to
`genesis_hash`.

The materializer consumes a canonically ordered
`List<BootstrapDefinitionEntryV1>` where each entry is:

```text
definition_kind              u16
definition_hash              Hash32
definition_bytes             Bytes
```

Entries are strictly increasing by `definition_kind`, duplicate-free, and
contain exactly one entry for every definition hash in the manifest, including
the kind-13 component-definition set. Component/fee/schema preimages occur only
inside that exact nested set; unknown top-level or nested kinds fail closed. Each
`definition_hash` is recomputed with the domain assigned to that definition
kind before any state is created. The decoder first parses `definition_bytes`
as the exact type fixed by the kind, rejects trailing/noncanonical bytes, then
computes `DigestV1(kind_domain, decoded_definition)`. Hashing the raw transport
payload or its enclosing `Bytes` wrapper is not equivalent. The exact
materialization context is:

```text
context                      ProtocolContextV1
runtime_profile_hash         Hash32
bootstrap_manifest_hash      Hash32
```

The resulting `GenesisDerivedStateV1` has this exact field order:

```text
context                      ProtocolContextV1
runtime_profile_hash         Hash32
validator_set_hash           Hash32
consensus_parameters_hash    Hash32
governance_policy_hash       Hash32
da_committee_set_root        Hash32
verification_registry_hash   Hash32
meter_registry_hash          Hash32
system_agents_root           Hash32
asset_allocations_root       Hash32
application_objects_root     Hash32
state_schema_hash            Hash32
application_state_root       Hash32
```

```text
genesis_derived_state_hash = DigestV1(
  "trnm.poco-ai.genesis-derived-state.v1",
  GenesisDerivedStateV1
)
```

Every list root in `GenesisDerivedStateV1` is
`DigestV1(root_domain, List<ContextBoundObjectCommitmentV1>)`, where the exact
commitment record is `(object_kind: u16, object_id: Hash32,
object_content_hash: Hash32)`. Entries are strictly increasing by
`(object_kind, raw object_id)` and duplicate-free. Root domains are:

| Derived field | Root domain |
|---|---|
| `da_committee_set_root` | `trnm.poco-ai.genesis-da-committee-set-root.v1` |
| `system_agents_root` | `trnm.poco-ai.genesis-system-agents-root.v1` |
| `asset_allocations_root` | `trnm.poco-ai.genesis-asset-allocations-root.v1` |
| `application_objects_root` | `trnm.poco-ai.genesis-application-objects-root.v1` |

The remaining singular fields use the exact content/object/root domains of
their decoded definition types. A materializer MUST output those typed values,
not one undifferentiated Merkle root.

For `system_agents_root`, `asset_allocations_root`, and
`application_objects_root`, `object_content_hash` is exactly `DigestV1(
"trnm.poco-ai.genesis-context-bound-object-content.v1",
(object_kind:u16,materialized_value:ApplicationObjectValueV1))`; the complete
immutable+mutable envelope recomputes the same ID. `da_committee_set_root`
instead hashes the exact context-bound `DaCommitteeDescriptorV1` bytes under
`trnm.poco-ai.genesis-da-committee-content.v1`. A body-only, state-only, or
wrapper-only alternate is invalid. Singular definition hashes use precisely
their registered body domain including the schema-version wrapper.

Root membership is closed. Per ordered system-agent seed,
`system_agents_root` contains exactly its tag-0 AgentIdentity, every tag-1
controller/recovery AgentKey derived from the seed policies, and its tag-44
controller lane 0 keyed by the zero controller-threshold sentinel.
`asset_allocations_root` contains exactly one tag45/46/47
materialized object per allocation entry. Since application seed entries are
forbidden, `application_objects_root` is the canonical empty-list root. The
authenticated `application_state_root` is separately built from the union of
all materialized state objects. Omission, duplication, or placing an object in
another derived root is invalid.

Every materialized chain object is derived from the verified context-free entry
plus the exact `ProtocolContextV1`; typed IDs are computed only after that
binding. The validator-set, DA-committee, system-agent, allocation, application,
and state roots are computed over canonical ordered context-bound objects and
MUST reproduce independent genesis vectors. The v1 genesis header commits
`genesis_derived_state_hash` and `application_state_root`; neither derived value
feeds back into `ChainDescriptorV1` or `genesis_hash`.

```text
genesis_hash = DigestV1(
  "trnm.poco-ai.chain-descriptor.v1",
  ChainDescriptorV1
)
```

Every v1 signature or object ID binds `genesis_hash` and `chain_id`. A v0 chain
cannot reuse its identity merely by copying state. Any legacy import is a
one-way audited manifest into a newly constructed v1 descriptor; old WAL, lock,
QC/finality, signer state, or watermark is never imported.

## 4. Stack profile

`StackProfileV1` has this exact logical field order:

```text
schema_version                       u16  // 1
protocol_version                     u32  // 1
profile_name                         Bytes
profile_revision                     u32
agent_profile_hash                   Hash32
market_profile_hash                  Hash32
compute_profile_hash                 Hash32
da_profile_hash                      Hash32
coordination_profile_hash            Hash32
consensus_parameters_hash            Hash32
runtime_profile_hash                 Hash32
snapshot_policy_hash                Hash32
verification_registry_hash           Hash32
meter_registry_hash                  Hash32
fee_schedule_hash                    Hash32
schema_manifest_hash                 Hash32
activation_epoch                     u64
```

```text
stack_profile_hash = DigestV1(
  "trnm.poco-ai.stack-profile.v1",
  StackProfileV1
)
```

All referenced profiles are complete immutable content-addressed values. The
stack profile and every component profile it references are context-free:
their hash preimages MUST NOT include `genesis_hash`, `chain_id`,
`stack_profile_hash`, or an object ID derived from those values. The activated
chain/epoch supplies that context when it commits `stack_profile_hash`. A
human name, local file path, URL, mutable registry pointer, environment variable,
or implementation feature flag is not profile authority. The activated stack
profile is immutable within an epoch. A successor activates only through the
epoch handoff/upgrade rules in documents 07 and 09.

## 5. CEV1 canonical encoding

`CEV1` is the only signing and hashing encoding for protocol-v1 logical values.
Transport protobuf, JSON, CBOR, compression, chunking, or framing bytes never
become a signing preimage by inference.

Primitive rules:

- unsigned integers are fixed-width little-endian (`u8`, `u16`, `u32`, `u64`,
  `u128`);
- `bool` is one byte, exactly `0` or `1`;
- `Hash32` is exactly 32 raw bytes;
- `Bytes` and UTF-8 `ConsensusString` use a checked `u32` byte-length followed
  by exact bytes;
- `Option<T>` is `0` for absent or `1 || CEV1(T)` for present;
- `List<T>` is a checked `u32` element count followed by values in declared
  order;
- records encode fields in their normative order and contain no field tags;
- enums encode the normative `u8` or `u16` discriminant followed only by the
  selected variant body;
- maps are represented as lists of key/value records strictly increasing by the
  normative raw key bytes, with no duplicates; and
- no value admits trailing bytes, unknown discriminants, alternate integer
  widths, Unicode normalization, ignored fields, or default-field omission.

Before allocation or expensive verification, a decoder MUST authenticate or
enforce the active maximum encoded length, collection count, nesting depth,
decompressed length, and integer conversion. Canonical order is verified on the
received input; a decoder MUST NOT sort attacker input and accept the result.

### 5.1 Object, body, ID, state, and signature names

Protocol v1 uses one naming layer throughout the numbered documents:

- `XBodyV1` is the immutable, exact CEV1 preimage from which `XIdV1` is derived;
- `XIdV1` is the typed domain-separated `Hash32` for that body;
- `XV1` is the admitted protocol object consisting of the body, its recomputed
  typed ID, and the required authorization/signature material;
- `XStateV1` is mutable authenticated application state keyed by the typed ID;
  it is not silently included in the immutable ID preimage. The state-tree
  value is the closed `ApplicationObjectValueV1` envelope `(schema_version:
  u16=1,object_id:TypedObjectIdV1,immutable_object_bytes:Bytes,
  mutable_state_bytes:Bytes)`: both byte fields strictly decode as the exact
  kind-assigned `XV1`/`XStateV1`, the immutable body recomputes the typed ID,
  and every repeated context/ID agrees; and
- `XSignatureV1` or an explicitly named signature set authenticates the typed ID
  through the signature-root domain assigned below. Signature bytes are not in
  an object ID unless the object is explicitly a certificate whose signer set is
  part of its body.

A document MAY use a shorter name only after defining it as an exact alias at
one of these layers. It MUST NOT use `X`, `XBody`, and `XState` for the same
bytes. Typed wrappers have the same 32-byte representation as `Hash32`, but a
decoder or API MUST retain the type and reject cross-kind substitution.

The closed body-only exceptions to the admitted-object wrapper shape are tag
20 and tags 44–49: their immutable bytes are respectively the exact
`SettlementIntentV1`, `NonceLaneKeyBodyV1`,
`AccountBodyV1`, `ValuePoolBodyV1`, `BondBodyV1`,
`ConsumptionReceiptCoordinateBodyV1`, and `DaObligationBodyV1`; mutable bytes
are their exact state types in the dispatch table. These types carry no
independent authorization wrapper because creation authority is authenticated
by the enclosing atomic transition/genesis materializer. No live application's immutable bytes may be pruned
from the state value while its mutable state or any dependent liability is
retained. Consequently a snapshot/catch-up verifier never needs to invert an ID
hash or trust historical blocks outside the retained window to recover keys,
scopes, deadlines, policies, or value terms.

## 6. Hash construction and typed IDs

```text
DigestV1(domain, value) = SHA-256(
  u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value)
)
```

Candidate domains are nonempty ASCII strings and become frozen only when this
draft passes document 10's normative-freeze gates. Domain length
and every CEV1 length are checked before concatenation. The reference profile
uses SHA-256; algorithm agility requires a later protocol version. `Digest` in
v1 formulas is an exact shorthand for `DigestV1`, never for the v0 digest
construction or a transport hash.

### 6.1 Typed ordered roots

Every consensus-visible list root uses one closed `RootKindV1`; a raw hash from
one kind is invalid for every other. `MerkleLeafBodyV1` is exactly
`(root_kind:u16, index:u32, item_kind:u16, item_id:Hash32,
item_commitment:Hash32)` and its hash is
`DigestV1("trnm.poco-ai.merkle-leaf.v1", body)`. `MerkleNodeBodyV1` is exactly
`(root_kind:u16, level:u32, left:Hash32, right:Hash32)` and uses
`trnm.poco-ai.merkle-node.v1`. Leaves retain canonical input order. At each
level an unpaired final hash is duplicated as both `left` and `right`; level
starts at zero for parents of leaves and increments with checked arithmetic.

The final root is
`DigestV1("trnm.poco-ai.merkle-list-root.v1",
(root_kind:u16, item_count:u32, tree_root:Option<Hash32>))`. Empty lists use
`item_count=0, tree_root=None`; nonempty lists require `Some` and the exact
tree above. Thus leaf, node, empty, count, order, item kind, typed ID, content,
and destination root kind are all bound without transport normalization.

The draft `RootKindV1` registry is:

| Value | Root field/purpose |
|---:|---|
| 0 | block `batch_refs_root` |
| 1 | block `protocol_objects_root` |
| 2 | block `transaction_execution_receipts_root` |
| 3 | block/evaluation `evidence_root` |
| 4 | block `consumption_rollups_root` |
| 5 | block `settlement_root` |
| 6 | block `resource_usage_root` |
| 7 | TransactionBatch `content_root` |
| 8 | ArtifactEvidence `content_root` |
| 9 | DA `chunk_root` |
| 10 | retrieval `returned_chunks_root` |
| 11 | transaction `events_root` |
| 12 | transaction `read_set_root` |
| 13 | transaction `write_set_root` |
| 14 | transaction `state_delta_root` |
| 15 | transaction `created_object_root` |
| 16 | rollup `receipts_root` |
| 17 | result/task `task_result_root` |
| 18 | settlement `input_value_root` |
| 19 | settlement `planned_deltas_root` |
| 20 | settlement `conservation_root` |
A later candidate artifact may add a root kind only before normative freeze;
after freeze, adding or reinterpreting a kind requires a new protocol version.
Authenticated application/JMT state roots, schema-manifest roots, and external
artifact content digests use their separately specified algorithms and domains;
they are not `RootKindV1` list roots.

The only state-eligible tags and dispatch are closed:

| Tag | Immutable bytes | Mutable bytes | outer version field |
|---:|---|---|---|
| 0 | `AgentIdentityV1` | `AgentIdentityStateV1` | `identity_revision` |
| 1 | `AgentKeyV1` | `AgentKeyStateV1` | `generation` |
| 2 | `CapabilityGrantV1` | `CapabilityStateV1` | `state_version` |
| 3 | `SessionKeyGrantV1` | `SessionKeyGrantStateV1` | `state_version` |
| 4 | `TaskOfferV1` | `TaskStateV1` | `revision` |
| 5 | `BidV1` | `BidStateV1` | `state_version` |
| 6 | `TaskLeaseV1` | `TaskLeaseStateV1` | `revision` |
| 7 | `EscrowV1` | `EscrowStateV1` | `version` |
| 8 | `ComputeCheckpointV1` | `ComputeCheckpointStateV1` | `state_version` |
| 9 | `ResultV1` | `ResultStateV1` | `revision` |
| 14 | `ChallengeV1` | `ChallengeStateV1` | `revision` |
| 18 | `ConsumptionRollupV1` | `ConsumptionRollupStateV1` | `version` |
| 19 | `ConsumptionReceiptV1` | `ConsumptionReceiptStateV1` | `version` |
| 20 | `SettlementIntentV1` | `SettlementStateV1` | `state_version` |
| 44 | `NonceLaneKeyBodyV1` | `NonceLaneStateV1` | `state_version` |
| 45 | `AccountBodyV1` | `AccountStateV1` | `version` |
| 46 | `ValuePoolBodyV1` | `ValuePoolStateV1` | `version` |
| 47 | `BondBodyV1` | `BondStateV1` | `version` |
| 48 | `ConsumptionReceiptCoordinateBodyV1` | `ConsumptionReceiptCoordinateStateV1` | `version` |
| 49 | `DaObligationBodyV1` | `DaObligationStateV1` | `version` |
| 50 | `GlobalExecutionBindingV1` | `GlobalExecutionBindingStateV1` | `version` (fixed zero) |

For these tags, `StateSyncRecordV1.object_version` equals the named field;
schema/status/terminal interpretation is exactly the owner document. Every
other ObjectKind is forbidden as an application-state key/value in reference
v1 and may appear only in its specified consensus, DA, proof, or historical
object carrier. Unknown dispatch is invalid, never a generic byte blob.

Every typed ID is one `Hash32` wrapper around a domain-separated body digest:

| Type | Domain |
|---|---|
| `AgentIdV1` | `trnm.poco-ai.agent.v1` |
| `AgentKeyIdV1` | `trnm.poco-ai.agent-key.v1` |
| `CapabilityIdV1` | `trnm.poco-ai.capability.v1` |
| `SessionKeyGrantIdV1` | `trnm.poco-ai.session-key-grant.v1` |
| `TaskIdV1` | `trnm.poco-ai.task.v1` |
| `BidIdV1` | `trnm.poco-ai.bid.v1` |
| `LeaseIdV1` | `trnm.poco-ai.lease.v1` |
| `EscrowIdV1` | `trnm.poco-ai.escrow.v1` |
| `CheckpointIdV1` | `trnm.poco-ai.compute-checkpoint.v1` |
| `ResultIdV1` | `trnm.poco-ai.result.v1` |
| `ExecutionReceiptIdV1` | `trnm.poco-ai.execution-receipt.v1` |
| `TransactionExecutionReceiptIdV1` | `trnm.poco-ai.transaction-execution-receipt.v1` |
| `VerificationClaimIdV1` | `trnm.poco-ai.verification-claim.v1` |
| `VerificationDecisionIdV1` | `trnm.poco-ai.verification-decision.v1` |
| `ChallengeIdV1` | `trnm.poco-ai.challenge.v1` |
| `BatchIdV1` | `trnm.poco-ai.da-batch.v1` |
| `ArtifactIdV1` | `trnm.poco-ai.artifact.v1` |
| `AvailabilityCertificateIdV1` | `trnm.poco-ai.availability-certificate.v1` |
| `ConsumptionRollupIdV1` | `trnm.poco-ai.consumption-rollup.v1` |
| `ConsumptionReceiptIdV1` | `trnm.poco-ai.consumption-receipt.v1` |
| `SettlementIdV1` | `trnm.poco-ai.settlement.v1` |
| `AgentTransactionIdV1` | `trnm.poco-ai.agent-transaction.v1` |
| `BlockIdV1` | `trnm.poco-ai.order-block.v1` |
| `OrderProposalIdV1` | `trnm.poco-ai.order-proposal.v1` |
| `VoteIdV1` | `trnm.poco-ai.order-vote.v1` |
| `TimeoutIdV1` | `trnm.poco-ai.order-timeout.v1` |
| `QuorumCertificateIdV1` | `trnm.poco-ai.order-qc.v1` |
| `TimeoutCertificateIdV1` | `trnm.poco-ai.order-tc.v1` |
| `EpochDescriptorIdV1` | `trnm.poco-ai.epoch-descriptor.v1` |
| `EpochCheckpointIdV1` | `trnm.poco-ai.epoch-checkpoint.v1` |
| `EpochHandoffIdV1` | `trnm.poco-ai.epoch-handoff.v1` |
| `DaCommitteeIdV1` | `trnm.poco-ai.da-committee.v1` |
| `DaAttestationIdV1` | `trnm.poco-ai.da-attestation.v1` |
| `RetrievalReceiptIdV1` | `trnm.poco-ai.retrieval-receipt.v1` |
| `StateSyncManifestIdV1` | `trnm.poco-ai.state-sync-manifest.v1` |
| `UpgradePlanIdV1` | `trnm.poco-ai.upgrade-plan.v1` |
| `MigrationReceiptIdV1` | `trnm.poco-ai.migration-receipt.v1` |
| `V0ToV1ActivationStatementIdV1` | `trnm.poco-ai.v0-to-v1-activation-statement.v1` |
| `ActivationAnchorIdV1` | `trnm.poco-ai.activation-anchor.v1` |
| `OrderFinalityProofIdV1` | `trnm.poco-ai.order-finality-proof.v1` |
| `ApplicationStateProofIdV1` | `trnm.poco-ai.application-state-proof.v1` |
| `ArtifactAvailabilityProofIdV1` | `trnm.poco-ai.artifact-availability-proof.v1` |
| `ResultSettlementFinalityProofIdV1` | `trnm.poco-ai.result-settlement-finality-proof.v1` |
| `GenesisAnchorIdV1` | `trnm.poco-ai.genesis-anchor.v1` |
| `NonceLaneIdV1` | `trnm.poco-ai.nonce-lane.v1` |
| `AccountIdV1` | `trnm.poco-ai.account.v1` |
| `ValuePoolIdV1` | `trnm.poco-ai.value-pool.v1` |
| `BondIdV1` | `trnm.poco-ai.bond.v1` |
| `ConsumptionReceiptCoordinateIdV1` | `trnm.poco-ai.consumption-receipt-coordinate.v1` |
| `DaObligationIdV1` | `trnm.poco-ai.da-obligation.v1` |
| `GlobalExecutionBindingIdV1` | `trnm.poco-ai.global-execution-binding.v1` |

Where a schema must carry an ID of more than one possible type, it uses the
exact tagged record `(object_kind: u16, object_id: Hash32)` named
`TypedObjectIdV1`. Its closed `ObjectKindV1` mapping follows the table order
above: `0 AgentIdV1`, `1 AgentKeyIdV1`, `2 CapabilityIdV1`,
`3 SessionKeyGrantIdV1`, `4 TaskIdV1`, `5 BidIdV1`, `6 LeaseIdV1`,
`7 EscrowIdV1`, `8 CheckpointIdV1`, `9 ResultIdV1`,
`10 ExecutionReceiptIdV1`, `11 TransactionExecutionReceiptIdV1`,
`12 VerificationClaimIdV1`, `13 VerificationDecisionIdV1`,
`14 ChallengeIdV1`, `15 BatchIdV1`, `16 ArtifactIdV1`,
`17 AvailabilityCertificateIdV1`, `18 ConsumptionRollupIdV1`,
`19 ConsumptionReceiptIdV1`, `20 SettlementIdV1`,
`21 AgentTransactionIdV1`, `22 BlockIdV1`, `23 OrderProposalIdV1`,
`24 VoteIdV1`, `25 TimeoutIdV1`, `26 QuorumCertificateIdV1`,
`27 TimeoutCertificateIdV1`, `28 EpochDescriptorIdV1`,
`29 EpochCheckpointIdV1`, `30 EpochHandoffIdV1`, `31 DaCommitteeIdV1`,
`32 DaAttestationIdV1`, `33 RetrievalReceiptIdV1`,
`34 StateSyncManifestIdV1`, `35 UpgradePlanIdV1`,
`36 MigrationReceiptIdV1`, `37 V0ToV1ActivationStatementIdV1`,
`38 ActivationAnchorIdV1`, `39 OrderFinalityProofIdV1`,
`40 ApplicationStateProofIdV1`, `41 ArtifactAvailabilityProofIdV1`, and
`42 ResultSettlementFinalityProofIdV1`, `43 GenesisAnchorIdV1`, `44
NonceLaneIdV1`, `45 AccountIdV1`, `46 ValuePoolIdV1`, `47 BondIdV1`, and `48
ConsumptionReceiptCoordinateIdV1`, `49 DaObligationIdV1`, and `50
GlobalExecutionBindingIdV1`.
Unknown
tags, a tag inconsistent with
the field's allowed type set, or a digest that does not recompute under that
type's domain fails closed. A bare `Hash32` is never an alias. Operation-kind
and state-proof schemas must explicitly constrain the allowed object-kind tag;
they cannot infer it from mutable state or the digest bytes.

Context-free or root content hashes use distinct names and domains rather than
masquerading as typed chain-object IDs:

| Hash value | Domain |
|---|---|
| `genesis_hash` | `trnm.poco-ai.chain-descriptor.v1` |
| `genesis_bootstrap_manifest_hash` | `trnm.poco-ai.genesis-bootstrap-manifest.v1` |
| `genesis_derived_state_hash` | `trnm.poco-ai.genesis-derived-state.v1` |
| `stack_profile_hash` | `trnm.poco-ai.stack-profile.v1` |
| `verification_profile_hash` | `trnm.poco-ai.verification-profile.v1` |
| `initial_controller_seed_hash` | `trnm.poco-ai.controller-seed-policy.v1` |
| `recovery_policy_seed_hash` | `trnm.poco-ai.recovery-seed-policy.v1` |
| `artifact_content_digest` | `trnm.poco-ai.artifact-content.v1` |
| `fee_schedule_hash` | `trnm.poco-ai.fee-schedule.v1` |

Each chain-scoped ID body begins with the exact `ProtocolContextV1`, inline or
nested as its normative schema states, followed by the type-specific fields.
Context-free bootstrap/profile hashes are named `...Hash`, not `...Id`, and are
the only explicit exception. One type's raw `Hash32` MUST NOT be accepted where
another typed ID is required.

The following exact signature-root domains are reserved. Consensus, DA,
verifier, bilateral-receipt, and other non-authorization signatures sign
`DigestV1(signature_domain, typed_object_id)` unless their exact schema defines
a richer statement. Every user/agent authorization entry instead signs
`DigestV1(signature_domain, AuthorizationStatementV1)` using the one
operation-specific domain selected by the closed table below. The statement
itself binds the operation typed ID and all authorization/replay facts. There is
no generic authorization-domain shortcut, and no operation may be valid under
two signature domains. No signer signs transport bytes or reuses an object's ID
domain.

| Signed intent | Signature-root domain |
|---|---|
| Agent identity creation | `trnm.poco-ai.agent-identity-signature.v1` |
| Agent self-origin creation | `trnm.poco-ai.agent-self-origin-signature.v1` |
| Agent key registration | `trnm.poco-ai.agent-key-registration-signature.v1` |
| Capability grant | `trnm.poco-ai.capability-grant-signature.v1` |
| Session-key grant | `trnm.poco-ai.session-key-grant-signature.v1` |
| Task offer | `trnm.poco-ai.task-offer-signature.v1` |
| Bid | `trnm.poco-ai.bid-signature.v1` |
| Lease acceptance, requester | `trnm.poco-ai.lease-requester-acceptance-signature.v1` |
| Lease acceptance, provider | `trnm.poco-ai.lease-provider-acceptance-signature.v1` |
| Compute checkpoint | `trnm.poco-ai.compute-checkpoint-signature.v1` |
| Artifact commitment | `trnm.poco-ai.artifact-commitment-signature.v1` |
| Execution receipt | `trnm.poco-ai.execution-receipt-signature.v1` |
| Verification claim | `trnm.poco-ai.verification-claim-signature.v1` |
| Challenge | `trnm.poco-ai.challenge-signature.v1` |
| Order proposal | `trnm.poco-ai.order-proposal-signature.v1` |
| Vote | `trnm.poco-ai.order-vote-signature.v1` |
| Timeout | `trnm.poco-ai.order-timeout-signature.v1` |
| V1 old-set epoch handoff | `trnm.poco-ai.epoch-handoff-old-signature.v1` |
| V1 new-set epoch handoff | `trnm.poco-ai.epoch-handoff-new-signature.v1` |
| DA attestation | `trnm.poco-ai.da-attestation-signature.v1` |
| DA batch author | `trnm.poco-ai.da-batch-author-signature.v1` |
| DA retrieval receipt | `trnm.poco-ai.retrieval-receipt-signature.v1` |
| Consumption receipt, provider | `trnm.poco-ai.consumption-receipt-provider-signature.v1` |
| Consumption receipt, consumer | `trnm.poco-ai.consumption-receipt-consumer-signature.v1` |
| Consumption rollup, provider | `trnm.poco-ai.consumption-rollup-provider-signature.v1` |
| Consumption rollup, consumer | `trnm.poco-ai.consumption-rollup-consumer-signature.v1` |
| Fee-payer authorization | `trnm.poco-ai.fee-payer-authorization.v1` |
| V0-to-v1 activation, old set | `trnm.poco-ai.v0-to-v1-activation-old-signature.v1` |
| V0-to-v1 activation, new set | `trnm.poco-ai.v0-to-v1-activation-new-signature.v1` |

## 7. Common authorization statement

The closed authorization operation mapping is:

| `operation_kind` | Authorized object/intent | Signature domain |
|---:|---|---|
| 0 | existing-agent identity creation | `trnm.poco-ai.agent-identity-signature.v1` |
| 1 | agent-key registration | `trnm.poco-ai.agent-key-registration-signature.v1` |
| 2 | capability grant | `trnm.poco-ai.capability-grant-signature.v1` |
| 3 | session-key grant | `trnm.poco-ai.session-key-grant-signature.v1` |
| 4 | task offer | `trnm.poco-ai.task-offer-signature.v1` |
| 5 | bid | `trnm.poco-ai.bid-signature.v1` |
| 6 | lease acceptance, requester | `trnm.poco-ai.lease-requester-acceptance-signature.v1` |
| 7 | lease acceptance, provider | `trnm.poco-ai.lease-provider-acceptance-signature.v1` |
| 8 | compute checkpoint | `trnm.poco-ai.compute-checkpoint-signature.v1` |
| 9 | artifact commitment | `trnm.poco-ai.artifact-commitment-signature.v1` |
| 10 | execution receipt | `trnm.poco-ai.execution-receipt-signature.v1` |
| 11 | challenge | `trnm.poco-ai.challenge-signature.v1` |
| 12 | capability revocation | `trnm.poco-ai.capability-revocation-signature.v1` |
| 13 | agent administration | `trnm.poco-ai.agent-administration-signature.v1` |
| 14 | task start | `trnm.poco-ai.task-start-signature.v1` |
| 15 | task pause | `trnm.poco-ai.task-pause-signature.v1` |
| 16 | task resume | `trnm.poco-ai.task-resume-signature.v1` |
| 17 | task cancel | `trnm.poco-ai.task-cancel-signature.v1` |
| 18 | task timeout trigger | `trnm.poco-ai.task-timeout-trigger-signature.v1` |
| 19 | task migration | `trnm.poco-ai.task-migration-signature.v1` |
| 20 | task revision | `trnm.poco-ai.task-revision-signature.v1` |
| 21 | verification-claim submission | `trnm.poco-ai.verification-claim-submit-signature.v1` |
| 22 | evaluation-result submission | `trnm.poco-ai.evaluation-result-submit-signature.v1` |
| 23 | challenge update | `trnm.poco-ai.challenge-update-signature.v1` |
| 24 | consumption-receipt submission | `trnm.poco-ai.consumption-receipt-submit-signature.v1` |
| 25 | consumption-rollup submission | `trnm.poco-ai.consumption-rollup-submit-signature.v1` |
| 26 | settlement intent | `trnm.poco-ai.settlement-intent-signature.v1` |
| 27 | ordered-evidence submission | `trnm.poco-ai.ordered-evidence-submit-signature.v1` |
| 28 | DA obligation operation | `trnm.poco-ai.da-obligation-operation-signature.v1` |
| 29 | economic object operation | `trnm.poco-ai.economic-object-operation-signature.v1` |

Adding or reassigning a value changes accepted authorization bytes and requires
a new protocol version. Verifier, consensus, DA, bilateral-consumption, and
cross-version handoff signatures are not `AuthorizationStatementV1` operations;
their exact statements are defined in their owning sections.

Every user/agent authorization signature signs this exact statement under the
operation-specific signature domain selected above:

```text
AuthorizationStatementV1 =
  schema_version          u16  // 1
  context                 ProtocolContextV1
  operation_kind          u16
  operation_id            TypedObjectIdV1
  authorizing_agent_id    AgentIdV1
  authorizing_policy_revision u64
  authorizing_key_id      AgentKeyIdV1
  capability_id           Option<CapabilityIdV1>
  capability_generation   u64
  session_key_grant_id    Option<SessionKeyGrantIdV1>
  session_generation      u64
  nonce_lane              u16
  nonce                   u64
  valid_after_height      u64
  expires_after_height    u64
```

The signing root is `DigestV1(operation_signature_domain,
AuthorizationStatementV1)`. `operation_kind` has one exact domain mapping;
unknown mappings and a supplied domain that differs from that mapping fail
closed. Controller-threshold authorization uses the exact current
`authorizing_policy_revision`, the zero `AgentKeyIdV1` sentinel,
`capability_id = None`, `capability_generation = 0`,
`session_key_grant_id = None`, `session_generation = 0`, and lane `0`. Session
authorization uses the exact live capability ID and generation, exact active
session-key grant ID and nonzero grant generation, the grant's key ID, and a
nonzero allowed lane. Every other present/absent or zero/nonzero combination is
invalid. The validity interval is inclusive and MUST satisfy
`valid_after_height <= expires_after_height`.

The operation-specific document fixes `operation_kind`, signature domain, and
body. User/agent operations enter Order only through `AgentTransactionV1` as
specified in document 08: `operation_id` is always the exact
`AgentTransactionIdV1`, so every immutable transaction field—including
generation/grant, maximum fee, fee payer, access list, operation bytes,
validity, and memo—is covered. The selected operation body is unsigned by
itself and derives its typed application-object ID during execution; admitted
application objects do not carry a second `AuthorizationSetV1`. The only
standalone signed objects are the explicitly non-transactional consensus, DA,
bilateral-consumption, verifier, bootstrap, or cross-version objects defined by
their owning sections. Kinds `21`, `22`, `24`, `25`, and `27` carry a complete
independently signed inner object, but the outer submitter still signs the
transaction under the submit-domain row above; neither signature substitutes
for the other. Kind `18` authorizes only submission/fee/nonce—the exact chain
height predicate, not the sender, authorizes its timeout effect. A signature
for one operation, domain, profile, policy revision, capability generation,
session grant, key, or nonce lane is invalid for every other.

`AuthorizationSignatureEntryV1` is exactly `(authorizing_key_id:
AgentKeyIdV1, key_role: u8, signature_scheme: u16, signature: Bytes)`. An
`AuthorizationSetV1` is exactly `(statement: AuthorizationStatementV1,
entries: List<AuthorizationSignatureEntryV1>)`; entries are strictly ordered
by raw key ID and duplicate-free. The statement's `authorizing_key_id` is the
zero `AgentKeyIdV1` sentinel for a controller-threshold set and MUST equal the
sole entry's key ID for a one-key session authorization. Controller policy
weights are accumulated only after every entry verifies and must reach the
threshold of the policy at the exact `authorizing_policy_revision`; session authorization has
exactly one entry bound by its active grant and uses
`authorizing_policy_revision = 0`. A raw initial-controller seed authorization
for self-origin agent creation is the sole exception: section 03 defines its
separate seed-key statement and distinct signature domain because no admitted
agent/controller policy exists before the identity body is hashed.

`FeePayerAuthorizationStatementV1` is a distinct non-operation record with
exact fields `(schema_version:u16=1, context:ProtocolContextV1,
transaction_id:AgentTransactionIdV1, fee_payer_id:AgentIdV1,
authorizing_policy_revision:u64, authorizing_key_id:AgentKeyIdV1,
capability_id:Option<CapabilityIdV1>,capability_generation:u64,
session_key_grant_id:Option<SessionKeyGrantIdV1>,session_generation:u64,
nonce_lane:u16,nonce:u64,valid_after_height:u64,expires_after_height:u64)`.
`FeePayerAuthorizationV1` is exactly `(statement:
FeePayerAuthorizationStatementV1,
entries:List<AuthorizationSignatureEntryV1>)`; entries obey the same exact
controller/session threshold, ordering, key, generation, interval, and nonce
rules and sign `DigestV1("trnm.poco-ai.fee-payer-authorization.v1",
statement)`. No `operation_kind` or fake operation body exists. The signed
`AgentTransactionIdV1` already
binds the exact `fee_payer_id` and `max_fee`; no second, potentially divergent
fee limit exists in the sponsor object. It is absent only when the fee payer is
the sender and the sender authorization covers that exact transaction ID. A
distinct payer without this complete independent authorization is invalid.

## 8. Cryptographic profile

The reference v1 draft uses:

- SHA-256 for `Digest`;
- strict Ed25519 for agent, consensus, DA-attester, and verifier-set signatures;
- independently verified public-key ownership when a key enters an authorized
  set; and
- individual, canonically ordered signatures with duplicate signer rejection.

Ed25519 verification MUST reject non-canonical public keys or signatures and
MUST use the exact 32-byte digest selected by the domain construction. Keys are
role-bound in state; possession of the same raw key does not grant another role.
Aggregate/threshold signatures, alternative curves, post-quantum signatures,
and BLS are not enabled in the reference profile. Adding them changes accepted
signature objects and requires at least a separately enumerated protocol
version/profile plus new vectors and formal/conformance evidence.

## 9. Consensus signing context

Every PoCO-Order proposal, Vote, Timeout, QC constituent, handoff vote, and any
future consensus signature begins with this single exact context:

```text
ConsensusContextV1 =
  schema_version              u16  // 1, ConsensusContext record version
  context                     ProtocolContextV1
  runtime_profile_hash        Hash32
  epoch                       u64
  validator_set_hash          Hash32
  consensus_parameters_hash   Hash32
  view                        u64
  message_kind                u8
```

`ConsensusContextV1.schema_version` versions the consensus-context record;
`ProtocolContextV1.schema_version` independently versions its nested protocol
context. A Vote/Timeout/Proposal body MAY also have its own outer object
`schema_version` before its nested `ConsensusContextV1`. These fields are not
duplicates and all are encoded. Only an explicitly inline schema omits a nested
record boundary and MUST NOT repeat the fields it inlines. Reordering, eliding,
or merging these versions produces different, invalid CEV1 bytes.

`ConsensusMessageKindV1` is a closed `u8` enum:

```text
0 OrderProposal
1 Vote
2 Timeout
3 EpochHandoffOldSet
4 EpochHandoffNewSet
```

QC and TC objects are certificates over exact `VoteV1` and `TimeoutV1`
constituents respectively; they do not introduce an unsigned alternate context.
The names `validator_set_root`, `order_parameter_root`, a reordered protocol
context, or an “at least” subset are not aliases for these fields. A later
protocol version is required to add a message kind or signed context field.

The complete signed objects and message-kind discriminants are defined in
document 07. V0 consensus contexts and domains are invalid in v1.

## 10. Profile and object upgrade rules

- Unknown protocol versions fail before state mutation or signing.
- Unknown schemas for consensus-affecting objects fail closed.
- Unknown stack profiles fail before proposal acceptance or transaction
  execution.
- A profile update cannot reinterpret an existing object. Existing tasks,
  capabilities, leases, results, challenges, and rollups retain the exact
  profile/version hashes recorded at creation.
- If a successor profile cannot safely complete an old object's lifecycle, the
  epoch transition is invalid unless the protocol defines an explicit
  deterministic migration or terminalization rule for that exact old version.
- Protocol and stack-profile activation are atomic at an epoch boundary and are
  verified by both full nodes and light clients.

## 11. Vector obligations

Before draft freeze, independent vectors MUST cover every primitive boundary,
domain, ID, signature, wrong-chain/profile replay, schema discriminant, exact
limit and limit-plus-one, duplicate/map-order rejection, malformed length,
checked overflow, and v0-to-v1 substitution. At least one implementation that
does not reuse the Rust node parser or digest code MUST reproduce every accepted
byte string and reject the mutation corpus.
