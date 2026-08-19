# 08 — Coordination, settlement, deterministic execution, and fees

Status: **draft normative target; design-only, not implemented, not frozen, not activated**

This document defines deterministic on-chain execution for the Agent, Market,
Compute/Verify, and Settlement objects ordered by PoCO-Order. AI inference is
off-chain. Validators execute coordination and accounting, not model weights,
private prompts, datasets, or nondeterministic GPU kernels.

## 1. Transaction envelope

The v1 binary transaction is named `AgentTransactionV1`. The name
`CanonicalTxV1` is already used by a historical JSON/single-nonce application
contract and MUST NOT be reused or reinterpreted.

`AgentTransactionV1` binds:

```text
schema_version             u16                 // 1
context                    ProtocolContextV1
sender_agent_id            AgentIdV1
capability_id              Option<CapabilityIdV1>
capability_generation      u64
session_key_grant_id       Option<SessionKeyGrantIdV1>
authorizing_key_id          AgentKeyIdV1
session_generation          u64
nonce_lane_id              u16
nonce                      u64
valid_from_height          u64
valid_until_height         u64
max_fee                    u128
fee_payer_id               AgentIdV1
fee_payer_account_id       AccountIdV1
declared_access_list       List<ObjectAccessV1>
operation_kind             u16
operation_body             Bytes
memo_commitment            Option<Hash32>
```

`OperationPayloadV1` is the only interpretation of `operation_kind` and
`operation_body`. It is this closed tagged union:

| Kind | Exact body | Effect |
|---:|---|---|
| 0 | `AgentIdentityCreationOperationBodyV1` | existing/self-origin identity creation |
| 1 | `AgentKeyBodyV1` | key registration |
| 2 | `CapabilityGrantBodyV1` | capability grant |
| 3 | `SessionKeyGrantBodyV1` | session grant |
| 4 | `TaskCreationOperationBodyV1` | task and funded escrow creation |
| 5 | `BidBodyV1` | bid |
| 6 | `TaskLeaseBodyV1` | requester lease acceptance |
| 7 | `LeaseProviderAcceptanceBodyV1` | provider lease acceptance |
| 8 | `ComputeCheckpointBodyV1` | checkpoint |
| 9 | `ArtifactCommitmentBodyV1` | artifact commitment |
| 10 | `ExecutionReceiptBodyV1` | execution receipt |
| 11 | `ChallengeBodyV1` | challenge opening |
| 12 | `CapabilityRevocationOperationV1` | immediate revocation |
| 13 | `AgentAdministrationOperationV1` | key/session/policy/status change |
| 14 | `TaskStartOperationBodyV1` | start |
| 15 | `TaskPauseOperationBodyV1` | pause |
| 16 | `TaskResumeOperationBodyV1` | resume |
| 17 | `TaskCancelOperationBodyV1` | cancel |
| 18 | `TaskTimeoutOperationBodyV1` | permissionless height timeout |
| 19 | `TaskMigrationOperationBodyV1` | migrate |
| 20 | `TaskRevisionOperationBodyV1` | authorized revision/deadline change |
| 21 | complete `VerificationClaimV1` | external claim admission |
| 22 | complete `EvaluationResultV1` | deterministic signed-claim aggregation |
| 23 | `ChallengeUpdateOperationBodyV1` | challenge evidence/decision/closure |
| 24 | complete `ConsumptionReceiptV1` | bilateral receipt admission |
| 25 | complete `ConsumptionRollupV1` | bilateral rollup admission |
| 26 | `SettlementOperationBodyV1` | deterministic settlement application |
| 27 | complete `OrderedEvidenceV1` | accountability evidence admission |
| 28 | `DaObligationOperationBodyV1` | DA obligation create/extend/release/GC |
| 29 | `EconomicObjectOperationBodyV1` | account transfer/create and bond fund/create |

`LeaseProviderAcceptanceBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, lease_id:LeaseIdV1,
provider_agent_id:AgentIdV1, expected_task_revision:u64,
acceptance_nonce:Hash32)`. Each exact body for kinds `12..23` is defined once
in its owner document and referenced here verbatim; there is no inferred common
prefix or opaque `action_parameters` shortcut. Every body names its target,
expected revision/generation, and closed action-specific fields directly.
Kinds `18`, kind `23` action `4 CloseExpired`, kind `26`, and kind `28` action
`3 GarbageCollect` are the only permissionless
triggers: their outer sender pays/consumes a nonce but grants no lifecycle
authority; execution authorizes them only from current height and authenticated
target/deadline state. Kind `26` contains no caller-selected value allocation;
the chain derives its unique settlement facts. All other lifecycle operations require the exact
owner/policy authority defined by the target's creation profile.

For unsigned creation/transition kinds `0..20`, `23`, `26`, `28`, and `29`, `operation_body` is
the exact CEV1 body with no embedded admitted-object ID or authorization set.
For externally authorized kinds `21`, `24`, `25`, and `27`, it is the complete
exact object including its required verifier, bilateral, or evidence
signatures; those inner signatures prove their role-specific statements while
the outer transaction only authorizes submission, fee, nonce, and access. The
outer transaction is the only Order carrier and consumes its nonce once.
Unknown discriminants, trailing bytes, a signed wrapper in an unsigned-body
kind, or a standalone state-changing object outside this carrier fails closed.
DA and consensus certificates remain only in their separately closed Order
evidence/sidecar fields and cannot replace this carrier.
Kind 22 is a complete object carried under the ordinary outer authorization,
but its authority mode is ExistingAgent rather than ExternallySignedObject: its
inline `VerificationClaimV1` signatures are deterministically aggregated and
there is no extra evaluator signature.
Kind 29 uses `outer_authority_mode=0 ExistingAgent`; the source Account owner
and controller/capability asset/action scope must authorize the exact debit and
destination operation.

`CoordinationProfileV1` is the exact context-free body selected by
`StackProfileV1.coordination_profile_hash`: `(schema_version:u16=1,
protocol_version:u32=1, operation_limits:List<OperationLimitV1>,
state_tree_version:u16, transaction_failure_policy:u16,
mvcc_policy_hash:Hash32, event_policy_hash:Hash32,
settlement_policy_registry_hash:Hash32)`. `OperationLimitV1` is exactly
`(operation_kind:u16, enabled:bool, max_body_bytes:u64,
max_count_per_block:u32, outer_authority_mode:u8)`; the list contains exactly
one strictly ordered entry for every kind `0..29`. Authority modes are `0
ExistingAgent`, `1 ExistingOrSelfOrigin`, `2 PermissionlessTrigger`, and `3
ExternallySignedObjectSubmittedByAgent`, and `4 ActionDependent`, fixed by the carrier table and owner
documents. Disabled requires both maxima zero; enabled requires both positive.
Reference v1 enables required lifecycle kinds `0..19`, `21..26`, `28`, and `29`; it disables
kind `20` until exact mutable task-term semantics are frozen and kind `27`
until every evidence decoder and vector is frozen. This committed profile, not a feature flag, is the sole
enable/count/size authority.
Kind 28 uses `outer_authority_mode=4 ActionDependent`: its GC action is the
permissionless branch and every other action uses document 06's reason/owner
authority matrix.
`coordination_profile_hash = DigestV1(
"trnm.poco-ai.coordination-profile.v1", CoordinationProfileV1)` and MUST equal
the selected StackProfile/bootstrap component hash.

`ObjectAccessV1` is exactly `(object_id: TypedObjectIdV1,
expected_version: Option<u64>, access_mode: u8)`. Its closed modes are `0 Read`,
`1 Write`, `2 Create`, and `3 Delete`. Entries are strictly increasing by
`(object_id.object_kind, object_id.object_id)`, duplicate-free, and a single ID
cannot appear with two modes. `Create` requires no expected version; Read,
Write, and Delete require the exact current version. Unknown modes or a type
not permitted by the selected operation fail closed.

The complete nonce write set contains the sender's exact `NonceLaneIdV1`
(object kind 44) and, when a distinct fee payer exists, the payer statement's
independently derived lane ID. Both are declared Write with exact versions;
self-origin creation instead creates the new sender lane-0 state while writing
the already-admitted payer lane. The two IDs must be distinct unless sender and
payer are the same authorized identity, in which case there is exactly one
deduplicated lane/write/advance. A dynamic execution failure advances each
declared sender/payer nonce exactly once under the failure policy; static
invalidity advances neither. Thus fee sponsorship cannot replay a payer nonce,
and nonce advancement is neither implicit nor exempt from access validation.
`fee_payer_account_id` is signed by sender and payer; its owner equals
`fee_payer_id`, its asset equals the FeeSchedule settlement asset, and it is a
mandatory exact-version Write. Access-list presence alone grants no debit.

`EconomicObjectOperationBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,action:u8,source_account_id:AccountIdV1,
expected_source_version:u64,destination_id:Option<TypedObjectIdV1>,
destination_body:Option<Bytes>,expected_destination_version:Option<u64>,
amount:u128,operation_nonce:Hash32)`. Action `0 CreateAccount` decodes an exact
AccountBody owned by the authorized destination agent; `1 Transfer` names an
existing Account; `2 CreateBond` decodes an exact BondBody and funds it; `3
TopUpBond` names an existing Bond. Positive source debit equals destination
credit; asset/owner/bond-purpose/source and field presence are action-exact.
Writes or Create commit atomically with no mint. Stale versions, insufficient
value, duplicate IDs, or undeclared access invalidates the transaction.

The fields above are the complete immutable `AgentTransactionBodyV1`.
`TransactionSenderAuthorizationV1` is the closed union `0 ExistingAgent {
authorization:AuthorizationSetV1 } | 1 SelfOrigin {
authorization:SeedIdentityAuthorizationV1 }`. `AgentTransactionV1` is exactly
`(body: AgentTransactionBodyV1, transaction_id:AgentTransactionIdV1,
sender_authorization:TransactionSenderAuthorizationV1, fee_payer_authorization:
Option<FeePayerAuthorizationV1>)`. `AgentTransactionIdV1` is
`DigestV1("trnm.poco-ai.agent-transaction.v1",
AgentTransactionBodyV1)`, and `sender_authorization` authenticates that exact
typed ID through document 02 or the sole document-03 self-origin rule. A distinct payer requires the complete sponsor
authorization; same-sender payment may omit it only under document 02's exact
rule. Static validity checks context, expiry, encoding, size, authorization,
known operation, canonical
access-list order, unique object IDs, arithmetic, and profile bounds before
scheduling.

At execution-parent height `h`, validators recheck
`valid_from_height <= h <= valid_until_height`; every sender and present fee
payer statement independently satisfies `valid_after_height <= h <=
expires_after_height`; the transaction interval is contained within each
statement interval; and every selected key, capability, and session grant is
Active and its own inclusive interval contains `h`. Mempool-time success never
grandfathers an expired authorization into a block.

`SelfOrigin` is legal only for kind `0`. `sender_agent_id` MUST equal the
identity body-derived `AgentIdV1`; capability/session fields are absent/zero,
`authorizing_key_id` is the zero typed-key sentinel, lane and nonce are zero,
and the authorization binds both that transaction ID and derived agent ID.
Because the account does not yet exist, `fee_payer_id` MUST be a distinct
already admitted agent with a complete `FeePayerAuthorizationV1`; there is no
implicit nonce or free-fee path. `ExistingAgent` is mandatory for every other
kind.

Existing-agent controller-threshold authorization requires `capability_id = None`,
`capability_generation = 0`, `session_key_grant_id = None`, and
`session_generation = 0`; its `authorizing_key_id` is the zero
`AgentKeyIdV1` controller-threshold sentinel and selects the same lane-0 replay
namespace. Real controller key IDs appear only as the strictly ordered
signature members of the canonical `AuthorizationSetV1`, which must reach the
live threshold. Delegated session authorization requires all of
`capability_id`, its exact live `capability_generation`, and
`session_key_grant_id`, and the grant MUST bind the same
`authorizing_key_id`, `session_generation`, and nonzero lane. Every other
present/absent or zero/nonzero combination is invalid.

Nonce state uses the single replay key defined in document 03:
`(agent_id, authorizing_key_id, capability_id, session_generation,
nonce_lane_id:u16)`. One key/session/capability/lane cannot replay into another,
and revoking a capability or session generation invalidates its future
authorizations. All lanes reserve against the same capability budget as one
atomic deterministic transition. A higher nonce is not consensus-valid for the
current state; it may exist only in a bounded local admission queue. Duplicates
and lower nonces are invalid.

`AgentBatchV1` amortizes one authorization over a bounded ordered list of
operations. Its batch operation kind is reserved for a future protocol version
until an exact body/authorization schema is frozen; the current v1 draft target
does not accept it despite retaining the architectural target. When enabled it
must commit a batch sequence, lane, operation root, aggregate
budget, aggregate resource limit, and failure policy. Atomic-all and
continue-on-failure are distinct closed enum values; there is no implicit
partial success.

## 2. Deterministic object model

Consensus state is a versioned object graph. Every object has a canonical ID,
schema version, owner/authority, predecessor version, lifecycle state, and
content hash. State operations name explicit read/write/create/delete intents.
Unknown schema versions, undeclared writes, ownership violations, or cyclic
dependencies fail closed.

The economic state kinds are exact. `AccountBodyV1 = (schema_version:u16=1,
context:ProtocolContextV1,owner_agent_id:AgentIdV1,asset_id:Hash32,
account_nonce:Hash32)` and `AccountIdV1 = DigestV1(
"trnm.poco-ai.account.v1",AccountBodyV1)`; `AccountStateV1 =
(schema_version:u16=1,context:ProtocolContextV1,account_id:AccountIdV1,
version:u64,available:u128,reserved:u128,spent:u128,closed:bool)`.
`ValuePoolBodyV1 = (schema_version:u16=1,context:ProtocolContextV1,
pool_kind:u16,asset_id:Hash32,authority_hash:Hash32,pool_nonce:Hash32)` and
`ValuePoolIdV1 = DigestV1("trnm.poco-ai.value-pool.v1",ValuePoolBodyV1)`;
`ValuePoolStateV1` is `(schema_version:u16=1,
context:ProtocolContextV1,pool_id:ValuePoolIdV1,version:u64,
available:u128,reserved:u128,disbursed:u128,closed:bool)`.
`BondBodyV1 = (schema_version:u16=1,context:ProtocolContextV1,
owner_agent_id:AgentIdV1,asset_id:Hash32,purpose:u16,
source_object_id:TypedObjectIdV1,bond_nonce:Hash32)` and `BondIdV1 =
DigestV1("trnm.poco-ai.bond.v1",BondBodyV1)`; `BondStateV1` is
`(schema_version:u16=1,context:ProtocolContextV1,bond_id:BondIdV1,
version:u64,available:u128,held:u128,released:u128,slashed:u128,closed:bool)`.
All amounts use checked conservation; object kinds 45/46/47 are the only
account/pool/bond access keys, and bare bytes/hashes cannot name balances.

The reference executor uses object-aware optimistic MVCC:

1. transactions are assigned their canonical block index;
2. speculative workers execute against a versioned snapshot and record exact
   read versions, write sets, events, usage, and fee deltas;
3. validation occurs in canonical index order;
4. a read-version mismatch deterministically re-executes the transaction;
5. the canonical serial order is the semantic oracle;
6. only validated outputs commit, in canonical order, to one atomic block
   state transition and authenticated root update.

Scheduler interleaving, worker count, retry timing, cache state, CPU features,
or host ordering MUST NOT change receipts, fees, events, roots, or final state.
Floating point, wall clock, network I/O, external service calls, nondeterministic
GPU execution, unordered map iteration, unseeded randomness, and host locale
are forbidden in consensus execution.

Access lists are performance declarations, not authorization. An implementation
may discover extra reads but MUST deterministically reclassify/re-execute; an
undeclared write is invalid under the reference profile. Hot objects such as a
global fee collector MUST NOT force every transaction into one write conflict.

## 3. Receipt and outcome semantics

Unlike PoCO-BFT v0 application receipts,
`TransactionExecutionReceiptBodyV1` always commits an explicit outcome. This is
the deterministic on-chain transaction receipt and is distinct from the
off-chain provider `ExecutionReceiptV1` in document 05:

```text
schema_version             u16                 // 1
context                    ProtocolContextV1
transaction_id             AgentTransactionIdV1
transaction_index          u32
status                     ReceiptStatusV1
error_class                Option<u16>
return_data_commitment     Option<Hash32>
events_root                Hash32
read_set_root              Hash32
write_set_root             Hash32
state_delta_root           Hash32
post_transaction_state_root Hash32
resource_usage             List<ResourceUsageV1>
fee_charged                 u128
refund_amount               u128
created_object_root         Hash32
```

`TransactionExecutionReceiptIdV1` is
`DigestV1("trnm.poco-ai.transaction-execution-receipt.v1",
TransactionExecutionReceiptBodyV1)`. `TransactionExecutionReceiptV1` is
exactly `(body:TransactionExecutionReceiptBodyV1,
receipt_id:TransactionExecutionReceiptIdV1)`; it has no signer or self ID in
its body. Block root kind 2 orders receipts strictly by `transaction_index`,
which must be gap-free from zero and correspond one-to-one with the ordered
transactions. Each leaf has `item_kind = 11` (the closed typed-object kind for
this receipt), `item_id = receipt_id`, and `item_commitment = DigestV1(
"trnm.poco-ai.transaction-execution-receipt-content.v1",
TransactionExecutionReceiptV1)`. Body, ID, index, transaction ID, list count,
and root are all recomputed; a body-only or signature-bearing alias is invalid.

The receipt deliberately omits the current `BlockIdV1`: the header commits the
receipt root and the block ID is the digest of that header, so embedding the
current block ID in a committed receipt would be self-referential. An
application-state or receipt-inclusion proof binds the receipt, its canonical
transaction index, the header receipt root, and the finalized block ID.
Its `events_root`, `read_set_root`, `write_set_root`, `state_delta_root`, and
`created_object_root` use document 02 root kinds 11 through 15 respectively.

The exact root item records are:

```text
EventRecordV1 =
  event_kind:u16, source_object_id:TypedObjectIdV1,
  event_sequence:u64, event_bytes:Bytes
ReadSetEntryV1 =
  object_id:TypedObjectIdV1, observed_version:u64,
  observed_value_hash:Hash32
WriteSetEntryV1 =
  object_id:TypedObjectIdV1, prior_version:u64, successor_version:u64,
  successor_value_hash:Hash32
StateDeltaEntryV1 =
  object_id:TypedObjectIdV1, prior_version:Option<u64>,
  successor_version:Option<u64>, prior_value_hash:Option<Hash32>,
  successor_value_hash:Option<Hash32>, delta_kind:u8
CreatedObjectEntryV1 =
  object_id:TypedObjectIdV1, initial_version:u64,
  owner_id:TypedObjectIdV1, value_hash:Hash32
```

`delta_kind` is `0 Create`, `1 Update`, or `2 Delete`; the option pattern must
match the kind exactly. Each list is strictly increasing by typed object ID
(events by `(source_object_id, event_sequence, event_kind)`) and duplicate-free.
For root kinds 11–15, the Merkle leaf `item_kind` equals the corresponding
closed kind value `0..4`, `item_id` is the deterministic digest
`DigestV1("trnm.poco-ai.execution-root-item-id.v1",
(root_kind:u16, transaction_id:AgentTransactionIdV1, index:u32))`, and
`item_commitment` is `DigestV1(
"trnm.poco-ai.execution-root-item.v1",
(root_kind:u16, item_record_bytes:Bytes))`, where `item_record_bytes` is the
exact CEV1 record above. The leaf position equals `index`. A different root
kind, record type, order, version transition, or body-only hash is invalid.

Closed statuses are `Success`, `Reverted`, and `OutOfResource`. Static invalid
transactions are block-invalid and have no receipt. A dynamically reverted or
out-of-resource transaction consumes its authorized nonce and deterministically
pays the defined admission/execution cost while rolling back operation writes
other than canonical nonce, fee, and evidence effects. Panic, overflow,
unknown error, or host failure is not a receipt status; it is validator
unavailability or a consensus bug.

## 4. Task and verification coordination

The state machine from [04](04-market-task-lease-escrow-and-lifecycle.md) is
enforced as explicit versioned objects. The deterministic chain validates:

- capability and budget authority for offer/accept/cancel/migrate actions;
- lease ownership, deadlines, checkpoint ancestry, escrow coverage, and SLA;
- exact task/input/artifact/profile bindings on execution receipts;
- proof, attestation, evaluator, or challenge evidence according to the exact
  `(verification_profile_id: Bytes, verification_profile_version: u32,
  verification_profile_hash: Hash32)` committed by the task;
- the exact monotonic `ResultStatusV1` transitions
  `Submitted -> Evaluating -> ProvisionalValid/ChallengeOpen/Final*` and the
  separate `SettlementMaturityV1` transitions from document 05.

Unknown verification profiles fail closed. A verification profile defines its
statement, public bindings, verifier authority, evidence format, DA/retention
requirements, provisional result rule, challenge/appeal windows, resolution
rule, settlement maturity, and eligibility for future PoCO weight. A hash
receipt alone proves none of usefulness, factual truth, quality, fair price,
privacy, or independence.

## 5. Consumption receipts and rollups

A `ConsumptionReceiptBodyV1` is a bilateral, monotonic metering body with this
exact logical field order:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
provider_id                 AgentIdV1
consumer_id                 AgentIdV1
task_id                     TaskIdV1
lease_id                    LeaseIdV1
attempt                     u32
result_id                   ResultIdV1
meter_id                    Bytes
meter_version               u32
sequence                    u64                 // positive
period_start_height         u64
period_end_height           u64
usage                       List<ResourceUsageV1>
unit_price_commitment       Hash32
prior_receipt_id            Option<ConsumptionReceiptIdV1>
cumulative_usage            List<CumulativeResourceUsageV1>
cumulative_usage_root       Hash32
cumulative_charge           u128
artifacts                   List<ConsumptionArtifactBindingV1>
artifact_root               Hash32
evidence_certificate_id     AvailabilityCertificateIdV1
related_party_policy_hash   Hash32
```

`usage` uses the single seven-field `ResourceUsageV1` defined in section 7 and
document 05; there is no receipt-local compact alias.
`CumulativeResourceUsageV1` is exactly `(resource_class:u16,
resource_id:Bytes,meter_id:Bytes,meter_version:u32,total_amount:u128,unit:u16,
accumulator_commitment:Hash32)`, strictly ordered and unique by
`(resource_class,resource_id,meter_id,meter_version,unit)`, with positive total.
For sequence one,
`prior_receipt_id` is absent; for every later sequence it is the exact ID at
the immediately preceding coordinate. `cumulative_usage` has the same closed
keys and `total_amount` equals the checked component-wise prior cumulative
value plus this receipt's `usage.amount` (zero prior for a newly introduced
key). For each key, `accumulator_commitment = DigestV1(
"trnm.poco-ai.consumption-usage-accumulator.v1",
(key_fields,prior_total:u128,prior_accumulator:Option<Hash32>,
period_amount:u128,period_measurement_commitment:Hash32,total_amount:u128))`;
the sequence-one prior is zero/absent. Its root is
`DigestV1("trnm.poco-ai.consumption-cumulative-usage-root.v1",
List<CumulativeResourceUsageV1>)`. `cumulative_charge` is likewise the checked prior
charge plus the exact price-schedule charge for this period; it cannot be an
independent signed scalar.

`ConsumptionArtifactBindingV1` is exactly `(artifact_role:u16,
artifact_id:ArtifactIdV1,certificate_id:AvailabilityCertificateIdV1,
content_commitment:Hash32)`, strictly ordered and unique by
`(artifact_role,artifact_id,certificate_id)`. Every certificate/item inclusion
is supplied and verified at admission. `artifact_root = DigestV1(
"trnm.poco-ai.consumption-artifact-root.v1",
List<ConsumptionArtifactBindingV1>)`. Thus both roots have complete canonical
preimages in the signed body. Admission reads the preceding receipt state/body
when present and rejects a gap, fork, decreasing total, root mismatch, price
mismatch, or unverifiable artifact.

`BilateralSignatureEntryV1` is exactly `(agent_id:AgentIdV1,
key_id:AgentKeyIdV1, key_role:u8, policy_revision:u64, key_generation:u64,
authority_height:u64, signature_scheme:u16, signature:Bytes)`.
`BilateralSignatureStatementV1` is exactly `(schema_version:u16=1,
body_id:TypedObjectIdV1, agent_id:AgentIdV1, key_id:AgentKeyIdV1,
key_role:u8, policy_revision:u64, key_generation:u64,
authority_height:u64)`. Reference v1 uses exactly one active
bilateral-receipt key per role, so each role set has exactly one entry; a future
threshold set requires a new protocol version. `key_role` MUST equal `4`.
For both receipt signatures, `authority_height` MUST equal both body
`period_end_height` and the current execution height. Admission authenticates
the exact current AgentIdentityState, policy revision, and AgentKeyState and
requires that role-4 key Active at that height. A naked caller-selected or
historical height, cached past policy, or signature admitted after revocation
cannot backfill authority. Later rotation/revocation does not erase a receipt
already order-finalized before revocation.

`ConsumptionReceiptV1` is exactly `(body: ConsumptionReceiptBodyV1,
provider_signature:BilateralSignatureEntryV1,
consumer_signature:BilateralSignatureEntryV1)`. Its typed ID is
`DigestV1("trnm.poco-ai.consumption-receipt.v1", body)`; signatures are not part
of the logical ID. Provider signs `DigestV1(
"trnm.poco-ai.consumption-receipt-provider-signature.v1",
BilateralSignatureStatementV1)` and consumer signs the same exact statement
shape under the corresponding consumer domain. Wrapper agent IDs must equal
the body roles; domains/keys cannot be swapped.

Admission creates `ConsumptionReceiptStateV1 = (schema_version:u16=1,
context:ProtocolContextV1,receipt_id:ConsumptionReceiptIdV1,version:u64,
status:u8,assigned_rollup_id:Option<ConsumptionRollupIdV1>,
accepted_height:u64)`, version zero/status `0 Unassigned`. Status `1 Assigned`
is terminal and requires a present rollup ID. Its unique coordinate is the body
`(provider,consumer,task,lease,attempt,meter_id,meter_version,sequence)`; a
secondary authenticated coordinate index maps it to exactly one receipt ID.
Receipt admission creates both records atomically; an occupied coordinate
rejects any different receipt.

`ConsumptionReceiptCoordinateBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,provider_id:AgentIdV1,
consumer_id:AgentIdV1,task_id:TaskIdV1,lease_id:LeaseIdV1,attempt:u32,
meter_id:Bytes,meter_version:u32,sequence:u64)`. Its typed ID is
`DigestV1("trnm.poco-ai.consumption-receipt-coordinate.v1",
ConsumptionReceiptCoordinateBodyV1)`. Admission creates
`ConsumptionReceiptCoordinateStateV1 = (schema_version:u16=1,
context:ProtocolContextV1,
coordinate_id:ConsumptionReceiptCoordinateIdV1,version:u64=0,
receipt_id:ConsumptionReceiptIdV1)` under that ID in the same atomic write as
the receipt. This state is immutable: no transition or deletion is legal in
reference v1. The coordinate body MUST equal the exact projection of the
receipt body, so alternate encodings or role/order substitutions fail closed.

One `(provider, consumer, task, lease, meter_profile, sequence)` can appear at
most once. Related-party classification is committed, not inferred after
weight calculation.

`ConsumptionRollupBodyV1` has this exact logical field order:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
provider_id                 AgentIdV1
consumer_id                 AgentIdV1
task_id                     TaskIdV1
lease_id                    LeaseIdV1
attempt                     u32
result_id                   ResultIdV1
meter_id                    Bytes
meter_version               u32
first_sequence              u64
last_sequence               u64
receipt_ids                 List<ConsumptionReceiptIdV1>
receipt_count               u32
receipts_root               Hash32
usage_totals                List<ResourceUsageV1>
total_charge                u128
task_result_root            Hash32
evidence_entries            List<RollupEvidenceEntryV1>
evidence_root               Hash32
evidence_certificate_id     AvailabilityCertificateIdV1
escrow_id                   EscrowIdV1
settlement_policy_hash      Hash32
related_party_policy_hash   Hash32
```

`ConsumptionRollupV1` is exactly `(body: ConsumptionRollupBodyV1,
provider_signature:BilateralSignatureEntryV1,
consumer_signature:BilateralSignatureEntryV1)`. Its typed ID is
`DigestV1("trnm.poco-ai.consumption-rollup.v1", body)` and both signatures cover
their exact authority statements containing that typed ID under the registered
rollup provider/consumer domains. For a rollup, each statement's
`authority_height` MUST equal the current execution height and both role-4 keys
and policy revisions MUST be Active in that exact execution-parent state. The
complete receipt interval remains authenticated by `receipts_root`; it is not
reinterpreted as a historical signing-state height. The receipt and rollup
rules admit no alternate signing-state height.

Each signer durably journals `(context, provider, consumer, task, lease,
attempt, meter_id, meter_version, first_sequence, last_sequence, role)` plus the
exact receipt/rollup ID before signature release. Exact replay returns the same
signature. A distinct ID under that coordinate/role is conflicting bilateral
meter evidence and fails closed; it cannot be normalized into another range.

`first_sequence <= last_sequence`, `receipt_count` equals both the inclusive
interval length and the length of `receipt_ids`, and the root binds every exact
receipt by sequence. `receipt_ids` are in strictly increasing sequence order,
not digest order. Entries
cannot be omitted, duplicated, split, or reused across rollups. A rollup is
provisional until its evidence is available, all required signatures/proofs
pass, and its challenge window closes.
For `receipts_root`, entry `i` uses root kind 16 with `item_kind=0`,
`item_id = receipt_ids[i]`, and `item_commitment = DigestV1(
"trnm.poco-ai.rollup-receipt-entry.v1",
(sequence:first_sequence+i,receipt_id:receipt_ids[i]))`; every ID MUST equal
the supplied admitted receipt at that sequence. `TaskResultBindingV1` is
exactly `(task_id:TaskIdV1,lease_id:LeaseIdV1,attempt:u32,
result_id:ResultIdV1)`. `task_result_root` is root kind 17 with exactly one
entry: kind zero, ID `DigestV1("trnm.poco-ai.task-result-binding-id.v1",
TaskResultBindingV1)`, and commitment `DigestV1(
"trnm.poco-ai.task-result-binding.v1",TaskResultBindingV1)`.
`RollupEvidenceEntryV1` is exactly `(evidence_kind:u16,
artifact_id:ArtifactIdV1,certificate_id:AvailabilityCertificateIdV1,
evidence_commitment:Hash32)`. Entries are strictly ordered and unique by
`(evidence_kind,artifact_id,certificate_id)`, their certificates/artifacts are
fully verified, and the named `evidence_certificate_id` occurs in exactly one
entry. `evidence_root` is root kind 3 over these entries with item kind equal
`evidence_kind`, item ID `DigestV1("trnm.poco-ai.rollup-evidence-entry-id.v1",
RollupEvidenceEntryV1)`, and item commitment `DigestV1(
"trnm.poco-ai.rollup-evidence-entry.v1",RollupEvidenceEntryV1)`.
Settlement input, delta, and conservation roots use kinds 18, 19, and 20
under section 6. The
conservation root commits the exact canonical `planned_deltas` list and checked
input/output totals; it is not an independently asserted scalar.

Rollup admission supplies the complete ordered `ConsumptionReceiptV1` list as
verification input, recomputes every ID/root/total and declares every receipt
state Write. It atomically changes each gap-free Unassigned receipt to Assigned
with this exact rollup ID while creating the rollup. Any already-assigned,
missing, differently coordinated, or overlapping interval invalidates the
whole operation. Settlement and PoCO weight require every referenced receipt
state to name that one rollup.

Challenge heights are chain-assigned state, not values chosen by the two
signers. On first admission the chain sets
`accepted_height = current_height` and
`challenge_close_height = checked_add(accepted_height,
settlement_policy.minimum_rollup_challenge_blocks)`. The minimum is positive
and epoch committed; overflow is invalid. A policy may extend but never shorten
the close height, and every open challenge/evidence/legal hold delays maturity.
`ConsumptionRollupStateV1` commits accepted/close heights and settlement/
PoCO-eligibility status. Reference v1 has no separate rollup challenge action;
the bilateral evidence dispute belongs to Result/Challenge state.

Its exact value is `(schema_version:u16=1,
context:ProtocolContextV1, rollup_id:ConsumptionRollupIdV1, version:u64,
accepted_height:u64,challenge_close_height:u64,
status:u8,consumed_by_settlement_id:Option<SettlementIdV1>)`, where status is
`0 Provisional` or `1 Consumed`. Admission creates version zero/Provisional and
no settlement. Maturity is a pure predicate, never a state write:
`current_height > challenge_close_height` and all referenced Result/Challenge/
DA/legal holds are terminal/cleared. Kind 26 rechecks that predicate and changes
Provisional directly to Consumed while naming the settlement. This is the only
rollup-state transition and is one-shot.

Only fully paid or correctly refunded, challenge-closed, non-reversed,
related-party-policy-compliant consumption that has passed the configured
maturity delay may enter a later epoch's PoCO weight snapshot. Order inclusion,
receipt signing, or rollup creation alone is never voting power.

## 6. Result and settlement lifecycle

Document 05 owns the unique `ResultStatusV1`. Settlement uses the separate
`SettlementMaturityV1`; the combined client/proof view is
`ResultSettlementStatusV1`. The forward-only projection is:

```text
Result Submitted/Evaluating
  -> ProvisionalValid/ChallengeOpen
  -> FinalValid | FinalInvalid | Inconclusive
SettlementMaturity NotStarted -> Final  // Pending is execution-internal only
```

`FinalValid` authorizes any success-contingent provider payment. A frozen task
policy may also compensate separately measured work, storage, or cancellation
cost after `FinalInvalid` or `Inconclusive`, but MUST NOT label that
compensation as payment for a valid result. `FinalInvalid` may create a forward
payment/refund/slash/retry or mixed settlement under that exact policy, while
`Inconclusive` may create only its explicit work-cost/refund/retry/failure
settlement and never becomes valid. Both use
the same atomic `NotStarted -> Final` committed transition, whose exact
receipt records whether deltas paid, refunded, slashed, or mixed. Task attempts
may also end in the exact document-04 states `Cancelled`, `Expired`, or
`Failed` where the task/profile contract permits.
A successful challenge never rolls
the chain back. It produces ordered state transitions that may invalidate a
provisional result, release/refund escrow, pay a challenger, slash a bonded
party, lower reputation, and authorize resume/migration/re-execution.

`SettlementOperationBodyV1` is the closed trigger `(schema_version:u16=1,
context:ProtocolContextV1,task_id:TaskIdV1,lease_id:LeaseIdV1,attempt:u32,
result_id:ResultIdV1,expected_task_revision:u64,
expected_result_revision:u64,expected_escrow_version:u64,
settlement_policy_hash:Hash32)`. It carries no amounts, rollup selection,
receipt, maturity, or status. Execution uniquely projects the complete
settlement below from authenticated state; ambiguity or a missing input makes
the operation invalid.

`SettlementPolicyV1` is the exact context-free record `(schema_version:u16=1,
policy_revision:u32,result_outcome_rules:List<ResultOutcomeSettlementRuleV1>,
minimum_rollup_challenge_blocks:u64,maximum_rollups:u32,
allowed_input_kinds:List<u16>,allowed_delta_reasons:List<u16>,
fee_schedule_hash:Hash32)`. `ResultOutcomeSettlementRuleV1` fixes one
ResultStatus and the permitted provider-payment/refund/slash/retry buckets.
Both lists are strictly numeric-ordered/unique and subsets of the closed enums
below. Its digest under `trnm.poco-ai.settlement-policy.v1` equals every task,
escrow, result, rollup and operation reference. This full preimage, not a bare
hash, is distributed by the epoch settlement-policy registry.

`SettlementIntentV1` freezes the derived inputs and value-conservation equation:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
task_id                     TaskIdV1
lease_id                    LeaseIdV1
attempt                     u32
result_id                   ResultIdV1
result_revision             u64
result_status               ResultStatusV1
settlement_maturity         SettlementMaturityV1
escrow_id                   EscrowIdV1
consumption_rollup_ids      List<ConsumptionRollupIdV1>
challenge_resolution_ids    List<ChallengeIdV1>
fee_schedule_hash           Hash32
settlement_policy_hash      Hash32
inputs                      List<SettlementInputV1>
input_value_root            Hash32
planned_deltas              List<ValueDeltaV1>
planned_deltas_root         Hash32
conservation_root           Hash32
```

The only legal value of `settlement_maturity` in the derived
`SettlementIntentV1` is `Pending`; `NotStarted` or `Final` makes the operation
invalid. It is an authenticated consistency discriminant, not caller authority
to mature settlement. This yields one intent ID per planned settlement and
prevents an early-final or synonymous alternate ID.

`SettlementInputV1` is exactly `(asset_id:Hash32, input_kind:u16,
source_object_id:TypedObjectIdV1, source_state_version:u64,
source_account_or_pool_id:TypedObjectIdV1, amount:u128)`. Inputs are positive, strictly
ordered by `(asset_id,input_kind,source_object_id.object_kind,
source_object_id.object_id,source_account_or_pool_id)`, and duplicate-free.
`input_value_root` uses root kind 18: leaf `item_kind = input_kind`, `item_id =
DigestV1("trnm.poco-ai.settlement-input-id.v1", SettlementInputV1)`, and
`item_commitment = DigestV1("trnm.poco-ai.settlement-input.v1",
SettlementInputV1)`. The inline list and root must match exactly.

`input_kind` is closed: `0 Account`, `1 Escrow`, `2 ValuePool`, or `3 Bond`.
The `source_account_or_pool_id` tag must respectively be 45, 7, 46, or 47 and
equal the actual debited state; `source_object_id` is the lifecycle object that
authorizes that debit. Asset/body/state/version/positive amount must all agree.
No kind changes sign semantics: every settlement input is value consumed from
the named source exactly once.

The complete input list is uniquely projected—not selected by the caller—from
the authenticated current task/lease/attempt/result/escrow, all referenced
mature rollups, challenge bonds/resolutions, fee schedule, and settlement
policy. Application atomically requires: all repeated IDs and the exact
`result_revision/status` equal current state; status is `FinalValid` or
`FinalInvalid`, or `Inconclusive` only when the frozen policy explicitly
permits its failure/refund compensation; task is `SettlementPending`; every
challenge index entry is terminal, `open_challenge_count = 0`, its close height
has passed, and no evidence/legal/rollup hold remains; each rollup is mature,
unconsumed, and exactly listed; input versions/amounts equal current state; and
no prior settlement state exists for this task/lease/attempt/result.
Any failure leaves escrow, inputs, deltas, nonce effects beyond the ordinary
failed-transaction rule, and settlement state unchanged.

`planned_deltas_root` uses root kind 19. Its leaves contain the canonical
`ValueDeltaV1` records in sorted order: `item_kind = 0`, `item_id` is
`DigestV1("trnm.poco-ai.value-delta-id.v1", (index:u32,
value_delta:ValueDeltaV1))`, and `item_commitment` is
`DigestV1("trnm.poco-ai.value-delta.v1", ValueDeltaV1)`. It MUST recompute from
the exact inline `planned_deltas`; the inline list cannot disagree.

`ConservationStatementV1` is exactly `(schema_version:u16=1,
asset_id:Hash32, asset_input_value_root:Hash32,
asset_planned_deltas_root:Hash32, input_total:u128, explicit_mint_total:u128,
output_total:u128, refund_total:u128, burn_total:u128, fee_total:u128,
bond_held_total:u128, reward_total:u128, slash_held_total:u128,
rounding_remainder:u128)`. `conservation_root` uses root kind 20 with one leaf
per distinct asset, strictly increasing by raw `asset_id`. Each leaf has
`item_kind = 0`, `item_id = DigestV1(
"trnm.poco-ai.conservation-statement-id.v1", ConservationStatementV1)`, and
`item_commitment = DigestV1("trnm.poco-ai.conservation-statement.v1",
ConservationStatementV1)`. Each asset-specific input root/delta root is the
canonical filtered projection from the intent's complete roots/lists; every
input and delta appears in exactly one asset statement. All totals are uniquely
recomputed and each asset independently satisfies section 8's equation with
checked arithmetic. Amounts of one asset never offset another. A
planned-deltas root is never valid as a conservation root.

`SettlementReceiptV1` records the applied result:

```text
schema_version              u16                 // 1
context                     ProtocolContextV1
settlement_id               SettlementIdV1
task_id                     TaskIdV1
lease_id                    LeaseIdV1
result_id                   ResultIdV1
escrow_id                   EscrowIdV1
applied_deltas              List<ValueDeltaV1>
post_account_versions_root  Hash32
post_escrow_version         u64
```

`PostAccountVersionEntryV1` is exactly `(state_id:TypedObjectIdV1,
prior_version:u64,post_version:u64,post_value_hash:Hash32)`, strictly ordered
by typed ID and containing every account/pool/bond/escrow write exactly once.
`post_account_versions_root = DigestV1(
"trnm.poco-ai.post-account-versions-root.v1",
List<PostAccountVersionEntryV1>)`; versions are checked predecessor plus one and
the receipt's inline applied deltas uniquely produce the same post values.

The one state-tree value under the typed `SettlementIdV1` key is
`SettlementStateV1 = (schema_version:u16=1,
context:ProtocolContextV1,settlement_id:SettlementIdV1,state_version:u64,
intent:SettlementIntentV1,status:u8,receipt:Option<SettlementReceiptV1>,
applied_height:Option<u64>)`. Status is `0 Pending` or `1 Final`; Pending is
reserved for a future protocol version and is invalid as committed reference-v1
post-state. Kind 26 deterministically constructs both intent and receipt and
creates version zero/Final with present receipt/current applied height in one
atomic transition. The intent and receipt are never separate values or aliases
under that key.

Execution requires receipt task/lease/result/escrow fields byte-for-byte equal
the derived intent, `applied_deltas == planned_deltas` byte-for-byte, every
input version and amount still equal current authenticated state, and no prior
state for this settlement ID. It consumes all inputs and applies all deltas
atomically once and derives `post_account_versions_root` and
`post_escrow_version` from the actual canonical write set. Exact transaction
replay is idempotent only after proving the already-committed state has the
identical receipt/write result; a different result or stale input fails closed.

The canonical successful atomic write set is ordered by typed state key and is:

1. one new `SettlementStateV1` at version zero/status Final with the exact
   derived intent, receipt, and applied height;
2. every referenced input account/pool/bond state at its exact declared version;
3. `EscrowStateV1` version `n -> n+1`, conserved amounts, closed state, and
   `last_settlement_id = Some(settlement_id)`;
4. every included `ConsumptionRollupStateV1` version `n -> n+1`, status
   `Provisional -> Consumed` only after the pure maturity predicate succeeds,
   and named settlement;
5. `ResultStateV1` revision `n -> n+1`, the derived settlement ID, and
   maturity `NotStarted -> Final`, while appending a closed
   `SettlementFinalized` Result transition (kind 6) whose sole authority ID is
   the tag-20 SettlementId and whose resulting challenge root/count are
   unchanged;
6. `TaskStateV1` revision `n -> n+1`, `SettlementPending` to the exact policy
   terminal `Settled`, `Refunded`, or `Failed` disposition.

All expected prior values and next statuses are implied by the frozen policy;
no caller supplies them. `Final` inside the candidate post-state means the
settlement transition has executed; clients may prove settlement finality only
after the containing block is order-finalized. If any precondition/write fails,
none of these six write classes occur; only the globally specified failed-
transaction nonce/fee outcome may occur.

The settlement receipt likewise omits the block that contains it and any
claim that this block is already finalized. Its inclusion position and the
containing finalized header are bound by the `SettlementStateV1` membership
proof under that header's `post_state_root`;
an `OrderFinalityProofV1` establishes when that containing block becomes
order-finalized. This avoids both a block-ID/root cycle and a premature
finality claim during execution. The receipt also omits `post_state_root`:
including the root of a state that itself contains this receipt would create a
fixed-point cycle. The finalized header and state-membership proof bind the
receipt externally to the resulting post-state root.

`settlement_id = DigestV1("trnm.poco-ai.settlement.v1",
SettlementIntentV1)`; the intent body never contains its own ID. The receipt
binds that single typed ID and is not itself a second settlement identity or a
second raw intent hash.

`SignAndU128V1` is exactly `(sign: u8, magnitude: u128)`: `sign = 0` is Zero
and requires `magnitude = 0`; `sign = 1` is Positive and requires a nonzero
magnitude; `sign = 2` is Negative and requires a nonzero magnitude. Unknown
signs, positive zero, and negative zero are invalid.

`ValueDeltaV1` is exactly `(asset_id: Hash32, account_or_pool_id: TypedObjectIdV1,
reason: u16, signed_magnitude: SignAndU128V1, source_object_id:
TypedObjectIdV1)` and is strictly ordered by `(asset_id, account_or_pool_id,
reason, source_object_id.object_kind, source_object_id.object_id)`. Equal keys
are combined once with checked signed-magnitude arithmetic before the receipt
is encoded; a zero result uses the unique Zero representation. Unknown reason
or object-kind values and a source type not allowed for that reason fail
closed. Result finality precedes settlement finality unless a profile explicitly
defines an immediate deterministic result with no challenge window.

`reason` is closed: `0 ProviderPayment` (positive Account), `1 RequesterRefund`
(positive Account), `2 ProtocolFee` (positive ValuePool), `3 Burn` (negative
ValuePool), `4 BondHold` (positive Bond held bucket), `5 BondRelease` (positive
Account and matching negative Bond), `6 Slash` (negative Bond plus positive
challenger/treasury Account), and `7 RoundingRemainder` (positive configured
ValuePool). The destination tag/sign and required paired deltas are fixed by
that mapping; assets must equal the source input asset. Every reason maps to
the correspondingly named conservation bucket, and no policy may reinterpret a
number. A new reason/type/sign rule requires a new protocol version.

### 6.1 Immutable global-execution binding state object

Object kind 50 is reserved for one create-only
`GlobalExecutionBindingIdV1`. Its exact typed-ID body is
`GlobalExecutionBindingBodyV1 = (schema_version:u16=1,
context:ProtocolContextV1,candidate_height:u64,
candidate_block_id:BlockIdV1,candidate_composite_root:Hash32,
final_execution_root:Hash32)`, and
`binding_id = DigestV1("trnm.poco-ai.global-execution-binding.v1",
GlobalExecutionBindingBodyV1)`. Height, block ID and both roots are nonzero.
The composite root is the exact deterministic pre-vote commitment and the
final root is the exact terminal five-plane commitment for that same
candidate; neither is an application JMT root or a substitute for the
containing header's `post_state_root`.

The immutable bytes are exactly `GlobalExecutionBindingV1 =
(body:GlobalExecutionBindingBodyV1,binding_id:GlobalExecutionBindingIdV1)`.
The mutable bytes are the deliberately inert
`GlobalExecutionBindingStateV1 = (schema_version:u16=1,
binding_id:GlobalExecutionBindingIdV1,version:u64=0)`. The outer
`ApplicationObjectValueV1.object_id` equals the recomputed binding ID and the
outer state version is also zero. Reference v1 has no update or deletion
transition for this kind. Replaying the identical create is idempotent only
after exact value readback; another root tuple derives another typed key and
cannot overwrite the first value.

The object cannot be included in the candidate that it binds: doing so would
make the candidate/application root recursively depend on itself. A valid
membership binding therefore requires an independently verified Order
finality path which proves `(candidate_height,candidate_block_id)` is a strict
ancestor of the later finalized header whose `post_state_root` proves the
tag-50 value. A mere height comparison, a caller-supplied block ID, or two
parallel local observations is insufficient.

The bounded Rust direct verifier now supplies the minimum non-forgeable
ancestry kernel for FreshGenesis-rooted direct-view proofs: it verifies every
header/QC/parent/height/view edge and retains only the certified prefix through
the exact three-chain target in a private ancestry map. It also exposes a
cloneable, explicitly inert material derivation for the deterministic tag-50
typed ID, state key, outer version zero and canonical value bytes. The
derivation requires `materialized_at_height > candidate_height`; because it is
public data, it is not state-write or finality authority.

Registration of the tag and value grammar alone does not authorize state
creation. The bounded reference path now has an independent Order-state writer
which consumes the real non-Clone terminal execution owner, checks exact-parent
absence of the derived key, atomically creates the immutable tag-50 value, and
freshly proves the resulting sparse-tree membership. Its typed receipt plus a
separately verified later Order-finality carrier can issue the positive
execution-binding capability; a raw proof-side parser or caller-supplied root
still cannot. This reference writer is not yet the canonical Node-owned,
multi-object Order JMT transition and supplies no Node/process authority, so it
does not by itself close G2, activation, or production readiness.

## 7. Multi-resource usage and fees

`ResourceUsageV1` is the exact canonical record:

```text
resource_class              u16
resource_id                 Bytes
meter_id                    Bytes
meter_version               u32
amount                      u128
unit                        u16
measurement_commitment      Hash32
```

`measurement_commitment` binds the closed, acyclic
`UsageMeasurementSubjectV1`: `0 TransactionExecution {
transaction_id:AgentTransactionIdV1,transaction_index:u32,
evidence_root:Hash32 }` is legal only in the post-execution transaction
receipt; `1 ProviderExecution { task_id:TaskIdV1,lease_id:LeaseIdV1,
attempt:u32,receipt_sequence:u64,evidence_root:Hash32 }`; `2 ConsumptionPeriod
{ provider_id:AgentIdV1,consumer_id:AgentIdV1,task_id:TaskIdV1,
lease_id:LeaseIdV1,attempt:u32,sequence:u64,period_start_height:u64,
period_end_height:u64,evidence_root:Hash32 }`; or `3 RollupAggregate {
receipt_ids:List<ConsumptionReceiptIdV1> }`. Each usage location permits only
its matching variant. No operation body hashes an enclosing transaction,
receipt, or rollup ID that recursively depends on itself.

Resource classes are closed: `0 OrderedBytes`, `1 SignatureVerification`, `2
StateReadBytes`, `3 StateWriteBytes`, `4 StateObjectCreateDelete`, `5
TransactionDaByteEpoch`, `6 ArtifactDaByteEpoch`, `7 DeterministicComputeUnit`,
`8 DeterministicMemoryPeakByte`, `9 ProofVerificationUnit`, `10
ChallengeEvaluationUnit`, and `11 PriorityUnit`. Units are `0 Count`, `1 Byte`,
`2 ByteEpoch`, and `3 ComputeUnit`; each class uses respectively its only
natural unit (classes 0/2/3/8 Byte; 5/6 ByteEpoch; 7/9/10/11 ComputeUnit; 1/4
Count). Unknown or mismatched pairs fail closed.

`MeterDefinitionV1` is exactly `(meter_id:Bytes,meter_version:u32,
resource_class:u16,unit:u16,measurement_algorithm:u16,
algorithm_commitment:Hash32,active_from_epoch:u64,
inactive_after_epoch:Option<u64>)`; entries are strictly ordered/unique by
ID/version. `MeterRegistryV1 = (schema_version:u16=1,
entries:List<MeterDefinitionV1>)` hashes under
`trnm.poco-ai.meter-registry.v1`. Reference algorithm 0 counts canonical CEV1
bytes/items or deterministic executor counters selected by the class; its
measurement commitment is `DigestV1("trnm.poco-ai.resource-measurement.v1",
(subject:UsageMeasurementSubjectV1,resource_class,resource_id,meter_id,
meter_version,amount,unit))`. Aggregation is checked sum only over
identical ordered class/resource/meter/version/unit keys.

Usage lists are strictly increasing by `(resource_class, resource_id,
meter_id, meter_version)`, duplicate-free, and use checked aggregation. The
closed reference resource classes cover:

- ordered canonical bytes and signature verification;
- state reads, bytes read, writes, bytes written, objects created/deleted;
- transaction-batch DA bytes and retention;
- artifact/evidence DA bytes and retention;
- deterministic compute units and memory peak class;
- proof/attestation verification by profile;
- challenge/evaluation work; and
- priority or congestion class.

The context-free, epoch-committed `FeeScheduleV1` has exact fields:

```text
schema_version              u16                 // 1
protocol_version            u32                 // 1
schedule_name               Bytes
schedule_revision           u32
settlement_asset_id         Hash32
resource_prices             List<ResourcePriceV1>
congestion_policy_hash      Hash32
operation_floor_caps        List<OperationFloorCapEntryV1>
operation_floor_cap_root    Hash32
refund_policy_hash          Hash32
rounding_policy             u16
remainder_destination       TypedObjectIdV1
destination_splits          List<DestinationSplitEntryV1>
destination_split_root      Hash32
```

`ResourcePriceV1` binds the exact resource class/id/unit, integer price
numerator/denominator, minimum, maximum, and congestion-multiplier cap. Its
exact field order is:

```text
resource_class                       u16
resource_id                          Bytes
unit                                 u16
base_price_numerator                 u128
base_price_denominator               u128
minimum_charge                       u128
maximum_charge                       u128
congestion_multiplier_cap_numerator u128
congestion_multiplier_cap_denominator u128
```

Prices are strictly increasing by `(resource_class, resource_id, unit)` and
duplicate-free. Both denominators are positive, `minimum_charge <=
maximum_charge`, and the congestion cap fraction is at least one. Every
multiply/add uses checked `u128`. The reference schedule accepts only
`rounding_policy = 0`, meaning nonnegative rational charges use exact ceiling
division: `q = numerator / denominator`, then checked `q + 1` iff the remainder
is nonzero. Congestion multiplication is applied and capped before the
operation min/max clamp; each intermediate rational is reduced only as an
optimization and never changes the specified result. Unknown resource
classes/units, zero denominators, overflow, or a differently rounded value are
invalid. Destination-split and floor/cap roots must resolve to their exact
profile-bounded typed records before fee execution.

`OperationFloorCapEntryV1` is exactly `(operation_kind:u16,
minimum_charge:u128,maximum_charge:u128)`, one strictly ordered entry per enabled
operation; its root is `DigestV1("trnm.poco-ai.operation-floor-cap-root.v1",
List<OperationFloorCapEntryV1>)`. `DestinationSplitEntryV1` is exactly
`(destination_kind:u16,destination_id:TypedObjectIdV1,
asset_id:Hash32,numerator:u128,denominator:u128)`;
entries are strictly ordered/unique, denominators positive, and their rational
sum is exactly one. Its root is `DigestV1(
"trnm.poco-ai.destination-split-root.v1",List<DestinationSplitEntryV1>)`.
Both complete inline lists are hashed into the epoch fee-schedule definition,
and each adjacent root MUST recompute from its corresponding list; a bare
unresolved root or mismatched list/root cannot execute fees.
Destination kind is closed: `0 Treasury` requires tag46 ValuePool and reason 2,
`1 Burn` requires tag46 ValuePool and reason 3, `2 ValidatorReward` requires
tag45 Account and reason 0, and `3 RemainderPool` requires tag46 ValuePool and
reason 7. Every asset equals `settlement_asset_id`; the remainder destination
must equal the unique kind-3 entry. Tag/kind/reason/asset mismatch is invalid.

The
content digest is `fee_schedule_hash`; the body does not contain its own hash.
It is exactly `DigestV1("trnm.poco-ai.fee-schedule.v1", FeeScheduleV1)`.
The schedule defines base prices, congestion functions, per-operation
floors/caps, refund rules, rounding, and destination splits.
Arithmetic is checked integer/fixed-point only. Fee payer authorization and
maximum fee are validated before execution.

AI compute/provider payment is a market settlement and remains separate from
protocol execution fees, DA/storage payment, validator reward, challenge bond,
and slash proceeds. Marketing must not merge these into one ambiguous
“transaction cost”.

Fee accounting uses per-transaction deltas and block-end aggregation. The
executor does not write one global fee-collector object for every transaction.
Canonical block-end reduction credits explicit treasury, burn, validator,
storage, proof-verifier, and other destinations once per destination in sorted
order.

## 8. Conservation and invariants

For every transaction, rollup, challenge, and settlement, checked arithmetic
must prove:

```text
inputs + minted_by_explicit_rule
= outputs + refunds + burns + fees + bonds_held + rewards + slashes_held
```

Escrow cannot be double released; bonds cannot simultaneously refund and pay a
slash; a receipt cannot be paid twice; a rollup entry cannot affect two
settlements or two PoCO snapshots; and rounding remainder destinations are
explicit. Supply changes require a separately authorized deterministic rule.

Block execution additionally preserves unique object IDs, monotonic object
versions, nonce-lane monotonicity, canonical event/receipt order, authenticated
root equality, and exact finalization replay. Exact replay of a finalized block
is idempotent; a different body under one block ID fails closed.

## 9. Resource failures and backpressure

Consensus-visible transaction/block limits are epoch committed. Admission
queues, MVCC workers, speculative versions, retry count, proof work, event
bytes, state delta, and result buffers have hard bounds. A transaction that
exceeds its declared deterministic limit receives `OutOfResource`; a validator
whose local resources are temporarily insufficient reports `Unavailable` and
does not vote. Local pressure cannot change canonical fees or outcomes.

## 10. Required evidence before freeze

Freeze requires canonical positive/negative vectors for transactions, batches,
receipts, rollups, settlements, usage, and fees; differential execution across
at least two implementations/schedulers; retained stale-read, undeclared-write,
single-nonce, global-fee-hotspot, receipt-without-status, rollup-reuse,
double-settlement, and broken-conservation mutants; randomized high-conflict
MVCC tests; crash/replay/finalization tests; and a formal serial-equivalence and
value-conservation model. None is complete for v1 today.
