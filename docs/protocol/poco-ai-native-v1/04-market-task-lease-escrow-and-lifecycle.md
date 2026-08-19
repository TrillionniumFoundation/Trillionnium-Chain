# 04 — Market, task, lease, escrow, and lifecycle

Status: **DRAFT / design-only / not implemented / not activated**

## 1. Purpose

PoCO-Market turns an AI work request into explicit, versioned obligations. Task
ordering and escrow transitions are deterministic chain state. Model execution,
artifact production, and external service calls remain off-chain.

All deadlines in this document are block heights. Wall-clock estimates may be
displayed to users but cannot determine consensus validity.

## 2. Task offer and identity

`TaskOfferBodyV1` has this logical field order:

```text
schema_version                u16  // 1
genesis_hash                  Hash32
chain_id                      ConsensusString
protocol_version              u32  // 1
stack_profile_hash            Hash32
requester_agent_id            AgentIdV1
requester_key_id              AgentKeyIdV1
requester_capability_id       Option<CapabilityIdV1>
requester_session_generation  u64
request_nonce_lane            u16
request_nonce                 u64
task_kind                     Bytes
task_spec_commitment          Hash32
input_artifacts               List<ArtifactIdV1>
model_scope_commitment        Hash32
tool_scope_commitment         Hash32
verification_profile_id       Bytes
verification_profile_version  u32
verification_profile_hash     Hash32
privacy_lane                  u8
provider_policy_hash          Hash32
resource_limit_hash           Hash32
pricing_policy_hash           Hash32
escrow_terms_hash             Hash32
checkpoint_policy_hash        Hash32
migration_policy_hash         Hash32
challenge_policy_hash         Hash32
offer_expiry_height           u64
start_deadline_height         u64
result_deadline_height        u64
settlement_deadline_height    u64
requester_metadata_commitment Hash32
```

`EscrowTermsV1` is the exact context-free value `(schema_version:u16=1,
asset_id:Hash32,funded_amount:u128,provider_payment_cap:u128,
order_fee_reserve:u128,transaction_da_fee_reserve:u128,
artifact_da_fee_reserve:u128,verification_fee_reserve:u128,
challenge_reserve:u128,refund_beneficiary:AgentIdV1,
settlement_policy_hash:Hash32)`. Its digest under
`trnm.poco-ai.escrow-terms.v1` MUST equal `escrow_terms_hash`.
`TaskCreationOperationBodyV1` is exactly `(task_offer_body:TaskOfferBodyV1,
escrow_terms:EscrowTermsV1,funding_account_id:AccountIdV1,
expected_funding_account_version:u64,escrow_nonce:Hash32)`. Kind 4 carries this
complete value. Execution first recomputes terms hash and task ID, then uniquely
constructs the `EscrowBodyV1` from task/requester/terms/nonce, debits/reserves
the exact typed funding account, and creates Task/Escrow states atomically.
The declared access list includes the funding-account Write and both Creates;
hash-only terms cannot fund or create an escrow.

The four deadlines are nondecreasing and every referenced artifact required at
task creation has the DA status required by the active profile. `privacy_lane`
is `0 public`, `1 sealed-envelope`, or another value explicitly enumerated by
the stack profile. A privacy-lane label is not evidence that the input is
confidential.

The three consecutive verification-profile fields are the exact inline
`VerificationProfileRefV1`. Requester agent, key sentinel-or-key, capability,
session generation, lane, and nonce MUST equal the operation-kind `4`
`AuthorizationStatementV1` and the five-component nonce namespace in document
03. The statement additionally binds the live capability generation and exact
session-key grant when session authorization is used.

```text
task_id = DigestV1(
  "trnm.poco-ai.task.v1",
  TaskOfferBodyV1
)
```

`TaskOfferV1` is the exact body, recomputed `TaskIdV1`, and the unique creating
`AgentTransactionIdV1`. Its operation-kind `4` transaction authorization uses
`trnm.poco-ai.task-offer-signature.v1`; authorization bytes are not copied into
the admitted task. Mutable revision,
attempt, and lifecycle fields live in `TaskStateV1` keyed by `TaskIdV1`; they do
not change `task_id`.

Creation verifies PoCO-Agent authorization, exact nonce, profile/registry
activation, scopes, deadlines, artifact commitments, and escrow funding in one
atomic transition. The initial task has `task_revision = 0`, `attempt = 0`, and
state `Open`. A body cannot be amended in place. Mutable choices are represented
by explicitly versioned task revisions whose predecessor is the current task
revision and whose change kind is permitted by the creation profile.

## 3. Task state

`TaskStatusV1` is:

```text
0  Open
1  Leased
2  Running
3  Paused
4  Migrating
5  ResultSubmitted
6  Verifying
7  SettlementPending
8  Settled          // terminal
9  Cancelled        // terminal
10 Refunded         // terminal
11 Expired          // terminal
12 Failed           // terminal
```

Every transition consumes the exact current `(task_id, task_revision, attempt,
state)` and increments `task_revision` by one. A state name alone is never
sufficient replay protection.

Allowed transitions are:

```text
Open -> Leased | Cancelled | Expired
Leased -> Running | Cancelled | Expired | Failed
Running -> Paused | Migrating | ResultSubmitted | Cancelled | Failed
Paused -> Running | Migrating | Cancelled | Expired | Failed
Migrating -> Leased | Refunded | Expired | Failed
ResultSubmitted -> Verifying
Verifying -> SettlementPending | Migrating | Refunded | Failed
SettlementPending -> Settled | Refunded | Failed
```

`Migrating -> Leased` installs a new lease, increments `attempt`, and binds the
new lease to an accepted checkpoint from the prior attempt. A failed or
challenged result never moves backward to `Running`; retry is a new attempt via
`Migrating`. Terminal tasks have no outgoing transition.

The authenticated mutable value is `TaskStateV1 = (schema_version:u16=1,
context:ProtocolContextV1, task_id:TaskIdV1, revision:u64, attempt:u32,
status:TaskStatusV1, active_lease_id:Option<LeaseIdV1>,
latest_checkpoint_id:Option<CheckpointIdV1>, active_result_id:
Option<ResultIdV1>, escrow_id:EscrowIdV1,
active_deadline_kind:u8,active_deadline_height:u64)`. Deadline kind is `0 Offer`,
`1 Start`, `2 Result`, `3 Resume`, `4 MigrationBid`, or `5 Settlement`.
Creation sets revision/attempt `0`, status `Open`, no lease/checkpoint/result,
and exact Offer deadline. Leased selects Start; Running selects Result; Paused
selects the operation's resume deadline; Migrating selects its bid deadline;
ResultSubmitted/Verifying/SettlementPending select Settlement. Terminal states
retain the last pair but no timeout is enabled. Every listed
transition consumes this complete prior value, increments revision once, and
updates all presence fields according to status.

## 4. Bid

`BidBodyV1` contains:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
task_id                     TaskIdV1
task_revision               u64
provider_agent_id           AgentIdV1
provider_key_id             AgentKeyIdV1
provider_capability_id      Option<CapabilityIdV1>
provider_session_generation u64
provider_nonce_lane         u16
provider_nonce              u64
price_asset_id              Hash32
maximum_price               u128
pricing_terms_hash          Hash32
resource_offer_hash         Hash32
execution_environment_hash  Hash32
provider_bond_id            BondIdV1
checkpoint_terms_hash       Hash32
availability_terms_hash     Hash32
bid_expiry_height           u64
provider_metadata_commitment Hash32
```

```text
bid_id = DigestV1("trnm.poco-ai.bid.v1", BidBodyV1)
```

`BidV1` is the body, recomputed `BidIdV1`, and the unique creating
`AgentTransactionIdV1`. Its operation-kind `5` transaction authorization uses
`trnm.poco-ai.bid-signature.v1`. Bid admission state
is keyed by `BidIdV1`. The provider authorization fields MUST equal the exact
five-component nonce namespace and `AuthorizationStatementV1`;
`capability_generation` is a separately validated live generation in the
statement and is not an alias for `session_generation`.

A bid is valid only for the exact open task revision, permitted provider/model/
tool/resource scope, active provider capability, sufficient provider bond, and
compatible verification/DA/checkpoint policy. The provider signs the exact bid.
Bid submission does not reserve requester escrow or create a lease. Bid expiry
or task-revision change makes an unaccepted bid unusable; it is never silently
retargeted.

`BidStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,bid_id:BidIdV1,state_version:u64,status:u8,
accepted_lease_id:Option<LeaseIdV1>,accepted_height:Option<u64>,
terminal_height:Option<u64>)`. Status is `0 Active`, `1 Consumed`, `2 Expired`,
or `3 Invalidated`; the latter two tags are reserved and MUST NOT appear in
committed reference-v1 state. Creation is version zero/Active with all optional
fields absent. Lease creation declares and consumes this exact version
atomically, changes it once to Consumed, and fills the unique lease/current
height. After expiry or a task-revision mismatch, Active remains stored but is
deterministically ineligible; there is no optional materialization write.
Acceptance always rechecks height and exact task revision. Consumed is
one-shot; no second lease can consume the bid.

## 5. Lease

`TaskLeaseBodyV1` contains:

```text
schema_version               u16  // 1
genesis_hash                 Hash32
chain_id                     ConsensusString
protocol_version             u32  // 1
stack_profile_hash           Hash32
task_id                      TaskIdV1
base_task_revision           u64
attempt                      u32
accepted_bid_id              BidIdV1
requester_agent_id           AgentIdV1
provider_agent_id            AgentIdV1
escrow_id                    EscrowIdV1
provider_bond_id             BondIdV1
resume_checkpoint_id         Option<CheckpointIdV1>
execution_environment_hash   Hash32
verification_profile_id      Bytes
verification_profile_version u32
verification_profile_hash    Hash32
pricing_terms_hash           Hash32
checkpoint_terms_hash        Hash32
availability_terms_hash      Hash32
start_deadline_height        u64
checkpoint_deadline_height   u64
result_deadline_height       u64
lease_nonce                  Hash32
```

```text
lease_id = DigestV1("trnm.poco-ai.lease.v1", TaskLeaseBodyV1)
```

The three consecutive verification-profile fields are the exact inline
`VerificationProfileRefV1` and MUST equal the active task reference. A hash-only
or ID/version-only lease is invalid. `TaskLeaseV1` is the body, recomputed
`LeaseIdV1`, and the requester operation-kind `6` transaction ID that accepts
the exact bid under
`trnm.poco-ai.lease-requester-acceptance-signature.v1`. The provider's later
acceptance is a distinct operation-kind `7` transaction binding the same lease
ID under
`trnm.poco-ai.lease-provider-acceptance-signature.v1`; mutable lease status is
`TaskLeaseStateV1` keyed by `LeaseIdV1`. Neither side may reuse the other's
authorization domain or nonce namespace.

Lease creation is one atomic transition that consumes the exact active bid,
reserves the maximum authorized requester escrow and provider bond, changes the
task from `Open` or `Migrating` to `Leased`, and creates lease status `Offered`.
The provider's acceptance changes the lease to `Active` but leaves the task
`Leased`. It reserves the provider obligation; it is not the start
acknowledgement and does not prove input availability.

Lease status is `0 Offered`, `1 Active`, `2 Completed`, `3 Cancelled`,
`4 Defaulted`, or `5 Superseded`. Only one lease may be Offered or Active for a
task attempt. A migration terminalizes the prior lease before a successor is
installed. Provider signatures, result receipts, checkpoints, and meter records
for one lease/attempt cannot be replayed into another.

`LeaseStatusV1` is that six-value enum. `TaskLeaseStateV1` is exactly
`(schema_version:u16=1, context:ProtocolContextV1, lease_id:LeaseIdV1,
revision:u64, attempt:u32, status:LeaseStatusV1,
accepted_height:Option<u64>, started_height:Option<u64>,
terminal_height:Option<u64>, latest_checkpoint_id:Option<CheckpointIdV1>)`.
Creation is revision `0`/Offered with optional
fields absent; acceptance, start, checkpoint, completion/cancel/default/
supersede consume exact revision and set the unique chain-assigned fields.

Protocol v1 has no redundant-compute exception inside one task attempt. A task
or profile that would authorize two concurrent `Offered`/`Active` leases for the
same `(task_id, attempt)` is invalid. Redundancy must be represented as separate
task IDs or later attempts whose predecessor transition terminalized the prior
lease; it cannot share one attempt, receipt slot, or escrow reservation.

## 6. Escrow

`EscrowBodyV1` contains:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
task_id                     TaskIdV1
requester_agent_id          AgentIdV1
asset_id                    Hash32
funded_amount               u128
provider_payment_cap        u128
order_fee_reserve           u128
transaction_da_fee_reserve  u128
artifact_da_fee_reserve     u128
verification_fee_reserve    u128
challenge_reserve           u128
refund_beneficiary          AgentIdV1
settlement_policy_hash      Hash32
escrow_nonce                Hash32
```

```text
escrow_id = DigestV1("trnm.poco-ai.escrow.v1", EscrowBodyV1)
```

`EscrowV1` is the immutable terms body and recomputed `EscrowIdV1` created by
the authorized task transition. Balances and reservations are
`EscrowStateV1`; they mutate only through conserved state transitions and are
not part of `escrow_id`.

`EscrowStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, escrow_id:EscrowIdV1, version:u64,
available:u128,reserved:u128,disbursed:u128,refunded:u128,forfeited:u128,
active_reservations:List<EscrowReservationEntryV1>,
active_reservation_root:Hash32,last_settlement_id:Option<SettlementIdV1>,
closed:bool)`. Creation sets version zero, `available = funded_amount`, every
other amount zero, the canonical empty reservation root, no settlement, and
`closed=false`. Every mutation consumes exact version, increments once, and
recomputes the equation below; closure is terminal except exact replay.

`EscrowReservationEntryV1` is exactly `(reservation_kind:u16,
source_object_id:TypedObjectIdV1,asset_id:Hash32,amount:u128,
created_height:u64,release_condition_hash:Hash32)`, strictly ordered/unique by
`(reservation_kind,source_object_id kind/id)`. The root is `DigestV1(
"trnm.poco-ai.escrow-active-reservations-root.v1",
List<EscrowReservationEntryV1>)`; `reserved` is the checked amount sum. Empty
uses the canonical empty list. Every reserve/release atomically changes the
inline list, root, amount fields, and version.

At all times, its accounting satisfies:

```text
funded_amount = available + reserved + disbursed + refunded + forfeited
```

Every term is a checked `u128` amount in the same canonical asset. Transfers
between terms are atomic and journaled by reason plus the exact task, lease,
result, challenge, DA or fee object that authorized them. No hash reference to
a payment creates funds. Provider bond accounting is separate from requester
escrow and has its own conservation invariant.

Escrow release requires the exact result and settlement conditions in documents
05 and 08. Order finality of a receipt alone does not release provider payment.
Unused reserve is returned only by a terminal transition. Fees for service
already durably provided MAY remain charged after cancellation if the creation
policy explicitly defines that allocation.

### 6.1 Exact lifecycle operation bodies

The required operation-kind `14..20` bodies are:

```text
TaskStartOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:LeaseIdV1, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:u64,
   input_artifact_root:Hash32, execution_environment_hash:Hash32,
   start_nonce:Hash32)

TaskPauseOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:LeaseIdV1, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:u64,
   latest_checkpoint_id:Option<CheckpointIdV1>,
   resume_deadline_height:u64, settlement_policy_hash:Hash32,
   reason_code:u16)

TaskResumeOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:LeaseIdV1, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:u64,
   checkpoint_id:CheckpointIdV1, execution_environment_hash:Hash32,
   resume_nonce:Hash32)

TaskCancelOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:Option<LeaseIdV1>, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:Option<u64>,
   expected_task_status:TaskStatusV1,
   latest_checkpoint_id:Option<CheckpointIdV1>,
   settlement_policy_hash:Hash32, reason_code:u16)

TaskTimeoutOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:Option<LeaseIdV1>, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:Option<u64>,
   expected_task_status:TaskStatusV1,
   committed_deadline_height:u64, timeout_kind:u16)

TaskMigrationOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, lease_id:LeaseIdV1, attempt:u32,
   expected_task_revision:u64, expected_lease_revision:u64,
   reason_code:u16, latest_checkpoint_id:CheckpointIdV1,
   successor_environment_hash:Hash32, bid_deadline_height:u64,
   migration_policy_hash:Hash32)

TaskRevisionOperationBodyV1 =
  (schema_version:u16=1, context:ProtocolContextV1,
   task_id:TaskIdV1, expected_task_revision:u64,
   expected_status:TaskStatusV1, revision_kind:u16,
   successor_terms:TaskNarrowingTermsV1,
   revision_nonce:Hash32)
```

`InputArtifactRefV1` is exactly `(artifact_id:ArtifactIdV1,
required_da_policy_hash:Hash32)`, and the start input root is
`DigestV1("trnm.poco-ai.task-input-artifacts-root.v1",
List<InputArtifactRefV1>)` over the task body's complete strictly ordered
artifact list paired with its required DA policy. It cannot omit/reorder an
artifact or substitute a provider-selected set. Every pause/cancel
`settlement_policy_hash` MUST equal the immutable escrow body's exact field;
there is no separate allocation-policy authority.

`TaskNarrowingTermsV1` is exactly `(task_spec_commitment:Hash32,
input_artifacts:List<ArtifactIdV1>,model_scope_commitment:Hash32,
tool_scope_commitment:Hash32,resource_limit_hash:Hash32,
maximum_provider_payment:u128,offer_expiry_height:u64,
start_deadline_height:u64,result_deadline_height:u64,
settlement_deadline_height:u64)`. The successor list must be a set-subset of
the current task list, every scope/resource predicate must verify as a subset
under its frozen policy, payment cannot increase, and each deadline is no
later than its predecessor while remaining nondecreasing internally and above
current height. The task revision stores the exact successor terms and
`DigestV1("trnm.poco-ai.task-narrowing-terms.v1",TaskNarrowingTermsV1)`;
there is no caller-supplied opaque successor hash.

Start/resume require the active provider; pause/cancel/migration require the
single role permitted by the task's frozen policy. Timeout is permissionless
but requires `current_height > committed_deadline_height`, exact equality to
authenticated `active_deadline_height`, and `timeout_kind` equal the exact
`active_deadline_kind`; no other kind/height can trigger that state.
Operation kind 20 and every `revision_kind` are disabled in reference v1 until
an exact mutable-terms state and subset proof are frozen. The
`TaskNarrowingTermsV1` grammar above is a future design candidate, not an
accepted carrier. Changes use cancel/migrate/new task/attempt. All enabled bodies
consume exact revisions, validate their declared read/write sets, use chain
height rather than local time, and update Task/Lease/Escrow state atomically.

## 7. Start and progress

The provider starts a lease by signing an exact start acknowledgement containing
`task_id`, `lease_id`, `attempt`, input-artifact commitments, environment hash,
and current task revision. The transition verifies all required inputs are
available under the selected profiles and changes `Leased -> Running`.
This is the sole `Leased -> Running` transition. It requires lease status
`Active`; a provider cannot bypass input/environment checks by accepting the
lease alone.

Progress reports are informative unless a checkpoint is created. They cannot
extend a deadline, increase price, release escrow, or establish result validity.
Reference-v1 deadline changes are limited to the exact pre-lease requester
narrowing rule above. After lease creation, deadlines are immutable; parties
use cancel, timeout, migration, or a new attempt instead of an ambiguous
multi-party revision.

## 8. Compute checkpoint

`ComputeCheckpointBodyV1` contains:

```text
schema_version               u16  // 1
genesis_hash                 Hash32
chain_id                     ConsensusString
protocol_version             u32  // 1
stack_profile_hash           Hash32
task_id                      TaskIdV1
lease_id                     LeaseIdV1
attempt                      u32
checkpoint_sequence          u64
previous_checkpoint_id       Option<CheckpointIdV1>
execution_environment_hash   Hash32
input_commitment             Hash32
state_artifact_id            ArtifactIdV1
state_commitment             Hash32
progress_commitment          Hash32
meter_root                   Hash32
resume_compatibility_hash    Hash32
availability_certificate_id  AvailabilityCertificateIdV1
```

```text
checkpoint_id = DigestV1(
  "trnm.poco-ai.compute-checkpoint.v1",
  ComputeCheckpointBodyV1
)
```

`ComputeCheckpointV1` is the exact body, recomputed `CheckpointIdV1`, and the
provider operation-kind `8` transaction ID whose statement binds that exact
transaction under
`trnm.poco-ai.compute-checkpoint-signature.v1`. Signing the checkpoint ID alone
is not authorization. Sequence
starts at zero per lease/attempt
and is exact and gap-free. A successor binds its immediate predecessor. The
state artifact must have a compatible, unexpired availability certificate
before checkpoint acceptance.

`created_height` is not a submitter-controlled field and is not part of
`ComputeCheckpointBodyV1`, `checkpoint_id`, or the provider signature. On
successful execution the chain sets `accepted_height = current_height` in
`ComputeCheckpointStateV1`. Retries before acceptance retain the same ID; exact
replay after acceptance is idempotent and cannot assign a second height.

`ComputeCheckpointStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,checkpoint_id:CheckpointIdV1,state_version:u64,
accepted_height:u64,status:u8,retention_hold_until_height:u64)`. Status is `0
Active`, `1 Superseded`, or `2 Released`. Creation is version zero/Active at the
chain-assigned height with the policy-derived hold. A successor checkpoint may
atomically mark only its immediate predecessor Superseded; release is permitted
only after all task/migration/challenge/evidence holds close. Each transition
increments once and terminal Released has no outgoing transition.

A checkpoint proves only that the provider signed these commitments and that
the named artifact met its DA contract. It does not prove correct progress,
correct execution, resumability on another provider, or result validity. Those
claims require the task's verification/checkpoint policies.

## 9. Pause, cancellation, expiry, and timeout

A requester-authorized pause moves `Running -> Paused` only when the task policy
allows it and names the latest accepted checkpoint, a resume deadline, and the
fee allocation. Resume requires the same active lease, exact checkpoint, and
compatible environment unless it proceeds through migration.

Cancellation is deterministic:

- `Open -> Cancelled` returns all funds except explicitly earned order/DA fees;
- cancellation of `Leased`, `Running`, or `Paused` requires the policy-defined
  party authorization or timeout condition, exact latest checkpoint handling,
  and an atomic allocation of work payment, fees, refund, and bond consequence;
- a result already in `ResultSubmitted`, `Verifying`, or `SettlementPending`
  follows result/challenge rules rather than being erased by cancellation; and
- cancellation never deletes artifacts, receipts, authority records, or
  evidence whose retention window remains open.

After a committed deadline, any submitter MAY trigger its exact timeout
transition. The transition consumes current state and deadline; it cannot use a
local clock or operator discretion. Depending on the frozen policy it
terminalizes as `Expired`/`Failed`, or enters `Migrating`, and atomically applies
refund, earned fee, provider payment, and bond consequences.

## 10. Migration and resume

A migration request binds task/lease/attempt/revision, reason code, latest
accepted checkpoint, required successor environment, bid deadline, and
migration fee/bond policy. It changes `Running` or `Paused` to `Migrating` and
terminalizes the prior lease as `Superseded` or `Defaulted`.

The successor bid and lease must bind the exact checkpoint and
`resume_compatibility_hash`. Acceptance increments `attempt`, installs only one
new lease, and changes `Migrating -> Leased`. No provider may submit a valid
receipt under the old lease after terminalization. A successor provider that
cannot retrieve or validate the checkpoint remains unable to start; missing
data is not fabricated progress.

Migration does not transfer a provider's private execution state by inference,
does not prove environment equivalence, and does not waive verification of the
eventual result.

## 11. Result and settlement handoff

Only an Active lease in `Running` may submit an `ExecutionReceiptV1` for the
exact task/lease/attempt. Acceptance changes `Running -> ResultSubmitted` and
then `ResultSubmitted -> Verifying` as the result object is created. The receipt
and result lifecycle are defined in document 05.

Only `ResultStatusV1::FinalValid` or `ResultStatusV1::FinalInvalid` from
document 05 establishes result finality and moves the task from
`Verifying -> SettlementPending` with the exact pay/refund/slash disposition.
At this task boundary the ResultState maturity remains `NotStarted`;
`SettlementMaturityV1::Pending` is only an execution-internal candidate
discriminant while atomic kind 26 derives and applies settlement and is never a
committed reference-v1 state. This does not itself prove payment or settlement
finality.
`ResultStatusV1::Inconclusive` is terminal only for that result and follows the
frozen task policy to `Migrating`, `Refunded`, or `Failed`; it is never relabelled
valid. Document 08 performs the exact conserved allocation and moves a
settlement-pending task to `Settled`, `Refunded`, or `Failed`. No market
transition treats an order-finalized but non-final result as settlement-final.
Only order finality of its exact settlement receipt changes the proof/API pair
to `SettlementMaturityV1::Final`.

## 12. Required invariants and vectors

Conformance MUST cover:

- exact task/revision/attempt/lease binding and terminal-state rejection;
- at most one Offered-or-Active lease per attempt, rejection of every
  redundant-compute exception, and atomic bid consumption;
- escrow and provider-bond conservation under every normal, cancellation,
  timeout, failure, migration, challenge, and settlement path;
- deadlines at boundary and boundary-plus-one heights;
- checkpoint sequence/ancestry, wrong-lease replay, missing DA, and incompatible
  resume rejection;
- migration terminalizing the old lease before successor installation;
- crash/idempotent recovery at every reservation, lease, checkpoint, timeout,
  migration, result handoff, and escrow-allocation boundary; and
- no state transition, hash receipt, or DA certificate independently implying
  AI correctness or payment maturity.
