# 03 — Agent identity, capabilities, and nonce lanes

Status: **DRAFT / design-only / not implemented / not activated**

## 1. Purpose

PoCO-Agent makes delegated machine activity explicit and bounded. An agent can
use independently revocable session keys and parallel nonce lanes without
granting an unbounded root-key authority or serializing every operation through
one global account nonce.

Agent identity is not proof of a unique human, independent organization,
trustworthiness, legal authority, or Sybil resistance. Those are separate
policy and verification questions.

## 2. Agent identity

`AgentIdentityBodyV1` has this logical field order:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
creator_agent_id            Option<AgentIdV1>
creator_key_id              Option<AgentKeyIdV1>
creation_nonce              Hash32
agent_class                 u8
initial_controller_seed_hash Hash32
recovery_policy_seed_hash   Hash32
metadata_commitment         Hash32
```

`agent_class` is `0 individual`, `1 organization`, `2 autonomous-service`, or
`3 protocol-system`. The class is descriptive policy input and grants no
authority by itself. `creation_nonce` is caller-selected, unique within the
creator identity, and cannot be reused with another body. A protocol-system
agent may be created only by genesis or an explicitly versioned governance
transition.

```text
agent_id = DigestV1(
  "trnm.poco-ai.agent.v1",
  AgentIdentityBodyV1
)
```

`AgentIdentityCreationOperationBodyV1` is exactly `(identity_body:
AgentIdentityBodyV1,controller_seed_policy:ControllerSeedPolicyV1,
recovery_seed_policy:RecoverySeedPolicyV1)`. Kind 0 carries this complete body;
the two inline policies MUST recompute the two seed hashes before `agent_id` or
any signature is accepted. `AgentIdentityAuthorizationV1` is the closed union
`0 Transaction { transaction_id:AgentTransactionIdV1,
authorization_set:AuthorizationSetV1 }` or `1 GenesisMaterialized {
system_agent_seed_index:u32,genesis_bootstrap_manifest_hash:Hash32 }`.
`AgentIdentityV1` is exactly `(body:AgentIdentityBodyV1,
agent_id:AgentIdV1,authorization:AgentIdentityAuthorizationV1)`.
Existing-agent creation uses operation
kind `0` in an `AgentTransactionV1`; its `AuthorizationSetV1` binds the exact
transaction ID under
`trnm.poco-ai.agent-identity-signature.v1`; signatures are not part of
`agent_id`. The genesis branch is legal only inside the deterministic genesis
materializer: creator fields are absent, `agent_class=3`, its seed index and
manifest hash identify the ordered `SystemAgentSeedEntryV1`, and the body
policy hashes/metadata/nonce are its unique projection. That branch is
forbidden in transactions and after genesis.

The two seed hashes commit exact context-free policy values. A
`SeedKeyEntryV1` is:

```text
key_scheme                  u8
public_key                  Bytes
weight                      u64
valid_from_height           u64
expires_after_height        u64
```

`ControllerSeedPolicyV1` is:

```text
schema_version              u16  // 1
keys                        List<SeedKeyEntryV1>
threshold                   u64
```

`RecoverySeedPolicyV1` is:

```text
schema_version              u16  // 1
keys                        List<SeedKeyEntryV1>
threshold                   u64
recovery_delay_blocks       u64
allowed_recovery_actions    List<u16>
```

The key list is nonempty, strictly increasing by
`(key_scheme, raw public_key bytes)`, and duplicate-free. Every weight is
positive, checked, and the threshold is in `1..=total_weight`. Heights are
inclusive and ordered. Recovery actions are strictly increasing and
duplicate-free.

```text
initial_controller_seed_hash = DigestV1(
  "trnm.poco-ai.controller-seed-policy.v1",
  ControllerSeedPolicyV1
)
recovery_policy_seed_hash = DigestV1(
  "trnm.poco-ai.recovery-seed-policy.v1",
  RecoverySeedPolicyV1
)
```

The seed values MUST NOT contain `agent_id`, `AgentKeyIdV1`, or another value
derived from this identity. After `agent_id` is derived, key sequence is the
zero-based canonical position within its role. `SeedKeyRegistrationV1` is the
exact record `(agent_id: AgentIdV1, key_role: u8, key_sequence: u32,
seed_key_entry_hash: Hash32)`, where `seed_key_entry_hash` is
`DigestV1("trnm.poco-ai.seed-key-entry.v1", SeedKeyEntryV1)`. The materializer
sets `registration_nonce = DigestV1(
"trnm.poco-ai.seed-key-registration-nonce.v1", SeedKeyRegistrationV1)`, constructs each
`AgentKeyBodyV1`, then verifies that the resulting controller/recovery policy
projects back to the two seed hashes. No implementation-chosen key order or
nonce is permitted.

Creation by an existing agent requires its controller `AuthorizationSetV1`
over the exact enclosing `AgentTransactionIdV1`; deterministic execution of
that transaction derives and admits the exact `AgentIdV1`. Self-origin
creation uses the separate
non-circular `SeedIdentityAuthorizationStatementV1 = (schema_version: u16,
context: ProtocolContextV1, transaction_id:AgentTransactionIdV1,
agent_id: AgentIdV1,
initial_controller_seed_hash: Hash32, valid_after_height: u64,
expires_after_height: u64)`. The threshold of raw initial controller keys named
by the exact inline seed policy signs `DigestV1(
"trnm.poco-ai.agent-self-origin-signature.v1",
SeedIdentityAuthorizationStatementV1)`; key entries use the seed-policy order
and the same strict signature rules as document 02.
`SeedIdentitySignatureEntryV1` is exactly `(seed_key_index:u32,
signature_scheme:u16, signature:Bytes)`; the index resolves the exact key,
scheme, and weight from `ControllerSeedPolicyV1` and cannot substitute raw key
bytes. `SeedIdentityAuthorizationV1` is exactly `(statement:
SeedIdentityAuthorizationStatementV1,
entries:List<SeedIdentitySignatureEntryV1>)`. Entries are strictly increasing
and unique by index; every signature verifies the one statement under the
self-origin domain, and checked unique weight reaches the exact seed threshold.
Statement transaction/context/agent/seed/validity fields MUST equal the outer
transaction and identity body; the execution height lies in every selected key
and statement interval. It is subject to
deterministic admission/bond policy and cannot authorize any other operation.
The created state stores `agent_id`, the body, `identity_revision = 0`, active
controller and recovery policies, and status `Active`.

Agent status is:

```text
0 Active
1 Suspended
2 Retired
```

Suspension blocks new authorizations but does not erase already
order-finalized obligations. Retirement is terminal, blocks every new key,
capability, task, bid, receipt, or challenge, and can occur only when the active
profile's liability/retention conditions are satisfied.

`AgentIdentityStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, agent_id:AgentIdV1, identity_revision:u64,
status:u8, controller_policy:ControllerPolicyV1,
controller_policy_hash:Hash32,recovery_policy:RecoveryPolicyV1,
recovery_policy_hash:Hash32,
last_transition_height:u64)`. Creation is revision
zero/Active with materialized seed-policy hashes and its chain-assigned height.
Both inline policies MUST recompute their adjacent hashes; rotation atomically
replaces the complete policy and hash, so a snapshot verifier has the current
key/weight threshold preimage without historical lookup.
Suspension requires Active; reactivation requires Suspended and exact authority;
retirement requires closed liabilities and is terminal. Every transition
increments revision once.

## 3. Keys and controller policy

The immutable preimage for a key object is `AgentKeyBodyV1`:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
agent_id                    AgentIdV1
key_scheme                  u8   // 0 = strict Ed25519 in reference profile
public_key                  Bytes
key_role                    u8
key_sequence                u32
valid_from_height           u64
expires_after_height        u64
registration_nonce          Hash32
```

`key_role` is `0 controller`, `1 recovery`, `2 session`, `3 verifier`, or `4
bilateral-receipt`. A key
has exactly one role; the same raw public key used in two roles has two distinct
key IDs and state records.

```text
key_id = DigestV1(
  "trnm.poco-ai.agent-key.v1",
  AgentKeyBodyV1
)
```

`AgentKeyV1` is `AgentKeyBodyV1` and its recomputed `AgentKeyIdV1`; its creating
operation-kind `1` transaction carries the authorization, which is not copied
into the admitted object. Mutable active/suspended/revoked status is
`AgentKeyStateV1` keyed by `AgentKeyIdV1`; it is not part of `key_id`.

`AgentKeyStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,key_id:AgentKeyIdV1,generation:u64,status:u8,
activated_height:u64,status_changed_height:u64,reason_code:u16)`, with status
`0 Active`, `1 Suspended`, or `2 Revoked`. Creation uses generation zero and
Active. Active may suspend/revoke; Suspended may reactivate/revoke; Revoked is
terminal. Every change requires successor generation `expected + 1`.

`PolicyKeyEntryV1` is exactly `(key_id:AgentKeyIdV1,weight:u64)`, strictly
ordered/unique by raw key ID with positive weight. `ControllerPolicyV1` is
exactly `(schema_version:u16=1,entries:List<PolicyKeyEntryV1>,threshold:u64)`;
its hash domain is `trnm.poco-ai.controller-policy.v1`. Checked threshold is in
`1..=total_weight` and keys are active role 0. `RecoveryPolicyV1` is exactly
`(schema_version:u16=1,entries:List<PolicyKeyEntryV1>,threshold:u64,
recovery_delay_blocks:u64,allowed_recovery_actions:List<u16>)`; its domain is
`trnm.poco-ai.recovery-policy.v1`, keys are active role 1, and actions are
strictly ordered/unique. A recovery policy cannot spend, submit tasks, accept
leases, or issue compute results unless explicitly enumerated.

Controller rotation is one atomic transition that authenticates the current
policy, increments `identity_revision`, installs the complete successor policy,
and records its activation height. Key removal does not revoke signatures in
already order-finalized transitions. Unknown key schemes or expired, suspended,
revoked, wrong-role, or not-yet-active keys fail closed.

## 4. Capability grant

Every delegated operation requires an on-chain `CapabilityGrantV1` unless it is
authorized directly by the current controller threshold.

```text
CapabilityGrantBodyV1 =
  schema_version              u16  // 1
  genesis_hash                Hash32
  chain_id                    ConsensusString
  protocol_version            u32  // 1
  stack_profile_hash          Hash32
  issuer_agent_id             AgentIdV1
  issuer_key_id               AgentKeyIdV1
  delegate_agent_id           AgentIdV1
  delegate_key_id             Option<AgentKeyIdV1>
  parent_capability_id        Option<CapabilityIdV1>
  grant_nonce                 Hash32
  operation_scopes            List<OperationScopeV1>
  resource_scopes             List<ResourceScopeV1>
  spend_limits                List<AssetLimitV1>
  fee_limit                   u128
  gas_limit                   u64
  da_byte_limit               u64
  artifact_retention_limit    u64
  allowed_nonce_lanes         List<u16>
  valid_from_height           u64
  expires_after_height        u64
  rate_window_blocks          u64
  rate_max_operations         u64
  max_total_operations        u64
  delegation_depth_remaining  u8
  revocation_generation       u64
  conditions_hash             Hash32
```

`OperationScopeV1` has exact fields `(operation_kind: u16,
task_id: Option<TaskIdV1>, market_id: Option<Hash32>,
model_commitment: Option<Hash32>, tool_commitment: Option<Hash32>,
endpoint_commitment: Option<Hash32>,
verification_profile: Option<VerificationProfileRefV1>,
privacy_lane: Option<u8>, maximum_unit_price: Option<u128>)` in that order. A
verification constraint is therefore always the complete profile reference.

`ResourceScopeV1` has exact fields `(resource_kind: u16, scope_mode: u8,
allowed_ids: List<Hash32>, allowlist_commitment: Option<Hash32>)`.
`scope_mode = 0 ExactList` requires a nonempty `allowed_ids` and absent
commitment; `scope_mode = 1 CommittedSet` requires an empty list and present
commitment. `AssetLimitV1` is `(asset_id: Hash32, maximum_amount: u128)`.
All lists are bounded, strictly ordered by canonical key, and duplicate-free;
unknown modes or ambiguous list/commitment combinations fail closed.

```text
capability_id = DigestV1(
  "trnm.poco-ai.capability.v1",
  CapabilityGrantBodyV1
)
```

`CapabilityGrantV1` is the body, recomputed `CapabilityIdV1`, and issuer
authorization evidence from its unique operation-kind `2` transaction. Every
entry signs the common `AuthorizationStatementV1` binding that transaction ID under
`trnm.poco-ai.capability-grant-signature.v1`; signing the typed ID alone is not
an authorization. The admitted capability stores the authorizing transaction
ID rather than copying signatures. For a controller-threshold issuer, `issuer_key_id` is the
zero typed-key sentinel; for a one-key delegated issuer it equals the sole
authorization entry.
`CapabilityStateV1` stores status, live revocation generation, cumulative and
per-window operations, and the shared budget ledger defined below. Counters use
checked arithmetic.

Its exact value is `(schema_version:u16=1,
context:ProtocolContextV1,capability_id:CapabilityIdV1,state_version:u64,
status:u8,live_revocation_generation:u64,accepted_height:u64,
status_changed_height:u64,revoked_at_height:Option<u64>,
budget:CapabilityBudgetStateV1)`. Status is `0 Active`, `1 Suspended`, or `2
Revoked`; creation uses state version zero, Active, the body generation,
chain-assigned accepted/status heights, absent revocation height, and the exact
zero-spent/zero-reserved budget projected from the grant. Active may suspend or
revoke, Suspended may reactivate or revoke, and Revoked is terminal. Each
transition increments `state_version` once; revocation additionally requires
`live_revocation_generation = predecessor + 1` and sets
`revoked_at_height = Some(current_height)`. Every authorization compares the
body/ancestor generation to this live value and uses this exact state record.

## 5. Attenuation and delegation

A child capability is valid only if all of these hold:

1. its parent exists and is `Active`;
2. the issuer is the parent's delegate and uses the exact key allowed by the
   parent;
3. every child operation/resource/asset/verification/privacy scope is a subset
   of the parent scope under deterministic set comparison;
4. every numeric limit is no greater, the validity interval is contained, and
   allowed nonce lanes are a subset;
5. child `delegation_depth_remaining` is strictly less than the parent's value;
6. child `revocation_generation` equals the live parent generation; and
7. all ancestors are active and unexpired at the authorization height.

Missing, ambiguous, dynamically resolved, wildcard-escalating, or
implementation-defined scope comparison is invalid. A child can narrow but can
never widen authority. A profile cannot retroactively reinterpret an existing
capability's scope.

## 6. Session-key grant

`SessionKeyGrantV1` binds a session-role `AgentKeyIdV1` to exactly one active
capability. Its immutable ID preimage is `SessionKeyGrantBodyV1`:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
agent_id                    AgentIdV1
session_key_id              AgentKeyIdV1
capability_id               CapabilityIdV1
allowed_nonce_lanes         List<u16>
valid_from_height           u64
expires_after_height        u64
max_total_operations        u64
session_generation          u64
grant_nonce                 Hash32
```

```text
session_key_grant_id = DigestV1(
  "trnm.poco-ai.session-key-grant.v1",
  SessionKeyGrantBodyV1
)
```

The admitted `SessionKeyGrantV1` is the body, recomputed
`SessionKeyGrantIdV1`, and its unique operation-kind `3` transaction ID. Every
controller entry signs the common statement binding that exact transaction under
`trnm.poco-ai.session-key-grant-signature.v1`; signing the typed ID alone is not
an authorization.
The interval and limits MUST be within the capability. A session key cannot
issue capabilities, rotate controllers, alter recovery, create another session
key, revoke a controller, or use lane `0`.

`session_generation` starts at `1` and strictly increases for each successor
grant of the same `(agent_id, session_key_id)`. Reusing a previous generation,
including after revocation or expiry, is invalid. `SessionKeyGrantStateV1`
records Active or Revoked and is keyed by `SessionKeyGrantIdV1`.

Its exact value is `(schema_version:u16=1,
context:ProtocolContextV1,session_key_grant_id:SessionKeyGrantIdV1,
state_version:u64,status:u8,session_generation:u64,
bound_capability_generation:u64,operations_spent:u64,
accepted_height:u64,status_changed_height:u64,
revoked_at_height:Option<u64>)`. Status is `0 Active` or `1 Revoked`.
Creation uses state version zero, Active, the immutable grant generation, the
current capability's live generation, zero operations, chain-assigned heights,
and absent revocation height. Revocation is the only status transition,
increments `state_version`, sets the current height, and is terminal. An
authorization requires this state Active, the immutable and live session
generations equal, the bound capability generation equal its current live
generation, and checked `operations_spent < max_total_operations`.

Compromise of a session key is bounded only by its capability, unspent limits,
lanes, expiry, and the time until an order-finalized revocation. This protocol
does not undo operations finalized before revocation.

## 7. Nonce lanes

Each authorization namespace has `NonceLaneStateV1`:

```text
schema_version              u16  // 1
context                     ProtocolContextV1
nonce_lane_id               NonceLaneIdV1
state_version               u64
agent_id                    AgentIdV1
authorizing_key_id          AgentKeyIdV1
capability_id               Option<CapabilityIdV1>
session_generation          u64
lane                        u16
next_nonce                  u64
last_operation_digest       Option<Hash32>
status                      u8  // 0 Active, 1 Closed
```

The exact immutable nonce-lane key body is:

```text
(schema_version: u16 = 1,
 context: ProtocolContextV1,
 agent_id: AgentIdV1,
 authorizing_key_id: AgentKeyIdV1,
 capability_id: Option<CapabilityIdV1>,
 session_generation: u64,
 lane: u16)
```

`nonce_lane_id = DigestV1("trnm.poco-ai.nonce-lane.v1",
NonceLaneKeyBodyV1)` is `NonceLaneIdV1` (object kind 44), and
`NonceLaneStateV1` is keyed by that typed ID. Every field in the state must
equal the recomputed key body; this is the sole application-state/access-list/
state-sync identity for a lane.

No subset, `capability_generation`, widened `u32` lane, account-global nonce, or
implicit key is an alias. Controller-threshold operations use `(capability_id =
None, session_generation = 0, lane = 0)`. Session-key operations use the exact
capability ID and nonzero `session_generation` from their active grant. The
transaction/authorization bytes MUST carry all five key components.

Lane `0` is reserved for controller-authorized identity, key, capability, and
revocation administration. Session keys MUST use a nonzero lane explicitly
listed by their grant. The stack profile bounds lane count per key/capability;
no implicit lane exists.

An accepted operation MUST carry `nonce == next_nonce`. In one atomic
application transition it authenticates the operation, reserves all budgets and
fees, records the operation digest, and increments `next_nonce` by one with
checked arithmetic. Lane creation uses `state_version=0` and `next_nonce=0`.
Every accepted nonce consumption, including the canonical dynamic-failure
outcome, increments `state_version` in that same atomic write. Closing a lane
also increments it once and does not consume/reset a nonce unless the closing
operation itself is authorized through that lane. A stale expected version or
overflow is invalid. A lower nonce is replay; a higher nonce is a gap and is not
consensus-valid for current state. Nodes MAY retain higher-nonce transactions in
a bounded local queue, but queue admission is not chain acceptance.

Two operations in different lanes may execute concurrently when their declared
read/write sets do not conflict. A lane orders only its own operations and does
not define global task or settlement order. Closing a lane is terminal and does
not reset its nonce. A new session generation creates a distinct authorization
namespace and cannot replay a prior generation's nonce.

Genesis materialization and every admitted identity creation atomically create
that identity's controller lane-0 state at version/nonce zero using the zero
`AgentKeyIdV1` controller-threshold sentinel, `capability_id=None`, and
`session_generation=0`. Real controller keys remain only in the threshold
AuthorizationSet and never select the replay namespace. SessionKeyGrant
creation atomically creates one version/nonce-
zero NonceLane state for every strictly ordered allowed nonzero lane. All are
declared `Create`; a preexisting lane invalidates the parent transition. There
is no first-use implicit lane creation. A distinct fee payer must already have
its own active lane and signs/declares that exact Write.

## 8. Budget and rate accounting

All nonce lanes and session grants authorized by one capability share one
`CapabilityBudgetStateV1`; no lane receives an independent copy of a limit.
It is the embedded budget value of the capability state, not a separately
addressed state-tree leaf:

```text
schema_version              u16  // 1
context                     ProtocolContextV1
capability_id               CapabilityIdV1
budget_version              u64
revocation_generation       u64
asset_counters              List<AssetBudgetCounterV1>
fee_limit                   u128
fee_spent                   u128
fee_reserved                u128
gas_limit                   u64
gas_spent                   u64
gas_reserved                u64
da_byte_limit               u64
da_bytes_spent              u64
da_bytes_reserved           u64
retention_limit             u64
retention_spent             u64
retention_reserved          u64
operation_limit             u64
operations_spent            u64
operations_reserved         u64
rate_window_start_height    u64
rate_window_operations      u64
```

Creation uses `budget_version = 0`, the grant/live revocation generation, and
zero spent/reserved counters. Each successful reservation, charge, release, or
rate-window reset increments `budget_version` exactly once inside the same
atomic `CapabilityStateV1` version update; a failed transition changes neither
version. The embedded context/capability/generation must equal its enclosing
state or decoding fails closed.

Each `AssetBudgetCounterV1` is `(asset_id: Hash32, limit: u128, spent: u128,
reserved: u128)`; entries are strictly increasing by raw `asset_id` and
duplicate-free. Every `spent`, `reserved`, and requested sum is checked against
the one immutable grant limit. A capability ledger is keyed by capability ID
and live revocation generation, never by nonce lane or session key.

Delegated child capabilities do not mint budget. An accepted operation reserves
its exact deltas atomically in the selected capability and every ancestor
capability ledger. If any ancestor would exceed a limit, the whole transition is
invalid and no nonce advances. The deterministic operation digest is the
reservation key across all ledgers; exact replay is idempotent, and another
operation cannot release, charge, or reuse that reservation.

Authorization evaluates limits in this order:

1. agent, key, capability ancestry, generation, status, and height interval;
2. operation and resource scope;
3. exact nonce lane and nonce;
4. per-asset, fee, gas, DA, retention, operation-count, and rate-window limits;
5. deterministic task/market-specific policy; and
6. atomic reservation with the operation's escrow/fee transition.

`spent + reserved + requested` MUST be within each limit using checked
arithmetic. A reservation is released, charged, or reassigned only by a
specified order-finalized lifecycle transition. Retrying the identical pending
operation does not reserve twice. A different operation at the same lane/nonce
is invalid.

Concurrent operations in different lanes conflict on the shared budget ledgers
even when their application objects otherwise do not conflict. Deterministic
MVCC may execute them speculatively, but canonical validation order serializes
the ledger updates and reexecutes a stale budget read. Aggregate spending across
lanes, session generations, delegate keys, and descendant capabilities can
therefore never exceed the root grant.

Rate windows use chain heights, never local wall time. At the first operation in
a later deterministic window, the per-window counter resets as part of the same
transition. Local admission rate limits may be stricter but cannot alter a
block's deterministic result.

## 9. Revocation

`CapabilityRevocationOperationV1` is the exact state-transition operation body
`(capability_id: CapabilityIdV1, expected_live_generation: u64,
successor_generation: u64, reason_code: u16)`. It is not
an independently ID-addressed object; its identity and authorization are the
enclosing `AgentTransactionIdV1` and `AuthorizationStatementV1`. It requires
issuer controller authority or an explicitly authorized recovery action.

- `successor_generation` MUST equal `expected + 1`.
- The operation has no caller-selected effective height. On successful
  execution the chain writes `revoked_at_height = current_height` into
  `CapabilityStateV1` in the same atomic transition. Delayed, scheduled,
  retroactive, or future-dated revocation is not a v1 operation.
- Revocation atomically changes status to `Revoked`, increments both the
  capability state version and live generation, updates the embedded budget's
  version/generation without changing its monetary counters, and
  invalidates descendants and session grants that bind the old generation.
- Suspended agents, keys, and capabilities cannot authorize new operations.
- Already order-finalized operations, escrow, leases, receipts, challenges, and
  liabilities continue under their creation profiles.
- Pending mempool or unfinalized operations have no grandfathered authority and
  must revalidate against the execution parent state.
- Revocation cannot erase audit records, nonce state, spent budgets, or
  accountability evidence.

An expired capability is not automatically deleted. It remains retained for at
least every task, challenge, evidence, unbonding, and audit window that refers
to it.

`AgentAdministrationOperationV1` is the closed exact body for operation kind
`13`: `(schema_version:u16=1, context:ProtocolContextV1,
agent_id:AgentIdV1, expected_identity_revision:u64,
action:AgentAdministrationActionV1)`. Its action union is:

```text
0 KeyState {
    key_id:AgentKeyIdV1, expected_key_generation:u64,
    successor_key_generation:u64, next_status:u8, reason_code:u16
  }
1 SessionRevoke {
    session_key_grant_id:SessionKeyGrantIdV1,
    expected_session_generation:u64, reason_code:u16
  }
2 ControllerPolicyReplace {
    expected_controller_policy_hash:Hash32,
    successor_controller_policy:ControllerPolicyV1
  }
3 RecoveryPolicyReplace {
    expected_recovery_policy_hash:Hash32,
    successor_recovery_policy:RecoveryPolicyV1
  }
4 AgentStatus {
    expected_status:u8, next_status:u8, reason_code:u16
  }
5 NonceLaneClose {
    key_id:AgentKeyIdV1, capability_id:Option<CapabilityIdV1>,
    session_generation:u64, lane:u16, expected_next_nonce:u64
  }
```

Every successor generation/revision is the checked predecessor plus one.
Controller authority is mandatory for actions 0, 2, 4, and 5; the exact active
recovery policy may authorize only actions 0, 1, 3, or 4 that it explicitly
enumerates. Action 1 additionally requires the owning controller/recovery rule.
The chain assigns the current execution height to every status/policy change;
there is no scheduled or retroactive field. The declared access list must name
the identity and every key/session/lane/policy state written by the selected
action, and the entire transition is atomic.

## 10. Required invariants and vectors

Conformance MUST demonstrate:

- typed ID and wrong-domain/wrong-profile rejection;
- controller threshold and rotation atomicity;
- no capability widening through nesting, wildcard, numeric overflow, validity
  interval, lane set, or profile reinterpretation;
- transitive revocation and exact generation checks;
- session keys unable to perform controller operations;
- exact per-lane sequencing, independent-lane progress, no nonce reset, and no
  cross-key, cross-capability, or cross-session-generation replay under the
  exact five-component nonce key;
- atomic nonce, one shared ancestor-aware capability budget, fee, and escrow
  reservation under cross-lane conflicts and crash;
- deterministic rate-window boundaries; and
- retention of authority evidence after expiry, suspension, revocation, and
  retirement.
