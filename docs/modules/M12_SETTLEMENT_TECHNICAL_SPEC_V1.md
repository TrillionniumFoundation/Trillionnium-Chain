# M12 Settlement and Economics technical specification v1

Status: candidate contract; development economics below do not activate PoCO
weights or supply mainnet parameter authority. Primary module: M12.

## Authority

M12 owns deterministic fee/payment/refund/slash accounting and one-shot
consumption identities. It consumes authenticated task, result, challenge,
escrow, policy and finality facts. It cannot declare a task correct, infer
independent demand from a signature, issue an Order QC or activate voting power.

Applicable inputs are [AI-v1 specification 08, sections 5-8](../protocol/poco-ai-native-v1/08-coordination-settlement-execution-and-fees.md)
and [frozen v0 weight/bond/slash rules](../protocol/poco-bft-v0/05-poco-weights-bond-and-slashing.md).
Their profiles are separate. Mainnet economic activation remains blocked while
the frozen v0 rollout prerequisites are unmet; this file does not choose new
values for frozen `UNDECIDED` fields or rewrite signed v0 bytes.

Current local implementation is
`trillionnium/crates/trnm-poco-consumption-settlement-v1/src/`.
It supports one asset, task, lease, attempt, result, escrow and rollup through
`types.rs`, `engine.rs`, `codec.rs`, and `store.rs`. That bounded kernel is
not a multi-asset production ledger or a proof of economically independent demand.

## Interfaces

`ConsumptionSettlementStoreV1::execute_order_finalized` takes the exact
`ConsumptionOrderFinalizedExecutionContextV1` and a closed command:
`AdmitReceipt` (kind 24), `AdmitRollup` (25), or `Settle` (26).
`preview_before_vote_v1` computes without durable logical mutation;
`confirm_receipt` and `fresh_readback` bind actual store lineage.
The order context is an authenticated caller obligation, not a finality proof.

`ConsumptionSettlementFreshGenesisTrustBundleV1` supplies the exact context,
initial order head, provider/consumer bilateral keys, task/lease/attempt/result,
result revision/status, escrow/version/funding, asset, three destination accounts
and opening balances, sorted resource prices, accepted evidence certificate
IDs, related-party policy hash and `SettlementPolicyV1`.
Every identity/version must match live commissioned state before use.
Current genesis validation rejects the same provider/consumer identity,
duplicate bilateral keys and duplicate settlement accounts. Different accepted
identities may nevertheless have the same economic controller; the registry
policy below addresses that separate question without weakening these checks.

`SettlementPolicyV1` contains schema and policy revision,
`minimum_rollup_challenge_blocks`, `maximum_rollups`, protocol-fee numerator/
denominator and fee-schedule hash. A policy hash commits those exact values.
Each `ConsumptionPriceV1` binds resource class/ID, meter ID/version, unit and
integer unit price. No client-selected price or unit silently overrides it.

Current candidate byte layouts use exact Borsh type order and `codec.rs`
strict decode/re-encode. Receipt/rollup provider and consumer signatures use
distinct domains such as `trnm.poco-ai.consumption-rollup-provider-signature.v1`
and `trnm.poco-ai.consumption-rollup-consumer-signature.v1`.
The settlement intent is identified by `trnm.poco-ai.settlement.v1`; its
input, planned-delta and conservation roots are separate source-defined domains.
Transport JSON and a raw payment amount cannot stand in for these objects.

### Owned compatibility engine: `trnm-pouw`

The compatibility-named package is still consumed by runtime code; it is not
dead code and is not the AI-v1 settlement kernel. Public `apply_*` functions
operate on `StateStore`, `ObjectRef { id, version }` and `TaskObject`. The task
retains creator/bounty, worker, status, commitment/result/salt, version, proof
type, metadata/metering and challenge/deadline/bond fields. `consumption.rs`
adds the separate `ConsumptionReceipt`, `ConsumptionReplayKey` and consumption
challenge/resolve path; its `POCO_V1_SETTLEMENT_SCHEMA` name does not identify
the AI-v1 Borsh command layout above.

| Existing transition | Required binding and accounting |
|---|---|
| Create→Open | Canonical creator; new task ID/version 1; duplicate insertion rejects |
| Open→Assigned | Canonical worker, expected version and sufficient minimum stake; task-local stake lock funded |
| Assigned→Committed | Assigned worker equals canonical payload worker; exact object version and commitment retained |
| Committed→Revealed | Recompute commitment over task/result/salt/worker; check reveal deadline; snapshot challenge window for non-immediate proof modes |
| Committed→Completed | Only the configured TEE/ZK verification path can take this immediate branch; invalid/indeterminate verification rejects; this is compatibility behavior, not AI-v1 profile activation |
| Revealed→Challenged | Canonical authenticated challenger, expected task version, challenge window and funded bond; retain challenger/bond provenance |
| Challenged→Completed/Slashed | Emergency-pause gate, exact version/accounting, configured authenticated resolver(s), task-local funds and all transfer preflights |
| Timeout | Inspect the current task phase and its stored deadlines; apply the phase-specific release/refund/slash behavior, not an unconditional slash |

The current `_at_height` APIs carry actual chain height; compatibility wrappers
passing height 0 must not be used as a public finalized-block adapter. Assignment
and reveal defaults are 20 blocks, challenge default 100, minimum worker stake
1, minimum challenge bond 10 and fixed challenge-success bounty 1. Governance
overrides are read by existing helpers; defaults are not ECON-DEV-1 authority.
Current deadline construction includes saturating addition, and old Revealed
tasks lacking a window snapshot still consult challenge-time governance. Preserve
these behaviors in compatibility replay; retiring them requires a versioned
upgrade/migration, not a documentation assertion that they already disappeared.

Resolution authenticates `signer`, requires payload resolver equality, rejects
placeholder/system/custody accounts and overlapping worker/creator/challenger
roles. A multi-member authority requires two distinct approvals; first approval
returns `ResolveApprovalStaged` and intentionally retains approval state rather
than terminal settlement. Membership/decision drift invalidates stale approval.
Challenge success returns challenger bond and sources its bounty from that
task's worker stake lock; rejection forfeits bond to the selected treasury.
The metering weights default to prompt/generated/decode=1 and KV bytes=0;
additional metered bounty/bonus/rebate numerators default to zero. Do not merge
these formulas with the candidate fee/refund policy below.

`PouwError` distinguishes `VersionConflict`, `InvalidTransition`, `Unauthorized`,
`InsufficientStake`, `DeadlineExceeded`, commitment errors and staged approval;
`State` maps to stable `StateInternal`. Public direct calls have no independent
signature/nonce envelope and are not a durable atomic commit capability. M06's
authenticated runtime validates nonce/fee/resource limits and publishes resulting
mutations through M08. Direct StateStore consumers must use their selected
transaction/rollback contract; do not assume a sequence of helper calls is atomic.
Selected planned compatibility harness limits are 1,024 live tasks, 64 KiB
metadata/proof per call and one serial task transition at a time; reject before
mutation. These host caps are not retroactive frozen consensus rules.

Replay `common/apply_path/tests/metering_settlement/` for fee deductions, refunds,
settlement/preflight boundaries, and M06 runtime tests
`successful_challenge_refunds_payers_and_slashes_only_worker_stake` and
`paid_poco_rejected_challenge_preserves_every_issued_unit`. Add an explicit adapter
case for a staged first approval: no terminal receipt/payout, approval retained;
after membership change, old approval cannot complete settlement.

### Owned auxiliary contract: `contracts/settlement-vault`

This is a pure in-memory Rust MVP, not a deployed VM contract or token bridge.
`SettlementVault` retains owner, pause flag, account→u128 balances,
request→`LockRecord { account, amount, status }`, and `Vec<VaultEvent>`.
`AccountId`/`RequestId` are strings; `LockStatus` is Locked/Released/Slashed.
There is currently no durable codec, host ABI, token-deposit proof or map/log cap.

Every current mutator receives a caller string and checks owner authority;
ordinary mutations then reject while paused. `deposit` credits a positive amount
with checked arithmetic. `lock` requires a canonical nonblank/unpadded unique
request, sufficient account balance, and debits it once. `release` accepts only
Locked and credits its origin. `slash` accepts only Locked and credits a valid
different beneficiary. Both precheck destination overflow before marking terminal.
`transfer` checks funding/beneficiary/overflow; a self-transfer preserves funds
but may emit an event. `pause`/`unpause` are owner-only and reject redundant state.
`consume_audit_log` drains local events; it is not proof that they were durably
published. `normalized_audit_log` maps them into M00 audit-events with source
`settlement-vault`, preserving request/account/beneficiary field semantics.

Use exact `VaultError` classes: `Unauthorized`, `Paused`, `AlreadyPaused`,
`NotPaused`, `InvalidAmount`, `InvalidBeneficiary`, `InvalidRequestId`,
`InsufficientBalance`, `DuplicateRequest`, `RequestNotFound`,
`InvalidStateTransition`, `BalanceOverflow`. Errors preserve balances, locks and
audit log. Conservation is opening balance + authenticated deposits = free
balances + Locked amounts; Released/Slashed locks contribute zero locked value.
A caller-provided deposit number is not authenticated asset creation.

A planned host adapter must derive caller from authenticated M01/M05 context,
never from that string argument; require host nonce/expected vault revision and
an exact operation digest, and validate deposited asset custody before credit.
Persist vault delta, nonce, input identity and normalized events in one M08
transaction before publishing/draining events. Host retry compares operation
digest plus predecessor revision; altered bytes at the same nonce reject.
For **VAULT-DEV-1**, select one fixed asset, canonical UTF-8 IDs of 1..128 bytes
without surrounding whitespace, 4,096 accounts, 4,096 live locks, 256 events per
commit and at most 1,000,000 units/operation. Check caps before mutation; retain
terminal request tombstones for replay protection, with at most 16,384 retained
IDs before refusing new locks. Reclamation needs a separately authenticated
replay-horizon protocol and is disabled initially. Unknown asset/schema rejects.
These adapter, persistence and capacity rules are planned; they do not imply a
general on-chain WASM/EVM host exists.

Concrete acceptance: deposit 100, lock r=40 → free60/locked40; release r → free100;
second release rejects without event; alternatively slash r to B → A60/B40.
Depositing into u128::MAX and releasing into an overflowing account must leave
all state/events unchanged. Replay the crate's
`terminal_lock_operations_reject_replays_without_mutating_state_or_audit`,
`overflow_paths_fail_closed_without_partial_state_mutation`, and
`normalized_vault_audit_mapping_keeps_field_discipline`. Planned host tests add
lost-commit ACK, substituted caller, unauthenticated deposit and full-ID-cap
rejection. `contracts/bridge-relay` is owned by M15; its proof/replay authority
must not be inferred from the vault balance or M11 oracle admissibility.

## State machine

### Admit bilateral receipt

1. Resolve the exact provider and consumer keys, policy revision and generations.
2. Verify both signatures over the same receipt body and role-specific domains.
3. Match chain/profile/task/lease/attempt/result, meter/unit/price and evidence
   certificate bindings to the commissioned policy.
4. Require the next sequence and previous receipt identity; recompute usage
   deltas, cumulative quantities and cumulative charge with checked arithmetic.
5. Persist receipt and exact operation identity; exact retry produces one receipt.
   A sequence gap is `SequenceGap`, reuse with altered bytes is conflict.

This proves that two authorized keys acknowledged these meter values. It does
not prove independent beneficial ownership, external demand or physical GPU work.

### Admit rollup

Require the complete exact unassigned receipt interval, sorted/gap-free sequence,
matching endpoints and previous roots. Recompute cumulative usage and charge;
verify provider/consumer signatures. Assign each receipt once to this rollup,
increment receipt versions and record the challenge close height by checked
addition. The current kernel accepts its single bounded rollup only.

### Settle

Require exact task/lease/attempt/result and expected result/escrow/rollup
versions and settlement-policy hash. Reject if escrow is closed, settlement
already exists, result is not `FinalValid`, rollup is consumed, or result maturity
is not the selected unsettled state. Current maturity requires
`order_height > challenge_close_height`, not greater-than-or-equal.

For escrow balance E, approved total charge C and fee fraction n/d:

```text
require 0 <= C <= E, d > 0, 0 <= n <= d
protocol_fee = floor(checked(C * n) / d)
provider_payment = C - protocol_fee
consumer_refund = E - C
provider_payment + consumer_refund + protocol_fee = E
```

Build sorted nonzero `ValueDeltaV1` entries, input-value root, planned-delta
root and conservation root. Verify every destination and checked post-balance/
version before publishing any. Atomically consume rollup and settlement identity,
close escrow, apply all account legs, advance result maturity and persist the
exact intent/receipt. A retry returns the same settlement, never another payment.

### Planned multi-asset and terminal settlement

Group inputs, outputs, explicit fees and burns by exact asset ID. For each asset
separately require input sum = output sum + explicit burn; no cross-asset netting.
Sort `(asset_id, account_id, reason)` and consolidate duplicates before checking
post-balances. All groups commit together or none do.
Cancel/expiry/failure refunds consume an authenticated M10 terminal intent;
fraud slashes additionally require the exact M11 final challenge decision and
bond/policy predecessor. Never compensate a possibly completed payment with an
unauthenticated reverse transfer. These new variants/codecs are planned.

## Persistence and recovery

Store the exact command, receipt, account/escrow/result/rollup successors and
state/operation/finalized-block roots in one transaction.
`advance_empty_order_finalized_v1` advances maturity through empty blocks.
After mutation, fresh-confirm the exact operation and target state.
If a commit acknowledgement is lost, reopen against the named source/target;
source means safe exact retry, target means return the original receipt,
anything else is `ThirdStateFenced`. Do not select a state from account balances
alone while ignoring consumed rollup and settlement identities.

Keep historical consumed IDs until an authenticated archival/replay fence
proves they cannot become spendable again. Retention for receipt evidence lasts
through challenge, appeal, settlement and applicable economic audit windows.
Cross-store M10/M11/M12 facts require M08's canonical atomic application commit;
three independently successful local SQLite calls are not a global transaction.

## Resource bounds

Existing kernel bounds: 1,024 receipts, 32 usage/price entries and 128-byte
resource/meter IDs. It supports one rollup and one asset. Over-cap receipt
admission fails without consuming sequence or extending cumulative charge.

Select planned **ECON-DEV-1** for deterministic application development:
one asset; maximum funded escrow 1,000,000 integer units; fee 1/100;
rollup challenge window 20 finalized blocks; maximum 1,024 receipts/rollup;
maximum 32 usage entries; no voting-power or reward eligibility from consumption.
These are candidate development choices, not claims about existing fixture
values or mainnet. All prices, asset/account identities, evidence policy and
related-party policy digests must be supplied in the signed deployment manifest.
Denominator is positive, numerator <= denominator, windows in 1..10,000,
every price/usage multiplication checked u128, and no missing field gets a default.

Planned multi-asset extension caps a settlement at 16 assets, 64 input escrows,
256 output legs and 1 MiB canonical bytes in the development host. Admission
uses the smaller selected protocol bound; application-visible limit changes
require an authenticated profile revision, not local load shedding.

## Security

### Errors and invalidity versus unavailability

`InvalidSignature`, `Unauthorized`, `IdentifierMismatch`, `NonCanonical`
reject receipt identity/authority. `SequenceGap`, `RootMismatch`, `StaleVersion`,
`InvalidTransition`, `NotMature`, `AlreadyConsumed` reject lifecycle misuse.
`InsufficientFunds`, `ConservationViolation`, `ArithmeticOverflow` leave all
accounts and consumption identities unchanged. `StoreFailure` is local;
`CommitUncertain` needs readback; schema/tamper/third-state errors fence.
No saturation, negative wrapped value, implicit mint or implicit fee is legal.

### Planned related-party and anti-wash policy

ECON-DEV-1 permits service settlement under its funded contract but awards
**zero consensus weight and zero subsidy** from consumption. Consequently a
provider/consumer pair cannot turn self-paid development volume into power.
This is the selected safe policy, not a claim to solve permissionless identity.

Before any future economically weighted profile is commissioned, bind an
authenticated registry of economic-control groups with controller evidence,
validity interval, appeals/revocation and exact group IDs. Unknown, related,
revoked or provider-controlled consumer/verifier groups receive zero eligible
consumption weight. The registry is an explicit governance trust assumption;
independent keys, IPs, signatures or validator names do not prove independence.

Eligible quantity must be derived from finalized, challenge-mature, paid and
non-refunded receipts, net of rebates/rewards/round trips recognized by the
selected policy. Apply per-group and per-group-pair epoch ceilings before
aggregate weight; commit the exact registry/policy at epoch start. Delayed
fraud changes future eligibility and authorized bond effects, not past finality.
Do not enable such a profile until adversarial cost analysis shows assumptions
under which acquired effective weight remains below the BFT fault bound.
There is no universal numeric anti-Sybil constant that replaces that analysis.

### Planned development slash/refund choice

For ECON-DEV-1, an objectively upheld M11 fraud decision refunds all unsettled
escrow to the consumer and slashes min(available provider bond, floor(E/10)).
The slashed amount goes to an explicitly named development treasury account;
reporter subsidy is zero. Rejected challenge forfeits its selected challenge
bond under M11 policy; `Unavailable`/expired infrastructure never counts as fraud.
The exact policy and bond identity must be fixed before leasing; this behavior
is not present in the three current command variants and needs its own vectors.
Frozen consensus double-sign slashing remains a separate v0 evidence/activation
route and cannot consume an AI challenge as if it were consensus equivocation.

## Observability and SLO

Measure settlement age, immature backlog, escrow/held-bond totals per asset,
one-shot rejection rate, write/confirm latency and recovery scan cost.
Reconcile per-asset conservation and consumed-ID uniqueness after every replay.
Report customer payments separately from eligible consumption, shadow weights,
activated weights and protocol revenue. Synthetic development volume is labeled.

## Verification and evidence

| Case | Input and exact expected result |
|---|---|
| M12-SPLIT | E=1,000, C=250, n/d=1/100, destination openings zero: provider 248, treasury 2, refund 750; escrow 0/closed |
| M12-ROUND | C=99, n/d=1/100: fee 0, provider 99; no floating-point rounding |
| M12-MATURE | Close height 100: settle at 100→`NotMature`; 101 eligible if all other predicates hold |
| M12-REUSE | Same settlement after lost response: original receipt, no second debit; altered identity→conflict/consumed rejection |
| M12-SEQUENCE | Receipts 1,2,4: `SequenceGap`; rollup totals/roots unchanged |
| M12-OVERFLOW | C*n exceeds u128: `ArithmeticOverflow`, no account leg published |
| M12-ASSETS, planned | Asset A deficit 1 plus asset B surplus 1: reject; sums cannot cancel across assets |
| M12-WASH, planned | Distinct provider/consumer IDs in the same control group: service can settle if authorized, eligible PoCO weight remains zero |

Replay `receipt_rollup_and_settlement_are_bilateral_gap_free_and_conserved`,
`settlement_maturity_versions_replay_and_one_shot_are_exact`,
`commit_uncertainty_reopens_to_exact_source_target_or_permanent_fence`, and
`canonical_command_bytes_reject_trailing_and_truncation` in `src/tests.rs`.
Independent vectors bind full command/intent/receipt bytes and all pre/post
balances; equations alone are not an independent economic-security review.
The [settlement inventory](../protocol/poco-ai-native-v1/vectors/cev1-consumption-settlement-kernel-v1.json)
records the current single-asset/single-rollup candidate scope; new multi-asset
and policy-extension cases require their own exact independent expectations.

## Activation boundary

The current kernel trusts its supplied result/evidence/Order context; a public
settlement route requires actual M08/M09/M10/M11 proof consumers and atomic
state integration. Multi-asset, terminal refunds/slashes and ECON-DEV-1 admission
are planned extensions. Full PoCO activation additionally needs accepted
identity/economic assumptions, frozen mainnet parameters and governance authority.
