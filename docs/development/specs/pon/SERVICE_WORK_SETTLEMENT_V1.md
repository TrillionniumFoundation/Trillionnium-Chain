# Separate evaluation service, improvement bonus and consensus credit V1

This is a bounded accounting adapter under PN3/PN4 of the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It reuses the existing [five-lane funding and resource planner](REWARD_BUDGETS_V1.md),
the [complete integer numeric reference](USEFUL_CELL_RELATION_V1.md), and the
existing four-control [cluster evaluator](../../../../formal/pon-nakamoto-v1/evaluation.py).
It introduces no native transaction, wallet, issuance, payment adapter, model
installation or consensus rule. All production qualification remains **HOLD**.

Implementation:

- [Service/bonus adapter and reproducible scenarios](../../../../formal/pon-nakamoto-v1/service_work_settlement_v1.py)
- [Adversarial controls](../../../../formal/pon-nakamoto-v1/test_service_work_settlement_v1.py)
- [Existing funding/resource implementation](../../../../formal/pon-nakamoto-v1/reward_budget_oracle.py)
- [Existing full scalar arithmetic](../../../../formal/pon-nakamoto-v1/useful_cell_numeric_v1.py)
- [Native payment observation owner](../../../../trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs)

## Why this adapter is needed

The existing planner correctly separates five funding lanes, charges failed
resource use, preserves physical-resource records across its branch checkpoints,
and emits zero additional chainwork. Its generic `positive` versus `no-gain`
resolution does not itself distinguish a successfully completed evaluation
service from the evaluated candidate's failure to improve. Treating those as one
outcome would either deny a contracted evaluator's base fee or pay an improvement
bonus for an unsuccessful candidate.

The new contract freezes those obligations separately:

| Obligation | Existing funding lane | Finite checked condition | Reference allocation |
| --- | --- | --- | --- |
| Base evaluation service | `evaluation` | Complete correct replay of the frozen candidate, four controls and both task partitions | The fixed base fee, including a correct `NoUpdate` result |
| Conditional improvement bonus | `contribution` | Positive frozen gain against every control, retained statistical gate, and regression count within the frozen retention allowance | The fixed bonus if every condition passes; otherwise zero |
| Consensus credit | Existing consensus owner; absent from this adapter | No work relation is qualified by this adapter | Always zero additional credit |

V1 deliberately defines a concrete **evaluation service**. It does not rename
arbitrary inference, training, storage or repair records as completed evaluation.
Those services retain their existing task/serving/retention owners and require
their actual relation and delivery evidence. The same separation of obligations
can be applied there only through their own versioned contract.

An evaluator may complete its contract by demonstrating that a candidate is no
better than the controls. `NoUpdate` is a result of a complete evaluation. It is
not a synonym for failed execution, timeout, incomplete evidence or cancellation.

## Frozen material and independently retained context

The fresh contract schema is `pon-service-work-contract-v1`; its program identity
is `frozen-int257-evaluation-service-v1`. `freeze_contract` binds the original
task and consumer, evaluator/service-provider and improvement-beneficiary,
complete material commitment, numeric profile, separate budgets and fees,
contribution root, lane-specific resource reservations, original height window,
minimum gain and maximum retained-task regressions. The original task identity
must come from its admitting owner; generating another task ID is not proof of
another demand event.

The material includes the actual integer candidate, all four frozen control
models (`current`, `best_single`, `mean_merge`, `pooled`), and complete ordered
evaluation and retention rows. Every row binds its ID, declared source group,
label and all 257 input features. Each partition has 1 through 64 rows. Task IDs
are unique, the two partitions do not share task IDs or declared source groups,
and numeric/model schemas are validated by the existing implementations.

The accepting owner retains `expected`, the contract digest, independently of
the downloaded contract/result. An internally consistent replacement contract
does not match that expectation. The complete digest is additionally pinned in
both **existing monotonic resource-job records** as `service_work_contract_v1`.
It cannot be replaced during result submission or exact branch retry even if a
caller accidentally presents the replacement digest as a new expectation. No
second journal or native stored schema is added.

Declared source groups, labels, role identities and frozen controls are inputs,
not authenticated independence, fair control-training budgets, data custody or
ground truth. Rejecting an evaluator/author identity alias does not detect hidden
common control. This adapter therefore never reports independent evaluation or
real demand as certified.

The material uses the existing prequantized integer format. It does not perform
training, validate a float-to-integer conversion or run a trained Hepta encoder.
The numerical reference checks the supplied features. Actual upstream feature
provenance and ordinary Hepta admission remain separate obligations; the
[useful-Cell relation](USEFUL_CELL_RELATION_V1.md) and its successor are not
silently replaced by this narrower arithmetic task.

## Complete execution and separate model decision

`execute_service` actually evaluates the candidate and each of the four controls
on **both** partitions. For every model it returns all fifteen product rows,
routes, all logits and predictions using the existing exact scalar implementation.
It first takes one bounded private snapshot of the supplied material, then checks
the commitment and executes that same snapshot. Changes to the caller's original
object after the snapshot cannot substitute different material for execution.
The accepting path recomputes the entire service and compares the complete
canonical result bytes. A correct chosen class with omitted or forged unselected
expert products is insufficient. Additional caller fields such as
`work_profile_qualified=true` are not accepted contract or result fields.

For each frozen control, the implementation retains the existing cluster
comparison: at least twenty declared source groups, four-way multiplicity,
positive macro gain and the existing directional test. It also compares the
exact rational gain with the frozen `minimum_gain_ppm`; it does not accept a
rounded score supplied by the producer. All four controls must pass.

Retention counts a regression whenever the candidate misses a frozen label
that at least one control correctly predicts. That count must stay within the
precommitted allowance. Passing this finite test says nothing about unobserved
old capabilities, out-of-distribution behavior, future tasks or real statistical
independence. If any gain or retention condition fails, the correct complete
result is `NoUpdate`. A passing result is named `MeasuredImprovement`, not an
adoption authorization.

Both outcomes leave the actual model owner and loaded generation unchanged.
There is no fabricated install, release, payment or next-task receipt. Even a
positive finite result must still pass the original evaluator, governance,
funding, release, CURRENT and FinalUse boundaries before any real effect.

## Accounting, duplicate protection and failure handling

`reserve_contract` and `settle_contract` return a **new** `RewardBudgetPlanner`.
They perform both lane transitions on a copy and publish it only after all checks
pass. The caller's old planner is unchanged on success or failure. The caller
must explicitly retain the returned planner; these are reference state
transitions, not concurrent database transactions.

The base and bonus use distinct original funding sources, original budgets and
separate beneficiaries. An evaluation budget cannot be replaced by a contribution
or mining budget. Both budgets must already be mature at the contract's
`issued_height`, and both budget deadlines must cover the full original service
window. A future maturity in either lane is rejected with
`SERVICE_BUDGET_IMMATURE_AT_ISSUE`, even if it lies inside the service window.
Consequently no otherwise allowed completion height is made unpayable merely
by an immature base or bonus budget. Both claims use stable IDs derived from the original planner
context, task and lane. Changing consumer, policy, model, deadline or contract
version does not create another reservation under the same original task. The
existing contribution-root cap and cumulative resource accounting still apply.
Distinct sources mean distinct escrow/debit identities, not a requirement for
different sponsors. One sponsor may fund both obligations from distinct valid
sources. Conversely, two invented identifiers do not establish two actual debits;
source authenticity and conservation remain the original native funding owner's
responsibility.

For a complete, timely result, the base claim resolves as a positive **service**
outcome. The bonus claim separately resolves as positive or no-gain. The inherited
planner's `paid` counters describe conditional accounting here; the returned
report names the amounts `conditional_base_fee_units` and
`conditional_improvement_bonus_units`. `external_payment_executed` stays false.
The adapter does not import those counters into native balances.

An invalid or cancelled service earns neither fee and still consumes its
reported resources. `unknown` is nonterminal: it preserves both original
monetary and resource reservations, including after the original deadline, and
accepts no fabricated zero-cost terminal record. The same reserved task can
later complete once within its original payment window. A successful reservation
or settlement, including `unknown`, records its owner-supplied height in the
same monotonic resource-job records **if the caller retains the returned planner**.
A retry or branch rewind cannot backdate below that retained height. Failed
attempts discard their transition copy, and read-only supply queries do not
record new height observations. The real owner must separately persist valid
height observations; this adapter does not certify the physical clock or
canonical chain. A completed claim cannot be resolved again on
the same branch. The local outcome pin described below also survives branch
rewind; replayed branch accounting is not another external payment.
An unknown result must not be passed to the generic
planner's budget-closing/refund path as evidence of `NotDispatched`; actual
timeout/effect resolution belongs to the original operation and funding owners.

The original planner's resource records, including the contract pin, survive its
in-process branch rewind. This is **not** durable restart or backup-rollback
protection. A whole-process loss has no independently retained monotonic anchor
here. Resource counters are supplied owner observations, not independently
measured CPU/GPU/byte-time costs or a lower bound on the cheapest legal algorithm.
No private precomputation, cache, helper or failed mining attempt is charged by
this service adapter merely because the complete arithmetic relation was replayed.

The existing native payment reader reexecutes the actual canonical monetary
transition and binds the original task, release or reward. It remains the owner
of native payment observations. This reference does not replace its signature,
escrow, active-branch, maturity, original-operation or receipt checks. Real
settlement, physical worker cost, provider idempotency and cross-node recovery
remain open integration work.

## Local outcome continuity and V2 reports

The contract, complete evaluation result and original planner remain V1. The
adapter's settlement and supply reports now use the explicit namespaces
`pon-service-work-settlement-reference-v2` and
`pon-service-work-supply-observation-v2`. Historical V1 reports retain their
original meaning and are not relabeled as observations of the new checks.
These reports are not native transactions or consensus admission inputs.

Each successful `settle_contract` transition records the same
`pon-service-work-local-resolution-v1` object under `service_work_resolution_v1`
in both **existing monotonic resource-job records**. The record binds the exact
contract, outcome, complete-result digest, model decision, both reported cost
vectors and both conditional fee amounts. It is private in-memory metadata;
there is no new durable database, serialized native schema, dispatch owner or
branch checkpoint field. The caller must retain the returned planner as before.

Both pins must be jointly absent or agree exactly. A one-lane pin, contradictory
pins, changed contract or disagreement with the original consumed cost vectors
is refused. Both new pins are published only on the successful private-copy
transition after both original lane resolutions succeed. A failed base or bonus
transition leaves the caller's original planner unchanged.

`unknown` remains nonterminal. Repeated Unknown observations and subsequent
completion, invalidity or cancellation can reconcile the same original task
within its unchanged height and payment rules. A terminal `complete`, `invalid`
or `cancelled` record cannot become a different outcome, or revert to Unknown,
after a branch rewind. The earlier adapter retained costs but not that outcome:
restoring the reserved branch could relabel a completed service as cancelled or
Unknown, or a cancelled service as complete, at the same reported charges.
The retained regression comparisons distinguish this reference-accounting
defect from any claim about deployed native acceptance.

Exact monetary reapplication after reorganization remains permitted. Its
outcome, complete-result bytes, decision, charges and conditional fees must
match the original pin. Height and branch membership are deliberately excluded
from that immutable pin; the existing separate monotonic-height check still
applies. The V2 report identifies this case with `local_resolution_replayed`.
It authorizes no physical re-execution, contributes no additional chainwork and
does not reset the original external-intent journal. A completed external intent
still returns `done`. A separate native dispute, refund or compensation decision
must use its original owner; it cannot be represented by changing this service's
historical outcome.

The generic planner can conservatively charge a whole reservation when an
unresolved budget expires. Therefore `consumed != null` establishes resource
accounting, not physical execution or successful service completion. An existing
Unknown service pin stays Unknown if the generic close path accounts resources.
Accounted jobs without a service outcome pin are reported as
`resource-accounted-outcome-unobserved`; the adapter refuses to invent a prior
service outcome for them. Their original owner must reconcile the missing fact.

Failed function calls still discard their private transition copy. This module
does not automatically observe an external settlement refusal, a dispatch or
worker termination. Its observer cannot infer those missing facts from silence.
The new outcome pin neither authenticates those events nor supplies durable
restart, independent rollback protection, physical metering or real demand.

## Work credit and task supply

No API here accepts a caller's `qualified` flag, proof-system name, nominal MAC
count or model-quality score as consensus authority. Every settlement report
retains `additional_consensus_credit=0`, and the reused planner still reports
`additional_chainwork=0`. A future work credit must come from the existing
consensus owner after the actual relation, lifecycle cost, selection distribution,
tail and admission obligations are qualified. A service's legitimate optimization
can reduce its actual cost without invalidating its contracted value.

`supply_observation` inspects only the finite supplied contract set, current
reference reservations and the original local resource jobs. Its retained
`pending_contracts` and `conditional_base_reservations` fields explicitly count
**active branch monetary reservations**. They do not count fresh executable
tasks. A reorganization can restore a monetary reservation while its physical
job remains Unknown or has a recorded terminal outcome.

The V2 report exposes each task's branch status, original window, recorded
outcome, resource accounting and reconciliation requirement. It separately
counts unobserved active reservations, recorded Unknown/terminal outcomes,
accounted resources, orphaned resource jobs and expired contracts. These are
different dimensions, not disjoint totals to sum as a task-supply measure.
Completed or Unknown work remains visible even when the selected branch no
longer contains its reservation. Expired contracts cannot become active supply
by keeping, restoring or renaming a monetary claim.

A branch labeled `resolved` need not agree with the original service outcome.
The observer compares both lane outcomes and fee amounts with the immutable
local resolution and exposes `branch_resolution_matches_local`. A later generic
expiry/refund or different branch disposition retains its own facts and remains
a reconciliation requirement. It neither replaces the recorded service outcome
nor authorizes another dispatch or payment.

An active reservation with no outcome observation is labeled `unobserved`.
This is not `NotDispatched`, permission to execute again, or proof that an
honest worker can obtain a fresh eligible task. Every report retains
`execution_dispatch_authorized=false` and `fresh_work_supply_verified=false`.
Only the original dispatch owner can resolve that boundary.

The observer neither creates replacement tasks nor calls a random task useful.
An empty set reports zero pending reservations. A nonempty finite set still reports
`actual_demand_verified=false`, `native_funding_verified=false` and
`liveness_qualified=false`. Sustained task supply, actual external budgets and
pure useful-work consensus liveness are not closed by an accounting example.

## Reproduction and scope

From `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_service_work_settlement_v1 test_reward_budget_oracle
python3 service_work_settlement_v1.py
```

`run_demo()` returns JSON-serializable scenarios using a deliberately synthetic
integer fixture, with these exact reference allocations:

| Scenario | Base fee units | Improvement bonus units | Added consensus credit |
| --- | ---: | ---: | ---: |
| Complete evaluation, no gain | 7 | 0 | 0 |
| Complete evaluation, all frozen improvement gates pass | 7 | 11 | 0 |
| Complete evaluation, retention regression | 7 | 0 | 0 |
| Unknown | 0; original reservation retained | 0; original reservation retained | 0 |
| Invalid service | 0 | 0 | 0 |

These amounts are fixture constants, not prices, protocol reward parameters or
actual transfers. The tests exercise full-output omission, unselected-product
corruption, forged improvement, caller qualification flags, external-context
substitution, strongest-control failure, insufficient clusters, retention loss,
duplicate/relabelled claims, contract pins across branch rewind, wrong funding
lanes, maturity in either lane, atomic partial failure, overrun, expiry and
unknown-result retention. A deterministic copy-boundary control also checks that
external material mutation cannot change the committed execution snapshot.
The continuation checks terminal-outcome substitution after both pre-reservation
and post-reservation branch rewinds, unchanged result bytes and charge vectors,
Unknown reconciliation, paired-pin consistency, expiry, generic resource closing,
unobserved execution and exact external-intent reuse. The earlier retained Unknown
test additionally checks the new private pin while retaining its original
monetary, resource, height and input-immutability assertions.
No test is reported as evidence of trained-model efficacy, independent customer
demand, native payment execution, production adoption or chain security.
