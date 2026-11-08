# Funded demand, independent evaluation and continuous upgrade V1

Status: bounded research composition plus the existing M12 fee-observation repair.
No new consensus revision, economic ledger, model registry, native activation or
Hepta CURRENT authority is introduced. The sole plan remains the
[AI native blockchain development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Existing owners and the actual gap

The [V5 model owner](MODEL_EVOLUTION_V5.md) already resolves complete parent,
candidate and four control models, normalizes updates, checks commit/reveal and
adopts one allocation leaf only for positive native gain. Its controlled public
fixture reaches 24/25, then 25/25, then refuses a zero-gain successor. Three
parameter generations are not three beneficial upgrades. A new round number
does not create an untouched evaluation set.

The [qualified-work statement](../../../../trillionnium/crates/trnm-protocol/src/qualified_work_task.rs)
binds demand, model, inputs, recipe, authorization and output meter, but does not
itself authenticate an escrow or independent customer. The ordinary native Task
instance binds payer, nonce, provider, budget and deadline; it does not by itself
bind the complete request/model/output/dispute contract. These are separate
existing owners whose evidence must be joined by an accepting consumer.

The native maintenance path already defines `ledger-continuity-maintenance`
with `useful_output_credit=0`. See
[continuity](../../../../trillionnium/crates/trnm-mvcc-fee/src/continuity_v1.rs).
It is a development continuity rule, not a new source of business demand or a
qualification of work hardness. This change preserves it.

The [M12 native budget adapter](NATIVE_BUDGET_ADAPTER_V1.md) already accounts for
six resource lanes and observes actual native monetary effects. The conceptual
five economic accounts below are a reporting/eligibility mapping, not a request
to replace those enums or add a second payment database.

## What computation cannot establish

If a real customer and a self-dealing producer submit exactly the same observable
request, matrices, commitments and proofs, a verifier sees identical inputs.
Its output distribution must be the same in both worlds. Neither an arithmetic
proof nor a customer signature can prove the unobserved motivation or beneficial
ownership needed to distinguish those worlds.

The [Pearl empirical preprint](https://arxiv.org/html/2606.04819v2) reports 44
pool-accepted shares from random-matrix mining: three on NVIDIA and 41 on AMD.
CPU/Apple throughput results are separate. This is a reported experiment, not a
reproduction here, and not evidence of 44 forged blocks or universal zero demand.
It supports the distinction between the verification relation and outside use.
Filecoin's [Verified Clients specification](https://spec.filecoin.io/algorithms/verified_clients/)
explicitly locates demand validation in social verification and bounded DataCap;
its page is marked work in progress. Its
[storage-market contract](https://spec.filecoin.io/systems/filecoin_markets/storage_market/)
provides a useful separate precedent for signatures and locked payment/collateral.
Neither mechanism turns payment into a proof of independent demand.

## Frozen service contract and evidence composition

[demand_evidence.py](../../../../formal/pon-nakamoto-v1/demand_evidence.py) consumes
one immutable canonical bundle per contract. Its new `pon-demand-evidence-v1`
signed namespace binds the caller-pinned context and contract. The accepting
owner supplies the expected contract, current anchor, registry root and role keys
outside the producer's bundle. Records have exact schemas and bounded sizes.

The contract binds request identity, requester, provider, actual parent model,
input root, output specification, qualified-work statement, evaluation protocol,
fixed fee schedule, dispute policy, delivery deadline, dispute end and retention
end. It precommits four service/bonus amounts and exact beneficiaries. A positive
evaluation cannot change either the gross or precommitted net evaluation fee.
The improvement beneficiary must be the provider in this Task/Release contract;
an evaluator, auditor or adoption owner cannot receive a result-dependent bonus
through another account. Provider/control conflicts still prevent eligibility.
A zero-priced account requires no
fabricated funding source.

| Evidence | Conditional check | What remains outside the reference |
| --- | --- | --- |
| Request | Exact customer signature and contract commitment | Genuine motivation and lawful authority |
| Funding | Installed owner statement, anchor, payer/payee, original amount, lock and observation windows; distinct sources | Actual native lock/export adapter and fresh chain verification |
| Delivery | Complete output, on-time completion and pinned replay-owner statement | Execution of the correctness proof and real material delivery |
| Acceptance or dispute | Exact customer acceptance or the frozen dispute owner's explicit verdict | Production fair exchange, adjudicator independence and enforcement |
| Evaluation | Frozen protocol, same complete output, fulfilled evaluation, exact result record | Actual prospective experiment and independent evaluator control |
| Availability | Correct output and completed original retention interval | Real storage/repair proof and independent custody |
| Adoption | Exact parent/candidate/evaluation, actual-use receipt and current adopted status | Ordinary Hepta installation, consumer execution, causal net benefit and rollback |
| Payment | Installed native-owner statement with exact source, operation, beneficiary, output, anchor and gross/net amounts | Actual native payment replay; this code never issues a transfer |

Ed25519 authenticates these development statements. It does not qualify PQ
authorization or authenticate the assertions inside a corrupt owner's statement.
The current implementation is an executable composition contract, **not an
implemented native statement exporter**. An arbitrary caller or a synthetic test
key cannot produce a production funding capability. Every result retains
`native_adapter_verified=false`, `independent_demand_proven=false`,
`payment_authorized=false`, `dispatch_authorized=false` and
`production_activation=false`.

`external-attested`, `project-budget`, `self-or-related` and `unknown` remain
separate. An external classification requires a current complete statement from
the pinned common-control auditor. Known shared customer/provider control becomes
related-party activity. Missing, revoked, conflicted or unknown controls cannot
be promoted into external demand. The source registry must be audited by its
existing owner; the composition does not independently reconstruct a global
beneficial-ownership graph. A customer may consume its own purchase: customer and
adopter need not be different people. Evaluator/auditor/producer conflicts still
block the improvement path.

The independently developed
[common-control continuation, PR742](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/742)
contains a more complete registry and control-coalition audit. This work specifies
its receiving boundary; it does not pretend that the full separate PR or real
independent identities have been imported. Observation schema
`pon-demand-composition-observation-v2` retains the audit validity end; later
queue queries recheck it without changing the historical revenue observation.

## Five economic accounts, existing native sources

| Economic account | Existing owner/source mapping | Payment basis |
| --- | --- | --- |
| Chain security | M06 Reward; M12 Mining | Original qualified work, issuance and maturity rules |
| Compute service | Task/Contribution for commissioned training; Quota/Serving for inference | Funded agreed computation and delivery; a completed negative result can be paid |
| Evaluation service | Task/Evaluation | Fulfilled frozen evaluation, independent of whether the result is positive |
| Data availability | Distinct Task/Storage and Task/Repair sources | Original retention/repair obligations and real completed effects |
| Improvement bonus | Release/Contribution | Existing positive-gain allocation plus new external evidence gates before any future production integration |

This continuation reuses the M12 repair from
[PR744's exact source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3e44c471187fc6c883693c836cdae6adae4bdafb/trillionnium/crates/trnm-service-settlement/src/native_budget.rs).
Task/Contribution is now a permitted resource contract. `NoGain` can be observed
as an already-executed fee payment only for Task/Contribution, Task/Evaluation and
Quota/Serving, with recorded resources, a completed effect and exact native
payment readback. Release/Contribution and Reward/Mining remain ineligible for
that exception. Failed/cancelled/unknown outcomes cannot be relabeled after the
fact. `NoGain` with unknown measured cost conservatively charges the full existing
reservation; this does not turn it into an independent physical measurement.

The M12 adapter and Node's separate five-lane local obligation journal are not
the same API. The latter's Contribution prefix remains Release. This repair
does not claim to have expanded both interfaces, implemented a new training worker
or completed the entire commissioned-training service pipeline. Historical
`reward_budget_oracle.py` keeps its original semantics and namespace.

## Delivery, disagreement and empty queues

Complete computation, statistical improvement and delivery are separate facts.
Correct negative training results can support service and evaluation fees. A
missing improvement or missing adoption produces `NoUpdate`/zero improvement
bonus, while preserving fulfilled-contract records.

An unaccepted delivery or an unresolved dispute never silently becomes paid or
refunded. The reference accepts an explicit `pay-service` or `refund` verdict
bound to the original dispute policy, and otherwise retains the missing decision.
Objective arithmetic, retention and subjective quality disputes need their own
owners and evidence. The current native Task still requires the customer's
acceptance for its ordinary fee path; this reference does not install an arbiter
or remove that real fair-exchange gap.

The finite supplied inventory is ordered by externally attested funded tasks,
project-budget tasks, related-party tasks and unknown-origin tasks, then deadline
and contract identity. Expired/settled funding, expired attached provenance,
any observed delivery, a refund or pending dispute, or a different current anchor
is excluded.
This is a queue observation, not global queue discovery or dispatch authority.
An empty eligible inventory returns the **existing native maintenance** mode with
zero useful-output credit. Funding shortages do not create fictitious demand.

## Deduplication, revenue and fiscal limits

The result identity binds context, parent, inputs, output specification and
complete output. It excludes requester, provider, request number, work wrapper,
round, branch and payment address. Two genuine customers can pay separate service
fees for the same result. Those fees remain two payments, but the complete result
counts once and its improvement bonus cannot be observed twice. A complete
candidate artifact can receive at most one observed improvement payment in this
book's entire context, even under a changed input window or parent. A reused adoption
receipt or payment operation also refuses, including across accounts.

This is exact canonical-content deduplication, not a solution to general program
equivalence or arbitrary semantically equivalent tensor encodings. The canonical
input/output owners remain responsible for their admitted semantics.

The complete signed evidence set is validated before any observation changes.
Source reuse, invalid payment category, wrong fixed fee, incomplete delivery,
duplicate result bonus and excess global bonus all refuse atomically. Exact replay
is idempotent. The observable gross improvement total obeys the declared global
cap; the original native source and per-release caps remain separate mandatory
constraints. The reference is not a pre-dispatch reservation/solvency system.

For an attacker controlling payer and provider, a service fee F is an internal
transfer. If the provider receives F and an extra subsidy B, the alliance's net
profit is B minus nonrecoverable external cost, not B minus F. Even B <= beta*F
with beta < 1 therefore does not prove self-dealing unprofitable. A finite cap
bounds fiscal exposure; it does not prove Sybil resistance or independent demand.

Only net service receipts are reported as service revenue, grouped by origin.
Security rewards, evaluation/DA fees and improvement subsidies are separate.
The observer reports unique delivered outputs and repeated complete outputs.
`business_work_reuse_ratio` is null until the complete workload/cost denominator
is supplied by the existing meter owner. A count of results is not a compute
reuse fraction, and repeated lottery work is not new business output.

All duplicate/payment/source identities must survive epochs, branch changes and
restart in the existing durable operations owner. Recreating this in-memory book,
restoring an old host backup or signing a new registry epoch cannot be claimed as
anti-replay protection. This V1 accepts one final evidence snapshot per contract;
incremental receipts require a separately specified reconciliation/export adapter.

## Continuous-upgrade reference and statistical scope

[upgrade_policy.py](../../../../formal/pon-nakamoto-v1/upgrade_policy.py) freezes the
actual parent/candidate, four strong controls, evaluation and canary windows,
data-owner/independence roots, fixed sample count, one cost unit/conversion,
complete declared fixed overhead, per-cluster costs, margin, bet and bonus cap.
It consumes future paired cluster results from a pinned review owner. Frozen
identities and signed conditions are necessary bindings, not proofs of fresh
sampling, independence, truthful costs or causal adoption.

Each begun candidate, including cancellation, failure and timeout, consumes one
global attempt k. Its error budget is alpha_k = alpha/[k(k+1)], alpha <= 0.05.
The telescoping sum is at most alpha. The sequence and proposed-bonus cap do not
restart on a new parent or window within the same retained history.

For each frozen control j, let D_ij be candidate utility minus control utility,
after declared variable costs and the allocated fixed overhead. With a frozen
margin m and deterministic valid bound R, the implementation computes exactly:

```text
Z_ij = (D_ij - m) / R,              -1 <= Z_ij <= 1
E_j  = product_i (1 + lambda * Z_ij),  0 < lambda <= 1
accept only if E_j >= 4/alpha_k for all four controls,
and every observed average net difference exceeds m.
```

All arithmetic is rational; no float/NaN or sign-test approximation supplies a
mean-benefit claim. Under the null E[Z_ij | the complete previous history] <= 0,
each product is a nonnegative supermartingale starting at one. Markov's inequality
at the one frozen sample size (or Ville's inequality for the product process)
bounds false crossing by alpha_k/4 per control. Union bounds across controls and
attempts give a conservative global alpha bound, **conditional on those sampling
and history assumptions**. The controls may share paired observations; they need
not be mutually independent. The implementation performs one fixed-size readout,
not a confidence-sequence inversion or a numeric lower confidence bound.
The product construction follows
[Estimating means of bounded random variables by betting](https://arxiv.org/pdf/2010.09686)
and the [safe anytime-valid inference review](https://arxiv.org/html/2210.01948v2).

Marginal zero means are insufficient: let all 20 ostensibly different clusters
share one fair sign Z. Take alpha=0.05 and lambda=1/2: the positive branch gives 1.5^20 > 160 and
passes the first-attempt threshold with probability 1/2. The nominal per-control
budget is only 1/160. This violates the conditional-mean assumption even if every
row has a new hash. Fresh IDs and future timestamps cannot fix dependent sampling.
The fixed bet is deliberately simple and has a power limitation: for fair-range
signs with P(Z=1)=0.55 and lambda=1/2, the mean gain is positive but the expected
log growth is negative. Thus this gate does not promise to detect every beneficial
update. A future frozen mixture of bets needs its own implementation and tests;
choosing a winning bet after looking at these same data is invalid.

Repeated adaptive use of one exposed benchmark is also excluded. See
[The Ladder](https://proceedings.mlr.press/v37/blum15.html) for a direct analysis of
adaptive leaderboard overfitting. The 2026
[Leaderboard Incentives study](https://proceedings.mlr.press/v306/chen26gf.html)
suggests a future budget-matched tune-before-test experiment under its explicit
game assumptions. That is not a drop-in anti-collusion or consensus theorem.

The progression is frozen attempt -> conditional evaluation eligibility ->
observed canary -> conditional promotion proposal, with explicit `NoUpdate`
outcomes. Parent changes, unknown/revoked conditions, reuse, incomplete costs,
insufficient evidence, absent use, safety failures and exhausted proposal budget
stop progression. The canary is an owner-attested observed-use gate, not a second
statistical efficacy trial. A positive result does not certify all future tasks,
nonstationary deployment gains or uninterrupted improvement.

The existing V5 release owner and Hepta installation/CURRENT/revocation owners
must independently verify and enact any later release. No method in this class
adopts a model, pays a bonus or changes an authorization key. All native,
independence, reward and production authorization flags remain false.

## Verification and remaining acceptance gates

Run from the repository root:

```sh
python3 formal/pon-nakamoto-v1/test_demand_evidence.py -v
python3 formal/pon-nakamoto-v1/test_upgrade_policy.py -v
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-service-settlement --all-targets --all-features
```

The new Python suites are registered exactly once in the original protocol lane;
CI mutation controls reject omission, duplication, moving them or swallowing
their failure. Tests use synthetic keys, owner receipts and model observations.
They are implementation evidence, not externally supplied customers, financial
receipts, independent organizations or measured new model quality.

The initial reference acceptance list is continued by the native
[funded service Task](FUNDED_SERVICE_TASK_V1.md) and
[owner evidence/reconciliation](NATIVE_TASK_EVIDENCE_V1.md) specifications. The
new development Task context admits frozen contract commitments and enforces
the payer's acceptance or frozen arbitrator's disposition through the original
escrow. The native evidence adapter replays retained actual funding and payment
histories rather than accepting caller JSON as native authority. Their exact
source tests and limitations must be assessed separately from the Python tests
above. Neither extension proves the off-chain contents of a commitment, adds a
qualified-work registry membership rule, nor establishes customer independence.

Audited control/funding evidence, fresh cost-matched evaluation with real data
owners, and ordinary Hepta canary/install/next-task/rollback remain distinct
business acceptance requirements. Persistent global dispatch deduplication,
source/epoch/global reservation and independent custody still need their actual
owners. Local histories can reject an old journal when a newer fence survives;
they cannot authenticate a joint rollback of every owner and witness. None of
these requirements can be replaced by a mock receipt or by relabeling a
controlled positive fixture as real demand.
