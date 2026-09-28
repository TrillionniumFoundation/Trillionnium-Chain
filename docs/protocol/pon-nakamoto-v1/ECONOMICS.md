# PoN rewards, conservation and free public intelligence

Status: economic design; no token launch, price, yield, demand or sustainability claim.
Owners M12/M10; inputs M11, custody M09; clients M14 and local Hepta owners.

## E1. Three reward responsibilities

Mining secures fresh ledger history. Its branch-local block subsidy/fee payout follows
valid work and maturity, not model rank or validator stake. Model commons rewards pay
for independently measured improvements actually adopted in a reproducible release.
Service payments compensate approved inference, evaluation, storage and composition
work. A contributor can earn model rewards without mining or hosting; an author going
offline must not remove public parameters or require all inference to call that author.

Genesis/profile must define the asset, atomic unit, finite emission/supply rule,
block-subsidy schedule, maturity, fee allocation, treasury/model/service budgets,
rounding, dust, vesting and maximum liabilities. The reproducible experimental profile fixes valueless test units, subsidy1000,
halving100000, maturity20 and exact command fees in [L1](details/LEDGER_WIRE.md).
No market price or production launch allocation is asserted; production activation stays disabled.
No new votes, consumption-derived weights or slashable-bond ceiling select PoN blocks.
Application service collateral is allowed only under its own explicit contract.

## E2. Exact accounting and reorg

For each asset, sources equal live escrow plus paid services plus refunds plus defined
fee/penalty transfers. Authorized new issuance is accounted once separately from escrow.
Balances and accumulators use checked integers, not floats. Model and inference budget
reservations, reward maturity and spent/nullifier state belong to branch-specific state.

TentativeReward -> MatureClaimable -> Claimed is reverted with the branch when reorged.
A local external payout is NOT undone by reverting SQL rows. Such payouts require the
external-effect protocol, a risk/collateral policy and reconciliation; automatic blind
reissuance after reorg is forbidden. A confirmation threshold never makes a valid deeper
reorg impossible. Header depth and cumulative work are both reported at claim time.

Invalid proofs receive no mining reward. Stale blocks have no active-chain subsidy.
Their useful parameter artifacts can still be assessed on the surviving chain without
relabeling stale mining work as new work. Same contribution lineage/round/budget cannot
pay twice. The canonical chain determines entitlement; off-chain historical delivery
and authorization facts remain separately durable across reorganizations.

## E3. Contribution attribution and finite release budget

For locked reference M, plan pi and admitted contribution set S, define evaluation
value V_pi(M(S)) from declared metrics and serving resources. Compatibility, consent,
safety and authority are hard feasibility checks, not compensable utility weights.
Marginal or sampled-Shapley-like attribution is an estimate with explicit uncertainty,
not a proof of fairness, truth or Sybil resistance. Recomposition/training recipes and
budgets must be equal across compared cases.

A release has reserved budget B. Unlock P in [0,B] according to the preregistered
whole-model improvement rule; no adequate improvement means P=0. For nonnegative
accepted scores s_i, allocate floor(P*s_i/sum(s)); residual atomic units are retained
by the named budget, not minted or assigned via iteration order. A later version may
specify deterministic remainder allocation. A failed/undefined score cannot authorize
payment. Future-window validation can unlock only its already reserved tranche.

Parents, organs and cells share ONE root-work contribution budget. Splitting one expert
into many cells, aliases or accounts must not multiply that budget. Record root_work_id,
accepted version, contribution component and nullifier. Upstream shared weights do not
earn an unbounded hereditary royalty by default; lineage is provenance, not permanent
liability. Exact duplicates can be caught by digest; perturbations and controller
clusters need additional declared tests and independent economic review.

## E4. Challenge and failure treatment

Fraud dispositions require objectively specified evidence or a separately labelled
business arbitration profile. Timeout, low quality, reviewer disagreement or training
nonconvergence is not double signing. Ordinary PoW fork mining is not a PoCO double-vote
offense. Challenge deposits/costs, appeal limits and due-service budgets must be fixed
before admitting obligations. Late evidence cannot silently edit a past valid block;
apply its contract's future task/reward/adoption disposition on the current branch.

Free benchmark access must not expose a permanent reward oracle for unlimited adaptive
search. Bound submissions/evaluation spend, rotate lawful held-out/future tasks, test
copied models and split identities, and disclose remaining collusion assumptions.
No evaluator cartel may exclude an otherwise valid miner or rewrite chainwork.

## E5. Free basic use with a real resource budget

PublicModelAccess permits download/use under a checked public policy. Hosted inference
uses a PublicInferenceBudget sponsored by the network/community or explicitly funded
services. A free request atomically reserves quota and finite provider capacity before
execution; queue pressure yields an honest delay/rejection, never unlimited debt.

    free inference + evaluation + model rewards + reserved future obligations
        <= funded usable budget + separately accounted committed in-kind resources

Do not add token-denominated balances and GPU-hours without a fixed conversion contract.
Token issuance is not physical GPU supply or guaranteed purchasing power. Base access
can be free without promising unlimited hosted capacity. Contribution credits can add
quota, but anonymous new users need not first contribute a model. Anti-abuse controls
and identity assumptions are explicit; an account id does not prove one human.

Meter a root request once, attribute resource use across experts rather than duplicating
shared-base charges, and bind request/payout identities. Sponsor/provider self-traffic,
reciprocal requests, feedback farming and Sybil quota amplification are explicit tests.
Training/export consent is separate from accepting free service.

## E6. Resource and cost observability

Report useful adopted improvement per training/evaluation/serving resource, proof
overhead, actual utilization, free-tier acceptance/queue tails, independent provider
concentration, treasury runway in its declared unit and unfunded obligations. Separate
failed work, stale mining, unreused artifacts and useful contractions. Do not equate
matrix FLOPs, parameter uploads, rewards emitted or token activity with useful AI.

[Exact evaluated-score publication, bounded claims and prepaid free-use rules](details/LEDGER_WIRE.md)
are executable. [The controlled real-model campaign](details/MODEL_EVALUATION.md) binds
actual artifacts/observations to these transitions without claiming independent economics.
