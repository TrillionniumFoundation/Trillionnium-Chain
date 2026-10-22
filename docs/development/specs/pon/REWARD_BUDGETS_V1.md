# Five-lane reward and capacity budget reference V1

Owner: M12. This is an executable, non-activated accounting reference for PN4 in
the [sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Its namespace is `pon-five-lane-budget-reference-v1`. It changes no historical
transaction, root, issuance, signature domain, reward allocation or chainwork.

## Existing sources and five separate liabilities

| Lane | Funding fact supplied by the existing owner | Separately reserved resource units | Upstream qualification still required |
| --- | --- | --- | --- |
| Mining | One unique native block reward; the existing subsidy plus collected fees | Verified work units and CPU ns | Full W1 validity, required target, active branch and reward maturity |
| Contribution | Sponsor-debited release escrow | Training CPU ns and parameter bytes | Whole-model improvement, independent evaluation, root/source attribution and exact allocation membership |
| Evaluation | Explicit sponsor-debited evaluation escrow | Evaluation CPU ns and evaluated examples | Complete evaluation contract, evidence identity, independent control and result availability |
| Storage | Explicit owner-debited retention/repair escrow | Retained byte-blocks and repair bytes | Custody duration, actual retrieval/repair, independent replicas and contract deadlines |
| Serving | Explicit sponsor/consumer-debited service escrow | Inference CPU ns and output tokens | Original consent, provider/output/units, target-side delivery and quotas |

No percentages, new mint, launch prices or perpetual royalties are introduced.
Mining reads the existing development schedule from
[devnet-v1.json](../../../../config/pon/devnet-v1.json); it requires the registered
amount to equal subsidy plus fees and retains its configured maturity.
The model-contribution root cap cannot exceed the current
[source-round ceiling](../../../../config/pon/model-evidence-v3.json).
That is a conservative current-profile bound, not an economic recommendation.
Root/source identity and hidden common control remain upstream owner obligations.

## Executable boundary

[`reward_budget_oracle.py`](../../../../formal/pon-nakamoto-v1/reward_budget_oracle.py)
accepts independently authenticated source identities and original amounts as
**premises**. It does not authenticate them, debit a native account, evaluate a
model, measure capacity, issue money, dispatch an effect or grant local authority.
The returned report always states `native_funding_verified=false`,
`public_reward_eligible=false`, `production_activation=false` and
`additional_chainwork=0`.

Each original source identity registers once per branch and belongs to one lane;
an exact fork replay cannot change its original amount, lane or maturity. Multiple
budgets may draw only from that source's remaining funds. Every budget pins its
cap, resource units, maturity and deadline before claims. Monetary units never
substitute for GPU, disk, bandwidth, repair or evaluator capacity. Native source
verification and actual physical resource backing are required before activation.

Reservation atomically checks funds, lane-specific resource capacity, stable
subject uniqueness and the shared contribution-root cap. Splitting a known root
across cells, accounts or budgets preserves that cap. This does not discover
concealed common control or prove arbitrary model equivalence.

Resolution pays at most the reservation, only for an independently determined
positive outcome inside the maturity/deadline window. No-gain, invalid, unknown
and cancellation pay zero. Failed work still consumes its reported resources;
an unmeasured outstanding job at expiry conservatively consumes its entire
reservation. Unspent monetary funds return to their original source at deadline.

For every source: `available + sum(budget cap - refunded) == original funding`.
For every lane: `cap == available + reserved + paid + refunded`.
Resource consumption and remaining reservations must stay inside each original
resource cap; there is no implicit exchange rate between lanes or units.

## Reorganization and external effects

Reference branch checkpoints contain funding, budgets and claims. They exclude
the local monotonic physical-resource and external-intent journals. Pending
resource reservations keep occupying capacity after a fork; completed work keeps
its cost. An exact reservation retry returns `pending`/`done` instead of opening
fresh resource capacity. Renaming the same subject, changing its reported cost or
repinning a budget to larger capacity refuses. Orphaned pending work conservatively
charges its whole reservation at expiry; orphaned resource jobs remain visible.
An external intent is recorded before any
external dispatch; an unresolved intent returns `pending` and requires target-side
reconciliation. Exact completed retry returns `done`; an altered operation,
beneficiary or effect under the same stable lane/subject refuses. A separate
monotonic global operation index binds the complete lane, subject, claim, budget,
beneficiary, effect and paid amount. Reusing an operation under a different
subject or lane refuses before either index changes, including after a fork.
Completion checks the same global full-intent binding; it cannot finish a different
subject's pending operation. Both indexes share the finite record bound; exact
pending/done retry consumes no new slot. A branch rollback cannot remove either
pending or completed external facts.

This process-local model provides neither a durable journal nor atomicity between
chain settlement and a remote target. The existing
[service kernel](../../../../trillionnium/crates/trnm-service-settlement/README.md)
also explicitly lacks a branch/undo adapter. That native adapter, durable crash
recovery, proof-backed funding, actual storage/serving receipts and independent
economic acceptance remain required. A checkpoint or reference test cannot close
them.

## Executable controls

Run `python3 -m unittest -v test_reward_budget_oracle` from
`formal/pon-nakamoto-v1`. Controls exercise all five funded lanes, subsidy/halving
and maturity, duplicate source/claim, cross-lane funding, resource substitution,
root splitting, zero-gain costs, expiry/refund, overflow/numeric aliases, and a
rollback through both pending and completed external facts. Existing native
release/quota conservation remains covered by
[M12](../../../modules/M12_SETTLEMENT_TECHNICAL_SPEC_V1.md).
