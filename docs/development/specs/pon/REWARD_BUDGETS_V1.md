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

## Native Node funding observations and durable local obligations V1

The existing Node single SQLite writer now exposes `reserve_native_budget_v1`,
`settle_native_budget_resources_v1`, `prepare_native_budget_effect_v1` and
`finish_native_budget_effect_v1`. Their implementation is in
[`native_budget.rs`](../../../../trillionnium/crates/trnm-pon-node/src/store/native_budget.rs)
and its [source relations](../../../../trillionnium/crates/trnm-pon-node/src/store/native_budget_relation.rs).
This is the native persistence path, without another database, global supervisor,
operation journal or consensus transaction. Fresh records use the existing
`metadata` table under `pon-native-budget-v1:*` and schema
`pon-native-budget-obligation-v1`; the historical DDL/root/signature domains stay
unchanged. Existing migration refuses these additional local facts rather than
silently dropping them.

Mining observes an actual retained `reward:` row, contribution a `release:` row,
evaluation/storage a `task:` row, and serving a `quota:` row. The signed M06
transaction history and complete State checks supply amounts, owner, maturity,
deadline and the exact source-value digest. Direct payees must equal the actual
provider/miner owner. Contribution must replay the existing allocation Merkle
proof for the exact candidate/payee/score and amount. Evaluation/storage task
purpose and local funding policy remain protected-owner inputs; this generic
task escrow does not certify the real evaluation or storage service.

The complete operation/request, source tip/generation and funding observation
persist before local work may be associated with them. One source cannot acquire
different lanes, resource caps or original funding claims through another
operation. Summed monetary reservations are bounded by the observed native funds;
pending resource reservations and reported consumed units share the original
source resource cap. A global operation is one metadata primary key, so changing
its subject, lane, payee, source or declared allocation refuses.

**Caps, resource reservations, and consumption reports are local-owner inputs.**
This increment does not connect them to the scoped resource-owner CPU meter,
worker settlement, GPU supply or storage measurements. An input overrun beyond
its reservation currently refuses rather than recording a qualified physical
overrun. This cannot be described as complete worker accounting. The Python
reference's current 100,000/source-round contribution ceiling and this native
source-local escrow cap have different scopes; native release admission retains
its own source-round rules. No new public economic limit is inferred.

At most 128 records of 8,192 bytes plus one set-head record are retained. SQL
limits the row count and returns at most one byte beyond each record's byte bound
before owned JSON decoding. Metadata keys are also byte-length checked and
truncated in SQL before UTF-8 decoding, including oversized Unicode keys.
Strict decoding, canonical bytes, exact context,
source totals and a complete set-head digest are checked. Operation and head
updates share the existing immediate transaction, compare the previous bytes,
and read back the complete resulting set before COMMIT. Ignored SQL writes or
partial row corruption cannot publish a single-index success. Cold open also
replays the original source from the retained historical native State. This is
local corruption detection, not resistance to an administrator replacing the
entire database and all local trust anchors.
In particular, a consistently restored old complete set, or removal of all budget
records including their head, has no external anti-rollback anchor here. A complete
removal is indistinguishable from an unused namespace. Partial record/head changes
and CAS/readback failures are local-integrity errors that require owner stop;
ordinary input-capacity refusal is not promoted to that origin.
These are optional new metadata records; an older binary may ignore that prefix.
Software downgrade prevention and preservation of local facts therefore remain
the existing release owner's responsibility, not a property of this record hash.

These metadata facts do not participate in branch KV undo. Pending reservations,
reported cost and pending/completed effect facts survive reorganization and
reopen. A new effect intent requires the original source tip to remain canonical,
its exact funding value to remain unchanged, and maturity/deadline to hold.
Already spent, cancelled, changed or orphaned funds deny that economic condition.
An existing target receipt may still be recorded for a retained orphaned intent,
with `funding_current=false`, so recovery preserves what occurred rather than
claiming a new payment. These are durable intent/receipt records, not exactly-once
external actuation or independently authenticated target receipts.

Every native observation retains `chain_funds_locked=false`,
`payment_executed=false`, `execution_authority=false` and
`production_activation=false`. Existing on-chain spend/cancel commands remain
authoritative; these local reservations do **not** lock their escrow. Native
funding locks/debits, actual payment/undo policy, effect-owner authorization,
durable measured worker debt, custody/serving receipts and independent economics
remain open. A successful source observation or local intent cannot close PN4.

Executable native selectors:

- `store::native_budget::tests::native_signed_funding_and_exact_operations_survive_both_backends_reopen`.
- `store::native_budget::tests::fork_or_spent_source_denies_new_intent_but_preserves_resource_and_target_receipt`.
- `store::native_budget::tests::transaction_failure_leaves_no_partial_record_head_or_double_resource_charge`.
- `store::native_budget::tests::cold_open_refuses_deleted_oversized_and_forged_funding_records`.
- `store::native_budget::tests::native_mining_funds_keep_maturity_and_do_not_create_payment_authority`.
- `store::native_budget::tests::abrupt_exit_preserves_committed_resource_reservations_and_pending_intent`
  selects its explicit subprocess worker and exits without Rust destruction in
  both reserved and pending-intent phases. It tests committed WAL recovery,
  not physical power loss or target-side actuation.
- `objective_release_shared_source_reward_reopen_and_review_fork_are_native` in
  the existing [signed release integration](../../../../trillionnium/crates/trnm-pon-node/tests/model_evidence_v3.rs)
  also checks a real release's native budget funding and wrong-payee refusal.

Selectors require execution on their exact source; their presence is not a pass.
