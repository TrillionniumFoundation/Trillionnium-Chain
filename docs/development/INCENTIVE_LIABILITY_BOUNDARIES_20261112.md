# Incentive liability boundaries, 2026-11-12

Status: **HOLD**. This is a source audit and a focused regression inventory,
not a second development plan. The
[sole development plan](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains its ownership and release gates.

Audited baseline:
`4a59131acdf9b8c3210c9b6cd728aeb6c48291fc` (PR #939).
New source tests must be attributed to the exact successor on which they run.
Their presence in this document does not claim execution or production adoption.

## Existing mechanisms and exact limits

| Owner/path | Implemented property | Remaining liability boundary |
| --- | --- | --- |
| M10 portable Task kernel | Task creation debits the funding account. Lease acceptance atomically consumes available bond funds, increases held funds, locks task escrow and checks versions and conservation. | The bond stores aggregate held funds rather than an explicit per-obligation bond-reservation object. The command set ends at provider acceptance; there is no complete audit, adjudication, slash, release or exit lifecycle. |
| M12 portable bilateral settlement | A positive challenge delay, exact result/escrow/rollup versions and one-shot settlement conserve the escrow. | No Challenge, Adjudicate or Slash command; no provider bond or actual audit-resource owner. Final-valid result state comes from its bootstrap trust bundle. Waiting for a height does not establish dispute execution. |
| M12 escrow vault | Each request lock debits available balance; release or slash consumes that lock once. | Pure in-memory reference. Owner-authorized release has no liability-maturity proof. It is not a durable Node balance authority. |
| M06 ordinary Task tags 2-5 | Payer debit funds the native task; provider delivery and payer acceptance lead to native payment; outstanding funds expire to the payer. | No provider collateral. Payer acceptance can pay immediately after delivery. No sampled-audit, adjudication-loss or clawback lifecycle is implemented by these tags. |
| M06 funded-service V1 | A fresh opt-in contract binds delivery/dispute deadlines and arbitrator pay/refund decisions to the existing native task owner. | Customer acceptance and arbitrator payment still pay the entire obligation directly. There is no provider-bond input or funded audit/adjudication resource lifecycle. Distinct keys do not prove independent control. |
| M12 native budget and Task V2 | Local durable resource/effect accounting retains Unknown and historical effects. Task V2 has native-owner reservation and a shared one-time begin fence across local journals. | A local monetary reservation is not a new native coin lock. These fences do not by themselves implement collateral, executable penalties or reward maturity tied to liability extinction. |

Source owners:

- [M10 store](../../trillionnium/crates/trnm-task-kernel/src/store.rs),
  [types](../../trillionnium/crates/trnm-task-kernel/src/types.rs) and
  [candidate scope](../../trillionnium/crates/trnm-task-kernel/README.md).
- [M12 settlement engine](../../trillionnium/crates/trnm-service-settlement/src/engine.rs),
  [types](../../trillionnium/crates/trnm-service-settlement/src/types.rs) and
  [candidate scope](../../trillionnium/crates/trnm-service-settlement/README.md).
- [M12 escrow reference](../../trillionnium/crates/trnm-escrow-vault/README.md).
- [M06 native executor](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs) and
  [funded-service contract owner](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/funded_service_v1.rs).
- [Native budget](../../trillionnium/crates/trnm-service-settlement/src/native_budget.rs) and
  [Task V2 owner fence](../../trillionnium/crates/trnm-service-settlement/src/native_budget/task_operation_v2.rs).

M10 and portable M12 are local monotonic kernels, not the Node branch backend.
Their separate passes must not be combined into an unexecuted cross-owner
economic guarantee. The V2 begin fence must not be replaced with a new local-only
reservation path.

## Focused shared-bond regression inventory

The new methods are in the retained
[M10 test module](../../trillionnium/crates/trnm-task-kernel/src/tests.rs).
They execute signed commands through the existing SQLite kernel without changing
its implementation or adding an economic owner.

Three distinct tasks each reserve 220 units from the original account and use
50-unit provider payment caps. Their aggregate 660-unit charge stays within the
original 700-unit capability budget. All three bids are admitted before any
lease consumes collateral. The shared provider bond has 200 units and the
existing per-lease hold is 100 units.

| Method | Required observation |
| --- | --- |
| `shared_bond_outstanding_leases_exhaust_collateral_without_partial_commit` | Two separate active leases consume 200 bond units. A third signed lease with current versions is refused. Task, escrow, nonce-bearing state, operation journal and committed-block journal remain unchanged after refusal; reopened state retains both holds. |
| `shared_bond_stale_handle_rechecks_collateral_and_preserves_rejected_nonce` | A second already-open handle cannot use the old bond version after the first lease commits. Rejection leaves the complete durable heads unchanged. A newly signed current-version command can then use the still-unconsumed authorization nonce. |
| `shared_bond_ack_loss_reopen_and_exact_replay_keep_one_hold_per_lease` | Not-applied acknowledgment loss leaves no hold; applied acknowledgment loss persists exactly one. Reopening and exact replay preserve it. A second obligation adds one further hold, and replaying the first cannot add another. |

These cover simultaneously outstanding liabilities and stale handles. They do
not claim simultaneous-writer liveness through the strict SQLite sidecar refusal
boundary. Acknowledgment-loss cases use the existing explicit fault-injection
API; they are not an unperformed process-kill campaign.

Run from `trillionnium` after the required project preflight:

```bash
cargo test --locked -p trnm-task-kernel --lib shared_bond_ -- --nocapture
cargo test --locked -p trnm-task-kernel --all-targets --all-features
```

Keep raw command results, source identities and failures separately. A test
definition, old source pass or source-only check is not a current native result.

## Required native liability lifecycle

A future registered profile must use the existing M06 monetary owner and a
fresh signed/stored namespace. It must bind the obligation, source/provider,
task or release, collateral asset and amount, audit plan, adjudication policy,
reward maturity and authorized internal distribution before execution.

Every unresolved obligation needs a funded reservation that cannot be reused.
Collateral, pending reward, audit fees and adjudication fees are distinct
accounting objects. An exit cannot release funds while the covered obligation
or dispute remains unresolved. Payment maturity requires its specified audit
and adjudication conditions; missing or unavailable evidence cannot be treated
as a successful challenge-free close.

Any slash or release must bind its exact obligation and unique decision. Replays,
partial commits and acknowledgement loss must preserve the original outcome.
Chain reorganization must not erase local physical costs, revocation history,
provider begin fences or unresolved external effects. A caller must reconcile
an uncertain operation under its original identity.

M06 currently enumerates four monetary namespaces:
`quota:`, `release:`, `reward:` and `task:`.
A new collateral namespace requires the complete supply relation, mandatory
expiry/maturity, authenticated obligation-range producer/verifier, replay,
reorganization and conservation tests to be updated together. Adding a payout
check without these owners would leave the new funds outside the original
complete accounting relation.

The existing bootstrap/bid/lease checks also do not specify a conversion rule
between bond and payment assets. A successor must define denomination and
valuation explicitly; an unexplained cross-asset haircut or same-asset rule
must not be inferred from integer balance conservation.

## Economic model boundary

For a mathematical example with independent per-task detection probability
`p=0.05`, saved cost `c=1`, one shared bond `S=25`, at most one slash,
already-final payments and no other recovery:

```text
G(k) = k*c - (1 - (1-p)^k)*S
G(1) = -0.25
G(100) = 75.1480132305...
```

These are model values, not measurements of this implementation or a market.
The M10 reservation rule already prevents unbounded reuse of the same available
bond inside one correctly initialized store. This example must not be reported
as a reproduced M10 double-booking exploit.

Independent per-obligation collateral would change the loss term under an
appropriate execution model. Cancelling all still-unmatured rewards on one
detection changes it again. Therefore future payoff analysis must consume the
actual payment, audit, adjudication, slash, refund and exit sequence. Effective
detection probability must include adjudication and executable-loss failure;
correlated probabilities cannot be multiplied without justification.

## Open acceptance boundaries

- Native per-obligation collateral ownership and actual denomination/valuation.
- Funded audit and adjudication availability before final payout.
- Executable penalty, reward-delay, exit and recovery transitions in one profile.
- Strategy- and history-specific effective detection and worst-case payoff.
- Unknown common control, collusion, truthful reporting and global fairness.
- Full integration and production qualification under the existing plan gates.

This document does not close those boundaries or authorize deployment.
