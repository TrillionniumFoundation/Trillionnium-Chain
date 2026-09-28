# M12 Mining rewards, model contribution allocation and free-use budgets — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M12; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/ECONOMICS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own deterministic asset accounting and three separate economic responsibilities: mining reward
maturity, adopted-model gain rewards and actual serving/evaluation/storage payment.
Consumption-derived voting power and validator-weight phases are retired from the target.

## PoN Interfaces

RecordTentativeMiningReward; MatureReward; ClaimAllocation; ReserveModelBudget;
AllocateContributionGain; ReservePublicInferenceBudget; SettleService; ReorgEntitlement. Every
operation binds asset, branch, predecessor, task/release and deduplication identity.

## PoN State machine

Apply fixed genesis/profile issuance, fee and maturity rules only for active valid-chain blocks.
Unlock a bounded model pool only for credible whole-model improvement under the locked plan;
zero gain pays zero. Allocate accepted nonnegative contribution scores using exact floor
arithmetic and retain dust. Root work has one budget across parents/experts/cells. Fund and
reserve bounded public inference before service, separately accounting tokens and in-kind
resources.

## PoN Persistence and recovery

Account balances, claim nullifiers, subsidy maturity and release entitlement revert with branch
state. Actual off-chain delivery/payout observations do not. Reconcile orphaned external effects
under a declared policy before reissuing; SQL rollback does not recover money or undo an API
call.

## PoN Resource bounds

Finite emission rule, per-release/period budget, service capacity, maximum liabilities,
evidence/appeal horizon and claim batch work. No guessed launch token price, infinite reward
stream, permanent automatic lineage royalty or unlimited free tier.

## PoN Security

Identity-splitting/near-duplicate experts, reciprocal free traffic, copied parameter rewards,
same-root double attribution, dust overflow, fake capacity and blind reorg replay. Normal fork
mining is not PoCO double signing; service timeout is not objective fraud.

## PoN Verification and evidence

Conservation through reorg/restart, zero score and no-gain allocation, floor/dust, repeat
claims, split contributions, reward maturity crossed by deep fork, insufficient sponsor funds,
free-tier Sybil load and non-idempotent external payout recovery.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-service-settlement`](../../trillionnium/crates/trnm-service-settlement/README.md): `cargo test --locked -p trnm-service-settlement --all-targets --all-features`.
- [`trnm-escrow-vault`](../../trillionnium/crates/trnm-escrow-vault/README.md): `cargo test --locked -p trnm-escrow-vault --all-targets --all-features`.
