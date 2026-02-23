# Challenge Economics (Minimal Account/Staking Semantics)

## Scope

This patch upgrades challenge handling from **status-only markers** to **minimal real balance movement** while keeping current architecture unchanged.

## Data Flow

1. `apply_challenge(..., challenger, bond)`
   - validates task status (`Revealed`) and governance min bond.
   - debits `challenger` balance immediately in `StateStore`.
   - records `task.challenge_bond` + `task.challenger`.
2. `apply_resolve(..., slash_worker)`
   - if `slash_worker=true` (challenge succeeds): refunds bond to recorded challenger.
   - if `slash_worker=false` (challenge fails): bond remains forfeited (MVP lock/burn semantics).
3. `apply_timeout` on `Challenged`
   - challenge expires as failed; bond is forfeited.

## Verifiability

- `StateStore` now tracks account balances and includes them in `state_root()` hashing.
- Tests assert pre/post challenger balances for both refund and forfeiture paths.

## Boundary / Known Limits

- Forfeited bond does **not** yet route to treasury/validator reward pool; it is effectively burned/locked in MVP semantics.
- No dedicated `StakeObject` is introduced yet; balances are a minimal in-memory account ledger in `StateStore`.
- No transfer/nonce/signature checks are added for challenge actor in this patch (kept out-of-scope for minimal change).
