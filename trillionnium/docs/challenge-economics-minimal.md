# Challenge Economics (Minimal Account/Staking Semantics)

## Scope

This patch upgrades challenge handling from **status-only markers** to **minimal real balance movement** while keeping current architecture unchanged.

## Data Flow

1. `apply_challenge(..., challenger, bond, signer)`
   - validates task status (`Revealed`), signer binding (`signer == challenger`), and governance-derived minimum bond.
   - debits `challenger` balance in `StateStore` and credits challenge escrow.
   - records `task.challenge_bond` + `task.challenger` and challenge timing metadata.
2. `apply_resolve(..., slash_worker, resolver, signer)`
   - validates signer against configured governance `resolve_authority` (payload `resolver` is not sufficient by itself).
   - if `slash_worker=true` (challenge succeeds): refunds bond to recorded challenger (plus minimal bounty path if configured by current implementation).
   - if `slash_worker=false` (challenge fails): bond is forfeited to treasury accounting (`treasury.challenge_forfeits`).
3. `apply_timeout` on `Challenged`
   - unresolved challenged timeout now refunds bond to challenger (`challenge_bond_forfeited = false`) instead of forfeiting to treasury.

## Verifiability

- `StateStore` now tracks account balances and includes them in `state_root()` hashing.
- Tests assert pre/post challenger balances for both refund and forfeiture paths.

## Boundary / Known Limits

- Forfeited bond is currently recorded in treasury accounting (`treasury.challenge_forfeits`), but no downstream distribution policy (e.g., validator rewards/burn split) is implemented yet.
- No dedicated `StakeObject` is introduced yet; balances are a minimal in-memory account ledger in `StateStore`.
- Challenge and resolve now both enforce signer-based authorization in PoCO core (`signer==challenger` for challenge, `signer==resolve_authority` for resolve).
- Upstream transaction validation/signature plumbing is still required in production so signer context cannot be spoofed at integration boundaries.
- `resolve_authority` defaults to the literal string `governance.resolve_authority` when governance value is absent; deployments should set an explicit authority account before enabling challenge/resolve flows.
- `set_gov_param_unchecked(...)` bypasses timelock/rate-limit checks by design; production governance execution should prefer `set_gov_param(...)` and restrict unchecked usage to trusted bootstrap/test paths.
- `REVEALED` tasks carry `challenge_deadline_height`; after deadline, unchallenged tasks can finalize via timeout.
- Challenge submission is bounded by reveal-derived `challenge_deadline_height`; late challenges are rejected.
- For legacy Revealed tasks without `challenge_window_blocks_snapshot`, first accepted challenge freezes the effective window into snapshot to keep downstream timing deterministic.
- Challenge/resolve/timeout paths use preflight transfer feasibility checks and centralized challenge-field invariants to fail early on malformed/corrupt states without partial side-effects.
- Terminal proof/collateral retention snapshots are part of the economics boundary, not cosmetic metadata: restore must fail closed if retained challenger identities are non-canonical/reserved or if retained challenge-window / deadline anchors are zeroed, because sponsor-funded audit/refund trails depend on a single canonical payer/challenger record.
