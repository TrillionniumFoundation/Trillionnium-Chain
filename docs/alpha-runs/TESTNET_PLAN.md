# Trillionnium Testnet Plan (Minimal)

## Scope
Only validate production-relevant paths. No new feature expansion.

## Hard Rules
1. `TRNM_ENABLE_DEV_RESOLVE` MUST remain unset.
2. D positive path MUST use governance/module-authority route.
3. Acceptance is data-driven (status + stake + tx evidence), not log-only.

## Testnet Gate Checklist
- [ ] Dev resolve gate disabled on all validator/fullnode processes.
- [ ] Governance route for `MsgResolveChallenge` is documented and executable.
- [ ] A/B/C/E scripts run cleanly in testnet timing conditions.
- [ ] D positive resolved only via gov path (no local bypass).

## Execution Phases

### Phase 1 — Environment readiness
- Confirm chain-id / RPC / keyring / gas policy.
- Confirm governance proposal flow and voting period.
- Confirm monitoring for tx confirmation and event indexing.

### Phase 2 — Functional validation (N=3 rounds)
For each round:
1. Run A (happy)
2. Run B (timeout)
3. Run C (challenge)
4. Run D positive via gov route
5. Run E (unbonding cooldown)

Pass criteria per round:
- A/B/C/E all pass.
- D positive ends with task status `SLASHED(6)` or expected configured terminal status.
- Worker stake delta matches `worker_slash_percent_on_bad_result`.

### Phase 3 — Stability sign-off
- 3/3 rounds pass with tx hashes archived.
- Publish short risk memo and go/no-go.

## Required Evidence
- Tx hash for each scenario step.
- `show-task` snapshots before/after resolve.
- `show-worker` stake before/after slash.
- Acceptance report artifacts path.

## Exit Criteria
- Governance resolve path proven on testnet.
- No reliance on dev-only bypass.
- Repeatable success across 3 rounds.
