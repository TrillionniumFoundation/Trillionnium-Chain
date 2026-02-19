# P1 Negative Coverage (Adversarial Paths)

Last updated: 2026-02-19

## Goal
Make adversarial and failure paths reproducible and regression-testable before testnet hardening.

## Suite Entry

```bash
# precondition: dev chain already running (recommended: cd chain && ignite chain serve)
./scripts/p1_negative_suite.sh
```

Artifacts:
- `data/p1-negative/<timestamp>/summary.txt`
- `data/p1-negative/<timestamp>/summary.json`
- per-step logs in same directory

Summary status model:
- `PASS`: case assertions satisfied
- `FAIL`: case assertion failed or runtime error
- `SKIP`: precondition unmet (currently used by challenge_path when challenger deposit balance is insufficient)

## Current Cases

1. **unauthorized_authority_calls**
   - Script: `scripts/scenario_D_slash.sh`
   - Checks:
     - unauthorized `resolve-challenge` must be rejected
     - unauthorized `slash-worker` must be rejected

2. **timeout_path**
   - Script: `scripts/scenario_B_timeout.sh`
   - Checks:
     - timeout transition behavior is valid and observable

3. **challenge_path**
   - Script: `scripts/scenario_C_challenge.sh`
   - Checks:
     - challenge flow executes with expected lifecycle transitions

4. **restart_reconcile_recovery**
   - Script: `scripts/worker_reconcile_smoke.sh`
   - Checks:
     - worker local state can recover finalized phase after restart/reconcile

5. **forged_reveal_rejection**
   - Script: `scripts/scenario_F_forged_reveal.sh`
   - Checks:
     - reveal with commit/reveal mismatch (salt mismatch) must be rejected

6. **duplicate_reveal_rejection**
   - Script: `scripts/scenario_G_duplicate_reveal.sh`
   - Checks:
     - second reveal on an already revealed task must be rejected

## Planned Additions

- reveal timeout edge (boundary block-height behavior)
- sequence replay rejection under rapid re-broadcast

## DoD (P1 negative baseline)

- Single command runner with non-zero exit on any failed case ✅
- Machine-readable summary + archived logs ✅
- At least 6 adversarial/failure paths with reproducible scripts ✅
- Planned edge cases tracked for next iteration ✅
