# Release Note — P1 Closure Baseline (2026-02-19)

## Summary
P1 core objectives are now in a deliverable state:
- Worker reliability upgrades landed (phase persistence, tx commit confirmation, startup reconciliation)
- Challenge re-execution lite framework landed (doc + template + e2e demo script)
- Unified acceptance flow now covers P0 + optional P1 + optional reexec checks

## Validation Runs

### 1) Full acceptance bundle
Command:
```bash
./scripts/p0_acceptance.sh --with-p1 --with-reexec
```
Result:
- total: 5
- pass: 5
- fail: 0

Artifacts:
- `data/p0-acceptance/20260219-121950/summary.txt`
- `data/p0-acceptance/20260219-121950/summary.json`

Included steps:
- `check_pouw_commands`
- `smoke_pouw_cli_flow`
- `alpha_acceptance`
- `worker_reconcile_smoke`
- `challenge_reexec_template_smoke`

### 2) Re-execution e2e demo (mismatch path)
Command:
```bash
./scripts/challenge_reexec_e2e_demo.sh mismatch
```
Result:
- challenged task produced successfully
- resolve template generated

Artifacts:
- `data/reexec-demo/20260219-122159/summary.json`
- `data/reexec-demo/20260219-122159/resolve-template.txt`

## Scope Delivered in P1
- `docs/protocol/worker-onchain-integration-v1.md`
- `worker/listener.py` reliability upgrades
- `scripts/worker_reconcile_smoke.sh`
- `docs/protocol/challenge-reexecution-framework-v0.1.md`
- `scripts/challenge_reexec_resolve_template.sh`
- `scripts/challenge_reexec_e2e_demo.sh`
- `scripts/p0_acceptance.sh` optional flags: `--with-p1`, `--with-reexec`

## Known Constraints
- Authority-side `resolve-challenge` execution remains environment/governance dependent.
- Re-execution v0.1 is off-chain replay + on-chain decision writeback (not on-chain deterministic replay).

## Recommended Next Step (P2)
- Add observability stitching by `trace_id` across worker logs, chain events, and reexec artifacts.
- Add one-command authority resolve smoke in environments where authority signing path is available.
