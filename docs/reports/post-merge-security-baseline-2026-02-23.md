# Post-merge Security Baseline Snapshot (2026-02-23)

## Scope
Merged security PRs:
- PR #5: governance value schema + RPC hard caps + strict real-cli authenticity
- PR #7: PoUW deadline/timeout flow + challenge-bond gates
- PR #8: node timeout auto-scan + event audit field unification + minimal challenge economics

## Baseline gates wired into CI
Updated workflows:
- `.github/workflows/trnm-merge-gates.yml`
- `.github/workflows/rust-l1-nightly-health.yml`

New hard-gate steps added:
- `./scripts/v2/pouw_commit_timeout_migration_test.sh`
- `./scripts/v2/pouw_challenge_timeout_migration_test.sh`
- `./scripts/v2/challenge_bond_enforcement_test.sh`

## Local post-merge validation (executed)
- `cargo test -p trnm-node -p trnm-rpc -p trnm-pouw -p trnm-state -p trnm-types` ✅
- `bash trillionnium-rust/scripts/check_event_fields.sh` ✅
- `./scripts/v2/pouw_commit_timeout_migration_test.sh` ✅
- `./scripts/v2/pouw_challenge_timeout_migration_test.sh` ✅
- `./scripts/v2/challenge_bond_enforcement_test.sh` ✅

## Operational note
- CI checks may still fail to start when GitHub billing/spending limits are not available.
- Gate logic is committed; execution depends on Actions account health.
