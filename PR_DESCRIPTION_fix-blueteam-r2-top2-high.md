## Summary
This PR merges the long-running hardening branch `fix/blueteam-r2-top2-high` into `main`.

It consolidates autonomous micro-iterations across three lanes:
- **laneA (consensus/security):** replay/auth canonicalization, challenge/resolve/timeout invariant hardening.
- **laneB (governance/pause):** emergency_pause checked/unchecked path safety, idempotence, merge-gate expansion.
- **laneC (CLI/RPC):** tx hash/status parser robustness against noisy/variant real-world outputs.

## Why
- Close known medium/high operational hardening gaps.
- Convert many low-risk incremental protections into a tested integrated baseline.

## Validation
- Rebased on latest `origin/main` before final validation.
- `cargo test --workspace` passed on branch tip.
- Post-rebase test stabilization included in commit `61b9256`.

## Risk & Rollback
- Integration risk: **moderate** (large commit set), mitigated by broad test pass.
- Rollback strategy:
  1. Preferred: revert merge commit as a single unit.
  2. If partial rollback needed: revert lane-prefixed commits (`laneA:`, `laneB:`, `laneC:`) selectively.

## Notes
- Pre-rebase local WIP was stashed and is not part of this PR (`wip-before-main-sync-20260227`).
