# GA Release Checklist (Rust L1 P2.2)

Date: 2026-02-20
Status: EXECUTED (owner override GO)

## Execution Record
- Release published: `rust-l1-p2.2-ga-20260220`
- URL: https://github.com/ProfAlexQI/TrillionniumChain/releases/tag/rust-l1-p2.2-ga-20260220
- Post-merge mainline checks green:
  - nightly: https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22217929438
  - preflight: https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22217930662
  - merge-gates: https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22218059479

## 0) Preconditions (must all be true)
- [ ] `docs/GA_GO_NO_GO.md` decision = `GO`
- [ ] Stage2 observation window >=24h and no hard-fail regression
- [ ] Testnet preflight consecutive >=2 successes (`status=GO`)
- [ ] Clean-environment `release_rc.sh` reproduction pass is still valid

## 1) Evidence Freeze
- [ ] Pin latest nightly run IDs (last 5)
- [ ] Pin preflight evidence files:
  - `trillionnium-rust/run/preflight/go-no-go-*.txt`
  - `trillionnium-rust/run/preflight/preflight-*.log`
- [ ] Pin state-root audit + bench artifacts referenced in preflight

## 2) Versioning / Tagging Plan
Recommended GA tag format:
- `rust-l1-p2.2-ga-YYYYMMDD`

Example:
- `rust-l1-p2.2-ga-20260220`

## 3) Release Notes Skeleton
Include:
1. Scope (Rust-native L1 mainline)
2. v1 interface freeze commitment
3. Gate results summary:
   - nightly green streak/window
   - preflight consecutive GO
   - clean-env reproduction pass
4. Known advisories:
   - `tuning-recommended` is non-blocking
5. Upgrade / rollback pointers:
   - `docs/runbooks/rust-l1-testnet-readiness.md`
   - `docs/runbooks/rust-l1-rollback-runbook.md`

## 4) Command Draft (execute only after GO)
```bash
# in repo root
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain

# sanity
git checkout main
git pull --ff-only

# tag
TAG="rust-l1-p2.2-ga-$(date +%Y%m%d)"
git tag "$TAG"
git push origin "$TAG"

# create GitHub release (adjust notes file path if needed)
# gh release create "$TAG" -R ProfAlexQI/TrillionniumChain \
#   --title "Rust L1 P2.2 GA" \
#   --notes-file docs/releases/RUST_L1_P2_2_GA.md
```

## 5) Post-Release Verification
- [ ] `gh release view <TAG>` confirms publish success
- [ ] `gh run list` latest nightly remains green
- [ ] `docs/P2.2_POST_RC.md` and `STATUS.md` updated with GA record

## 6) Abort Conditions (No-Go fallback)
If any item fails before tagging:
- Stop publish flow immediately
- Update `docs/GA_GO_NO_GO.md` back to `NO-GO`
- Record blocker + action owner in `docs/stage2-observation.md`
