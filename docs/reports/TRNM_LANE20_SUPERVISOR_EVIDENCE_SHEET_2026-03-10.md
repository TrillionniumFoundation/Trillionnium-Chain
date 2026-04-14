# TRNM Lane 20 Supervisor Rollup / Evidence Sheet — 2026-03-10

> Scope note: this document is a **historical evidence rollup**, not the current release-readiness truth source. It must not be cited as current release sign-off. For current release/readiness status, see the repository-root `RELEASE_READINESS.md`.
>
> BL09 retirement-prep note: retained `trnm-pouw`, PoUW, or verification / lane evidence wording in this historical rollup is migration-era compatibility and provenance / audit evidence only. It must not be read as current default payout authority or as re-authorizing the default work-unit payout path once PoCO settlement is primary.

## Scope

This sheet consolidates **only verifiable evidence** for the expanded TRNM lanes currently present in the workspace.

Evidence sources used:
- local git refs / commits / worktrees
- committed file paths and diff stats
- `memory/2026-03-09.md` and `memory/2026-03-10.md`

Evidence sources **not** assumed:
- unlogged subagent claims
- inferred test passes without a recorded command/result
- branch intent from names alone

## Repo snapshot

- Repo: `/Users/qianqi/.openclaw/workspace/TrillionniumChain`
- `origin/main`: `0b209289`
- Current checked-out branch: `fix/laneD-week7-closeout-20260310`
- Current branch head: `4acb4141` `test(trnm-pouw): add zk vector backend path coverage`
- Current worktree is **dirty** (uncommitted changes present), so branch tip and working tree must be distinguished during integration.

Dirty files observed at collection time:
- `.github/workflows/rust-l1-nightly-health.yml`
- `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
- `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
- `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`
- `scripts/v2/pr6_daily_security_summary.py`
- `trillionnium/crates/trnm-state/tests/m1_pause_resolve_escrow_invariant.rs`
- `trillionnium/scripts/nightly_attribution.sh`
- `trillionnium/scripts/run_consensus_fault_matrix.sh`

## Executive rollup

| Lane | Branch / ref | Verifiable head commit | Evidence status | Tests status | Main blocker / gap |
|---|---|---:|---|---|---|
| Lane 03 | `docs/lane03-zk-payload-spec-20260310` | `d2340f9e` | Present | No explicit run log found | Branch is stacked on earlier non-lane03 commits; lane-specific validation not isolated |
| Lane 09 | `fix/lane09-preexec-hang-20260310` | `62597be3` | Present | No explicit run log found | Single code fix, but no accompanying test or run evidence located |
| Lane 11 | `fix/lane11-mempool-baseline-red-20260310` | `87788143` | Present | No explicit run log found | Stacked branch; lane11-only delta is small but branch carries unrelated ancestry |
| Lane 12 | `fix/lane12-retry-fairness-contract-20260310` | `6f494b0b` | Present | No explicit run log found | Tip commit is docs-only; no direct retry-fairness execution proof located |
| Lane 16 | `lane16/integration-batches-20260310` | `5313d3d4` | Present | No explicit run log found | Tip commit is docs normalization; integration meaning not independently evidenced |
| Lane 18 | `fix/lane18-proof-metrics-20260310` | `2828ee32` | Present | No explicit run log found | Branch contains useful code/docs, but no recorded proof-metrics command output found |
| Lane D (real backend) | `fix/laneD-real-backend-20260310` | `83c2f9a6` | Present | No explicit run log found | Tip is explicitly `wip`; no green verification evidence found |
| Lane D (week7 closeout) | `fix/laneD-week7-closeout-20260310` | `4acb4141` | Present | Test file / script added, but no full green log found in this collection | Branch currently dirty; integration should use commit refs, not working tree |
| Lane E | `laneE/integration-20260310` | `34a128ce` | Present | No explicit run log found | Merge branch exists, but no standalone integration validation log found |
| Lane F | `laneF/integration-20260310` | `14b7ebe7` | Present | Test file changed; no explicit run log found | Merge branch exists, but no standalone integration validation log found |

## Per-lane evidence

### Lane 03 — zk payload spec
- Branch: `docs/lane03-zk-payload-spec-20260310`
- Head: `d2340f9e` — `docs: freeze zk payload and public input protocol v0`
- Ahead of `origin/main`: 11 commits
- Key committed files in tip commit:
  - `docs/protocol/zk-proof-payload-public-input-v0.md` *(new)*
  - `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
  - `trillionnium/docs/zk-proof-payload-v1.md`
- Evidence notes:
  - tip commit is clearly attributable and doc-producing
  - branch also includes inherited commits such as `1a5c360b`, `e69e611c`, `808c2571`, so lane03 is **not isolated as a single-lane stack**
- Tests:
  - **Gap:** no explicit command/result log found for lane03-specific validation
- Blocked / caution:
  - if integrating, cherry-pick-by-commit is safer than trusting branch ancestry wholesale

### Lane 09 — preexec hang / malformed jobs
- Branch: `fix/lane09-preexec-hang-20260310`
- Head: `62597be3` — `fix: keep preexec workers alive on malformed jobs`
- Ahead of `origin/main`: 1 commit
- Tip commit touches:
  - `trillionnium/crates/trnm-node/src/main.rs`
- Diff stat:
  - 1 file changed, 45 insertions, 11 deletions
- Evidence notes:
  - cleanest lane-specific artifact among current branches (single unique commit)
- Tests:
  - **Gap:** no committed test file added in this branch and no recorded command output found
- Blocked / caution:
  - requires targeted reproduction / regression run before promotion

### Lane 11 — mempool baseline reds
- Branch: `fix/lane11-mempool-baseline-red-20260310`
- Head: `87788143` — `fix: isolate mempool lane11 baseline reds`
- Ahead of `origin/main`: 12 commits
- Tip commit touches:
  - `trillionnium/crates/trnm-mempool/src/lib.rs`
- Diff stat of tip:
  - 1 file changed, 8 insertions, 15 deletions
- Additional inherited evidence in branch ancestry:
  - `8ae140b5` — retry freshness guard under borrowed-slot saturation
  - `149d90db` / `808c2571` — timing/profiling metrics commits
  - docs / closeout commits carried on the branch
- Tests:
  - branch diff includes `trillionnium/crates/trnm-mempool/tests/lane_free_ingress_recovery_bound.rs`
  - **Gap:** no explicit lane11 command/result log found
- Blocked / caution:
  - branch is materially stacked; lane11-only scope is not cleanly isolated by branch boundary

### Lane 12 — retry fairness contract
- Branch: `fix/lane12-retry-fairness-contract-20260310`
- Head: `6f494b0b` — `docs: add lane 08 verification backend comparison review`
- Ahead of `origin/main`: 11 commits
- Tip commit creates:
  - `docs/reviews/TRNM_REVIEW_LANE_08_VERIFICATION_BACKEND_COMPARISON_2026-03-10.md`
- Evidence notes:
  - branch name implies retry fairness, but current tip evidence is a docs review for lane08/backend comparison
  - inherited ancestry includes `8ae140b5` (`guard critical retry freshness under borrowed-slot saturation`)
- Tests:
  - **Gap:** no explicit retry-fairness test execution log located
- Blocked / caution:
  - naming / tip mismatch; integration should identify whether `8ae140b5` is the real payload versus docs-only tip `6f494b0b`

### Lane 16 — integration batches
- Branch: `lane16/integration-batches-20260310`
- Head: `5313d3d4` — `docs: normalize markdown whitespace in closeout reports`
- Ahead of `origin/main`: 8 commits
- Tip commit touches:
  - `docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`
  - `docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md`
  - `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`
- Evidence notes:
  - branch currently reads as a docs/integration rollup rather than a narrow code lane
- Tests:
  - **Gap:** no explicit validation command/result found for lane16 batch integration
- Blocked / caution:
  - branch intent needs clarification before merge attribution

### Lane 18 — proof metrics
- Branch: `fix/lane18-proof-metrics-20260310`
- Head: `2828ee32` — `docs: further downgrade historical readiness entrypoints`
- Ahead of `origin/main`: 15 commits
- Notable commits in branch evidence chain:
  - `18c7a76e` — `refactor verification backend family routing`
  - `61b086ae` — `trnm-pouw: close zk verification router path`
  - `149d90db` — `perf: add node closeout timing metrics`
  - `808c2571` — `perf: add executor profiling closeout metrics`
  - `2c228bd5` — benchmark closeout e2e bridge schema
- Tests:
  - branch diff includes mempool test file changes via ancestry, but no direct proof-metrics run log found
- Blocked / caution:
  - branch mixes metrics, zk routing, and docs/readiness cleanups; attribution is broad rather than lane-pure

### Lane D — real backend
- Branch: `fix/laneD-real-backend-20260310`
- Head: `83c2f9a6` — `wip: scaffold real zk backend integration`
- Ahead of `origin/main`: 6 commits
- Tip commit touches:
  - `trillionnium/crates/trnm-pouw/Cargo.toml`
  - `trillionnium/crates/trnm-pouw/src/verification/verifiers/zk.rs`
- Diff stat of tip:
  - 2 files changed, 269 insertions, 633 deletions
- Evidence notes:
  - explicit `wip` subject is itself evidence that the lane is not yet ready to be summarized as complete
- Tests:
  - **Gap:** no green test / check log located
- Blocked / caution:
  - should be treated as in-progress until a backend-specific verification matrix is recorded

### Lane D — week7 closeout
- Branch: `fix/laneD-week7-closeout-20260310`
- Head: `4acb4141` — `test(trnm-pouw): add zk vector backend path coverage`
- Previous commit: `49baf91a` — `ci: bind nightly artifacts explicitly to avoid latest-file races`
- Remote branch exists: `origin/fix/laneD-week7-closeout-20260310`
- Ahead of `origin/main`: 16 commits
- Tip / near-tip committed evidence:
  - `scripts/v2/nightly_artifact_binding_guard_test.sh` *(new in `49baf91a`)*
  - `.github/workflows/rust-l1-nightly-health.yml`
  - `trillionnium/scripts/nightly_attribution.sh`
  - `trillionnium/scripts/run_consensus_fault_matrix.sh`
  - `trillionnium/crates/trnm-pouw` test coverage added at tip `4acb4141`
- Memory-backed evidence:
  - `memory/2026-03-10.md` records earlier verified green results for a **different selective absorption / merge flow** (`ca6a58d3` lineage), not for this branch tip specifically
- Tests:
  - committed test additions exist
  - **Gap:** no direct command/result log found tying current head `4acb4141` to a green run
- Blocked / caution:
  - checked-out worktree is dirty; do not integrate from filesystem state without first committing or stashing

### Lane E — integration
- Branch: `laneE/integration-20260310`
- Head: `34a128ce` — merge from `origin/fix/laneD-week7-closeout-20260310`
- Ahead of `origin/main`: 5 commits
- Committed files visible in merge tip:
  - `docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md` *(new)*
  - `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md` *(new)*
  - `trillionnium/scripts/render_benchmark_closeout.py` *(new)*
  - `trillionnium/scripts/run_benchmark_closeout.sh` *(new)*
  - `trillionnium/crates/trnm-mempool/tests/lane_free_ingress_recovery_bound.rs`
- Tests:
  - test file present in branch diff
  - **Gap:** no standalone integration run log found for `laneE/integration-20260310`
- Blocked / caution:
  - merge branch summarizes artifacts, but completion evidence is primarily file-level, not run-level

### Lane F — integration
- Branch: `laneF/integration-20260310`
- Head: `14b7ebe7` — merge `merge/challenge-group3c-20260310` into laneF
- Ahead of `origin/main`: 9 commits
- Evidence chain in unique commits:
  - `11f79745` — widen RPC node event log sources
  - `f399c992` — bound blocking health socket reads
  - `8ba76435` — bound sqlite reliability store growth
  - `c53b5c1a` — clean expired sqlite sessions
  - `156ff10d` — trim redundant pre-exec state clones
  - `8a2b4d3a` — avoid mempool rebuild in critical guard picker
  - `4522a6f9` — scan full mempool for critical guard fairness
- Tip merge touches:
  - `trillionnium/crates/trnm-rpc/src/main.rs`
  - `trillionnium/crates/trnm-rpc/src/reliability.rs`
  - `trillionnium/crates/trnm-rpc/tests/reliability_persistent_smoke.rs`
- Tests:
  - test file changes exist in committed diff
  - **Gap:** no explicit laneF integration command/result log located in this collection
- Blocked / caution:
  - good code-level evidence exists, but run-level evidence still needs pinning to exact commit(s)

## Cross-lane hard evidence from memory

These are verifiable from workspace memory, but they belong to an earlier recovery / selective-absorption stream and should **not** be automatically conflated with the newer lane branch tips above:

- `memory/2026-03-10.md` records a verified-green selective absorption flow containing:
  - commits: `3fae9d3b`, `d6f4ed5b`, `2c144ceb`, `12deee39`, `8473a7ca`, `cd83d8d0`, plus repair commits `cb86934b`, `e7cfd8fe`, `65fc7237`
  - green commands:
    - `cargo test -p trnm-pouw -q`
    - `cargo test -p trnm-state -q`
    - `cargo test -p trnm-rpc -q`
    - `cargo check --workspace -q`
    - `bash scripts/v2/rust_l1_nightly_health_deterministic_env_guard_test.sh`
  - merge commit: `ca6a58d3`
  - blocker after merge prep: dirty root file `trillionnium/crates/trnm-pouw/src/lib.rs`

- `memory/2026-03-09.md` records an earlier local integration branch with validated results:
  - branch: `fix/integrate-challenge-wave-20260309`
  - commits: `fcfc0e5d`, `0adb37c3`
  - green commands:
    - `cargo test -p trnm-state`
    - `cargo test -p trnm-pouw`
    - `cargo test -p trnm-node`
    - `cargo check --workspace`
    - `npm ci`
    - `npm run ci:check`

## Recommended integration posture

1. **Use commit-level cherry-picks / merge-base review, not branch-name trust.** Several lane branches are stacked and carry inherited payload unrelated to their names.
2. **Treat run evidence and file evidence separately.** For most current lane branches, file/commit evidence exists but run evidence is absent.
3. **Do not integrate from the dirty checked-out worktree.** For `fix/laneD-week7-closeout-20260310`, use committed refs only after cleaning/stashing local modifications.
4. **Prefer these branches as cleanest immediate evidence anchors:**
   - `fix/lane09-preexec-hang-20260310` (`62597be3`) — narrowest single-commit lane payload
   - `docs/lane03-zk-payload-spec-20260310` (`d2340f9e`) — clear docs artifact
   - `laneF/integration-20260310` (`14b7ebe7`) — strongest code+test-file integration evidence, but still missing explicit run log
5. **Keep these as explicitly incomplete / cautionary:**
   - `fix/laneD-real-backend-20260310` (`83c2f9a6`) — marked `wip`
   - `fix/lane12-retry-fairness-contract-20260310` — branch name/tip mismatch
   - `fix/lane11-mempool-baseline-red-20260310`, `fix/lane18-proof-metrics-20260310`, `lane16/integration-batches-20260310` — stacked, mixed-scope branches

## Missing evidence checklist

The following items were **not** found during this collection and remain gaps:
- exact subagent handoff logs for each lane
- per-lane command transcripts tied to exact head commits
- an authoritative mapping from lane number/name to exact expected deliverable and acceptance test
- a clean, non-stacked integration branch that supersedes the current lane stack set
