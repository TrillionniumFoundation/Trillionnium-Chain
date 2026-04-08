# TRNM Stage-1 RC Candidate Stack (2026-03-24)

## Goal

Define the **smallest credible candidate stack** for a stage-1 internal devnet / RC-prep branch, based on already-validated path-scoped commits harvested from the current dirty main worktree.

This document is intentionally conservative.
It is also a **historical candidate-stack snapshot captured on 2026-03-24**, not a rolling truth source for the current repository tip.
When reusing it for a fresh RC rehearsal, record the live `git rev-parse origin/main` output alongside this document instead of treating the embedded base commit below as a timeless reference.
It answers:

1. Which commits are already clean enough to form a candidate stack?
2. Which parts of the current tree must be **frozen / excluded** rather than opportunistically pulled in?
3. What should be replayed on a clean candidate branch before calling the tree RC-ready?

---

## Current Situation

### Base
- `origin/main` currently points to: `2aca564f6`

### Current local harvested stack on top of `origin/main`
1. `7527dfed1` — `fix(trnm-state): close restore and state-root replay regressions`
2. `909a0c682` — `chore(trnm-state): remove unused restore helpers`
3. `a7b7daff3` — `fix(worker-agent): unblock assigned devnet smoke path`
4. `2481c85b5` — `docs(devnet): add stage-1 readiness checklist and evidence pack`
5. `012b0d1f5` — `chore(trnm-node): scope timeout helpers to tests`
6. `d01f126ed` — `fix(trnm-node): canonicalize rollback restore replay`
7. `ad1d4632b` — `fix(trnm-rpc): dedupe and compact ingress quarantine`
8. `51a639c76` — `test(trnm-rpc): stabilize sqlite reliability smoke`

These 8 commits are the **current RC-candidate stack**.

---

## Why these 8 commits qualify

They share all of the following properties:

- harvested via **path-scoped** selection rather than broad worktree capture
- validated locally after extraction
- narrow behavioral surface
- low risk of unintentionally bundling unrelated parallel work
- directly improve stage-1 devnet credibility:
  - protocol restore/state-root correctness
  - worker/operator smoke reliability
  - node rollback/recovery canonicalization
  - rpc ingress quarantine stability
  - devnet checklist/evidence availability

---

## Candidate Stack Scope

### Included scope
- `crates/trnm-state/*` (only the already-harvested restore/state-root fixes)
- `crates/trnm-worker-agent/*` (only the already-harvested assigned-path fix)
- `crates/trnm-node/src/main.rs` (only the already-harvested test scoping + rollback restore canonicalization)
- `crates/trnm-rpc/src/main.rs` (only the already-harvested quarantine dedupe/compact fix)
- `crates/trnm-rpc/tests/reliability_persistent_smoke.rs` (only the already-harvested stability fix)
- `docs/release/*` plus archived root evidence under `docs/archive/devnet-ready-history/*`, and `trillionnium/artifacts/devnet-ready/*` inventory additions
- `docs/worker-agent-timeout-retry-runbook.md`

### Explicitly excluded from this candidate stack
Anything not already represented by the 8 commits above.

Especially excluded:
- broad `trnm-pouw` in-flight refactors
- `trnm-mempool` split work
- broad `trnm-rpc` / `trnm-cli` thin-entrypoint refactors
- bridge/oracle in-flight restructuring
- backlog/roadmap/document drift outside the explicit devnet evidence pack

---

## Dirty-Tree Freeze / Exclusion Map

### Top-level dirty count snapshot
- current dirty count observed during stack audit: **409**

### Largest dirty crate clusters
- `trnm-pouw` — **95 files**
- `trnm-mempool` — **73 files**
- `trnm-rpc` — **69 files**
- `trnm-node` — **48 files**
- `trnm-bridge-poc` — **41 files**
- `trnm-state` — **21 files**
- `trnm-worker-agent` — **19 files**
- `trnm-cli` — **13 files**
- `trnm-executor` — **7 files**
- `trnm-types` — **7 files**
- `trnm-oracle` — **6 files**
- `trnm-bench` — **1 file**

### Freeze now (do not pull opportunistically)

#### 1. `crates/trnm-pouw/`
Reason:
- largest complexity hotspot in repo
- high protocol/trust-surface risk
- not currently reduced to a small verified path-scoped patch set

#### 2. `crates/trnm-mempool/`
Reason:
- 70+ dirty files
- ongoing module split plus widespread test churn
- clearly a dedicated topic branch, not a quick harvest source

#### 3. `crates/trnm-rpc/` except the already-harvested quarantine + reliability test commits
Reason:
- remaining changes are broad thin-entrypoint/refactor work, not isolated hotfixes

#### 4. `crates/trnm-cli/`
Reason:
- current state is large command/router decomposition with many untracked modules
- not suitable for opportunistic RC harvesting

#### 5. `crates/trnm-bridge-poc/`
Reason:
- broad integration-test tree split in progress
- likely valid work, but too large/noisy for RC stack inclusion without a dedicated pass

#### 6. `crates/trnm-node/` except the already-harvested 2 commits
Reason:
- remaining node diffs are no longer obviously noise-sized
- further node harvesting should happen only as dedicated, revalidated patches

#### 7. `BACKLOG.md`, `ROADMAP.md`
Reason:
- not part of the minimum devnet candidate story
- should not block candidate-branch creation

---

## What this stack already proves

### 1. Core protocol path is stable enough for stage-1 devnet
Evidence:
- `trnm-state` restore/state-root regressions were fixed and harvested
- `trnm-state --lib` and `state_root_regression` were green at harvest time

### 2. Worker/operator assigned path no longer silently drops lowercase `assigned`
Evidence:
- worker-agent assigned path harvested with tests + runbook update

### 3. Node rollback restore replay is canonicalized in the harvested candidate
Evidence:
- node-specific rollback restore replay patch harvested and validated with crate + workspace tests

### 4. RPC ingress quarantine behavior is more RC-safe
Evidence:
- quarantine dedupe/compaction patch harvested
- ingress persistence tests passed

### 5. Stage-1 devnet evidence pack exists
Evidence:
- checklist doc
- evidence index
- repo hygiene snapshot
- testlists
- BFT smoke evidence reference

---

## What this stack does **not** prove yet

It does **not** prove RC-ready by itself.

Missing before calling the clean branch RC-ready:

1. clean-branch replay of the stack from `origin/main`
2. rerun of key smoke/tests on the clean candidate branch
3. confirmation that no hidden dependency on excluded dirty work remains
4. release/rehearsal evidence on a clean tree

---

## Recommended clean candidate branch procedure

### Step 1 — create clean branch from `origin/main`
Suggested pattern:
- branch name example: `rc/stage1-devnet-20260324`
- start from `origin/main` (`2aca564f6`)

### Step 2 — cherry-pick only the 8 candidate commits
In this order:
1. `7527dfed1`
2. `909a0c682`
3. `a7b7daff3`
4. `2481c85b5`
5. `012b0d1f5`
6. `d01f126ed`
7. `ad1d4632b`
8. `51a639c76`

### Step 3 — bind the rehearsal to the assigned worktree/ref before any RC script
Before `testnet_preflight.sh`, `run_local_release_evidence.sh`, or `release_rc.sh`, record the exact lane/ticket worktree and branch from the release note instead of deriving expectations from the current shell prompt.

Recommended fail-closed helper (`--expected-branch-ref` accepts either a short branch name like `rc/stage1-devnet-20260324` or a full ref like `refs/heads/rc/stage1-devnet-20260324`):

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/rc/stage1-devnet-20260324"
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Interpretation rule:
- do not replace `EXPECTED_*` with values copied back out of the current shell session; use the lane assignment / ticket values
- if the helper fails, stop instead of continuing to release evidence generation
- after the helper passes, record its `verified_worktree=`, `verified_branch_ref=`, and `verified_head=` lines verbatim in the handoff note; do not paraphrase them into "same branch as before" or re-derive them from the shell later
- when you also record `git rev-parse HEAD`, treat it as a duplicate cross-check next to the helper output rather than the sole identity anchor
- even after path-resolving the latest `run/health/evidence-*` or `release/rc-*` artifact, still compare `git_worktree_path=` / `git_worktree_branch_ref=` inside those files against the ticket-assigned worktree/ref; `git_expected_worktree_branch_ref=` must also preserve the ticket-assigned target and `git_worktree_branch_ref_match=true` is required rather than a soft warning
- prefer the shared extraction helper for handoff quoting (`./scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" --expected-branch-ref "$EXPECTED_BRANCH_REF"`) so path resolution and cross-artifact identity checks fail closed together instead of depending on manually recopied snippets

### Step 4 — run minimum replay verification on the clean branch
Required:
- `cargo test -p trnm-state --lib -- --test-threads=1`
- `cargo test -p trnm-state --test state_root_regression -- --test-threads=1`
- `cargo test -p trnm-rpc --lib -- --test-threads=1`
- `cargo test -p trnm-rpc --test submit_message_ingress_persistence -- --test-threads=1`
- `cargo test -p trnm-rpc --test reliability_persistent_smoke -- --test-threads=1`
- `cargo test -p trnm-node -- --test-threads=1`
- `cargo test -p trnm-worker-agent -- --test-threads=1`
- `cargo test -p trnm-cli -- --test-threads=1`
- `./scripts/check_bft_4node_smoke.sh`
- `./scripts/check_query_audit_smoke.sh`

Strongly recommended:
- `cargo test --workspace --all-targets`
- `./scripts/run_local_release_evidence.sh`
- `./scripts/release_rc.sh`

---

## Go / No-Go rule for Stage-1 RC-prep

### Go if all are true
- clean branch contains only the 8 commits above
- all minimum replay verification passes
- no hidden dependence on excluded dirty trees
- checklist/evidence documents still describe the branch truthfully

### No-Go if any are true
- cherry-pick needs additional ad hoc dirty hunks from excluded clusters
- `trnm-pouw` / `mempool` / `rpc` refactor work must be pulled in to keep tests green
- clean branch cannot reproduce BFT smoke / worker-agent smoke / key crate tests
- release evidence only passes on the dirty main tree but not on the clean branch

---

## Practical next move

The next action should **not** be further opportunistic harvesting from the large dirty clusters.

The highest-value next step is:

> create a clean candidate branch from `origin/main`, cherry-pick the 8 commits, and replay the minimum stage-1 verification suite.

That is the shortest path from “harvested good patches” to an actual RC-prep branch.
