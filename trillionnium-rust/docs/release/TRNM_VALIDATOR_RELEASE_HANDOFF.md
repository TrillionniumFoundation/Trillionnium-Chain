# TRNM Validator Release Handoff

Cosmos/CometBFT-style operator discipline for a local Stage-1 release rehearsal.

This document is intentionally narrow: it tells a validator/operator **what to run, what evidence must exist, what blocks a release, and how to back out cleanly**.

## Scope

Use this handoff when rehearsing or validating a Stage-1 TRNM release candidate on a clean worktree.

Primary entrypoints:
- `./scripts/testnet_preflight.sh`
- `./scripts/run_local_release_evidence.sh`
- `./scripts/release_rc.sh`

## Operator invariants

Before starting, confirm all of the following:
- you are on the intended release branch/worktree
- `git status --short` is empty
- the branch tip is recorded in the ticket / release note
- required config files exist: `configs/node1.toml`, `configs/node2.toml`, `configs/node3.toml`
- no one is treating local evidence as a public release claim
- exactly one validator signing context is active for the validator identity under rehearsal

If any invariant fails, stop and fix the operator state first.

### Single-signer / process exclusivity check

Before swapping binaries, replaying evidence, or restarting a validator process, confirm the validator key is not active in two places at once.

Minimum operator rule:
- never let the same validator identity sign from two worktrees, two hosts, or two processes concurrently
- if you cannot prove which process owns the validator identity right now, treat the release rehearsal as **No-Go** until clarified
- if the release step is docs/evidence-only, still record that no background validator process from another worktree is assumed to be signing on behalf of this rehearsal

Recommended fail-closed check before any restart / binary swap:

```bash
ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep
lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'
```

Interpretation rule:
- if you see an unexpected second validator process, stop before continuing
- if the owning process / host / worktree cannot be named explicitly in the handoff note, stop before continuing
- do not normalize "it was probably just the old process" into a GO decision; ambiguous signer ownership is an operator failure, not a cosmetic warning

### Canonical worktree / branch identity check

Before running any release or evidence script, resolve identity from git instead of terminal memory:

```bash
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
git status --short
git worktree list --porcelain
```

Interpretation rule:
- `git rev-parse --show-toplevel` must match the intended repo root for the rehearsal
- `git branch --show-current` must return the release/rehearsal branch name; if it is empty, treat the run as detached-HEAD and **No-Go** until explicitly explained
- `git rev-parse HEAD` must be copied into the ticket / handoff note together with the branch name
- generated artifacts should normalize detached-HEAD runs as `git_branch=<detached-HEAD>` plus `git_head_state=detached`; never treat literal `HEAD` as a valid branch name in a handoff note
- `git status --short` must be empty for clean-tree release rehearsals
- `git worktree list --porcelain` should show the current path attached to the branch you intend to rehearse; if branch/path pairing is different from expectation, stop instead of "fixing it later"

For multi-worktree validator rehearsals, prefer the shared fail-closed helper instead of eyeballing the shell prompt or rewriting the assertion block by hand:

```bash
EXPECTED_WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
EXPECTED_BRANCH_REF="refs/heads/$(git branch --show-current)"
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

If you need the raw shell assertions for an air-gapped/debugging context, the equivalent block is:

```bash
CURRENT_WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
CURRENT_BRANCH_NAME="$(git branch --show-current)"
CURRENT_BRANCH_REF="refs/heads/${CURRENT_BRANCH_NAME}"

[ -n "$CURRENT_BRANCH_NAME" ] || { echo "detached HEAD: no branch checked out" >&2; exit 1; }
[ "$CURRENT_WORKTREE_ROOT" = "$EXPECTED_WORKTREE_ROOT" ] || {
  printf 'worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$CURRENT_WORKTREE_ROOT" >&2
  exit 1
}
[ "$CURRENT_BRANCH_REF" = "$EXPECTED_BRANCH_REF" ] || {
  printf 'branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF" "$CURRENT_BRANCH_REF" >&2
  exit 1
}
```

Operator rule:
- do not begin `testnet_preflight.sh`, `run_local_release_evidence.sh`, or `release_rc.sh` until the exact worktree path, branch, and commit are all recorded together
- when the run is bound to a dedicated lane/worktree, replace the self-derived `EXPECTED_*` values above with the lane-assigned path/ref from the ticket or supervisor prompt, so the shell fails closed if the operator opened the wrong worktree
- if an artifact later reports a different branch or commit than this pre-run identity block, treat the handoff as **No-Go** until reconciled

### Dedicated lane / ticket-bound assertion example

When a supervisor ticket already assigns the exact worktree and branch ref, bind those values directly instead of deriving expectations from the current shell:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

CURRENT_WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
CURRENT_BRANCH_NAME="$(git branch --show-current)"
CURRENT_BRANCH_REF="refs/heads/${CURRENT_BRANCH_NAME}"
CURRENT_HEAD="$(git rev-parse HEAD)"
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain | awk -v target="$CURRENT_WORKTREE_ROOT" '
  BEGIN { in_match=0 }
  /^worktree / { in_match = ($2 == target) }
  in_match { print }
  in_match && /^$/ { exit }
')"

[ -n "$CURRENT_BRANCH_NAME" ] || { echo "detached HEAD: no branch checked out" >&2; exit 1; }
[ "$CURRENT_WORKTREE_ROOT" = "$EXPECTED_WORKTREE_ROOT" ] || {
  printf 'worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$CURRENT_WORKTREE_ROOT" >&2
  exit 1
}
[ "$CURRENT_BRANCH_REF" = "$EXPECTED_BRANCH_REF" ] || {
  printf 'branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF" "$CURRENT_BRANCH_REF" >&2
  exit 1
}
if [ -n "$EXPECTED_HEAD" ] && [ "$CURRENT_HEAD" != "$EXPECTED_HEAD" ]; then
  printf 'head mismatch: expected %s got %s\n' "$EXPECTED_HEAD" "$CURRENT_HEAD" >&2
  exit 1
fi
printf 'verified_worktree=%s\nverified_branch_ref=%s\nverified_head=%s\n' \
  "$CURRENT_WORKTREE_ROOT" "$CURRENT_BRANCH_REF" "$CURRENT_HEAD"
printf '%s\n' "$CURRENT_WORKTREE_ENTRY"
```

Interpretation rule:
- use this block exactly as the first operator step when a lane prompt, release ticket, or handoff note already assigns a dedicated worktree/ref
- if the printed `git worktree list --porcelain` stanza does not describe the current path/ref pairing you expected, stop immediately instead of continuing to the release scripts
- if `EXPECTED_HEAD` is intentionally unknown, leave it empty; do **not** invent or backfill a commit from memory

## Recommended execution order

### 1. Fast preflight

Run:

```bash
./scripts/testnet_preflight.sh
```

Expected outputs:
- `run/preflight/preflight-<timestamp>.log`
- `run/preflight/go-no-go-<timestamp>.txt`
- `run/preflight/go-no-go-latest.txt`

A preflight run is a **No-Go** if any of the following occurs:
- workspace tests fail
- `parallel-sanity.log` contains `[tx] apply_error` or `rollback=true`
- consensus summary line is missing
- state-root audit reports mismatch or missing entries

### 2. Local release evidence capture

Run:

```bash
./scripts/run_local_release_evidence.sh
```

Expected output directory:
- `run/health/evidence-<timestamp>/`

Minimum evidence files to preserve:
- `summary.txt`
- `cargo_test_key_packages.log`
- `check_request_tx_binding.log`
- `run_request_fault_injection.log`
- `challenge_reexec.log` when the challenge re-exec entry is present

Interpretation rule:
- `summary.txt` must end with `result=PASS`
- `git_status_summary=clean` must be present before anyone treats the evidence as handoff-grade
- if `challenge_reexec=FAIL(entry_not_found)`, treat the rehearsal as incomplete rather than silently acceptable

### 3. RC gate rehearsal

Run:

```bash
./scripts/release_rc.sh
```

Expected output directory:
- `release/rc-<timestamp>/`

Minimum artifacts to preserve:
- `manifest.txt`
- `nightly-streak.log`
- `cargo-test.log`
- `state-root-audit.log`
- `parallel-sanity.log`
- `event-field-check.log`
- `event-replay-smoke.log`
- `bench-matrix.log`
- `bench-mixed-matrix.log`
- `threshold-enforcement.log`
- `cargo-build.log`

Manifest/evidence identity fields to verify before handoff:
- `git_toplevel=` matches the intended repo root
- `git_branch=`, `git_head=`, and `git_head_state=` match the branch/commit attachment state under review
- `git_worktree_path=` matches the exact worktree path you intended to run from
- `git_worktree_branch_ref=` matches the branch binding shown by `git worktree list --porcelain`
- `git_worktree_entry_begin` … `git_worktree_entry_end` contains the current worktree stanza, so path/branch binding can be audited from the artifact itself
- `git_status_summary=clean`
- `git_status_short_begin` … `git_status_short_end` is empty for clean-tree rehearsals
- `env_mvp_mode=` and any nightly-streak log lines are preserved so operators can distinguish a real external policy blocker from a locally skipped gate

## Artifact ownership quick map

Use the generated artifact as the source of truth for the step you just ran; do not cross-quote fields from memory or terminal scrollback.

| Step | Primary artifact | Identity fields to verify first | Operator question it answers |
| --- | --- | --- | --- |
| Fast preflight | `run/preflight/go-no-go-latest.txt` | generated timestamp, referenced log paths | Did the local rehearsal fail fast on obvious safety blockers? |
| Local release evidence | `run/health/evidence-<timestamp>/summary.txt` | `git_branch=`, `git_head=`, `git_head_state=`, `git_status_summary=`, `generated_at=`, `truth_source=` | Did the evidence bundle pass, and what exact replay / rollback commands apply? |
| RC gate rehearsal | `release/rc-<timestamp>/manifest.txt` | `git_toplevel=`, `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_status_summary=`, `truth_source=` | Is this branch/commit rehearsal-ready, and is any remaining blocker code vs policy? |

### Canonical path resolution commands

When multiple timestamped evidence directories exist, resolve the artifact path from disk before quoting any field in chat, a ticket, or a handoff note.

```bash
# Latest local-evidence summary
latest_evidence_dir="$(ls -dt run/health/evidence-* 2>/dev/null | head -n 1)"
[ -n "$latest_evidence_dir" ] || { echo "missing local evidence" >&2; exit 1; }
summary_path="$latest_evidence_dir/summary.txt"
printf 'summary_path=%s\n' "$summary_path"

# Latest RC rehearsal manifest
latest_rc_dir="$(ls -dt release/rc-* 2>/dev/null | head -n 1)"
[ -n "$latest_rc_dir" ] || { echo "missing rc manifest" >&2; exit 1; }
manifest_path="$latest_rc_dir/manifest.txt"
printf 'manifest_path=%s\n' "$manifest_path"
```

Operator rule:
- if the directory listing returns nothing, do not guess the path from memory; treat the step as not yet run or artifact retention as incomplete
- quote `summary_path` / `manifest_path` together with the `git_branch=` and `git_head=` fields from the file you just resolved

Operator discipline:
- quote `summary.txt` only for local-evidence conclusions
- quote `manifest.txt` only for RC rehearsal conclusions
- if branch / commit / worktree identity differs across artifacts, stop and treat the handoff as **No-Go** until the mismatch is explained

### Canonical handoff extraction block

When handing off to another validator/operator, prefer copying fields from the artifact itself instead of free-typing them from terminal scrollback.

```bash
latest_evidence_dir="$(ls -dt run/health/evidence-* 2>/dev/null | head -n 1)"
latest_rc_dir="$(ls -dt release/rc-* 2>/dev/null | head -n 1)"

[ -n "$latest_evidence_dir" ] || { echo "missing local evidence" >&2; exit 1; }
[ -n "$latest_rc_dir" ] || { echo "missing rc manifest" >&2; exit 1; }

summary_path="$latest_evidence_dir/summary.txt"
manifest_path="$latest_rc_dir/manifest.txt"

printf 'summary_path=%s\n' "$summary_path"
printf 'manifest_path=%s\n' "$manifest_path"

awk -F= '/^(git_branch|git_head|git_head_state|git_worktree_path|git_worktree_branch_ref|truth_source|result|rollback_command|replay_command)=/ { print }' "$summary_path"
awk -F= '/^(git_branch|git_head|git_head_state|git_worktree_path|git_worktree_branch_ref|truth_source|rollback_command|replay_command)=/ { print }' "$manifest_path"
```

Interpretation rule:
- if either path is missing, the handoff is incomplete; do not substitute an older artifact from memory
- if `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, or `git_worktree_branch_ref=` differ between the two files, stop and treat the rehearsal as **No-Go** until explained
- quote the emitted `rollback_command=` / `replay_command=` lines verbatim; do not rewrite them into a shorter or "equivalent" form

## Forbidden operator shortcuts

Treat each of the following as a release-discipline violation, not a harmless convenience:
- rerunning only the final script after switching branches or worktrees without regenerating the full evidence chain
- copying `git_branch=`, `git_head=`, or `rollback_command=` from terminal scrollback instead of the generated artifact
- presenting a `CONDITIONAL GO` rehearsal as if it were `GO`
- deleting a failed evidence directory before another operator can inspect the first failing artifact
- claiming the nightly gate is the blocker when `nightly-streak.log` is missing, skipped, or locally overridden
- hand-editing `summary.txt` / `manifest.txt` to "clean up" wording before handoff

Operator rule:
- if any shortcut above occurred, rerun the affected step from a clean operator state and attach the new artifact path; do not try to patch the handoff note retroactively.

## Go / No-Go decision rule

### GO only if all are true
- preflight passed
- local release evidence passed
- `release_rc.sh` completed successfully
- nightly streak gate passed without override
- generated manifests/logs match the branch and commit being evaluated
- no operator had to hand-edit evidence after the run

### CONDITIONAL GO
- local code/tests/evidence are green
- `release_rc.sh` is blocked only by an external policy gate such as insufficient nightly green streak
- the nightly check actually ran, and `nightly-streak.log` shows an external-policy failure rather than a local skip/override

This is **not** release-ready. It is only rehearsal-ready pending the external gate.

### NO-GO
- any replay/test log shows rollback/apply-error anomalies
- branch/worktree identity is unclear
- evidence directory is missing required files
- the run depended on undocumented environment overrides
- the nightly streak gate was skipped or locally overridden for a handoff being presented as release discipline evidence
- artifacts were produced on a dirty tree

## Evidence handoff template

Record these fields in the release ticket or operator handoff note:
- branch:
- commit:
- worktree:
- worktree branch ref:
- preflight summary path:
- local evidence summary path:
- local evidence truth_source:
- rc manifest path:
- rc manifest truth_source:
- nightly streak result:
- go/no-go decision:
- blocker summary:
- rollback command:
- replay command:

## Rollback discipline

Do not improvise cleanup.

Use the rollback command emitted by the script you just ran:
- `run_local_release_evidence.sh` writes `rollback_command=` to `summary.txt`
- `release_rc.sh` writes `rollback_command=` to `manifest.txt`

If an operator cannot quote the exact rollback command from the generated artifact, treat the handoff as incomplete.

## Replay discipline

For deterministic re-runs, prefer the exact replay command emitted by the artifact:
- `summary.txt` contains `replay_command=` for local evidence
- `manifest.txt` contains `replay_command=` for RC rehearsal

This prevents drift in locale, timezone, build-job parallelism, and output directory selection.

## Common failure interpretation

- `nightly green streak insufficient`: process/policy blocker, not necessarily a code regression
- `apply_error` / `rollback=true` in sanity logs: consensus or execution safety blocker
- missing challenge re-exec entry: evidence-pack completeness blocker
- missing finality summary line: node observability blocker

## Why this exists

A validator release rehearsal fails in practice when evidence exists but operators cannot quickly answer:
- what exact command was run?
- where is the resulting evidence?
- is this a code failure, an environment failure, or a policy gate?
- what is the exact rollback path?

This page is meant to make those answers explicit before anyone claims a release is ready.
