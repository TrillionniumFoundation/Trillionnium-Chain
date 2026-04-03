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
- required config files exist: `configs/node1.toml`, `configs/node2.toml`, `configs/node3.toml`, `configs/node4.toml`
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

For multi-worktree validator rehearsals, prefer the shared fail-closed helper instead of eyeballing the shell prompt or rewriting the assertion block by hand. **Important:** set the expected values from the ticket/lane assignment, not by re-reading the current shell state, otherwise the check only proves the current worktree is self-consistent:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="lane/assigned-branch" # or refs/heads/lane/assigned-branch
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

After the helper passes, record its `verified_worktree=`, `verified_branch_ref=`, and `verified_head=` output verbatim in the ticket / handoff note before generating evidence artifacts. Those three lines are the pre-run identity anchor that later `summary.txt` / `manifest.txt` fields must match; do not replace them with paraphrases like "same branch as before".

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

When a supervisor ticket already assigns the exact worktree and branch ref, bind those values directly and prefer the shared fail-closed helper instead of re-copying the assertion block into the runbook:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

Helper output to capture before running any release/evidence script:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`
- the matching `git worktree list --porcelain` stanza for the current worktree path

If you need the raw shell assertions for an air-gapped/debugging context, fall back to the equivalent block documented in `scripts/v2/verify_lane_worktree.sh` rather than hand-editing a new variant in this runbook.

Interpretation rule:
- use this helper invocation exactly as the first operator step when a lane prompt, release ticket, or handoff note already assigns a dedicated worktree/ref
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
- `generated_at=` and `git_status_summary=clean` must both be present before anyone treats the evidence as handoff-grade
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
- `git_expected_worktree_branch_ref=` matches the lane/ticket-assigned ref you expected to review
- `git_worktree_branch_ref_match=true` (treat `false` / `unknown` as a stop signal rather than a soft warning)
- `git_worktree_entry_begin` … `git_worktree_entry_end` contains the current worktree stanza, so path/branch binding can be audited from the artifact itself
- `git_status_summary=clean`
- `git_status_short_begin` … `git_status_short_end` is empty for clean-tree rehearsals
- `env_mvp_mode=` and any nightly-streak log lines are preserved so operators can distinguish a real external policy blocker from a locally skipped gate

## Artifact ownership quick map

Use the generated artifact as the source of truth for the step you just ran; do not cross-quote fields from memory or terminal scrollback.

| Step | Primary artifact | Identity fields to verify first | Operator question it answers |
| --- | --- | --- | --- |
| Fast preflight | `run/preflight/go-no-go-latest.txt` plus the saved helper transcript when lane-bound verification is required | `result=`, `generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `expected_worktree_root=`, `ticket_expected_branch_ref=` (ticket form), `expected_branch_ref=` (canonical form), referenced log paths | Did the local rehearsal fail fast on obvious safety blockers *and* stay bound to the ticket-assigned worktree/ref? |
| Local release evidence | `run/health/evidence-<timestamp>/summary.txt` | `git_toplevel=`, `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `git_status_summary=`, `generated_at=`, `truth_source=`, `historical_evidence_only=`, `evidence_scope=` | Did the evidence bundle pass, and what exact replay / rollback commands apply? |
| RC gate rehearsal | `release/rc-<timestamp>/manifest.txt` | `git_toplevel=`, `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `git_status_summary=`, `generated_at=`, `truth_source=`, `historical_evidence_only=`, `evidence_scope=` | Is this branch/commit rehearsal-ready, and is any remaining blocker code vs policy? |

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
- path resolution alone is **not** lane-identity proof: after resolving the files, also verify the artifact `git_worktree_path=` / `git_worktree_branch_ref=` against the lane-assigned worktree/ref from the ticket instead of assuming “latest artifact under this checkout” is automatically the assigned lane
- prefer `./scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <lane-worktree> --expected-branch-ref <lane-branch-ref>` (or `./trillionnium-rust/scripts/v2/extract_release_handoff_fields.sh ...` from the repo root) so artifact resolution and assigned-lane comparison fail closed in one step

Operator discipline:
- quote `summary.txt` only for local-evidence conclusions
- quote `manifest.txt` only for RC rehearsal conclusions
- if branch / commit / worktree identity differs across artifacts, stop and treat the handoff as **No-Go** until the mismatch is explained

### Canonical handoff extraction block

When handing off to another validator/operator, prefer copying fields from the artifact itself instead of free-typing them from terminal scrollback.

Preferred helper (fail-closed on missing paths, cross-artifact identity mismatches, or drift from the lane/ticket-assigned worktree/ref when you provide them; by default it resolves the most recently modified artifacts under the `trillionnium-rust` root derived from the helper script path, matching the `ls -dt ... | head -n 1` path-resolution discipline shown elsewhere in this runbook; `--expected-branch-ref` accepts either a short branch name like `lane/foo` or a full ref like `refs/heads/lane/foo`):

```bash
handoff_helper_output_path="run/preflight/handoff-fields-$(date -u +%Y%m%dT%H%M%SZ).txt"
mkdir -p "$(dirname "$handoff_helper_output_path")"
./scripts/v2/extract_release_handoff_fields.sh \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch" \
  | tee "$handoff_helper_output_path"
printf 'handoff_helper_output_path=%s\n' "$handoff_helper_output_path"
```

Operator rule:
- treat `handoff_helper_output_path=` as a first-class artifact, not throwaway terminal scrollback
- quote `summary_generated_at=`, `manifest_generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `rollback_command=`, and `replay_command=` from that saved transcript or the underlying artifacts, not from memory
- if the helper output was not saved anywhere path-resolved, the handoff remains evidence-incomplete even if the terminal showed the expected lines once

If you need the raw shell extraction for an air-gapped/debugging context, the equivalent block is:

```bash
latest_evidence_dir="$(ls -dt run/health/evidence-* 2>/dev/null | head -n 1)"
latest_rc_dir="$(ls -dt release/rc-* 2>/dev/null | head -n 1)"

[ -n "$latest_evidence_dir" ] || { echo "missing local evidence" >&2; exit 1; }
[ -n "$latest_rc_dir" ] || { echo "missing rc manifest" >&2; exit 1; }

summary_path="$latest_evidence_dir/summary.txt"
manifest_path="$latest_rc_dir/manifest.txt"

printf 'summary_path=%s\n' "$summary_path"
printf 'manifest_path=%s\n' "$manifest_path"

awk -F= '/^(git_toplevel|git_branch|git_head|git_head_state|git_worktree_path|git_worktree_branch_ref|git_expected_worktree_branch_ref|git_worktree_branch_ref_match|git_status_summary|generated_at|truth_source|historical_evidence_only|evidence_scope|result|rollback_command|replay_command|challenge_reexec_entry|replay_env_trnm_challenge_reexec_entry)=/ { print }' "$summary_path"
awk -F= '/^(git_toplevel|git_branch|git_head|git_head_state|git_worktree_path|git_worktree_branch_ref|git_expected_worktree_branch_ref|git_worktree_branch_ref_match|git_status_summary|generated_at|truth_source|historical_evidence_only|evidence_scope|rollback_command|replay_command)=/ { print }' "$manifest_path"
```

Interpretation rule:
- if either path is missing, the handoff is incomplete; do not substitute an older artifact from memory
- if `git_toplevel=`, `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `git_status_summary=`, `truth_source=`, `historical_evidence_only=`, or `evidence_scope=` differ between the two files, stop and treat the rehearsal as **No-Go** until explained
- treat `git_worktree_branch_ref_match=true` as mandatory; `false` / `unknown` is a stop signal even if the rest of the fields look plausible
- preserve both `summary_generated_at=` and `manifest_generated_at=` from the artifacts/helper output; they do **not** need to be identical, but they must both exist so operators can audit when each artifact was generated instead of collapsing them into one hand-copied timestamp
- if `challenge_reexec_entry=` / `replay_env_trnm_challenge_reexec_entry=` appear in `summary.txt`, quote them verbatim next to `replay_command=` instead of dropping them from the handoff note
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
- assigned worktree (from ticket/lane prompt):
- assigned branch ref (from ticket/lane prompt):
- verified worktree:
- verified branch ref:
- verified head:
- branch:
- commit:
- signer exclusivity note (which process/host/worktree owns the validator identity during this rehearsal):
- worktree:
- worktree branch ref:
- worktree branch ref match (`true` required):
- git status summary (`clean` required):
- preflight summary path:
- preflight result:
- preflight generated_at:
- preflight rollback command:
- preflight replay command:
- local evidence summary path:
- local evidence generated_at:
- local evidence truth_source:
- local evidence historical_evidence_only:
- local evidence evidence_scope:
- evaluated origin/main (record fresh `git rev-parse origin/main` when this handoff cites `RELEASE_READINESS.md`):
- rc manifest path:
- rc manifest generated_at:
- rc manifest truth_source:
- rc manifest historical_evidence_only:
- rc manifest evidence_scope:
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

Quoting rule:
- when `summary.txt` exposes both `env_*` and `replay_env_*`, treat `replay_env_*` as the deterministic audit/replay baseline and do not rewrite the run as a shorter shell without those fields
- if `challenge_reexec_entry=` / `replay_env_trnm_challenge_reexec_entry=` appear in `summary.txt`, quote them verbatim in the handoff note together with `replay_command=`; if the value is `<entry_not_found>`, preserve that literal rather than rewriting it as an implicit TODO
- when quoting `manifest.txt`, keep `truth_source=`, `historical_evidence_only=`, and `evidence_scope=` adjacent to `replay_command=` / `rollback_command=` so a local RC rehearsal is not misread as a public-mainnet readiness proof

This prevents drift in locale, timezone, build-job parallelism, output directory selection, and release-readiness interpretation.

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
