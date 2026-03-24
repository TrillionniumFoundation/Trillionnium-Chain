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

If any invariant fails, stop and fix the operator state first.

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
- `git_branch=` and `git_head=` match the branch/commit under review
- `git_status_summary=clean`
- `git_status_short_begin` … `git_status_short_end` is empty for clean-tree rehearsals

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

This is **not** release-ready. It is only rehearsal-ready pending the external gate.

### NO-GO
- any replay/test log shows rollback/apply-error anomalies
- branch/worktree identity is unclear
- evidence directory is missing required files
- the run depended on undocumented environment overrides
- artifacts were produced on a dirty tree

## Evidence handoff template

Record these fields in the release ticket or operator handoff note:
- branch:
- commit:
- worktree:
- preflight summary path:
- local evidence summary path:
- rc manifest path:
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
