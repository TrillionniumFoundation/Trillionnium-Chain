# Read-only mixed-trust Cargo policy validation v1

Primary module: M17. Consumers: project preflight, independent source readers,
required-baseline qualification and local contributors. This is a validation
contract, not another execution plan. The only development plan remains
[Plan v2](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Source ownership

The mixed-trust wrapper must not move, remove, rewrite or restore a source
workflow while validating it. The former worktree path moved the required
baseline out of the checkout before privileged validation. A second reader could
observe it missing, a concurrent edit could be overwritten by restoration, and
an uncatchable termination could leave it absent permanently.

The existing runner policy validates the complete selected source first. The
existing privileged validator already excludes hosted workflow names from its
frozen privileged inventory; moving the hosted file is unnecessary. Worktree
mode now calls that validator directly, with the original workflow left in place.
No exclusion, registry entry, actor, runner, command or acceptance threshold is
added to either underlying policy.

Staged and HEAD modes retain their existing independent Git snapshots, including
selection of the validator bytes from the corresponding index or commit. Removal
of the hosted workflow is limited to those disposable snapshots. Before initializing a foreign snapshot repository, its subshell clears Git's
reported repository-local environment variables. Source extraction still uses
the caller's selected index; subsequent snapshot writes cannot be redirected by
an inherited `GIT_INDEX_FILE`, `GIT_DIR` or `GIT_WORK_TREE`. This follows Git's
foreign-repository hook guidance. No restoration step writes a snapshot back
into the source checkout. A failed validator retains
its nonzero exit and must not produce the wrapper's successful summary.

This control does not make worktree reads atomic and does not qualify a checkout
being edited concurrently. Exact-source acceptance still needs a stable, clean
source and before/after identity checks. It is not containment of an arbitrary
malicious validator. Uncatchable termination can leave temporary scratch files;
it must not require recovery of a source workflow from those files.

## Retained regression and qualification

`test_cargo_policy_readonly_v1.py` runs the actual wrapper with explicitly
controlled validators, real Git repositories, two simultaneous invocations and
bounded process handshakes. It checks source bytes, inode, permissions, timestamp,
index identity and HEAD; SIGKILL/SIGTERM; preservation of a concurrent edit;
validator failure propagation; missing baseline rejection; source-mode selection;
visibility of ignored workflows, untracked scripts and tracked missing files;
and separation of source Git directories and alternate indexes from snapshot
writes. The alternate-index positive control uses different index, HEAD and
worktree payloads, so clearing source selection too early also fails.
The controlled validators are fixtures, not proof that real policy rules pass.

The existing `check_cargo_offline_policy_test.sh` invokes those regressions and
then retains its full real-validator positive and negative matrix. Its existing
required-baseline invocation remains the CI execution owner; no workflow change
or weaker alternative gate is introduced.

```bash
python3 scripts/ci/test_cargo_policy_readonly_v1.py
bash scripts/check_cargo_offline_policy_test.sh
bash scripts/check_cargo_offline_policy.sh --worktree
```

This repair grants no Rust execution, independent review, external evidence,
protected merge, release qualification or network activation. Those facts require
their own source-bound verification and authorization.
