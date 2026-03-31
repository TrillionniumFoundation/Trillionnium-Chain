# TRNM Validator Replacement / Rotation / DR Runbook

Fail-closed operator checklist for replacing a validator host, rotating ownership to a new validator/config bundle, or rebuilding after a disaster-recovery event.

This runbook is intentionally narrow:
- it does **not** declare TRNM public-mainnet ready by itself
- it does define the minimum operator evidence needed before a validator replacement/rotation/DR event can be called reproducible
- it treats unclear ownership, unsigned handoff, or missing rollback as **No-Go**

## Scope

Use this when an operator needs to:
- replace a validator host or process owner while preserving explicit chain/worktree identity
- rotate to a different validator/config bundle under operator control
- rebuild after data loss, host loss, or uncertain process ownership
- hand replacement/rotation/DR status to another validator/operator without relying on shell memory

Primary references:
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/runbooks/local-release-evidence.md`
- `docs/runbooks/bft-checkpoint-wal-recovery.md`
- `scripts/v2/verify_lane_worktree.sh`
- `scripts/v2/extract_release_handoff_fields.sh`

## Operator cutover note template

Before starting the event, open a handoff note and pre-fill these fields so replacement / rotation / DR does not depend on terminal memory:

```text
cutover_kind=
verified_worktree=
verified_branch_ref=
verified_head=
outgoing_validator_config=
outgoing_validator_identity=
incoming_validator_config=
incoming_validator_identity=
expected_genesis_or_checkpoint=
handoff_signed_by=
handoff_acknowledged_by=
rollback_command=
handoff_summary_path=
handoff_manifest_path=
summary_generated_at=
manifest_generated_at=
dr_summary_path=
dr_generated_at=
dr_replay_command=
dr_rollback_command=
bootstrap_command=
result=
next_blocker=
```

Rules:
- `dr_summary_path=` / `dr_generated_at=` / `dr_replay_command=` / `dr_rollback_command=` may remain empty unless `cutover_kind=dr_rebuild`.
- `handoff_summary_path=` / `handoff_manifest_path=` / `summary_generated_at=` / `manifest_generated_at=` may remain empty unless release-evidence or RC artifacts are part of the handoff.
- when `extract_release_handoff_fields.sh` is used, copy both artifact paths and both generated-at fields verbatim; do not collapse them into one hand-written timestamp.
- `result=` should stay empty until the smallest credible bootstrap/re-bootstrap sanity actually finishes.
- if any identity or rollback field cannot be filled before cutover, stop.

## Cutover evidence matrix

Use the smallest evidence set that still proves ownership, rollback, and artifact lineage for the specific cutover kind.
If any required row cannot be satisfied, treat the event as **No-Go** before execution.

| Cutover kind | Required identity fields | Required artifacts | Minimum stop condition if missing |
| --- | --- | --- | --- |
| `replacement` | `verified_worktree=` / `verified_branch_ref=` / `verified_head=` plus explicit outgoing and incoming validator identity/config | clean `git status --short`, config-bundle check output, exact `bootstrap_command=`, explicit `rollback_command=` | cannot name which validator identity is being retired vs activated |
| `rotation` | all replacement fields plus `handoff_signed_by=` / `handoff_acknowledged_by=` and explicit lineage (`expected_genesis_or_checkpoint=`) | handoff note with signed/acknowledged ownership transfer, optional `handoff_summary_path=` / `handoff_manifest_path=` when release artifacts are part of the cutover | signer/acknowledger missing, or rotation lineage cannot be stated from the note |
| `dr_rebuild` | all rotation fields plus `dr_summary_path=` / `dr_generated_at=` / `dr_replay_command=` / `dr_rollback_command=` | concrete recovery artifact from the current worktree, plus the bootstrap/re-bootstrap sanity command used after rebuild | DR claimed but no path-resolved recovery report exists for the rebuild |

Interpretation rule:
- `replacement` is a local operator-owner swap with explicit rollback and clean config proof.
- `rotation` is a replacement that also requires a human handoff boundary; do not reduce it to an unsigned config rename.
- `dr_rebuild` is the strongest evidence bar because it must prove both ownership transfer and recovery lineage from a concrete artifact.

## Operator invariants

Before touching validator ownership, all of the following must be true:
- the assigned worktree path and branch ref are known explicitly
- `git status --short` is empty
- the outgoing validator identity/config and incoming validator identity/config can both be named explicitly
- the intended genesis artifact/hash or checkpoint lineage is named explicitly
- the operator can state whether this is **replacement**, **rotation**, or **DR rebuild**
- the operator can quote the rollback action before starting the cutover

If any invariant fails, stop before continuing.

## Minimal procedure

### 1. Re-prove worktree identity

Run the same fail-closed binding step used for validator bootstrap:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

Record:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

Interpretation rule:
- if the ticket or handoff note already assigns an exact commit, pass it via `EXPECTED_HEAD` so the cutover fails closed on the wrong lane tip
- if `EXPECTED_HEAD` is intentionally unknown, leave it empty rather than inventing a commit from memory

### 2. Name the cutover shape before execution

Record one of:
- `cutover_kind=replacement`
- `cutover_kind=rotation`
- `cutover_kind=dr_rebuild`

Also record:
- `outgoing_validator_config=`
- `incoming_validator_config=`
- `expected_genesis_or_checkpoint=`
- `handoff_signed_by=` / `handoff_acknowledged_by=` when `cutover_kind=rotation` or `cutover_kind=dr_rebuild`
- `rollback_command=`

Interpretation rule:
- if the outgoing or incoming validator identity cannot be named explicitly, stop
- if `cutover_kind=rotation` or `cutover_kind=dr_rebuild` and either handoff signer/acknowledger is still unknown, stop
- if `cutover_kind=replacement`, leave `handoff_signed_by=` / `handoff_acknowledged_by=` empty rather than inventing a fake approval boundary
- if the rollback command is still "to be figured out later", stop

### 3. Re-check config bundle and ownership hygiene

Minimum commands:

```bash
git status --short
ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep
lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'
python3 scripts/v2/check_validator_config_bundle.py \
  configs/node1.toml \
  configs/node2.toml \
  configs/node3.toml \
  configs/node4.toml
```

Interpretation rule:
- the worktree must still be clean
- any ambiguous running owner is a stop condition
- the incoming validator config must pass the config-bundle check before cutover

### 4. Attach DR/recovery evidence when the event is a rebuild

For `cutover_kind=dr_rebuild`, attach one explicit recovery artifact instead of summarizing it from memory.

Recommended command:

```bash
./scripts/check_bft_restart_recovery.sh
```

Minimum DR evidence fields to preserve from the generated report:
- `generated_at=`
- `config_path=`
- `git_worktree_path=`
- `git_worktree_branch_ref=`
- `git_branch=`
- `git_head=`
- `git_status_summary=`
- `rollback_command=`
- `replay_command=`
- final pass/fail result

Copy the report path itself into the cutover note as `dr_summary_path=`, copy the report `generated_at=` into `dr_generated_at=`, and quote the emitted `rollback_command=` / `replay_command=` verbatim from that report. Treat missing `generated_at=` / `git_worktree_path=` / `git_status_summary=` as evidence-incomplete, because another operator should be able to audit artifact freshness, lane identity, and clean-tree status directly from the recovery report instead of reconstructing them from shell memory. The recovery script emits `status=PASS` on success; do not search for a non-existent `result=` field when auditing the report.
If release-evidence or RC artifacts also exist for the same handoff, prefer extracting the final handoff fields with the fail-closed helper instead of copying mixed snippets by hand:

```bash
./scripts/v2/extract_release_handoff_fields.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

When that helper is used, record at minimum:
- `handoff_summary_path=`
- `handoff_manifest_path=`
- `summary_generated_at=`
- `manifest_generated_at=`

Keep the two generated-at fields distinct. They do not need to match, but both must survive the handoff note so another operator can audit artifact freshness without relying on shell memory.

### 4a. Fail-closed DR evidence capture order

For a DR rebuild, preserve evidence in this order so the handoff can be audited without shell scrollback:

1. run `verify_lane_worktree.sh` with the **ticket-assigned** worktree path and branch ref (and `EXPECTED_HEAD` too when the ticket/handoff already pins an exact commit)
2. run `check_bft_restart_recovery.sh` and capture the emitted report path
3. copy `dr_summary_path=` and `dr_generated_at=` from that concrete report
4. copy `dr_replay_command=` / `dr_rollback_command=` verbatim from the report
5. if RC/release artifacts are part of the same event, run `extract_release_handoff_fields.sh` against the same expected worktree/branch and copy the emitted `handoff_*` / `*_generated_at` fields verbatim

Recommended shell shape:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}

EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT" \
EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF" \
./scripts/check_bft_restart_recovery.sh
report_path="$(ls -dt run/bft-restart-recovery-*.txt 2>/dev/null | head -n 1)"

[ -n "$report_path" ] || { echo "missing recovery report" >&2; exit 1; }
awk -F= '/^(generated_at|git_worktree_path|git_worktree_branch_ref|git_branch|git_head|git_status_summary|rollback_command|replay_command|status)=/ { print }' "$report_path"
```

Stop if any of the following occurs:
- `report_path` does not resolve to a concrete report
- `git_worktree_path=` in the report does not match the ticket-assigned worktree
- `git_worktree_branch_ref=` in the report does not match the ticket-assigned branch ref
- `verify_lane_worktree.sh` was expected to pin `EXPECTED_HEAD`, but the verified head does not match the ticket/handoff commit
- `git_status_summary=` is not `clean`
- `rollback_command=` or `replay_command=` is missing from the report

If recovery evidence cannot be produced from the current worktree, treat the DR rebuild as **No-Go**.

### 5. Perform the smallest credible replacement/rotation bootstrap

After the checks above, use the exact incoming config you intend to hand off and run the smallest credible bootstrap/re-bootstrap sanity from `validator-bootstrap-rebootstrap.md`.

Record:
- the exact bootstrap command used
- whether the cutover reached a clean pass/fail result
- whether the cutover reused an existing validator identity or introduced a replacement identity

## Minimum handoff fields

When handing this event to another operator, record:
- `cutover_kind=`
- worktree path
- branch ref
- HEAD commit
- outgoing validator config / identity
- incoming validator config / identity
- genesis artifact/hash or checkpoint lineage
- `handoff_signed_by=` / `handoff_acknowledged_by=` when `cutover_kind=rotation` or `cutover_kind=dr_rebuild`
- commands run
- pass/fail result
- rollback command
- DR report generated-at timestamp when DR evidence was required
- replay command when DR evidence was required
- one-line blocker if the event is not reproducible

## No-Go conditions

Treat replacement/rotation/DR as **No-Go** if any of the following is true:
- assigned worktree/branch identity is not proven
- outgoing or incoming validator ownership is ambiguous
- `cutover_kind=rotation` or `cutover_kind=dr_rebuild` and the handoff signer or acknowledger is missing
- the incoming config was not validated from a clean worktree
- the event depends on unstaged edits or undocumented manual shell state
- DR rebuild is claimed without a concrete recovery artifact
- the operator cannot quote the rollback command verbatim

## Rollback discipline

Rollback must be chosen before cutover, not invented after failure.

Typical rollback shape:
- stop the just-started validator process
- revert to the previously named validator owner/config/worktree
- remove only the artifacts created by the current DR/rebuild rehearsal

If the rollback path would require guessing which validator currently owns the process, the cutover was not operator-safe enough to begin.
