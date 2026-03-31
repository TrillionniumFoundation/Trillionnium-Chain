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

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Record:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

### 2. Name the cutover shape before execution

Record one of:
- `cutover_kind=replacement`
- `cutover_kind=rotation`
- `cutover_kind=dr_rebuild`

Also record:
- `outgoing_validator_config=`
- `incoming_validator_config=`
- `expected_genesis_or_checkpoint=`
- `handoff_signed_by=`
- `handoff_acknowledged_by=`
- `rollback_command=`

Interpretation rule:
- if the outgoing or incoming validator identity cannot be named explicitly, stop
- if either handoff signer/acknowledger is still unknown, stop
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
- `config_path=`
- `git_branch=`
- `git_head=`
- `rollback_command=`
- `replay_command=`
- final pass/fail result

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
- `handoff_signed_by=`
- `handoff_acknowledged_by=`
- commands run
- pass/fail result
- rollback command
- replay command when DR evidence was required
- one-line blocker if the event is not reproducible

## No-Go conditions

Treat replacement/rotation/DR as **No-Go** if any of the following is true:
- assigned worktree/branch identity is not proven
- outgoing or incoming validator ownership is ambiguous
- handoff signer or acknowledger is missing
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
