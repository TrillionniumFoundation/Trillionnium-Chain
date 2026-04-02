# TRNM Signer Rotation / Suspected Compromise SOP

Fail-closed operator runbook for rotating a validator or operator signing key, or responding to suspected signer compromise during prelaunch/mainnet rehearsal work.

This document is intentionally narrow:
- it does **not** claim TRNM public-mainnet readiness
- it does provide a concrete operator checklist for one of the current signer-path blockers
- it prefers explicit stop conditions over "probably fine" recovery

## Scope

Use this SOP when any of the following is true:
- a validator/operator key must be rotated on schedule
- a signing host/worktree is being replaced
- the signer key may have leaked, been copied, or been used by an unexpected process
- offline signing ownership is ambiguous and the operator needs a fail-closed response

Primary references:
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `scripts/v2/verify_lane_worktree.sh`

## Operator invariants

Before taking any signer action, all of the following must be true:
- you can name the exact worktree path, branch ref, and HEAD you are operating from
- `git status --short` is empty in the owning worktree
- exactly one operator owns the rotation action
- exactly one process/worktree/host is allowed to sign for the validator identity during the procedure
- the rollback or containment action is written down before touching any process

If any invariant fails, stop.

## Severity classification

### A. Planned rotation
Use when the signer is being replaced intentionally and there is **no** evidence of key leakage.

### B. Suspected compromise
Use when any of the following is true:
- you cannot prove which process/host currently owns the signer
- a key file may have been copied to an unapproved location
- unexpected signatures, tx submissions, or process restarts were observed
- an operator cannot prove whether the key was ever exposed

Rule: when in doubt, classify as **suspected compromise**.

## Step 1 — Bind to the assigned lane/worktree

Do this before inspecting processes or claiming ownership:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Record verbatim:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

Stop conditions:
- worktree mismatch
- branch mismatch
- detached HEAD
- current shell cannot be bound to the ticket-assigned lane

## Step 2 — Establish signer exclusivity

Before rotation or containment, prove the signer is not active in two places at once:

```bash
ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep
lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'
```

Operator rule:
- if any unexpected validator/signer process is active, stop and classify as `SIGNER_OWNERSHIP_AMBIGUOUS`
- do **not** rotate while an unaccounted signer process may still be live
- do **not** describe the state as GO/green until one explicit owner is named

## Step 3 — Decide the lane

### Planned rotation lane
Proceed only if:
- signer ownership is unambiguous
- the old signer can be stopped cleanly
- the new signer material/location has been pre-approved
- the operator can name the exact rollback action

### Suspected compromise lane
Immediate containment first:
1. stop the signer process that may still own the validator identity
2. freeze further signing from the old location/worktree
3. mark any pending handoff or rehearsal result as **No-Go** until the rotation completes
4. require a new signer location/material instead of reusing the ambiguous path

Minimum containment note:
- `incident_class=suspected_signer_compromise`
- `affected_worktree=`
- `affected_branch_ref=`
- `suspected_owner=`
- `containment_action=`

## Step 4 — Execute the smallest safe cutover

The cutover must stay minimal and auditable:
1. stop the old signer/node process
2. confirm the old process is no longer live
3. switch to the new signer location/host/worktree
4. re-run the lane/worktree identity check from Step 1 in the new owner context
5. perform the smallest bootstrap/re-bootstrap sanity pass
6. record whether this was planned rotation or compromise response

What must be recorded together:
- previous owner worktree/host/process
- new owner worktree/host/process
- exact commands run
- pass/fail result
- rollback/containment command

## Step 5 — Post-cutover validation

Minimum validation after the new signer takes ownership:

```bash
git status --short
cargo check -p trnm-cli -q
```

If the cutover includes any offline-signed or manually submitted transaction, record the locally expected tx hash and verify that every later lookup returns the same canonical hash:
- save the requested hash exactly once from the submit path (`requested_tx_hash=`)
- compare it against the hash returned by every follow-up query/wait path
- if any query returns a different normalized hash for the same operator action, stop and classify the procedure as **No-Go**
- do **not** treat a tx-hash mismatch as cosmetic formatting drift; treat it as signer-path ambiguity or wrong-transaction evidence until disproven

Minimum operator pattern after manual/offline submit:

```bash
REQUESTED_TX_HASH="0x...captured-from-submit-path..."

./target/debug/trnm-cli tx query "$REQUESTED_TX_HASH"
./target/debug/trnm-cli tx wait "$REQUESTED_TX_HASH" --timeout 30 --interval 2
```

Operator input rule:
- capture the submit-path hash in canonical `0x...` form exactly once and reuse that same value for every follow-up command
- do **not** strip the `0x` prefix or replace the original submit-path hash with a later explorer/log rendering; `trnm-cli tx query` and `trnm-cli tx wait` fail closed on bare hex input because a missing prefix is treated as ambiguous operator evidence, not harmless formatting drift

Record together:
- `requested_tx_hash=` from the submit path exactly once
- `query_tx_hash=` from `trnm-cli tx query`
- `wait_tx_hash=` from `trnm-cli tx wait`

Alias-handling rule:
- later tooling may echo the same canonical value under aliases such as `tx_hash=`, `tx-hash=`, `transaction_hash=`, `transaction-hash=`, or `transactionHash=`
- treat those as formatting aliases only after they normalize to the exact same canonical tx hash
- do not overwrite the original `requested_tx_hash=` field with a later alias line; keep the first captured submit-path hash as the source of truth for the entire procedure

Fail-closed rule:
- if `query_tx_hash` or `wait_tx_hash` normalizes to a different value than `requested_tx_hash`, stop and treat the cutover as wrong-transaction or signer-path ambiguity evidence
- do not replace the original requested hash mid-procedure just because a later shell command prints a differently formatted alias

And re-run the operator checks from:
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`

Interpretation rule:
- if identity, process exclusivity, targeted validation, or tx-hash continuity cannot be proven after cutover, treat the rotation as blocked
- do not normalize an ambiguous signer state into a soft warning

## Rollback / containment

### Planned rotation rollback
Use when the new signer failed validation but the old signer was never suspected compromised.

Typical shape:
```bash
pkill -f 'trnm-node|cometbft'
# then return ownership to the previously recorded known-good signer context
```

### Suspected compromise containment
Use when the old signer may be exposed.

Rule:
- do **not** roll back to the suspect signer context just because the replacement failed fast
- keep the old signer disabled until ownership and exposure are resolved explicitly

## Required report fields

For every rotation/compromise run, record:
- changed files (or `none`, if procedure-only)
- exact commands run
- pass/fail result
- rollback command
- next blocker (one line)
- `rotation_class=planned|suspected_compromise`
- `old_signer_owner=`
- `new_signer_owner=`
- `root_cause=` (`SCHEDULED_ROTATION`, `SIGNER_OWNERSHIP_AMBIGUOUS`, `HOST_REBUILD`, `SUSPECTED_KEY_EXPOSURE`)

## Non-go conditions

Treat the signer procedure as **No-Go** if any of the following is true:
- the assigned worktree/ref is not proven
- the old signer may still be live in another process/worktree/host
- the new signer owner cannot be named explicitly
- the rollback/containment command is missing
- the operator cannot distinguish planned rotation from suspected compromise
- post-cutover targeted validation is red or skipped

This SOP closes a small documentation gap for signer rotation / suspected compromise handling, but it does **not** by itself close the broader TRNM signer-path blocker: secure keystore architecture, true offline signing flow, remote signer/HSM integration, and operator-safe transaction UX remain open.