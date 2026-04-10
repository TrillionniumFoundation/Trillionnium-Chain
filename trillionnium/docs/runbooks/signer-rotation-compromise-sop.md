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

Do this before inspecting processes or claiming ownership.
Use the worktree path and branch ref from the ticket / lane assignment **directly**; do not first infer them from the current shell and then feed those inferred values back into verification.
The branch argument may be either the short branch name (for example `lane/mn07-offline-signing-tx-safety`) or the full ref (`refs/heads/lane/mn07-offline-signing-tx-safety`).

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="lane/assigned-branch"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Record verbatim:
- `expected_worktree_root=`
- `expected_branch_ref=`
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

Stop conditions:
- worktree mismatch
- branch mismatch
- detached HEAD
- expected ticket-assigned values were unavailable and the operator tried to substitute shell-inferred values
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
TRNM_RPC_TX_FILE="$(pwd)/run/rpc/txs.json"
export TRNM_RPC_TX_FILE
printf 'recorded_tx_file=%s\n' "$TRNM_RPC_TX_FILE"

./target/debug/trnm-cli tx query "$REQUESTED_TX_HASH"
./target/debug/trnm-cli tx wait "$REQUESTED_TX_HASH" --timeout 30 --interval 2
```

Operator safety rule:
- pin `TRNM_RPC_TX_FILE` to the exact pending-state file that was active for the submit path before running any follow-up `tx query` / `tx wait` command
- prefer freezing it as an absolute path from the active worktree, for example `TRNM_RPC_TX_FILE="$(pwd)/run/rpc/txs.json"`, and record that exact value next to `requested_tx_hash=` before any owner/worktree handoff
- if the cutover moved to a different worktree/host, copy the submit-path pending-state file into the new owner context (or mount the same absolute path) before reusing `REQUESTED_TX_HASH`
- do **not** let follow-up commands silently fall back to a different default `run/rpc/txs.json`; treat that as signer-path ambiguity until you can prove the pending-state file path is the same one recorded for the submit action

If the submit path is `trnm-cli` itself, capture the first shell-safe hash line once and freeze it as the operator truth-source before any later lookup rewrites the screen context:

```bash
SUBMIT_LOG=/tmp/trnm-submit.log
./target/debug/trnm-cli tx ... | tee "$SUBMIT_LOG"
REQUESTED_TX_HASH="$({
  grep -m1 -E '^tx_hash="0x[0-9A-Fa-f]+"$' "$SUBMIT_LOG" \
    || grep -m1 -E '^(txhash|transaction_hash|transaction-hash|transactionHash|tx-hash)=0x[0-9A-Fa-f]+$' "$SUBMIT_LOG" \
    || grep -m1 -E '^(tx hash|transaction hash)[[:space:]]*=[[:space:]]*0x[0-9A-Fa-f]+$' "$SUBMIT_LOG" \
    || exit 1
} | sed -E 's/^[^=]+=[[:space:]]*"?([^"]+)"?$/\1/')"
[ -n "$REQUESTED_TX_HASH" ] || {
  echo "failed to capture canonical tx hash from submit output" >&2
  exit 1
}
```

Operator input rule:
- capture the submit-path hash in canonical `0x...` form exactly once and reuse that same value for every follow-up command
- prefer the first emitted `tx_hash="0x..."` line from `trnm-cli` because it is shell-safe and maps directly to the canonical hash preserved in local pending state
- do **not** strip the `0x` prefix or replace the original submit-path hash with a later explorer/log rendering; `trnm-cli tx query` and `trnm-cli tx wait` fail closed on bare hex input because a missing prefix is treated as ambiguous operator evidence, not harmless formatting drift
- treat later bare-hex renderings, copied dashboard values, or explorer aliases as **display-only** until the operator manually confirms they normalize back to the same canonical `0x...` value; do not paste a non-canonical alias directly into follow-up commands
- when the submit path is `trnm-cli` itself, preserve the first emitted shell-safe `tx_hash="0x..."` line as the operator truth-source and keep the corresponding local pending-state record (`run/rpc/txs.json`, or `TRNM_RPC_TX_FILE` if overridden) until cutover validation is complete
- if an operator clipboard, chat transcript, or ticket comment contains multiple hash renderings for the same action, keep the original submit-path `requested_tx_hash=` field unchanged and record the other values as comparison evidence instead of promoting them into the truth-source slot

Record together:
- `requested_tx_hash=` from the submit path exactly once
- the first locally emitted shell-safe `tx_hash="0x..."` line from the submit path (if `trnm-cli` produced it)
- local pending-state file path used for the cutover (`run/rpc/txs.json` by default, or `TRNM_RPC_TX_FILE=` override)
- `query_tx_hash=` from `trnm-cli tx query`
- `wait_tx_hash=` from `trnm-cli tx wait`

Alias-handling rule:
- later tooling may echo the same canonical value under aliases such as `tx_hash="..."`, `txhash=`, `transaction_hash=`, `tx-hash=`, `transaction-hash=`, `transactionHash=`, `tx hash=`, or `transaction hash=`
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

## Day-1 signer safety checklist attachment

Attach this checklist to any launch packet, rehearsal decision memo, or signer handoff note that claims the signer path is ready enough for operator review.
Mark every item `PASS`, `FAIL`, or `NOT_APPLICABLE`; do not leave silent gaps.

- **identity bound** — ticket-assigned `expected_worktree_root=` and `expected_branch_ref=` were checked with `./scripts/v2/verify_lane_worktree.sh`, and the recorded `verified_worktree=` / `verified_branch_ref=` / `verified_head=` all match the assigned lane
- **clean owner context** — `git status --short` was empty before signer work began, and any later diff is either the intentional patch or explicitly recorded as blocking noise
- **single signer owner** — exactly one operator, process set, host, and worktree owned signing authority during the procedure; any ambiguity was classified as `SIGNER_OWNERSHIP_AMBIGUOUS`
- **severity declared** — the event was classified up front as either `planned_rotation` or `suspected_signer_compromise`; if uncertain, the packet uses the compromise classification
- **rollback/containment preserved** — one single-line rollback or containment command was written down before cutover and copied verbatim into the packet
- **targeted validation green** — the packet preserves the exact validation commands run (minimum: `git status --short`, `cargo check -p trnm-cli -q`) and whether each passed or failed
- **offline/manual submit continuity** — if any offline-signed or manually submitted transaction was involved, the original `requested_tx_hash=` stayed frozen as the truth-source and every later `query_tx_hash=` / `wait_tx_hash=` normalized to the same canonical `0x...` value
- **local pending-state evidence preserved** — the packet records the local pending-state file path (`run/rpc/txs.json` or `TRNM_RPC_TX_FILE=` override) until cutover validation is complete
- **no-go rule honored** — any identity drift, signer dual-ownership, tx-hash mismatch, or missing validation evidence was treated as `No-Go`, not downgraded into a warning
- **out-of-scope gaps called out** — the packet explicitly states that this checklist does not by itself close keystore architecture, remote signer/HSM integration, multisig policy, or broader public-mainnet readiness

Recommended packet footer fields:
- `signer_checklist_result=PASS|FAIL|CONDITIONAL`
- `rotation_class=planned|suspected_compromise`
- `rollback_command=`
- `requested_tx_hash=` (if applicable)
- `query_tx_hash=` / `wait_tx_hash=` (if applicable)
- `next_blocker=`

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