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
- `scripts/v2/extract_validator_rotation_dr_fields.sh`
- `scripts/v2/run_validator_dr_rehearsal.sh`

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
genesis_artifact_path=
genesis_artifact_sha256=
config_bundle_sha256=
validator_identity_check=
preflight_command=
preflight_result=
handoff_signed_by=
handoff_acknowledged_by=
operator_ack=
operator_ack_signature_path=
rollback_command=
config_bundle_check_command=
config_bundle_check_result=
config_bundle_check_log_path=
expected_worktree_root=
expected_branch_ref=
expected_head=
lane_verify_command=
handoff_summary_path=
handoff_manifest_path=
summary_generated_at=
manifest_generated_at=
dr_summary_path=
dr_generated_at=
dr_status=
dr_replay_command=
dr_rollback_command=
bootstrap_command=
captured_at_utc=
result=
next_blocker=
```

Rules:
- `dr_summary_path=` / `dr_generated_at=` / `dr_status=` / `dr_replay_command=` / `dr_rollback_command=` may remain empty unless `cutover_kind=dr_rebuild`.
- `genesis_artifact_path=` / `genesis_artifact_sha256=` / `config_bundle_sha256=` / `validator_identity_check=` / `preflight_command=` / `preflight_result=` / `captured_at_utc=` may remain empty unless `cutover_kind=dr_rebuild`; when the cutover is a rebuild, copy the genesis fields from the validated bootstrap packet and capture the remaining fields from the exact rebuild validation/bootstrap pass instead of reconstructing them from memory.
- `operator_ack=` may remain empty only for `cutover_kind=replacement`; once the event crosses a human handoff boundary (`rotation` or `dr_rebuild`), preserve one explicit operator acknowledgment line rather than relying on the signer/acknowledger names alone.
- `operator_ack_signature_path=` may remain empty when the acknowledgment is captured inline in the cutover note, but when a separate durable sign-off artifact exists, copy its immutable path verbatim.
- when `cutover_kind=dr_rebuild`, copy `dr_status=` verbatim from the selected recovery report's `status=` field; do not infer it from shell exit status, wrapper success text, or a hand-written `PASS`.
- `handoff_summary_path=` / `handoff_manifest_path=` / `summary_generated_at=` / `manifest_generated_at=` may remain empty unless release-evidence or RC artifacts are part of the handoff.
- `expected_worktree_root=` / `expected_branch_ref=` / `expected_head=` / `lane_verify_command=` may remain empty until Step 1 finishes, but once lane binding is part of the ticket or handoff they must be copied verbatim from the verification/recovery step instead of reconstructed from chat or shell memory.
- `config_bundle_check_command=` / `config_bundle_check_result=` may remain empty until Step 3 finishes, but they must be filled before any replacement / rotation / DR event can be called reproducible.
- `config_bundle_check_log_path=` may remain empty unless Step 3 needed a tee/log capture, but when the last-line verdict is ambiguous or the command spans multiple files it should point to the preserved full log instead of forcing a later operator to reconstruct stderr from memory.
- when `extract_release_handoff_fields.sh` is used, copy both artifact paths and both generated-at fields verbatim; do not collapse them into one hand-written timestamp.
- `result=` should stay empty until the smallest credible bootstrap/re-bootstrap sanity actually finishes.
- if any identity or rollback field cannot be filled before cutover, stop.

## Cutover evidence matrix

Use the smallest evidence set that still proves ownership, rollback, and artifact lineage for the specific cutover kind.
If any required row cannot be satisfied, treat the event as **No-Go** before execution.

| Cutover kind | Required identity fields | Required artifacts | Minimum stop condition if missing |
| --- | --- | --- | --- |
| `replacement` | `verified_worktree=` / `verified_branch_ref=` / `verified_head=` plus explicit outgoing and incoming validator identity/config | clean `git status --short`, config-bundle check output, exact `bootstrap_command=`, explicit `rollback_command=` | cannot name which validator identity is being retired vs activated |
| `rotation` | all replacement fields plus `handoff_signed_by=` / `handoff_acknowledged_by=` / `operator_ack=` and explicit lineage (`expected_genesis_or_checkpoint=`) | handoff note with signed/acknowledged ownership transfer, operator acknowledgment text, optional `handoff_summary_path=` / `handoff_manifest_path=` when release artifacts are part of the cutover | signer/acknowledger missing, operator acknowledgment missing, or rotation lineage cannot be stated from the note |
| `dr_rebuild` | all rotation fields plus `genesis_artifact_path=` / `genesis_artifact_sha256=` / `config_bundle_sha256=` / `validator_identity_check=` / `preflight_command=` / `preflight_result=` / `captured_at_utc=` and `dr_summary_path=` / `dr_generated_at=` / `dr_status=` / `dr_replay_command=` / `dr_rollback_command=` | concrete recovery artifact from the current worktree, operator acknowledgment text, the bootstrap packet lineage cited by path/hash, and the bootstrap/re-bootstrap sanity command used after rebuild | DR claimed but no path-resolved recovery report exists for the rebuild, or the rebuild cannot be tied back to the validated bootstrap tuple |

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

## Incident boundary: compromise is not a normal rotation

This runbook covers planned or explicitly-audited `replacement`, `rotation`, and `dr_rebuild` events.
It does **not** authorize a cutover that starts from suspected key compromise, signer leakage, or validator identity theft.

Treat the event as incident response instead of routine rotation if any of the following is true:
- the outgoing validator key may be exposed, copied, or controlled by an unknown party
- the operator cannot state whether the current signer is still trustworthy
- ownership transfer depends on "rotate first, investigate later"
- the rollback path would restore a validator identity that is itself suspected compromised

Fail-closed rule:
- stop the normal replacement / rotation / DR flow
- preserve the concrete evidence already gathered (`verified_worktree=`, `verified_branch_ref=`, `verified_head=`, current process ownership notes, and any generated report paths)
- open a dedicated compromise-response track before any public-mainnet-facing handoff is called reproducible

A planned validator replacement can become a compromise event mid-flight. If that happens, mark the current cutover `result=FAIL`, preserve the partially collected evidence, and do not relabel the same artifact set as a successful `rotation`.

## Minimal procedure

### 1. Re-prove worktree identity

Run the same fail-closed binding step used for validator bootstrap:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch" # or short name: lane/assigned-branch
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

Interpretation rule:
- `EXPECTED_BRANCH_REF` may be either a short branch name such as `lane/assigned-branch` or a full ref such as `refs/heads/lane/assigned-branch`; pick one from the ticket/handoff and copy it verbatim instead of normalizing by memory mid-cutover

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
- `outgoing_validator_identity=`
- `incoming_validator_config=`
- `incoming_validator_identity=`
- `expected_genesis_or_checkpoint=`
- `handoff_signed_by=` / `handoff_acknowledged_by=` when `cutover_kind=rotation` or `cutover_kind=dr_rebuild`
- `operator_ack=` when `cutover_kind=rotation` or `cutover_kind=dr_rebuild`
- `operator_ack_signature_path=` when a separate durable sign-off artifact exists
- `rollback_command=`

Interpretation rule:
- if the outgoing or incoming validator identity cannot be named explicitly, stop
- if `cutover_kind=rotation` or `cutover_kind=dr_rebuild` and either handoff signer/acknowledger is still unknown, stop
- if `cutover_kind=rotation` or `cutover_kind=dr_rebuild` and `operator_ack=` is still empty, stop
- copy `handoff_signed_by=` / `handoff_acknowledged_by=` as trimmed operator identifiers; leading/trailing whitespace is evidence-incomplete and should fail before packet generation
- if `cutover_kind=replacement`, leave `handoff_signed_by=` / `handoff_acknowledged_by=` empty rather than inventing a fake approval boundary
- if the rollback command is still "to be figured out later", stop

### 3. Re-check config bundle and ownership hygiene

Minimum commands:

```bash
git status --short
ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep
lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'
python3 scripts/v2/check_validator_config_bundle.py \
  <incoming-validator-config.toml> \
  [additional-config.toml ...]
```

Interpretation rule:
- the worktree must still be clean
- any ambiguous running owner is a stop condition
- validate the exact incoming validator config bundle named in the cutover note; do not substitute an unrelated demo quartet just because those files happen to exist in the repo
- copy the exact `python3 scripts/v2/check_validator_config_bundle.py ...` invocation into `config_bundle_check_command=` and the final pass/fail line into `config_bundle_check_result=` so another operator can audit which bundle was actually validated
- the incoming validator config must pass the config-bundle check before cutover

Recommended evidence-capture shape for the cutover note:

```bash
config_bundle_check_log_dir="run/validator-cutover"
mkdir -p "$config_bundle_check_log_dir"
config_bundle_check_log_path="$config_bundle_check_log_dir/config-bundle-check-$(date -u +%Y%m%dT%H%M%SZ).log"
config_bundle_check_command="python3 scripts/v2/check_validator_config_bundle.py configs/validator-new.toml"
config_bundle_check_result="$(python3 scripts/v2/check_validator_config_bundle.py configs/validator-new.toml 2>&1 | tee "$config_bundle_check_log_path" | tail -n 1)"
printf 'config_bundle_check_command=%s\n' "$config_bundle_check_command"
printf 'config_bundle_check_result=%s\n' "$config_bundle_check_result"
printf 'config_bundle_check_log_path=%s\n' "$config_bundle_check_log_path"
```

Interpretation rule:
- replace `configs/validator-new.toml` with the exact incoming bundle named in the cutover note (and append any additional config files to the same command when the bundle spans more than one file)
- preserve `config_bundle_check_log_path=` under the current worktree's `run/` directory rather than `/tmp` or another ephemeral location, so the handoff still points to a durable, lane-local log after shell exit or operator changeover
- keep the emitted `config_bundle_check_command=` / `config_bundle_check_result=` / `config_bundle_check_log_path=` lines adjacent in the handoff note so another operator can audit the exact bundle, terminal verdict, and full stderr/stdout capture together
- if the last line is ambiguous or truncated, preserve the full log path (for example `run/validator-cutover/config-bundle-check-<timestamp>.log`) next to the handoff note rather than paraphrasing the result from memory

### 3a. Fail-closed config bundle evidence capture order

Capture config-bundle evidence in this order so the handoff proves **which exact incoming bundle was validated**, not just that some last-line verdict looked green:

1. run `git status --short` and stop immediately if the worktree is not clean
2. write `config_bundle_check_command=` with the exact `python3 scripts/v2/check_validator_config_bundle.py ...` invocation for the incoming validator bundle named in the cutover note
3. run that exact command once, teeing stdout/stderr to `config_bundle_check_log_path=` when the validation spans multiple files or when the final line alone would not let another operator audit the full context
4. copy the emitted terminal verdict into `config_bundle_check_result=` without paraphrasing it
5. keep `config_bundle_check_command=` / `config_bundle_check_result=` / `config_bundle_check_log_path=` adjacent in the same note block before moving on to replacement / rotation / DR execution

Stop if any of the following occurs:
- the command you copied into `config_bundle_check_command=` is not the same command that produced the recorded verdict/log
- the validated bundle does not match the incoming validator config named in the cutover note
- the final line is ambiguous, truncated, or clearly refers to a different file set, and no preserved `config_bundle_check_log_path=` exists
- a later operator would need shell scrollback to reconstruct which bundle was actually checked

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
- `expected_worktree_root=`
- `expected_branch_ref=`
- `expected_head=` when the ticket or handoff already pinned a commit
- `lane_verify_command=`
- `rollback_command=`
- `replay_command=`
- final pass/fail result

Copy the report path itself into the cutover note as `dr_summary_path=`, copy the report `generated_at=` into `dr_generated_at=`, copy `dr_status=` verbatim from the report `status=` field, and quote the emitted `rollback_command=` / `replay_command=` verbatim from that report. Prefer `./scripts/v2/extract_validator_rotation_dr_fields.sh` so another operator copies one fail-closed field set rather than retyping ad hoc `awk` output. That helper now rejects non-`PASS` recovery reports, missing fields, and `--report-path` values that do not resolve under the current worktree's `run/` directory, so a stale, cross-worktree, or failed rebuild report cannot be silently handed off as valid DR evidence. When lane binding is enabled, also preserve `expected_worktree_root=` / `expected_branch_ref=` / `expected_head=` and the exact `lane_verify_command=` string from the same report so another operator can prove the rebuild was checked against the ticket-assigned lane rather than a self-derived shell guess. Treat missing `generated_at=` / `git_worktree_path=` / `git_status_summary=` as evidence-incomplete, because another operator should be able to audit artifact freshness, lane identity, and clean-tree status directly from the recovery report instead of reconstructing them from shell memory. If lane binding was expected for the event, treat missing `expected_worktree_root=` / `expected_branch_ref=` / `lane_verify_command=` the same way. The recovery script emits `status=PASS` on success; do not search for a non-existent `result=` field when auditing the report, and do not synthesize `dr_status=` from wrapper success alone.
If release-evidence or RC artifacts also exist for the same handoff, prefer extracting the final handoff fields with the fail-closed helper instead of copying mixed snippets by hand:

```bash
./scripts/v2/extract_release_handoff_fields.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

When that helper is used, record at minimum:
- `handoff_summary_path=` copied from the helper's emitted `summary_path=`
- `handoff_manifest_path=` copied from the helper's emitted `manifest_path=`
- `summary_generated_at=`
- `manifest_generated_at=`
- `expected_worktree_root=`
- `ticket_expected_branch_ref=`
- `expected_branch_ref=`
- `expected_head=` when the ticket or handoff pinned a commit

Keep the two generated-at fields distinct. They do not need to match, but both must survive the handoff note so another operator can audit artifact freshness without relying on shell memory. Keep the expected-worktree and expected-branch fields adjacent to those artifact paths so the signed packet still proves the cutover was audited against the ticket-assigned worktree instead of a self-derived shell guess.

### 4a. Fail-closed DR evidence capture order

For a DR rebuild, preserve evidence in this order so the handoff can be audited without shell scrollback:

1. run `verify_lane_worktree.sh` with the **ticket-assigned** worktree path and branch ref (and `EXPECTED_HEAD` too when the ticket/handoff already pins an exact commit)
2. run `check_bft_restart_recovery.sh` and capture the emitted `report_path` for **this exact run** instead of resolving "latest" from disk afterwards
3. copy `dr_summary_path=` / `dr_generated_at=` / `dr_status=` from that concrete report
4. copy `dr_replay_command=` / `dr_rollback_command=` verbatim from the report
5. if RC/release artifacts are part of the same event, run `extract_release_handoff_fields.sh` against the same expected worktree/branch and copy the emitted `summary_path=` into `handoff_summary_path=`, copy `manifest_path=` into `handoff_manifest_path=`, and preserve the emitted `*_generated_at` fields verbatim

Recommended shell shape:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch" # or short name: lane/assigned-branch
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}

recovery_stdout="$({
  EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT" \
  EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF" \
  EXPECTED_HEAD="$EXPECTED_HEAD" \
  ./scripts/check_bft_restart_recovery.sh;
} 2>&1)"
printf '%s\n' "$recovery_stdout"
report_path="$(printf '%s\n' "$recovery_stdout" | sed -n 's/^\[OK\] bft restart recovery passed: //p' | tail -n 1)"

[ -n "$report_path" ] || { echo "missing recovery report" >&2; exit 1; }
./scripts/v2/extract_validator_rotation_dr_fields.sh \
  --report-path "$report_path" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

Interpretation rule:
- prefer the `report_path` emitted by the script you just ran over `ls -dt run/bft-restart-recovery-*.txt | head -n 1`; the latter can bind the handoff to the wrong artifact when multiple operators or retries produce nearby reports in the same worktree
- when lane binding is expected, pass `--expected-worktree-root` and `--expected-branch-ref` together; the helper now rejects half-bound invocations so operators cannot accidentally treat a single self-supplied field as sufficient lane identity proof
- `--expected-branch-ref` may be either a short branch name or a full `refs/heads/...` ref, but the handoff note should preserve whichever form the ticket assigned rather than rewriting it during DR evidence capture

For operators who want one deterministic wrapper instead of manually chaining verify → recovery → extract, use:

```bash
./scripts/v2/run_validator_dr_rehearsal.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

This wrapper preserves the same fail-closed behavior, captures the concrete `report_path` emitted by the recovery run you just executed, and then prints the canonical `dr_*` fields as one block for the cutover note.

Recommended note-capture shape right after the helper succeeds:

```bash
dr_fields="$(./scripts/v2/extract_validator_rotation_dr_fields.sh \
  --report-path "$report_path" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"})"

printf '%s\n' "$dr_fields"
printf '%s\n' "$dr_fields" >> cutover-note.txt
```

Interpretation rule:
- keep the emitted `dr_summary_path=` / `dr_generated_at=` / `dr_status=` / `dr_replay_command=` / `dr_rollback_command=` lines adjacent in the cutover note so another operator can audit one coherent DR evidence block instead of reconstructing individual fields from shell history
- do not hand-copy only `dr_status=PASS` while dropping the corresponding report path or replay/rollback commands; the helper output is meant to travel as one fail-closed bundle
- do not rewrite `dr_status=` from memory after a green wrapper run; copy the literal report-backed value so later review can tie the cutover note to one concrete recovery artifact

Stop if any of the following occurs:
- `report_path` does not resolve to a concrete report
- `git_worktree_path=` in the report does not match the ticket-assigned worktree
- `git_worktree_branch_ref=` in the report does not match the ticket-assigned branch ref
- lane binding was expected, but `expected_worktree_root=` / `expected_branch_ref=` / `lane_verify_command=` are missing from the report
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
- config-bundle check command/result
- config-bundle check log path when tee/log capture was used
- pass/fail result
- rollback command
- for `cutover_kind=dr_rebuild`, also preserve `genesis_artifact_path=` / `genesis_artifact_sha256=` from the validated bootstrap packet, `config_bundle_sha256=`, `validator_identity_check=`, `preflight_command=`, `preflight_result=`, and `captured_at_utc=` from the exact rebuild pass
- DR summary/report path when DR evidence was required
- DR report generated-at timestamp when DR evidence was required
- DR report status when DR evidence was required
- replay command when DR evidence was required
- rollback command from the DR report when DR evidence was required
- one-line blocker if the event is not reproducible

## Minimum signed operator ceremony packet

For public-mainnet-facing replacement / rotation / DR rehearsal, do not stop at a green local shell run.
Attach one compact packet that another operator can audit without terminal scrollback:

1. the pre-filled cutover note with every required identity field resolved
2. the concrete worktree-binding proof from `verify_lane_worktree.sh`
3. the generated recovery / release artifacts referenced by path, not paraphrase
4. one explicit sign-off boundary:
   - `handoff_signed_by=` names the operator who is releasing ownership
   - `handoff_acknowledged_by=` names the operator who is accepting ownership
   - both names must be attached to the same artifact set and cutover kind

Fail-closed interpretation:
- a replacement may stay local/unsigned only when there is no human ownership boundary; once the event crosses operators, treat it as `rotation`
- if the handoff references release or RC evidence, preserve both `handoff_summary_path=` and `handoff_manifest_path=` together with both generated-at timestamps
- if the handoff references DR rebuild evidence, preserve `dr_summary_path=` together with `dr_generated_at=` / `dr_status=` / `dr_replay_command=` / `dr_rollback_command=` from the same concrete report
- if an operator name, artifact path, or generated-at field has to be reconstructed from chat or shell memory, the ceremony packet is incomplete and the event is **No-Go**

This packet does not make TRNM public-mainnet ready by itself, but it does close the operator-facing question "what exact signed evidence turns a local cutover rehearsal into an auditable handoff?"

When operators prefer a generated packet instead of hand-copying the skeleton, `./scripts/v2/emit_validator_rotation_packet.sh` now accepts the release-artifact pair `--handoff-summary-path` / `--handoff-manifest-path` together with `--summary-generated-at` / `--manifest-generated-at`, and fails closed if only a partial release-artifact set is supplied. When config-bundle evidence is included, the same helper now also rejects any `--config-bundle-check-command` that does not quote the exact `--incoming-config-path`, so a packet cannot silently reuse a green verdict from some other validator bundle. When lane binding is present, the same helper also requires `--expected-worktree-root`, `--expected-branch-ref`, and `--lane-verify-command` together (with optional `--expected-head`) so the generated packet cannot carry a half-copied lane identity. It also rejects packets whose `verified_worktree=` / `verified_branch_ref=` / `verified_head=` tuple drifts from that lane-bound expectation, so operators cannot pair a correct-looking verify command with a hand-copied packet body from the wrong lane tip. If any `--dr-*` evidence fields are supplied, the helper now also requires `--dr-status=PASS` and rejects any `--dr-summary-path` that resolves outside the current `verified_worktree` `run/` tree, so a generated packet cannot silently carry a failed, stale, or cross-worktree DR report as if it were valid handoff evidence. Use that path when the same cutover packet needs to carry both ownership sign-off and concrete release-evidence lineage.

### 6a. Copy-paste ceremony packet skeleton

Use this exact shape when a replacement crosses operators or when a DR rebuild is being handed off. Keep unresolved fields empty; do not backfill them from chat or shell memory after the fact.

```text
cutover_kind=rotation
verified_worktree=/abs/path/from-ticket
verified_branch_ref=refs/heads/lane/assigned-branch
verified_head=<git rev-parse HEAD>
outgoing_validator_config=configs/validator-old.toml
outgoing_validator_identity=<validator-id-or-key-fingerprint>
incoming_validator_config=configs/validator-new.toml
incoming_validator_identity=<validator-id-or-key-fingerprint>
expected_genesis_or_checkpoint=<genesis-hash-or-checkpoint>
genesis_artifact_path=<path copied from validated bootstrap packet when cutover_kind=dr_rebuild>
genesis_artifact_sha256=<hash copied from validated bootstrap packet when cutover_kind=dr_rebuild>
config_bundle_sha256=<checksum for the exact recovered config bundle when cutover_kind=dr_rebuild>
validator_identity_check=<validator entry or node ID proved by the rebuild when cutover_kind=dr_rebuild>
preflight_command=<exact validation command rerun after rebuild when cutover_kind=dr_rebuild>
preflight_result=<verbatim result from the rebuild preflight command when cutover_kind=dr_rebuild>
handoff_signed_by=<operator releasing ownership>
handoff_acknowledged_by=<operator accepting ownership>
rollback_command=<quoted verbatim from the cutover note or generated artifact>
config_bundle_check_command=<verbatim python3 scripts/v2/check_validator_config_bundle.py ... invocation>
config_bundle_check_result=<verbatim final OK/fail line for the exact incoming bundle>
config_bundle_check_log_path=<path to preserved tee/log output when used, else empty>
expected_worktree_root=<ticket-assigned worktree root>
expected_branch_ref=<ticket-assigned branch ref>
expected_head=<ticket-assigned commit or empty when not pinned>
lane_verify_command=<verbatim verify_lane_worktree.sh invocation>
handoff_summary_path=<path from extract_release_handoff_fields.sh or empty>
handoff_manifest_path=<path from extract_release_handoff_fields.sh or empty>
summary_generated_at=<verbatim summary generated_at or empty>
manifest_generated_at=<verbatim manifest generated_at or empty>
dr_summary_path=<path to recovery report when cutover_kind=dr_rebuild>
dr_generated_at=<verbatim generated_at from recovery report when cutover_kind=dr_rebuild>
dr_status=<verbatim status from recovery report when cutover_kind=dr_rebuild>
dr_replay_command=<verbatim replay_command from recovery report when cutover_kind=dr_rebuild>
dr_rollback_command=<verbatim rollback_command from recovery report when cutover_kind=dr_rebuild>
bootstrap_command=<exact bootstrap or re-bootstrap command>
captured_at_utc=<UTC timestamp recorded after the rebuild bootstrap sanity when cutover_kind=dr_rebuild>
result=PASS|FAIL
next_blocker=<one line or empty>
```

Fail-closed interpretation:
- for `cutover_kind=replacement`, `handoff_signed_by=` / `handoff_acknowledged_by=` may stay empty only when there is truly no cross-operator ownership boundary
- for `cutover_kind=rotation`, both handoff names must be present on the same note as the verified worktree/branch/head tuple
- for `cutover_kind=dr_rebuild`, do not mark `result=PASS` unless the same note also carries `expected_worktree_root=` / `expected_branch_ref=` / `lane_verify_command=` together with `dr_summary_path=` / `dr_generated_at=` / `dr_status=PASS` plus verbatim `dr_replay_command=` / `dr_rollback_command=` from one concrete report
- if `expected_worktree_root=` / `expected_branch_ref=` / `lane_verify_command=` had to be reconstructed from chat instead of copied from the lane-verification step, the packet is incomplete
- if `config_bundle_check_command=` / `config_bundle_check_result=` are missing or paraphrased, the packet is incomplete because the incoming validator bundle was not auditable as-validated
- if tee/log capture was used but `config_bundle_check_log_path=` is omitted, the packet is incomplete whenever the last-line verdict alone would not let another operator audit the exact failure/success context
- if `rollback_command=` was paraphrased instead of copied verbatim from the selected artifact or pre-declared cutover note, the packet is incomplete

## No-Go conditions

Treat replacement/rotation/DR as **No-Go** if any of the following is true:
- assigned worktree/branch identity is not proven
- outgoing or incoming validator ownership is ambiguous
- `cutover_kind=rotation` or `cutover_kind=dr_rebuild` and the handoff signer or acknowledger is missing
- the incoming config was not validated from a clean worktree
- the event depends on unstaged edits or undocumented manual shell state
- DR rebuild is claimed without a concrete recovery artifact
- the operator cannot quote the rollback command verbatim
- the event begins from suspected signer/key compromise or validator identity theft rather than a planned/audited cutover

## Rollback discipline

Rollback must be chosen before cutover, not invented after failure.

Typical rollback shape:
- stop the just-started validator process
- revert to the previously named validator owner/config/worktree
- remove only the artifacts created by the current DR/rebuild rehearsal

If the rollback path would require guessing which validator currently owns the process, the cutover was not operator-safe enough to begin.
