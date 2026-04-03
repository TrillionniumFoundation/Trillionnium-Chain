# TRNM Mainnet Rehearsal GO / NO-GO Template

Use this template when converting a local RC / rehearsal run into a decision memo.

This template is intentionally fail-closed:
- it is for **integrated prelaunch rehearsal** on the assigned worktree/branch only
- it does **not** by itself prove public-mainnet readiness
- if any required path or identity field is missing, the decision must remain **NO-GO** or **evidence-incomplete**

Companion truth sources:
- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`

---

## 1. Decision header

- decision: `GO` | `CONDITIONAL GO` | `NO-GO`
- decision_scope: `local rehearsal only` | `internal RC only` | `public-mainnet candidate review`
- decision_timestamp_utc:
- decision_owner:
- reviewer(s):
- assigned worktree:
- assigned branch ref:
- evaluated repo root:
- evaluated branch:
- evaluated head:
- evaluated origin/main:

Rule:
- if `assigned worktree` / `assigned branch ref` are not recorded from the ticket before quoting artifacts, stop and mark the packet **evidence-incomplete**
- when this memo cites `RELEASE_READINESS.md` as a truth source, it must also record the current `origin/main` commit (`git rev-parse origin/main`) for the evaluated snapshot; if `evaluated origin/main` is missing, decision cannot exceed **NO-GO**

## 2. Pre-run lane identity proof

Before any release/evidence script runs, record the validator signing ownership note and capture the fail-closed helper output verbatim.

Single-signer / process exclusivity note (required for any validator/operator-bound rehearsal):
- signer_exclusivity_note=
- checked_process_command=`ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep`
- checked_process_output=
- checked_listener_command=`lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'`
- checked_listener_output=

Capture the fail-closed helper output verbatim before any release/evidence script runs:

```bash
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch"
```

`--expected-branch-ref` may be either the short branch name from the ticket (for example `lane/assigned-branch`) or the fully qualified ref (`refs/heads/lane/assigned-branch`), but the memo should preserve exactly which form the ticket assigned.

Record:
- signer_exclusivity_note=
- checked_process_output=
- checked_listener_output=
- verified_worktree=
- verified_branch_ref=
- verified_head=
- verified_worktree_entry=
- `git status --short` result:

Rule:
- if signer ownership is ambiguous, if either exclusivity check output is missing, if the helper fails, if `git status --short` is non-empty, or if the recorded values were inferred from the shell instead of the assigned ticket values, decision = **NO-GO**

## 3. Artifact path resolution

Resolve the exact evidence files from disk before quoting any PASS / GO language:

```bash
latest_preflight_path="run/preflight/go-no-go-latest.txt"
[ -f "$latest_preflight_path" ] || { echo "missing preflight artifact" >&2; exit 1; }
printf 'preflight_path=%s\n' "$latest_preflight_path"
printf 'preflight_summary_path=%s\n' "$latest_preflight_path"
awk -F= '/^(result|generated_at|git_toplevel|git_branch|git_head|git_head_state|git_status_summary|git_worktree_path|git_worktree_branch_ref|git_worktree_branch_ref_match|expected_worktree_root|ticket_expected_branch_ref|expected_branch_ref|expected_head|rollback_command|replay_command)=/ { print }' "$latest_preflight_path"

latest_evidence_dir="$(ls -dt run/health/evidence-* 2>/dev/null | head -n 1)"
[ -n "$latest_evidence_dir" ] || { echo "missing release evidence dir" >&2; exit 1; }
summary_path="$latest_evidence_dir/summary.txt"
[ -f "$summary_path" ] || { echo "missing summary artifact" >&2; exit 1; }
printf 'summary_path=%s\n' "$summary_path"

latest_rc_dir="$(ls -dt release/rc-* 2>/dev/null | head -n 1)"
[ -n "$latest_rc_dir" ] || { echo "missing release rc dir" >&2; exit 1; }
manifest_path="$latest_rc_dir/manifest.txt"
[ -f "$manifest_path" ] || { echo "missing manifest artifact" >&2; exit 1; }
printf 'manifest_path=%s\n' "$manifest_path"

handoff_helper_output_path="run/preflight/handoff-fields-$(date -u +%Y%m%dT%H%M%SZ).txt"
mkdir -p "$(dirname "$handoff_helper_output_path")"
./scripts/v2/extract_release_handoff_fields.sh \
  --summary-path "$summary_path" \
  --manifest-path "$manifest_path" \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch" \
  | tee "$handoff_helper_output_path"
printf 'handoff_helper_output_path=%s\n' "$handoff_helper_output_path"
```

As with the pre-run helper, `--expected-branch-ref` may be supplied as either the short branch name from the ticket or the full ref. Preserve both forms in the memo: record `ticket_expected_branch_ref=` from the helper output as the exact ticket-assigned form, and record `expected_branch_ref=` / `git_expected_worktree_branch_ref=` as the canonicalized branch ref emitted by the helper/artifacts.

Treat the helper output as a first-class artifact for memo assembly, not throwaway terminal scrollback. Preserve it (or an equivalent saved transcript) so `summary_generated_at=`, `manifest_generated_at=`, `git_expected_worktree_branch_ref=`, `git_status_summary=`, `truth_source=`, `historical_evidence_only=`, `evidence_scope=`, `summary_rollback_command=`, `summary_replay_command=`, `manifest_rollback_command=`, and `manifest_replay_command=` can all be quoted from the helper/artifacts rather than recopied from memory.

Record:
- preflight_path=
- preflight_summary_path=
- summary_path=
- manifest_path=
- handoff_helper_output_path=
- preflight_result=
- preflight_generated_at=
- preflight_git_toplevel=
- preflight_git_branch=
- preflight_git_head=
- preflight_git_head_state=
- preflight_git_status_summary=
- preflight_expected_worktree_root=
- preflight_ticket_expected_branch_ref=
- preflight_expected_branch_ref=
- preflight_expected_head=
- preflight_git_worktree_path=
- preflight_git_worktree_branch_ref=
- preflight_git_worktree_branch_ref_match=
- preflight_rollback_command=
- preflight_replay_command=
- summary_generated_at=
- manifest_generated_at=
- git_expected_worktree_branch_ref=

Rule:
- if `preflight_path`, `preflight_summary_path`, `summary_path`, or `manifest_path` is missing or unresolved, decision = **NO-GO**
- if the preflight artifact/helper transcript does not preserve `result=`, `generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `expected_worktree_root=`, `ticket_expected_branch_ref=`, `expected_branch_ref=`, `rollback_command=`, and `replay_command=`, decision = **NO-GO**
- if the ticket assigned an expected head, preserve `expected_head=` verbatim from the preflight artifact and require it to match the ticket-assigned value; do not silently downgrade that field into an optional note
- treat `expected_worktree_root=` plus `ticket_expected_branch_ref=` as the ticket-binding proof for the rehearsal packet, and keep `expected_branch_ref=` as the canonicalized companion field rather than a replacement for the ticket-original form

## 4. Required cross-artifact identity fields

Copy these fields from the extracted artifact output or directly from `go-no-go-latest.txt`, `summary.txt`, and `manifest.txt`:

- `git_toplevel=`
- `git_branch=`
- `git_head=`
- `git_head_state=`
- `git_worktree_path=`
- `git_worktree_branch_ref=`
- `git_expected_worktree_branch_ref=`
- `git_worktree_branch_ref_match=`
- `git_status_summary=`
- `preflight_generated_at=`
- `summary_generated_at=`
- `manifest_generated_at=`
- `truth_source=`
- `historical_evidence_only=`
- `evidence_scope=`
- `evaluated_origin_main=`

Decision rule:
- `preflight_result=GO` is mandatory before quoting later PASS / GO language
- `evaluated_origin_main=` must be recorded whenever this memo cites `RELEASE_READINESS.md`; do not reuse a stale hash from an older packet
- preflight `git_worktree_path=` / `git_worktree_branch_ref=` must match the assigned worktree/branch, not just exist
- preflight `expected_worktree_root=` plus `ticket_expected_branch_ref=` must preserve the ticket-assigned values verbatim; `expected_branch_ref=` may be the helper's canonicalized form, but the memo must retain the ticket-original form too. A packet is incomplete if the preflight artifact/helper transcript only proves the current shell was self-consistent
- if the ticket assigned an expected head, preflight `expected_head=` must match it verbatim
- preflight `git_worktree_branch_ref_match=true` is mandatory before later summary/manifest evidence can be treated as lane-bound
- summary/manifest `git_worktree_branch_ref_match=true` is also mandatory; do not let a green preflight soften a later artifact mismatch
- all three stages (preflight / summary / manifest) must agree on lane identity; a two-of-three match is still **NO-GO**
- `git_status_summary=clean` is mandatory
- `preflight_generated_at=`, `summary_generated_at=`, and `manifest_generated_at=` must all be present and quoted as separate artifact timestamps; do not collapse them into one hand-copied `generated_at=` line
- the summary and manifest values must match each other and match the assigned worktree/branch
- any mismatch = **NO-GO**

## 5. Gate summary

Record exact commands, resolved artifact paths, and outcomes:

- preflight command:
- preflight artifact:
- preflight result:
- local evidence command:
- local evidence result:
- RC rehearsal command:
- RC rehearsal result:
- nightly/policy gate result:

Minimum interpretation:
- `GO` requires all local gates green and no unresolved policy blocker
- `CONDITIONAL GO` is allowed only when local evidence is green and the remaining blocker is an explicitly preserved external policy gate
- any ambiguous, skipped, hand-edited, or missing gate record = **NO-GO**

## 6. Replay / rollback discipline

Quote verbatim from generated artifacts:

- summary_rollback_command=
- summary_replay_command=
- manifest_rollback_command=
- manifest_replay_command=
- challenge_reexec_entry=
- replay_env_trnm_challenge_reexec_entry=

Record one explicit rollback-drill note for the packet:

- rollback_drill_scope: `docs-only` | `artifact replay only` | `operator procedure walkthrough` | `executed on rehearsal environment`
- rollback_drill_command=
- rollback_drill_result: `PASS` | `FAIL` | `NOT_RUN`
- rollback_drill_evidence=

Rule:
- do not rewrite these commands from shell memory
- use `summary_*` commands only for local-evidence conclusions and `manifest_*` commands only for RC rehearsal conclusions; do not collapse them into one synthetic command if the artifacts differ
- `rollback_drill_command=` must either quote the stage-appropriate generated rollback command verbatim (`summary_rollback_command=` for local evidence or `manifest_rollback_command=` for RC rehearsal) or explicitly explain why a narrower docs-only/procedure-only drill was used
- if `rollback_drill_result=NOT_RUN`, decision cannot exceed `CONDITIONAL GO`
- if `challenge_reexec_entry=<entry_not_found>` appears, preserve it literally and treat the packet as incomplete unless the scope explicitly allows that absence

## 7. Blocker classification

- blocker_type: `none` | `code` | `env` | `policy` | `evidence` | `operator`
- blocker_summary:
- root_cause_tag: `CI_FLAKE` | `ENV_DRIFT` | `DOC_DRIFT` | `MISSING_FIXTURE` | `NON_DETERMINISTIC_TEST` | `POLICY_GATE` | `IDENTITY_DRIFT`
- next_blocker:

Rule:
- if blocker_type is `evidence` or `operator`, do not upgrade the packet to `CONDITIONAL GO`; keep it **NO-GO**

## 8. Launch-boundary statement

Required paragraph:

> This memo evaluates a specific rehearsal packet on a specific worktree/branch snapshot. It does not by itself override `RELEASE_READINESS.md` or collapse the public-mainnet P0 blockers listed in `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` and `TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`.

## 9. Decision checklist

Mark each item explicitly:

- [ ] assigned worktree / branch recorded from ticket
- [ ] signer/process exclusivity checked and recorded
- [ ] `checked_process_output=` preserved next to signer exclusivity note
- [ ] `checked_listener_output=` preserved next to signer exclusivity note
- [ ] `verify_lane_worktree.sh` passed using ticket-assigned values
- [ ] `verified_worktree=` preserved from helper output
- [ ] `verified_branch_ref=` preserved from helper output
- [ ] `verified_head=` preserved from helper output
- [ ] `verified_worktree_entry=` preserved from helper output / `git worktree list --porcelain` stanza
- [ ] `git status --short` empty before evidence generation
- [ ] `preflight_path` resolved from disk
- [ ] `preflight_summary_path` resolved from disk
- [ ] `summary_path` resolved from disk
- [ ] `manifest_path` resolved from disk
- [ ] `handoff_helper_output_path` resolved from disk and preserved as a first-class artifact
- [ ] summary/manifest identity fields match each other
- [ ] summary/manifest identity fields match assigned worktree/branch
- [ ] `git_worktree_branch_ref_match=true`
- [ ] `git_status_summary=clean`
- [ ] `preflight_generated_at=` preserved next to preflight decision language
- [ ] `preflight_git_toplevel=` preserved next to preflight decision language
- [ ] `preflight_git_branch=` preserved next to preflight decision language
- [ ] `preflight_git_head=` preserved next to preflight decision language
- [ ] `preflight_git_head_state=` preserved next to preflight decision language
- [ ] `preflight_git_status_summary=` preserved next to preflight decision language
- [ ] `preflight_expected_worktree_root=` preserved next to preflight decision language
- [ ] `preflight_ticket_expected_branch_ref=` preserved next to preflight decision language
- [ ] `preflight_expected_branch_ref=` preserved next to preflight decision language
- [ ] `preflight_expected_head=` preserved when the ticket assigned one
- [ ] `preflight_git_worktree_path=` preserved next to preflight decision language
- [ ] `preflight_git_worktree_branch_ref=` preserved next to preflight decision language
- [ ] `preflight_git_worktree_branch_ref_match=true` preserved next to preflight decision language
- [ ] `preflight_rollback_command=` quoted verbatim next to preflight decision language
- [ ] `preflight_replay_command=` quoted verbatim next to preflight decision language
- [ ] `summary_generated_at=` preserved next to local-evidence decision language
- [ ] `manifest_generated_at=` preserved next to RC decision language
- [ ] `git_expected_worktree_branch_ref=` preserved next to summary/manifest decision language
- [ ] preflight identity fields preserved next to preflight decision language
- [ ] `truth_source=` preserved next to decision language
- [ ] `historical_evidence_only=` preserved next to decision language
- [ ] `evidence_scope=` preserved next to decision language
- [ ] `evaluated_origin_main=` recorded from `git rev-parse origin/main` for this packet
- [ ] `summary_rollback_command=` quoted verbatim
- [ ] `summary_replay_command=` quoted verbatim
- [ ] `manifest_rollback_command=` quoted verbatim
- [ ] `manifest_replay_command=` quoted verbatim
- [ ] rollback drill scope/command/result recorded
- [ ] remaining blocker, if any, is explicitly classified

## 10. Final memo stub

```text
decision=<GO|CONDITIONAL GO|NO-GO>
decision_scope=<local rehearsal only|internal RC only|public-mainnet candidate review>
assigned_worktree=<ticket path>
assigned_branch_ref=<ticket ref>
signer_exclusivity_note=<one line>
checked_process_output=<captured command output or explicit "no matching process">
checked_listener_output=<captured command output or explicit "no matching listener">
verified_worktree=<helper output>
verified_branch_ref=<helper output>
verified_head=<helper output>
verified_worktree_entry=<captured current-path stanza from helper output or git worktree list --porcelain>
preflight_path=<resolved path>
preflight_summary_path=<resolved path>
summary_path=<resolved path>
manifest_path=<resolved path>
handoff_helper_output_path=<resolved saved helper transcript path>
preflight_result=<GO|NO-GO>
preflight_generated_at=<artifact value>
preflight_git_toplevel=<artifact value>
preflight_git_branch=<artifact value>
preflight_git_head=<artifact value>
preflight_git_head_state=<artifact value>
preflight_git_status_summary=<artifact value>
preflight_git_worktree_path=<artifact value>
preflight_git_worktree_branch_ref=<artifact value>
preflight_git_worktree_branch_ref_match=<true|false|unknown>
preflight_expected_worktree_root=<artifact value>
preflight_ticket_expected_branch_ref=<helper transcript value preserving ticket form>
preflight_expected_branch_ref=<artifact/helper canonicalized value>
preflight_expected_head=<artifact value or <unset>>
preflight_rollback_command=<artifact value>
preflight_replay_command=<artifact value>
summary_generated_at=<artifact value>
manifest_generated_at=<artifact value>
git_branch=<artifact value>
git_head=<artifact value>
git_worktree_path=<artifact value>
git_worktree_branch_ref=<artifact value>
git_expected_worktree_branch_ref=<artifact value>
git_worktree_branch_ref_match=<true|false|unknown>
git_status_summary=<clean|dirty|unknown>
truth_source=<artifact value>
historical_evidence_only=<artifact value>
evidence_scope=<artifact value>
evaluated_origin_main=<git rev-parse origin/main at memo time>
summary_rollback_command=<summary artifact value>
summary_replay_command=<summary artifact value>
manifest_rollback_command=<manifest artifact value>
manifest_replay_command=<manifest artifact value>
challenge_reexec_entry=<artifact value including <entry_not_found> when present>
replay_env_trnm_challenge_reexec_entry=<artifact value including <entry_not_found> when present>
rollback_drill_scope=<docs-only|artifact replay only|operator procedure walkthrough|executed on rehearsal environment>
rollback_drill_command=<artifact value or documented narrower drill command>
rollback_drill_result=<PASS|FAIL|NOT_RUN>
rollback_drill_evidence=<path|note>
blocker_type=<none|code|env|policy|evidence|operator>
blocker_summary=<one line>
next_blocker=<one line>
```
