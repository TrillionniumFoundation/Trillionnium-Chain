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

Rule:
- if `assigned worktree` / `assigned branch ref` are not recorded from the ticket before quoting artifacts, stop and mark the packet **evidence-incomplete**

## 2. Pre-run lane identity proof

Before any release/evidence script runs, record the validator signing ownership note and capture the fail-closed helper output verbatim.

Single-signer / process exclusivity note (required for any validator/operator-bound rehearsal):
- signer_exclusivity_note=
- checked_process_command=`ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep`
- checked_listener_command=`lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'`

Capture the fail-closed helper output verbatim before any release/evidence script runs:

```bash
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch"
```

Record:
- signer_exclusivity_note=
- verified_worktree=
- verified_branch_ref=
- verified_head=
- `git status --short` result:

Rule:
- if signer ownership is ambiguous, if the helper fails, if `git status --short` is non-empty, or if the recorded values were inferred from the shell instead of the assigned ticket values, decision = **NO-GO**

## 3. Artifact path resolution

Resolve the exact evidence files from disk before quoting any PASS / GO language:

```bash
latest_preflight_path="run/preflight/go-no-go-latest.txt"
[ -f "$latest_preflight_path" ] || { echo "missing preflight artifact" >&2; exit 1; }
printf 'preflight_path=%s\n' "$latest_preflight_path"
awk -F= '/^(result|generated_at|git_toplevel|git_branch|git_head|git_head_state|git_status_summary|git_worktree_path|git_worktree_branch_ref|expected_worktree_root|expected_branch_ref|expected_head|rollback_command|replay_command)=/ { print }' "$latest_preflight_path"

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

./scripts/v2/extract_release_handoff_fields.sh \
  --summary-path "$summary_path" \
  --manifest-path "$manifest_path" \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch"
```

Record:
- preflight_path=
- summary_path=
- manifest_path=
- preflight_result=
- preflight_generated_at=
- preflight_expected_worktree_root=
- preflight_expected_branch_ref=
- preflight_expected_head=
- summary_generated_at=
- manifest_generated_at=

Rule:
- if `preflight_path`, `summary_path`, or `manifest_path` is missing or unresolved, decision = **NO-GO**
- if the preflight artifact does not preserve `result=`, `generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `expected_worktree_root=`, `expected_branch_ref=`, `rollback_command=`, and `replay_command=`, decision = **NO-GO**
- if the ticket assigned an expected head, preserve `expected_head=` verbatim from the preflight artifact and require it to match the ticket-assigned value; do not silently downgrade that field into an optional note
- treat `expected_worktree_root=` / `expected_branch_ref=` in the preflight artifact as the ticket-binding proof for the rehearsal packet, not as decorative metadata

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
- `generated_at=`
- `truth_source=`
- `historical_evidence_only=`
- `evidence_scope=`

Decision rule:
- `preflight_result=GO` is mandatory before quoting later PASS / GO language
- preflight `git_worktree_path=` / `git_worktree_branch_ref=` must match the assigned worktree/branch, not just exist
- preflight `expected_worktree_root=` / `expected_branch_ref=` must also match the ticket-assigned values verbatim; a packet is incomplete if the preflight artifact only proves the current shell was self-consistent
- if the ticket assigned an expected head, preflight `expected_head=` must match it verbatim
- `git_worktree_branch_ref_match=true` is mandatory
- `git_status_summary=clean` is mandatory
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

- rollback_command=
- replay_command=
- challenge_reexec_entry=
- replay_env_trnm_challenge_reexec_entry=

Rule:
- do not rewrite these commands from shell memory
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
- [ ] `verify_lane_worktree.sh` passed using ticket-assigned values
- [ ] `git status --short` empty before evidence generation
- [ ] `preflight_path` resolved from disk
- [ ] `summary_path` resolved from disk
- [ ] `manifest_path` resolved from disk
- [ ] summary/manifest identity fields match each other
- [ ] summary/manifest identity fields match assigned worktree/branch
- [ ] `git_worktree_branch_ref_match=true`
- [ ] `git_status_summary=clean`
- [ ] `preflight_generated_at=` preserved next to preflight decision language
- [ ] `preflight_expected_worktree_root=` preserved next to preflight decision language
- [ ] `preflight_expected_branch_ref=` preserved next to preflight decision language
- [ ] `preflight_expected_head=` preserved when the ticket assigned one
- [ ] `summary_generated_at=` preserved next to local-evidence decision language
- [ ] `manifest_generated_at=` preserved next to RC decision language
- [ ] preflight identity fields preserved next to preflight decision language
- [ ] `truth_source=` preserved next to decision language
- [ ] `historical_evidence_only=` preserved next to decision language
- [ ] `rollback_command=` quoted verbatim
- [ ] `replay_command=` quoted verbatim
- [ ] remaining blocker, if any, is explicitly classified

## 10. Final memo stub

```text
decision=<GO|CONDITIONAL GO|NO-GO>
decision_scope=<local rehearsal only|internal RC only|public-mainnet candidate review>
assigned_worktree=<ticket path>
assigned_branch_ref=<ticket ref>
signer_exclusivity_note=<one line>
preflight_path=<resolved path>
summary_path=<resolved path>
manifest_path=<resolved path>
preflight_result=<GO|NO-GO>
preflight_generated_at=<artifact value>
preflight_git_toplevel=<artifact value>
preflight_git_branch=<artifact value>
preflight_git_head=<artifact value>
preflight_git_head_state=<artifact value>
preflight_git_status_summary=<artifact value>
preflight_git_worktree_path=<artifact value>
preflight_git_worktree_branch_ref=<artifact value>
preflight_expected_worktree_root=<artifact value>
preflight_expected_branch_ref=<artifact value>
preflight_expected_head=<artifact value or <unset>>
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
rollback_command=<artifact value>
replay_command=<artifact value>
blocker_type=<none|code|env|policy|evidence|operator>
blocker_summary=<one line>
next_blocker=<one line>
```
