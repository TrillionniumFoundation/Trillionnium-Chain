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

Capture the fail-closed helper output verbatim before any release/evidence script runs:

```bash
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch"
```

Record:
- verified_worktree=
- verified_branch_ref=
- verified_head=
- `git status --short` result:

Rule:
- if the helper fails, if `git status --short` is non-empty, or if the recorded values were inferred from the shell instead of the assigned ticket values, decision = **NO-GO**

## 3. Artifact path resolution

Resolve the exact evidence files from disk before quoting any PASS / GO language:

```bash
./scripts/v2/extract_release_handoff_fields.sh \
  --expected-worktree-root "/abs/path/from-ticket" \
  --expected-branch-ref "refs/heads/lane/assigned-branch"
```

Record:
- summary_path=
- manifest_path=
- summary_generated_at=
- manifest_generated_at=

Rule:
- if either artifact path is missing or unresolved, decision = **NO-GO**

## 4. Required cross-artifact identity fields

Copy these fields from the extracted artifact output or directly from `summary.txt` / `manifest.txt`:

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
- `git_worktree_branch_ref_match=true` is mandatory
- `git_status_summary=clean` is mandatory
- the summary and manifest values must match each other and match the assigned worktree/branch
- any mismatch = **NO-GO**

## 5. Gate summary

Record exact commands and outcomes:

- preflight command:
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
- [ ] `verify_lane_worktree.sh` passed using ticket-assigned values
- [ ] `git status --short` empty before evidence generation
- [ ] `summary_path` resolved from disk
- [ ] `manifest_path` resolved from disk
- [ ] summary/manifest identity fields match each other
- [ ] summary/manifest identity fields match assigned worktree/branch
- [ ] `git_worktree_branch_ref_match=true`
- [ ] `git_status_summary=clean`
- [ ] `generated_at=` preserved next to decision language
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
summary_path=<resolved path>
manifest_path=<resolved path>
git_branch=<artifact value>
git_head=<artifact value>
git_worktree_path=<artifact value>
git_worktree_branch_ref=<artifact value>
git_expected_worktree_branch_ref=<artifact value>
git_worktree_branch_ref_match=<true|false|unknown>
git_status_summary=<clean|dirty|unknown>
generated_at=<artifact value>
truth_source=<artifact value>
historical_evidence_only=<artifact value>
evidence_scope=<artifact value>
rollback_command=<artifact value>
replay_command=<artifact value>
blocker_type=<none|code|env|policy|evidence|operator>
blocker_summary=<one line>
next_blocker=<one line>
```
