# TRNM Mainnet Blocker Board — 2026-03-31

Scope: public-mainnet blocker tracking for the validator/operator lifecycle lane (`MN05`).
This board is intentionally narrow: it only tracks validator replacement, rotation, rollback, disaster recovery, and node rebuild operator discipline.

Primary truth sources:
- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `docs/runbooks/validator-rotation-dr.md`
- `scripts/v2/verify_lane_worktree.sh`
- `scripts/v2/extract_release_handoff_fields.sh`
- `scripts/v2/extract_validator_rotation_dr_fields.sh`

## Board summary

| Blocker ID | Area | Current state | Blocking because | Exit evidence |
| --- | --- | --- | --- | --- |
| MN05-P0-01 | Validator replacement / rotation workflow | **Partial** — runbooks exist, but closure is still documentation-heavy | A public mainnet cannot rely on operator memory or unsigned ownership transfer | One signed replacement/rotation rehearsal packet with path-resolved evidence, explicit rollback, and verifier-bound worktree/branch fields |
| MN05-P0-02 | DR rebuild evidence | **Partial** — DR report extraction helper exists, but no captured live rebuild rehearsal is referenced here | DR is still not proven reproducible from concrete artifacts produced by the assigned worktree | One `dr_rebuild` rehearsal carrying `dr_summary_path=`, `dr_generated_at=`, `dr_status=PASS`, verbatim replay/rollback commands, and lane-binding fields from the same report |
| MN05-P0-03 | Validator bootstrap / re-bootstrap operator discipline | **Partial** — bootstrap/re-bootstrap SOP exists | Operators still need concrete evidence that the named validator bundle was validated from a clean lane before cutover | One handoff packet with exact `config_bundle_check_command=`, `config_bundle_check_result=`, optional `config_bundle_check_log_path=`, plus bootstrap command and rollback command |
| MN05-P0-04 | Signed handoff boundary | **Open** for cross-operator events | Cross-operator cutovers are not auditable unless the signer and acknowledger are attached to the same artifact set | One compact ceremony packet with `handoff_signed_by=` and `handoff_acknowledged_by=` on the same note as verified worktree/branch/head and any referenced handoff / DR artifacts |
| MN05-P0-05 | Automation gap | **Open** | The gap matrix still records no validator replacement / rotation automation and no DR rebuild drill with captured evidence | At least one deterministic operator-facing rehearsal script or command sequence that produces the packet fields without shell-memory reconstruction |

## What is already closed enough to build on

- `docs/runbooks/validator-bootstrap-rebootstrap.md` defines fail-closed bootstrap / re-bootstrap steps bound to exact worktree and branch identity.
- `docs/runbooks/validator-rotation-dr.md` defines the minimum evidence bar for `replacement`, `rotation`, and `dr_rebuild`.
- `scripts/v2/extract_validator_rotation_dr_fields.sh` can fail closed on missing report fields, non-`PASS` recovery reports, and lane/worktree identity drift.
- `RELEASE_READINESS.md` now explicitly instructs operators to prefer fail-closed helper extraction over hand-copied shell snippets.

## Still-open blocker details

### MN05-P0-01 — Replacement / rotation remains documentation-first

Current truth from the gap matrix:
- bootstrap / replacement / rotation / DR procedures are documented
- a real signed rehearsal packet produced from live operator artifacts is still missing

Why this blocks public mainnet:
- operator lifecycle is part of launchability, not an optional appendix
- unsigned or memory-based handoff means ownership is ambiguous under stress

Minimum next evidence:
- a concrete `replacement` or `rotation` rehearsal that records:
  - `verified_worktree=` / `verified_branch_ref=` / `verified_head=`
  - outgoing and incoming validator identity/config
  - `rollback_command=` quoted verbatim
  - signed handoff boundary when ownership crosses operators

### MN05-P0-02 — DR rebuild needs a concrete packet, not only a runbook

Current truth from the gap matrix:
- no disaster-recovery rebuild drill with captured evidence

Why this blocks public mainnet:
- recovery that cannot be replayed from concrete artifacts is not operationally credible

Minimum next evidence:
- one `dr_rebuild` packet containing:
  - `dr_summary_path=` referencing the exact report created by the current run
  - `dr_generated_at=` / `dr_status=PASS`
  - verbatim `dr_replay_command=` / `dr_rollback_command=`
  - `expected_worktree_root=` / `expected_branch_ref=` / `lane_verify_command=` when lane binding is part of the ticket

### MN05-P0-03 — Config bundle validation must travel with the handoff

Current truth from the runbooks:
- operators must validate the exact incoming config bundle from a clean worktree
- later auditors should not need shell scrollback to discover what was actually checked

Why this blocks public mainnet:
- a green-sounding note without the exact validation command is not auditable

Minimum next evidence:
- preserve the trio together:
  - `config_bundle_check_command=`
  - `config_bundle_check_result=`
  - `config_bundle_check_log_path=` when tee/log capture is needed

### MN05-P0-04 — Cross-operator ownership boundary is still open

Current truth from the runbooks:
- `rotation` and `dr_rebuild` require `handoff_signed_by=` and `handoff_acknowledged_by=`
- missing signer or acknowledger is a hard **No-Go**

Why this blocks public mainnet:
- without the sign-off boundary, a cutover can be technically reproducible but still operationally unauditable

Minimum next evidence:
- one signed packet where both names appear on the same artifact set as:
  - verified worktree / branch / head
  - explicit cutover kind
  - rollback command
  - any referenced handoff / DR artifact paths

### MN05-P0-05 — Automation gap is still explicit

Current truth from the gap matrix:
- no validator replacement / rotation automation
- no DR rebuild drill with captured evidence

Why this blocks public mainnet:
- a public validator lifecycle that only exists as prose is fragile and hard to rehearse consistently

Minimum next evidence:
- a deterministic rehearsal path that reduces operator memory load and emits reusable packet fields
- examples: helper-driven capture flow, signed note template backed by emitted paths, or a narrow rehearsal wrapper that does not hide the underlying commands

## Lane operating rule

For MN05 micro-iterations, prefer the smallest change that improves one of these:
1. fail-closed identity binding
2. signed handoff clarity
3. config-bundle auditability
4. DR evidence capture order
5. rollback / replay quote discipline

Do **not** claim mainnet closure from documentation alone.
Until a real rehearsal packet exists, treat this board as **blockers partially documented, not operationally discharged**.
