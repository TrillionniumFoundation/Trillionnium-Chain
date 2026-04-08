# Tokenomics residual risk register (round4, post R1-R14 gate)

## Scope
Residual / second-order risks after current fixes and `scripts/v2/run_tokenomics_r1_r14_regression_gate.sh`.

## Ranked risks

| Rank | Risk | Severity | Likelihood | Impact |
|---|---|---|---|---|
| 1 | **Governance timelock pending update can get stuck** (cannot supersede/cancel before activation) | High | Medium | Key rotation and sensitive param ops can deadlock for 20 blocks + human error recovery delay |
| 2 | **Resolve authority rotation failure mode** (single authority, no emergency override, challenged tasks can timeout to forfeits) | High | Medium | Bond-loss / fairness incidents during key loss or signer outage |
| 3 | **Window drift across lifecycle** (`challenge_window_blocks` read at reveal and challenge separately) | Medium | Medium | Unpredictable resolve deadline after governance update between reveal/challenge |
| 4 | **Bond floor couples to current global `min_worker_stake` instead of per-task locked stake snapshot** | Medium | Medium | Challenge deterrence or under-bonding after governance changes; strategy instability |
| 5 | **Event identity inconsistency in node emitter** (`Challenge` actor/challenger hardcoded) | Medium | Medium | Forensic/accounting ambiguity under mixed challengers; replay/audit false positives |
| 6 | **R1-R14 gate blind spot: no mixed-sequence property checks** (gov schedule/apply interleaving + repeated timeout scan + replay permutations) | Medium | High | Realistic failures can pass targeted tests |

## Medium+ patch proposals (minimal)

### R1. Pending governance update stuck / non-replaceable
- **Touchpoints**:
  - `trillionnium/crates/trnm-state/src/lib.rs`
    - `StateStore::set_gov_param(...)`
- **Patch (minimal)**:
  - Allow same `key`+`key_id` pending update to be **re-scheduled/replaced** before activation (new value + refreshed `activate_at_height`).
  - Keep whitelist/schema/rate-limit checks.
  - Optional explicit `cancel_pending_gov_param(key)` helper for runbook ops.
- **Tests**:
  - add `governance_sensitive_pending_update_can_be_replaced_before_activation`
  - add `governance_sensitive_pending_update_cancel_then_reschedule`

### R2. Resolve authority rotation outage
- **Touchpoints**:
  - `trillionnium/crates/trnm-state/src/lib.rs` (new gov key: `resolve_authority_next` or `resolve_authority_emergency`)
  - `trillionnium/crates/trnm-pouw/src/lib.rs` (`resolve_authority_account`, `apply_resolve_at_height`)
- **Patch (minimal)**:
  - Support dual-authority during controlled transition window (`current` OR `next`).
  - Keep timelock on setting `next`; explicit finalize step swaps to single authority.
- **Tests**:
  - `resolve_accepts_dual_authority_during_rotation_window`
  - `resolve_rejects_stale_previous_authority_after_finalize`

### R3. Lifecycle window drift
- **Touchpoints**:
  - `trillionnium/crates/trnm-types/src/lib.rs` (`TaskObject` add `resolve_window_blocks_snapshot: Option<u64>` or equivalent)
  - `trillionnium/crates/trnm-pouw/src/lib.rs` (`apply_reveal_result_at_height`, `apply_challenge_at_height`)
- **Patch (minimal)**:
  - Snapshot resolve window at reveal; challenge uses snapshot instead of fresh gov read.
- **Tests**:
  - `challenge_uses_reveal_snapshotted_window_when_gov_changes_between_reveal_and_challenge`

### R4. Bond floor based on global param instead of per-task stake
- **Touchpoints**:
  - `trillionnium/crates/trnm-types/src/lib.rs` (`TaskObject` add `worker_stake_locked`)
  - `trillionnium/crates/trnm-pouw/src/lib.rs` (`apply_accept_task`, `required_challenge_bond`)
- **Patch (minimal)**:
  - Persist worker stake lock amount in task at accept.
  - Compute worker-stake floor from `task.worker_stake_locked` (not current global `min_worker_stake`).
- **Tests**:
  - `challenge_min_bond_worker_stake_floor_uses_task_snapshot_not_current_global_param`

### R5. Event identity inconsistency for challenge actor/challenger
- **Touchpoints**:
  - `trillionnium/crates/trnm-node/src/main.rs`
    - `actor_of`, `challenger_of`, `emit_event`
- **Patch (minimal)**:
  - Use tx payload challenger for challenge events (not hardcoded `"challenger"`).
- **Tests**:
  - `event_challenge_uses_payload_challenger_identity`

### R6. Regression gate blind spot (interleavings)
- **Touchpoints**:
  - `scripts/v2/run_tokenomics_r1_r14_regression_gate.sh`
  - `trillionnium/crates/trnm-pouw/src/lib.rs` (new tests)
  - `trillionnium/crates/trnm-state/src/lib.rs` (new tests)
- **Patch (minimal)**:
  - Add targeted R15/R16 tests into gate:
    - interleaving: reveal -> schedule gov update -> apply at boundary -> challenge/resolve
    - repeated timeout scans + replay-like duplicated tx/event patterns
- **Tests**:
  - `timeout_repeated_scan_is_idempotent_across_status_edges`
  - `gov_update_between_reveal_challenge_resolve_preserves_invariants`

## Parameter sensitivity (safe envelope)

Current enforced bounds (`trnm-state::validate_gov_param_value`) permit wide ranges; operationally safer envelope:

- `challenge_window_blocks`: **120–240** preferred (protocol allows 100–600)
  - <120 raises false-timeout risk under network/ops jitter
  - >300 slows capital recycling and dispute finality
- `challenge_min_bond_bounty_bps`: **500–3000** (5%–30%)
  - >5000 tends to suppress valid challenges on high-bounty tasks
- `challenge_min_bond_worker_stake_bps`: **2000–10000** (20%–100%)
  - 0 disables worker-stake coupling (easy grief/churn)
  - >10000 over-penalizes challengers
- `challenge_min_bond` absolute floor: target at least **max(10, expected tx fee × 20)** in production-equivalent units
- `min_worker_stake` should preserve **challenger upside**:
  - require `challenge_success_bounty + expected slash transfer >= expected verifier cost` (else selective non-participation)

## Gate blind spots summary

Current R1-R14 gate is strong on direct regressions, but under-covers:
1. Mixed actor strategy games (collusion, selective participation utility, repeated self-challenge attempts).
2. Timelock operational workflows (replace/cancel pending updates, rotation failover drills).
3. Cross-height interleavings where governance changes between lifecycle phases.
4. Property-style invariants over randomized event permutations (single-run examples only).

## Highest-ROI next patches

1. **Pending gov update replace/cancel support** (R1): smallest code delta, large ops-risk reduction.
2. **Reveal-time snapshot of resolve window + gate test** (R3/R6): prevents subtle fairness drift and improves determinism with minimal schema/code change.
