# P11 Plan — Policy Promotion & Notification SLO (2026-02-23)

## Goal
Move from “policy exists” to “policy safely promoted + measurable reliability”.

## Scope
1. Policy promotion workflow (staging -> prod with approval gate)
2. Notification SLO dashboard metrics
3. Automatic rollback trigger on abnormal failure spikes (dry-run first)

---

## Workstream A: Policy Promotion Workflow
### Deliverables
- `config/alert-policy/profiles/staging.json`
- `config/alert-policy/profiles/prod.json`
- `scripts/v2/p11_policy_promote.sh`
- `scripts/v2/p11_policy_promote_gate.sh`

### Requirements
- Promotion requires explicit `--from staging --to prod`
- Validate with `alert_policy_lint.py` before promote
- Write immutable audit entry in `run/pr11/policy-promotions.log`
- Support `--dry-run`

### Acceptance
- Promotion blocked when lint fails
- Promotion writes changelog + version snapshot

---

## Workstream B: Notification SLO
### Deliverables
- `scripts/v2/p11_notification_slo_report.py`
- Output: `run/pr11/notification-slo.md` + `run/pr11/notification-slo.json`

### Metrics
- sent_rate
- suppressed_rate
- failed_rate
- p95_delivery_attempts
- channel_split (imessage/slack/telegram)

### Acceptance
- Report reads PR7 state/history and computes 24h/7d windows
- Missing data degrades gracefully with explicit note

---

## Workstream C: Auto Rollback Trigger (Dry-run)
### Deliverables
- `scripts/v2/p11_policy_rollback_guard.py`
- `scripts/v2/p11_policy_rollback_guard.sh`

### Trigger Conditions (initial)
- failed_rate > 20% for 1h window
- consecutive delivery failures > 10
- critical alerts dropped (failed) > 0

### Behavior
- Dry-run only in P11: output would-rollback action
- Emit machine-readable status and reason

### Acceptance
- Produces PASS/WARN/FAIL with clear remediation text
- Integrates into nightly as non-gate step

---

## Suggested execution order
1. A (Promotion workflow)
2. B (SLO report)
3. C (Rollback guard dry-run)
4. Nightly wiring + docs update

## Success criteria
- Policy changes can be promoted with audit trail
- Alert reliability is measured daily/weekly
- Rollback decisions are computable and reviewable before automation
