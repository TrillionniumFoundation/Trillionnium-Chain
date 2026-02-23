# PR-7 Threshold Advisor (7-day)

- generated_at_utc: `2026-02-23T10:54:30.794582+00:00`
- window: `2026-02-17 .. 2026-02-23` (7d)
- pr5_days_found: `1`

## Suggested Thresholds

| rule | warn | fail | mode | reason |
|---|---:|---:|---|---|
| unresolved_challenges | 3.0 | 5.0 | conservative_default | insufficient_data: samples=1 < min_days=3 |
| forfeits_daily_increase | 70.0 | 100.0 | conservative_default | insufficient_data: samples=0 < min_days=2 |
| escrow_nonzero_hours | 16.0 | 24.0 | conservative_default | insufficient_data: samples=1 < min_days=3 |

## Rationale

- unresolved_challenges: derived from PR5 `carry_out_open` per day; when data insufficient, keep PR6 conservative baseline.
- forfeits_daily_increase: derived from day-over-day increase of PR5 `forfeited_total`; sparse history falls back to baseline.
- escrow_nonzero_hours: sourced from PR6 ops gate samples; if <min_days, keep conservative baseline.

## Data Pointers
- PR5 root: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr5-reconcile`
- PR6 ops root: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr6-ops`
- PR6 gate: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr6-ops/pr6-alert-rules-gate.txt`
- JSON: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr7-threshold-advisor/20260223-105430/threshold-advice.json`
