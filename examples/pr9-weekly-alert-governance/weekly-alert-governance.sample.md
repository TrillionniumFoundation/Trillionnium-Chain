# PR9 Weekly Alert Governance Report

- generated_at_utc: `2026-02-23 11:48:12Z`
- lookback_days: `7`
- source.pr7_delivery_state: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr7-alert-delivery/state.json`
- source.pr7_dead_letter: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr7-alert-delivery/dead-letter.jsonl`
- source.pr7_topn_latest: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr7-topn/20260223-185854/topn-anomaly-summary.md`
- source.pr7_threshold_advice_latest: `/Users/qianqi/.openclaw/workspace/TrillionniumChain/run/pr7-threshold-advisor/20260223-105854/threshold-advice.json`

## 1) Alert Volume & Delivery Quality
- alerts.total: `4`
- alerts.sent: `1`
- alerts.suppressed: `2`
- alerts.failed: `1`
- suppression_rate: `50.00%`
- failure_rate: `25.00%`
- dead_letter_entries_last_7d: `2`

## 2) TopN Anomalies (latest PR7, top_n=5)
### Unresolved Tasks
1. ✅ no unresolved task found in current event window

### Forfeit Spikes
1. day_utc=`2026-02-23` | forfeit_bond=`10` | forfeit_events=`1`

### Escrow Lingering
1. ✅ no lingering escrow found in current event window

## 3) Threshold Suggestion Changes
- no env value changed vs run/pr9/alert-thresholds.previous.env

### advisor suggestions
- `unresolved_challenges`: warn=`3.0` fail=`5.0` mode=`conservative_default` reason=`insufficient_data: samples=1 < min_days=3`
- `forfeits_daily_increase`: warn=`70.0` fail=`100.0` mode=`conservative_default` reason=`insufficient_data: samples=0 < min_days=2`
- `escrow_nonzero_hours`: warn=`16.0` fail=`24.0` mode=`conservative_default` reason=`insufficient_data: samples=1 < min_days=3`

## 4) Nightly Integration (non-blocking)
- Recommended workflow step: run this script with `continue-on-error: true` after PR7/PR6 summary steps.
- Artifact path: `run/pr9/**` (upload with nightly artifacts).
- Optional Step Summary append: embed `run/pr9/weekly-alert-governance.md` for operator visibility.

## 5) Repro Commands
```bash
python3 scripts/v2/pr9_weekly_alert_governance.py \
  --lookback-days 7 \
  --top-n 5 \
  --out run/pr9/weekly-alert-governance.md
```
