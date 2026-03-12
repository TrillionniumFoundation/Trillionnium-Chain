#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-invalid-min-level.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.sh"
POLICY_JSON="$TMP/policy.json"
RUN_DIR="$TMP/run"

cat >"$MOCK_PR6" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=PASS
alert_code=NONE
alert_message=ok
generated_at_utc=2026-03-12T00:00:00Z
EOR
exit 0
EOF
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[FAIL] PR7 delivery should not run when min level is invalid" >&2
exit 99
EOF
chmod +x "$MOCK_PR7"

cat >"$POLICY_JSON" <<'EOF'
{
  "policy_id": "test-alert-policy",
  "version": "1",
  "profiles": {
    "default": {
      "thresholds": {
        "unresolved_challenges": { "warn": 4, "fail": 6 },
        "forfeits_daily_increase": { "warn": 80, "fail": 120 },
        "escrow_nonzero_hours": { "warn": 18.0, "fail": 24.0 }
      },
      "delivery": {
        "min_level": "NOISE",
        "channel_route": {
          "info": "imessage",
          "warn": "imessage",
          "critical": "telegram"
        },
        "dedup_seconds": 1800,
        "aggregate_seconds": 1800,
        "retries": {
          "max_retries": 3,
          "base_backoff_ms": 500,
          "max_backoff_ms": 8000
        },
        "cooldown": {
          "info": 1800,
          "warn": 1800,
          "critical": 300
        },
        "quiet_hours": {
          "enabled": true,
          "start": "23:00",
          "end": "08:00",
          "tz": "Asia/Shanghai",
          "critical_bypass": true
        },
        "escalation": {
          "warn_escalate_count": 3,
          "warn_escalate_window_seconds": 3600
        }
      }
    }
  }
}
EOF

set +e
RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="$MOCK_PR7" \
ALERT_POLICY_FILE="$POLICY_JSON" \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out.log" 2>&1
rc=$?
set -e

if [[ $rc -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for invalid ALERT_NOTIFY_MIN_LEVEL, got rc=$rc"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "invalid ALERT_NOTIFY_MIN_LEVEL='NOISE'" "$TMP/out.log"; then
  echo "[FAIL] expected invalid min-level message"
  cat "$TMP/out.log"
  exit 1
fi

echo "[OK] pr7 gate rejects invalid ALERT_NOTIFY_MIN_LEVEL from resolved policy before delivery runs"
