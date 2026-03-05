#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-/tmp/pr7-replay-idempotency-test}"
mkdir -p "$OUT_DIR"
DLQ="$OUT_DIR/dead-letter.jsonl"
RECEIPT="$OUT_DIR/dead-letter.replayed.jsonl"
LOCK="$OUT_DIR/dead-letter.lock"

cat > "$DLQ" <<'EOF'
{"channel":"imessage","message":"hello-1","fingerprint":"fp-1"}
EOF
: > "$RECEIPT"
rm -f "$LOCK"

python3 scripts/v2/pr7_dead_letter_replay.py \
  --dead-letter-file "$DLQ" \
  --receipt-file "$RECEIPT" \
  --lock-file "$LOCK" \
  --dry-run \
  --max-retries 1

# second run should be dedup skip (no resend) and still success
python3 scripts/v2/pr7_dead_letter_replay.py \
  --dead-letter-file "$DLQ" \
  --receipt-file "$RECEIPT" \
  --lock-file "$LOCK" \
  --dry-run \
  --max-retries 1 > "$OUT_DIR/run2.log"

if ! grep -Eq "(dedup_skipped=|no dead-letter entries)" "$OUT_DIR/run2.log"; then
  echo "expected dedup/no-entry signal in run2" >&2
  cat "$OUT_DIR/run2.log" >&2
  exit 1
fi

# lock contention should return rc=4
( echo $$ > "$LOCK" )
set +e
python3 scripts/v2/pr7_dead_letter_replay.py \
  --dead-letter-file "$DLQ" \
  --receipt-file "$RECEIPT" \
  --lock-file "$LOCK" \
  --dry-run >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 4 ]]; then
  echo "expected rc=4 on lock contention, got rc=$rc" >&2
  exit 1
fi
rm -f "$LOCK"

# channel casing should not bypass message-hash based dedup when fingerprint is absent
DLQ2="$OUT_DIR/dead-letter-case.jsonl"
RECEIPT2="$OUT_DIR/dead-letter-case.replayed.jsonl"
LOCK2="$OUT_DIR/dead-letter-case.lock"
cat > "$DLQ2" <<'EOF'
{"channel":"telegram","message":"hello-case"}
{"channel":"Telegram","message":"hello-case"}
EOF
: > "$RECEIPT2"
rm -f "$LOCK2"

python3 scripts/v2/pr7_dead_letter_replay.py \
  --dead-letter-file "$DLQ2" \
  --receipt-file "$RECEIPT2" \
  --lock-file "$LOCK2" \
  --dry-run \
  --max-items 2 > "$OUT_DIR/case.log"

if ! grep -q "replayed=1 dedup_skipped=1 failed=0" "$OUT_DIR/case.log"; then
  echo "expected case-insensitive channel dedup summary" >&2
  cat "$OUT_DIR/case.log" >&2
  exit 1
fi

echo "[OK] pr7 dead-letter replay idempotency/lock test passed"
