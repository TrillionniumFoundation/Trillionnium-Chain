#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/pr7-replay-idempotency-test.XXXXXX")}" 
mkdir -p "$OUT_DIR"
cleanup() {
  if [[ -z "${OUT_DIR:-}" ]]; then
    return
  fi
  case "$OUT_DIR" in
    /tmp/pr7-replay-idempotency-test.*|"${TMPDIR:-/tmp}"/pr7-replay-idempotency-test.*)
      rm -rf "$OUT_DIR"
      ;;
  esac
}
trap cleanup EXIT
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

echo "[OK] pr7 dead-letter replay idempotency/lock test passed"
