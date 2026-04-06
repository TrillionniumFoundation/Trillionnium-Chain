#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

OUT_DIR="run/challenges"
OUT="$OUT_DIR/rpc-pending-to-fail-probe-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

TXS_FILE="run/rpc/txs.json"
if [[ ! -f "$TXS_FILE" ]]; then
  echo "[FAIL] missing $TXS_FILE; run challenge #1 first" >&2
  exit 1
fi

# 抽样最多 10 条“最近写入”的 pending hash，避免历史脏数据误报
RECENT_WINDOW_MS="${RECENT_WINDOW_MS:-900000}" # 15 分钟
mapfile -t hashes < <(python3 - <<'PY'
import json, time, os
p='run/rpc/txs.json'
try:
    with open(p,'r',encoding='utf-8') as f:
        d=json.load(f)
except Exception:
    d={}
if not isinstance(d,dict):
    d={}
try:
    window_ms=int(os.environ.get('RECENT_WINDOW_MS','900000'))
except Exception:
    window_ms=900000
now_ms=int(time.time()*1000)
out=[]
for h,v in d.items():
    if not isinstance(v,dict):
        continue
    if v.get('status')!='pending':
        continue
    ts=v.get('submitted_at_unix_ms') or 0
    try:
        ts=int(ts)
    except Exception:
        ts=0
    if ts > 0 and (now_ms - ts) <= window_ms:
        out.append((ts,h))
out.sort(reverse=True)
for _,h in out[:10]:
    print(h)
PY
)

if [[ "${#hashes[@]}" -eq 0 ]]; then
  {
    echo "challenge=rpc_pending_to_fail_probe"
    echo "sampled=0"
    echo "fail_after_probe=0"
    echo "still_pending=0"
    echo "other=0"
    echo "result=NOT_CONFIRMED"
    echo "note=no recent pending tx found within RECENT_WINDOW_MS=${RECENT_WINDOW_MS}"
  } | tee "$OUT"
  echo "[OK] report: $OUT"
  exit 0
fi

fail_count=0
pending_count=0
other_count=0

for h in "${hashes[@]}"; do
  out=$(cargo run -q -p trnm-rpc -- get-tx --tx-hash "$h" 2>&1 || true)
  status=$(python3 -c 'import json,sys
s=sys.stdin.read()
status=""
for line in reversed([ln.strip() for ln in s.splitlines() if ln.strip()]):
    if not (line.startswith("{") and line.endswith("}")):
        continue
    try:
        j=json.loads(line)
    except Exception:
        continue
    if isinstance(j,dict):
        status=str(j.get("status", "") or "")
        break
print(status)' <<< "$out")
  case "$status" in
    fail) fail_count=$((fail_count+1)) ;;
    pending) pending_count=$((pending_count+1)) ;;
    *) other_count=$((other_count+1)) ;;
  esac
done

{
  echo "challenge=rpc_pending_to_fail_probe"
  echo "sampled=${#hashes[@]}"
  echo "fail_after_probe=$fail_count"
  echo "still_pending=$pending_count"
  echo "other=$other_count"
  if [[ "$fail_count" -gt 0 ]]; then
    echo "result=DEFERRED_VALIDATION_CONFIRMED"
  else
    echo "result=NOT_CONFIRMED"
  fi
} | tee "$OUT"

echo "[OK] report: $OUT"
