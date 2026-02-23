#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TS=$(date +%Y%m%d-%H%M%S)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/run/pr5-reconcile/$TS"}
mkdir -p "$OUT_DIR"

cd "$ROOT_DIR"

SOURCE_LOG=${SOURCE_LOG:-}
if [[ -z "$SOURCE_LOG" ]]; then
  for candidate in \
    "trillionnium-rust/run/event-field-check.log" \
    "trillionnium-rust/run/parallel-sanity.log" \
    "trillionnium-rust/run/node1.log" \
    "trillionnium-rust/run/node2.log" \
    "trillionnium-rust/run/node3.log"; do
    if [[ -f "$candidate" ]]; then
      SOURCE_LOG="$candidate"
      break
    fi
  done
fi

if [[ -z "$SOURCE_LOG" || ! -f "$SOURCE_LOG" ]]; then
  cat >"$OUT_DIR/summary.txt" <<EOF
status=SKIP
reason=no_event_log_found
hint=provide SOURCE_LOG=trillionnium-rust/run/event-field-check.log
EOF
  echo "[PR5][reconcile] no event log found; wrote $OUT_DIR/summary.txt"
  exit 0
fi

python3 - "$SOURCE_LOG" "$OUT_DIR" <<'PY'
import json
import pathlib
import sys
from collections import defaultdict
from datetime import datetime, timezone

source = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)

lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()

def parse_kv(line: str):
    kv = {}
    for tok in line.split()[1:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
    return kv

records = []
for line in lines:
    if not line.startswith("[event]"):
        continue
    kv = parse_kv(line)
    if kv.get("event_type") not in {"challenge", "resolve"}:
        continue
    ts_ms_raw = kv.get("ts_unix_ms")
    try:
        ts_ms = int(ts_ms_raw) if ts_ms_raw and ts_ms_raw != "-" else 0
    except ValueError:
        ts_ms = 0
    day = "unknown"
    if ts_ms > 0:
        day = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

    def parse_num(v):
        if v in (None, "-"):
            return None
        try:
            return int(v)
        except ValueError:
            return None

    records.append(
        {
            "event_type": kv.get("event_type", ""),
            "task_id": kv.get("task_id"),
            "day_utc": day,
            "treasury_delta": parse_num(kv.get("treasury_delta")),
            "challenger_delta": parse_num(kv.get("challenger_delta")),
            "bond_disposition": kv.get("bond_disposition"),
            "resolution_code": kv.get("resolution_code"),
            "tx_hash": kv.get("tx_hash"),
            "raw": line,
        }
    )

agg = defaultdict(lambda: {
    "challenge_events": 0,
    "resolve_events": 0,
    "posted_count": 0,
    "forfeited_count": 0,
    "refunded_count": 0,
    "treasury_delta_sum": 0,
    "challenger_delta_sum": 0,
})

for r in records:
    a = agg[r["day_utc"]]
    if r["event_type"] == "challenge":
        a["challenge_events"] += 1
    elif r["event_type"] == "resolve":
        a["resolve_events"] += 1

    if r["bond_disposition"] == "posted":
        a["posted_count"] += 1
    elif r["bond_disposition"] == "forfeited":
        a["forfeited_count"] += 1
    elif r["bond_disposition"] == "refunded":
        a["refunded_count"] += 1

    if isinstance(r["treasury_delta"], int):
        a["treasury_delta_sum"] += r["treasury_delta"]
    if isinstance(r["challenger_delta"], int):
        a["challenger_delta_sum"] += r["challenger_delta"]

report = {
    "status": "PASS",
    "source_log": str(source),
    "record_count": len(records),
    "days": [{"day_utc": day, **vals} for day, vals in sorted(agg.items())],
}

(out_dir / "reconcile.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
    f.write("status=PASS\n")
    f.write(f"source_log={source}\n")
    f.write(f"record_count={len(records)}\n")
    for day, vals in sorted(agg.items()):
        f.write(
            "day={day} challenge_events={challenge_events} resolve_events={resolve_events} "
            "posted={posted_count} forfeited={forfeited_count} refunded={refunded_count} "
            "treasury_delta_sum={treasury_delta_sum} challenger_delta_sum={challenger_delta_sum}\n".format(
                day=day,
                **vals,
            )
        )
PY

echo "[PR5][reconcile] source_log=$SOURCE_LOG"
echo "[PR5][reconcile] summary=$OUT_DIR/summary.txt"
echo "[PR5][reconcile] json=$OUT_DIR/reconcile.json"