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
    "trillionnium/run/event-field-check.log" \
    "trillionnium/run/parallel-sanity.log" \
    "trillionnium/run/node1.log" \
    "trillionnium/run/node2.log" \
    "trillionnium/run/node3.log"; do
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
hint=provide SOURCE_LOG=trillionnium/run/event-field-check.log
EOF
  echo "[PR5][reconcile] no event log found; wrote $OUT_DIR/summary.txt"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  cat >"$OUT_DIR/summary.txt" <<EOF
status=SKIP
reason=python3_missing
hint=install_python3_or_run_on_python3_enabled_host
EOF
  echo "[PR5][reconcile] python3 not found; wrote $OUT_DIR/summary.txt"
  exit 0
fi

python3 - "$SOURCE_LOG" "$OUT_DIR" <<'PY'
import json
import pathlib
import sys
from collections import defaultdict, deque
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


def parse_num(v):
    if v in (None, "-"):
        return None
    try:
        return int(v)
    except ValueError:
        return None


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

agg = defaultdict(
    lambda: {
        "challenge_events": 0,
        "resolve_events": 0,
        "posted_count": 0,
        "forfeited_count": 0,
        "refunded_count": 0,
        "treasury_delta_sum": 0,
        "challenger_delta_sum": 0,
    }
)

queues = defaultdict(deque)
posted_total = 0
refunded_total = 0
forfeited_total = 0
carry_in_resolve = 0
forfeited_without_post = 0
conservation_details = []

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

    task_id = r.get("task_id") or ""
    disp = r.get("bond_disposition")
    ch_delta = r.get("challenger_delta")
    treasury_delta = r.get("treasury_delta")

    if isinstance(treasury_delta, int) and treasury_delta != 0:
        conservation_details.append(
            f"nonzero treasury_delta task={task_id} event_type={r.get('event_type')} tx={r.get('tx_hash')} got={treasury_delta} want=0"
        )

    if r["event_type"] == "challenge":
        if disp == "posted" and isinstance(ch_delta, int) and ch_delta < 0:
            bond = -ch_delta
            posted_total += bond
            queues[task_id].append({"bond": bond, "tx_hash": r.get("tx_hash")})
        elif disp == "posted":
            conservation_details.append(
                f"challenge posted missing/invalid challenger_delta task={task_id} tx={r.get('tx_hash')} got={ch_delta}"
            )
        continue

    if r["event_type"] == "resolve" and disp in {"forfeited", "refunded"}:
        if not queues[task_id]:
            carry_in_resolve += 1
            conservation_details.append(
                f"resolve without posted challenge in log task={task_id} tx={r.get('tx_hash')} disposition={disp}"
            )
            continue

        posted = queues[task_id].popleft()
        bond = int(posted["bond"])
        if disp == "forfeited":
            forfeited_total += bond
            if isinstance(ch_delta, int) and ch_delta != 0:
                conservation_details.append(
                    f"forfeited resolve expects challenger_delta=0 task={task_id} tx={r.get('tx_hash')} got={ch_delta}"
                )
        else:
            if not isinstance(ch_delta, int) or ch_delta <= 0:
                conservation_details.append(
                    f"refunded resolve expects challenger_delta>0 task={task_id} tx={r.get('tx_hash')} got={ch_delta}"
                )
                continue
            refunded_total += ch_delta
            if ch_delta != bond:
                conservation_details.append(
                    f"refund mismatch task={task_id} posted_bond={bond} refunded={ch_delta} challenge_tx={posted.get('tx_hash')} resolve_tx={r.get('tx_hash')}"
                )

open_bond_total = 0
for q in queues.values():
    for item in q:
        open_bond_total += int(item["bond"])

conservation_gap = posted_total - refunded_total - forfeited_total - open_bond_total
status = "PASS"
if conservation_gap != 0 or conservation_details:
    status = "FAIL"

report = {
    "status": status,
    "source_log": str(source),
    "record_count": len(records),
    "conservation": {
        "posted_total": posted_total,
        "refunded_total": refunded_total,
        "forfeited_total": forfeited_total,
        "open_bond_total": open_bond_total,
        "carry_in_resolve": carry_in_resolve,
        "gap": conservation_gap,
        "details": conservation_details,
    },
    "days": [{"day_utc": day, **vals} for day, vals in sorted(agg.items())],
}

(out_dir / "reconcile.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
    f.write(f"status={status}\n")
    f.write(f"source_log={source}\n")
    f.write(f"record_count={len(records)}\n")
    f.write(f"conservation.posted_total={posted_total}\n")
    f.write(f"conservation.refunded_total={refunded_total}\n")
    f.write(f"conservation.forfeited_total={forfeited_total}\n")
    f.write(f"conservation.open_bond_total={open_bond_total}\n")
    f.write(f"conservation.carry_in_resolve={carry_in_resolve}\n")
    f.write(f"conservation.gap={conservation_gap}\n")
    f.write(f"conservation.detail_count={len(conservation_details)}\n")
    for day, vals in sorted(agg.items()):
        f.write(
            "day={day} challenge_events={challenge_events} resolve_events={resolve_events} "
            "posted={posted_count} forfeited={forfeited_count} refunded={refunded_count} "
            "treasury_delta_sum={treasury_delta_sum} challenger_delta_sum={challenger_delta_sum}\n".format(
                day=day,
                **vals,
            )
        )
    for idx, detail in enumerate(conservation_details[:50], start=1):
        f.write(f"conservation.detail.{idx}={detail}\n")
PY

echo "[PR5][reconcile] source_log=$SOURCE_LOG"
echo "[PR5][reconcile] summary=$OUT_DIR/summary.txt"
echo "[PR5][reconcile] json=$OUT_DIR/reconcile.json"

status=$(awk -F= '/^status=/{print $2; exit}' "$OUT_DIR/summary.txt" 2>/dev/null || true)
if [[ "$status" == "FAIL" ]]; then
  echo "[PR5][reconcile][FAIL] status=FAIL; blocking with non-zero exit" >&2
  if [[ -f "$OUT_DIR/summary.txt" ]]; then
    sed 's/^/[PR5][reconcile][summary] /' "$OUT_DIR/summary.txt" >&2
  fi
  if [[ "${PR5_RECONCILE_SOFT_FAIL:-0}" == "1" ]]; then
    echo "[PR5][reconcile][WARN] PR5_RECONCILE_SOFT_FAIL=1 set; return 0 for compatibility" >&2
    exit 0
  fi
  exit 1
fi
