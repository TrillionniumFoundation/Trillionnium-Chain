#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_DIR="${RUN_DIR:-$ROOT/run}"
OUT_DIR="${OUT_DIR:-$ROOT/run/audit}"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/state-root-audit-$TS.txt"

mkdir -p "$OUT_DIR"

for n in 1 2 3; do
  f="$RUN_DIR/node${n}.log"
  if [[ ! -f "$f" ]]; then
    echo "[ERR] missing log: $f" >&2
    exit 1
  fi
done

python3 - <<'PY' "$RUN_DIR/node1.log" "$RUN_DIR/node2.log" "$RUN_DIR/node3.log" "$REPORT"
import re,sys
logs=sys.argv[1:4]
report_path=sys.argv[4]
pat=re.compile(r"\[block\].*height=(\d+).*state_root=([0-9a-fA-F]+)")

by_node=[]
for p in logs:
    m={}
    with open(p,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            mm=pat.search(line)
            if mm:
                h=int(mm.group(1)); r=mm.group(2).lower()
                m[h]=r
    by_node.append(m)

all_heights=sorted(set().union(*[set(d.keys()) for d in by_node]))
lines=[]
lines.append("state_root_audit")
lines.append(f"nodes={len(by_node)} heights={len(all_heights)}")

mismatch=0
missing=0
for h in all_heights:
    vals=[]
    for d in by_node:
        vals.append(d.get(h))
    uniq=sorted(set(v for v in vals if v is not None))
    if any(v is None for v in vals):
        missing+=1
        lines.append(f"H={h} status=MISSING roots={vals}")
    elif len(uniq)>1:
        mismatch+=1
        lines.append(f"H={h} status=MISMATCH roots={vals}")
    else:
        lines.append(f"H={h} status=OK root={uniq[0]}")

ok = (mismatch==0 and missing==0 and len(all_heights)>0)
lines.append(f"summary ok={str(ok).lower()} mismatch={mismatch} missing={missing}")

with open(report_path,'w',encoding='utf-8') as f:
    f.write("\n".join(lines)+"\n")

print(report_path)
print(f"ok={str(ok).lower()} mismatch={mismatch} missing={missing} heights={len(all_heights)}")
if not ok:
    sys.exit(2)
PY

echo "[OK] audit report: $REPORT"