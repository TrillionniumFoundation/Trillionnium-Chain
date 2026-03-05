#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/phasea-soak-gate-$TS.txt"
mkdir -p "$OUT_DIR"

# Inputs (can be overridden)
SOAK_RESULT="${SOAK_RESULT:-}"
FAULT_RESULT="${FAULT_RESULT:-}"

# SLO thresholds
MIN_COMMIT_QUEUED_PCT="${MIN_COMMIT_QUEUED_PCT:-99}"
MAX_PROOF_VERIFY_FAIL="${MAX_PROOF_VERIFY_FAIL:-0}"
MAX_STORE_REJECTED="${MAX_STORE_REJECTED:-0}"
MAX_RETRY_EXHAUSTED="${MAX_RETRY_EXHAUSTED:-0}"

pick_latest() {
  local pattern="$1"
  python3 - "$pattern" <<'PY'
import glob
import os
import sys

pattern = sys.argv[1]
matches = [p for p in glob.glob(pattern) if os.path.isfile(p)]
if not matches:
    sys.exit(0)

# Deterministic tie-breaker for equal mtimes: lexical path order.
matches.sort(key=lambda p: (-os.path.getmtime(p), p))
print(matches[0])
PY
}

if [[ -z "$SOAK_RESULT" ]]; then
  SOAK_RESULT="$(pick_latest "$ROOT/run/health/reliability-soak-*.json")"
fi
if [[ -z "$SOAK_RESULT" ]]; then
  SOAK_RESULT="$(pick_latest "$ROOT/../run/health/reliability-soak-*.json")"
fi
if [[ -z "$SOAK_RESULT" ]]; then
  SOAK_RESULT="$(pick_latest "$ROOT/run/health/reliability-soak-*.txt")"
fi
if [[ -z "$SOAK_RESULT" ]]; then
  SOAK_RESULT="$(pick_latest "$ROOT/../run/health/reliability-soak-*.txt")"
fi
if [[ -z "$FAULT_RESULT" ]]; then
  FAULT_RESULT="$(pick_latest "$ROOT/run/health/phasea-fault-suite-*/summary.txt")"
fi
if [[ -z "$FAULT_RESULT" ]]; then
  FAULT_RESULT="$(pick_latest "$ROOT/../run/health/phasea-fault-suite-*/summary.txt")"
fi
if [[ -z "$FAULT_RESULT" ]]; then
  FAULT_RESULT="$(pick_latest "$ROOT/run/health/*phasea*fault*summary*.txt")"
fi

if [[ -z "$SOAK_RESULT" || ! -f "$SOAK_RESULT" ]]; then
  echo "[FAIL] soak result file not found. set SOAK_RESULT=/path/to/report" | tee "$OUT"
  exit 10
fi
if [[ -z "$FAULT_RESULT" || ! -f "$FAULT_RESULT" ]]; then
  echo "[FAIL] fault result file not found. set FAULT_RESULT=/path/to/report" | tee "$OUT"
  exit 11
fi

export SOAK_RESULT FAULT_RESULT
METRICS="$(python3 - <<'PY'
import json
import os
import re
from pathlib import Path

soak_path = Path(os.environ["SOAK_RESULT"])
fault_path = Path(os.environ["FAULT_RESULT"])


def load_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def flatten_json(obj, out, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = re.sub(r"[^a-z0-9]+", "_", str(k).strip().lower()).strip("_")
            key = f"{prefix}_{nk}" if prefix else nk
            flatten_json(v, out, key)
    elif isinstance(obj, list):
        for x in obj:
            flatten_json(x, out, prefix)
    else:
        key = prefix or "value"
        out.setdefault(key, []).append(obj)


def parse_json_candidates(text: str):
    t = text.strip()
    if not t:
        return {}
    try:
        obj = json.loads(t)
    except Exception:
        return {}
    d = {}
    flatten_json(obj, d)
    return d


def parse_kv(text: str):
    kv = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.\- ]+)\s*=\s*([^\n]+?)\s*$", line)
        if not m:
            continue
        k = re.sub(r"[^a-z0-9]+", "_", m.group(1).strip().lower()).strip("_")
        kv.setdefault(k, []).append(m.group(2).strip())
    return kv


def merge_maps(*maps):
    r = {}
    for m in maps:
        for k, vals in m.items():
            r.setdefault(k, []).extend(vals if isinstance(vals, list) else [vals])
    return r


def to_num(v):
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if s.endswith("%"):
        s = s[:-1].strip()
    m = re.search(r"-?\d+(?:\.\d+)?", s)
    if not m:
        return None
    try:
        return float(m.group(0))
    except Exception:
        return None


def pick_num(m, keys):
    for k in keys:
        if k not in m:
            continue
        for v in reversed(m[k]):
            n = to_num(v)
            if n is not None:
                return n
    return None


def count_token(text: str, token: str):
    return len(re.findall(re.escape(token), text, flags=re.IGNORECASE))

soak_text = load_text(soak_path)
fault_text = load_text(fault_path)
soak_map = merge_maps(parse_json_candidates(soak_text), parse_kv(soak_text))
fault_map = merge_maps(parse_json_candidates(fault_text), parse_kv(fault_text))
all_map = merge_maps(soak_map, fault_map)

commit_pct = pick_num(all_map, [
    "commit_queued_pct", "commit_queued_percent", "slo_commit_queued_pct", "commit_queued_rate_pct"
])
if commit_pct is None:
    queued = pick_num(all_map, ["commit_queued", "status_commit_queued", "commit_queued_count", "status_histogram_reveal_submitted"])
    total = pick_num(all_map, ["total", "total_requests", "request_total", "soak_total", "metrics_terminal_total"])
    if queued is not None and total and total > 0:
        commit_pct = queued * 100.0 / total
if commit_pct is None:
    terminal_success = pick_num(all_map, ["terminal_success_rate", "metrics_terminal_success_rate", "success_rate", "commit_queued_rate"])
    if terminal_success is not None:
        # rates in [0,1] are treated as ratio, otherwise already percent
        commit_pct = terminal_success * 100.0 if terminal_success <= 1.0 else terminal_success

proof_verify_fail = pick_num(all_map, [
    "proof_verify_fail", "proof_verify_failed", "proof_verification_fail", "proof_verify_fail_count"
])
if proof_verify_fail is None:
    proof_verify_fail = 0.0

store_rejected = pick_num(all_map, ["store_rejected", "store_rejected_count"])
retry_exhausted = pick_num(all_map, ["retry_exhausted", "retry_exhausted_count"])

# Fallback: count literal tokens in raw text when explicit counters are absent.
if store_rejected is None:
    store_rejected = float(count_token(soak_text + "\n" + fault_text, "store_rejected"))
if retry_exhausted is None:
    retry_exhausted = float(count_token(soak_text + "\n" + fault_text, "retry_exhausted"))

print(f"commit_queued_pct={'' if commit_pct is None else f'{commit_pct:.6f}'}")
print(f"proof_verify_fail={'' if proof_verify_fail is None else int(proof_verify_fail)}")
print(f"store_rejected={int(store_rejected)}")
print(f"retry_exhausted={int(retry_exhausted)}")
PY
)"

# shellcheck disable=SC2046
export $(echo "$METRICS" | xargs)

{
  echo "phasea_soak_gate.ts=$TS"
  echo "phasea_soak_gate.soak_result=$SOAK_RESULT"
  echo "phasea_soak_gate.fault_result=$FAULT_RESULT"
  echo "phasea_soak_gate.threshold.min_commit_queued_pct=$MIN_COMMIT_QUEUED_PCT"
  echo "phasea_soak_gate.threshold.max_proof_verify_fail=$MAX_PROOF_VERIFY_FAIL"
  echo "phasea_soak_gate.threshold.max_store_rejected=$MAX_STORE_REJECTED"
  echo "phasea_soak_gate.threshold.max_retry_exhausted=$MAX_RETRY_EXHAUSTED"
  echo "phasea_soak_gate.metric.commit_queued_pct=${commit_queued_pct:-}"
  echo "phasea_soak_gate.metric.proof_verify_fail=${proof_verify_fail:-}"
  echo "phasea_soak_gate.metric.store_rejected=${store_rejected:-0}"
  echo "phasea_soak_gate.metric.retry_exhausted=${retry_exhausted:-0}"
} | tee "$OUT"

if [[ -z "${commit_queued_pct:-}" ]]; then
  echo "[FAIL] missing metric: commit_queued_pct" | tee -a "$OUT"
  exit 20
fi
if [[ -z "${proof_verify_fail:-}" ]]; then
  echo "[FAIL] missing metric: proof_verify_fail" | tee -a "$OUT"
  exit 21
fi

python3 - <<'PY' "$commit_queued_pct" "$MIN_COMMIT_QUEUED_PCT" "$proof_verify_fail" "$MAX_PROOF_VERIFY_FAIL" "$store_rejected" "$MAX_STORE_REJECTED" "$retry_exhausted" "$MAX_RETRY_EXHAUSTED" "$OUT"
import sys

commit_pct = float(sys.argv[1])
min_commit = float(sys.argv[2])
proof_fail = int(float(sys.argv[3]))
max_proof = int(float(sys.argv[4]))
store_rejected = int(float(sys.argv[5]))
max_store = int(float(sys.argv[6]))
retry_exhausted = int(float(sys.argv[7]))
max_retry = int(float(sys.argv[8]))
out = sys.argv[9]

fails = []
if commit_pct < min_commit:
    fails.append(f"commit_queued_pct {commit_pct:.3f} < {min_commit:.3f}")
if proof_fail > max_proof:
    fails.append(f"proof_verify_fail {proof_fail} > {max_proof}")
if store_rejected > max_store:
    fails.append(f"store_rejected {store_rejected} > {max_store}")
if retry_exhausted > max_retry:
    fails.append(f"retry_exhausted {retry_exhausted} > {max_retry}")

with open(out, "a", encoding="utf-8") as f:
    if fails:
        f.write("phasea_soak_gate.result=FAIL\n")
        for item in fails:
            f.write(f"phasea_soak_gate.fail={item}\n")
    else:
        f.write("phasea_soak_gate.result=PASS\n")

if fails:
    for item in fails:
        print(f"[FAIL] {item}")
    sys.exit(1)

print("[OK] phaseA soak SLO gate passed")
PY

echo "[OK] phaseA soak gate report: $OUT"