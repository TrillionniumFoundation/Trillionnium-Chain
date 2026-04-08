#!/usr/bin/env python3
import glob
import os
import re
from statistics import median
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BENCH_DIR = os.path.join(ROOT, "run", "bench")
OUT_DIR = os.path.join(ROOT, "run", "health")
os.makedirs(OUT_DIR, exist_ok=True)

CUR_STREAK = float(os.getenv("TRNM_AUTO_HOT_STREAK_RATIO", "0.22"))
CUR_MARGIN = float(os.getenv("TRNM_AUTO_REORDER_MIN_MARGIN", "0.04"))
CUR_HOT_SHARE = float(os.getenv("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.06"))

strategy_files = sorted(
    glob.glob(os.path.join(BENCH_DIR, "executor-strategy-exp-*.txt")),
    key=os.path.getmtime,
    reverse=True,
)[:7]
hotspot_files = sorted(
    glob.glob(os.path.join(BENCH_DIR, "executor-hotspot-exp-*.txt")),
    key=os.path.getmtime,
    reverse=True,
)[:7]


def parse_sections(path):
    sections = {}
    cur = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"^--- strategy=(.+) ---$", line)
            if m:
                cur = m.group(1)
                sections[cur] = {}
                continue
            if cur and "=" in line:
                k, v = line.split("=", 1)
                sections[cur][k.strip()] = v.strip()
    return sections


def fget(d, k, default=None):
    v = d.get(k)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


mixed_rows = []
for p in strategy_files:
    s = parse_sections(p)
    auto = s.get("auto-adaptive", {})
    orig = s.get("original", {})
    mixed_rows.append(
        {
            "file": os.path.basename(p),
            "auto_elapsed": fget(auto, "elapsed_ms"),
            "orig_elapsed": fget(orig, "elapsed_ms"),
            "streak_ratio": fget(auto, "profile.auto.streak_ratio"),
            "hot_key_share": fget(auto, "profile.auto.hot_key_share"),
            "use_hot": auto.get("profile.auto.use_hot_bucket", "false") == "true",
        }
    )

hot_rows = []
for p in hotspot_files:
    s = parse_sections(p)
    auto = s.get("auto-adaptive", {})
    orig = s.get("original", {})
    hot_rows.append(
        {
            "file": os.path.basename(p),
            "auto_elapsed": fget(auto, "elapsed_ms"),
            "orig_elapsed": fget(orig, "elapsed_ms"),
            "streak_ratio": fget(auto, "profile.auto.streak_ratio"),
            "hot_key_share": fget(auto, "profile.auto.hot_key_share"),
            "use_hot": auto.get("profile.auto.use_hot_bucket", "false") == "true",
        }
    )

# Heuristic suggestions
mixed_streaks = [r["streak_ratio"] for r in mixed_rows if r["streak_ratio"] is not None]
hot_streaks = [r["streak_ratio"] for r in hot_rows if r["streak_ratio"] is not None]
mixed_hot_share = [r["hot_key_share"] for r in mixed_rows if r["hot_key_share"] is not None]
hot_hot_share = [r["hot_key_share"] for r in hot_rows if r["hot_key_share"] is not None]

suggest_streak = CUR_STREAK
suggest_margin = CUR_MARGIN
suggest_hot_share = CUR_HOT_SHARE

if mixed_streaks and hot_streaks:
    # Keep threshold between mixed median and hotspot median with conservative bias.
    m = median(mixed_streaks)
    h = median(hot_streaks)
    suggest_streak = max(0.05, min(0.95, (m * 0.55 + h * 0.45)))

if mixed_hot_share and hot_hot_share:
    mhs = median(mixed_hot_share)
    hhs = median(hot_hot_share)
    suggest_hot_share = max(0.005, min(0.5, (mhs * 0.7 + hhs * 0.3)))

# Margin nudges to suppress false positives if recent hotspot still slower than original.
mismatch_count = sum(
    1
    for r in (mixed_rows + hot_rows)
    if r["use_hot"] and r["auto_elapsed"] is not None and r["orig_elapsed"] is not None and r["auto_elapsed"] > r["orig_elapsed"]
)
if mismatch_count >= 2:
    suggest_margin = min(0.3, CUR_MARGIN + 0.01)

recommend = (
    abs(suggest_streak - CUR_STREAK) >= 0.02
    or abs(suggest_margin - CUR_MARGIN) >= 0.01
    or abs(suggest_hot_share - CUR_HOT_SHARE) >= 0.01
)

now = datetime.now().strftime("%Y%m%d-%H%M%S")
out = os.path.join(OUT_DIR, f"auto-adaptive-threshold-suggestion-{now}.txt")
with open(out, "w", encoding="utf-8") as f:
    f.write("auto_adaptive_threshold_suggestion\n")
    f.write(f"input.strategy_files={len(strategy_files)}\n")
    f.write(f"input.hotspot_files={len(hotspot_files)}\n")
    f.write(f"current.streak_ratio={CUR_STREAK:.4f}\n")
    f.write(f"current.min_margin={CUR_MARGIN:.4f}\n")
    f.write(f"current.min_hot_key_share={CUR_HOT_SHARE:.4f}\n")
    f.write(f"suggest.streak_ratio={suggest_streak:.4f}\n")
    f.write(f"suggest.min_margin={suggest_margin:.4f}\n")
    f.write(f"suggest.min_hot_key_share={suggest_hot_share:.4f}\n")
    f.write(f"suggest.recommended={'true' if recommend else 'false'}\n")
    f.write(f"stats.mismatch_count={mismatch_count}\n")

print(f"[OK] threshold suggestion: {out}")
