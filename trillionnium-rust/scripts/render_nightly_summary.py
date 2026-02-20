#!/usr/bin/env python3
import glob
import os
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HEALTH = os.path.join(ROOT, "run", "health")
OUT = os.path.join(HEALTH, f"nightly-summary-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md")
os.makedirs(HEALTH, exist_ok=True)


def latest(pattern: str):
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_kv(path: str):
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out

attrib_file = latest(os.path.join(HEALTH, "nightly-attribution-*.txt"))
suggest_file = latest(os.path.join(HEALTH, "auto-adaptive-threshold-suggestion-*.txt"))
a = parse_kv(attrib_file)
s = parse_kv(suggest_file)

labels = a.get("attribution.labels", "unknown")
reasons = a.get("attribution.reasons", "none")

lines = []
lines.append("# Nightly Health Summary")
lines.append("")
lines.append(f"- Labels: `{labels}`")
lines.append(f"- Reasons: `{reasons}`")
lines.append("")
lines.append("## Auto-adaptive decision snapshot")
lines.append(f"- Mixed: `{a.get('strategy_exp.auto.reason', 'unknown')}` (use_hot={a.get('strategy_exp.auto.use_hot_bucket', 'unknown')})")
lines.append(f"- Hotspot: `{a.get('hotspot_exp.auto.reason', 'unknown')}` (use_hot={a.get('hotspot_exp.auto.use_hot_bucket', 'unknown')})")
lines.append(f"- Mixed elapsed: original={a.get('strategy_exp.elapsed.original_ms', 'n/a')}ms / auto={a.get('strategy_exp.elapsed.auto_ms', 'n/a')}ms")
lines.append(f"- Hotspot elapsed: original={a.get('hotspot_exp.elapsed.original_ms', 'n/a')}ms / auto={a.get('hotspot_exp.elapsed.auto_ms', 'n/a')}ms")
lines.append("")
lines.append("## Threshold suggestion")
if s:
    lines.append(f"- Recommended: `{s.get('suggest.recommended', 'false')}`")
    lines.append(f"- Current: streak={s.get('current.streak_ratio', 'n/a')}, margin={s.get('current.min_margin', 'n/a')}, hot_share={s.get('current.min_hot_key_share', 'n/a')}")
    lines.append(f"- Suggest: streak={s.get('suggest.streak_ratio', 'n/a')}, margin={s.get('suggest.min_margin', 'n/a')}, hot_share={s.get('suggest.min_hot_key_share', 'n/a')}")
else:
    lines.append("- No suggestion artifact found")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print(f"[OK] nightly summary: {OUT}")
