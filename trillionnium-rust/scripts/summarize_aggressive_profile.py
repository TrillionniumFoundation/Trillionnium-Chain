#!/usr/bin/env python3
import re
import sys
from pathlib import Path

if len(sys.argv) < 2:
    print("usage: summarize_aggressive_profile.py <bench-report.txt>")
    sys.exit(2)

p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8", errors="ignore")

blocks = []
cur = {}
for line in text.splitlines():
    line = line.strip()
    if line.startswith("--- strategy="):
        if cur:
            blocks.append(cur)
        s = line.split("=", 1)[1].strip()
        s = s.replace("---", "").strip()
        cur = {"strategy": s}
        continue
    for k in ["workload", "txs", "keys", "elapsed_ms", "profile.candidate_groups_scanned", "profile.conflict_checks", "profile.conflict_hits"]:
        prefix = k + "="
        if line.startswith(prefix):
            cur[k] = line[len(prefix):]
if cur:
    blocks.append(cur)

by = {b.get("strategy", "unknown"): b for b in blocks}
orig = by.get("original")
aggr = by.get("aggressive-greedy")

print(f"source={p}")
if not orig or not aggr:
    print("missing original/aggressive-greedy block")
    sys.exit(1)

def iv(x):
    try:
        return int(x)
    except Exception:
        return 0

o_ms = iv(orig.get("elapsed_ms"))
a_ms = iv(aggr.get("elapsed_ms"))
o_scan = iv(orig.get("profile.candidate_groups_scanned"))
a_scan = iv(aggr.get("profile.candidate_groups_scanned"))
ratio = (a_ms / o_ms) if o_ms else 0.0

print(f"workload={orig.get('workload','?')} txs={orig.get('txs','?')} keys={orig.get('keys','?')}")
print(f"original.elapsed_ms={o_ms}")
print(f"aggressive.elapsed_ms={a_ms}")
print(f"aggressive_vs_original_ratio={ratio:.3f}")
print(f"original.candidate_groups_scanned={o_scan}")
print(f"aggressive.candidate_groups_scanned={a_scan}")
