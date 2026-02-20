#!/usr/bin/env python3
import argparse
import csv
import glob
import math
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List


def latest(pattern: str) -> Optional[str]:
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def iv(v: str, default=0) -> int:
    try:
        return int(float(v))
    except Exception:
        return default


def fv(v: str, default=0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def pearson(xs: list[float], ys: list[float]) -> Optional[float]:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x == 0 or den_y == 0:
        return None
    return num / (den_x * den_y)


def main():
    ap = argparse.ArgumentParser(description="Analyze aggressive/original ratio vs scan metrics")
    ap.add_argument("--csv", default=None, help="bench-regression-matrix csv path")
    ap.add_argument("--out", default=None, help="output markdown path")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    bench = root / "run" / "bench"
    csv_path = Path(args.csv) if args.csv else None
    if csv_path is None:
        p = latest(str(bench / "bench-regression-matrix-*.csv"))
        if not p:
            raise SystemExit("no regression csv found")
        csv_path = Path(p)

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    cases: dict[tuple[str, str, str], dict[str, dict]] = defaultdict(dict)
    for r in rows:
        key = (r.get("workload", "?"), r.get("txs", "0"), r.get("keys", "0"))
        cases[key][r.get("strategy", "?")] = r

    agg = defaultdict(list)
    for (workload, txs, keys), pair in cases.items():
        if "original" not in pair or "aggressive-greedy" not in pair:
            continue
        o = pair["original"]
        a = pair["aggressive-greedy"]

        o_ms = fv(o.get("elapsed_ms", "0"))
        a_ms = fv(a.get("elapsed_ms", "0"))
        if o_ms <= 0:
            continue
        ratio = a_ms / o_ms

        txs_i = iv(txs)
        groups_i = iv(a.get("groups", "0"))
        scans = iv(a.get("candidate_groups_scanned", "0"))

        agg[workload].append(
            {
                "txs": txs_i,
                "keys": iv(keys),
                "ratio": ratio,
                "scan": scans,
                "scan_per_tx": (scans / txs_i) if txs_i else 0.0,
                "scan_per_group": (scans / groups_i) if groups_i else 0.0,
            }
        )

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else bench / f"aggressive-scan-correlation-{ts}.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Aggressive Scan Correlation Report",
        f"generated_at={datetime.now().isoformat()}",
        f"source_csv={csv_path}",
        "",
        "| workload | n | avg_ratio | max_ratio | corr(ratio, scan) | corr(ratio, scan_per_tx) | corr(ratio, scan_per_group) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]

    for workload in sorted(agg.keys()):
        xs_ratio = [r["ratio"] for r in agg[workload]]
        ys_scan = [float(r["scan"]) for r in agg[workload]]
        ys_scan_tx = [r["scan_per_tx"] for r in agg[workload]]
        ys_scan_group = [r["scan_per_group"] for r in agg[workload]]

        c1 = pearson(xs_ratio, ys_scan)
        c2 = pearson(xs_ratio, ys_scan_tx)
        c3 = pearson(xs_ratio, ys_scan_group)

        def fmt(x):
            return "n/a" if x is None else f"{x:.4f}"

        lines.append(
            "| {} | {} | {:.3f} | {:.3f} | {} | {} | {} |".format(
                workload,
                len(xs_ratio),
                sum(xs_ratio) / len(xs_ratio),
                max(xs_ratio),
                fmt(c1),
                fmt(c2),
                fmt(c3),
            )
        )

    lines += ["", "## Notes", "- Pearson 相关系数用于快速判断线性相关（仅作归因信号，不作因果证明）。", "- 当 scan 指标在样本中几乎不变时，相关系数会显示 `n/a`。", ""]

    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] correlation report: {out}")


if __name__ == "__main__":
    main()
