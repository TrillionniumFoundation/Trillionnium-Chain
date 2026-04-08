#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

SECTION_RE = re.compile(r"^---\s+strategy=(.+?)\s+---$")
KV_RE = re.compile(r"^([a-zA-Z0-9_\.-]+)=(.+)$")


def pick_latest(root: Path, pattern: str) -> Optional[str]:
    files = sorted(glob.glob(str(root / pattern)), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def iv(x, default=0):
    try:
        return int(float(x))
    except Exception:
        return default


def fv(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def parse_report(path: Path):
    meta = {"source": str(path), "workload": "?", "txs": "?", "keys": "?"}
    rows = {}
    cur = None

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        m = SECTION_RE.match(line)
        if m:
            cur = m.group(1).strip()
            rows[cur] = {}
            continue

        if line.startswith("workload=") and " " not in line:
            meta["workload"] = line.split("=", 1)[1].strip()
            continue

        if line.startswith("workload=") and " " in line:
            for token in line.split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    if k in ("workload", "txs", "keys"):
                        meta[k] = v
            continue

        if line.startswith("txs="):
            for token in line.split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    if k in ("txs", "keys"):
                        meta[k] = v
            continue

        if cur is not None:
            m2 = KV_RE.match(line)
            if m2:
                k, v = m2.group(1), m2.group(2)
                rows[cur][k] = v

    return meta, rows


def summarize_txt(path: Path):
    meta, rows = parse_report(path)
    orig = rows.get("original")
    aggr = rows.get("aggressive-greedy")
    if not orig or not aggr:
        return None

    o_ms = iv(orig.get("elapsed_ms"))
    a_ms = iv(aggr.get("elapsed_ms"))
    ratio = (a_ms / o_ms) if o_ms else 0.0

    o_scan = iv(orig.get("profile.candidate_groups_scanned"))
    a_scan = iv(aggr.get("profile.candidate_groups_scanned"))
    scan_ratio = (a_scan / o_scan) if o_scan else (float("inf") if a_scan > 0 else 0.0)

    return {
        "source": str(path),
        "workload": meta.get("workload", "?"),
        "txs": iv(meta.get("txs", 0)),
        "keys": iv(meta.get("keys", 0)),
        "original_ms": o_ms,
        "aggressive_ms": a_ms,
        "elapsed_ratio": ratio,
        "original_scan": o_scan,
        "aggressive_scan": a_scan,
        "scan_ratio": scan_ratio,
    }


def summarize_csv(path: Path):
    rows = list(csv.DictReader(path.open("r", encoding="utf-8")))
    by_case = {}
    out = []

    for r in rows:
        k = (r["workload"], r["txs"], r["keys"])
        by_case.setdefault(k, {})[r["strategy"]] = r

    for (workload, txs, keys), pair in sorted(by_case.items(), key=lambda x: (x[0][0], iv(x[0][1]), iv(x[0][2]))):
        if "original" not in pair or "aggressive-greedy" not in pair:
            continue

        o = pair["original"]
        a = pair["aggressive-greedy"]

        o_ms = fv(o.get("elapsed_ms"))
        a_ms = fv(a.get("elapsed_ms"))
        ratio = (a_ms / o_ms) if o_ms else 0.0

        txs_i = iv(txs)
        groups_i = iv(a.get("groups"))
        cand_i = iv(a.get("candidate_groups_scanned"))
        ww_c = iv(a.get("stage_ww_checks")); ww_h = iv(a.get("stage_ww_hits"))
        wr_c = iv(a.get("stage_wr_checks")); wr_h = iv(a.get("stage_wr_hits"))
        rw_c = iv(a.get("stage_rw_checks")); rw_h = iv(a.get("stage_rw_hits"))

        total_checks = ww_c + wr_c + rw_c
        total_hits = ww_h + wr_h + rw_h

        out.append({
            "source": str(path),
            "workload": workload,
            "txs": txs_i,
            "keys": iv(keys),
            "original_ms": o_ms,
            "aggressive_ms": a_ms,
            "elapsed_ratio": ratio,
            "aggressive_scan": cand_i,
            "scan_per_tx": (cand_i / txs_i) if txs_i else 0.0,
            "scan_per_group": (cand_i / groups_i) if groups_i else 0.0,
            "ww_hit_rate": (ww_h / ww_c) if ww_c else 0.0,
            "wr_hit_rate": (wr_h / wr_c) if wr_c else 0.0,
            "rw_hit_rate": (rw_h / rw_c) if rw_c else 0.0,
            "total_hit_rate": (total_hits / total_checks) if total_checks else 0.0,
            "total_checks": total_checks,
            "total_hits": total_hits,
        })

    return out


def pctl(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    idx = min(len(xs) - 1, max(0, int((len(xs) - 1) * q)))
    return xs[idx]


def render_markdown(rows: list[dict]) -> str:
    lines = ["# Aggressive Profiling Summary", f"generated_at={datetime.now().isoformat()}", ""]

    if not rows:
        return "\n".join(lines + ["No comparable original/aggressive reports found.", ""])

    lines.append("| workload | keys | txs | orig_ms | aggr_ms | aggr/orig | aggr_scan | scan/tx | scan/group | ww_hit | wr_hit | rw_hit | total_hit | source |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in sorted(rows, key=lambda x: (x["workload"], x["keys"])):
        lines.append(
            "| {workload} | {keys} | {txs} | {original_ms:.3f} | {aggressive_ms:.3f} | {elapsed_ratio:.3f} | {aggressive_scan} | {scan_per_tx:.3f} | {scan_per_group:.3f} | {ww_hit_rate:.4f} | {wr_hit_rate:.4f} | {rw_hit_rate:.4f} | {total_hit_rate:.4f} | `{source}` |".format(**r)
        )

    lines.append("")
    lines.append("## Aggregate by workload")
    lines.append("| workload | avg_ratio | p50_ratio | p95_ratio | scan_p50 | scan_p95 | scan_max | avg_scan_tx | avg_scan_group | avg_total_hit |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for wl in sorted({r["workload"] for r in rows}):
        subset = [r for r in rows if r["workload"] == wl]
        ratios = [r["elapsed_ratio"] for r in subset]
        scans = [float(r["aggressive_scan"]) for r in subset]
        lines.append(
            "| {} | {:.3f} | {:.3f} | {:.3f} | {:.0f} | {:.0f} | {:.0f} | {:.3f} | {:.3f} | {:.4f} |".format(
                wl,
                sum(ratios) / len(subset),
                pctl(ratios, 0.50),
                pctl(ratios, 0.95),
                pctl(scans, 0.50),
                pctl(scans, 0.95),
                max(scans) if scans else 0.0,
                sum(r["scan_per_tx"] for r in subset) / len(subset),
                sum(r["scan_per_group"] for r in subset) / len(subset),
                sum(r["total_hit_rate"] for r in subset) / len(subset),
            )
        )

    worst = max(rows, key=lambda x: x["elapsed_ratio"])
    lines.append("")
    lines.append(
        "worst_elapsed_ratio: workload={workload} txs={txs} keys={keys} ratio={elapsed_ratio:.3f}".format(**worst)
    )
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Summarize aggressive strategy profile reports")
    p.add_argument("reports", nargs="*", help="bench report files (txt)")
    p.add_argument("--csv", default=None, help="regression CSV path")
    p.add_argument("--out", default=None, help="output markdown path")
    args = p.parse_args()

    root = Path(__file__).resolve().parent.parent
    bench_dir = root / "run" / "bench"

    rows = []

    csv_path = Path(args.csv) if args.csv else None
    if csv_path is None:
        latest_csv = pick_latest(bench_dir, "bench-regression-matrix-*.csv")
        if latest_csv:
            csv_path = Path(latest_csv)

    if csv_path and csv_path.exists():
        rows.extend(summarize_csv(csv_path))

    if not rows:
        report_paths = [Path(x) for x in args.reports]
        if not report_paths:
            for pat in ["executor-strategy-exp-*.txt", "executor-hotspot-exp-*.txt"]:
                latest = pick_latest(bench_dir, pat)
                if latest:
                    report_paths.append(Path(latest))

        for rp in report_paths:
            s = summarize_txt(rp)
            if s:
                rows.append(s)

    if not rows:
        print("no reports found", file=sys.stderr)
        sys.exit(2)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else bench_dir / f"aggressive-profile-summary-{ts}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(rows), encoding="utf-8")

    print(f"[OK] aggressive profile summary: {out}")


if __name__ == "__main__":
    main()
