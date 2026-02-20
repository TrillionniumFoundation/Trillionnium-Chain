#!/usr/bin/env python3
import argparse
import glob
import os
import re
import sys
from datetime import datetime
from pathlib import Path


SECTION_RE = re.compile(r"^---\s+strategy=(.+?)\s+---$")
KV_RE = re.compile(r"^([a-zA-Z0-9_\.-]+)=(.+)$")


def pick_latest(root: Path, pattern: str) -> str | None:
    files = sorted(glob.glob(str(root / pattern)), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_report(path: Path):
    meta = {
        "source": str(path),
        "workload": "?",
        "txs": "?",
        "keys": "?",
    }
    rows = {}
    cur = None

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        m = SECTION_RE.match(line)
        if m:
            cur = m.group(1).strip()
            rows[cur] = {}
            continue

        # header style in executor_strategy_experiment
        if line.startswith("workload=") and " " not in line:
            meta["workload"] = line.split("=", 1)[1].strip()
            continue

        # compact style in hotspot experiment: workload=hot-streak txs=... keys=...
        if line.startswith("workload=") and " " in line:
            for token in line.split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    if k in ("workload", "txs", "keys"):
                        meta[k] = v
            continue

        # separate line: txs=... keys=...
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


def iv(d: dict, k: str) -> int:
    try:
        return int(float(d.get(k, "0")))
    except Exception:
        return 0


def summarize_one(path: Path):
    meta, rows = parse_report(path)
    orig = rows.get("original")
    aggr = rows.get("aggressive-greedy")
    if not orig or not aggr:
        return None

    o_ms = iv(orig, "elapsed_ms")
    a_ms = iv(aggr, "elapsed_ms")
    ratio = (a_ms / o_ms) if o_ms else 0.0

    o_scan = iv(orig, "profile.candidate_groups_scanned")
    a_scan = iv(aggr, "profile.candidate_groups_scanned")
    scan_ratio = (a_scan / o_scan) if o_scan else (float("inf") if a_scan > 0 else 0.0)

    return {
        "source": str(path),
        "workload": meta.get("workload", "?"),
        "txs": meta.get("txs", "?"),
        "keys": meta.get("keys", "?"),
        "original_ms": o_ms,
        "aggressive_ms": a_ms,
        "elapsed_ratio": ratio,
        "original_scan": o_scan,
        "aggressive_scan": a_scan,
        "scan_ratio": scan_ratio,
    }


def render_markdown(rows: list[dict]) -> str:
    lines = []
    lines.append("# Aggressive Profiling Summary")
    lines.append(f"generated_at={datetime.now().isoformat()}")
    lines.append("")

    if not rows:
        lines.append("No comparable original/aggressive reports found.")
        return "\n".join(lines) + "\n"

    lines.append("| workload | txs | keys | original_ms | aggressive_ms | aggr/orig | original_scan | aggressive_scan | scan_ratio | source |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")

    for r in sorted(rows, key=lambda x: (x["workload"], str(x["txs"]), str(x["keys"]))):
        lines.append(
            "| {workload} | {txs} | {keys} | {original_ms} | {aggressive_ms} | {elapsed_ratio:.3f} | {original_scan} | {aggressive_scan} | {scan_ratio:.3f} | `{source}` |".format(**r)
        )

    worst = max(rows, key=lambda x: x["elapsed_ratio"])
    lines.append("")
    lines.append(
        "worst_elapsed_ratio: workload={workload} txs={txs} keys={keys} ratio={elapsed_ratio:.3f}".format(
            **worst
        )
    )
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Summarize aggressive strategy profile reports")
    p.add_argument("reports", nargs="*", help="bench report files")
    p.add_argument("--out", default=None, help="output markdown path")
    args = p.parse_args()

    root = Path(__file__).resolve().parent.parent
    bench_dir = root / "run" / "bench"

    report_paths = [Path(x) for x in args.reports]
    if not report_paths:
        for pat in ["executor-strategy-exp-*.txt", "executor-hotspot-exp-*.txt"]:
            latest = pick_latest(bench_dir, pat)
            if latest:
                report_paths.append(Path(latest))

    if not report_paths:
        print("no reports found", file=sys.stderr)
        sys.exit(2)

    rows = []
    for rp in report_paths:
        s = summarize_one(rp)
        if s:
            rows.append(s)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else bench_dir / f"aggressive-profile-summary-{ts}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(rows), encoding="utf-8")

    print(f"[OK] aggressive profile summary: {out}")


if __name__ == "__main__":
    main()
