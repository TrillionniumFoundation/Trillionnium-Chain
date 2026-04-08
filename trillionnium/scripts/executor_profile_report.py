#!/usr/bin/env python3
import argparse
import glob
import os
import re
import statistics
from datetime import datetime


def latest(pattern: str):
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_sections(path: str):
    sections = []
    cur = None
    sec_header = re.compile(r"^---\s+(.+?)\s+---$")
    kv = re.compile(r"^([a-zA-Z0-9_\.]+)=(.+)$")

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            m = sec_header.match(line)
            if m:
                if cur:
                    sections.append(cur)
                cur = {"header": m.group(1)}
                continue
            m = kv.match(line)
            if m and cur is not None:
                k, v = m.group(1), m.group(2)
                try:
                    if "." in v:
                        cur[k] = float(v)
                    else:
                        cur[k] = int(v)
                except ValueError:
                    cur[k] = v
    if cur:
        sections.append(cur)
    return sections


def summarize_rows(rows, title):
    out = [f"## {title}"]
    if not rows:
        out.append("(no rows)")
        return out

    elapsed = [r.get("elapsed_ms", 0) for r in rows]
    groups = [r.get("groups", 0) for r in rows]
    hit_rate = [r.get("profile.conflict_hit_rate", 0.0) for r in rows if "profile.conflict_hit_rate" in r]
    avg_group_size = [r.get("profile.avg_group_size", 0.0) for r in rows if "profile.avg_group_size" in r]
    hot_object_share = [r.get("profile.hot_object_share", 0.0) for r in rows if "profile.hot_object_share" in r]

    out.append(f"rows={len(rows)}")
    out.append(
        "elapsed_ms: min={:.0f} p50={:.0f} max={:.0f}".format(
            min(elapsed), statistics.median(elapsed), max(elapsed)
        )
    )
    out.append(
        "groups: min={} p50={} max={}".format(
            min(groups), int(statistics.median(groups)), max(groups)
        )
    )
    if avg_group_size:
        out.append(
            "avg_group_size: min={:.4f} p50={:.4f} max={:.4f}".format(
                min(avg_group_size), statistics.median(avg_group_size), max(avg_group_size)
            )
        )
    if hot_object_share:
        out.append(
            "hot_object_share: min={:.4f} p50={:.4f} max={:.4f}".format(
                min(hot_object_share), statistics.median(hot_object_share), max(hot_object_share)
            )
        )
    if hit_rate:
        out.append(
            "conflict_hit_rate: min={:.4f} p50={:.4f} max={:.4f}".format(
                min(hit_rate), statistics.median(hit_rate), max(hit_rate)
            )
        )

    top_hot = sorted(rows, key=lambda r: r.get("profile.conflict_hit_rate", 0.0), reverse=True)[:3]
    out.append("top_conflict_rows:")
    for r in top_hot:
        out.append(
            "  - {} | elapsed_ms={} groups={} hit_rate={:.4f}".format(
                r.get("header", "?"),
                r.get("elapsed_ms", "?"),
                r.get("groups", "?"),
                float(r.get("profile.conflict_hit_rate", 0.0)),
            )
        )
    return out


def main():
    p = argparse.ArgumentParser(description="Build executor profiling summary from bench reports")
    p.add_argument("--classic", default=None, help="bench-matrix txt")
    p.add_argument("--mixed", default=None, help="bench-mixed-matrix txt")
    p.add_argument("--out", default=None, help="output txt")
    args = p.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    bench_dir = os.path.join(root, "run", "bench")
    classic = args.classic or latest(os.path.join(bench_dir, "bench-matrix-*.txt"))
    mixed = args.mixed or latest(os.path.join(bench_dir, "bench-mixed-matrix-*.txt"))

    if not classic and not mixed:
        raise SystemExit("no bench reports found")

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join(bench_dir, f"executor-profile-summary-{ts}.txt")

    lines = ["# Executor Profile Summary", f"generated_at={datetime.now().isoformat()}"]
    if classic:
        classic_rows = parse_sections(classic)
        lines.append(f"classic_file={classic}")
        lines.extend(summarize_rows(classic_rows, "Classic Matrix"))
    if mixed:
        mixed_rows = parse_sections(mixed)
        lines.append(f"mixed_file={mixed}")
        lines.extend(summarize_rows(mixed_rows, "Mixed Matrix"))

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[OK] executor profile summary: {out}")


if __name__ == "__main__":
    main()
