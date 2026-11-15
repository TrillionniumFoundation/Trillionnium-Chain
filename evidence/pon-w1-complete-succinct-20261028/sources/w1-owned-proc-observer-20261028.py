#!/usr/bin/env python3
"""Read-only CPU/RSS evidence for the exact frozen W1 process groups.

This observer does not send signals, run work, grant budget, or decide whether
a proof is valid. Birth ticks distinguish PID reuse. Samples give a cumulative
CPU lower bound and sampled aggregate RSS, not an exact peak. Use successful
stage wait4 results as the primary CPU total; do not add both observations.
"""
import argparse
import json
import os
from pathlib import Path
import time


def info(path):
    raw = (path / "stat").read_text()
    rest = raw[raw.rfind(")") + 2:].split()
    return {"pid":int(path.name), "state":rest[0], "ppid":int(rest[1]),
            "pgrp":int(rest[2]), "user_ticks":int(rest[11]),
            "system_ticks":int(rest[12]), "birth_ticks":int(rest[19]),
            "rss_pages":int(rest[21])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(exist_ok=False)
    hz, pages = os.sysconf("SC_CLK_TCK"), os.sysconf("SC_PAGE_SIZE")
    started = time.monotonic()
    declaration = {"schema":"TRNM-W1-OWNED-PROC-OBSERVER1", "started_unix_ns":time.time_ns(),
        "clock_ticks_per_second":hz, "page_bytes":pages, "poll_seconds":0.5,
        "maximum_wall_seconds":9000, "checkpoint":str(args.checkpoint),
        "source_of_truth":"visible /proc stat, keyed by (PID,birth_ticks)",
        "ownership":"exact frozen runner argv + checkpoint; r0vm must share the recorded process group",
        "purpose":"supplement interrupted-stage wait4 lower bounds; not summed with completed-stage wait4",
        "can_modify_processes":False, "complete_proof_claim":False}
    (args.out / "declaration.json").write_text(json.dumps(declaration,indent=2)+"\n")
    groups = {}
    maxima = {}
    sampled_peak = 0
    errors = 0
    with (args.out / "samples.jsonl").open("x",buffering=1) as log:
        while time.monotonic()-started < 9000 and not args.stop_file.exists():
            now = time.monotonic()
            candidates = []
            for path in Path("/proc").iterdir():
                if not path.name.isdigit():
                    continue
                try:
                    comm = (path / "comm").read_text().strip()
                    if comm not in ("w1-staged-prove", "r0vm"):
                        continue
                    argv = (path / "cmdline").read_bytes().split(b"\0")
                    row = info(path)
                    if (argv[0] == b"/tmp/trnm-w1-r2-target/release/w1-staged-prover"
                        and os.fsencode(args.checkpoint) in argv):
                        row["role"] = "frozen-w1-runner"
                        groups[row["pgrp"]] = now
                        candidates.append(row)
                    elif argv[0] == b"/tmp/pure-pon-risc0-3.0.3/r0vm":
                        row["role"] = "pinned-r0vm"
                        candidates.append(row)
                except (OSError, ValueError, IndexError):
                    errors += 1
            # A short grace observes surviving server children after parent exit,
            # without attributing arbitrary future process groups to this task.
            groups = {g:t for g,t in groups.items() if now-t < 30}
            rows = [row for row in candidates if row["pgrp"] in groups]
            for row in rows:
                key = f"{row['pid']}:{row['birth_ticks']}"
                prior = maxima.get(key)
                if prior is None or row["user_ticks"]+row["system_ticks"] >= prior["user_ticks"]+prior["system_ticks"]:
                    maxima[key] = {**row,"last_seen_unix_ns":time.time_ns()}
            rss = sum(row["rss_pages"]*pages for row in rows)
            sampled_peak = max(sampled_peak,rss)
            try:
                stage = json.loads((args.run/"current-stage.json").read_text())["stage"]
            except (OSError,ValueError,KeyError):
                stage = None
            log.write(json.dumps({"unix_ns":time.time_ns(),"monotonic":now,
                "stage":stage,"processes":rows,"sampled_aggregate_rss_bytes":rss})+"\n")
            if int((now-started)*2)%20 == 0:
                os.fsync(log.fileno())
                (args.out/"observed-maxima.json").write_text(json.dumps({"processes":maxima,
                    "sampled_aggregate_peak_rss_bytes":sampled_peak,"proc_read_races":errors},indent=2)+"\n")
            time.sleep(0.5)
        os.fsync(log.fileno())
    result = {**declaration,"finished_unix_ns":time.time_ns(),"wall_seconds":time.monotonic()-started,
        "processes":maxima,"observed_cumulative_cpu_lower_bound_seconds":
            sum(r["user_ticks"]+r["system_ticks"] for r in maxima.values())/hz,
        "sampled_aggregate_peak_rss_bytes":sampled_peak,"proc_read_races":errors,
        "all_process_cpu_exactly_measured":False,"other_processes_modified":False}
    (args.out/"result.json").write_text(json.dumps(result,indent=2)+"\n")


if __name__ == "__main__":
    main()
