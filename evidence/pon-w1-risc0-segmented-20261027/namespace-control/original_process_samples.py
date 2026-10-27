#!/usr/bin/env python3
"""Bounded live observations of only this experiment's owned process group.

No environment or command-line data is read. These samples diagnose activity;
they cannot replace terminal wait4 CPU accounting or a full cgroup memory peak.
"""
import json
import os
from pathlib import Path
import time


def group_sample(pgid):
    processes = []
    races = 0
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            raw = (path / "stat").read_text()
            fields = raw.rsplit(")", 1)[1].split()
            if int(fields[2]) != pgid:
                continue
            processes.append({"pid": int(path.name), "state": fields[0],
                "parent_pid": int(fields[1]), "user_cpu_ticks": int(fields[11]),
                "system_cpu_ticks": int(fields[12]), "threads": int(fields[17]),
                "resident_bytes": max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE")})
        except (OSError, ValueError, IndexError):
            races += 1
    return {"monotonic_seconds": time.monotonic(), "process_group": pgid,
            "processes": sorted(processes, key=lambda value: value["pid"]),
            "process_read_races": races, "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "live_rss_sum_bytes": sum(value["resident_bytes"] for value in processes)}


class GroupSampler:
    def __init__(self, path):
        self.output = path.open("x")
        self.samples = 0
        self.next_at = 0
        self.maximum_rss_sum = 0

    def tick(self):
        if time.monotonic() < self.next_at or self.samples >= 2000:
            return
        sample = group_sample(os.getpgrp())
        self.output.write(json.dumps(sample) + "\n")
        self.output.flush()
        self.samples += 1
        self.next_at = time.monotonic() + 2
        self.maximum_rss_sum = max(self.maximum_rss_sum, sample["live_rss_sum_bytes"])

    def close(self):
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        return {"samples": self.samples, "maximum_sampled_live_rss_sum_bytes": self.maximum_rss_sum,
            "interval_seconds": 2, "maximum_samples": 2000,
            "scope": "only the owned process group; RSS sums include shared pages; sampling can miss peaks and exited processes; not PSS, cgroup peak or terminal total CPU"}
