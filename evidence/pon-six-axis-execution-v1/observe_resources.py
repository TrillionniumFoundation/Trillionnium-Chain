#!/usr/bin/env python3
"""Observe one unchanged command, retaining its actual exit and complete cost.

This is an external development observer, not a native acceptance validator.
The command's output is inherited, and its arguments and environment are unaltered.
"""
import argparse
import datetime
import json
from pathlib import Path
import resource
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required")
    with args.output.open("x", encoding="utf-8") as stream:
        record = {
            "schema": "pon-six-axis-whole-command-resources-v1",
            "argv": command,
            "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "started",
            "scope": "entire command and waited children, including setup, warmup, checks, output and compilation if any; no per-stage attribution",
            "maximum_rss_scope": "Linux RUSAGE_CHILDREN maximum resident set, KiB; not the simultaneous sum of all process memory",
            "production_activation": False,
        }
        json.dump(record, stream, indent=2)
        stream.write("\n")
        stream.flush()
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic()
        result = subprocess.run(command, check=False)
        wall = time.monotonic() - start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update(
            status="returned",
            returncode=result.returncode,
            wall_seconds=wall,
            child_user_cpu_seconds=after.ru_utime - before.ru_utime,
            child_system_cpu_seconds=after.ru_stime - before.ru_stime,
            maximum_rss_kib=after.ru_maxrss,
            major_page_faults=after.ru_majflt - before.ru_majflt,
            minor_page_faults=after.ru_minflt - before.ru_minflt,
            block_input_operations=after.ru_inblock - before.ru_inblock,
            block_output_operations=after.ru_oublock - before.ru_oublock,
        )
        stream.seek(0)
        json.dump(record, stream, indent=2)
        stream.write("\n")
        stream.truncate()
        stream.flush()
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
