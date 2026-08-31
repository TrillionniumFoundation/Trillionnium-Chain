#!/usr/bin/env python3
"""Read-only SSH/local probe for the bounded PoCO LAN fleet."""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import socket
import subprocess
import time
import tomllib


REMOTE_PROBE = r'''set -eu
printf 'hostname=%s\n' "$(hostname)"
printf 'kernel=%s\n' "$(uname -srm)"
printf 'arch=%s\n' "$(uname -m)"
if command -v nproc >/dev/null; then printf 'cpu_threads=%s\n' "$(nproc)"; else printf 'cpu_threads=%s\n' "$(sysctl -n hw.logicalcpu)"; fi
if command -v free >/dev/null; then free -b | awk '/^Mem:/{print "memory_bytes="$2}'; else printf 'memory_bytes=%s\n' "$(sysctl -n hw.memsize)"; fi
printf 'epoch_ns=%s\n' "$(date +%s%N 2>/dev/null || date +%s000000000)"
'''


def parse_lines(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            raise ValueError(f"invalid probe line: {line!r}")
        result[key] = value
    return result


def local_probe() -> dict[str, str]:
    try:
        memory = str(
            int(
                subprocess.check_output(
                    ["awk", "/^MemTotal:/{print $2*1024}", "/proc/meminfo"],
                    text=True,
                ).strip()
            )
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        memory = "unknown"
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.platform(),
        "arch": platform.machine(),
        "cpu_threads": str(platform.os.cpu_count() or "unknown"),
        "memory_bytes": memory,
        "epoch_ns": str(time.time_ns()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inventory",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("inventory.toml"),
    )
    parser.add_argument("--timeout-seconds", type=int, default=15)
    args = parser.parse_args()
    with args.inventory.open("rb") as source:
        inventory = tomllib.load(source)

    observations = []
    failures = []
    for host in inventory["hosts"]:
        started = time.monotonic_ns()
        try:
            if host["management"] == "local":
                facts = local_probe()
            else:
                output = subprocess.run(
                    [
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        f"ConnectTimeout={args.timeout_seconds}",
                        host["management"],
                        REMOTE_PROBE,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=args.timeout_seconds,
                )
                facts = parse_lines(output.stdout)
            elapsed = time.monotonic_ns() - started
            if facts["arch"] != host["arch"]:
                raise ValueError(f"arch {facts['arch']} != inventory {host['arch']}")
            observations.append(
                {
                    "id": host["id"],
                    "lan_ip": host["lan_ip"],
                    "management": host["management"],
                    "round_trip_ns": elapsed,
                    "facts": facts,
                }
            )
        except (KeyError, OSError, subprocess.SubprocessError, ValueError) as error:
            failures.append({"id": host["id"], "error": str(error)})

    report = {
        "schema_version": 1,
        "fleet_id": inventory["fleet_id"],
        "network_scope": inventory["network_scope"],
        "geo_wan_evidence": False,
        "observed_at_epoch_ns": time.time_ns(),
        "observations": observations,
        "failures": failures,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if failures or len(observations) != 6:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
