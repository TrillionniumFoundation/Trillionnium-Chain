#!/usr/bin/env python3
"""Actual Linux prerequisites for exactly two independent two-thread provers."""
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re

GIB = 1024**3


def controller_paths(membership, mountinfo):
    """Locate the actual v2 hierarchy, including a cgroup-namespace mount root."""
    members = [line.split(":", 2)[2] for line in membership.splitlines()
               if line.startswith("0::")]
    if len(members) != 1:
        raise ValueError("one actual cgroup-v2 membership is required")
    member = PurePosixPath(members[0])
    if not member.is_absolute() or ".." in member.parts:
        raise ValueError("noncanonical cgroup membership")
    mounts = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator or after.split()[0] != "cgroup2":
            continue
        fields = before.split()
        decode = lambda value: re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
        mount_root = PurePosixPath(decode(fields[3]))
        if member.is_relative_to(mount_root):
            mounts.append((Path(decode(fields[4])), member.relative_to(mount_root)))
    if len(mounts) != 1:
        raise ValueError("one unambiguous mounted actual cgroup-v2 hierarchy is required")
    root, relative = mounts[0]
    root = root.resolve()
    current = (root / relative).resolve()
    if not current.is_relative_to(root):
        raise ValueError("cgroup membership escapes its mounted hierarchy")
    paths = []
    while True:
        paths.append(current)
        if current == root:
            return paths
        current = current.parent


def observe():
    cpu_affinity = sorted(os.sched_getaffinity(0))
    memory = {key: int(value.split()[0]) * 1024
              for key, value in (line.split(":", 1)
                                 for line in Path("/proc/meminfo").read_text().splitlines())
              if key in {"MemTotal", "MemAvailable"}}
    membership = Path("/proc/self/cgroup").read_text()
    mountinfo = Path("/proc/self/mountinfo").read_text()
    result = {"schema": "pon-w1-segmented-runner-prerequisites-v1",
        "requested_workers": 2, "rayon_threads_per_worker": 2,
        "minimum_available_bytes": 8 * GIB, "affinity_cpu_ids": cpu_affinity,
        "memory": memory, "cgroup_membership": membership,
        "cgroup_observations": [], "resource_qualification": False}
    errors = []
    cpu_limits = []
    available_limits = []
    try:
        paths = controller_paths(membership, mountinfo)
    except ValueError as error:
        errors.append(str(error))
    else:
        seen_cpu = seen_memory = False
        for current in paths:
            record = {"path": str(current)}
            for name in ["cpu.max", "memory.max", "memory.current"]:
                try:
                    record[name] = (current / name).read_text().strip()
                except OSError as error:
                    record[name] = None
                    record[name + "_errno"] = error.errno
            if record["cpu.max"] is not None:
                seen_cpu = True
                quota, period = record["cpu.max"].split()
                if quota != "max":
                    cpu_limits.append(int(quota) / int(period))
            if record["memory.max"] is not None:
                seen_memory = True
                if record["memory.max"] != "max":
                    if record["memory.current"] is None:
                        errors.append("finite memory limit has no current usage observation")
                    else:
                        available_limits.append(max(0, int(record["memory.max"])
                                                    - int(record["memory.current"])))
            result["cgroup_observations"].append(record)
        if not seen_cpu or not seen_memory:
            errors.append("actual controller limits unavailable; absence is not unlimited")
    effective_cpus = min([len(cpu_affinity), *cpu_limits])
    available_memory = min([memory.get("MemAvailable", 0), *available_limits])
    result.update(effective_cpu_limit=effective_cpus,
                  conservative_available_memory_bytes=available_memory)
    if effective_cpus < 4:
        errors.append("the fixed two-by-two profile requires at least four available CPUs")
    if available_memory < 8 * GIB:
        errors.append("the fixed profile requires at least eight GiB observed available memory")
    result.update(prerequisites_met=not errors, errors=errors,
                  missing_limits_mean_unlimited=False, silent_profile_fallback=False)
    return result


def require_runner(path):
    result = observe()
    with path.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if not result["prerequisites_met"]:
        raise RuntimeError("; ".join(result["errors"]))
    return result
