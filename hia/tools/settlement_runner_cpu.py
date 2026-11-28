"""Optional, bounded runner observations. Never qualifies Settlement execution."""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


SCHEMA = "trnm.hia.settlement-runner-cpu.v1"
SYS = Path("/sys/fs/cgroup")
MAX_PROC_BYTES = 256 * 1024
MAX_NODE_BYTES = 4096
MAX_DEPTH = 16
MAX_CPU = 4096
MAX_NUMBER = (1 << 63) - 1
STAT_FIELDS = ("usage_usec", "user_usec", "system_usec", "nr_periods",
               "nr_throttled", "throttled_usec")


def read(path, limit):
    # Refuse symlinks at the counter itself; /proc/self is kernel-owned.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not a regular counter file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("overlong input")
    return data.decode("ascii")


def number(value, *, positive=False):
    if re.fullmatch(r"[0-9]{1,19}", value) is None:
        raise ValueError("invalid integer")
    value = int(value)
    if value > MAX_NUMBER or (positive and value == 0):
        raise ValueError("out-of-range integer")
    return value


def quota(value):
    fields = value.split()
    if len(fields) != 2:
        raise ValueError("invalid cpu.max")
    return [None if fields[0] == "max" else number(fields[0], positive=True),
            number(fields[1], positive=True)]


def counters(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ValueError("invalid cpu.stat")
        key, raw = fields
        if key in STAT_FIELDS:
            if key in result:
                raise ValueError("duplicate cpu.stat counter")
            result[key] = number(raw)
    if not result:
        raise ValueError("no recognized cpu.stat counters")
    return result


def safe_parts(path):
    if path == "/":
        return ()
    if not path.startswith("/"):
        raise ValueError("non-absolute cgroup path")
    pieces = tuple(path[1:].split("/"))
    if len(pieces) > MAX_DEPTH or any(
            not p or p in (".", "..") or re.fullmatch(r"[-a-zA-Z0-9_.:@]{1,128}", p) is None
            for p in pieces):
        raise ValueError("unsupported cgroup path")
    return pieces


def lineage(membership, mounts):
    matches = [line[3:] for line in membership.splitlines() if line.startswith("0::")]
    if len(matches) != 1:
        raise ValueError("unified cgroup membership unavailable")
    selected = []
    for line in mounts.splitlines():
        a, sep, b = line.partition(" - ")
        fields = a.split()
        if sep and len(fields) >= 6 and b.split()[:1] == ["cgroup2"] and fields[4] == str(SYS):
            selected.append(safe_parts(fields[3]))
    if len(selected) != 1:
        raise ValueError("unified cgroup mount unavailable")
    root = selected[0]
    path = safe_parts(matches[0])
    if root != path[:len(root)]:
        raise ValueError("membership outside visible mount")
    return path[len(root):], not root


def try_read(node, name, parse, reader):
    try:
        return parse(reader(node / name, MAX_NODE_BYTES))
    except (OSError, ValueError):
        return None


def cgroup(reader=read, base=SYS):
    try:
        parts, system_root_visible = lineage(
            reader(Path("/proc/self/cgroup"), MAX_NODE_BYTES),
            reader(Path("/proc/self/mountinfo"), MAX_PROC_BYTES))
        visible = [base.joinpath(*parts[:i]) for i in range(len(parts), -1, -1)]
        for path in visible:
            if path.resolve(strict=True) != path or not path.is_dir():
                raise ValueError("unsupported cgroup directory")
        leaf_identity = visible[0].stat()
    except (OSError, ValueError, RuntimeError):
        return {"availability": "unavailable"}
    qos = [try_read(node, "cpu.max", quota, reader) for node in visible]
    leaf = try_read(visible[0], "cpu.stat", counters, reader)
    # cpu.max does not exist on the real cgroup-v2 root; don't treat all other
    # missing ancestors as unlimited. Even visible quotas aren't a hard bound
    # on throughput or a guarantee we can see host namespace parents.
    inspectable = qos[:-1] if system_root_visible else qos
    known = [q for q in qos if q is not None and q[0] is not None]
    limit = min(known, key=lambda q: Fraction(*q)) if known else None
    return {"availability": "observed" if leaf is not None else "partial",
            "_local_identity": (leaf_identity.st_dev, leaf_identity.st_ino),
            "scope": "snapshot-process-cgroup-shared-not-settlement-process",
            "leaf_counters": leaf, "visible_quota_chain": qos,
            "visible_quota_min": limit,
            "visible_quota_chain_complete": all(q is not None for q in inspectable)}


def cpu_model(reader=read):
    try:
        raw = reader(Path("/proc/cpuinfo"), MAX_PROC_BYTES)
    except (OSError, ValueError):
        return None
    values = set()
    for line in raw.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() in {"model name", "Hardware"}:
            value = value.strip()
            if re.fullmatch(r"[a-zA-Z0-9 +@()_.:/,-]{1,120}", value) is None:
                return None
            values.add(value)
            if len(values) > 8:
                return None
    return sorted(values) or None


def affinity():
    try:
        cpus = sorted(os.sched_getaffinity(0))
    except (OSError, AttributeError):
        return None
    if not cpus or len(cpus) > MAX_CPU or cpus[-1] >= 65536:
        return None
    return cpus


def snapshot(phase, head, tree, run_id, run_attempt, reader=read):
    if phase not in ("before", "after") or any(
            re.fullmatch(r"[0-9a-f]{40}", x) is None for x in (head, tree)):
        raise ValueError("invalid snapshot identity")
    number(run_id, positive=True)
    number(run_attempt, positive=True)
    limits = cgroup(reader)
    local = limits.pop("_local_identity", None)
    limits["same_run_leaf_token"] = None if local is None else hashlib.sha256(
        f"{SCHEMA}:{run_id}:{run_attempt}:{local[0]}:{local[1]}".encode("ascii")
    ).hexdigest()
    return {"schema": SCHEMA, "phase": phase,
            "lineage": {"head": head, "tree": tree, "run_id": run_id,
                        "run_attempt": run_attempt},
            "clock": {"monotonic_ns": time.monotonic_ns()},
            "cpu_models": cpu_model(reader),
            "snapshot_process_affinity": affinity(), "cgroup_v2": limits,
            "qualifies_execution": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("phase", "head", "tree", "run-id", "run-attempt"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = snapshot(args.phase, args.head, args.tree, args.run_id, args.run_attempt)
    data = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    path = args.output_dir / (args.phase + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


if __name__ == "__main__":
    main()
