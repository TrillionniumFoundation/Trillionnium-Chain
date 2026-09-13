#!/usr/bin/env python3
"""Read-only, pre-effect host-capacity gate for PoCO G3 mesh runners."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any


MAX_PROBE_BYTES = 64 * 1024
PROBE_TIMEOUT_SECONDS = 30
PROCESS_FD_RESERVE = 128
COORDINATOR_FD_RESERVE = 128
UID_THREAD_RESERVE = 128
SYSTEM_THREAD_RESERVE = 128
WORKER_STACK_BYTES = 2 * 1024 * 1024
BASE_PROCESS_RSS_BYTES = 64 * 1024 * 1024
GLOBAL_QUEUE_BYTES = 64 * 1024 * 1024
FRAME_SCRATCH_BYTES = 8 * 1024 * 1024
THREADS_PER_CPU_CEILING = 32
HOST_MEMORY_NUMERATOR = 3
HOST_MEMORY_DENOMINATOR = 4
HOST_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
MANAGEMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")

FACT_KEYS = {
    "hostname",
    "os",
    "arch",
    "epoch",
    "cpu_threads",
    "memory_bytes",
    "memory_available_bytes",
    "nofile_soft",
    "nofile_hard",
    "nproc_soft",
    "nproc_hard",
    "threads_max",
    "system_threads",
    "file_nr_allocated",
    "file_nr_max",
    "uid_threads",
}

REMOTE_PROBE = r'''set -eu
printf 'hostname=%s\n' "$(hostname)"
printf 'os=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'epoch=%s\n' "$(date +%s)"
printf 'cpu_threads=%s\n' "$(nproc)"
free -b | awk '/^Mem:/{print "memory_bytes="$2; print "memory_available_bytes="$7}'
printf 'nofile_soft=%s\n' "$(ulimit -Sn)"
printf 'nofile_hard=%s\n' "$(ulimit -Hn)"
printf 'nproc_soft=%s\n' "$(ulimit -Su)"
printf 'nproc_hard=%s\n' "$(ulimit -Hu)"
printf 'threads_max=%s\n' "$(cat /proc/sys/kernel/threads-max)"
printf 'system_threads=%s\n' "$(ps -eL -o lwp= | wc -l | tr -d ' ')"
set -- $(cat /proc/sys/fs/file-nr)
printf 'file_nr_allocated=%s\n' "$1"
printf 'file_nr_max=%s\n' "$3"
printf 'uid_threads=%s\n' "$(ps -u "$(id -u)" -L -o lwp= | wc -l | tr -d ' ')"
'''


def fail(message: str) -> None:
    raise RuntimeError(f"PoCO G3 mesh resource preflight failed: {message}")


def parse_probe(raw: str) -> dict[str, str]:
    if len(raw.encode("utf-8")) > MAX_PROBE_BYTES:
        fail("host probe output exceeds its bound")
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            fail(f"invalid or duplicate host probe line {line!r}")
        result[key] = value
    if set(result) != FACT_KEYS:
        fail("host probe keys differ from the exact contract")
    return result


def probe_host(management: str) -> dict[str, str]:
    if management != "local" and (
        MANAGEMENT.fullmatch(management) is None or management.startswith("-")
    ):
        fail("management route is unsafe")
    arguments = (
        ["bash", "-c", REMOTE_PROBE]
        if management == "local"
        else [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={PROBE_TIMEOUT_SECONDS}",
            management,
            "bash -s",
        ]
    )
    try:
        completed = subprocess.run(
            arguments,
            input=None if management == "local" else REMOTE_PROBE,
            capture_output=True,
            text=True,
            check=False,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"capacity probe for {management} did not complete: {error}")
    if completed.returncode != 0:
        fail(
            f"capacity probe for {management} exited {completed.returncode}: "
            f"{completed.stderr.strip()[:256]}"
        )
    if completed.stderr:
        fail(f"capacity probe for {management} emitted stderr")
    return parse_probe(completed.stdout)


def positive_int(value: object, field: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        fail(f"{field} must be one positive decimal integer")
    parsed = int(value)
    if parsed <= 0:
        fail(f"{field} must be positive")
    return parsed


def finite_limit(value: object, field: str) -> int | None:
    if value == "unlimited":
        return None
    return positive_int(value, field)


def _limit_passes(required: int, limit: int | None) -> bool:
    return limit is None or required <= limit


def evaluate_mesh_fleet_resources_v1(
    processes: Sequence[Any],
    validator_count: int,
    facts_by_host: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    if isinstance(validator_count, bool) or validator_count not in {7, 31, 100}:
        fail("validator count is outside the frozen topology")
    if len(processes) != validator_count:
        fail("validator process inventory cardinality differs")
    host_inventory: dict[str, dict[str, Any]] = {}
    validator_ids: set[str] = set()
    for process in processes:
        host_id = getattr(process, "host_id", None)
        management = getattr(process, "management", None)
        validator_id = getattr(process, "validator_id", None)
        if (
            not isinstance(host_id, str)
            or HOST_ID.fullmatch(host_id) is None
            or not isinstance(management, str)
            or not isinstance(validator_id, str)
            or validator_id in validator_ids
        ):
            fail("validator process inventory is invalid or duplicated")
        validator_ids.add(validator_id)
        host = host_inventory.setdefault(
            host_id, {"management": management, "validator_processes": 0}
        )
        if host["management"] != management:
            fail("one validator host has conflicting management routes")
        host["validator_processes"] += 1
    if set(facts_by_host) != set(host_inventory):
        fail("capacity observations differ from the validator host inventory")
    if sum(item["management"] == "local" for item in host_inventory.values()) != 1:
        fail("capacity preflight requires one exact local coordinator host")

    peer_degree = 6 if validator_count == 7 else 8
    per_validator_threads = peer_degree * 2 + 1
    per_validator_socket_fds = peer_degree * 4 + 2
    per_validator_open_file_fds = per_validator_socket_fds + PROCESS_FD_RESERVE
    per_validator_rss_bytes = (
        BASE_PROCESS_RSS_BYTES
        + GLOBAL_QUEUE_BYTES
        + per_validator_threads * WORKER_STACK_BYTES
        + peer_degree * 2 * FRAME_SCRATCH_BYTES
    )
    coordinator_capture_fds = validator_count * 2 + COORDINATOR_FD_RESERVE
    observations: list[dict[str, Any]] = []
    epochs: list[int] = []
    for host_id, inventory in host_inventory.items():
        facts = facts_by_host[host_id]
        if set(facts) != FACT_KEYS:
            fail(f"host {host_id} facts differ from the exact contract")
        if facts["os"] != "Linux" or facts["arch"] != "x86_64":
            fail(f"host {host_id} is not one Linux/x86_64 validator host")
        epoch = positive_int(facts["epoch"], f"{host_id}.epoch")
        cpu_threads = positive_int(facts["cpu_threads"], f"{host_id}.cpu_threads")
        memory_bytes = positive_int(facts["memory_bytes"], f"{host_id}.memory_bytes")
        memory_available = positive_int(
            facts["memory_available_bytes"], f"{host_id}.memory_available_bytes"
        )
        if memory_available > memory_bytes:
            fail(f"host {host_id} available memory exceeds total memory")
        nofile_soft = finite_limit(facts["nofile_soft"], f"{host_id}.nofile_soft")
        nofile_hard = finite_limit(facts["nofile_hard"], f"{host_id}.nofile_hard")
        nproc_soft = finite_limit(facts["nproc_soft"], f"{host_id}.nproc_soft")
        nproc_hard = finite_limit(facts["nproc_hard"], f"{host_id}.nproc_hard")
        if (
            nofile_soft is not None
            and nofile_hard is not None
            and nofile_soft > nofile_hard
        ) or (
            nproc_soft is not None
            and nproc_hard is not None
            and nproc_soft > nproc_hard
        ):
            fail(f"host {host_id} soft resource limit exceeds its hard limit")
        threads_max = positive_int(facts["threads_max"], f"{host_id}.threads_max")
        system_threads = positive_int(
            facts["system_threads"], f"{host_id}.system_threads"
        )
        uid_threads = positive_int(facts["uid_threads"], f"{host_id}.uid_threads")
        file_allocated = positive_int(
            facts["file_nr_allocated"], f"{host_id}.file_nr_allocated"
        )
        file_max = positive_int(facts["file_nr_max"], f"{host_id}.file_nr_max")
        if file_allocated >= file_max:
            fail(f"host {host_id} has no authoritative system file-handle capacity")

        validator_processes = inventory["validator_processes"]
        host_threads = per_validator_threads * validator_processes
        host_open_file_fds = per_validator_open_file_fds * validator_processes
        host_rss_bytes = per_validator_rss_bytes * validator_processes
        maximum_host_threads = cpu_threads * THREADS_PER_CPU_CEILING
        usable_memory = memory_bytes * HOST_MEMORY_NUMERATOR // HOST_MEMORY_DENOMINATOR
        coordinator_fds = (
            coordinator_capture_fds if inventory["management"] == "local" else 0
        )
        system_file_required = host_open_file_fds + coordinator_fds
        system_file_available = file_max - file_allocated
        uid_thread_required = uid_threads + host_threads + UID_THREAD_RESERVE
        system_thread_required = system_threads + host_threads + SYSTEM_THREAD_RESERVE
        if not _limit_passes(per_validator_open_file_fds, nofile_soft):
            fail(f"host {host_id} per-validator open files exceed RLIMIT_NOFILE")
        if coordinator_fds and not _limit_passes(coordinator_fds, nofile_soft):
            fail(f"host {host_id} coordinator capture files exceed RLIMIT_NOFILE")
        if not _limit_passes(uid_thread_required, nproc_soft):
            fail(f"host {host_id} validator threads exceed the UID process/thread limit")
        if system_thread_required > threads_max:
            fail(f"host {host_id} validator threads exceed system thread capacity")
        if host_threads > maximum_host_threads:
            fail(f"host {host_id} placement exceeds the CPU-thread ceiling")
        if system_file_required > system_file_available:
            fail(f"host {host_id} placement exceeds system file-handle capacity")
        if host_rss_bytes > usable_memory or host_rss_bytes > memory_available:
            fail(f"host {host_id} placement exceeds RSS capacity")
        epochs.append(epoch)
        observations.append(
            {
                "host_id": host_id,
                "management": inventory["management"],
                "hostname": facts["hostname"],
                "validator_processes": validator_processes,
                "cpu_threads": cpu_threads,
                "memory_bytes": memory_bytes,
                "memory_available_bytes": memory_available,
                "per_process_nofile_soft": facts["nofile_soft"],
                "per_process_nofile_hard": facts["nofile_hard"],
                "uid_nproc_soft": facts["nproc_soft"],
                "uid_nproc_hard": facts["nproc_hard"],
                "uid_threads_observed": uid_threads,
                "system_threads_observed": system_threads,
                "system_threads_max": threads_max,
                "system_file_handles_allocated": file_allocated,
                "system_file_handles_max": file_max,
                "system_file_handles_available": system_file_available,
                "host_threads_required": host_threads,
                "host_open_file_fds_required": host_open_file_fds,
                "coordinator_capture_fds_required": coordinator_fds,
                "host_rss_bytes_required": host_rss_bytes,
                "capacity_passed": True,
            }
        )
    spread = max(epochs) - min(epochs)
    if spread > 30:
        fail("capacity observation epoch spread exceeds 30 seconds")
    return {
        "schema_version": 1,
        "profile": "poco-g3-mesh-host-resource-preflight-v1",
        "validator_count": validator_count,
        "peer_degree": peer_degree,
        "per_validator_threads": per_validator_threads,
        "per_validator_socket_fds": per_validator_socket_fds,
        "per_validator_open_file_fds": per_validator_open_file_fds,
        "per_validator_rss_bytes": per_validator_rss_bytes,
        "coordinator_capture_fds": coordinator_capture_fds,
        "observed_epoch_spread_seconds": spread,
        "hosts": observations,
        "capacity_passed": True,
        "validator_run_completed": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def preflight_mesh_fleet_resources_v1(
    processes: Sequence[Any], validator_count: int
) -> dict[str, Any]:
    host_routes: dict[str, str] = {}
    for process in processes:
        host_id = getattr(process, "host_id", None)
        management = getattr(process, "management", None)
        if not isinstance(host_id, str) or not isinstance(management, str):
            fail("validator process lacks host identity")
        previous = host_routes.setdefault(host_id, management)
        if previous != management:
            fail("one validator host has conflicting management routes")
    facts = {host_id: probe_host(route) for host_id, route in host_routes.items()}
    return evaluate_mesh_fleet_resources_v1(processes, validator_count, facts)
