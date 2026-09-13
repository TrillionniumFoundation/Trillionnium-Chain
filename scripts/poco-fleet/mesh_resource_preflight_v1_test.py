#!/usr/bin/env python3
"""Static positive/negative controls for the pre-effect mesh resource gate."""

from __future__ import annotations

import copy
import dataclasses
import pathlib
import re
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import mesh_resource_preflight_v1 as preflight  # noqa: E402


@dataclasses.dataclass(frozen=True)
class Process:
    validator_id: str
    host_id: str
    management: str


PLACEMENT = {"local": 20, "x230": 3, "desktop": 36, "rog": 38, "j3160": 3}
ROUTES = {
    "local": "local",
    "x230": "p4-x230",
    "desktop": "p4-desktop",
    "rog": "p4-rog",
    "j3160": "p4-j3160",
}
CPUS = {"local": 24, "x230": 4, "desktop": 48, "rog": 32, "j3160": 4}
MEMORY = {
    "local": 24_781_164_544,
    "x230": 8_012_709_888,
    "desktop": 134_923_124_736,
    "rog": 130_456_432_640,
    "j3160": 4_008_587_264,
}


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except RuntimeError as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def processes() -> list[Process]:
    values: list[Process] = []
    index = 0
    for host_id, count in PLACEMENT.items():
        for _ in range(count):
            values.append(Process(f"{index + 1:064x}", host_id, ROUTES[host_id]))
            index += 1
    return values


def facts() -> dict[str, dict[str, str]]:
    return {
        host_id: {
            "hostname": f"host-{host_id}",
            "os": "Linux",
            "arch": "x86_64",
            "epoch": str(1_786_707_200 + index),
            "cpu_threads": str(CPUS[host_id]),
            "memory_bytes": str(MEMORY[host_id]),
            "memory_available_bytes": str(MEMORY[host_id] * 7 // 8),
            "nofile_soft": "1024",
            "nofile_hard": "1048576",
            "nproc_soft": "100000",
            "nproc_hard": "100000",
            "threads_max": "200000",
            "system_threads": "1000",
            "file_nr_allocated": "1000",
            "file_nr_max": "1000000",
            "uid_threads": "500",
        }
        for index, host_id in enumerate(PLACEMENT)
    }


def assert_runner_pre_effect_order(path: pathlib.Path) -> None:
    source = path.read_text(encoding="utf-8")
    probe = "mesh_resources.preflight_mesh_fleet_resources_v1("
    output_effect = "output.mkdir("
    deployment_effect = "base.create_stages("
    assert source.count(probe) == 1
    assert source.count(output_effect) == 1
    assert source.count(deployment_effect) == 1
    assert source.index(probe) < source.index(output_effect) < source.index(
        deployment_effect
    )
    if path.name == "run_consensus_fleet.py":
        independent_anchor = "anchor_snapshot = checked_coordinator_anchor("
        assert source.count(independent_anchor) == 1
        assert '"--coordinator-manifest-sha256"' in source
        assert source.index(independent_anchor) < source.index(probe)
        assert source.index(independent_anchor) < source.index(output_effect)
        assert source.index(independent_anchor) < source.index(deployment_effect)


def main() -> None:
    validators = processes()
    host_facts = facts()
    report = preflight.evaluate_mesh_fleet_resources_v1(validators, 100, host_facts)
    assert report["capacity_passed"] is True
    assert report["per_validator_threads"] == 17
    assert report["per_validator_socket_fds"] == 34
    assert report["per_validator_open_file_fds"] == 162
    assert report["per_validator_rss_bytes"] == 290 * 1024 * 1024
    assert report["coordinator_capture_fds"] == 328
    by_host = {item["host_id"]: item for item in report["hosts"]}
    assert by_host["desktop"]["host_open_file_fds_required"] == 5_832
    assert by_host["rog"]["host_open_file_fds_required"] == 6_156
    assert by_host["rog"]["per_process_nofile_soft"] == "1024"
    assert by_host["local"]["coordinator_capture_fds_required"] == 328
    assert by_host["x230"]["coordinator_capture_fds_required"] == 0
    assert report["validator_run_completed"] is False
    assert report["g3_lan_multihost_evidence"] is False

    parsed = preflight.parse_probe(
        "\n".join(f"{key}={value}" for key, value in host_facts["local"].items())
        + "\n"
    )
    assert parsed == host_facts["local"]

    assert_runner_pre_effect_order(HERE / "run_consensus_fleet.py")
    assert_runner_pre_effect_order(HERE / "run_fault_restart_fleet_v1.py")
    probe_source = (HERE / "mesh_resource_preflight_v1.py").read_text(
        encoding="utf-8"
    )
    assert '["bash", "-c", REMOTE_PROBE]' in probe_source
    assert '["bash", "-lc", REMOTE_PROBE]' not in probe_source
    launch_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            HERE / "mesh_resource_preflight_v1.py",
            HERE / "run_consensus_fleet.py",
            HERE / "run_fault_restart_fleet_v1.py",
        )
    )
    assert re.search(r"ulimit\s+-[SH]?[nu]\s+[^)'\"\s]", launch_sources) is None

    low_nofile = copy.deepcopy(host_facts)
    low_nofile["rog"]["nofile_soft"] = "161"
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_nofile
        ),
        "per-validator open files",
    )

    low_coordinator_nofile = copy.deepcopy(host_facts)
    low_coordinator_nofile["local"]["nofile_soft"] = "327"
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_coordinator_nofile
        ),
        "coordinator capture files",
    )

    low_system_files = copy.deepcopy(host_facts)
    low_system_files["rog"]["file_nr_max"] = str(1000 + 6_155)
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_system_files
        ),
        "system file-handle",
    )

    low_nproc = copy.deepcopy(host_facts)
    low_nproc["rog"]["nproc_soft"] = "1200"
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_nproc
        ),
        "UID process/thread",
    )

    low_threads = copy.deepcopy(host_facts)
    low_threads["rog"]["threads_max"] = "1600"
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_threads
        ),
        "system thread capacity",
    )

    low_memory = copy.deepcopy(host_facts)
    low_memory["j3160"]["memory_available_bytes"] = str(869 * 1024 * 1024)
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(
            validators, 100, low_memory
        ),
        "RSS capacity",
    )

    stale = copy.deepcopy(host_facts)
    stale["j3160"]["epoch"] = str(1_786_707_300)
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(validators, 100, stale),
        "epoch spread",
    )

    missing = copy.deepcopy(host_facts)
    del missing["rog"]["uid_threads"]
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(validators, 100, missing),
        "facts differ",
    )
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(validators[:-1], 100, host_facts),
        "cardinality",
    )
    expect_failure(
        lambda: preflight.evaluate_mesh_fleet_resources_v1(validators, 31, host_facts),
        "cardinality",
    )
    expect_failure(
        lambda: preflight.parse_probe("hostname=a\nhostname=b\n"),
        "duplicate",
    )

    print(
        "poco_g3_mesh_resource_preflight_v1_test=passed positives=18 negatives=11 "
        "topology=100 per_process_rlimit=distinct host_file_capacity=system-wide "
        "uid_threads=bounded system_threads=bounded rss=bounded "
        "coordinator_capture_fds=per-process-bounded inherited_rlimit=true "
        "pre_effect_runners=consensus,fault "
        "ulimit_elevation=false validator_run=false g3_complete=false"
    )


if __name__ == "__main__":
    main()
