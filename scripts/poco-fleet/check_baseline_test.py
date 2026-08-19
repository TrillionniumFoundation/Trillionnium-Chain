#!/usr/bin/env python3
"""Pure-Python producer/checker contract tests for ``probe-fleet-v1``."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock


sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
CHECKER = HERE / "check_baseline.py"
PROBE = HERE / "probe_fleet.py"
HISTORICAL_NAME = "lan-fleet-probe-2026-08-13.json"
HOST_COUNT = 6
CPU_THREADS = 8
MEMORY_BYTES = 16 * 1024**3


def load_probe():
    spec = importlib.util.spec_from_file_location("poco_probe_fleet_contract", PROBE)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load probe_fleet.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_inventory(path: pathlib.Path) -> None:
    lines = [
        'schema_version = 1',
        'fleet_id = "fixture-six-host-current-probe"',
        'network_scope = "single-lan"',
        'geo_wan_evidence = false',
        f"host_count = {HOST_COUNT}",
        "",
    ]
    for index in range(HOST_COUNT):
        management = "local" if index == 0 else f"fixture-ssh-{index}"
        lines.extend(
            [
                "[[hosts]]",
                f'id = "host-{index}"',
                f'management = "{management}"',
                f'lan_ip = "10.23.0.{index + 1}"',
                'os = "linux"',
                'arch = "x86_64"',
                f"cpu_threads = {CPU_THREADS}",
                f"memory_bytes = {MEMORY_BYTES}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def current_facts() -> dict[str, str]:
    return {
        "hostname": "fixture-host",
        "kernel": "Linux fixture-kernel x86_64",
        "arch": "x86_64",
        "cpu_threads": str(CPU_THREADS),
        "memory_bytes": str(MEMORY_BYTES),
        "epoch_ns": "fixture-raw-epoch-ns",
    }


def produce_current_document(inventory: pathlib.Path) -> dict:
    probe = load_probe()
    monotonic_values = iter(range(1_000, 1_000 + HOST_COUNT * 2))

    class FakeTime:
        @staticmethod
        def monotonic_ns() -> int:
            return next(monotonic_values)

        @staticmethod
        def time_ns() -> int:
            return 2_000

    def fake_remote(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        stdout = "".join(f"{key}={value}\n" for key, value in current_facts().items())
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    probe.time = FakeTime
    probe.local_probe = current_facts
    output = io.StringIO()
    with (
        mock.patch.object(probe.subprocess, "run", side_effect=fake_remote),
        mock.patch.object(sys, "argv", [str(PROBE), "--inventory", str(inventory)]),
        contextlib.redirect_stdout(output),
    ):
        probe.main()
    document = json.loads(output.getvalue())
    if not isinstance(document, dict):
        raise AssertionError("probe_fleet.py did not emit a JSON object")
    return document


def run_raw(
    raw: str,
    inventory: pathlib.Path,
    *,
    name: str = "fixture.json",
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-current-probe-check-") as directory:
        evidence = pathlib.Path(directory) / name
        evidence.write_text(raw, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(evidence),
                "--inventory",
                str(inventory),
            ],
            text=True,
            capture_output=True,
            check=False,
        )


def run(
    document: dict,
    inventory: pathlib.Path,
    *,
    name: str = "fixture.json",
) -> subprocess.CompletedProcess[str]:
    return run_raw(json.dumps(document, sort_keys=True), inventory, name=name)


def run_historical_path(inventory: pathlib.Path) -> subprocess.CompletedProcess[str]:
    path = pathlib.Path("/nonexistent/poco-audit-only") / HISTORICAL_NAME
    return subprocess.run(
        [sys.executable, str(CHECKER), str(path), "--inventory", str(inventory)],
        text=True,
        capture_output=True,
        check=False,
    )


def mutate(base: dict, change) -> dict:
    document = copy.deepcopy(base)
    change(document)
    return document


def reject(base: dict, inventory: pathlib.Path, change, expected: str) -> None:
    result = run(mutate(base, change), inventory)
    if result.returncode == 0 or expected not in result.stderr:
        raise AssertionError(
            f"fleet observation mutant expected {expected!r}; rc={result.returncode}; "
            f"stderr={result.stderr!r}"
        )


def observation(document: dict, host_id: str) -> dict:
    return next(item for item in document["observations"] if item["id"] == host_id)


def legacy_flat(document: dict) -> None:
    document.pop("observed_at_epoch_ns")
    document["validator_run_completed"] = False
    for item in document["observations"]:
        facts = item.pop("facts")
        item.pop("management")
        item.pop("round_trip_ns")
        item.update(facts)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-current-probe-contract-") as directory:
        inventory = pathlib.Path(directory) / "inventory.toml"
        write_inventory(inventory)
        base = produce_current_document(inventory)
        positive = run(base, inventory)
        if positive.returncode != 0:
            raise AssertionError(positive.stderr)
        false_claims = (
            "build=false",
            "validator_run=false",
            "multihost_run=false",
            "geo_wan=false",
            "production=false",
        )
        if any(claim not in positive.stdout for claim in false_claims):
            raise AssertionError(f"missing fail-closed claim boundary: {positive.stdout!r}")

        historical_path = run_historical_path(inventory)
        if historical_path.returncode == 0 or "historical/audit-only" not in historical_path.stderr:
            raise AssertionError(historical_path.stderr)

        controls = (
            (lambda d: d.update(schema_version=2), "schema_version must be 1"),
            (lambda d: d.update(schema_version=True), "schema_version must be 1"),
            (lambda d: d.update(extra="field"), "keys must be exactly"),
            (legacy_flat, "historical/audit-only"),
            (lambda d: d.update(network_scope="geo-wan"), "network_scope must be single-lan"),
            (lambda d: d.update(geo_wan_evidence=True), "geo_wan_evidence must remain false"),
            (
                lambda d: d.update(failures=[{"id": "host-0", "error": "fault"}]),
                "contains failures",
            ),
            (
                lambda d: observation(d, "host-0").update(management="other"),
                "management route mismatch",
            ),
            (
                lambda d: observation(d, "host-0").update(round_trip_ns=True),
                "positive JSON integer",
            ),
            (
                lambda d: observation(d, "host-0")["facts"].update(extra="field"),
                "keys must be exactly",
            ),
            (
                lambda d: observation(d, "host-0")["facts"].update(
                    kernel="Darwin fixture"
                ),
                "operating system mismatch",
            ),
            (
                lambda d: observation(d, "host-0")["facts"].update(arch="arm64"),
                "architecture mismatch",
            ),
            (
                lambda d: observation(d, "host-0")["facts"].update(cpu_threads="7"),
                "CPU thread count mismatch",
            ),
            (
                lambda d: observation(d, "host-0")["facts"].update(memory_bytes="1"),
                "memory size mismatch",
            ),
            (lambda d: observation(d, "host-0")["facts"].update(epoch_ns=""), "non-empty string"),
            (lambda d: observation(d, "host-1").update(id="host-0"), "unique inventory members"),
            (lambda d: d["observations"].reverse(), "canonical inventory order"),
        )
        for change, expected in controls:
            reject(base, inventory, change, expected)

        canonical = json.dumps(base, sort_keys=True)
        duplicate = '{"schema_version":1,' + canonical[1:]
        duplicate_result = run_raw(duplicate, inventory)
        if duplicate_result.returncode == 0 or "duplicate JSON key" not in duplicate_result.stderr:
            raise AssertionError(duplicate_result.stderr)

    print(
        "poco_g3_current_fleet_observation_self_test=passed "
        f"producer_positive=1 negatives={len(controls) + 2} historical_gate=false "
        "build=false validator_run=false multihost_run=false geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
