#!/usr/bin/env python3
"""Pure-Python producer/checker contract tests for ``run-readiness-v2``."""

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
import tomllib
from unittest import mock


sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
CHECKER = HERE / "check_run_readiness_evidence.py"
PROBE = HERE / "probe_run_readiness.py"
INVENTORY = HERE / "inventory.toml"
HISTORICAL_NAME = "lan-run-readiness-2026-08-13.json"


def load_probe():
    spec = importlib.util.spec_from_file_location("poco_run_readiness_contract", PROBE)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load probe_run_readiness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_inventory() -> dict:
    with INVENTORY.open("rb") as source:
        return tomllib.load(source)


def facts_for(host: dict, lan_ips: list[str], epoch: int) -> dict[str, str]:
    macos = host["os"] == "macos"
    facts = {
        "hostname": f"fixture-{host['id']}",
        "os": "Darwin" if macos else "Linux",
        "arch": host["arch"],
        "tmp_free_bytes": str(8 * 1024**3),
        "nofile_soft": "1024",
        "nofile_hard": "4096",
        "python3": "/usr/bin/python3",
        "tar": "/usr/bin/tar",
        "sha256": "/usr/bin/shasum" if macos else "/usr/bin/sha256sum",
        "cargo": "/fixture/bin/cargo",
        "rustc": "/fixture/bin/rustc",
        "sudo_nopass": "ok",
        "network_fault_tool": "/sbin/pfctl" if macos else "/usr/sbin/tc+/usr/sbin/nft",
        "process_inspector": "/usr/sbin/lsof" if macos else "/usr/bin/ss",
        "epoch": str(epoch),
        "poco_listeners": "0",
    }
    facts.update({f"ping_{ip}": "ok" for ip in lan_ips})
    return facts


def produce_current_document() -> dict:
    probe = load_probe()
    inventory = load_inventory()
    hosts = inventory["hosts"]
    lan_ips = [host["lan_ip"] for host in hosts]
    base_epoch = 2_000_000_000
    facts = [facts_for(host, lan_ips, base_epoch + index) for index, host in enumerate(hosts)]
    local_facts = iter(item for host, item in zip(hosts, facts) if host["management"] == "local")
    remote_facts = iter(item for host, item in zip(hosts, facts) if host["management"] != "local")

    def fake_local(_lan_ips: list[str]) -> dict[str, str]:
        return copy.deepcopy(next(local_facts))

    def fake_remote(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        item = next(remote_facts)
        stdout = "".join(f"{key}={value}\n" for key, value in item.items())
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    class FakeTime:
        @staticmethod
        def time() -> float:
            return float(base_epoch + len(hosts))

    probe.local_facts = fake_local
    probe.time = FakeTime
    output = io.StringIO()
    with (
        mock.patch.object(probe.subprocess, "run", side_effect=fake_remote),
        mock.patch.object(sys, "argv", [str(PROBE), "--inventory", str(INVENTORY)]),
        contextlib.redirect_stdout(output),
    ):
        probe.main()
    document = json.loads(output.getvalue())
    if not isinstance(document, dict):
        raise AssertionError("probe_run_readiness.py did not emit a JSON object")
    return document


def run_raw(raw: str, *, name: str = "fixture.json") -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-current-readiness-check-") as directory:
        path = pathlib.Path(directory) / name
        path.write_text(raw, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(path), "--inventory", str(INVENTORY)],
            text=True,
            capture_output=True,
            check=False,
        )


def run(document: dict, *, name: str = "fixture.json") -> subprocess.CompletedProcess[str]:
    return run_raw(json.dumps(document, sort_keys=True), name=name)


def run_historical_path() -> subprocess.CompletedProcess[str]:
    path = pathlib.Path("/nonexistent/poco-audit-only") / HISTORICAL_NAME
    return subprocess.run(
        [sys.executable, str(CHECKER), str(path), "--inventory", str(INVENTORY)],
        text=True,
        capture_output=True,
        check=False,
    )


def mutate(base: dict, change) -> dict:
    document = copy.deepcopy(base)
    change(document)
    return document


def reject(base: dict, change, expected: str) -> None:
    result = run(mutate(base, change))
    if result.returncode == 0 or expected not in result.stderr:
        raise AssertionError(
            f"readiness mutant expected {expected!r}; rc={result.returncode}; "
            f"stderr={result.stderr!r}"
        )


def host(document: dict, host_id: str) -> dict:
    return next(item for item in document["observations"] if item["id"] == host_id)["facts"]


def clear_builders(document: dict, os_name: str) -> None:
    for item in document["observations"]:
        if item["facts"]["os"] == os_name:
            item["facts"]["cargo"] = ""
            item["facts"]["rustc"] = ""


def main() -> None:
    base = produce_current_document()
    positive = run(base)
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

    historical_path = run_historical_path()
    if historical_path.returncode == 0 or "historical/audit-only" not in historical_path.stderr:
        raise AssertionError(historical_path.stderr)

    inventory = load_inventory()
    lan_ips = [item["lan_ip"] for item in inventory["hosts"]]
    controls = (
        (lambda d: d.update(schema_version=1), "schema_version must be 2"),
        (lambda d: d.update(schema_version=True), "schema_version must be 2"),
        (lambda d: d.update(extra="field"), "keys must be exactly"),
        (lambda d: d.update(failures=[{"id": "local", "error": "fault"}]), "contains failures"),
        (lambda d: d.update(validator_run_completed=True), "not a validator run"),
        (lambda d: d.update(geo_wan_evidence=True), "geo_wan_evidence must remain false"),
        (lambda d: host(d, "x230").update(sudo_nopass="fail"), "fault authority"),
        (lambda d: host(d, "desktop").update(network_fault_tool=""), "tc+nft"),
        (lambda d: host(d, "mac").update(network_fault_tool="/usr/sbin/tc"), "pfctl"),
        (lambda d: host(d, "local").update(process_inspector=""), "process inspector"),
        (lambda d: clear_builders(d, "Linux"), "toolchain observation"),
        (lambda d: clear_builders(d, "Darwin"), "toolchain observation"),
        (lambda d: host(d, "j3160").update(poco_listeners="1"), "reserved PoCO listener"),
        (lambda d: host(d, "rog").update(**{f"ping_{lan_ips[-1]}": "fail"}), "LAN reachability"),
        (lambda d: host(d, "local").update(extra="field"), "keys must be exactly"),
        (lambda d: host(d, "local").update(tmp_free_bytes="4.5e9"), "canonical decimal"),
        (lambda d: host(d, "local").update(nofile_soft="0"), "canonical decimal"),
        (lambda d: host(d, "local").update(cargo="", rustc="/fixture/bin/rustc"), "together"),
        (lambda d: d.update(observed_epoch_spread_seconds=True), "JSON integer"),
        (lambda d: d.update(probe_completed_at_epoch=1), "precedes a host observation"),
        (lambda d: d["observations"].reverse(), "canonical inventory order"),
    )
    for change, expected in controls:
        reject(base, change, expected)

    canonical = json.dumps(base, sort_keys=True)
    duplicate = '{"schema_version":2,' + canonical[1:]
    duplicate_result = run_raw(duplicate)
    if duplicate_result.returncode == 0 or "duplicate JSON key" not in duplicate_result.stderr:
        raise AssertionError(duplicate_result.stderr)

    print(
        "poco_g3_current_run_readiness_self_test=passed "
        f"producer_positive=1 negatives={len(controls) + 2} historical_gate=false "
        "build=false validator_run=false multihost_run=false geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
