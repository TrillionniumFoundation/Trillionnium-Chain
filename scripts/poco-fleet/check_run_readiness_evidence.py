#!/usr/bin/env python3
"""Validate one current, read-only six-host run-readiness observation."""

from __future__ import annotations

import argparse
import json
import pathlib
import tomllib
from collections.abc import Iterable
from typing import NoReturn


CURRENT_SCHEMA_VERSION = 2
CURRENT_PROFILE = "run-readiness-v2"
EXPECTED_HOST_COUNT = 6
HISTORICAL_EVIDENCE_NAMES = {"lan-run-readiness-2026-08-13.json"}
HISTORICAL_ONLY_ERROR = (
    "the 2026-08-13 readiness JSON is historical/audit-only; "
    "the current gate requires a fresh probe_run_readiness.py report"
)
MIN_TMP_FREE_BYTES = 4 * 1024**3
MAX_CLOCK_SPREAD_SECONDS = 30
DOCUMENT_KEYS = {
    "schema_version",
    "fleet_id",
    "network_scope",
    "geo_wan_evidence",
    "validator_run_completed",
    "probe_completed_at_epoch",
    "observed_epoch_spread_seconds",
    "observations",
    "failures",
}
OBSERVATION_KEYS = {"id", "lan_ip", "facts"}
BASE_FACT_KEYS = {
    "hostname",
    "os",
    "arch",
    "tmp_free_bytes",
    "nofile_soft",
    "nofile_hard",
    "python3",
    "tar",
    "sha256",
    "cargo",
    "rustc",
    "sudo_nopass",
    "network_fault_tool",
    "process_inspector",
    "epoch",
    "poco_listeners",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PoCO G3 current run-readiness observation invalid: {message}")


def duplicate_rejecting_object(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def read_document(path: pathlib.Path) -> dict[str, object]:
    if path.name in HISTORICAL_EVIDENCE_NAMES:
        fail(HISTORICAL_ONLY_ERROR)
    try:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw, object_pairs_hook=duplicate_rejecting_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read canonical JSON: {error}")
    if not isinstance(document, dict):
        fail("document must be a JSON object")
    return document


def exact_keys(value: object, expected: set[str], field: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{field} keys must be exactly {sorted(expected)!r}")
    return value


def nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{field} must be a non-empty string without NUL")
    return value


def integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{field} must be a JSON integer >= {minimum}")
    return value


def decimal(value: object, field: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        fail(f"{field} must be a canonical decimal string")
    parsed = int(value)
    if parsed < minimum or str(parsed) != value:
        fail(f"{field} must be a canonical decimal string >= {minimum}")
    return parsed


def nofile_limit(value: object, field: str) -> None:
    if value == "unlimited":
        return
    decimal(value, field, minimum=1)


def load_inventory(path: pathlib.Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            inventory = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read inventory: {error}")
    if not isinstance(inventory, dict):
        fail("inventory must be a TOML table")
    hosts = inventory.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        fail("inventory hosts must be a non-empty array")
    return inventory


def validate(document: dict[str, object], inventory: dict[str, object]) -> dict[str, int]:
    exact_keys(document, DOCUMENT_KEYS, "document")
    if (
        isinstance(document["schema_version"], bool)
        or document["schema_version"] != CURRENT_SCHEMA_VERSION
    ):
        fail(f"schema_version must be {CURRENT_SCHEMA_VERSION} for {CURRENT_PROFILE}")
    if isinstance(inventory.get("schema_version"), bool) or inventory.get("schema_version") != 1:
        fail("inventory schema_version must be 1")
    fleet_id = nonempty_string(inventory.get("fleet_id"), "inventory fleet_id")
    if document["fleet_id"] != fleet_id:
        fail("fleet_id mismatch")
    if inventory.get("network_scope") != "single-lan":
        fail("inventory network_scope must be single-lan")
    if document["network_scope"] != "single-lan":
        fail("network_scope must be single-lan")
    if inventory.get("geo_wan_evidence") is not False:
        fail("inventory geo_wan_evidence must remain false")
    if document["geo_wan_evidence"] is not False:
        fail("geo_wan_evidence must remain false")
    if document["validator_run_completed"] is not False:
        fail("readiness observation is not a validator run")
    if document["failures"] != []:
        fail("current readiness observation contains failures")

    raw_hosts = inventory["hosts"]
    assert isinstance(raw_hosts, list)
    hosts: dict[str, dict[str, object]] = {}
    host_order: list[str] = []
    lan_ips: list[str] = []
    for index, raw_host in enumerate(raw_hosts):
        if not isinstance(raw_host, dict):
            fail(f"inventory hosts[{index}] must be a table")
        host_id = nonempty_string(raw_host.get("id"), f"inventory hosts[{index}].id")
        lan_ip = nonempty_string(raw_host.get("lan_ip"), f"inventory host {host_id}.lan_ip")
        if host_id in hosts:
            fail("inventory host IDs must be unique")
        if lan_ip in lan_ips:
            fail("inventory LAN addresses must be unique")
        hosts[host_id] = raw_host
        host_order.append(host_id)
        lan_ips.append(lan_ip)
    if len(hosts) != EXPECTED_HOST_COUNT:
        fail(f"the current LAN profile requires exactly {EXPECTED_HOST_COUNT} hosts")
    if inventory.get("host_count") != len(hosts):
        fail("inventory host_count mismatch")

    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) != len(hosts):
        fail("observations must contain every physical host exactly once")
    seen: set[str] = set()
    observed_order: list[str] = []
    epochs: list[int] = []
    build_arches: set[tuple[str, str]] = set()
    expected_fact_keys = BASE_FACT_KEYS | {f"ping_{ip}" for ip in lan_ips}
    for index, raw_observation in enumerate(observations):
        observation = exact_keys(raw_observation, OBSERVATION_KEYS, f"observations[{index}]")
        host_id = nonempty_string(observation["id"], f"observations[{index}].id")
        if host_id not in hosts or host_id in seen:
            fail("observation host IDs must be unique inventory members")
        seen.add(host_id)
        observed_order.append(host_id)
        host = hosts[host_id]
        if observation["lan_ip"] != host.get("lan_ip"):
            fail(f"host {host_id} LAN address mismatch")
        facts = exact_keys(observation["facts"], expected_fact_keys, f"facts[{host_id}]")
        for key, value in facts.items():
            if not isinstance(value, str) or "\x00" in value:
                fail(f"host {host_id} fact {key} must be a string without NUL")
        nonempty_string(facts["hostname"], f"host {host_id} hostname")
        expected_os = {"linux": "Linux", "macos": "Darwin"}.get(host.get("os"))
        if expected_os is None or facts["os"] != expected_os:
            fail(f"host {host_id} OS mismatch")
        if facts["arch"] != host.get("arch"):
            fail(f"host {host_id} architecture mismatch")
        if decimal(facts["tmp_free_bytes"], f"host {host_id} tmp_free_bytes") < MIN_TMP_FREE_BYTES:
            fail(f"host {host_id} has less than 4 GiB temporary space")
        nofile_limit(facts["nofile_soft"], f"host {host_id} nofile_soft")
        nofile_limit(facts["nofile_hard"], f"host {host_id} nofile_hard")
        for tool in ("python3", "tar", "sha256"):
            nonempty_string(facts[tool], f"host {host_id} {tool}")
        if facts["sudo_nopass"] != "ok":
            fail(f"host {host_id} lacks non-interactive bounded fault authority")
        expected_fault = "pfctl" if host.get("os") == "macos" else "tc+nft"
        if host.get("os") == "macos":
            valid_fault_tool = pathlib.Path(facts["network_fault_tool"]).name == "pfctl"
        else:
            parts = facts["network_fault_tool"].split("+")
            valid_fault_tool = len(parts) == 2 and [pathlib.Path(part).name for part in parts] == [
                "tc",
                "nft",
            ]
        if not valid_fault_tool:
            fail(f"host {host_id} lacks the declared {expected_fault} fault tool")
        if pathlib.Path(facts["process_inspector"]).name not in {"ss", "lsof"}:
            fail(f"host {host_id} lacks a supported process inspector")
        if facts["poco_listeners"] != "0":
            fail(f"host {host_id} already had a reserved PoCO listener")
        if any(facts[f"ping_{ip}"] != "ok" for ip in lan_ips):
            fail(f"host {host_id} lacks full LAN reachability")
        epoch = decimal(facts["epoch"], f"host {host_id} epoch", minimum=1)
        epochs.append(epoch)
        cargo = facts["cargo"]
        rustc = facts["rustc"]
        if bool(cargo) != bool(rustc):
            fail(f"host {host_id} must observe cargo and rustc together")
        if cargo:
            if pathlib.Path(cargo).name != "cargo" or pathlib.Path(rustc).name != "rustc":
                fail(f"host {host_id} reported invalid Rust tool paths")
            build_arches.add((facts["os"], facts["arch"]))

    if observed_order != host_order:
        fail("observations must retain canonical inventory order")
    if seen != set(hosts):
        fail("current readiness observation omits an inventory host")
    spread = max(epochs) - min(epochs)
    claimed_spread = integer(
        document["observed_epoch_spread_seconds"],
        "observed_epoch_spread_seconds",
    )
    if claimed_spread != spread or spread > MAX_CLOCK_SPREAD_SECONDS:
        fail("readiness epoch spread is inconsistent or exceeds 30 seconds")
    completed = integer(document["probe_completed_at_epoch"], "probe_completed_at_epoch", minimum=1)
    if completed < max(epochs):
        fail("probe completion epoch precedes a host observation")
    expected_build_arches = {
        ({"linux": "Linux", "macos": "Darwin"}[str(host["os"])], str(host["arch"]))
        for host in hosts.values()
    }
    if build_arches != expected_build_arches:
        fail("native toolchain observation does not cover every OS/architecture")
    return {"host_count": len(hosts), "epoch_spread_seconds": spread}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument(
        "--inventory",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("inventory.toml"),
    )
    args = parser.parse_args()
    inventory = load_inventory(args.inventory)
    report = validate(read_document(args.evidence), inventory)
    print(
        "poco_g3_current_run_readiness=passed "
        f"schema={CURRENT_PROFILE} hosts={report['host_count']} failures=0 "
        "fault_tools_observed=true native_toolchains_observed=true "
        f"epoch_spread_seconds={report['epoch_spread_seconds']} "
        "build=false validator_run=false multihost_run=false geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
