#!/usr/bin/env python3
"""Validate one current ``probe_fleet.py`` six-host LAN observation.

The 2026-08-13 flat observation is preserved historical material.  It is not a
current readiness gate and is deliberately not opened by this checker.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import tomllib
from collections.abc import Iterable
from typing import NoReturn


CURRENT_SCHEMA_VERSION = 1
CURRENT_PROFILE = "probe-fleet-v1"
EXPECTED_HOST_COUNT = 6
# Linux ``MemTotal`` is a managed-page count, not an immutable DIMM-size fact.
# Keep the fixed x86_64 fleet fingerprint fail-closed while admitting at most
# eight 4 KiB pages of boot/kernel reserved-page accounting drift.
LINUX_X86_64_PAGE_BYTES = 4096
LINUX_X86_64_MEMTOTAL_TOLERANCE_BYTES = 8 * LINUX_X86_64_PAGE_BYTES
HISTORICAL_EVIDENCE_NAMES = {"lan-fleet-probe-2026-08-13.json"}
HISTORICAL_ONLY_ERROR = (
    "the 2026-08-13 flat probe is historical/audit-only; "
    "the current gate requires a fresh probe_fleet.py report"
)
DOCUMENT_KEYS = {
    "schema_version",
    "fleet_id",
    "network_scope",
    "geo_wan_evidence",
    "observed_at_epoch_ns",
    "observations",
    "failures",
}
OBSERVATION_KEYS = {"id", "lan_ip", "management", "round_trip_ns", "facts"}
FACT_KEYS = {
    "hostname",
    "kernel",
    "arch",
    "cpu_threads",
    "memory_bytes",
    "epoch_ns",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PoCO G3 current fleet observation invalid: {message}")


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


def positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive JSON integer")
    return value


def positive_decimal(value: object, field: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        fail(f"{field} must be a canonical positive decimal string")
    parsed = int(value)
    if parsed <= 0 or str(parsed) != value:
        fail(f"{field} must be a canonical positive decimal string")
    return parsed


def positive_inventory_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive TOML integer")
    return value


def nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{field} must be a non-empty string without NUL")
    return value


def is_historical_flat_v1(document: dict[str, object]) -> bool:
    if document.get("schema_version") != CURRENT_SCHEMA_VERSION:
        return False
    if "validator_run_completed" in document:
        return True
    observations = document.get("observations")
    if not isinstance(observations, list):
        return False
    return any(
        isinstance(observation, dict)
        and "facts" not in observation
        and {"arch", "cpu_threads", "memory_bytes"}.issubset(observation)
        for observation in observations
    )


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


def validate(document: dict[str, object], inventory: dict[str, object]) -> dict[str, object]:
    if is_historical_flat_v1(document):
        fail(HISTORICAL_ONLY_ERROR)
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
    positive_integer(document["observed_at_epoch_ns"], "observed_at_epoch_ns")
    if document["failures"] != []:
        fail("current fleet observation contains failures")

    raw_hosts = inventory["hosts"]
    assert isinstance(raw_hosts, list)
    hosts: dict[str, dict[str, object]] = {}
    host_order: list[str] = []
    lan_ips: set[str] = set()
    management_routes: set[str] = set()
    for index, raw_host in enumerate(raw_hosts):
        if not isinstance(raw_host, dict):
            fail(f"inventory hosts[{index}] must be a table")
        host_id = nonempty_string(raw_host.get("id"), f"inventory hosts[{index}].id")
        lan_ip = nonempty_string(raw_host.get("lan_ip"), f"inventory host {host_id}.lan_ip")
        management = nonempty_string(
            raw_host.get("management"), f"inventory host {host_id}.management"
        )
        if host_id in hosts:
            fail("inventory host IDs must be unique")
        if lan_ip in lan_ips:
            fail("inventory LAN addresses must be unique")
        if management in management_routes:
            fail("inventory management routes must be unique")
        hosts[host_id] = raw_host
        host_order.append(host_id)
        lan_ips.add(lan_ip)
        management_routes.add(management)
    if len(hosts) != EXPECTED_HOST_COUNT:
        fail(f"the current LAN profile requires exactly {EXPECTED_HOST_COUNT} hosts")
    if inventory.get("host_count") != len(hosts):
        fail("inventory host_count mismatch")

    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) != len(hosts):
        fail("observations must contain every physical host exactly once")
    observed_order: list[str] = []
    seen: set[str] = set()
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
        if observation["management"] != host.get("management"):
            fail(f"host {host_id} management route mismatch")
        positive_integer(observation["round_trip_ns"], f"host {host_id} round_trip_ns")

        facts = exact_keys(observation["facts"], FACT_KEYS, f"facts[{host_id}]")
        nonempty_string(facts["hostname"], f"host {host_id} hostname")
        kernel = nonempty_string(facts["kernel"], f"host {host_id} kernel")
        expected_kernel = {"linux": "Linux", "macos": "Darwin"}.get(host.get("os"))
        if expected_kernel is None or not kernel.startswith(expected_kernel):
            fail(f"host {host_id} operating system mismatch")
        if facts["arch"] != host.get("arch"):
            fail(f"host {host_id} architecture mismatch")
        if positive_decimal(facts["cpu_threads"], f"host {host_id} cpu_threads") != host.get(
            "cpu_threads"
        ):
            fail(f"host {host_id} CPU thread count mismatch")
        observed_memory = positive_decimal(
            facts["memory_bytes"], f"host {host_id} memory_bytes"
        )
        expected_memory = positive_inventory_integer(
            host.get("memory_bytes"), f"inventory host {host_id} memory_bytes"
        )
        if (host.get("os"), host.get("arch")) == ("linux", "x86_64"):
            if expected_memory % LINUX_X86_64_PAGE_BYTES != 0:
                fail(
                    f"inventory host {host_id} memory_bytes must be "
                    f"{LINUX_X86_64_PAGE_BYTES}-byte aligned"
                )
            memory_delta = observed_memory - expected_memory
            if abs(memory_delta) > LINUX_X86_64_MEMTOTAL_TOLERANCE_BYTES:
                fail(f"host {host_id} memory size mismatch")
            if memory_delta % LINUX_X86_64_PAGE_BYTES != 0:
                fail(
                    f"host {host_id} Linux/x86_64 MemTotal drift must be "
                    f"{LINUX_X86_64_PAGE_BYTES}-byte page aligned"
                )
        elif observed_memory != expected_memory:
            fail(f"host {host_id} memory size mismatch")
        # ``date +%s%N`` is not portable to every BSD date implementation.
        # The current producer therefore owns epoch_ns only as a non-empty raw
        # fact; the stricter run-readiness probe separately gates clock spread.
        nonempty_string(facts["epoch_ns"], f"host {host_id} epoch_ns")

    if observed_order != host_order:
        fail("observations must retain canonical inventory order")
    if seen != set(hosts):
        fail("current fleet observation omits an inventory host")
    return {"host_count": len(hosts)}


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
        "poco_g3_current_fleet_observation=passed "
        f"schema={CURRENT_PROFILE} hosts={report['host_count']} failures=0 "
        "inventory_contract_match=true linux_x86_64_memtotal_match=page-bounded "
        f"linux_x86_64_memtotal_tolerance_bytes={LINUX_X86_64_MEMTOTAL_TOLERANCE_BYTES} "
        f"linux_x86_64_page_bytes={LINUX_X86_64_PAGE_BYTES} macos_memory_match=exact "
        "build=false validator_run=false multihost_run=false "
        "geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
