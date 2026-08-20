#!/usr/bin/env python3
"""Fail-closed validation for the bounded six-host PoCO LAN inventory."""

from __future__ import annotations

import argparse
import ipaddress
import pathlib
import tomllib


EXPECTED_TOPOLOGIES = {
    "seven": 7,
    "thirty_one": 31,
    "one_hundred": 100,
}
LINUX_X86_64_PAGE_BYTES = 4096


def fail(message: str) -> None:
    raise SystemExit(f"fleet inventory invalid: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "inventory",
        nargs="?",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("inventory.toml"),
    )
    args = parser.parse_args()
    with args.inventory.open("rb") as source:
        document = tomllib.load(source)

    if document.get("schema_version") != 1:
        fail("schema_version must be 1")
    if document.get("network_scope") != "single-lan":
        fail("network_scope must remain single-lan")
    if document.get("geo_wan_evidence") is not False:
        fail("geo_wan_evidence must remain false for this inventory")
    network = ipaddress.ip_network(document.get("lan_cidr", ""), strict=True)
    hosts = document.get("hosts")
    if not isinstance(hosts, list) or len(hosts) != document.get("host_count") or len(hosts) != 6:
        fail("exactly six hosts are required")
    if document.get("validator_host_count") != 5 or document.get("observer_host_count") != 1:
        fail("the fleet must contain exactly five validator hosts and one observer host")

    ids: set[str] = set()
    management: set[str] = set()
    addresses: set[ipaddress._BaseAddress] = set()
    architecture_pairs: set[tuple[str, str]] = set()
    topology_totals = {key: 0 for key in EXPECTED_TOPOLOGIES}
    validator_hosts = 0
    observer_hosts = 0
    for host in hosts:
        host_id = host.get("id")
        route = host.get("management")
        if not isinstance(host_id, str) or not host_id or host_id in ids:
            fail("host ids must be unique non-empty strings")
        if not isinstance(route, str) or not route or route in management:
            fail("management routes must be unique non-empty strings")
        ids.add(host_id)
        management.add(route)
        address = ipaddress.ip_address(host.get("lan_ip", ""))
        if address not in network or address in addresses:
            fail(f"{host_id} has an invalid or duplicate LAN address")
        addresses.add(address)
        os_name = host.get("os")
        arch = host.get("arch")
        if os_name not in {"linux", "macos"} or arch not in {"x86_64", "arm64"}:
            fail(f"{host_id} has an unsupported os/arch pair")
        architecture_pairs.add((os_name, arch))
        if not isinstance(host.get("cpu_threads"), int) or host["cpu_threads"] <= 0:
            fail(f"{host_id} cpu_threads must be positive")
        memory_bytes = host.get("memory_bytes")
        if (
            isinstance(memory_bytes, bool)
            or not isinstance(memory_bytes, int)
            or memory_bytes < 2**30
        ):
            fail(f"{host_id} memory_bytes is implausible")
        if (
            (os_name, arch) == ("linux", "x86_64")
            and memory_bytes % LINUX_X86_64_PAGE_BYTES != 0
        ):
            fail(
                f"{host_id} Linux/x86_64 memory_bytes must be "
                f"{LINUX_X86_64_PAGE_BYTES}-byte aligned"
            )
        validator_eligible = host.get("validator_eligible")
        roles = host.get("run_roles")
        if not isinstance(validator_eligible, bool):
            fail(f"{host_id} validator_eligible must be boolean")
        if not isinstance(roles, list) or not roles or any(
            not isinstance(role, str) or not role for role in roles
        ) or len(set(roles)) != len(roles):
            fail(f"{host_id} run_roles must be a unique non-empty string list")
        if validator_eligible:
            validator_hosts += 1
            if roles != ["validator"] or os_name != "linux":
                fail(f"{host_id} validator role must be one Linux validator host")
        else:
            observer_hosts += 1
            if roles != [
                "load-generator",
                "evidence-collector",
                "crypto-cross-verifier",
            ] or (os_name, arch) != ("macos", "arm64"):
                fail(f"{host_id} observer role must be the bounded macOS evidence role")
        counts = host.get("validator_counts")
        if not isinstance(counts, dict) or set(counts) != set(EXPECTED_TOPOLOGIES):
            fail(f"{host_id} validator_counts inventory is not closed")
        for topology, count in counts.items():
            if not isinstance(count, int) or count < 0:
                fail(f"{host_id}/{topology} validator count must be non-negative")
            if validator_eligible and count < 1:
                fail(f"{host_id}/{topology} must allocate at least one validator")
            if not validator_eligible and count != 0:
                fail(f"{host_id}/{topology} observer must allocate zero validators")
            topology_totals[topology] += count

    if topology_totals != EXPECTED_TOPOLOGIES:
        fail(f"validator totals {topology_totals!r} do not match {EXPECTED_TOPOLOGIES!r}")
    if validator_hosts != 5 or observer_hosts != 1:
        fail("validator/observer host cardinality mismatch")
    if architecture_pairs != {("linux", "x86_64"), ("macos", "arm64")}:
        fail("the heterogeneous Linux/x86_64 plus macOS/arm64 boundary is missing")
    print(
        "poco_g3_lan_inventory=passed hosts=6 topology=7,31,100 "
        "validator_hosts=5 observer_hosts=1 observer_role=load-generator,evidence-collector,crypto-cross-verifier "
        "network_scope=single-lan geo_wan_evidence=false heterogeneous=true "
        "linux_x86_64_memory_reference_page_aligned=true"
    )


if __name__ == "__main__":
    main()
