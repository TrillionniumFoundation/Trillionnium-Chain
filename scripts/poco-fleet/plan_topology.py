#!/usr/bin/env python3
"""Emit a deterministic, key-free 7/31/100-validator LAN placement plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import tomllib
from typing import Any


TOPOLOGY_KEYS = {7: "seven", 31: "thirty_one", 100: "one_hundred"}
INVENTORY = pathlib.Path(__file__).with_name("inventory.toml")
CANONICAL_PLACEMENT = "canonical"
REDUCED_PLACEMENT = "desktop4-rog3-mac-v1"
PLACEMENT_PROFILES = (CANONICAL_PLACEMENT, REDUCED_PLACEMENT)


def identity(fleet_id: str, validator_index: int) -> str:
    return hashlib.sha256(
        f"{fleet_id}/validator/{validator_index:03d}".encode("ascii")
    ).hexdigest()


def build_topology(
    inventory: dict[str, Any],
    validator_count: int,
    weight_profile: str,
    placement_profile: str = CANONICAL_PLACEMENT,
) -> dict[str, Any]:
    """Derive a complete key-free plan from one explicitly selected placement."""
    if type(validator_count) is not int or validator_count not in TOPOLOGY_KEYS:
        raise ValueError("unsupported validator count")
    if weight_profile not in ("equal", "bounded-unequal"):
        raise ValueError("unknown weight profile")
    if placement_profile not in PLACEMENT_PROFILES:
        raise ValueError("unknown placement profile")
    topology_key = TOPOLOGY_KEYS[validator_count]
    hosts = inventory["hosts"]
    if placement_profile == REDUCED_PLACEMENT:
        if validator_count != 7 or weight_profile != "equal":
            raise ValueError("reduced placement requires exactly seven equal-weight validators")
        by_id = {host["id"]: host for host in hosts}
        if len(by_id) != len(hosts) or not {"desktop", "rog", "mac"} <= by_id.keys():
            raise ValueError("reduced placement requires exact inventory host identities")
        hosts = [by_id[name] for name in ("desktop", "rog", "mac")]
        allocation = {"desktop": 4, "rog": 3, "mac": 0}
    else:
        allocation = {host["id"]: host["validator_counts"][topology_key] for host in hosts}
    validators = []
    validator_index = 0
    for host in hosts:
        for local_index in range(allocation[host["id"]]):
            validators.append(
                {
                    "index": validator_index,
                    "validator_id": identity(inventory["fleet_id"], validator_index),
                    "host_id": host["id"],
                    "management": host["management"],
                    "lan_ip": host["lan_ip"],
                    "host_local_index": local_index,
                    "p2p_port": 31000 + validator_index,
                    "metrics_port": 32000 + validator_index,
                    "weight": 1
                    if weight_profile == "equal"
                    else 1 + ((validator_index * 17 + 3) % 4),
                }
            )
            validator_index += 1
    if validator_index != validator_count:
        raise ValueError("inventory allocation does not match requested validator count")

    degree = validator_count - 1 if validator_count == 7 else 8
    for validator in validators:
        index = validator["index"]
        validator["peers"] = [
            validators[(index + offset) % validator_count]["validator_id"]
            for offset in range(1, degree + 1)
        ]
    output = {
        "schema_version": 1 if placement_profile == CANONICAL_PLACEMENT else 2,
        "fleet_id": inventory["fleet_id"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_count": validator_count,
        "weight_profile": weight_profile,
        "peer_degree": degree,
        "test_keys_included": False,
        "participants": [
            {
                "host_id": host["id"],
                "management": host["management"],
                "lan_ip": host["lan_ip"],
                "os": host["os"],
                "arch": host["arch"],
                "validator_eligible": host["validator_eligible"],
                "run_roles": list(host["run_roles"]),
            }
            for host in hosts
        ],
        "validators": validators,
    }
    if placement_profile != CANONICAL_PLACEMENT:
        output["placement_profile"] = placement_profile
    return output


def validate_topology_v1(inventory: dict[str, Any], topology: object) -> str:
    """Bind every typed topology field to the closed inventory-derived plan."""
    if not isinstance(topology, dict) or type(topology.get("schema_version")) is not int:
        raise ValueError("topology schema must be one exact supported integer")
    if topology["schema_version"] == 1:
        placement = CANONICAL_PLACEMENT
    elif topology["schema_version"] == 2 and topology.get("placement_profile") == REDUCED_PLACEMENT:
        placement = REDUCED_PLACEMENT
    else:
        raise ValueError("topology schema/placement profile is unsupported")
    expected = build_topology(
        inventory, topology.get("validator_count"), topology.get("weight_profile"), placement
    )
    # Serialized typed comparison also refuses True/1 and 31000.0/31000 aliases.
    if json.dumps(topology, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError("topology differs from exact inventory placement")
    return placement


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("validator_count", type=int, choices=TOPOLOGY_KEYS)
    parser.add_argument("--inventory", type=pathlib.Path, default=INVENTORY)
    parser.add_argument(
        "--weight-profile", choices=("equal", "bounded-unequal"), default="equal"
    )
    parser.add_argument("--placement-profile", choices=PLACEMENT_PROFILES, default=CANONICAL_PLACEMENT)
    args = parser.parse_args()
    if args.inventory.resolve() != INVENTORY.resolve():
        parser.error("only the committed fleet inventory is supported")
    with INVENTORY.open("rb") as source:
        inventory = tomllib.load(source)
    try:
        output = build_topology(inventory, args.validator_count, args.weight_profile, args.placement_profile)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
