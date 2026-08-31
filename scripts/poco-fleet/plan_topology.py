#!/usr/bin/env python3
"""Emit a deterministic, key-free 7/31/100-validator LAN placement plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import tomllib


TOPOLOGY_KEYS = {7: "seven", 31: "thirty_one", 100: "one_hundred"}


def identity(fleet_id: str, validator_index: int) -> str:
    return hashlib.sha256(
        f"{fleet_id}/validator/{validator_index:03d}".encode("ascii")
    ).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("validator_count", type=int, choices=TOPOLOGY_KEYS)
    parser.add_argument(
        "--inventory",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("inventory.toml"),
    )
    parser.add_argument(
        "--weight-profile", choices=("equal", "bounded-unequal"), default="equal"
    )
    args = parser.parse_args()
    with args.inventory.open("rb") as source:
        inventory = tomllib.load(source)

    topology_key = TOPOLOGY_KEYS[args.validator_count]
    validators = []
    validator_index = 0
    for host in inventory["hosts"]:
        for local_index in range(host["validator_counts"][topology_key]):
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
                    if args.weight_profile == "equal"
                    else 1 + ((validator_index * 17 + 3) % 4),
                }
            )
            validator_index += 1
    if validator_index != args.validator_count:
        raise SystemExit("inventory allocation does not match requested validator count")

    degree = args.validator_count - 1 if args.validator_count == 7 else 8
    for validator in validators:
        index = validator["index"]
        validator["peers"] = [
            validators[(index + offset) % args.validator_count]["validator_id"]
            for offset in range(1, degree + 1)
        ]
    output = {
        "schema_version": 1,
        "fleet_id": inventory["fleet_id"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_count": args.validator_count,
        "weight_profile": args.weight_profile,
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
                "run_roles": host["run_roles"],
            }
            for host in inventory["hosts"]
        ],
        "validators": validators,
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
