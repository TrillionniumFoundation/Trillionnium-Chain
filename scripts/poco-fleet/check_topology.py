#!/usr/bin/env python3
"""Self-test deterministic PoCO LAN topology planning."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


PLANNER = pathlib.Path(__file__).with_name("plan_topology.py")


def plan(count: int, profile: str) -> dict:
    return json.loads(
        subprocess.check_output(
            [sys.executable, str(PLANNER), str(count), "--weight-profile", profile],
            text=True,
        )
    )


def main() -> None:
    for count in (4, 7, 31, 100):
        profiles = ("equal",) if count == 4 else ("equal", "bounded-unequal")
        for profile in profiles:
            first = plan(count, profile)
            second = plan(count, profile)
            assert first == second
            validators = first["validators"]
            assert len(validators) == count
            assert len({item["validator_id"] for item in validators}) == count
            assert len({(item["lan_ip"], item["p2p_port"]) for item in validators}) == count
            assert len({(item["lan_ip"], item["metrics_port"]) for item in validators}) == count
            expected_validator_hosts = {"local", "x230", "desktop", "rog"}
            if count != 4:
                expected_validator_hosts.add("j3160")
            assert {item["host_id"] for item in validators} == expected_validator_hosts
            participants = first["participants"]
            assert {item["host_id"] for item in participants} == {
                "local", "x230", "desktop", "rog", "j3160", "mac"
            }
            mac = next(item for item in participants if item["host_id"] == "mac")
            assert mac["validator_eligible"] is False
            assert mac["run_roles"] == [
                "load-generator", "evidence-collector", "crypto-cross-verifier"
            ]
            assert all(
                item["validator_eligible"] is True and item["run_roles"] == ["validator"]
                for item in participants if item["host_id"] != "mac"
            )
            expected_degree = count - 1 if count in {4, 7} else 8
            assert first["peer_degree"] == expected_degree
            for item in validators:
                assert len(item["peers"]) == expected_degree
                assert item["validator_id"] not in item["peers"]
                assert len(set(item["peers"])) == expected_degree
            weights = [item["weight"] for item in validators]
            if profile == "equal":
                assert set(weights) == {1}
            else:
                assert set(weights) == {1, 2, 3, 4}
                assert max(weights) * 4 <= sum(weights)
    print(
        "poco_g3_topology_planner=passed counts=4,7,31,100 four_equal_only=true profiles=equal,bounded-unequal "
        "five_linux_validator_hosts=true mac_observer=true all_six_hosts_participate=true "
        "unique_ports=true deterministic=true test_keys=false"
    )


if __name__ == "__main__":
    main()
