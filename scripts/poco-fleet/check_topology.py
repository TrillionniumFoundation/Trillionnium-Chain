#!/usr/bin/env python3
"""Self-test deterministic PoCO LAN topology planning."""

from __future__ import annotations

import json
import hashlib
import pathlib
import subprocess
import sys
import tomllib

import check_raw_run_artifacts
import plan_topology


PLANNER = pathlib.Path(__file__).with_name("plan_topology.py")
CANONICAL_SHA256 = {
    (7, "equal"): "577c51bb986a03e23486a9fd43e60bdd8dd97469cb958dc114aa1741b74f81a5",
    (7, "bounded-unequal"): "2d10d4c5b37b58572418d8bf826e9bac7350841cb057dbe76b64a3ec0022c5fa",
    (31, "equal"): "27f6bf2337b71662ffa6b30b31ef10cde4c382f934b65541c147bbc5f03d592d",
    (31, "bounded-unequal"): "5b912c89fca8f08a5933b94666e32b8b3059a8e4d32338ec1a2f8e26d908559a",
    (100, "equal"): "8abf159d28b69631aec92d545c2024fec249e56ac36b3775c5e41e9882a0db8b",
    (100, "bounded-unequal"): "01dab2c65719803011074843bbdafe70f7a0cdba11d32ea2614fab333e8807db",
}


def plan(count: int, profile: str) -> dict:
    return json.loads(
        subprocess.check_output(
            [sys.executable, str(PLANNER), str(count), "--weight-profile", profile],
            text=True,
        )
    )


def main() -> None:
    with plan_topology.INVENTORY.open("rb") as source:
        inventory = tomllib.load(source)
    for count in (7, 31, 100):
        for profile in ("equal", "bounded-unequal"):
            command = [sys.executable, str(PLANNER), str(count), "--weight-profile", profile]
            original = subprocess.check_output(command)
            assert hashlib.sha256(original).hexdigest() == CANONICAL_SHA256[(count, profile)]
            assert subprocess.check_output(command + ["--placement-profile", "canonical"]) == original
            first = plan(count, profile)
            second = plan(count, profile)
            assert first == second
            validators = first["validators"]
            assert len(validators) == count
            assert len({item["validator_id"] for item in validators}) == count
            assert len({(item["lan_ip"], item["p2p_port"]) for item in validators}) == count
            assert len({(item["lan_ip"], item["metrics_port"]) for item in validators}) == count
            assert {item["host_id"] for item in validators} == {
                "local",
                "x230",
                "desktop",
                "rog",
                "j3160",
            }
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
            expected_degree = count - 1 if count == 7 else 8
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
            assert plan_topology.validate_topology_v1(inventory, first) == "canonical"
            check_raw_run_artifacts.require_full_fleet_topology_v1(first)
    run_id = "poco-g3-7-20260921T000000Z-01234567"
    annotated = {**plan_topology.build_topology(inventory, 7, "equal"), "run_id": run_id}
    check_raw_run_artifacts.require_full_fleet_topology_v1(annotated, expected_run_id=run_id)
    for expected in (None, run_id + "-foreign"):
        try:
            check_raw_run_artifacts.require_full_fleet_topology_v1(annotated, expected_run_id=expected)
        except SystemExit as error:
            assert "run annotation differs" in str(error)
        else:
            raise AssertionError("unbound completed topology annotation was accepted")
    try:
        check_raw_run_artifacts.require_full_fleet_topology_v1(
            {**annotated, "undeclared": True}, expected_run_id=run_id
        )
    except SystemExit as error:
        assert "closed inventory placement" in str(error)
    else:
        raise AssertionError("completed topology annotation admitted an unknown field")
    try:
        plan_topology.validate_topology_v1(inventory, annotated)
    except ValueError:
        pass
    else:
        raise AssertionError("material topology admitted the completed-bundle annotation")
    reduced = plan_topology.build_topology(inventory, 7, "equal", plan_topology.REDUCED_PLACEMENT)
    assert reduced["schema_version"] == 2
    assert [item["host_id"] for item in reduced["participants"]] == ["desktop", "rog", "mac"]
    assert [item["host_id"] for item in reduced["validators"]] == ["desktop"] * 4 + ["rog"] * 3
    assert [item["p2p_port"] for item in reduced["validators"]] == list(range(31000, 31007))
    assert [item["metrics_port"] for item in reduced["validators"]] == list(range(32000, 32007))
    assert plan_topology.validate_topology_v1(inventory, reduced) == plan_topology.REDUCED_PLACEMENT
    assert json.loads(subprocess.check_output([
        sys.executable, str(PLANNER), "7", "--placement-profile", plan_topology.REDUCED_PLACEMENT,
    ])) == reduced
    try:
        check_raw_run_artifacts.require_full_fleet_topology_v1(reduced)
    except SystemExit as error:
        assert "cannot satisfy full-fleet" in str(error)
    else:
        raise AssertionError("reduced topology entered the full-fleet raw evidence gate")
    local = plan_topology.build_topology(inventory, 7, "equal", "local4-rog3-mac-v1")
    assert [item["host_id"] for item in local["participants"]] == ["local", "rog", "mac"]
    assert [item["host_id"] for item in local["validators"]] == ["local"] * 4 + ["rog"] * 3
    assert plan_topology.validate_topology_v1(inventory, local) == "local4-rog3-mac-v1"
    assert json.loads(subprocess.check_output([
        sys.executable, str(PLANNER), "7", "--placement-profile", "local4-rog3-mac-v1",
    ])) == local
    try:
        check_raw_run_artifacts.require_full_fleet_topology_v1(local)
    except SystemExit as error:
        assert "cannot satisfy full-fleet" in str(error)
    else:
        raise AssertionError("pocket4/ROG diagnostic plan was relabeled as full fleet")
    for mutate in (
        lambda t: t.update(placement_profile=plan_topology.REDUCED_PLACEMENT),
        lambda t: t.update(placement_profile={}),
        lambda t: t["validators"][0].update(host_id="desktop"),
        lambda t: t["validators"][0].update(p2p_port=True),
        lambda t: t["participants"][0].update(management="p4-desktop"),
    ):
        changed = json.loads(json.dumps(local))
        mutate(changed)
        try:
            plan_topology.validate_topology_v1(inventory, changed)
        except ValueError:
            pass
        else:
            raise AssertionError("diagnostic placement accepted a remapped or relabeled host")
    for count, weight, placement in (
        (31, "equal", plan_topology.REDUCED_PLACEMENT),
        (100, "equal", plan_topology.REDUCED_PLACEMENT),
        (7, "bounded-unequal", plan_topology.REDUCED_PLACEMENT),
        (31, "equal", "local4-rog3-mac-v1"),
        (7, "bounded-unequal", "local4-rog3-mac-v1"),
        (7, "equal", "unknown"),
    ):
        result = subprocess.run([
            sys.executable, str(PLANNER), str(count), "--weight-profile", weight,
            "--placement-profile", placement,
        ], capture_output=True)
        assert result.returncode != 0
    override = subprocess.run([
        sys.executable, str(PLANNER), "7", "--inventory", "/tmp/arbitrary-inventory.toml",
    ], capture_output=True, text=True)
    assert override.returncode != 0 and "only the committed fleet inventory" in override.stderr
    print(
        "poco_g3_topology_planner=passed counts=7,31,100 profiles=equal,bounded-unequal "
        "five_linux_validator_hosts=true mac_observer=true all_six_hosts_participate=true "
        "unique_ports=true deterministic=true test_keys=false canonical_bytes_unchanged=true "
        "reduced_desktop4_rog3_mac=true reduced_not_full_fleet=true"
    )


if __name__ == "__main__":
    main()
