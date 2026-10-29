#!/usr/bin/env python3
"""Read the explicit pure-pressure fixed-Host client composition.

The original raw pressure/receiver readers remain mandatory and unchanged.
This gate additionally binds all client imports, confirmations and snapshots to
the actual source-bound fixed-parent actor. Launcher wait4 is launcher-only;
native process CPU and cumulative fixed-parent CPU remain distinct, nested
observations. None authenticates an independently operated machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import check_pure_pon_pressure_v2 as pressure
from check_pure_pon_attacker_cost_v1 import parse_raw
import read_native_history_verifier as owner

COMPOSITION_SCHEMA = "pon-pure-fixed-host-client-composition-v1"
RESULT_SCHEMA = "pon-pure-fixed-host-client-readback-v1"
PROFILE = owner.PURE_CLIENT_PROFILE
EXPERIMENTS = {
    "pure-pressure": "pure_pon_cold_shared_domain_pressure_fixed_host_client_v1",
    "receiver-owner-supplement": "receiver_owner::whole_receiver_owner_pressure_fixed_host_client_v1",
}
require = owner.require


def phase_file(path):
    require(path.is_file() and not path.is_symlink(), "regular original raw phase required")
    require(path.stat().st_size <= pressure.MAX_FILE_BYTES, "original phase byte bound")
    with path.open("rb") as stream:
        raw = stream.read(pressure.MAX_FILE_BYTES + 1)
    require(len(raw) <= pressure.MAX_FILE_BYTES, "original actual phase byte bound")
    return parse_raw(raw, pressure.MAX_FILE_BYTES), hashlib.sha256(raw).hexdigest()


def check_directory(directory, binary_sha256, outer_cgroup, experiment):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "retained composition directory required")
    require(experiment in EXPERIMENTS, "explicit supported pure client experiment required")
    owner.digest(binary_sha256)
    composition, _ = owner.read(directory / "client-composition.json")
    require(composition["schema"] == COMPOSITION_SCHEMA
            and composition["client_execution_profile"] == owner.PURE_CLIENT_PROFILE
            and composition["experiment"] == experiment
            and composition["native_selector"] == EXPERIMENTS[experiment],
            "exact new composition namespace and native selector required")
    require(composition["receiver_outer_budget_changed"] is False
            and composition["attacker_outer_budget_changed"] is False
            and type(composition["window_ns"]) is int and composition["window_ns"] == pressure.WINDOW
            and type(composition["history_call_cap"]) is int and composition["history_call_cap"] == 64,
            "original pressure window, History cap and outer resource placement required")
    pressure.no_authority(composition)
    manifest, manifest_sha = phase_file(directory / "campaign.json")
    require(owner.digest(composition["campaign_sha256"]) == manifest_sha,
            "composition must bind actual original campaign bytes")
    expected_schema = (pressure.SCHEMA if experiment == "pure-pressure"
                       else "pon-pure-receiver-owner-campaign-v1")
    require(manifest["schema"] == expected_schema, "original data-layout namespace required")
    expected = list(pressure.PHASES)
    require([row["phase"] for row in composition["phases"]] == expected
            and [row["file"] for row in composition["phases"]] == [name + ".json" for name in expected]
            and [row["phase"] for row in manifest["phases"]] == expected,
            "complete ordered original three phases required")
    prepared = pressure.load(directory / "preparation.json")
    pressure.preparation(prepared)
    seed_tip = pressure.packet(pressure.raw_hex(prepared["seed"][-1]))["id"]
    rows = []
    for binding in composition["phases"]:
        name = binding["phase"]
        phase, sha = phase_file(directory / binding["file"])
        require(phase["phase"] == name and owner.digest(binding["sha256"]) == sha,
                "composition must bind exact ordered raw phase bytes")
        phase_directory = directory / name
        native_directory = phase_directory / "independent-client"
        require(phase_directory.is_dir() and not phase_directory.is_symlink()
                and native_directory.is_dir() and not native_directory.is_symlink(),
                "fresh actual phase and client directories required")
        job, _ = owner.read(native_directory / "job.json")
        require(job["seed"] == prepared["seed"], "actual client must replay the exact original seed packets")
        ready = phase["history_verifier_process"]["ready"]
        require(owner.native_hash(ready["initial_tip"]) == seed_tip,
                "actual isolated client initial tip must match the original four seed blocks")
        row = owner.validate_pure_client_phase(phase, native_directory, binary_sha256, outer_cgroup)
        row["phase"] = name
        rows.append(row)
    return {"schema": RESULT_SCHEMA, "client_execution_profile": owner.PURE_CLIENT_PROFILE,
            "experiment": experiment, "input_consistent": True, "client_boundary_complete": True,
            "original_service_predicates_still_required": True, "phases": rows,
            "native_actor_wait4_claimed": False, "full_receiver_state_equality_claimed": False,
            "cost_scopes_are_nested_not_additive": True,
            "independent_host_authentication": False, "public_fairness_qualified": False,
            "production_qualified": False, "work_hardness_qualified": False,
            "installation_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--outer-cgroup", required=True)
    parser.add_argument("--experiment", required=True, choices=EXPERIMENTS)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check_directory(args.directory, args.binary_sha256, args.outer_cgroup, args.experiment)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {"schema": RESULT_SCHEMA, "client_execution_profile": owner.PURE_CLIENT_PROFILE,
                  "experiment": args.experiment, "input_consistent": False,
                  "client_boundary_complete": False, "error": str(error),
                  "native_actor_wait4_claimed": False, "public_fairness_qualified": False,
                  "production_qualified": False, "work_hardness_qualified": False,
                  "installation_authorized": False}
    raw = json.dumps(result, sort_keys=True, indent=2) + "\n"
    with args.output.open("x") as stream:
        stream.write(raw)
    print(raw, end="")
    return 0 if result["input_consistent"] and result["client_boundary_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
