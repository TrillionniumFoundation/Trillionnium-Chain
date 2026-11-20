#!/usr/bin/env python3
"""Read the two original hosted archives; execute no native workload."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import run_from_zero_native as native
import run_from_zero_host as host

HEAD = "974049daa4b72825332b07b59084cb70f4b4c8b5"
TREE = "21c3ba7c2239103f1f18dfcf8e9099020bee9f74"
ARCHIVES = {
    "x64": (14431202653, "3bd5d0ca8a2374cf1c4d549b079530494791f4786a0e9cbfd936d4a08c9dd4c1"),
    "arm64": (14431971535, "ed58ba96672fcd66040c81e804e95065998059df0dbee8f1d08bd8675e78db0b"),
}
LIMITS = {"cpu.max": "25000 100000", "cpu.max.burst": "0",
          "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256"}

# SHA-256 of git blobs at HEAD above, independently compared before publication.
ORIGINAL_READER_SHA256 = {
    "formal/pon-nakamoto-v1/contract_wire.py": "cbe45d72ad20ed5683d50dceaa97b93bc74cdafced7d0896386edf9cbe9f98f6",
    "formal/pon-nakamoto-v1/experiments/architecture_compare.py": "fa438f829e305020fce190250d46e9b6272c2ec7b9aeb82745dfc311cc2e0fb4",
    "scripts/ci/check_required_native_test.py": "6f211d1a23521e9960df94ebd6de63c6c9733489d795eb7d2d4eaac1b790db28",
    "scripts/ci/from_zero_phase_cost.py": "3d9e7f7323a88a39853629e31b19faedd84d8b5d8762cc97074aaeb39ace7cfc",
    "scripts/ci/public_fixture_host_lease.py": "c6abe7ac89aa479917d0d39cac40c7550e37b2dc25f34d02e28f6d19fcfc76cf",
    "scripts/ci/public_host_ci_observation.py": "cc0facf46d14bc113d6a83d6b1215afe91c7b5cf22d65892f34921c8f1b983e3",
    "scripts/ci/replay_pinned_native.py": "d14d2f61ab98bb30b5932530437064dce5d3a330c05a9530988fe776cefea44a",
    "scripts/ci/run_from_zero_host.py": "2840de7cc19626c32d165bcfd032479db27180f03516ba3cefb0dafdaf61f4eb",
    "scripts/ci/run_from_zero_native.py": "87cf7fbeb89186b2c1207b232805094e6343224c543c4d210f63609d42bb24ba",
    "scripts/ci/run_history_diagnostic.py": "2ec0a8c0a6a574bdf4c5d41f69933c44a9ca83679b19ad705615c110b5af592c",
    "scripts/ci/run_history_native.py": "35ca32bbf23d33242b88a2edf994739ff804fbd7b33b5b7ac2e090b4ffce4797",
    "scripts/ci/run_public_fixture_native.py": "47def7fc617e4be335ec58bf693ea1f152347dc65c1fbcc326ab339e83375f58",
    "scripts/ci/run_sp27_receiver_controls.py": "d16701eb61c7949912d45694520b24e395436d1e1492680d6ce6228085a85476",
    "scripts/ci/run_sp27_strata_controls.py": "459dafde601c9fdad23cb36f9f8931fd0a7a7967439a6b7cc933464eb9f7a907",
    "scripts/ci/verify_ci_source.py": "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946",
    "scripts/pon_public_v3_phase_read.py": "f2dd54ec905117e26fc7128218acb74c36a3ae7c16229d56c7cc04dae1a5ef41",
    "scripts/pon_public_v3_policy_read.py": "89c45bebc01691bf42fcd65bc19625797b32d4112907f3d24ada094c6b9d698a"
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return native.json_load(path.read_bytes())


def review(archives, architecture):
    artifact, expected_zip = ARCHIVES[architecture]
    archive = archives / (architecture + ".zip")
    require(digest(archive) == expected_zip, "original GitHub ZIP digest changed")
    with tempfile.TemporaryDirectory(prefix="chain-readback-") as temporary:
        root = Path(temporary).resolve()
        with zipfile.ZipFile(archive) as zipped:
            entries = zipped.infolist()
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), "duplicate archive member")
            require(sum(entry.file_size for entry in entries) < 512 * 1024 * 1024,
                    "archive expansion bound")
            for entry in entries:
                require((root / entry.filename).resolve().is_relative_to(root)
                        and not Path(entry.filename).is_absolute()
                        and not stat.S_ISLNK(entry.external_attr >> 16), "unsafe archive member")
            zipped.extractall(root)
        source = read_json(root / "source.json")
        require(source["tested_commit"] == source["candidate"] == HEAD
                and source["tested_tree"] == TREE and source["kind"] == "head"
                and source["tracked_worktree_verified"] is True, "wrong hosted source")
        original = root / "from-zero-native"
        manifest = read_json(original / "manifest.json")
        require(manifest["source_before"] == manifest["source_after"]
                and manifest["source_before"]["commit"] == HEAD
                and manifest["source_before"]["tree"] == TREE, "native source changed")
        for name, expected in manifest["files"].items():
            path = original / name
            require(path.resolve().is_relative_to(original) and path.is_file()
                    and digest(path) == expected, "changed original member: " + name)
        binary = digest(original / native.TARGET)
        require(binary == manifest["binary_sha256_before"] == manifest["binary_sha256_after"],
                "retained executable changed")
        require([row["name"] for row in manifest["runs"]] == list(native.TESTS),
                "named native test roster changed")
        for row in manifest["runs"]:
            folder = original / row["name"]
            require(read_json(folder / "process.json") == row["process"], "process receipt changed")
            require(row["process"]["exit_code"] == 0 and row["process"]["timed_out"] is False,
                    "native invocation did not complete successfully")
            require(native.validate((folder / "stdout").read_text().splitlines(), row["name"])
                    == row["named_execution"], "named test execution mismatch")
        for key, validator in (("service_report", native.validate_service_report),
                               ("sustained_report", native.validate_sustained_report),
                               ("confirmation_report", native.validate_confirmation_report)):
            require(validator(original / native.REPORT_PATHS[key]) == manifest[key],
                    "original business validator disagrees: " + key)
        controller = read_json(root / "from-zero-native-host/controller-result.json")
        child = read_json(root / "from-zero-native-host/child-result.json")
        require(controller["passed"] is True and controller["failure"] is None
                and controller["final_host_errors"] == [] and child["host_errors"] == []
                and child["native_child_exit"] == 0, "original Host owner failed")
        lease = controller["parent_lease"]
        require(lease == controller["final_parent_lease"]
                and lease["parent_identity"]["limits"] == LIMITS
                and lease["parent_identity"]["parent"]["uid"] == 0
                and lease["parent_identity"]["parent"]["canonical_path"]
                == "/sys/fs/cgroup/trnmponpublic.slice", "original Host owner or limits changed")
        binding = host.bind_prepared_execution(controller["preparation"], original)
        require(binding == controller["preparation_execution_binding"], "build/execution binding changed")
        observation = native.summarize_confirmation_report(original / "confirmation/report.json")
        require(observation == manifest["confirmation_observation"]
                and observation["original_gate_validated"] is True, "independent readback disagrees")
        raw = read_json(original / "confirmation/report.json")
        phases = []
        for phase in raw["phases"]:
            process_cost = phase["phase_process_cost"]
            derived = next(row for row in observation["phases"] if row["mode"] == phase["mode"])
            phases.append({
                "mode": phase["mode"], "workers": phase["workers"],
                "requested_window_ns": phase["requested_window_ns"],
                "confirmed": phase["client_confirmed_transactions"],
                "confirmation_latency_ns": phase["client_confirmation_latency_ns"],
                "confirmation_ended_ns": phase["confirmation_ended_ns"],
                "signed_submissions": len(phase["honest_submissions"]),
                "independent_pages": len(phase["independent_history_page_replay"]),
                "accounting_closed": phase["accounting_closed"],
                "no_attack_accepted": phase["no_attack_accepted"],
                "overlapping_false_calls": phase["overlapping_false_calls"],
                "attacker_workers_cpu_ns": phase["attacker_workers_cpu_ns"],
                "independent_replay_cpu_ns": phase["independent_replay_and_confirmation_cpu_ns"],
                "phase_process_cost": process_cost,
                "resource_coverage": derived["resource_coverage"],
                "attacker_attempt_coverage": derived["attacker_attempts"],
            })
        invocation = next(row["process"] for row in manifest["runs"]
                          if row["name"] == native.TESTS[-1])
        return {"architecture": architecture, "artifact_id": artifact,
                "archive_sha256": expected_zip, "archive_bytes": archive.stat().st_size,
                "archive_members": len(entries), "manifest_members_checked": len(manifest["files"]),
                "source": source, "native_binary_sha256": binary,
                "original_named_tests_checked": len(native.TESTS),
                "original_business_validators_checked": 3,
                "build_execution_binding": binding, "unchanged_host_limits": LIMITS,
                "original_confirmation_gate": observation["original_gate_validated"],
                "phases": phases, "whole_confirmation_invocation": invocation,
                "whole_invocation_scope": "both phases, construction, records and exit; not pressure-only cost",
                "unknown_costs": ["exact four-second whole-tree CPU", "physical network bytes",
                                  "physical storage I/O", "whole-tree peak memory", "energy joules"],
                "full_cost_closed": False, "public_network_qualified": False,
                "sybil_fairness_qualified": False, "production_activation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema": "chain-original-window-independent-readback-v1",
              "observed_run_id": 44309944062, "observed_head": HEAD, "observed_tree": TREE,
              "scope": "read-only exact hosted originals; no workload rerun, new-source adoption or production qualification",
              "architectures": [review(args.archives, name) for name in ARCHIVES]}
    reader_sources = {
        str(Path(module.__file__).resolve().relative_to(ROOT)): digest(Path(module.__file__))
        for module in tuple(sys.modules.values())
        if getattr(module, "__file__", None)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and Path(module.__file__).suffix == ".py"}
    self_path = str(Path(__file__).resolve().relative_to(ROOT))
    require({name: sha for name, sha in reader_sources.items() if name != self_path}
            == ORIGINAL_READER_SHA256, "reader differs from original tested-source graph")
    result["reader_source_sha256"] = reader_sources
    result["reader_original_commit"] = HEAD
    result["original_reader_source_graph_verified"] = True
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"readback": "PASS", "architectures": list(ARCHIVES), "original_business_gate": True,
                      "whole_cost_closed": False, "production_activation": False}))


if __name__ == "__main__":
    main()
