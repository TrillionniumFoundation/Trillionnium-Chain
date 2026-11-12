#!/usr/bin/env python3
"""Index separate, byte-verified observations; never relabel an old campaign."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

SOURCE = "031d442dd0acb693afcfaf42f9cc4db446ba52cb"
RUNNER_SHA = "8f82ae65d146be8513d0bc9fb14ed8f08e2df378f5db8e3471d99301d78fd3d9"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_names(runner: Path) -> list[str]:
    data = runner.read_bytes()
    if digest(data) != RUNNER_SHA:
        raise ValueError("unexpected original runner bytes")
    constants = {}
    for node in ast.parse(data).body:
        if isinstance(node, ast.Assign):
            for name in node.targets:
                if isinstance(name, ast.Name) and name.id in {
                    "REQUIRED_DA_CONTROLS", "REQUIRED_NODE_CONTROLS"
                }:
                    constants[name.id] = ast.literal_eval(node.value)
    if len(constants["REQUIRED_DA_CONTROLS"]) != 5 or len(constants["REQUIRED_NODE_CONTROLS"]) != 13:
        raise ValueError("original required selector roster changed")
    names = ["preflight", "source-before", "rustc-version", "cargo-version",
             "locked-graph", "locked-all-feature-graph", "format", "inventory",
             "test_cell_discovery_v3_ci", "test_cell_storage_convergence_ci",
             "test_ci_source_integrity", "check_pq_research_integration",
             "test_pq_research_integration", "check_repository",
             "next-architecture-python", "counterexample-fixture",
             "cell_complete_version_vector", "cell_discovery_epoch_v3_vector",
             "cell_version_content_vector", "cell_version_retention_v3_vector",
             "cell_storage_descriptor_reference", "sealed-research-python-controls",
             "sealed-research-python-readback", "da-complete"]
    for i in range(1, 6):
        names.extend([f"da-required-{i:02d}", f"da-required-{i:02d}-readback"])
    names.extend(["cell_sealed_research_next_use_v2-tests",
                  "cell_sealed_research_paged_next_use_v1-tests"])
    for label in ("default", "pq"):
        names.extend(["native-grouped-example-" + label,
                      "native-complete-selection-" + label,
                      "native-complete-selection-" + label + "-readback"])
    names.append("node-storage-default")
    for i in range(1, 14):
        names.extend([f"node-required-{i:02d}", f"node-required-{i:02d}-readback"])
    names.extend(["node-storage", "clippy-default-trnm-data-availability",
                  "clippy-default-trnm-pon-node", "strict-clippy", "source-after"])
    if len(names) != 74 or len(set(names)) != 74:
        raise ValueError("candidate command roster mismatch")
    return names


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--summary", action="append", required=True,
                        help="Relative path of an unchanged original summary")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_root.resolve(strict=True)
    names = expected_names(args.runner)
    observations = {name: [] for name in names}
    inputs = []
    for relative in args.summary:
        path = root / relative
        if not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("summary outside evidence root")
        data = path.read_bytes()
        report = json.loads(data)
        if report.get("source") != SOURCE:
            raise ValueError("summary source differs from frozen B")
        inputs.append({"path": relative, "bytes": len(data), "sha256": digest(data),
                       "original_completed": report.get("completed"),
                       "original_status": report.get("status"),
                       "original_all_commands_passed": report.get("all_commands_passed")})
        for command in report["commands"]:
            name = command["name"]
            if name not in observations:
                continue
            item = {"summary": relative, "exit_code": command.get("exit_code"),
                    "status": command.get("status"), "timed_out": command.get("timed_out"),
                    "argv": command.get("argv"), "streams": [], "raw_verified": False}
            for stream in ("stdout", "stderr"):
                size_key, sha_key = stream + "_bytes", stream + "_sha256"
                if size_key not in command or sha_key not in command:
                    continue
                log_path = path.parent / (name + "." + stream)
                if not log_path.is_file():
                    raise ValueError("declared completed stream missing: " + str(log_path))
                raw = log_path.read_bytes()
                if len(raw) != command[size_key] or digest(raw) != command[sha_key]:
                    raise ValueError("original stream pin mismatch: " + str(log_path))
                item["streams"].append({"path": str(log_path.relative_to(root)),
                                        "bytes": len(raw), "sha256": digest(raw)})
            item["raw_verified"] = len(item["streams"]) == 2
            item["accepted_exit_observation"] = (
                item["raw_verified"] and command.get("exit_code") == 0
                and command.get("timed_out") is not True
                and command.get("status") not in {"running", "timed_out"}
                and command.get("exact_native_test_observed", True) is True
            )
            observations[name].append(item)
    missing = [name for name in names if not any(x["accepted_exit_observation"]
                                               for x in observations[name])]
    output = {"schema": "trnm.bt-candidate-separate-observation-coverage.v1",
              "source": SOURCE, "original_runner_sha256": RUNNER_SHA,
              "expected_candidate_command_count": len(names),
              "covered_command_count": len(names) - len(missing),
              "coverage_complete": not missing, "missing_commands": missing,
              "single_original_campaign_claimed_passed": False,
              "original_summaries_rewritten": False,
              "source_and_environment_binding_requires_original_reports": True,
              "native_model_execution_qualified_by_this_index": False,
              "production_qualified": False, "inputs": inputs,
              "commands": [{"name": name, "observations": observations[name]} for name in names]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(output, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"expected": len(names), "covered": len(names) - len(missing),
                      "missing": missing, "output": str(args.output)}))


if __name__ == "__main__":
    main()
