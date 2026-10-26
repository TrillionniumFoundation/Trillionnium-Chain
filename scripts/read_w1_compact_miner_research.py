#!/usr/bin/env python3
"""Read the frozen compact/comparator campaign and replay complete deterministic attempts.

External pins must come from the owner, not be inferred from an untrusted bundle.
This checks software evidence and exact arithmetic. It is not execution attestation,
an independent operator, a physical resource lower bound, or model qualification.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from read_w1_cost_research import (
    bundle_file, exact, hx, require, uint64, validate_child_resources,
)
from run_w1_compact_miner_research import BINARIES, SCHEMA, decode, sha, usage_snapshot, validate_plan

from w1_lossless_raw import verified_raw_stream

SETUP_NAMES = ("preflight", "rustc-version", "cargo-version", "metadata", "build")
READER_FILES = ("scripts/read_w1_compact_miner_research.py", "scripts/w1_compact_miner_reader.py",
                "scripts/w1_late_assembly_reader.py",
                "formal/pon-nakamoto-v1/work_oracle.py",
                "formal/pon-nakamoto-v1/contract_wire.py")
READER_SOURCE_SCOPES = ("scripts", "formal", "config")
WAITED_CPU_ALLOWANCE_NS = 2000
GNU_TIME_PRINT_ALLOWANCE_NS = 20_000_000


def same_json(left, right):
    """Type-sensitive JSON equality: Python otherwise aliases false/0 and true/1."""
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    return canonical(left) == canonical(right)


def cpu_observer_reconciliation(result, step):
    """Cross-observer units/scope check, never truncate a negative residual.

    Waited-child resource counters have microsecond output; the registered 2-us
    allowance covers differencing two endpoints. GNU time prints two components
    in hundredths of a second; a conservative 20-ms allowance covers both printed
    components. Wrapper/startup/teardown costs remain in the signed residual.
    This consistency test does not authenticate either observer or physical cost.
    """
    waited = step["whole_waited_child_resources"]
    whole = waited["user_cpu_ns"] + waited["system_cpu_ns"]
    nested = result["total_process_cpu_ns"]
    label = "whole waited command minus native process CPU from its recorded origin to the explicit endpoint; final serialization and remaining drops stay in the residual"
    uint64(nested, "NATIVE_CPU_OBSERVER_SCOPE")
    residual = whole - nested
    require(residual >= -WAITED_CPU_ALLOWANCE_NS, "NATIVE_CPU_EXCEEDS_WHOLE_WAITED_COMMAND")
    usage = step["command_usage"]
    printed = int((Decimal(usage["user_seconds_decimal"]) +
                   Decimal(usage["system_seconds_decimal"])) * 1_000_000_000)
    require(printed + GNU_TIME_PRINT_ALLOWANCE_NS >= nested and
            printed <= whole + GNU_TIME_PRINT_ALLOWANCE_NS + WAITED_CPU_ALLOWANCE_NS,
            "GNU_TIME_CPU_UNIT_OR_SCOPE_DISAGREEMENT")
    return {"scope": label, "whole_waited_cpu_ns": whole, "nested_native_cpu_ns": nested,
            "signed_residual_cpu_ns": residual, "residual_clamped": False,
            "waited_endpoint_allowance_ns": WAITED_CPU_ALLOWANCE_NS,
            "gnu_time_printed_cpu_ns": printed,
            "gnu_time_print_allowance_ns": GNU_TIME_PRINT_ALLOWANCE_NS,
            "hardware_or_clock_attestation": False}


def reader_tree_snapshot(head):
    """Bind all repository helper code and data, including transitive imports.

    Comparing only top-level readers misses dynamically loaded config and
    existing helper modules. Publication-only docs/evidence may change later;
    these complete source/data scopes must retain their exact measured bytes.
    This is a software snapshot, not protection from a malicious host or Python.
    """
    command = ["git", "--no-replace-objects", "-C", str(ROOT)]
    records = subprocess.check_output(command + ["ls-tree", "-r", "-z", head, "--", *READER_SOURCE_SCOPES], timeout=30)
    current = subprocess.check_output(command + ["ls-files", "-z", "--cached", "--others",
                                                "--", *READER_SOURCE_SCOPES], timeout=30)
    entries = []
    for record in records.split(b"\0"):
        if not record:
            continue
        metadata, path_bytes = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        require(kind == "blob" and mode in ("100644", "100755"), "READER_SOURCE_ENTRY_TYPE")
        path = path_bytes.decode("utf-8")
        require(not Path(path).is_absolute() and ".." not in Path(path).parts, "READER_SOURCE_ENTRY_PATH")
        entries.append((path, mode, oid))
    require(entries and {path for path, _, _ in entries} ==
            {path.decode("utf-8") for path in current.split(b"\0") if path}, "READER_SOURCE_FILE_SET")
    receipt, total = hashlib.sha256(), 0
    for path, mode, oid in entries:
        local = ROOT / path
        require(not local.is_symlink() and local.is_file() and local.resolve().is_relative_to(ROOT.resolve()),
                "READER_SOURCE_FILE_SCOPE:" + path)
        content = local.read_bytes()
        require(hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest() == oid,
                "READER_SOURCE_BYTES:" + path)
        require(bool(local.stat().st_mode & 0o111) == (mode == "100755"), "READER_SOURCE_MODE:" + path)
        receipt.update(path.encode() + b"\0" + mode.encode() + b"\0" + str(len(content)).encode() + b"\0")
        receipt.update(content)
        total += len(content)
    return {"tested_commit": head, "scopes": list(READER_SOURCE_SCOPES), "files": len(entries),
            "bytes": total, "sha256": receipt.hexdigest(), "all_current_bytes_match_git_blobs": True,
            "hardware_or_interpreter_attestation": False}


def source_objects(head, tree, blobs):
    """Compare declared snapshots with immutable, non-replaced local Git objects."""
    command = ["git", "--no-replace-objects", "-C", str(ROOT)]
    actual = subprocess.check_output(command + ["rev-parse", head + "^{tree}"], timeout=30)
    require(actual.decode().strip() == tree, "SOURCE_COMMIT_TREE_BINDING")
    for path, digest in blobs.items():
        content = subprocess.check_output(command + ["show", head + ":" + path], timeout=30)
        require(hashlib.sha256(content).hexdigest() == digest, "SOURCE_BLOB_BINDING:" + path)


def check_source(bundle, expected_head, expected_tree, plan_hash):
    before = exact(bundle["source_before"], ("head", "tree", "branch", "status"), "SOURCE_FIELDS")
    require(same_json(before, bundle["source_after"]) and before["head"] == expected_head and
            before["tree"] == expected_tree and before["status"] == "" and
            type(before["branch"]) is str and bool(before["branch"]), "BUNDLE_SOURCE_PIN")
    raw = exact(bundle["raw_source_before"], (
        "schema", "kind", "tested_commit", "tested_tree", "candidate", "base", "prospective_merge",
        "tracked_worktree_verified", "tracked_entries", "tracked_bytes", "tests_executed_by_identity_check",
    ), "RAW_SOURCE_FIELDS")
    require(same_json(raw, bundle["raw_source_after"]) and raw["schema"] == "trnm-ci-source-v1" and
            raw["kind"] == "head" and raw["tested_commit"] == raw["candidate"] == expected_head and
            raw["tested_tree"] == expected_tree and raw["base"] is None and raw["prospective_merge"] is None and
            raw["tracked_worktree_verified"] is True and raw["tests_executed_by_identity_check"] is False,
            "RAW_SOURCE_PIN")
    uint64(raw["tracked_entries"], "RAW_SOURCE_ENTRIES", 1)
    uint64(raw["tracked_bytes"], "RAW_SOURCE_BYTES", 1)
    plan_path = Path(bundle["plan_source_path"])
    require(not plan_path.is_absolute() and ".." not in plan_path.parts and
            str(plan_path) == bundle["plan_source_path"], "PLAN_SOURCE_PATH")
    hx(bundle["runner_sha256"], 32, "RUNNER_HASH")
    reader_hashes = {path: sha(ROOT / path) for path in READER_FILES}
    source_objects(expected_head, expected_tree, {
        str(plan_path): plan_hash, "scripts/run_w1_compact_miner_research.py": bundle["runner_sha256"],
        **reader_hashes,
    })
    return before, reader_hashes


def check_steps(directory, steps, jobs, output_limit, observer, compression):
    exact(compression, [job["name"] for job in jobs], "COMPRESSION_JOB_SET")
    require(type(steps) is list and [row.get("name") for row in steps] ==
            list(SETUP_NAMES) + [job["name"] for job in jobs], "EXACT_REGISTERED_STEPS")
    result, cwd = {}, None
    for step in steps:
        fields = {
            "name", "command", "cwd", "timeout_seconds", "output_limit_bytes", "returncode", "error",
            "stdout_truncated", "stderr_truncated", "stdout", "stderr", "wall_ns", "stdout_bytes",
            "stderr_bytes", "stdout_sha256", "stderr_sha256", "complete_success", "whole_waited_child_resources",
        }
        measured = step["name"] not in SETUP_NAMES
        exact(step, fields | ({"command_usage"} if measured else set()), "STEP_FIELDS")
        validate_child_resources(step["whole_waited_child_resources"])
        require(step["complete_success"] is True and type(step["returncode"]) is int and
                step["returncode"] == 0 and step["error"] is None and step["stdout_truncated"] is False and
                step["stderr_truncated"] is False, "FAILED_STEP")
        require(type(step["command"]) is list and all(type(v) is str for v in step["command"]), "STEP_COMMAND")
        require(type(step["cwd"]) is str and Path(step["cwd"]).is_absolute(), "STEP_CWD")
        cwd = step["cwd"] if cwd is None else cwd
        require(step["cwd"] == cwd and type(step["output_limit_bytes"]) is int and
                step["output_limit_bytes"] == output_limit, "STEP_ENVELOPE")
        uint64(step["wall_ns"], "STEP_WALL")
        uint64(step["timeout_seconds"], "STEP_TIMEOUT", 1, 1800)
        for stream in ("stdout", "stderr"):
            require(step[stream] == step["name"] + "." + stream, "STEP_STREAM_IDENTITY")
            if measured and stream == "stdout":
                receipt = exact(compression[step["name"]], ("path", "compressed_bytes", "compressed_sha256", "raw_bytes", "raw_sha256"), "COMPRESSION_FIELDS")
                require(receipt["path"] == step[stream] + ".gz" and same_json(receipt["raw_bytes"], step["stdout_bytes"]) and receipt["raw_sha256"] == step["stdout_sha256"], "COMPRESSION_RAW_BINDING")
                path = bundle_file(directory, receipt["path"], 2 * output_limit + 1024 * 1024)
                require(path.stat().st_size == uint64(receipt["compressed_bytes"], "COMPRESSED_BYTES", 1) and sha(path) == receipt["compressed_sha256"], "COMPRESSED_STREAM_IDENTITY")
                require(not (directory / step[stream]).exists(), "AMBIGUOUS_ORIGINAL_STREAM")
                for _ in verified_raw_stream(path, receipt["raw_bytes"], receipt["raw_sha256"], max_output_bytes=output_limit):
                    pass
            else:
                path = bundle_file(directory, step[stream], output_limit if stream == "stdout" else 4 * 1024 * 1024)
                require(path.stat().st_size == uint64(step[stream + "_bytes"], "STREAM_BYTES") and
                        sha(path) == step[stream + "_sha256"], "CHANGED_RAW_STREAM")
        receipt = bundle_file(directory, step["name"] + ".step.json", 1024 * 1024)
        original = {key: value for key, value in step.items() if key != "command_usage"}
        require(same_json(decode(receipt.read_bytes()), original), "DIVERGENT_STEP_RECEIPT")
        if measured:
            usage = bundle_file(directory, step["name"] + ".usage", 16 * 1024)
            require(same_json(usage_snapshot(usage), step["command_usage"]), "DIVERGENT_USAGE_RECEIPT")
            observed = decode(bundle_file(directory, step["name"] + ".observer.json", 32 * 1024).read_bytes())
            require(same_json(observed, {"usage": step["command_usage"], "usage_error": None,
                                 "original_step_receipt_sha256": sha(receipt),
                                 "observer_sha256": observer["sha256"]}), "DIVERGENT_OBSERVER_RECEIPT")
        result[step["name"]] = step
    return result, Path(cwd)


def read_job(item):
    directory, job = item
    if job["binary"] == "pon_w1_compact_miner_research":
        from w1_compact_miner_reader import read_compact as read_one, options_from_args
    else:
        from w1_late_assembly_reader import read_late as read_one, options_from_args
    result = read_one(Path(directory) / (job["name"] + ".stdout.gz"),
                      expected_options=options_from_args(job["args"]))
    result["job"] = job["name"]
    result["binary"] = job["binary"]
    return result


def read_bundle(directory, *, expected_head, expected_tree, expected_plan_sha256,
                expected_late_binary_sha256, expected_compact_binary_sha256,
                expected_manifest_sha256, replay_workers=1):
    for value, length, name in ((expected_head, 20, "HEAD"), (expected_tree, 20, "TREE"),
                               (expected_plan_sha256, 32, "PLAN"),
                               (expected_late_binary_sha256, 32, "LATE_BINARY"),
                               (expected_compact_binary_sha256, 32, "COMPACT_BINARY"),
                               (expected_manifest_sha256, 32, "MANIFEST")):
        hx(value, length, "EXTERNAL_EXPECTED_" + name)
    uint64(replay_workers, "REPLAY_WORKERS", 1, 4)
    directory = Path(directory).resolve()
    manifest_path = bundle_file(directory, "campaign.json", 8 * 1024 * 1024)
    require(sha(manifest_path) == expected_manifest_sha256, "BUNDLE_MANIFEST_PIN")
    bundle = decode(manifest_path.read_bytes())
    plan_path = bundle_file(directory, "preregistered-plan.json", 1024 * 1024)
    require(sha(plan_path) == expected_plan_sha256 == bundle["plan_sha256"], "BUNDLE_PLAN_PIN")
    plan = decode(plan_path.read_bytes())
    jobs = validate_plan(plan)
    require(plan.get("waited_cpu_endpoint_allowance_ns") == WAITED_CPU_ALLOWANCE_NS and
            plan.get("gnu_time_print_allowance_ns") == GNU_TIME_PRINT_ALLOWANCE_NS,
            "REGISTERED_OBSERVER_ALLOWANCES")
    output_limit = plan["collection_output_limit_bytes"]
    require(bundle["schema"] == SCHEMA and bundle["complete_success"] is True and
            bundle["source_unchanged"] is True and bundle["failure"] is None and
            same_json(bundle["collection_output_limit_bytes"], output_limit), "INCOMPLETE_SOURCE_BOUND_BUNDLE")
    for flag in ("hardness_accepted", "production_activation", "hardware_attested",
                 "independent_hardware_qualification", "prior_campaign_or_service_acceptance_changed"):
        require(bundle[flag] is False, "BUNDLE_AUTHORITY")
    require(bundle["profile"] == "release" and bundle["fresh_target"] is True, "BUILD_PROFILE")
    before, reader_hashes = check_source(bundle, expected_head, expected_tree, expected_plan_sha256)
    reader_source_before = reader_tree_snapshot(expected_head)
    for key in ("compiler", "cargo"):
        exact(bundle[key], ("path", "sha256"), "TOOLCHAIN_FIELDS")
        require(Path(bundle[key]["path"]).is_absolute(), "TOOLCHAIN_PATH")
        hx(bundle[key]["sha256"], 32, "TOOLCHAIN_HASH")
    compiler, cargo = bundle["compiler"]["path"], bundle["cargo"]["path"]
    require(Path(compiler) == Path(cargo).parent / "rustc", "DIRECT_COMPILER_PATH")
    environment = exact(bundle["declared_build_environment"], (
        "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_BUILD_JOBS",
        "CARGO_INCREMENTAL", "PYTHONDONTWRITEBYTECODE",
    ), "BUILD_ENVIRONMENT_FIELDS")
    require(environment["RUSTC"] == compiler and environment["CARGO_NET_OFFLINE"] == "true" and
            environment["CARGO_BUILD_JOBS"] == "2" and environment["CARGO_INCREMENTAL"] == "0" and
            environment["PYTHONDONTWRITEBYTECODE"] == "1" and
            Path(environment["CARGO_HOME"]).is_absolute() and
            Path(environment["CARGO_TARGET_DIR"]).is_absolute(), "BUILD_ENVIRONMENT_BINDING")
    pins = {BINARIES[0]: expected_late_binary_sha256, BINARIES[1]: expected_compact_binary_sha256}
    exact(bundle["binaries"], BINARIES, "BINARY_SET")
    for name, binary in bundle["binaries"].items():
        exact(binary, ("path", "sha256", "bytes", "cargo_artifact"), "BINARY_FIELDS")
        require(binary["sha256"] == pins[name] and Path(binary["path"]) ==
                Path(environment["CARGO_TARGET_DIR"]) / "release/examples" / name, "BINARY_EXTERNAL_PIN")
        uint64(binary["bytes"], "BINARY_BYTES", 1)
    observer = exact(bundle["gnu_time_observer"], ("executable", "sha256", "identity", "observation"), "OBSERVER_FIELDS")
    require(Path(observer["executable"]).is_absolute() and type(observer["identity"]) is str and
            re.match(r"^time \(GNU [Tt]ime\)", observer["identity"]) is not None and
            observer["observation"] == "software-file-snapshot-not-execution-attestation", "OBSERVER_SCOPE")
    hx(observer["sha256"], 32, "OBSERVER_HASH")
    launcher_identity = exact(bundle["taskset"], ("path", "sha256"), "TASKSET_FIELDS")
    require(Path(launcher_identity["path"]).is_absolute() and
            Path(launcher_identity["path"]).name == "taskset", "TASKSET_PATH")
    hx(launcher_identity["sha256"], 32, "TASKSET_HASH")
    hardware = []
    for when in ("before", "after"):
        path = bundle_file(directory, "hardware-" + when + ".json", 4 * 1024 * 1024)
        require(sha(path) == bundle["hardware_" + when + "_sha256"], "HARDWARE_HASH")
        row = decode(path.read_bytes())
        uint64(row["requested_child_cpu"], "CHILD_CPU")
        require(row["requested_child_cpu"] in row["allowed_affinity"] and
                row["hardware_attested"] is False and row["exclusive_cpu"] is False and
                row["energy_joules"] is None and row["network_transfer_measured"] is False, "HARDWARE_SCOPE")
        hardware.append(row)
    require(all(hardware[0][key] == hardware[1][key] for key in
                ("requested_child_cpu", "machine", "cpu_models")), "HARDWARE_CHANGED")
    by_name, root = check_steps(directory, bundle["steps"], jobs, output_limit, observer, bundle["compression"])
    expected_configs = {Path(environment["CARGO_HOME"]) / "config", Path(environment["CARGO_HOME"]) / "config.toml"}
    for ancestor in (root, *root.parents):
        expected_configs.update((ancestor / ".cargo/config", ancestor / ".cargo/config.toml"))
    configurations = bundle["cargo_configurations"]
    require(type(configurations) is list and len(configurations) == len(expected_configs) and
            {row["path"] for row in configurations} == {str(path) for path in expected_configs}, "CARGO_CONFIG_COVERAGE")
    for row in configurations:
        exact(row, ("path", "exists", "sha256"), "CARGO_CONFIG_FIELDS")
        require(row["exists"] is False and row["sha256"] is None, "UNDECLARED_CARGO_CONFIGURATION")
    build = [cargo, "build", "--offline", "--locked", "--release", "--jobs", "2",
             "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--message-format=json"]
    for name in BINARIES:
        build.extend(("--example", name))
    for name, command, timeout in (
        ("preflight", ["bash", "scripts/project-preflight.sh"], 60),
        ("rustc-version", [compiler, "-Vv"], 60),
        ("cargo-version", [cargo, "-Vv"], 60),
        ("metadata", [cargo, "metadata", "--offline", "--locked", "--format-version", "1",
                      "--manifest-path", "trillionnium/Cargo.toml"], 120),
        ("build", build, 1200),
    ):
        require(by_name[name]["command"] == command and by_name[name]["timeout_seconds"] == timeout,
                "SETUP_COMMAND_BINDING:" + name)
    toolchain = (directory / "rustc-version.stdout").read_text()
    require(toolchain == bundle["toolchain"] and toolchain.startswith("rustc 1.95.0 "), "COMPILER_VERSION_RECEIPT")
    preflight = decode((directory / "preflight.stdout").read_bytes())
    require(preflight["result"] == "PASS" and preflight["project"] == "trillionnium-chain" and
            preflight["remote_policy_mutated"] is False and preflight["branch"] == before["branch"], "PREFLIGHT_RECEIPT")
    metadata = decode((directory / "metadata.stdout").read_bytes())
    require(metadata["workspace_root"] == str(root / "trillionnium") and
            metadata["target_directory"] == environment["CARGO_TARGET_DIR"], "CARGO_METADATA_PATHS")
    messages = [decode(line) for line in (directory / "build.stdout").read_bytes().splitlines()]
    for name, binary in bundle["binaries"].items():
        artifacts = [row for row in messages if row.get("reason") == "compiler-artifact" and
                     row.get("target", {}).get("name") == name and row.get("executable")]
        require(len(artifacts) == 1 and same_json(artifacts[0], binary["cargo_artifact"]) and
                artifacts[0]["executable"] == binary["path"] and artifacts[0]["fresh"] is False and
                "example" in artifacts[0]["target"]["kind"] and artifacts[0]["target"]["src_path"] ==
                str(root / "trillionnium/crates/trnm-pon-node/examples" / (name + ".rs")), "CARGO_ARTIFACT_BINDING")
    require(messages and messages[-1].get("reason") == "build-finished" and
            messages[-1].get("success") is True, "CARGO_BUILD_COMPLETION")
    launcher, original_output = None, None
    for job in jobs:
        step, binary = by_name[job["name"]], bundle["binaries"][job["binary"]]
        command = step["command"]
        require(len(command) == 9 + len(job["args"]) and
                command[:4] == [observer["executable"], "-f", "%U %S %M %e", "-o"] and
                Path(command[4]).is_absolute() and Path(command[4]).name == job["name"] + ".usage" and
                command[5] == launcher_identity["path"] and
                command[6:9] == ["-c", str(hardware[0]["requested_child_cpu"]), binary["path"]] and
                command[9:] == job["args"] and step["timeout_seconds"] == job["timeout_seconds"],
                "REGISTERED_JOB_COMMAND_BINDING")
        launcher = command[5] if launcher is None else launcher
        require(command[5] == launcher, "TASKSET_CHANGED")
        original_output = str(Path(command[4]).parent) if original_output is None else original_output
        require(str(Path(command[4]).parent) == original_output, "OUTPUT_DIRECTORY_CHANGED")
    items = [(str(directory), job) for job in jobs]
    if replay_workers == 1:
        results = [read_job(item) for item in items]
    else:
        with ProcessPoolExecutor(max_workers=replay_workers) as pool:
            results = list(pool.map(read_job, items))
    for result in results:
        step = by_name[result["job"]]
        require(result["raw_sha256"] == step["stdout_sha256"], "REPLAY_STREAM_DIFFERS_FROM_PINNED_BYTES")
        result["whole_command_usage"] = step["command_usage"]
        result["whole_waited_child_resources"] = step["whole_waited_child_resources"]
        result["cpu_observer_reconciliation"] = cpu_observer_reconciliation(result, step)
    reader_source_after = reader_tree_snapshot(expected_head)
    require(reader_source_before == reader_source_after, "READER_SOURCE_CHANGED")
    return {
        "schema": "pon-w1-compact-miner-research-derived-v1", "source": before,
        "raw_manifest_sha256": expected_manifest_sha256, "plan_sha256": expected_plan_sha256,
        "binaries": bundle["binaries"], "reader_sha256": sha(__file__), "reader_components": reader_hashes,
        "taskset_software_identity": launcher_identity,
        "complete_reader_source_before": reader_source_before,
        "complete_reader_source_after": reader_source_after,
        "python_version_observation": sys.version,
        "external_identity_pins_checked": True,
        "external_pins_must_come_from_trusted_owner_not_untrusted_bundle": True,
        "jobs": results, "posthoc_replay_workers": replay_workers,
        "posthoc_replay_provides_no_selection_feedback": True,
        "all_retained_full_proof_records_independently_replayed": True,
        "compact_original_miss_records_retained": False,
        "compact_all_deterministic_attempts_independently_recomputed": True,
        "posthoc_reconstructions_have_zero_new_credit": True,
        "record_counts_are_not_unique_ticket_counts": True,
        "native_execution_attested_by_reader": False,
        "native_qualification_independently_reexecuted_by_python": False,
        "miner_budget_endpoint": "complete original winning bytes flushed by B, followed by actual native admission; compact uses production Packet wire, late comparator uses original PNW1/JSON output; all posthoc work has zero new credit",
        "phase_order": ["setup", "miner", "receiver", "audit"],
        "receiver_and_audit_feedback_to_miner": False,
        "setup_budget_is_separate_from_online_miner_budget": True,
        "different_budget_scopes_must_not_share_a_rate_denominator": True,
        "whole_command_maximum_rss_is_not_concurrent_aggregate_memory": True,
        "hardware": hardware, "hardware_attested": False,
        "universal_kappa_bound_established": False, "hardness_accepted": False,
        "production_activation": False, "new_training_qualification": False,
        "energy_joules": None, "network_transfer_measured": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for name in ("head", "tree", "plan-sha256", "late-binary-sha256", "compact-binary-sha256", "manifest-sha256"):
        parser.add_argument("--expected-" + name, required=True)
    parser.add_argument("--replay-workers", type=int, default=1, choices=range(1, 5))
    args = parser.parse_args()
    try:
        require(not args.out.exists(), "OUTPUT_ALREADY_EXISTS")
        keywords = {key: value for key, value in vars(args).items() if key not in ("bundle", "out")}
        result = read_bundle(args.bundle, **keywords)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"jobs": len(result["jobs"]), "all_retained_proofs_replayed": True,
                          "source": result["source"], "hardness_accepted": False}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
