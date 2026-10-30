#!/usr/bin/env python3
"""One exact-source supplemental campaign; failures never become retried passes.

The receiver and attackers keep the outer 4-CPU/16-GiB experimental cgroup;
the new named client composition uses the original fixed 25%-CPU parent.
This runner never authenticates an independently operated inner parent,
unrestricted Sybil fairness, proof soundness or production activation.
"""
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "scripts/ci")]
import run_pon_w1_native_campaign as bounds
from verify_ci_source import verify
import pure_pon_binary_archive_v1 as binary_archive
import read_pure_fixed_host_client_v1 as fixed_client


TOOLCHAIN = "1.95.0"
NATIVE_GATES = frozenset({"transparent-complete-proof", "pure-runtime", "pure-cli",
                          "native-confirmation-risk", "pressure-observation-contract",
                          "pressure-call-window-contract", "pressure-attacker-cost-contract",
                          "pressure-process-cost-contract", "child-ownership-probe-contract",
                          "pressure-process-peek-contract", "client-profile-contract",
                          "receiver-ipc-deadline-contract", "receiver-owner-contract",
                          "pure-pressure", "receiver-owner-supplement"})
CLIENT_READER_GATES = frozenset({"pure-client-reader", "receiver-client-reader"})
FRESH_NATIVE_GATES = frozenset({"authenticated-caller-observation-contract",
                               "fresh-caller-namespace-contract", "fresh-caller-pressure",
                               "receiver-terminal-failure-contract"})
FRESH_READER_GATES = frozenset({"fresh-caller-environment", "fresh-caller-reader-controls",
                               "fresh-caller-reader", "fresh-caller-client-reader"})
BUILD_OVERRIDES = frozenset(bounds.BUILD_ENV) | {
    "RUSTDOC", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC_BOOTSTRAP",
    "RUSTC_FORCE_UNSTABLE", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
    "CMAKE_TOOLCHAIN_FILE", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER",
}
BUILD_OVERRIDE_PATTERNS = (
    re.compile(r"CARGO_TARGET_.+_(?:RUSTFLAGS|RUSTDOCFLAGS|LINKER|RUNNER|AR)"),
    re.compile(r"CARGO_PROFILE_.+"),
    re.compile(r"(?:HOST_|TARGET_)?(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)(?:_.+)?"),
    re.compile(r"CMAKE_(?:C|CXX|EXE_LINKER|SHARED_LINKER)_FLAGS(?:_.+)?"),
    re.compile(r"DYLD_.+"),
)


def validate_build_environment(environment):
    # An empty override can suppress a configured value, so reject presence,
    # not just truthiness. Report variable names only; values may be sensitive.
    rejected = sorted(name for name in environment if name in BUILD_OVERRIDES
                      or any(pattern.fullmatch(name) for pattern in BUILD_OVERRIDE_PATTERNS))
    bounds.require(not rejected, "UNDECLARED_BUILD_OVERRIDE:" + ",".join(rejected))


def validate_cargo_configuration(environment, root=ROOT):
    # This dedicated campaign uses Cargo defaults and an isolated Cargo home.
    # Cargo's per-target/profile config can override rustc while artifact JSON
    # still describes the manifest profile. Do not silently accept that route.
    root = Path(root).resolve()
    cargo_home = Path(environment.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if not cargo_home.is_absolute():
        cargo_home = root / cargo_home
    folders = {cargo_home.resolve(), *(parent / ".cargo" for parent in (root, *root.parents))}
    present = sorted(str(path) for folder in folders for name in ("config", "config.toml")
                     if (path := folder / name).exists() or path.is_symlink())
    bounds.require(not present, "CARGO_CONFIG_OVERRIDE_NOT_ALLOWED:" + ",".join(present))


def toolchain_identity(rustc_text, cargo_text, machine):
    def parse(text, program):
        lines = text.strip().splitlines()
        bounds.require(bool(lines), "EMPTY_TOOLCHAIN_IDENTITY")
        header = re.fullmatch(rf"{program} 1\.95\.0 \(([0-9a-f]{{9,40}}) (\d{{4}}-\d{{2}}-\d{{2}})\)", lines[0])
        bounds.require(header is not None, "TOOLCHAIN_VERSION_MISMATCH")
        fields = {}
        for line in lines[1:]:
            name, separator, value = line.partition(": ")
            bounds.require(separator and name not in fields and value, "TOOLCHAIN_IDENTITY_FIELDS")
            fields[name] = value
        bounds.require(fields.get("release") == TOOLCHAIN
                       and re.fullmatch(r"[0-9a-f]{40}", fields.get("commit-hash", "")) is not None
                       and fields["commit-hash"].startswith(header.group(1))
                       and fields.get("commit-date") == header.group(2), "TOOLCHAIN_IDENTITY_MISMATCH")
        return fields

    compiler, cargo = parse(rustc_text, "rustc"), parse(cargo_text, "cargo")
    hosts = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu"}
    bounds.require(machine in hosts and compiler.get("host") == cargo.get("host") == hosts[machine],
                   "TOOLCHAIN_NATIVE_HOST_MISMATCH")
    bounds.require(compiler.get("binary") == "rustc" and bool(compiler.get("LLVM version")),
                   "RUSTC_IDENTITY_INCOMPLETE")
    return {"schema": "pon-native-compiler-observation-v1", "rustc": compiler, "cargo": cargo,
            "native_machine": machine, "supply_chain_attestation": False}


def native_verdict(name, process_row, stdout):
    # Match the final harness summary, not an earlier nested run or a printed
    # success string followed by a zero-test outer invocation.
    terminal = stdout.rstrip().splitlines()[-1] if stdout.strip() else ""
    summary = re.fullmatch(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; "
        r"(\d+) filtered out; finished in \d+(?:\.\d+)?s", terminal)
    counts = None if summary is None else dict(zip(
        ("passed", "failed", "ignored", "measured", "filtered_out"), map(int, summary.groups())))
    nonempty = counts is not None and counts["passed"] > 0 and counts["failed"] == 0
    return {"schema": "pon-native-test-verdict-v1", "name": name,
            "process_complete_success": process_row["complete_success"],
            "terminal_summary": counts, "nonempty_test_pass": nonempty,
            "qualified": process_row["complete_success"] and nonempty}


def reader_command(command, fresh_callers=False):
    if fresh_callers and command and command[0] == "python3":
        return [sys.executable, *command[1:]]
    return command


def campaign_success(steps, verdicts, fresh_callers=False):
    native_gates = NATIVE_GATES | (FRESH_NATIVE_GATES if fresh_callers else frozenset())
    reader_gates = CLIENT_READER_GATES | (FRESH_READER_GATES if fresh_callers else frozenset())
    names = [verdict["name"] for verdict in verdicts]
    client_readers = [row.get("name") for row in steps if row.get("name") in reader_gates]
    return (bool(steps) and all(row["complete_success"] is True for row in steps)
            and len(client_readers) == len(reader_gates)
            and set(client_readers) == reader_gates
            and len(names) == len(native_gates) and set(names) == native_gates
            and all(verdict["qualified"] is True for verdict in verdicts))


def terminal_success(steps, verdicts, failure, finalization_failures, fresh_callers=False):
    return (campaign_success(steps, verdicts, fresh_callers) and failure is None
            and not finalization_failures)


def test_artifacts(path, target):
    found = {}
    finished = []
    for line in path.read_bytes().splitlines():
        row = json.loads(line)
        if row.get("reason") == "build-finished":
            finished.append(row.get("success"))
        is_test = row.get("profile", {}).get("test") is True
        is_runtime_binary = row.get("target", {}).get("kind") == ["bin"]
        if (row.get("reason") == "compiler-artifact" and (is_test or is_runtime_binary)
                and row.get("executable")):
            name = row["target"]["name"]
            binary = Path(row["executable"]).resolve(strict=True)
            bounds.require(name not in found, "DUPLICATE_TEST_ARTIFACT")
            bounds.require(binary.is_relative_to(target) and binary.is_file(), "TEST_ARTIFACT_OUTSIDE_TARGET")
            bounds.require(row["profile"]["opt_level"] == "3"
                           and row["profile"]["debug_assertions"] is False,
                           "ORIGINAL_RELEASE_PROFILE_REQUIRED")
            found[name] = {"path": str(binary), "sha256": bounds.sha(binary),
                           "test_harness": is_test,
                           "bytes": binary.stat().st_size, "profile": row["profile"]}
    bounds.require(len(finished) == 1 and finished[0] is True,
                   "COMPLETE_CARGO_BUILD_TERMINAL_REQUIRED")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--client-execution-profile", required=True, choices=[fixed_client.PROFILE])
    parser.add_argument("--fresh-caller-supplement", action="store_true",
                        help="add fresh identities and independent v4 caller/body readback; retain every original gate")
    args = parser.parse_args()
    out, target = args.output.resolve(), args.target.resolve()
    bounds.require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT)
                   and not out.is_relative_to(target) and not target.is_relative_to(out),
                   "ISOLATED_OUTPUT_AND_TARGET_REQUIRED")
    validate_build_environment(os.environ)
    validate_cargo_configuration(os.environ)
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema": ("pon-pure-admission-daa-fresh-caller-v1" if args.fresh_caller_supplement
                          else "pon-pure-admission-daa-fixed-client-v1"), "expected_head": args.expected_head,
              "client_execution_profile": args.client_execution_profile,
              "started_utc": datetime.now(timezone.utc).isoformat(), "steps": [], "binaries": {},
              "native_verdicts": [], "toolchain_observation": None,
              "required_native_gates": sorted(NATIVE_GATES | (
                  FRESH_NATIVE_GATES if args.fresh_caller_supplement else frozenset())),
              "required_client_reader_gates": sorted(CLIENT_READER_GATES | (
                  FRESH_READER_GATES if args.fresh_caller_supplement else frozenset())),
              "source_before": None, "source_after": None, "failure": None,
              "finalization_failures": [], "complete_success": False,
              "automatic_retries": 0, "pressure_phase_seconds": 30,
              "pressure_phases": 3, "attackers_per_attack_phase": 24,
              "outer_pressure_timeout_seconds": 600,
              "public_fairness_qualified": False, "production_activation": False,
              "pq128_qualified": False, "consensus_authority": False,
              "scope": "Exact head, release binaries, two local TCP listeners; shared hosted hardware. Receiver and attackers retain the original four-CPU outer group; only the actual History client uses the original separate fixed Host. The explicit new composition retains every original finite predicate and never relabels historical failures. Conditional model probabilities are not observed chain security."}
    env = {key: value for key, value in os.environ.items() if not key.startswith("TRNM_")}
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true",
               CARGO_INCREMENTAL="0", RUSTUP_TOOLCHAIN="1.95.0", RUST_TEST_THREADS="1",
               PYTHONDONTWRITEBYTECODE="1")
    cargo = [str(args.cargo), "+1.95.0"]

    def step(name, command, timeout, environment=None):
        row = bounds.run_step(out, name, reader_command(command, args.fresh_caller_supplement),
                              environment or env, timeout=timeout)
        result["steps"].append(row)
        return row

    def native(name, binary_name, selectors, timeout=600, environment=None):
        binary = result["binaries"][binary_name]
        bounds.require(bounds.sha(binary["path"]) == binary["sha256"], "TEST_BINARY_CHANGED")
        row = step(name, [binary["path"], *selectors, "--nocapture", "--test-threads=1"],
                   timeout, environment)
        raw = (out / row["stdout"]).read_text()
        verdict = native_verdict(name, row, raw)
        result["native_verdicts"].append(verdict)
        # Keep run_step's original process/timeout terminal immutable. A zero
        # process exit and a failed semantic test gate are distinct facts.
        bounds.write_new(out / (name + ".native-verdict.json"), verdict)
        return verdict

    try:
        result["source_before"] = verify("head", args.expected_head, root=ROOT)
        bounds.write_new(out / "source-before.json", result["source_before"])
        resources = bounds.resource_observation()
        bounds.write_new(out / "resources-before.json", resources)
        bounds.validate_resources(resources, 10)
        if args.fresh_caller_supplement:
            dependency = step("fresh-caller-environment",
                              ["python3", "scripts/ci/check_pure_pon_fresh_caller_v1.py",
                               "--check-environment", "--output", str(out / "fresh-caller-environment.json")], 30)
            bounds.require(dependency["complete_success"], "FRESH_CALLER_READER_ENVIRONMENT_REQUIRED")
            step("fresh-caller-reader-controls",
                 ["python3", "scripts/ci/test_check_pure_pon_fresh_caller_v1.py"], 180)
        compiler = step("rustc-version", [str(args.cargo.parent / "rustup"), "run", TOOLCHAIN,
                                         "rustc", "-Vv"], 30)
        cargo_version = step("cargo-version", [*cargo, "-Vv"], 30)
        bounds.require(compiler["complete_success"] and cargo_version["complete_success"],
                       "TOOLCHAIN_OBSERVATION_FAILED")
        result["toolchain_observation"] = toolchain_identity(
            (out / compiler["stdout"]).read_text(), (out / cargo_version["stdout"]).read_text(),
            platform.machine())
        bounds.write_new(out / "toolchain-observation.json", result["toolchain_observation"])
        step("locked-graph", [*cargo, "metadata", "--locked", "--offline", "--format-version", "1",
                              "--manifest-path", "trillionnium/Cargo.toml"], 120)
        for name, command in (
            ("repository", ["python3", "scripts/ci/check_repository.py"]),
            ("inventory", ["python3", "scripts/refresh_distributed_source_inventory.py", "--check"]),
            ("source-negatives", ["python3", "scripts/ci/test_ci_source_integrity.py"]),
            ("pressure-reader-negatives", ["python3", "scripts/ci/test_check_pure_pon_pressure_v2.py"]),
            ("attacker-cost-reader-negatives", ["python3", "scripts/ci/test_check_pure_pon_attacker_cost_v1.py"]),
            ("process-cost-reader-negatives", ["python3", "scripts/ci/test_check_pure_pon_process_cost_v1.py"]),
            ("receiver-owner-reader-negatives", ["python3", "scripts/ci/test_check_pure_pon_receiver_owner_v1.py"]),
            ("original-history-owner-reader-negatives", ["python3", "scripts/ci/test_native_history_verifier.py"]),
            ("pure-client-reader-negatives", ["python3", "scripts/ci/test_read_pure_fixed_host_client_v1.py"]),
            ("fixed-parent-reader-negatives", ["python3", "scripts/ci/test_history_fixed_parent_v2.py"]),
            ("campaign-runner-negatives", ["python3", "scripts/ci/test_run_pure_pon_admission_daa_v2.py"]),
            ("binary-archive-negatives", ["python3", "scripts/ci/test_pure_pon_binary_archive_v1.py"]),
            ("risk-model-negatives", ["python3", "formal/pon-nakamoto-v1/test_pon_risk_model_v1.py", "-v"]),
            ("risk-model-experiment", ["python3", "formal/pon-nakamoto-v1/pon_risk_model_v1.py"]),
            ("format", [*cargo, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"]),
        ):
            step(name, command, 180)
        common = [*cargo, "test", "--release", "--locked", "--offline", "--manifest-path",
                  "trillionnium/Cargo.toml", "--all-features", "--no-run", "--message-format=json"]
        crypto = step("build-crypto", [*common, "-p", "trnm-crypto-primitives", "--lib"], 1800)
        node = step("build-node", [*common, "-p", "trnm-pon-node", "--lib", "--test", "pure_pon_cli",
                                  "--test", "pon_confirmation_risk_v1", "--test", "pure_pon_pressure_v2"], 1800)
        for build in (crypto, node):
            if build["complete_success"]:
                result["binaries"].update(test_artifacts(out / build["stdout"], target))
        bounds.write_new(out / "binaries.json", result["binaries"])
        if node["complete_success"]:
            # The CLI integration binary launches this separately compiled
            # executable through CARGO_BIN_EXE. Pin it as well as its harness.
            bounds.require("trnm-pon-node" in result["binaries"]
                           and result["binaries"]["trnm-pon-node"]["test_harness"] is False,
                           "NATIVE_CLI_EXECUTABLE_REQUIRED")
        if crypto["complete_success"]:
            native("transparent-complete-proof", "trnm_crypto_primitives", ["pon_work::transparent_admission::"])
        if node["complete_success"]:
            native("pure-runtime", "trnm_pon_node", ["ingress::public_v3::", "host_kernel_parent::"])
            if args.fresh_caller_supplement:
                native("authenticated-caller-observation-contract", "trnm_pon_node", ["authenticated_caller"])
                native("fresh-caller-namespace-contract", "pure_pon_pressure_v2",
                       ["--exact", "fresh_caller_namespace_binds_phase_actor_and_every_call"])
                native("receiver-terminal-failure-contract", "pure_pon_pressure_v2",
                       ["--exact", "receiver_owner::native_receiver_terminal_failure_retains_partial_without_inventing_report"])
            native("pure-cli", "pure_pon_cli", [])
            native("native-confirmation-risk", "pon_confirmation_risk_v1", [])
            native("pressure-observation-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_active_position_keeps_block_height_distinct_from_generation"])
            native("pressure-call-window-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_call_window_refuses_late_entry_without_extending_deadlines"])
            native("pressure-attacker-cost-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_attacker_cost_retains_unissued_preparations_and_unknown_cpu"])
            native("pressure-process-cost-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_actor_wait4_preserves_whole_lifetime_and_single_reap"])
            native("pressure-process-peek-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_actor_terminal_observation_preserves_the_only_wait4_reap"])
            native("client-profile-contract", "pure_pon_pressure_v2",
                   ["--exact", "history_verifier::client_execution_profile_has_no_implicit_pure_relabel"])
            ownership_env = dict(env, TRNM_CHILD_OWNERSHIP_CONTROL_OUT=str(out / "child-ownership-control.json"))
            native("child-ownership-probe-contract", "pure_pon_pressure_v2",
                   ["--exact", "native_child_ownership_probe_distinguishes_live_zombie_and_reaped"],
                   60, ownership_env)
            ipc_env = dict(env, TRNM_RECEIVER_IPC_CONTROL_OUT=str(out / "ipc-deadline-control.json"))
            native("receiver-ipc-deadline-contract", "pure_pon_pressure_v2",
                   ["--exact", "receiver_owner::native_receiver_ipc_deadline_retains_partial_frame"],
                   60, ipc_env)
            control_env = dict(env, TRNM_RECEIVER_OWNER_CONTROL_OUT=str(out / "receiver-owner-control"))
            native("receiver-owner-contract", "pure_pon_pressure_v2",
                   ["--exact", "receiver_owner::native_receiver_owner_isolation_and_shutdown"],
                   60, control_env)
            # Run once. Always retain and independently read failure/partial data.
            pressure_env = dict(env, TRNM_PURE_PRESSURE_V2_OUT=str(out / "pressure-native"))
            native("pure-pressure", "pure_pon_pressure_v2",
                   ["--exact", fixed_client.EXPERIMENTS["pure-pressure"], "--ignored"],
                   600, pressure_env)
            step("pure-client-reader", ["python3", "scripts/ci/read_pure_fixed_host_client_v1.py",
                 str(out / "pressure-native"), "--experiment", "pure-pressure",
                 "--binary-sha256", result["binaries"]["pure_pon_pressure_v2"]["sha256"],
                 "--outer-cgroup", resources["cgroup"],
                 "--output", str(out / "pure-client-readback-v1.json")], 120)
            step("pure-pressure-reader", ["python3", "scripts/ci/check_pure_pon_pressure_v2.py",
                 str(out / "pressure-native"), "--output", str(out / "pressure-qualification.json"),
                 "--require-qualified"], 120)
            # Cost coverage is read even when the unchanged service gate failed.
            # Unknown CPU stays explicit; this separate step cannot qualify
            # service, arbitrary-Sybil fairness or physical work hardness.
            step("pure-attacker-cost-reader", ["python3", "scripts/ci/check_pure_pon_attacker_cost_v1.py",
                 str(out / "pressure-native"), "--output", str(out / "attacker-cost-observation-v1.json"),
                 "--require-observed-cpu"], 120)
            step("pure-process-cost-reader", ["python3", "scripts/ci/check_pure_pon_process_cost_v1.py",
                 str(out / "pressure-native"), "--output", str(out / "process-cost-observation-v2.json"),
                 "--require-observed-cpu", "--require-quiescent-descendants"], 120)
            # Independent receiver-owner experiment, with its own namespace and
            # originals. It never replaces the preceding 90-second campaign.
            receiver_env = dict(env, TRNM_RECEIVER_OWNER_V1_OUT=str(out / "receiver-owner-native"))
            native("receiver-owner-supplement", "pure_pon_pressure_v2",
                   ["--exact", fixed_client.EXPERIMENTS["receiver-owner-supplement"], "--ignored"],
                   600, receiver_env)
            step("receiver-client-reader", ["python3", "scripts/ci/read_pure_fixed_host_client_v1.py",
                 str(out / "receiver-owner-native"), "--experiment", "receiver-owner-supplement",
                 "--binary-sha256", result["binaries"]["pure_pon_pressure_v2"]["sha256"],
                 "--outer-cgroup", resources["cgroup"],
                 "--output", str(out / "receiver-client-readback-v1.json")], 120)
            step("receiver-owner-reader", ["python3", "scripts/ci/check_pure_pon_receiver_owner_v1.py",
                 str(out / "receiver-owner-native"), "--output", str(out / "receiver-owner-observation-v2.json"),
                 "--require-qualified", "--require-observed-cpu", "--require-quiescent-descendants"], 120)
            if args.fresh_caller_supplement:
                # This additional native campaign is not a retry or a replacement
                # for either original failure. Its raw namespace is independent.
                fresh_env = dict(env, TRNM_PURE_PRESSURE_V2_OUT=str(out / "fresh-caller-native"))
                native("fresh-caller-pressure", "pure_pon_pressure_v2",
                       ["--exact", fixed_client.EXPERIMENTS["fresh-caller-pressure"], "--ignored"],
                       600, fresh_env)
                step("fresh-caller-reader", ["python3", "scripts/ci/check_pure_pon_fresh_caller_v1.py",
                     str(out / "fresh-caller-native"), "--output", str(out / "fresh-caller-qualification.json"),
                     "--require-qualified"], 180)
                step("fresh-caller-client-reader", ["python3", "scripts/ci/read_pure_fixed_host_client_v1.py",
                     str(out / "fresh-caller-native"), "--experiment", "fresh-caller-pressure",
                     "--binary-sha256", result["binaries"]["pure_pon_pressure_v2"]["sha256"],
                     "--outer-cgroup", resources["cgroup"],
                     "--output", str(out / "fresh-caller-client-readback-v1.json")], 120)
        # Static validation runs after the pressure, never competes with it.
        step("strict-clippy", [*cargo, "clippy", "--release", "--locked", "--offline",
             "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-crypto-primitives",
             "-p", "trnm-pon-node", "--all-targets", "--all-features", "--", "-D", "warnings"], 1800)
        result["complete_success"] = campaign_success(result["steps"], result["native_verdicts"],
                                                      args.fresh_caller_supplement)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["failure"] = str(error)
    finally:
        try:
            result["source_after"] = verify("head", args.expected_head, root=ROOT)
            bounds.write_new(out / "source-after.json", result["source_after"])
            bounds.require(result["source_before"]["tested_tree"] == result["source_after"]["tested_tree"],
                           "SOURCE_TREE_CHANGED")
            validate_build_environment(os.environ)
            validate_cargo_configuration(os.environ)
            resources = bounds.resource_observation()
            bounds.write_new(out / "resources-after.json", resources)
            bounds.validate_resources(resources, 10)
            for binary in result["binaries"].values():
                bounds.require(bounds.sha(binary["path"]) == binary["sha256"], "TEST_BINARY_CHANGED")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result["finalization_failures"].append(str(error))
        # Observation-only retention after every native stage. The original
        # binaries remain the executables under test; no copy is run. Failed
        # builds/campaigns still retain available identities and failure bytes.
        try:
            tree = (result["source_after"] or result["source_before"] or {}).get("tested_tree")
            archived = binary_archive.retain(out, target, result["binaries"], args.expected_head, tree)
            bounds.require(archived["complete"], "ACTUAL_BINARY_ARCHIVE_INCOMPLETE")
            binary_archive.verify(out, result["binaries"], args.expected_head, tree)
        except (OSError, ValueError, KeyError, TypeError) as error:
            result["finalization_failures"].append(str(error))
        result["complete_success"] = terminal_success(
            result["steps"], result["native_verdicts"], result["failure"], result["finalization_failures"],
            args.fresh_caller_supplement)
        result["completed_utc"] = datetime.now(timezone.utc).isoformat()
        bounds.write_new(out / "results.json", result)
        print(json.dumps(result, sort_keys=True))
    return 0 if result["complete_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
