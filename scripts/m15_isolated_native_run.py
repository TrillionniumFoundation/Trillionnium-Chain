#!/usr/bin/env python3
"""Run one real M15 isolated native fixture after its separate static build.

This is an additional explicitly selected gate. It preserves the Rust case's
32-step/180-second/RPC2 limits and does not qualify independent deployment.
No host /etc, account database, existing source or foreign process is modified.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "m15_exact_isolated_support", Path(__file__).with_name("m15_isolated_native_support.py"))
isolated = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(isolated)
support = isolated.support
REPOSITORY = "https://github.com/TrillionniumFoundation/Trillionnium-Chain"
CONTROL_SCRIPTS = ("m15_native_build_support.py", "m15_isolated_native_support.py",
                   "m15_isolated_native_setup.py", "m15_isolated_native_run.py")


class Commands:
    def __init__(self, directory, environment):
        self.directory, self.environment, self.receipts = directory, environment, []

    def run(self, name, argv, cwd, timeout):
        started = time.monotonic_ns()
        out_path, err_path = self.directory / (name + ".stdout"), self.directory / (name + ".stderr")
        child, failure, code = None, None, None
        try:
            with out_path.open("xb") as out, err_path.open("xb") as err:
                child = subprocess.Popen(argv, cwd=cwd, env=self.environment,
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                try:
                    code = child.wait(timeout=timeout)
                except BaseException:
                    # Only this known child session. unshare --kill-child also
                    # tears down its newly owned PID namespace on outer failure.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                    raise
                finally:
                    out.flush()
                    err.flush()
                    os.fsync(out.fileno())
                    os.fsync(err.fileno())
        except Exception as error:
            failure = {"type": type(error).__name__, "message": str(error)}
        receipt = {"argv": list(argv), "cwd": str(cwd), "timeout_seconds": timeout,
                   "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns(),
                   "exit_code": code, "failure": failure,
                   "stdout": support.fingerprint(out_path) if out_path.exists() else {"missing": True},
                   "stderr": support.fingerprint(err_path) if err_path.exists() else {"missing": True}}
        self.receipts.append(receipt)
        support.create(self.directory / (name + ".json"), support.canonical(receipt))
        if failure is not None or code != 0:
            raise RuntimeError("isolated native command failed: " + name)
        return support.read(out_path, 64 * 1024**2)


def verify_native(evidence, artifacts):
    stdout = support.read(evidence / "native.stdout", 64 * 1024**2).decode()
    names = re.findall(r"(?m)^test ([A-Za-z0-9_:]+) \.\.\. ok$", stdout)
    summaries = re.findall(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+$", stdout)
    if names != [isolated.CASE] or len(summaries) != 1 or stdout.count("running 1 test\n") != 1:
        raise ValueError("actual libtest did not execute exactly the original one case successfully")
    result = json.loads(support.read(evidence / "consumer-result.json"), object_pairs_hook=isolated.unique)
    expected = {"schema": "trnm-m15-real-isolated-consumer-result-v1",
        "node_program_sha256": artifacts["node"]["sha256"], "observed_controller_frames": 3,
        "original_maximum_steps": 32, "original_wall_seconds": 180, "service_rpc_seconds": 2,
        "fixture_principals": [1000, 1001], "same_fd_static_exec": True, "single_claim": True,
        "actual_refresh": True, "copied_claim_refused": True, "catalog_next_launch_refused": True,
        "revoked_frame_not_recorded": True, "production_qualified": False,
        "independent_deployment_qualified": False}
    if set(result) != set(expected) | {"actual_pid", "attempt"}:
        raise ValueError("actual consumer report has missing/extra fields")
    if any(type(result[key]) is not type(value) or support.canonical(result[key]) != support.canonical(value)
           for key, value in expected.items()):
        raise ValueError("actual consumer report differs from the fixed scope")
    if type(result["actual_pid"]) is not int or result["actual_pid"] <= 0:
        raise ValueError("actual child PID was not retained")
    if not re.fullmatch(r"[0-9a-f]{64}", result["attempt"]) or result["attempt"] == "0" * 64:
        raise ValueError("actual nonzero signed launch-attempt identity required")
    namespace = json.loads(support.read(evidence / "namespace-result.json"), object_pairs_hook=isolated.unique)
    namespace_fields = {"schema", "exit_code", "failure", "unexpected_owned_process_group",
        "retained_state", "state_error", "original_case_seconds", "original_steps",
        "service_rpc_seconds", "independent_deployment_qualified"}
    if (set(namespace) != namespace_fields
            or namespace["schema"] != "trnm-m15-isolated-native-namespace-result-v1"
            or type(namespace["exit_code"]) is not int or namespace["exit_code"] != 0
            or namespace["failure"] is not None or namespace["state_error"] is not None
            or namespace["unexpected_owned_process_group"] is not False
            or namespace["independent_deployment_qualified"] is not False
            or any(type(namespace[key]) is not int for key in
                   ("original_case_seconds", "original_steps", "service_rpc_seconds"))
            or namespace["original_case_seconds"] != 180 or namespace["original_steps"] != 32
            or namespace["service_rpc_seconds"] != 2):
        raise ValueError("namespace execution/cleanup or remaining-state retention did not complete")
    retained = namespace["retained_state"]
    if (not isinstance(retained, dict) or set(retained) != {"entries", "regular_bytes"}
            or type(retained["entries"]) is not int or not 1 <= retained["entries"] <= 100000
            or type(retained["regular_bytes"]) is not int or not 1 <= retained["regular_bytes"] <= 2 * 1024**3):
        raise ValueError("remaining original fixture state was not retained")
    clocks = json.loads(support.read(evidence / "clock-observations.json"), object_pairs_hook=isolated.unique)
    if not isinstance(clocks, list) or not 1 <= len(clocks) <= 16384:
        raise ValueError("actual signed Clock observation bound differs")
    for row in clocks:
        if (set(row) != {"uid", "request", "challenge", "signed_seconds"}
                or type(row["uid"]) is not int or row["uid"] not in {1000, 1001}
                or type(row["signed_seconds"]) is not int or row["signed_seconds"] < 10000
                or not re.fullmatch(r"[0-9a-f]{64}", row["request"])
                or not re.fullmatch(r"[0-9a-f]{64}", row["challenge"])
                or row["challenge"] == "0" * 64):
            raise ValueError("actual signed Clock observation fields differ")
    if {row["uid"] for row in clocks} != {1000, 1001}:
        raise ValueError("actual two-principal signed Clock traffic was not retained")
    return {"native_cases": 1, "selected": isolated.CASE, "consumer": result,
            "clock_observations": len(clocks), "independent_deployment_qualified": False}


def evidence_inventory(directory):
    rows, total = [], 0
    for current, directories, files in os.walk(directory, followlinks=False):
        directories.sort()
        if any((Path(current) / name).is_symlink() for name in directories):
            raise ValueError("evidence directory may not follow a symlink")
        for name in sorted(files):
            path = Path(current) / name
            record = support.fingerprint(path, 512 * 1024**2)
            total += record["bytes"]
            rows.append({"path": path.relative_to(directory).as_posix(),
                         "sha256": record["sha256"], "bytes": record["bytes"]})
            if len(rows) > 100000 or total > 3 * 1024**3:
                raise ValueError("bounded complete native evidence inventory exceeded")
    return rows


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--artifacts-sha256", required=True)
    parser.add_argument("--tool-inputs", type=Path, required=True)
    parser.add_argument("--tool-inputs-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tmpfs-mebibytes", type=int, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("this verified fixture supports only Linux x86_64")
    if os.getuid() == 0 or os.getgid() == 0 or not sys.flags.isolated:
        raise ValueError("non-root host invocation with the pinned Python -I is required")
    if any(key.startswith(("LD_", "DYLD_")) for key in os.environ):
        raise ValueError("ambient loader injection is not part of this harness")
    repo, output = args.repo.resolve(strict=True), args.output.resolve(strict=False)
    if Path(__file__).resolve() != repo / "scripts/m15_isolated_native_run.py":
        raise ValueError("outer runner must be from the exact reviewed clean source")
    if output.exists() or output.is_relative_to(repo):
        raise ValueError("fresh output outside the source is required")
    if not 256 <= args.tmpfs_mebibytes <= 8192:
        raise ValueError("explicit bounded private tmpfs size required")
    tools, tools_raw, tool_observations = isolated.tools_input(args.tool_inputs, args.tool_inputs_sha256)
    if Path(sys.executable).resolve() != Path(tools["tools"]["python"]["path"]):
        raise ValueError("actual Python is not the pinned setup interpreter")
    if platform.python_version() != tools["python_version"]:
        raise ValueError("actual Python version differs from reviewed tool input")
    artifacts, artifacts_raw = isolated.artifact_input(args.artifacts, args.artifacts_sha256,
                                                       args.expected_head, args.expected_tree)
    required_space = artifacts["tests"]["bytes"] + 3 * artifacts["node"]["bytes"] + 128 * 1024**2
    if args.tmpfs_mebibytes * 1024**2 < required_space:
        raise ValueError("declared private tmpfs cannot contain these actual artifacts")
    output.mkdir(mode=0o700)
    for name in ("root", "evidence", "control", "commands"):
        (output / name).mkdir(mode=0o700)
    environment = {key: os.environ[key] for key in ("HOME", "USER") if key in os.environ}
    helper_directory = str(Path(tools["tools"]["newuidmap"]["path"]).parent)
    environment.update({"PATH": helper_directory + ":/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
    commands = Commands(output / "commands", environment)
    support.create(output / "reviewed-tools.json", tools_raw)
    support.create(output / "reviewed-artifacts.json", artifacts_raw)
    support.create(output / "effective-setup-environment.json", support.canonical(environment))
    success, failure, source_error, observation = False, None, None, None
    before = None
    try:
        commands.run("00-original-preflight", ["bash", "scripts/project-preflight.sh"], repo, 60)
        before = support.full_source(repo, args.expected_head, args.expected_tree)
        if before["origin"] not in {REPOSITORY, REPOSITORY + ".git"}:
            raise ValueError("official clean source origin required")
        support.create(output / "source-before.json", support.canonical(before))
        for number, name in enumerate(("unshare", "mount", "setpriv", "chroot"), 1):
            raw = commands.run(f"{number:02}-{name}-version", [tools["tools"][name]["path"], "--version"], repo, 15)
            lines = raw.decode().splitlines()
            if not lines or lines[0] != tools[name + "_version"]:
                raise ValueError("actual pinned setup tool version differs: " + name)
        controls = []
        for name in CONTROL_SCRIPTS:
            source, destination = repo / "scripts" / name, output / "control" / name
            support.copy_exact(source, destination, 1024**2)
            os.chmod(destination, 0o400)
            controls.append(support.fingerprint(destination, 1024**2))
        runtime_files = [{"destination": entry["destination"],
                          "record": support.fingerprint(entry["source"]["path"], 256 * 1024**2)}
                         for entry in tool_observations["setpriv"]["files"]]
        plan = {"schema": "trnm-m15-isolated-native-plan-v1",
            "host": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid(), "namespaces": isolated.namespaces()},
            "source": {"head": args.expected_head, "tree": args.expected_tree},
            "tools": tools, "tool_observations": tool_observations["files"],
            "runtime_files": runtime_files, "artifacts": artifacts, "control_scripts": controls,
            "root": str(output / "root"), "evidence": str(output / "evidence"),
            "test_selector": isolated.CASE, "tmpfs_bytes": args.tmpfs_mebibytes * 1024**2}
        plan_raw = support.canonical(plan)
        support.create(output / "namespace-plan.json", plan_raw)
        argv = [tools["tools"]["unshare"]["path"], "--user", "--map-root-user",
                f"--map-users=1:{tools['subuid']['start']}:2000",
                f"--map-groups=1:{tools['subgid']['start']}:2000",
                "--setgroups=allow", "--mount", "--pid", "--fork", "--kill-child=KILL",
                "--ipc", "--uts", "--net", "--propagation=private",
                tools["tools"]["python"]["path"], "-I", "-B",
                str(output / "control/m15_isolated_native_setup.py"),
                "--plan", str(output / "namespace-plan.json"), "--plan-sha256", support.sha(plan_raw)]
        # New setup/cleanup bound only; the actual Rust consumer keeps 180s.
        commands.run("05-owned-isolated-native", argv, repo, 240)
        observation = verify_native(output / "evidence", artifacts)
        after = support.full_source(repo, args.expected_head, args.expected_tree)
        support.create(output / "source-after.json", support.canonical(after))
        if before != after:
            raise ValueError("actual source changed during isolated native execution")
        isolated.artifact_input(args.artifacts, args.artifacts_sha256, args.expected_head, args.expected_tree)
        isolated.tools_input(args.tool_inputs, args.tool_inputs_sha256)
        success = True
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        if not (output / "source-after.json").exists():
            try:
                after = support.full_source(repo, args.expected_head, args.expected_tree)
                support.create(output / "source-after.json", support.canonical(after))
            except Exception as error:
                source_error = {"type": type(error).__name__, "message": str(error)}
        try:
            inventory = evidence_inventory(output / "evidence")
            support.create(output / "evidence-manifest.json", support.canonical(inventory))
        except Exception as error:
            success = False
            failure = failure or {"type": type(error).__name__, "message": str(error)}
        support.create(output / "result.json", support.canonical({
            "schema": "trnm-m15-isolated-native-execution-v1", "success": success,
            "failure": failure, "source_after_failure": source_error,
            "observation": observation, "commands": commands.receipts,
            "source": {"head": args.expected_head, "tree": args.expected_tree},
            "original_rust_case_seconds": 180, "original_maximum_steps": 32, "service_rpc_seconds": 2,
            "qualification": "isolated actual consumer execution only" if success else "not qualified",
            "original_complete_native_gates_replaced": False, "independent_deployment_qualified": False}))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
