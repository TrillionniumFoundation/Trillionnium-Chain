#!/usr/bin/env python3
"""Run additional component observations only after the unified source is frozen.

Run sequentially AFTER the unchanged 32-command authority runner when sharing
--target. No source edits, fetches, retries, resource/deadline changes or historic
DAA input fallback are performed. --list-commands executes no child process and
creates no output. --fullpath-plan prints the optional extra release/collector
commands only; it does not execute that separate cost observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import types

BASE_RUNNER = "evidence/pq-authority-preflight-20261108-9d315/authority-final-validation-runner.py"
BASE_SHA256 = "d81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710"
NODE_TARGETS = (
    "native_full_relation_context", "work_header_binding",
    "growth_persistence_cancellation", "work_fuzz_semantics",
    "daa_joint_consensus", "daa_adversarial_schedule",
    "native_owner_journal", "native_owner_observation", "native_risk_ledger",
    "native_node",
)
LIB_GROUPS = (
    ("consensus", "consensus::tests"),
    ("legacy-reorg", "store::legacy_reorg_root_tests::"),
    ("reorg-readback", "store::reorg_readback_tests::"),
)
RUST_SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out;.*$", re.M)
RUST_NAME = re.compile(r"^test ([A-Za-z0-9_:]+)( - should panic)? \.\.\. (ok|FAILED|ignored(?:,.*)?)$", re.M)
DAA_EXPORTS = {
    "daa": {"directory": "native-daa", "report": "daa-bounds.json", "packets": 84,
            "producer": "workspace-all-targets", "reader": "scripts/pon_daa_schedule_reader.py"},
    "pnh1": {"directory": "native-joint/pnh1-authenticated", "report": "joint-daa.json", "packets": 114,
             "producer": "workspace-all-targets", "reader": "scripts/pon_joint_daa_reader.py"},
    "pgh2": {"directory": "native-joint/pgh2-growth", "report": "joint-daa.json", "packets": 114,
             "producer": "workspace-all-targets", "reader": "scripts/pon_joint_daa_reader.py"},
}
SCOPE = {
    "qualification": "COMPONENT_OBSERVATION_ONLY",
    "production_activation": False,
    "public_network_qualified": False,
    "original_resource_confirmation_qualified": False,
    "whole_chain_quantum_security_qualified": False,
    "throughput_improvement_demonstrated": False,
    "resource_scope": "shared development host; existing provider and explicit build environment",
    "business_deadline_ns": 4_000_000_000,
    "business_required_depth": 6,
    "process_watchdog_is_not_business_deadline": True,
    "binary_identity_scope": "CARGO_DISPATCH_AND_POST_RUN_FILE_HASH",
    "os_loaded_identity": "NOT_OBSERVED",
}


def load_base(repo: Path):
    path = repo / BASE_RUNNER
    if path.resolve() != path or not path.is_file():
        raise ValueError("reviewed authority runner must be a canonical regular file")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_SHA256:
        raise ValueError("original 32-command authority runner bytes changed")
    module = types.ModuleType("retained_authority_validation")
    module.__file__ = str(path)
    # Compile the bytes already checked, avoiding a second unbound import read.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def spec(label, argv, kind, **extra):
    return {"label": label, "argv": argv, "kind": kind, **extra}


def command_list(base, expected_head: str, out: Path):
    py = [base.PYTHON, "-B"]
    locked = ["--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml"]
    tail = ["--", "--show-output", "--test-threads=1"]
    commands = [
        spec("preflight", ["/bin/bash", "scripts/project-preflight.sh"], "preflight"),
        spec("source-guard-before", py + ["scripts/ci/verify_ci_source.py", "--kind", "head",
             "--expected-head", expected_head, "--output", str(out / "verified-source-before.json")], "source"),
        spec("rustc-version", [str(base.TOOLCHAIN / "bin/rustc"), "-Vv"], "rustc", native=True),
        spec("cargo-version", [base.CARGO, "-V"], "cargo", native=True),
        spec("openssl-version", [str(base.PROVIDER / "bin/openssl"), "version"], "openssl", native=True),
        spec("workspace-metadata", [base.CARGO, "metadata", *locked, "--all-features",
             "--format-version", "1"], "metadata-main", native=True),
        spec("workspace-all-targets", [base.CARGO, "test", *locked, "--workspace", "--all-targets",
             "--all-features", "--no-fail-fast", "--message-format=json-render-diagnostics", *tail],
             "rust-workspace", native=True,
             export_roots=[str(out / "native-joint"), str(out / "native-daa")],
             env={"TRNM_JOINT_DAA_EVIDENCE_DIR": str(out / "native-joint"),
                  "TRNM_DAA_EVIDENCE_DIR": str(out / "native-daa")}),
    ]
    commands.extend([
        spec("capture-identity-tests", py + ["scripts/ci/test_capture_chain_hepta_identity.py", "-v"], "unittest"),
        spec("qualification-gate-tests", py + ["scripts/ci/test_chain_hepta_qualification.py", "-v"], "unittest"),
    ])
    for key, exported in DAA_EXPORTS.items():
        directory = str(out / exported["directory"])
        commands.append(spec("reader-" + key, py + [exported["reader"], "--raw-dir", directory,
                             "--expected-report-sha256", "<fresh-report-sha256>"], "reader", export=key))
        test = ("scripts/ci/test_pon_daa_schedule_reader.py" if key == "daa"
                else "scripts/ci/test_pon_joint_daa_reader.py")
        commands.append(spec("reader-controls-" + key, py + [test, "--raw-dir", directory, "-v"],
                             "unittest", export=key))
        if key == "daa":
            commands.append(spec("daa-head-binding-tests", py + ["scripts/ci/test_pon_daa_head_binding.py",
                                 "--raw-dir", directory, "-v"], "unittest", export=key))
    commands.append(spec("source-guard-after", py + ["scripts/ci/verify_ci_source.py", "--kind", "head",
                         "--expected-head", expected_head, "--output", str(out / "verified-source-after.json")], "source"))
    return commands


def rust_test_rows(text):
    return [{"name": name, "expected_panic": bool(panic), "outcome": outcome}
            for name, panic, outcome in RUST_NAME.findall(text)]


def test_observations(kind: str, stdout: str, stderr: str):
    if kind in ("rust", "rust-workspace"):
        rows = [{"status": r[0], **dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"),
                                          map(int, r[1:])))} for r in RUST_SUMMARY.findall(stdout)]
        names = rust_test_rows(stdout)
        return {"summaries": rows, "tests": names,
                "totals": {key: sum(row[key] for row in rows)
                           for key in ("passed", "failed", "ignored", "measured", "filtered_out")}}
    if kind == "unittest":
        combined = stdout + "\n" + stderr
        counts = [int(n) for n in re.findall(r"^Ran (\d+) tests? in .+$", combined, re.M)]
        endings = re.findall(r"^(OK|FAILED)(?: \(([^\r\n]*)\))?$", combined, re.M)
        terminals, details = [], {}
        for status, raw in endings:
            fields = re.findall(r"(failures|errors|skipped|expected failures|unexpected successes)=(\d+)", raw)
            exact = (not raw or raw == ", ".join(key + "=" + value for key, value in fields))
            unique = len({key for key, _ in fields}) == len(fields)
            terminals.append({"status": status, "raw_details": raw,
                              "fields": fields, "well_formed": exact and unique})
            for key, value in fields:
                details[key] = details.get(key, 0) + int(value)
        return {"reported_test_counts": counts, "outcome_counts": details,
                "terminal_outcomes": terminals,
                "executed_including_expected_failures": counts[-1] - details.get("skipped", 0) if counts else 0,
                "raw_skipped_lines": re.findall(r"^.* \.\.\. skipped.*$", combined, re.M)}
    return {}


def workspace_observations(stdout, executed, metadata):
    """Bind actual harnesses to Cargo artifacts, retaining failures and omissions.

    Cargo's machine-readable build messages identify package/target/binary. The
    separate stderr Running records identify which binaries Cargo dispatched.
    A mismatch with stdout harness boundaries remains an ambiguity, never PASS.
    """
    result = test_observations("rust-workspace", stdout, "")
    artifacts, artifact_errors = {}, []
    for line in stdout.splitlines():
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if (not isinstance(value, dict) or value.get("reason") != "compiler-artifact"
                or not value.get("executable") or value.get("profile", {}).get("test") is not True):
            continue
        path = str(Path(value["executable"]).resolve())
        description = {"package_id": value["package_id"], "target": value["target"],
                       "profile": value["profile"], "fresh": value.get("fresh"),
                       "executable": path}
        if path in artifacts and artifacts[path] != description:
            artifact_errors.append("conflicting compiled artifact for " + path)
        artifacts[path] = description
    packages = {item["id"]: item["name"] for item in (metadata or {}).get("packages", [])}
    members = set((metadata or {}).get("workspace_members", []))
    summaries = list(RUST_SUMMARY.finditer(stdout))
    unambiguous = bool(summaries) and len(summaries) == len(executed) and not artifact_errors
    harnesses, cursor = [], 0
    for index, match in enumerate(summaries):
        summary = result["summaries"][index]
        text = stdout[cursor:match.start()]
        cursor = match.end()
        names = rust_test_rows(text)
        announced = [int(value) for value in re.findall(r"^running (\d+) tests?$", text, re.M)]
        counts = {"passed": sum(row["outcome"] == "ok" for row in names),
                  "failed": sum(row["outcome"] == "FAILED" for row in names),
                  "ignored": sum(row["outcome"].startswith("ignored") for row in names)}
        reconcile = (len(announced) == 1 and announced[0] == len(names)
                     and len({row["name"] for row in names}) == len(names)
                     and all(summary[key] == value for key, value in counts.items()))
        binary = executed[index] if unambiguous else None
        artifact = artifacts.get(binary["path"]) if binary else None
        if artifact is None:
            reconcile = False
        ran = summary["passed"] + summary["failed"]
        state = ("FAIL" if summary["status"] != "ok" or summary["failed"] else
                 "NO_TESTS" if not ran and not summary["ignored"] else
                 "IGNORED" if not ran else "PASS")
        harnesses.append({"index": index, "status": state,
                          "executed_tests": ran, "counts_reconcile": reconcile,
                          "summary": summary, "tests": names, "binary": binary,
                          "artifact": artifact,
                          "package": packages.get(artifact["package_id"]) if artifact else None})
    trailing_markers = [line for line in stdout[cursor:].splitlines()
                        if line.startswith(("running ", "test "))]
    assigned_names = [name for row in harnesses for name in row["tests"]]
    all_running = re.findall(r"^running (\d+) tests?$", stdout, re.M)
    flow_conserved = (assigned_names == result["tests"]
                      and len(all_running) == len(harnesses) and not trailing_markers)
    unambiguous = unambiguous and all(row["counts_reconcile"] for row in harnesses) and flow_conserved
    roster = {}
    for target in NODE_TARGETS:
        matches = [row for row in harnesses if row["package"] == "trnm-pon-node" and row["artifact"]
                   and row["artifact"]["target"]["name"] == target
                   and "test" in row["artifact"]["target"]["kind"]]
        roster["node-test:" + target] = {"matching_harnesses": [row["index"] for row in matches],
            "executed_tests": sum(row["executed_tests"] for row in matches),
            "present_and_executed": len(matches) == 1 and matches[0]["executed_tests"] > 0}
    for package, label, prefix in [("trnm-crypto-primitives", "kernel-pon-work", "pon_work::"),
                                   *(("trnm-pon-node", label, group) for label, group in LIB_GROUPS)]:
        matches = [row for row in harnesses if row["package"] == package and row["artifact"]
                   and "lib" in row["artifact"]["target"]["kind"]]
        namespace = prefix if prefix.endswith("::") else prefix + "::"
        names = [item for row in matches for item in row["tests"] if item["name"].startswith(namespace)]
        ran = sum(item["outcome"] in ("ok", "FAILED") for item in names)
        roster["unit-group:" + label] = {"matching_harnesses": [row["index"] for row in matches],
            "tests": names, "executed_tests": ran,
            "present_and_executed": len(matches) == 1 and ran > 0}
    observed_packages = {row["artifact"]["package_id"] for row in harnesses if row["artifact"]}
    compiled_tests = set(artifacts)
    dispatched = {row["path"] for row in executed}
    result.update(
        harnesses=harnesses, compiled_test_artifacts=list(artifacts.values()), artifact_errors=artifact_errors,
        execution_order_unambiguous=unambiguous,
        compiled_but_not_dispatched=sorted(compiled_tests - dispatched),
        dispatched_without_compiler_identity=sorted(dispatched - compiled_tests),
        required_roster=roster,
        required_roster_complete=unambiguous and all(row["present_and_executed"] for row in roster.values()),
        workspace_harness_inventory_covered=bool(members) and members <= observed_packages
            and compiled_tests == dispatched,
        workspace_members=[],
        stdout_control_flow_conserved=flow_conserved,
        unattributed_trailing_markers=trailing_markers,
        zero_test_harnesses=[row["index"] for row in harnesses if row["status"] == "NO_TESTS"],
        fully_ignored_harnesses=[row["index"] for row in harnesses if row["status"] == "IGNORED"],
    )
    for key in sorted(members):
        owned = [row for row in harnesses if row["artifact"] and row["artifact"]["package_id"] == key]
        passed = sum(row["summary"]["passed"] for row in owned)
        failed = sum(row["summary"]["failed"] for row in owned)
        ignored = sum(row["summary"]["ignored"] for row in owned)
        state = ("NOT_OBSERVED" if not owned else "FAIL" if failed else
                 "PASS" if passed else "IGNORED" if ignored else "NO_TESTS")
        result["workspace_members"].append({"id": key, "package": packages.get(key),
            "harness_observed": bool(owned), "harness_count": len(owned),
            "executed_tests": passed + failed, "passed": passed, "failed": failed, "ignored": ignored,
            "zero_test_harnesses": sum(row["status"] == "NO_TESTS" for row in owned),
            "execution_status": state})
    return result


def validate_readback(base, item, stdout, stderr, repo, observed, export):
    kind = item["kind"]
    if kind == "rust-workspace":
        if not observed.get("execution_order_unambiguous"):
            raise ValueError("workspace harness/readback order is ambiguous or incomplete")
        if not observed.get("required_roster_complete"):
            raise ValueError("required native targets/kernel/unit groups were absent or executed zero tests")
        if not observed.get("workspace_harness_inventory_covered"):
            raise ValueError("workspace member execution inventory is incomplete")
        if observed["totals"]["passed"] <= 0 or observed["totals"]["failed"]:
            raise ValueError("workspace tests reported zero passes or actual failures")
        for harness in observed["harnesses"]:
            if not harness["counts_reconcile"] or harness["summary"]["filtered_out"] or harness["summary"]["measured"]:
                raise ValueError("workspace target counts disagree, filter tests or include measurements")
            if harness["summary"]["status"] != "ok":
                raise ValueError("workspace native harness reported failure")
        return {"required_roster_complete": True, "workspace_harness_inventory_covered": True,
                "zero_test_harnesses": observed["zero_test_harnesses"],
                "fully_ignored_harnesses": observed["fully_ignored_harnesses"],
                "scope": "native Cargo success over the recorded executed scope; NO_TESTS is never PASS"}
    if kind == "unittest":
        if len(observed["reported_test_counts"]) != 1:
            raise ValueError("exactly one unambiguous Python suite summary required")
        endings = observed["terminal_outcomes"]
        if (len(endings) != 1 or endings[0]["status"] != "OK" or not endings[0]["well_formed"]
                or any(observed["outcome_counts"].get(key, 0)
                       for key in ("failures", "errors", "unexpected successes"))):
            raise ValueError("one successful Python terminal with no failed outcomes required")
        if observed["executed_including_expected_failures"] <= 0:
            raise ValueError("zero executed Python tests cannot pass, including all-skipped suites")
        return base.validate_output(kind, stdout, stderr, repo)
    if kind != "reader":
        return base.validate_output(kind, stdout, stderr, repo)
    result = base.validate_output("json", stdout, stderr, repo)
    schema = ("pon-native-daa-bounds-reader-v1" if item["export"] == "daa"
              else "pon-native-joint-daa-reader-v1")
    if result.get("schema") != schema:
        raise ValueError("reader schema does not match the selected current verifier")
    required_false = ["reader_performed_native_admission", "reader_reopened_native_database",
                      "host_and_source_provenance_checked_by_reader", "public_network_qualification"]
    if item["export"] == "daa":
        required_false.append("proof_hardness_or_timestamp_attack_profitability_qualified")
    else:
        required_false.extend(["proof_hardness_or_quantum_attack_profitability_qualified",
                               "reader_verified_aam1_account_proofs",
                               "reader_replayed_native_task_eligibility_or_m06_execution"])
        profile = "PNH1" if item["export"] == "pnh1" else "PGH2"
        if result.get("header_profile") != profile or result.get("backend") != Path(export["directory"]).name:
            raise ValueError("reader profile differs from the fresh selected native export")
    if (result.get("record_and_oracle_consistency") != "PASS"
            or result.get("full_python_transcript_and_product_recomputed") is not True
            or ("production_activation" in result and result["production_activation"] is not False)
            or any(result.get(key) is not False for key in required_false)
            or type(result.get("unique_full_python_verified_proofs")) is not int
            or result["unique_full_python_verified_proofs"] != export["packet_count"]
            or result.get("report_sha256") != export["report"]["sha256"]):
        raise ValueError("reader consistency, proof count, digest or limited authority changed")
    identities = {name: {"sha256": row["sha256"], "bytes": row["bytes"]}
                  for name, row in export["files"].items() if name.startswith("packets/")}
    if result.get("packet_identities") != identities:
        raise ValueError("reader packet identity set differs from the fresh export manifest")
    return result


def export_manifest(base, out: Path, key: str):
    entry = DAA_EXPORTS[key]
    directory = out / entry["directory"]
    if directory.resolve() != directory or not directory.is_dir():
        raise ValueError("fresh native export directory missing or noncanonical")
    if set(p.name for p in directory.iterdir()) != {entry["report"], "packets"}:
        raise ValueError("unexpected or incomplete native export root inventory")
    packets = directory / "packets"
    if packets.resolve() != packets or not packets.is_dir():
        raise ValueError("fresh native packet directory missing or noncanonical")
    paths = sorted(packets.iterdir())
    if len(paths) != entry["packets"] or any(re.fullmatch(r"[0-9a-f]{64}\.pnk", p.name) is None for p in paths):
        raise ValueError("fresh native packet count or filename inventory differs")
    records = {str(path.relative_to(directory)): base.file_record(path)
               for path in [directory / entry["report"], *paths]}
    return {"directory": str(directory), "producer": entry["producer"],
            "packet_count": len(paths), "report": records[entry["report"]], "files": records}


def native_executables(base, stderr, repo, target):
    records = []
    for display, spelling in re.findall(r"^\s*Running\s+(.+?)\s+\(([^\r\n]+)\)\s*$", stderr, re.M):
        path = Path(spelling)
        if not path.is_absolute():
            path = repo / path
        path = path.resolve(strict=True)
        if not path.is_relative_to(target):
            raise ValueError("Cargo reported an executed test binary outside the selected target")
        records.append({"cargo_display": display, **base.file_record(path),
                        "binary_identity_scope": "CARGO_DISPATCH_AND_POST_RUN_FILE_HASH",
                        "os_loaded_identity": "NOT_OBSERVED"})
    return records


def run_command(base, item, repo, target, out, env, export=None, metadata=None):
    label, argv = item["label"], item["argv"]
    stdout_path, stderr_path = out / (label + ".stdout.log"), out / (label + ".stderr.log")
    row = {"label": label, "argv": argv, "kind": item["kind"], "cwd": str(repo),
           "expected_head": env["TRNM_EXTRA_EXPECTED_HEAD"], "passed": False, "status": "UNKNOWN",
           "exit_code": None, "started_unix_seconds": time.time(), "environment_additions": item.get("env", {})}
    if export is not None:
        row["fresh_export"] = {"directory": export["directory"], "producer": export["producer"],
                               "report_sha256": export["report"]["sha256"]}
    start = time.monotonic()
    print(json.dumps({"starting": label, "argv": argv}), flush=True)
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            child = subprocess.Popen(argv, cwd=repo, env={**env, **item.get("env", {})},
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            row["pid"] = child.pid
            try:
                row["exit_code"] = child.wait(timeout=base.TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                row["exit_code"] = child.returncode
        stdout = stdout_path.read_text(errors="replace")
        stderr = stderr_path.read_text(errors="replace")
        if row["exit_code"] != 0 and not row.get("timed_out"):
            row["status"] = "FAIL"
        row["test_observations"] = test_observations(item["kind"], stdout, stderr)
        if item["kind"] == "rust-workspace":
            row["native_test_executables"] = native_executables(base, stderr, repo, target)
            row["test_observations"] = workspace_observations(
                stdout, row["native_test_executables"], metadata)
        if row["exit_code"] == 0 and not row.get("timed_out"):
            row["readback"] = validate_readback(base, item, stdout, stderr, repo, row["test_observations"], export)
            row.update(passed=True, status="PASS")
        elif not row.get("timed_out"):
            row["status"] = "FAIL"
    except Exception as error:
        row["error"] = f"{type(error).__name__}: {error}"
        if row["exit_code"] == 0:
            row["status"] = "FAIL"
    row["elapsed_seconds"] = time.monotonic() - start
    row["finished_unix_seconds"] = time.time()
    row["logs"] = {p.name: base.file_record(p) for p in (stdout_path, stderr_path) if p.is_file()}
    base.save(out / (label + ".receipt.json"), row)
    print(json.dumps({"finished": label, "status": row["status"], "exit_code": row["exit_code"]}), flush=True)
    return row


def blocked(base, item, out, reason):
    row = {"label": item["label"], "argv": item["argv"], "kind": item["kind"],
           "passed": False, "status": "BLOCKED", "exit_code": None, "blocked": reason}
    base.save(out / (item["label"] + ".receipt.json"), row)
    return row


def validate_paths(repo, target, out):
    for path in (repo, target, out):
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError("source, target and output must use canonical absolute paths")
    for a, b in ((repo, target), (repo, out), (target, out)):
        if a.is_relative_to(b) or b.is_relative_to(a):
            raise ValueError("source, output and target must be disjoint trees")
    if not repo.is_dir() or out.exists() or out.is_symlink():
        raise ValueError("source must exist and output must be fresh")


def fullpath_plan(base, repo, head, target, out):
    directory = out / "fullpath-cost-observation"
    return {"scope": SCOPE, "executed": False, "requires_extra_release_build": True,
            "commands": [
                [base.CARGO, "build", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
                 "-p", "trnm-pon-node", "--release", "--example", "native_fullpath_v1"],
                [base.PYTHON, "-B", "formal/pon-native-fullpath-v1/collect_native.py", "--repo", str(repo),
                 "--expected-source", head, "--binary", str(target / "release/examples/native_fullpath_v1"),
                 "--output", str(directory)],
                [base.PYTHON, "-B", "formal/pon-native-fullpath-v1/adapt_native.py", str(directory),
                 "--preregistration-sha256", "<sha256 of THIS fresh preregistration.json>"],
            ], "adapter_normal_exit": 1,
            "constraints": ["original four offered starts, full proof and adversarial cases unchanged",
                            "collector process timeout remains its original 60 seconds",
                            "4-second/depth-six business checks unchanged",
                            "new collector output; retain every subprocess stdout/stderr and identity",
                            "adapter exit 1 and all HOLD/FAIL findings must remain visible"],
            "available_cost_fields": {"cpu": "parent+children rusage CPU nanoseconds",
                                      "memory": "parent plus historical child RSS peak upper bound",
                                      "ipc_bytes": "parent-observed stdin packet bytes; not WAN traffic",
                                      "phase_times": "native event and process observations"},
            "unknown_cost_fields": ["WAN bytes and delays", "disk IO cost attribution",
                                    "lock cost", "queue cost attribution", "same-security throughput improvement"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "target", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--list-commands", action="store_true")
    parser.add_argument("--fullpath-plan", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_head):
        parser.error("expected head must be the full lowercase SHA-1")
    try:
        if any(not path.is_absolute() for path in (args.repo, args.target, args.out)):
            raise ValueError("absolute paths required")
        base = load_base(args.repo)
        commands = command_list(base, args.expected_head, args.out)
        if args.fullpath_plan:
            print(json.dumps(fullpath_plan(base, args.repo, args.expected_head, args.target, args.out), indent=2))
            return 0
        if args.list_commands:
            print(json.dumps({"executed": False, "scope": SCOPE, "commands": commands}, indent=2))
            return 0
        validate_paths(args.repo, args.target, args.out)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    args.out.mkdir(parents=True, exist_ok=False)
    env = base.environment(args.target)
    env["TRNM_EXTRA_EXPECTED_HEAD"] = args.expected_head
    base.save(args.out / "environment.json", env)
    base.save(args.out / "commands.json", commands)
    runner = Path(__file__).resolve()
    (args.out / "run-extra-native.py").write_bytes(runner.read_bytes())
    report = {"schema": "trnm-unified-extra-native-v1", **SCOPE, "components_passed": False,
              "expected_head": args.expected_head, "repo": str(args.repo), "target": str(args.target),
              "runner": base.file_record(args.out / "run-extra-native.py"),
              "base_runner": base.file_record(args.repo / BASE_RUNNER),
              "shared_target_requires_sequential_original32_then_extra": True,
              "process_watchdog_seconds": base.TIMEOUT_SECONDS,
              "commands": [], "failures": [], "fresh_exports": {},
              "optional_fullpath_cost_observation": {"status": "UNKNOWN", "executed": False}}
    before = provider_before = None
    admission = native_ready = False
    exports = {}
    metadata = None
    completed = set()
    try:
        before = base.source_identity(args.repo, env)
        base.save(args.out / "source-before.json", before)
        if before["head"] != args.expected_head or before["status"]:
            raise ValueError("initial HEAD must match and tracked/index/untracked source must be clean")
        for item in commands[:2]:
            row = run_command(base, item, args.repo, args.target, args.out, env)
            report["commands"].append(row); completed.add(item["label"])
            if not row["passed"]:
                raise ValueError("initial preflight/raw-source admission failed")
        admission = True
        try:
            provider_before = base.provider_identity()
            base.save(args.out / "provider-before.json", provider_before)
            native_ready = True
        except Exception as error:
            report["failures"].append("provider admission: " + str(error))
        for original in commands[2:-1]:
            item = {**original, "argv": original["argv"][:]}
            export = None
            if item.get("native") and not native_ready:
                row = blocked(base, item, args.out, "native provider/toolchain admission failed")
            elif item["kind"] == "rust-workspace" and metadata is None:
                row = blocked(base, item, args.out, "current complete workspace metadata unavailable")
            elif item.get("export") and item["export"] not in exports:
                row = blocked(base, item, args.out, "this run has no complete fresh native export")
            else:
                if item.get("export"):
                    export = exports[item["export"]]
                    if export_manifest(base, args.out, item["export"]) != export:
                        raise ValueError("fresh native export changed before reader execution")
                    item["argv"] = [export["report"]["sha256"] if value == "<fresh-report-sha256>" else value
                                    for value in item["argv"]]
                fresh = [Path(value) for value in item.get("export_roots", [])]
                if any(path.exists() or path.is_symlink() for path in fresh):
                    row = blocked(base, item, args.out, "native output was not absent before its only producer")
                else:
                    row = run_command(base, item, args.repo, args.target, args.out, env, export, metadata)
            report["commands"].append(row); completed.add(item["label"])
            if item["kind"] in ("rustc", "cargo", "openssl") and not row["passed"]:
                native_ready = False
            if item["kind"] == "metadata-main" and row["passed"]:
                metadata = json.loads((args.out / (item["label"] + ".stdout.log")).read_text())
            for key, definition in DAA_EXPORTS.items():
                if definition["producer"] != item["label"] or row["status"] == "BLOCKED":
                    continue
                try:
                    exports[key] = export_manifest(base, args.out, key)
                    base.save(args.out / ("fresh-export-" + key + ".json"), exports[key])
                    report["fresh_exports"][key] = {"manifest": "fresh-export-" + key + ".json",
                        "producer_exit_code": row["exit_code"], "producer_passed": row["passed"]}
                except Exception as error:
                    report["failures"].append("fresh export " + key + ": " + str(error))
            base.save(args.out / "summary.json", report)
    except Exception as error:
        report["failures"].append(f"{type(error).__name__}: {error}")
    finally:
        for item in commands[:-1]:
            if item["label"] not in completed:
                report["commands"].append(blocked(base, item, args.out, "source admission or runner stopped before dispatch"))
        # The raw-source guard is attempted after both successful and failed native work.
        report["commands"].append(run_command(base, commands[-1], args.repo, args.target, args.out, env))
        try:
            after = base.source_identity(args.repo, env)
            base.save(args.out / "source-after.json", after)
            report["source_unchanged"] = before is not None and after == before and after["head"] == args.expected_head and not after["status"]
            if not report["source_unchanged"]:
                report["failures"].append("HEAD/tree/index/lockfiles/clean source identity changed")
            load_base(args.repo)
        except Exception as error:
            report["failures"].append("final source/helper observation: " + str(error))
        try:
            provider_after = base.provider_identity()
            base.save(args.out / "provider-after.json", provider_after)
            report["provider_unchanged"] = provider_before is not None and provider_after == provider_before
            if not report["provider_unchanged"]:
                report["failures"].append("provider changed or initial provider admission failed")
        except Exception as error:
            report["failures"].append("final provider observation: " + str(error))
        try:
            sqlite = base.sqlite_qualification(args.target, args.out)
            base.save(args.out / "sqlite-qualification.json", sqlite)
            if not sqlite["passed"]:
                report["failures"].append("SQLite qualification markers missing or unqualified")
        except Exception as error:
            report["failures"].append("SQLite observation: " + str(error))
        for key, manifest in exports.items():
            try:
                after = export_manifest(base, args.out, key)
                base.save(args.out / ("fresh-export-" + key + "-after.json"), after)
                if after != manifest:
                    report["failures"].append("fresh export changed during independent readback: " + key)
            except Exception as error:
                report["failures"].append("final fresh export " + key + ": " + str(error))
        report["components_passed"] = (admission and len(report["commands"]) == len(commands)
            and all(row["passed"] for row in report["commands"]) and not report["failures"])
        report["finished_unix_seconds"] = time.time()
        base.save(args.out / "summary.json", report)
        print(json.dumps({"qualification": report["qualification"], "production_activation": False,
              "components_passed": report["components_passed"], "summary": str(args.out / "summary.json"),
              "failed_or_unknown_commands": [row["label"] for row in report["commands"] if not row["passed"]],
              "failures": report["failures"]}), flush=True)
    return 0 if report["components_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
