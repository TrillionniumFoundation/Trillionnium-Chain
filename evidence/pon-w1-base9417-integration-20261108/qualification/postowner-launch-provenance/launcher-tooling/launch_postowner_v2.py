#!/usr/bin/env python3
"""Execute one pinned C8 post-owner qualification only after a retained handoff.

External experiment tooling. This does not change repository source, repair a
failed qualification, dispatch a full History workload, or reuse an output dir.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HEAD = "4e007a87ceecbec8d265f6a70cfd71d512a514b5"
TREE = "19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"
REPO = Path("/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b")
TARGET = Path("/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b")
TOOLS = Path("/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b")
VALIDATION = Path("/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b")
DRIVER_SHA = "d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f"
OWNER_PLAN_SHA = "47185c7eefa4e782478f193c1aaefca7748d957937d3d22616d1fa61fd87ec86"
HELPER_SHA = "434fddeea24ccb11a5975755eef092458c54b526673ef829756e1c727376a563"
STAGES = {
    "historical": {
        "plan": "historical-regressions-plan.json",
        "sha256": "cb6381162e1ad22bb12a5476cafeb9abfd84213e75900c88d05722dcc7f6adb9",
        "out": "exact-historical-regressions-01", "commands": 4,
        "rust": {"passed": 10, "failed": 0, "ignored": 0},
    },
    "history": {
        "plan": "history-local-plan.json",
        "sha256": "a89a9d74df0d974b4831851ab1ac8f1b3a34e166dcd9564d56762894fc72f2ad",
        "out": "exact-history-local-01", "commands": 5,
        "rust": {"passed": 0, "failed": 0, "ignored": 0},
    },
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def integer(value, expected, label):
    require(type(value) is int and value == expected, label)


def regular_bytes(path, maximum=64 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "bounded regular file: " + str(path))
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            require(size <= maximum, "file grew beyond bound: " + str(path))
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed while read: " + str(path))
        require(size == before.st_size, "incomplete read: " + str(path))
        return b"".join(chunks)
    finally:
        os.close(fd)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned_bytes(pin, maximum=64 * 1024 * 1024):
    require(type(pin) is dict and type(pin.get("path")) is str, "pin shape")
    require(type(pin.get("sha256")) is str and re.fullmatch("[0-9a-f]{64}", pin["sha256"]), "pin digest")
    data = regular_bytes(pin["path"], maximum)
    require(sha(data) == pin["sha256"], "pin mismatch: " + pin["path"])
    return data


def pinned_elf(pin):
    require(type(pin) is dict and type(pin.get("path")) is str, "ELF pin shape")
    require(type(pin.get("sha256")) is str and re.fullmatch("[0-9a-f]{64}", pin["sha256"]), "ELF pin digest")
    fd = os.open(pin["path"], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 4 <= before.st_size <= 1024 * 1024 * 1024, "bounded regular ELF")
        digest = hashlib.sha256()
        size = 0
        magic = b""
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            if size == 0:
                magic = block[:4]
            size += len(block)
            require(size <= before.st_size, "ELF grew while read")
            digest.update(block)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "ELF changed while read")
        require(size == before.st_size and magic == b"\x7fELF", "incomplete/invalid ELF")
        require(digest.hexdigest() == pin["sha256"], "ELF pin mismatch")
        if "bytes" in pin:
            integer(pin["bytes"], size, "ELF byte count")
        return {"bytes": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def reject_constant(value):
    raise ValueError("non-finite JSON constant: " + value)


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(pin):
    result = json.loads(pinned_bytes(pin).decode("utf-8"), object_pairs_hook=unique_object,
                        parse_constant=reject_constant, parse_float=finite_float)
    require(type(result) is dict, "JSON object required")
    return result


def terminal(pin, expected_job):
    record = read_json(pin)
    require(record.get("job_id") == expected_job and record.get("state") == "succeeded", "terminal job identity/state")
    integer(record.get("exit_code"), 0, "terminal nonzero/noninteger exit")
    for key in ("output_complete", "output_durable", "terminal_publication_confirmed"):
        require(record.get(key) is True, "terminal incomplete: " + key)
    for key in ("timed_out", "cancelled"):
        require(record.get(key) is False, "terminal timed out/cancelled/unknown: " + key)
    return record


def typed_counts(actual, expected, label):
    require(type(actual) is dict and set(actual) == set(expected), label + " shape")
    for key, count in expected.items():
        integer(actual[key], count, label + ":" + key)


def inspect_manifest(pin, plan_name, plan_sha, out, count, rust):
    manifest = read_json(pin)
    plan = read_json({"path": str(TOOLS / plan_name), "sha256": plan_sha})
    require(manifest.get("schema") == "TRNM-W1-EXACT-SOURCE-QUALIFICATION5", "qualification schema")
    require(plan.get("source_commit") == HEAD and plan.get("source_tree") == TREE, "plan source identity")
    require(plan.get("fresh_cargo_target") is False, "copied/reused target must not become fresh")
    require(manifest.get("source_commit") == HEAD and manifest.get("source_tree") == TREE, "manifest source identity")
    require(manifest.get("repo") == str(REPO) and manifest.get("cargo_target") == str(TARGET), "manifest repo/target")
    require(manifest.get("driver_sha256") == DRIVER_SHA and manifest.get("plan_sha256") == plan_sha, "manifest driver/plan pin")
    require(manifest.get("fresh_cargo_target") is False, "manifest falsely fresh")
    require(manifest.get("cache_basis") == plan.get("cache_basis"), "cache provenance text differs from actual pinned plan")
    require(manifest.get("qualification_complete") is True, "qualification incomplete")
    integer(manifest.get("actual_command_count"), count, "command count")
    integer(manifest.get("python_test_methods_reported"), 0, "unexpected Python test methods")
    typed_counts(manifest.get("rust_test_outcomes"), rust, "Rust aggregate")
    for key in ("production_qualified", "security_qualified", "original_business_budget_qualified",
                "resource_billing_complete", "payment_qualified", "independent_reproducible_build_established"):
        require(manifest.get(key) is False, "unsupported qualification: " + key)
    integer(manifest.get("fresh_proof_generations"), 0, "unexpected proof generation")
    guard = ["python3", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", HEAD, "--output"]
    expected = [("00-preflight", ["bash", "scripts/project-preflight.sh", "--dev"], str(REPO)),
                ("01-source-before", guard + [str(out / "source-before.json")], str(REPO))]
    for index, item in enumerate(plan["commands"], 2):
        argv = [v.replace("@REPO@", str(REPO)).replace("@OUT@", str(out)).replace("@HEAD@", HEAD) for v in item["argv"]]
        expected.append((f"{index:02d}-" + item["label"], argv, str(REPO / item.get("cwd", ""))))
    expected.append(("99-source-after", guard + [str(out / "source-after.json")], str(REPO)))
    commands = manifest.get("commands")
    require(type(commands) is list and len(commands) == count == len(expected), "manifest command inventory")
    totals = {"passed": 0, "failed": 0, "ignored": 0}
    for record, (label, argv, cwd) in zip(commands, expected):
        require(record.get("label") == label and record.get("argv") == argv and record.get("cwd") == cwd, "command tuple: " + label)
        integer(record.get("exit"), 0, "command failed/noninteger: " + label)
        require(record.get("timeout", False) is False, "command timed out: " + label)
        combined = []
        for stream in ("stdout", "stderr"):
            pin = record.get(stream)
            require(type(pin) is dict and pin.get("path") == str(out / (label + "." + stream)), "log path: " + label)
            data = pinned_bytes(pin)
            integer(pin.get("bytes"), len(data), "log byte count: " + label)
            combined.append(data.decode("utf-8"))
        text = "\n".join(combined)
        outcomes = [{"passed": int(p), "failed": int(f), "ignored": int(i)} for p, f, i in
                    re.findall(r"test result: [^.]+\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", text)]
        reported = record.get("rust_test_outcomes")
        require(type(reported) is list and len(reported) == len(outcomes), "raw Rust outcome inventory: " + label)
        for stated, observed in zip(reported, outcomes):
            typed_counts(stated, observed, "raw Rust outcome: " + label)
        require(record.get("python_test_counts") == [], "unexpected Python test count: " + label)
        for outcome in outcomes:
            for key in totals:
                totals[key] += outcome[key]
    typed_counts(totals, rust, "raw Rust aggregate")
    return manifest


def actual_source():
    def git(*args):
        return subprocess.check_output(["git", "--no-optional-locks", *args], cwd=REPO, text=True, timeout=30).strip()
    require(git("rev-parse", "HEAD") == HEAD, "current HEAD changed")
    require(git("rev-parse", "HEAD^{tree}") == TREE, "current tree changed")
    require(git("status", "--porcelain") == "", "current source not clean")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True, choices=STAGES)
    ap.add_argument("--gate", required=True, type=Path)
    ap.add_argument("--gate-sha256", required=True)
    ap.add_argument("--record-dir", required=True, type=Path)
    args = ap.parse_args()
    require(sys.platform == "linux", "Linux required")
    args.record_dir.mkdir(parents=True, exist_ok=False)
    result = {"schema": "TRNM-W1-C8-POSTOWNER-LAUNCH1", "stage": args.stage,
              "source_commit": HEAD, "source_tree": TREE, "driver_launched": False,
              "qualification_complete": False, "started_monotonic_ns": time.monotonic_ns(),
              "gate_path": str(args.gate), "gate_sha256": args.gate_sha256,
              "full_history_executed": False, "fresh_cargo_target": False}
    try:
        gate = read_json({"path": str(args.gate), "sha256": args.gate_sha256})
        require(gate.get("schema") == "TRNM-W1-C8-POSTOWNER-RELEASE1", "release gate schema")
        require(gate.get("source_commit") == HEAD and gate.get("source_tree") == TREE, "release gate identity")
        require(gate.get("target") == str(TARGET), "release target")
        require(gate.get("target_origin") == "copied_c7_owner_and_history_cache", "release target origin")
        require(gate.get("fresh_cargo_target") is False and gate.get("cleanroom") is False, "release provenance")
        require(gate.get("owner_attempt") == "exact-owner-02", "only authorized owner attempt accepted")
        require(gate.get("owner_target_released") is True and gate.get("released_by") == "/root/m12_owner", "owner has not handed off target")
        require(gate.get("root_execution_authorized") is True, "root execution confirmation missing")
        require(type(gate.get("root_confirmation")) is str and bool(gate["root_confirmation"].strip()), "root confirmation record missing")
        terminal(gate["owner_terminal"], gate["owner_job_id"])
        owner_out = Path(gate["owner_manifest"]["path"]).parent
        require(owner_out.name == "exact-owner-02", "wrong owner manifest attempt")
        inspect_manifest(gate["owner_manifest"], "owner-plan.json", OWNER_PLAN_SHA, owner_out, 19,
                         {"passed": 37, "failed": 0, "ignored": 4})
        terminal(gate["strict_import_terminal"], gate["strict_import_job_id"])
        import_record = read_json(gate["strict_import_receipt"])
        require(import_record.get("schema") == "TRNM-W1-TIMEOUT-OWNER-QUALIFICATION1", "strict import receipt schema")
        imported_source = import_record.get("source")
        require(type(imported_source) is dict and imported_source.get("commit") == HEAD and imported_source.get("tree") == TREE, "strict import source identity")
        require(import_record.get("qualification_complete") is True, "strict import incomplete")
        require(import_record.get("current_qualification_job_id") == gate["owner_job_id"], "strict import owner job binding")
        pinned_bytes(import_record["qualification_job_exit"])
        require(import_record.get("cargo_target") == str(TARGET), "strict import target identity")
        require(import_record.get("fresh_cargo_target") is False, "strict import target provenance")
        for key in ("independent_cleanroom_build", "operation_created", "node_executed_by_import", "new_tests_or_cargo_executed_by_import", "deadline_selected"):
            require(import_record.get(key) is False, "unsupported strict import scope: " + key)
        original_pin = import_record.get("original_qualification_manifest")
        require(type(original_pin) is dict and original_pin.get("path") == gate["owner_manifest"]["path"] and original_pin.get("sha256") == gate["owner_manifest"]["sha256"], "strict import original manifest binding")
        integer(original_pin.get("bytes"), len(pinned_bytes(original_pin)), "strict import original manifest bytes")
        binding = read_json(import_record["extracted_binding"])
        require(binding.get("source_commit") == HEAD and binding.get("source_tree") == TREE and binding.get("qualification_complete") is True and binding.get("fresh_cargo_target") is False, "strict import extracted binding")
        integer(import_record.get("actual_command_count"), 19, "strict import command count")
        typed_counts(import_record.get("rust_test_outcomes"), {"passed": 37, "failed": 0, "ignored": 4}, "strict import Rust aggregate")
        integer(import_record.get("raw_log_files_verified"), 38, "strict import raw logs verified")
        integer(import_record.get("raw_log_files_copied"), 38, "strict import raw logs copied")
        require(type(gate.get("owner_elfs")) is list and 1 <= len(gate["owner_elfs"]) <= 8, "owner ELF pins missing")
        for pin in gate["owner_elfs"]:
            require(Path(pin["path"]).resolve(strict=True).is_relative_to(TARGET.resolve(strict=True)), "ELF outside target")
            pinned_elf(pin)
        imported_owner = import_record.get("owner_binary")
        require(type(imported_owner) is dict and any(pin["path"] == imported_owner.get("path") and pin["sha256"] == imported_owner.get("sha256") for pin in gate["owner_elfs"]), "strict import owner ELF binding")
        if args.stage == "history":
            previous = gate["historical_prerequisite"]
            terminal(previous["terminal"], previous["job_id"])
            before = STAGES["historical"]
            inspect_manifest(previous["manifest"], before["plan"], before["sha256"], VALIDATION / before["out"],
                             before["commands"], before["rust"])
        pinned_bytes({"path": str(TOOLS / "qualify_source.py"), "sha256": DRIVER_SHA})
        pinned_bytes({"path": str(TOOLS / "history_compile_list.py"), "sha256": HELPER_SHA})
        selected = STAGES[args.stage]
        plan = read_json({"path": str(TOOLS / selected["plan"]), "sha256": selected["sha256"]})
        require(plan.get("source_commit") == HEAD and plan.get("source_tree") == TREE and plan.get("fresh_cargo_target") is False, "selected plan identity/provenance")
        out = VALIDATION / selected["out"]
        require(not out.exists(), "output already exists; no replay or overwrite")
        actual_source()
        lock = os.open(VALIDATION / "postowner-target.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            argv = ["/usr/bin/python3", "-B", str(TOOLS / "qualify_source.py"), "--repo", str(REPO),
                    "--head", HEAD, "--out", str(out), "--plan", str(TOOLS / selected["plan"]), "--target", str(TARGET)]
            result.update(argv=argv, output=str(out), driver_launched=True)
            (args.record_dir / "before-launch.json").write_text(json.dumps(result, indent=2) + "\n")
            env = os.environ.copy()
            env.pop("PYTHONOPTIMIZE", None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            with (args.record_dir / "driver.stdout").open("xb") as so, (args.record_dir / "driver.stderr").open("xb") as se:
                completed = subprocess.run(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=so, stderr=se)
            result["driver_exit"] = completed.returncode
            integer(completed.returncode, 0, "qualification driver failed; original outputs retained")
            manifest_data = regular_bytes(out / "manifest.json")
            manifest_pin = {"path": str(out / "manifest.json"), "sha256": sha(manifest_data)}
            inspect_manifest(manifest_pin, selected["plan"], selected["sha256"], out,
                             selected["commands"], selected["rust"])
            actual_source()
            for pin in gate["owner_elfs"]:
                pinned_elf(pin)
            if args.stage == "history":
                artifact = read_json({"path": str(out / "history-artifact-and-list.json"),
                                      "sha256": sha(regular_bytes(out / "history-artifact-and-list.json"))})
                require(artifact.get("source_commit") == HEAD and artifact.get("full_history_executed") is False, "History scope")
                integer(artifact.get("test_passes_claimed"), 0, "History list is not a passed test")
                integer(artifact.get("listed_test_count"), 1, "History exact list count")
                integer(artifact.get("list_exit"), 0, "History list exit")
                require(artifact.get("list_argv", [])[-3:] == ["--exact", "--ignored", "--list"], "History execution arguments")
            result.update(manifest=manifest_pin, qualification_complete=True,
                          rust_test_outcomes=selected["rust"], actual_command_count=selected["commands"])
        finally:
            os.close(lock)
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    finally:
        result["finished_monotonic_ns"] = time.monotonic_ns()
        (args.record_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    return 0 if result["qualification_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
