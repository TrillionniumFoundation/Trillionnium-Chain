#!/usr/bin/env python3
"""Record a separate diagnostic Cargo run of exactly 61 unfinished Node targets.

This is newly authored host evidence, not a recovered cloud receipt and not a
continuation of the original Cargo process. The original 30 complete targets
and their failures remain authoritative for that run. No test-name filters,
ignored-test changes, profile overrides, guard removal, or source edits.
The union remains UNQUALIFIED even if this separate selection exits zero.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time
import traceback

ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
SOURCE = ROOT / "chain-source-bounded"
TOOLS = ROOT / "recovery-evidence-tools"
ORIGINAL = ROOT / "build-receipts/complete-node-690f710c-v1"
OUT = ROOT / "build-receipts/remaining-node-690f710c-v1"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
AUDIT_SHA = "d906a690639ee78b6b38e1a97e27904e1a1b7a540f9206cadbde03aa40adbc70"
INVENTORY_SHA = "e7e2f7e0717cfaa4dc1278f0ef0bec449796c7a738def2fb093ea8b2a38300e5"
CAPTURE_SHA = "5fcee5ec1ce721a7e2dc954f6e5352737e46da8562db06e89245aaaa58fc386f"
RECORDER_SHA = "049c64cf32927bcd16a82059707a468c91d6fc9be7d7abc9047bb3efcd2d8123"
TERMINAL_SHA = "1ad19471b75c6b97570592289ebabe6bd1d486dca60d6bcb794a9dd40137e949"
COMPILER = Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
PREFIX = "trillionnium/crates/trnm-pon-node/"
COUNTS = ("passed", "failed", "ignored", "measured", "filtered_out")
COMPLETE = ("completed_passed", "completed_with_failures")
REMAINING = ("not_observed_started", "incomplete_at_termination")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value):
    return type(value) is int and value >= 0


def read(path):
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read()
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "file changed during read: " + str(path))
    return raw, {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def read_json(path, expected_sha=None):
    raw, fact = read(path)
    if expected_sha is not None:
        require(fact["sha256"] == expected_sha, "unexpected artifact: " + str(path))
    return json.loads(raw), fact


def create(name, raw):
    path = OUT / name
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write(name, value):
    return create(name, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def match(actual, declared, label):
    require(natural(declared.get("bytes")) and actual["bytes"] == declared["bytes"]
            and actual["sha256"] == declared.get("sha256"), "artifact differs: " + label)


def git(*args):
    return subprocess.check_output(
        ["/usr/bin/git", "--no-replace-objects", *args], cwd=SOURCE)


def source():
    require(git("rev-parse", "HEAD").decode().strip() == COMMIT, "source HEAD changed")
    require(git("rev-parse", "HEAD^{tree}").decode().strip() == TREE, "source tree changed")
    require(not git("status", "--porcelain=v1", "-z", "--untracked-files=all"),
            "source worktree is not clean")
    entries, omitted = [], []
    for row in git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        relative = name.decode()
        require(kind == "blob", "non-blob entry: " + relative)
        path = SOURCE / relative
        if not path.exists() and not path.is_symlink():
            require(relative.startswith(("evidence/", "qualification/")),
                    "missing non-archive source: " + relative)
            omitted.append({"path": relative, "mode": mode, "blob": blob})
            continue
        if mode == "120000":
            raw = os.readlink(path).encode()
        else:
            raw, _ = read(path)
            require(bool(path.stat().st_mode & 0o111) == (mode == "100755"),
                    "changed executable mode: " + relative)
        observed = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(observed == blob, "changed tracked bytes: " + relative)
        entries.append({"path": relative, "mode": mode, "blob": blob,
                        "bytes": len(raw), "sha256": sha(raw)})
    require(not git("status", "--porcelain=v1", "-z", "--untracked-files=all"),
            "source became dirty during snapshot")
    payload = {"head": COMMIT, "tree": TREE, "materialized": entries,
               "omitted_historical_archive_blobs": omitted}
    return payload, sha(canonical(payload))


def label(target):
    require(target["source"].startswith(PREFIX), "target outside Node")
    relative = target["source"][len(PREFIX):]
    return relative if target["kind"] == ["test"] else "unittests " + relative


def main():
    OUT.mkdir()
    orchestration_start = time.time()
    inputs = {}
    audit, inputs["original_audit"] = read_json(
        TOOLS / "original-node-failed-inventory-v1.json", AUDIT_SHA)
    inventory, inputs["inventory"] = read_json(
        TOOLS / "node-target-inventory-recovery-v1.json", INVENTORY_SHA)
    capture, inputs["inventory_capture"] = read_json(
        TOOLS / "inventory-capture-recovery-v1.json", CAPTURE_SHA)
    terminal, inputs["original_terminal"] = read_json(
        TOOLS / "original-node-terminal-status.json", TERMINAL_SHA)
    _, inputs["original_recorder"] = read(ROOT / "run_remote_node_gate.py")
    require(inputs["original_recorder"]["sha256"] == RECORDER_SHA, "original recorder changed")
    require(audit["schema"] == "pon-node-failed-observation-inventory-recovery-v1"
            and audit["result"] == "DIAGNOSTIC_RECORDED"
            and audit["qualification"] is False and audit["binding_integrity"] is True
            and audit["errors"] == [], "original audit is not a bound failure diagnostic")
    require(terminal["job_id"] == "1a1b6390138-12894-305"
            and terminal["state"] == "timed_out"
            and type(terminal["exit_code"]) is int and terminal["exit_code"] == 124
            and all(terminal[k] is True for k in (
                "audit_recorded", "output_complete", "output_durable",
                "terminal_publication_confirmed")), "original job not durably timed out")
    require(inventory["source_commit"] == COMMIT and inventory["source_tree"] == TREE,
            "inventory frozen identity")
    match(inputs["inventory"], capture["inventory"], "inventory capture")
    require(type(inventory["target_count"]) is int and inventory["target_count"] == 91,
            "inventory target count")
    targets = inventory["targets"]
    expected = {label(t): t for t in targets}
    require(len(expected) == len(targets) == 91, "duplicate or missing inventory targets")
    coverage = audit["coverage"]
    observed = {row["label"]: row for row in coverage}
    require(len(observed) == len(coverage) == 91 and set(observed) == set(expected),
            "audit target coverage mismatch")
    for name, target in expected.items():
        row = observed[name]
        require(row["target"] == target, "audit target identity differs: " + name)
        require(row["status"] in COMPLETE + REMAINING, "ambiguous target must be reviewed: " + name)
        require((row["summary"] is not None) == (row["status"] in COMPLETE),
                "target completion/summary inconsistent: " + name)
        if row["summary"] is not None:
            require(all(natural(row["summary"][key]) for key in COUNTS),
                    "non-integer target summary: " + name)
            require(row["summary"]["filtered_out"] == 0,
                    "original completed target filtered: " + name)
    selected = [observed[label(t)] for t in targets if observed[label(t)]["summary"] is None]
    completed = [row for row in coverage if row["summary"] is not None]
    require(len(selected) == 61 and len(completed) == 30, "remaining/completed partition changed")
    require(sum(row["status"] == "incomplete_at_termination" for row in selected) == 1,
            "partial-target count changed")
    require([row["target"]["name"] for row in selected
             if row["status"] == "incomplete_at_termination"] == ["model_composition_v4"],
            "partial target changed")
    kind_counts = {kind: sum(row["target"]["kind"] == [kind] for row in selected)
                   for kind in ("lib", "bin", "test", "example")}
    require(kind_counts == {"lib": 0, "bin": 0, "test": 41, "example": 20},
            "remaining target kinds changed")
    totals = {key: sum(row["summary"][key] for row in completed) for key in COUNTS}
    require(totals == audit["completed_target_totals"], "original completed totals differ")

    for name in ("started", "environment", "source_before"):
        path = ORIGINAL / {"started": "started.json", "environment": "environment.json",
                           "source_before": "source-before.json"}[name]
        _, inputs["original_" + name] = read(path)
        match(inputs["original_" + name], inventory["run_inputs"][name], name)
        match(inputs["original_" + name], capture["run_inputs"][name], "capture " + name)
    _, inputs["original_log"] = read(ORIGINAL / "complete-node.log")
    match(inputs["original_log"], audit["inputs"]["log"], "sealed original log")
    original_source = json.loads((ORIGINAL / "source-before.json").read_bytes())
    original_started = json.loads((ORIGINAL / "started.json").read_bytes())
    recorded_env = json.loads((ORIGINAL / "environment.json").read_bytes())
    original_toolchain, inputs["original_toolchain"] = read_json(ORIGINAL / "toolchain.json")
    metadata_path = TOOLS / inventory["metadata"]["path"]
    require(metadata_path.parent == TOOLS, "metadata path is not sibling")
    original_metadata, inputs["original_metadata"] = read_json(metadata_path)
    match(inputs["original_metadata"], inventory["metadata"], "original metadata")
    require(sha(canonical(original_source)) == inventory["source_before_canonical_sha256"]
            == original_started["source_sha256"], "original source canonical binding")
    require(original_source["head"] == COMMIT and original_source["tree"] == TREE,
            "original source identity")
    before, before_sha = source()
    source_before_artifact = write("source-before.json", before)
    require(before_sha == inventory["source_before_canonical_sha256"]
            and before == original_source, "current source differs from original source snapshot")

    # Preserve every inherited variable; only replay the original recorded build
    # environment and the same compiler PATH prefix. No guard variable is removed.
    env = dict(os.environ)
    unexpected = sorted(key for key, value in env.items() if value and
                        (key.startswith("CARGO_PROFILE_") or key in (
                            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")))
    require(not unexpected, "unexpected build overrides: " + repr(unexpected))
    env.update(recorded_env)
    env["PATH"] = str(COMPILER / "bin") + os.pathsep + env.get("PATH", "")
    require(recorded_env["RUSTC"] == str(COMPILER / "bin/rustc")
            and recorded_env["CARGO_TARGET_DIR"] == str(ROOT / "target")
            and recorded_env["CARGO_BUILD_JOBS"] == "2"
            and recorded_env["RUST_TEST_THREADS"] == "1"
            and recorded_env["CARGO_TERM_COLOR"] == "never", "original environment changed")
    environment_artifact = write("environment.json", recorded_env)
    provider, inputs["provider"] = read_json(ROOT / "build-receipts/pq-provider/provider.json")
    require(provider["result"] == "PREPARED_AND_SMOKE_VERIFIED"
            and provider["version"] == "3.5.9" and type(provider["exit_code"]) is int
            and provider["exit_code"] == 0, "provider is not qualified")
    provider_files = []
    for item in provider["native_backend_inputs"]:
        _, actual = read(item["path"])
        match(actual, item, "native provider input")
        provider_files.append(actual)
    cli_raw, cli_identity = read(recorded_env["TRNM_PQ_OPENSSL"])
    require(cli_identity["sha256"] == recorded_env["TRNM_PQ_OPENSSL_SHA256"],
            "provider CLI binding changed")
    provider_env_raw, inputs["provider_env"] = read(ROOT / "build-runtime/provider.env")
    for line in provider_env_raw.decode().splitlines():
        key, value = line.split("=", 1)
        require(recorded_env.get(key) == value, "provider.env disagrees: " + key)
    versions = {
        name: subprocess.check_output([str(COMPILER / "bin" / name), "-vV"],
                                      env=env, text=True)
        for name in ("rustc", "cargo")
    }
    versions["kernel"] = subprocess.check_output(["uname", "-a"], text=True)
    toolchain_artifact = write("toolchain.json", versions)
    require(versions == original_toolchain, "toolchain or kernel differs from original run")

    policy_env = {
        key: {"sha256": sha(value.encode()), "bytes": len(value.encode())}
        for key, value in sorted(os.environ.items())
        if key.startswith(("TRNM_", "PUBLIC_", "CARGO_PROFILE_"))
    }
    process_context = {
        "requested_host_timeout_seconds": 10800,
        "requested_memory_max_bytes": None, "requested_cpu_quota_percent": None,
        "requested_nice": 0, "actual_nice": os.getpriority(os.PRIO_PROCESS, 0),
        "inherited_policy_environment_names_and_hashes": policy_env,
        "inherited_environment_variables_removed": [],
        "profile_or_rustflags_overrides_added": [],
        "full_effective_environment_canonical_sha256": sha(canonical(env)),
        "full_environment_not_retained": "Only a digest; values outside the original build projection may be private.",
        "original_run_full_environment_not_available": True,
        "equivalence_claim": "Same recorded build projection, provider artifacts, compiler, kernel and test flags; not full environmental identity.",
        "fixed_public_kernel_parent_exists": Path("/sys/fs/cgroup/trnmponpublic.slice").exists(),
        "self_cgroup": Path("/proc/self/cgroup").read_text(),
        "qualification": False,
    }
    process_artifact = write("process-context.json", process_context)

    preflight_command = ["/usr/bin/bash", "scripts/project-preflight.sh", "--audit"]
    preflight = subprocess.run(preflight_command, cwd=SOURCE, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    preflight_receipt = {
        "command": preflight_command, "exit_code": preflight.returncode,
        "stdout": create("preflight.stdout.log", preflight.stdout),
        "stderr": create("preflight.stderr.log", preflight.stderr),
    }
    write("preflight.json", preflight_receipt)
    require(preflight.returncode == 0, "preflight failed")

    metadata_command = [str(COMPILER / "bin/cargo"), "metadata", "--locked", "--offline",
                        "--manifest-path", "trillionnium/Cargo.toml",
                        "--all-features", "--format-version", "1"]
    metadata_run = subprocess.run(metadata_command, cwd=SOURCE, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    metadata_artifact = create("cargo-metadata.json", metadata_run.stdout)
    metadata_stderr = create("cargo-metadata.stderr.log", metadata_run.stderr)
    require(metadata_run.returncode == 0, "metadata command failed")
    metadata = json.loads(metadata_run.stdout)
    require(metadata == original_metadata, "actual Cargo graph differs from bound inventory")
    graph = {
        "command": metadata_command, "exit_code": metadata_run.returncode,
        "metadata": metadata_artifact, "stderr": metadata_stderr,
        "identical_to_inventory_metadata": True,
        "workspace_members": len(metadata["workspace_members"]),
        "resolved_packages": len(metadata["packages"]),
        "node_inventory_targets": len(targets),
    }
    graph_artifact = write("cargo-graph.json", graph)

    target_args = []
    selected_rows = []
    for row in selected:
        target = row["target"]
        require(re.fullmatch(r"[A-Za-z0-9_-]+", target["name"]) is not None,
                "invalid target argument")
        require(target["kind"] in (["test"], ["example"]), "unexpected selected target kind")
        flag = "--test" if target["kind"] == ["test"] else "--example"
        target_args.extend((flag, target["name"]))
        selected_rows.append({"label": row["label"], "target": target,
                              "reason": row["status"], "original_summary": None})
    command = [str(COMPILER / "bin/cargo"), "test", "--locked", "--offline",
               "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node",
               *target_args, "--all-features", "--no-fail-fast", "--", "--test-threads=1"]
    selection = {
        "schema": "pon-node-remaining-target-selection-v1",
        "source_commit": COMMIT, "source_tree": TREE,
        "inventory_target_count": 91, "selected_target_count": len(selected),
        "previous_completed_target_count": len(completed), "selected_kind_counts": kind_counts,
        "selected": selected_rows,
        "previous_completed": [{"label": row["label"], "status": row["status"],
                                "summary": row["summary"]} for row in completed],
        "original_audit": inputs["original_audit"], "original_terminal": inputs["original_terminal"],
        "original_completed_target_totals": totals, "cargo_target_args": target_args,
        "command": command, "same_single_cargo_run": False, "qualification": False,
        "policy": "Run every incomplete or not-observed-started target exactly once. Never replace an original completed failure.",
    }
    selection_artifact = write("selection.json", selection)
    _, recorder_before = read(__file__)
    start = time.time()
    started = {
        "schema": "pon-native-remaining-node-start-v1", "command": command,
        "started_unix_seconds": start, "source_sha256": before_sha,
        "expected_commit": COMMIT, "expected_tree": TREE,
        "selection": selection_artifact, "inputs": inputs, "recorder": recorder_before,
        "source_before": source_before_artifact, "environment": environment_artifact,
        "toolchain": toolchain_artifact, "graph": graph_artifact,
        "provider_artifacts": provider_files, "provider_cli": cli_identity,
        "process_context": process_artifact,
        "preflight": preflight_receipt, "qualification": False,
    }
    write("started.json", started)
    print(json.dumps({"result": "REMAINING_SELECTION_STARTED", "directory": str(OUT),
                      "selected_targets": 61, "source_commit": COMMIT,
                      "selection": selection_artifact, "qualification": False}), flush=True)
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (OUT / "remaining-node.log").open("xb") as stream:
        cargo_result = subprocess.run(command, cwd=SOURCE, env=env, stdout=stream,
                                      stderr=subprocess.STDOUT, check=False)
        stream.flush()
        os.fsync(stream.fileno())
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    after_error, after_sha, source_after_artifact = None, None, None
    try:
        after, after_sha = source()
        source_after_artifact = write("source-after.json", after)
    except Exception as failure:
        after_error = {"type": type(failure).__name__, "message": str(failure)}
        write("source-after-error.json", after_error)
    log, log_artifact = read(OUT / "remaining-node.log")
    sqlite = []
    for path in sorted((ROOT / "target/debug/build").glob("trnm-sqlite-io-boundary-*/output")):
        raw, original = read(path)
        retained = create("sqlite-" + path.parent.name + ".txt", raw)
        sqlite.append({"original": original, "retained": retained,
                       "qualified": b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in raw,
                       "unqualified": b"UNQUALIFIED:" in raw})
    changed_inputs = []
    for key, original in inputs.items():
        try:
            _, actual = read(original["path"])
            if actual != original:
                changed_inputs.append({"key": key, "before": original, "after": actual})
        except Exception as failure:
            changed_inputs.append({"key": key, "error": str(failure)})
    _, recorder_after = read(__file__)
    result = {
        "schema": "pon-native-remaining-node-execution-v1",
        "label": OUT.name, "command": command, "exit_code": cargo_result.returncode,
        "started_unix_seconds": start, "elapsed_seconds": time.time() - start,
        "orchestration_elapsed_seconds": time.time() - orchestration_start,
        "child_user_cpu_seconds": usage_after.ru_utime - usage_before.ru_utime,
        "child_system_cpu_seconds": usage_after.ru_stime - usage_before.ru_stime,
        "child_max_rss_kib": usage_after.ru_maxrss,
        "source_before_sha256": before_sha, "source_after_sha256": after_sha,
        "source_unchanged": after_sha == before_sha, "source_after_error": after_error,
        "source_before": source_before_artifact, "source_after": source_after_artifact,
        "selection": selection_artifact, "environment": environment_artifact,
        "toolchain": toolchain_artifact, "graph": graph_artifact,
        "started": read(OUT / "started.json")[1], "inputs": inputs,
        "recorder_before": recorder_before, "recorder_after": recorder_after,
        "recorder_unchanged": recorder_before == recorder_after, "changed_inputs": changed_inputs,
        "log": log_artifact, "sqlite_build_outputs": sqlite,
        "top_level_totals": None,
        "totals_note": "Requires independent Cargo-header coverage attribution. Regex child summaries are not summed here.",
        "selected_target_count": 61, "original_complete_target_count": 30,
        "same_single_cargo_run_as_original": False,
        "qualification": False, "controlled_run_qualification_passed": False,
        "independent_operator": False, "independent_customer": False,
        "physical_model_efficacy": False, "production_activation": False,
        "source_or_original_recorder_modified": False,
    }
    result_artifact = write("result.json", result)
    print(json.dumps({"result": "REMAINING_SELECTION_ENDED", "cargo_exit_code": cargo_result.returncode,
                      "receipt": result_artifact, "log": log_artifact,
                      "source_unchanged": result["source_unchanged"],
                      "qualification": False}), flush=True)
    if cargo_result.returncode:
        return cargo_result.returncode
    return 0 if (result["source_unchanged"] and recorder_before == recorder_after
                 and not changed_inputs and sqlite
                 and all(r["qualified"] and not r["unqualified"] for r in sqlite)) else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as failure:
        diagnostic = {"schema": "pon-native-remaining-node-recorder-error-v1",
                      "type": type(failure).__name__, "message": str(failure),
                      "qualification": False, "traceback": traceback.format_exc()}
        if OUT.is_dir() and not (OUT / "recorder-error.json").exists():
            write("recorder-error.json", diagnostic)
        print(json.dumps(diagnostic), file=sys.stderr, flush=True)
        raise SystemExit(2)
