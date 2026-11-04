#!/usr/bin/env python3
"""Generate a fuzz-only lock with real Cargo after reproducing --locked refusal.

No package build, libFuzzer execution or native/business qualification occurs.
The original checkout stays unchanged; Cargo writes only an owned worktree.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
LOCK = "tests/fuzz/Cargo.lock"
MANIFEST = "tests/fuzz/Cargo.toml"
TOOLCHAIN = "nightly-2026-10-01"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
ASM_CHECKSUM = "b845214d6175804686b2bd482bcffe96651bb2d1200742b712003504a2dac1ab"


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def package_map(document):
    packages = document.get("package")
    require(type(packages) is list, "PACKAGE_ARRAY")
    result = {}
    for row in packages:
        require(type(row) is dict and type(row.get("name")) is str
                and type(row.get("version")) is str, "PACKAGE_SHAPE")
        identity = (row["name"], row["version"], row.get("source"))
        require(identity not in result, "DUPLICATE_PACKAGE_IDENTITY")
        dependencies = row.get("dependencies", [])
        require(type(dependencies) is list
                and all(type(item) is str for item in dependencies)
                and len(set(dependencies)) == len(dependencies), "DEPENDENCY_ARRAY")
        result[identity] = row
    return result


def qualify_graph(before, after, native):
    old, new, workspace = map(package_map, (before, after, native))
    asm = ("sha2-asm", "0.6.4", REGISTRY)
    digest = ("sha2", "0.10.9", REGISTRY)
    require(asm not in old and set(new) == set(old) | {asm}, "ONLY_ONE_ASM_PACKAGE")
    require(asm in workspace and workspace[asm] == {
        "name": "sha2-asm", "version": "0.6.4", "source": REGISTRY,
        "checksum": ASM_CHECKSUM, "dependencies": ["cc"]},
        "PINNED_NATIVE_ASM_RECORD")
    require(new[asm] == workspace[asm], "EXACT_NATIVE_ASM_RECORD")
    require(digest in old and digest in new, "PINNED_SHA2_RECORD")
    expected = dict(old[digest])
    require("sha2-asm" not in expected["dependencies"], "OLD_ASM_EDGE_PRESENT")
    expected["dependencies"] = expected["dependencies"] + ["sha2-asm"]
    require(new[digest] == expected, "ONLY_SHA2_ASM_EDGE")
    require(all(new[key] == row for key, row in old.items() if key != digest),
            "UNRELATED_PACKAGE_RECORD_CHANGED")
    require({k: v for k, v in before.items() if k != "package"}
            == {k: v for k, v in after.items() if k != "package"},
            "LOCK_METADATA_CHANGED")
    return {"packages_before": len(old), "packages_after": len(new),
            "added_identity": list(asm), "changed_dependency_identity": list(digest),
            "unchanged_old_package_records": len(old) - 1}


def controls():
    sha2 = {"name": "sha2", "version": "0.10.9", "source": REGISTRY,
            "checksum": "synthetic-sha2", "dependencies": ["cfg-if"]}
    cc = {"name": "cc", "version": "1.2.59", "source": REGISTRY,
          "checksum": "synthetic-cc"}
    asm = {"name": "sha2-asm", "version": "0.6.4", "source": REGISTRY,
           "checksum": ASM_CHECKSUM, "dependencies": ["cc"]}
    before = {"version": 4, "package": [sha2, cc]}
    after = {"version": 4, "package": [
        {**sha2, "dependencies": ["cfg-if", "sha2-asm"]}, cc, asm]}
    native = {"version": 4, "package": [asm]}
    qualify_graph(before, after, native)
    cases = []
    def copy():
        return json.loads(json.dumps(after))
    changed = copy()
    changed["package"][1]["version"] = "1.2.60"
    cases.append(changed)
    changed = copy()
    changed["package"][1]["dependencies"] = ["unrelated"]
    cases.append(changed)
    changed = copy()
    changed["package"].pop()
    cases.append(changed)
    changed = copy()
    changed["package"].append(dict(changed["package"][1]))
    cases.append(changed)
    changed = copy()
    changed["package"][2]["checksum"] = "wrong"
    cases.append(changed)
    changed = copy()
    changed["package"][0]["dependencies"].pop()
    cases.append(changed)
    changed = copy()
    changed["version"] = 3
    cases.append(changed)
    for changed in cases:
        try:
            qualify_graph(before, changed, native)
        except ValueError:
            continue
        raise ValueError("CONTROL_ACCEPTED_UNREVIEWED_CHANGE")
    return {"synthetic_positive": 1, "synthetic_negatives": len(cases),
            "native_executions": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(out.is_relative_to(temporary) and not out.is_relative_to(ROOT),
            "OWNED_OUTPUT_REQUIRED")
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": "trnm-fuzz-asm-lock-generation-v1", "result": "FAIL",
               "commands": [], "native_tests_executed": 0,
               "fuzz_mutations_executed": 0, "original_fuzz_gate_qualified": False,
               "performance_qualified": False, "production_activation": False}
    work = temporary / "chain-fuzz-asm-owned-worktree"
    created = False
    generated = None
    def run(label, argv, cwd, *, timeout=300, env=None, separate_stderr=False):
        path = out / (label + ".log")
        begin = time.monotonic_ns()
        error_path = out / (label + ".stderr.log")
        with path.open("xb") as stream:
            if separate_stderr:
                with error_path.open("xb") as errors:
                    result = subprocess.run(argv, cwd=cwd, env=env, stdout=stream,
                                            stderr=errors, timeout=timeout)
            else:
                result = subprocess.run(argv, cwd=cwd, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=timeout)
        raw = path.read_bytes()
        error_raw = error_path.read_bytes() if separate_stderr else None
        require(error_raw is None or len(error_raw) <= 2 * 1024 * 1024,
                "COMMAND_STDERR_LIMIT")
        require(len(raw) <= 2 * 1024 * 1024, "COMMAND_LOG_LIMIT")
        receipt["commands"].append({
            "label": label, "argv": argv, "exit_code": result.returncode,
            "elapsed_ns": time.monotonic_ns() - begin,
            "outer_timeout_seconds": timeout, "log_bytes": len(raw), "log_sha256": sha(raw),
            "stderr_bytes": len(error_raw) if error_raw is not None else None,
            "stderr_sha256": sha(error_raw) if error_raw is not None else None})
        return result.returncode, raw
    try:
        require(os.environ.get("GITHUB_REPOSITORY")
                == "TrillionniumFoundation/Trillionnium-Chain"
                and os.environ.get("GITHUB_REF")
                == "refs/heads/diagnostic/chain-fuzz-asm-lock-20261104-gpt6",
                "FROZEN_DIAGNOSTIC_SCOPE")
        inputs = json.loads(Path(__file__).with_name("inputs.json").read_bytes())
        require(inputs["owner"] == "44d3def32f515b98fc41f074fe1b88e97f046191",
                "FROZEN_OWNER")
        bound = []
        for item in inputs["files"]:
            raw = (ROOT / item["path"]).read_bytes()
            require(sha(raw) == item["sha256"] and blob(raw) == item["git_blob"],
                    "BOUND_INPUT_BYTES")
            bound.append(item)
        receipt["inputs"] = bound
        head = subprocess.check_output(
            ["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        require(head == os.environ["GITHUB_SHA"], "SOURCE_HEAD")
        receipt["source"] = head
        receipt["tree"] = subprocess.check_output(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{tree}"],
            cwd=ROOT, text=True).strip()
        receipt["controls"] = controls()
        code, _ = run("source-clean-before",
                      ["git", "--no-replace-objects", "diff", "--exit-code", "HEAD", "--"], ROOT)
        require(code == 0, "SOURCE_CLEAN_BEFORE")
        require(not work.exists(), "FRESH_WORKTREE_REQUIRED")
        code, _ = run("create-owned-worktree",
                      ["git", "--no-replace-objects", "worktree", "add", "--detach", str(work), head],
                      ROOT, timeout=120)
        require(code == 0, "WORKTREE_CREATION")
        created = True
        environment = dict(os.environ)
        environment["RUSTUP_TOOLCHAIN"] = TOOLCHAIN
        environment["CARGO_HOME"] = str(temporary / "chain-fuzz-asm-cargo-home")
        environment["CARGO_TARGET_DIR"] = str(temporary / "chain-fuzz-asm-query-target")
        environment.pop("CARGO_NET_OFFLINE", None)
        receipt["toolchain"] = TOOLCHAIN
        for label, argv in (("rustc", ["rustc", "--version", "--verbose"]),
                            ("cargo", ["cargo", "--version", "--verbose"])):
            code, _ = run(label, argv, work, timeout=60, env=environment)
            require(code == 0, "EXACT_TOOLCHAIN")
        before_raw = (work / LOCK).read_bytes()
        require(blob(before_raw) == "76dc02ff2332f5d0cf5ac4a0d49bcb4aac517434",
                "OLD_FUZZ_LOCK_BYTES")
        (out / "before-Cargo.lock").write_bytes(before_raw)
        argv = ["cargo", "fetch", "--locked", "--manifest-path", MANIFEST]
        code, raw = run("original-locked-negative", argv, work, env=environment)
        require(code == 101 and (work / LOCK).read_bytes() == before_raw,
                "ORIGINAL_LOCKED_NEGATIVE")
        refusal = raw.decode("utf-8", errors="strict")
        require(re.search(
            r"cannot update the lock file [^\n]+ because --locked was passed"
            r"|the lock file [^\n]+ needs to be updated but --locked was passed",
            refusal) is not None, "EXACT_LOCKED_REFUSAL")
        receipt["original_locked_refusal_demonstrated"] = True
        code, _ = run("cargo-generated-lock",
                      ["cargo", "fetch", "--manifest-path", MANIFEST], work, env=environment)
        require(code == 0, "CARGO_GENERATION_FAILED")
        generated = (work / LOCK).read_bytes()
        require(0 < len(generated) <= 128 * 1024, "GENERATED_LOCK_LIMIT")
        receipt["graph"] = qualify_graph(
            tomllib.loads(before_raw.decode()), tomllib.loads(generated.decode()),
            tomllib.loads((work / "trillionnium/Cargo.lock").read_text()))
        code, changed = run("worktree-diff",
                            ["git", "--no-replace-objects", "diff", "--name-only", "HEAD", "--"],
                            work, timeout=60)
        require(code == 0 and changed.decode().splitlines() == [LOCK],
                "ONLY_OWNED_FUZZ_LOCK_CHANGED")
        code, _ = run("same-locked-positive", argv, work, env=environment)
        require(code == 0 and (work / LOCK).read_bytes() == generated, "LOCKED_POSITIVE")
        offline = dict(environment)
        offline["CARGO_NET_OFFLINE"] = "true"
        code, metadata = run("offline-locked-metadata",
                             ["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                              "--manifest-path", MANIFEST], work, env=offline, separate_stderr=True)
        require(code == 0 and (work / LOCK).read_bytes() == generated, "OFFLINE_METADATA")
        graph = json.loads(metadata)
        asm = [p for p in graph["packages"] if p["name"] == "sha2-asm"]
        require(len(asm) == 1 and asm[0]["version"] == "0.6.4"
                and asm[0]["source"] == REGISTRY, "RESOLVED_ASM_IDENTITY")
        sha2 = [p for p in graph["packages"] if p["name"] == "sha2" and p["version"] == "0.10.9"]
        require(len(sha2) == 1, "RESOLVED_SHA2_IDENTITY")
        nodes = {node["id"]: node for node in graph["resolve"]["nodes"]}
        require(asm[0]["id"] in nodes[sha2[0]["id"]]["dependencies"]
                and "asm" in nodes[sha2[0]["id"]]["features"], "RESOLVED_ASM_EDGE")
        (out / "generated-Cargo.lock").write_bytes(generated)
        receipt["generated_lock"] = {
            "bytes": len(generated), "sha256": sha(generated), "git_blob": blob(generated)}
        receipt["metadata_sha256"] = sha(metadata)
        receipt["metadata_packages"] = len(graph["packages"])
        code, _ = run("source-clean-after",
                      ["git", "--no-replace-objects", "diff", "--exit-code", "HEAD", "--"], ROOT)
        require(code == 0, "SOURCE_CLEAN_AFTER")
        receipt["original_checkout_unchanged"] = True
        receipt["result"] = "PASS"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        receipt["error_type"] = type(error).__name__
        receipt["error_code"] = str(error) if type(error) is ValueError else None
    finally:
        if created:
            code, _ = run("remove-owned-worktree",
                          ["git", "--no-replace-objects", "worktree", "remove", "--force", str(work)],
                          ROOT, timeout=120)
            receipt["owned_worktree_removed"] = code == 0
            if code:
                receipt["result"] = "FAIL"
        encoded = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
        require(len(encoded) <= 64 * 1024, "RECEIPT_OUTPUT_LIMIT")
        (out / "receipt.json").write_bytes(encoded)
        print("FUZZ_LOCK_RESULT " + json.dumps(receipt, sort_keys=True), flush=True)
        if receipt["result"] == "PASS":
            data = base64.b64encode(generated).decode("ascii")
            chunks = [data[i:i + 3072] for i in range(0, len(data), 3072)]
            require(len(data) <= 180 * 1024, "LOCK_STDOUT_LIMIT")
            for index, chunk in enumerate(chunks):
                print("FUZZ_LOCK_CHUNK " + json.dumps({
                    "index": index, "count": len(chunks), "data": chunk}), flush=True)
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
