#!/usr/bin/env python3
"""Perform bounded post-test lint and format maintenance without rerunning tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback


def digest(path):
    raw = Path(path).read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_new(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--tested-head", required=True)
    parser.add_argument("--format-base", required=True)
    parser.add_argument("--test-result", action="append", required=True)
    args = parser.parse_args()
    root, out = Path(args.source), Path(args.output)
    out.mkdir(mode=0o700, exist_ok=False)

    def git(*values):
        return subprocess.check_output(["git", *values], cwd=root, text=True).strip()

    def source():
        return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
                "index_tree": git("write-tree"), "native_tree": git("rev-parse", "HEAD:codex-rs"), "status": git("status", "--porcelain")}

    def resources():
        raw = subprocess.check_output(["systemctl", "--user", "show", args.unit,
            "-p", "MemoryMax", "-p", "CPUQuotaPerSecUSec", "-p", "Nice", "-p", "ControlGroup",
            "-p", "RuntimeMaxUSec"], text=True)
        values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        group = Path("/sys/fs/cgroup") / values["ControlGroup"].lstrip("/")
        for name in ["memory.max", "memory.peak", "memory.swap.max", "memory.swap.peak", "cpu.max", "cpu.stat"]:
            path = group / name
            if path.exists():
                values[name] = path.read_text().strip()
        return values

    before = source()
    envelope = resources()
    test_results = []
    for path in args.test_result:
        result = json.loads(Path(path).read_text())
        if result["exit_code"] != 0 or result["error"] is not None or not result["source_unchanged"]:
            raise RuntimeError("native controls must have passed before maintenance")
        if result["source_before"]["head"] != args.tested_head or result["source_before"] != result["source_after"]:
            raise RuntimeError("tested source identity differs")
        test_results.append(digest(path))
    if before["head"] != args.expected_head or before["status"] or before["tree"] != before["index_tree"]:
        raise RuntimeError("maintenance requires exact clean tested source")
    if envelope["memory.max"] != "8589934592":
        raise RuntimeError("maintenance memory envelope differs")
    quota, period = envelope["cpu.max"].split()
    if quota == "max" or int(quota) != 2 * int(period):
        raise RuntimeError("maintenance CPU envelope differs")
    if git("rev-parse", "HEAD^") != args.tested_head:
        raise RuntimeError("maintenance successor must directly descend from tested source")
    insertions = {
        "codex-rs/hepta-agentd/src/learning_iteration_checkpoint_profile_tests.rs": (
            "#[path = \"learning_iteration_checkpoint_test_support.rs\"]\nmod support;",
            "#[allow(\n    clippy::duplicate_mod,\n    reason = \"This test-only module reuses the original fsync CAS fixture without widening its visibility\"\n)]\n"),
        "codex-rs/hepta-agentd/src/neuron_generation_learning_readback_test_support.rs": (
            "#[path = \"learning_iteration_checkpoint_codec.rs\"]\nmod checkpoint_codec;",
            "#[allow(\n    clippy::duplicate_mod,\n    reason = \"This test-only exporter reuses the private production codec without widening its API\"\n)]\n"),
    }
    if set(git("diff", "--name-only", args.tested_head, "HEAD").splitlines()) != set(insertions):
        raise RuntimeError("successor contains an unreviewed source delta")
    validation = []
    for relative, (anchor, attribute) in insertions.items():
        old = subprocess.check_output(["git", "show", args.tested_head + ":" + relative], cwd=root)
        new = (root / relative).read_bytes()
        if old.count(anchor.encode()) != 1 or new != old.replace(anchor.encode(), (attribute + anchor).encode(), 1):
            raise RuntimeError("reviewed local lint attribute is not the complete source change: " + relative)
        validation.append({"path": relative, "tested_sha256": hashlib.sha256(old).hexdigest(),
                           "maintenance_sha256": hashlib.sha256(new).hexdigest(),
                           "source_after_stripping_exact_attribute_matches_tested_bytes": True})
    provenance = {"tested_head": args.tested_head, "maintenance_head": args.expected_head,
                  "direct_successor": True, "format_base": args.format_base,
                  "format_scope_paths": git("diff", "--name-only", args.format_base, "HEAD").splitlines(),
                  "tested_tree": git("rev-parse", args.tested_head + "^{tree}"),
                  "tested_native_tree": git("rev-parse", args.tested_head + ":codex-rs"),
                  "maintenance_tree": before["tree"], "maintenance_native_tree": before["native_tree"],
                  "changed_paths": sorted(insertions), "files": validation,
                  "allowed_delta": "two local test-only duplicate_mod attributes and reasons",
                  "added_lines": sum(attribute.count("\n") for _, attribute in insertions.values()),
                  "test_names_and_runtime_source_bytes_preserved": True, "tests_rerun": False}
    (out / "reviewed-lint-only-delta.patch").write_bytes(subprocess.check_output(
        ["git", "diff", "--binary", args.tested_head, "HEAD"], cwd=root))
    write_new(out / "tested-source-equivalence.json", provenance)
    commands = [("scoped-fix", ["just", "fix", "-p", "codex-hepta-learning-artifacts", "-p", "codex-hepta-agentd", "--lib", "--locked"]),
                ("post-fmt", ["just", "fmt", "--base", args.format_base]),
                ("strict-clippy", ["just", "clippy", "-p", "codex-hepta-learning-artifacts", "-p", "codex-hepta-agentd", "--lib", "--locked", "--", "-D", "warnings"])]
    write_new(out / "start.json", {"source": before, "resources": envelope, "commands": commands,
                                  "test_results": test_results, "provenance": provenance, "tests_rerun_after_maintenance": False})
    env = os.environ.copy()
    env.update({"CARGO_TARGET_DIR": args.target, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
                "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                "LIBCLANG_PATH": "/usr/lib/llvm-21/lib", "RUSTUP_TOOLCHAIN": "1.96.0", "RUST_MIN_STACK": "8388608",
                "PATH": "/home/qian-qi/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/work/chain-hepta-native-1f3ba4601505/tools/bin:/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin"})
    steps, error, exit_code = [], None, 99
    try:
        relative = "codex-rs/hepta-learning-artifacts/src/learning_iteration_profile_tests.rs"
        path = root / relative
        original = path.read_text()
        if original.count("/*now_unix_seconds*/") != 6 or ", 20)" in original:
            raise RuntimeError("tested candidate must already contain the six reviewed argument comments")
        comment_diff = subprocess.check_output(["git", "diff", "--binary", "HEAD", "--", relative], cwd=root)
        (out / "pre-maintenance-source-diff.patch").write_bytes(comment_diff)
        for name, command in commands:
            started = time.monotonic()
            log = out / (name + ".log")
            with log.open("x") as stream:
                process = subprocess.run(command, cwd=root / "codex-rs", env=env, stdout=stream, stderr=subprocess.STDOUT)
            diff = out / (name + "-source-diff.patch")
            diff.write_bytes(subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root))
            steps.append({"name": name, "command": command, "exit_code": process.returncode,
                          "wall_seconds": time.monotonic() - started, "log": digest(log), "source": source(),
                          "diff": digest(diff), "resources": resources()})
            if process.returncode:
                exit_code = process.returncode
                raise RuntimeError("maintenance command failed: " + name)
        exit_code = 0
    except Exception as exc:
        error = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        result = {"tested_candidate": args.tested_head, "maintenance_candidate": args.expected_head, "provenance": provenance, "source_before": before, "source_after": source(),
                  "commands": steps, "test_results": test_results, "resources_before": envelope,
                  "resources_after": resources(), "error": error, "exit_code": exit_code,
                  "tests_rerun_after_maintenance": False, "engineering_controls_only": True,
                  "production_final_use_qualified": False}
        write_new(out / "result.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
