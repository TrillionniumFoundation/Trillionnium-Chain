#!/usr/bin/env python3
"""Observe two unchanged tests on exact da1374a in a new isolated worktree.

Does not alter source, assertions, deadlines, CPU budgets or ignored tests.
Test refusals are evidence and are retained; no green result is manufactured.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

BASE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
BASE_TREE = "00479a98dabc6b1fd91a0ceef82ffbdbffb78067"
SOURCE = Path("/home/qian-qi/chain-pon-followthrough-20261110-685a")
ROOT = Path("/home/qian-qi/chain-pon-baseline-control-20261110-685a")
BRANCH = "test/chain-pon-baseline-control-20261110-685a"
OUT = Path("/home/qian-qi/chain-pon-baseline-control-20261110-685a-output")
TARGET = Path("/home/qian-qi/chain-pon-followthrough-20261110-685a-target")
VERIFY = "scripts/ci/verify_ci_source.py"
TESTS = (
    ("legacy-large-parent", "store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner"),
    ("inactive-page-parents", "store::native_authenticated_tests::native_inactive_page_parents_use_checked_material_without_early_activation"),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def profile():
    limits = {}
    for name in ("cpu.max", "memory.max", "cpuset.cpus.effective"):
        path = Path("/sys/fs/cgroup") / name
        limits[name] = path.read_text().strip() if path.is_file() else None
    model = next((row.split(":", 1)[1].strip()
                  for row in Path("/proc/cpuinfo").read_text().splitlines()
                  if row.startswith("model name")), None)
    return {"observed_unix_ns": time.time_ns(), "platform": platform.platform(),
            "machine": platform.machine(), "logical_cpus": os.cpu_count(),
            "affinity": sorted(os.sched_getaffinity(0)),
            "load_average": list(os.getloadavg()), "cpu_model": model,
            "cgroup_limits": limits,
            "scope": "local host observations, not an independent resource qualification"}


def main():
    for path in (SOURCE, ROOT, OUT, TARGET, Path(__file__)):
        assert path.is_absolute() and path == path.resolve(), "normalized non-symlink paths required"
    assert not OUT.exists() and not ROOT.exists(), "create-only control paths already exist"
    assert not OUT.is_relative_to(SOURCE) and not ROOT.is_relative_to(SOURCE)
    assert not OUT.is_relative_to(ROOT) and not TARGET.is_relative_to(ROOT)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT"):
        assert not os.environ.get(name), "external Git override refused: " + name
    env = dict(os.environ, CARGO_TERM_COLOR="never", CARGO_BUILD_JOBS="2",
               CARGO_TARGET_DIR=str(TARGET), PYTHONDONTWRITEBYTECODE="1",
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    OUT.mkdir()
    records = []
    current_stage = "initial-guards"
    source = {"baseline_commit": BASE, "expected_tree": BASE_TREE,
              "recorder_sha256": sha(Path(__file__).read_bytes()),
              "source_provider_worktree": str(SOURCE), "worktree": str(ROOT),
              "branch": BRANCH, "shared_cargo_target": str(TARGET),
              "source_mutated": False, "budgets_or_assertions_changed": False,
              "full_library_suite_executed": False,
              "open_consensus_qualified": False, "production_activation": False}

    def git(*args, cwd=ROOT):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=cwd, env=env)

    def head():
        if not ROOT.exists():
            return None
        try:
            return git("rev-parse", "HEAD").decode().strip()
        except (OSError, subprocess.SubprocessError):
            return None

    def status(stage, phase, code=None, started=None):
        atomic_json(OUT / "status.json", {
            "stage": stage, "phase": phase, "last_exit": code,
            "start_unix_ns": started, "recorded_unix_ns": time.time_ns(),
            "current_head": head(), "baseline_commit": BASE, "security_status": "HOLD"})

    def run(label, argv, cwd=ROOT, required=True):
        nonlocal current_stage
        current_stage = label
        start = time.time_ns()
        status(label, "running", started=start)
        print("START", label, flush=True)
        stdout, stderr = OUT / (label + ".stdout.log"), OUT / (label + ".stderr.log")
        with stdout.open("xb") as output, stderr.open("xb") as error:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=error)
        row = {"label": label, "argv": argv, "cwd": str(cwd), "exit_code": result.returncode,
               "start_unix_ns": start, "end_unix_ns": time.time_ns()}
        for key, path in (("stdout", stdout), ("stderr", stderr)):
            raw = path.read_bytes()
            row[key] = {"file": path.name, "bytes": len(raw), "sha256": sha(raw)}
        records.append(row)
        atomic_json(OUT / "commands.json", records)
        atomic_json(OUT / (label + ".command.json"), row)
        status(label, "finished" if result.returncode == 0 else "failed", result.returncode, start)
        print("END", label, result.returncode, flush=True)
        if required and result.returncode:
            raise RuntimeError("actual guard failed: " + label)
        return row, stdout.read_text(errors="replace")

    try:
        status(current_stage, "running")
        assert git("rev-parse", BASE + "^{tree}", cwd=SOURCE).decode().strip() == BASE_TREE
        source["source_provider_head_at_start"] = git("rev-parse", "HEAD", cwd=SOURCE).decode().strip()
        branch_check = subprocess.run(["git", "show-ref", "--verify", "--quiet", "refs/heads/" + BRANCH],
                                      cwd=SOURCE, env=env)
        assert branch_check.returncode == 1, "baseline branch already exists or cannot be checked"
        run("create-isolated-worktree", ["git", "--no-replace-objects", "-c", "core.sparseCheckout=false",
            "-c", "core.sparseCheckoutCone=false", "-c", "submodule.recurse=false", "worktree", "add",
            "-b", BRANCH, str(ROOT), BASE], cwd=SOURCE)
        assert head() == BASE and git("rev-parse", "HEAD^{tree}").decode().strip() == BASE_TREE
        assert git("branch", "--show-current").decode().strip() == BRANCH
        assert not git("status", "--porcelain"), "new baseline worktree is not clean"
        entries = git("ls-files", "-v", "-z").split(b"\0")
        assert all(not row or row.startswith(b"H ") for row in entries), "hidden index flags refused"
        sparse = subprocess.run(["git", "config", "--bool", "core.sparseCheckout"],
                                cwd=ROOT, env=env, stdout=subprocess.PIPE)
        assert sparse.returncode in (0, 1) and sparse.stdout.strip() in (b"", b"false"), "sparse checkout refused"
        assert git("rev-parse", "--is-shallow-repository").strip() == b"false", "shallow source refused"
        source.update(actual_commit=head(), actual_tree=BASE_TREE,
                      tracked_entries=sum(bool(row) for row in entries), all_index_entries_H=True,
                      explicit_environment={name: env[name] for name in (
                          "CARGO_TERM_COLOR", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "PYTHONDONTWRITEBYTECODE")},
                      inherited_relevant_environment={name: env.get(name) for name in (
                          "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUST_TEST_THREADS",
                          "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_TEST_OPT_LEVEL")})
        atomic_json(OUT / "source.json", source)
        atomic_json(OUT / "profile-before.json", profile())
        run("preflight", ["bash", "scripts/project-preflight.sh"])
        source_args = ["python3", "-B", VERIFY, "--kind", "head", "--expected-head", BASE, "--output"]
        run("source-before", source_args + [str(OUT / "source-before.json")])
        run("rustc-version", ["rustc", "-Vv"])
        run("cargo-version", ["cargo", "-V"])
        run("locked-offline-graph", ["cargo", "metadata", "--manifest-path", "trillionnium/Cargo.toml",
                                    "--locked", "--offline", "--format-version", "1"])
        test_results = []
        for label, name in TESTS:
            row, text = run(label, ["cargo", "test", "--manifest-path", "trillionnium/Cargo.toml",
                "--locked", "--offline", "-p", "trnm-pon-node", "--lib", name,
                "--", "--exact", "--nocapture"], required=False)
            summaries = re.findall(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.M)
            observed = (len(summaries) == 1 and summaries[0][2:4] == ("0", "0")
                        and sum(map(int, summaries[0][:2])) == 1
                        and "running 1 test\n" in text
                        and re.search(r"^test " + re.escape(name) + r" \.\.\. (?:ok|FAILED)$", text, re.M) is not None)
            test_results.append({"label": label, "full_name": name, "exit_code": row["exit_code"],
                                 "exact_single_test_execution_observed": observed,
                                 "reported_counts": list(map(int, summaries[0])) if len(summaries) == 1 else None})
        run("source-after", source_args + [str(OUT / "source-after.json")])
        run("source-identical", ["cmp", str(OUT / "source-before.json"), str(OUT / "source-after.json")])
        assert head() == BASE and not git("status", "--porcelain"), "baseline source changed"
        assert all(not row or row.startswith(b"H ") for row in git("ls-files", "-v", "-z").split(b"\0"))
        before = json.loads((OUT / "source-before.json").read_bytes())
        assert before["tested_commit"] == BASE and before["tested_tree"] == BASE_TREE
        assert before["tracked_worktree_verified"] is True
        atomic_json(OUT / "profile-after.json", profile())
        complete = all(item["exact_single_test_execution_observed"] for item in test_results)
        passed = complete and all(item["exit_code"] == 0 for item in test_results)
        summary = dict(source, schema="pon-baseline-original-two-test-observation-v1",
                       observation_complete=complete, all_baseline_tests_passed=passed,
                       full_library_suite_passed=None, original_c2_fullsuite_result="1285 passed; 2 failed; 39 ignored; exit 101",
                       source_bracket_identical=True, tests=test_results, commands=len(records),
                       causal_attribution_established=False, security_status="HOLD",
                       limitations="Two unchanged individually selected baseline tests only; one run does not establish host-only causality or full-library success.")
        atomic_json(OUT / "summary.json", summary)
        code = 0 if passed else 101 if complete else 2
        if not passed:
            atomic_json(OUT / "failure.json", {"observation_complete": complete,
                "reason": "original baseline test refusal retained" if complete else "one exact test was not observed to execute",
                "tests": test_results, "source_bracket_identical": True, "exit_code": code,
                "recorded_unix_ns": time.time_ns(), "security_status": "HOLD"})
        status("complete", "finished" if passed else "tests-failed", code)
        print(json.dumps(summary, sort_keys=True), flush=True)
        return code
    except (AssertionError, RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        atomic_json(OUT / "failure.json", {"observation_complete": False, "stage": current_stage,
            "reason": str(error), "source": source, "recorded_unix_ns": time.time_ns(), "security_status": "HOLD"})
        status(current_stage, "guard-failed", 2)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
