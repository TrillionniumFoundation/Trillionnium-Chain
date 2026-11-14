#!/usr/bin/python3
"""Run one worker artifact component validation on an exact existing Linux checkout.

Preparation is static only. No fetch, import, checkout, dependency installation,
Host workload, benchmark or CI-budget change is performed by this driver.
"""
import argparse, collections, datetime, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys, time

BASE = pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
SOURCE = BASE / "source"
PYTHON = BASE / "final-python312-env/bin/python"
TOOLCHAIN = pathlib.Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
ARTIFACT_PATH = "trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs"
ARTIFACT_BLOB = "f021a33e2969305241099998f703172d29b15251"
ARTIFACT_BYTES = 12283
ARTIFACT_SHA256 = "12396ec45e2b059d588f7d00feb9f19cc557389e37be0053d9ff5f344825f3cc"
EXPECTED_TESTS = (
    "audit::artifact::tests::exact_stream_bound_includes_eof_and_limits_a_growing_reader",
    "audit::artifact::tests::pretty_index_and_jsonl_keep_original_format_and_missing_file_errors",
    "audit::artifact::tests::sparse_oversize_invalid_utf8_and_oversize_record_fail_closed",
    "audit::artifact::tests::path_aliases_nonregular_inputs_and_untrusted_permissions_are_refused",
    "audit::artifact::tests::replacement_growth_and_same_length_metadata_change_after_open_are_refused",
    "audit::artifact::tests::a_live_writer_lock_is_not_reported_as_an_empty_artifact",
    "audit::artifact::tests::query_bounds_both_export_and_pretty_index_before_reporting_records",
    "audit::artifact::tests::fifo_without_a_writer_is_refused_by_nonblocking_regular_file_check",
    "audit::artifact::tests::validation_to_lock_permission_change_is_refused",
    "audit::artifact::tests::validation_to_lock_hardlink_change_is_refused",
)
FMT_ARGV = [str(TOOLCHAIN / "cargo"), "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"]
CLIPPY_ARGV = [str(TOOLCHAIN / "cargo"), "clippy", "--locked", "--offline", "--manifest-path",
               "trillionnium/Cargo.toml", "-p", "trnm-worker-agent", "--all-targets", "--all-features", "--", "-D", "warnings"]
TEST_ARGV = [str(TOOLCHAIN / "cargo"), "test", "--locked", "--offline", "--manifest-path",
             "trillionnium/Cargo.toml", "-p", "trnm-worker-agent", "--bin", "trnm-worker-agent",
             "audit::artifact::tests::", "--", "--nocapture"]
BUDGETS = {"workspace-format": 180, "worker-strict-clippy": 1200, "worker-artifact-tests": 1200}
REFERENCE_SELECTORS = ("TRNM_NATIVE_WORK", "TRNM_NATIVE_EXECUTOR", "TRNM_NATIVE_SESSION",
                       "TRNM_EXECUTION_WORKERS", "TRNM_PON_EVALUATION_POLICY")
BUILD_OVERRIDE_NAMES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTFMT",
                        "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
                        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha_file(path):
    value = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def artifact_identity():
    path = SOURCE / ARTIFACT_PATH
    before = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "selected worker artifact must be a canonical single-link regular file")
    require(before.st_size == ARTIFACT_BYTES, "selected worker artifact size differs")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(ARTIFACT_BYTES + 1)
        closed = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(identity(before) == identity(opened) == identity(closed) == identity(path.lstat()),
            "selected artifact changed while being read")
    digest = hashlib.sha256(raw).hexdigest()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(len(raw) == ARTIFACT_BYTES and digest == ARTIFACT_SHA256 and blob == ARTIFACT_BLOB,
            "selected worker artifact bytes differ from reviewed source")
    return {"path": ARTIFACT_PATH, "bytes": len(raw), "sha256": digest, "git_blob": blob}

def reconcile_tests(raw):
    text = raw.decode("utf-8", errors="strict")
    events = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored(?:, [^\r\n]*)?)\s*$", text, re.MULTILINE)
    counts = collections.Counter(name for name, outcome in events)
    require(set(counts) == set(EXPECTED_TESTS) and all(count == 1 for count in counts.values()),
            "actual test names differ, duplicate, are missing or were not fully captured")
    require(all(outcome == "ok" for name, outcome in events), "required worker test did not pass")
    require(re.findall(r"^running (\d+) tests?\s*$", text, re.MULTILINE) == ["10"], "actual harness count is not exactly ten")
    summaries = re.findall(
        r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; "
        r"(\d+) filtered out; finished in ([^\r\n]+)\s*$", text, re.MULTILINE)
    require(len(summaries) == 1 and summaries[0][:5] == ("ok", "10", "0", "0", "0"),
            "actual harness summary is not ten passed, zero failed/ignored/measured")
    return {"expected_names": list(EXPECTED_TESTS), "actual_outcomes": [{"name": name, "outcome": outcome} for name, outcome in events],
            "passed": 10, "failed": 0, "ignored": 0, "measured": 0,
            "unrelated_tests_filtered_out": int(summaries[0][5]), "new_controls_executed": list(EXPECTED_TESTS[-2:])}

def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized interpreter is not allowed")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    for value in (args.head, args.tree):
        require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "exact SHA required")
    require(sys.platform == "linux" and os.getuid() != 0, "prepared non-root Linux environment required")
    require(os.environ.get("GITHUB_ACTIONS", "").lower() not in ("true", "1"), "this is a local component run")
    require(BASE.resolve(strict=True) == BASE and SOURCE.resolve(strict=True) == SOURCE, "canonical source/root required")
    evidence = pathlib.Path(args.evidence_dir)
    require(evidence.is_absolute() and evidence.parent == BASE
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", evidence.name),
            "evidence must be a new direct child of the authorized root")
    evidence.mkdir(mode=0o700, exist_ok=False)
    temporary = evidence / "tmp"
    receipts = evidence / "ci-observations"
    temporary.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    env = os.environ.copy()
    cleared = sorted(name for name in env if name.startswith("GIT_") or name.startswith("RUST_TEST_") or name in REFERENCE_SELECTORS)
    for name in cleared:
        env.pop(name, None)
    overrides = sorted(name for name, value in env.items() if value and (
        name in BUILD_OVERRIDE_NAMES or name.startswith("CARGO_PROFILE_")
        or (name.startswith("CARGO_TARGET_") and name.endswith(("_RUSTFLAGS", "_RUNNER", "_LINKER")))))
    env.update(
        PATH=str(PYTHON.parent) + ":" + str(TOOLCHAIN) + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        CI="true", TRNM_EXPECTED_SOURCE_SHA=args.head, TRNM_CI_RECEIPT_DIR=str(receipts), TMPDIR=str(temporary),
        CARGO_TARGET_DIR=str(BASE / "target"), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
        PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
        GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_TRACE="0", GIT_TRACE2="0", GIT_TRACE2_EVENT="0", GIT_TRACE2_PERF="0",
    )
    steps, errors = [], []
    result = {
        "schema": "trnm-final-linux-worker-artifact-existing-source-v1", "status": "running",
        "head": args.head, "tree": args.tree, "expected_start_head": args.head, "source": str(SOURCE),
        "driver": {"path": str(pathlib.Path(__file__).resolve(strict=True)), "sha256": sha_file(__file__)},
        "invocation": {"argv": list(sys.argv), "executable": sys.executable, "optimize": sys.flags.optimize},
        "component": "worker-artifact", "component_budgets_seconds": BUDGETS,
        "budget_basis": "separately approved extra component limits; no hosted/workflow/confirmation budget is changed",
        "steps": steps, "errors": errors, "expected_test_names": list(EXPECTED_TESTS),
        "environment": {name: env[name] for name in (
            "PATH", "CI", "TRNM_EXPECTED_SOURCE_SHA", "TRNM_CI_RECEIPT_DIR", "TMPDIR", "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_TERM_COLOR", "PYTHONDONTWRITEBYTECODE",
            "PYTHONOPTIMIZE", "GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH", "GIT_OPTIONAL_LOCKS",
            "GIT_TERMINAL_PROMPT", "GIT_TRACE", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF")},
        "inherited_selector_names_cleared": cleared, "inherited_selector_values_retained": False,
        "inherited_build_override_names_refused": overrides,
        "rust_test_threads": "default harness; no RUST_TEST_* variables or command-line thread override",
        "source_acquisition": "preexisting-exact-checkout",
        "source_fetch_import_checkout_or_installation_performed": False, "environment_installation_performed": False,
        "host_workload_or_benchmark_executed": False, "hosted_ci_qualification": False,
        "four_second_confirmation_qualification": False, "remote_publication_verified": False,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    def save():
        (evidence / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    save()
    unconfirmed_child = False
    def run(label, argv, timeout=300, required=True):
        nonlocal unconfirmed_child
        paths = {channel: evidence / (label + "." + channel) for channel in ("stdout", "stderr")}
        start, process, timed_out, terminated = time.monotonic(), None, False, True
        with paths["stdout"].open("xb") as stdout, paths["stderr"].open("xb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        terminated = False
                        unconfirmed_child = True
                        stderr.write(b"Owned command termination remains unconfirmed.\n")
                    code = 124
            except OSError as error:
                stderr.write((repr(error) + "\n").encode())
                code = 127
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": code,
               "timeout_seconds": timeout, "elapsed_seconds": round(time.monotonic() - start, 3),
               "timed_out": timed_out, "owned_process_terminated": terminated,
               "pid": process.pid if process is not None else None,
               "observed_returncode": process.returncode if process is not None else None}
        for channel, path in paths.items():
            row[channel + "_path"] = str(path)
            row[channel + "_bytes"] = path.stat().st_size
            row[channel + "_sha256"] = sha_file(path)
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": code, "owned_process_terminated": terminated}), flush=True)
        if required:
            require(code == 0 and terminated, "failed stage: " + label)
        return row, paths["stdout"]
    def read_output(path):
        require(path.stat().st_size <= 8 * 1024 * 1024, "unexpectedly large control output; raw file retained")
        return path.read_bytes()
    def git(label, *arguments):
        return run(label, ["git", "--no-replace-objects", *arguments])
    before_verified, component_passed = False, False
    test_exit = None
    try:
        require(not overrides, "unreviewed inherited build overrides: " + ", ".join(overrides))
        _, path = git("initial-head", "rev-parse", "HEAD")
        require(read_output(path).decode().strip() == args.head, "source HEAD differs")
        _, path = git("initial-tree", "rev-parse", "HEAD^{tree}")
        require(read_output(path).decode().strip() == args.tree, "source tree differs")
        _, path = git("initial-status", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none")
        require(not read_output(path).strip(), "source must be clean")
        run("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"])
        for label, binary, prefix in (("rust-version", "rustc", "rustc 1.95.0 "), ("cargo-version", "cargo", "cargo 1.95.0 ")):
            _, path = run(label, [str(TOOLCHAIN / binary), "--version"], timeout=60)
            require(read_output(path).decode().startswith(prefix), "pinned Rust toolchain differs")
        _, path = run("verify-source-before", [str(PYTHON), "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-before.json")])
        identity = json.loads(read_output(path))
        require(identity["tested_commit"] == args.head and identity["tested_tree"] == args.tree
                and identity["tracked_worktree_verified"] is True, "source identity differs")
        before_verified = True
        _, path = git("worker-artifact-git-blob", "rev-parse", args.head + ":" + ARTIFACT_PATH)
        require(read_output(path).decode().strip() == ARTIFACT_BLOB, "selected artifact Git blob differs")
        selected = artifact_identity()
        (evidence / "artifact-source-before.json").write_text(json.dumps(selected, indent=2) + "\n")
        result["selected_artifact"] = selected
        save()
        run("workspace-format", FMT_ARGV, timeout=BUDGETS["workspace-format"])
        run("worker-strict-clippy", CLIPPY_ARGV, timeout=BUDGETS["worker-strict-clippy"])
        row, path = run("worker-artifact-tests", TEST_ARGV, timeout=BUDGETS["worker-artifact-tests"], required=False)
        test_exit = row["exit"]
        require(test_exit == 0 and row["owned_process_terminated"], "worker module failed or timed out")
        outcomes = reconcile_tests(read_output(path))
        (evidence / "test-outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        result["actual_test_results"] = outcomes
        component_passed = True
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    finally:
        after_valid = False
        try:
            row, path = run("verify-source-after", [str(PYTHON), "-B", "scripts/ci/verify_ci_source.py",
                "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-after.json")],
                required=False)
            if row["exit"] == 0 and row["owned_process_terminated"] and before_verified:
                after = json.loads(read_output(path))
                before = json.loads((evidence / "source-before.json").read_bytes())
                require(after == before, "full source before/after differs")
                if "selected_artifact" in result:
                    selected_after = artifact_identity()
                    (evidence / "artifact-source-after.json").write_text(json.dumps(selected_after, indent=2) + "\n")
                    require(selected_after == result["selected_artifact"], "selected worker artifact changed")
                after_valid = not unconfirmed_child
            else:
                errors.append("final source verification did not confirm the tested source")
        except Exception as error:
            errors.append("post-run verification: " + repr(error))
        result["worker_test_exit"] = test_exit
        result["source_before_after_verified"] = after_valid
        result["owned_process_termination_unknown"] = unconfirmed_child
        result["status"] = ("unknown" if unconfirmed_child else
                            "passed" if not errors and component_passed and after_valid else "failed")
        result["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps({"status": result["status"], "head": args.head, "tree": args.tree,
                      "summary": str(evidence / "summary.json"), "summary_sha256": sha_file(evidence / "summary.json")}), flush=True)
    return 0 if result["status"] == "passed" else 2 if result["status"] == "unknown" else 1

if __name__ == "__main__":
    sys.exit(main())
