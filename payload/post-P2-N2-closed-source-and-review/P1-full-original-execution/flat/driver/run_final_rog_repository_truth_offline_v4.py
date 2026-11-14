#!/usr/bin/python3
"""Run the unchanged repository-truth lane on a fixed local candidate bundle.

Preparation performs no bundle read, fetch, checkout, build, or lane execution.
Invoke only after the bundle transfer is finalized and the operator authorizes
this offline-source run. This does not establish publication or hosted status.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys, time

BASE = pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
SOURCE = BASE / "source"
CONFORMANCE = BASE / "final-python312-env/bin/python"
RUNTIME = BASE / "final-runtime-release-env/bin/python"
TOOLCHAIN = pathlib.Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
BUNDLE_ROOT = BASE / "offline-source-bundles-v3"
REQUIREMENTS = {
    "formal/pon-nakamoto-v1/requirements.txt": "ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5",
    "scripts/ci/runtime-release-requirements.txt": "2acf07322b544b1d2318642b59877dd035bc7808590619f3cf23e75eedd0bbe7",
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha_file(path):
    value = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def verified_bundle_snapshot(bundle, bundle_bytes, bundle_sha256, previous=None):
    """Hash the complete finalized regular file and fence its filesystem version."""
    require(bundle.is_absolute() and bundle.parent == BUNDLE_ROOT
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.bundle", bundle.name),
            "bundle must be a safe direct child of the fixed source-bundle directory")
    require(BUNDLE_ROOT.resolve(strict=True) == BUNDLE_ROOT,
            "canonical fixed source-bundle directory required")
    require(bundle.resolve(strict=True) == bundle, "canonical finalized bundle path required")
    before = bundle.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "bundle must be a regular single-link file")
    require(before.st_size == bundle_bytes, "finalized bundle size differs")
    def version(info):
        return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                "links": info.st_nlink, "bytes": info.st_size,
                "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    expected_version = version(before)
    if previous is not None:
        require(previous == {"path": str(bundle), "bytes": bundle_bytes,
                             "sha256": bundle_sha256, "version": expected_version},
                "bundle filesystem version changed between stages")
    value, count = hashlib.sha256(), 0
    fd = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(version(os.fstat(stream.fileno())) == expected_version,
                "bundle changed before descriptor read")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            count += len(chunk)
            require(count <= bundle_bytes, "bundle grew during read")
            value.update(chunk)
        require(version(os.fstat(stream.fileno())) == expected_version,
                "bundle changed during descriptor read")
    require(version(bundle.lstat()) == expected_version,
            "bundle path changed during read")
    require(count == bundle_bytes and value.hexdigest() == bundle_sha256,
            "finalized bundle bytes/SHA256 differ")
    return {"path": str(bundle), "bytes": count, "sha256": value.hexdigest(),
            "version": expected_version}

def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized interpreter is not allowed")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--expected-start-head", required=True)
    parser.add_argument("--bundle-path", type=pathlib.Path, required=True)
    parser.add_argument("--bundle-bytes", type=int, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    args = parser.parse_args()
    for value in (args.head, args.tree, args.expected_start_head):
        require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "exact SHA required")
    require(args.bundle_bytes > 0, "positive exact bundle byte count required")
    require(re.fullmatch(r"[0-9a-f]{64}", args.bundle_sha256) is not None,
            "exact bundle SHA256 required")
    bundle = args.bundle_path
    require(os.getuid() != 0, "do not run as root")
    require(os.environ.get("GITHUB_ACTIONS", "").lower() not in ("true", "1"),
            "this is a local Linux run, not a hosted runner")
    require(SOURCE.resolve(strict=True) == SOURCE, "canonical source directory required")
    evidence = pathlib.Path(args.evidence_dir)
    require(evidence.is_absolute() and evidence.parent == BASE
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", evidence.name),
            "evidence must be a new direct child of the authorized root")
    evidence.mkdir(mode=0o700, exist_ok=False)
    receipts = evidence / "ci-observations"
    temporary = evidence / "tmp"
    receipts.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(
        PATH=str(CONFORMANCE.parent) + ":" + str(TOOLCHAIN)
             + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        TRNM_RUNTIME_RELEASE_PYTHON=str(RUNTIME),
        TRNM_CI_RECEIPT_DIR=str(receipts), TMPDIR=str(temporary),
        CARGO_TARGET_DIR=str(BASE / "target"), CARGO_BUILD_JOBS="2",
        CARGO_INCREMENTAL="0", RUST_TEST_THREADS="1", CARGO_TERM_COLOR="never",
        PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0",
        GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
    )
    steps, errors = [], []
    result = {
        "schema": "trnm-final-linux-repository-truth-offline-source-v4",
        "head": args.head, "tree": args.tree, "expected_start_head": args.expected_start_head,
        "driver": {"path": str(pathlib.Path(__file__).resolve(strict=True)),
                   "sha256": sha_file(pathlib.Path(__file__).resolve(strict=True))},
        "invocation": {"argv": list(sys.argv), "executable": sys.executable,
                       "optimize": sys.flags.optimize},
        "source": str(SOURCE), "status": "running", "steps": steps, "errors": errors,
        "environment": {name: env[name] for name in (
            "PATH", "TRNM_RUNTIME_RELEASE_PYTHON", "TRNM_CI_RECEIPT_DIR", "TMPDIR",
            "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUST_TEST_THREADS",
            "CARGO_TERM_COLOR", "PYTHONDONTWRITEBYTECODE", "PYTHONOPTIMIZE",
            "GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT")},
        "hosted_ci_qualification": False, "host_provisioning_performed": False,
        "remote_mutations_performed": False,
        "local_bundle_source": True, "remote_publication_verified": False,
        "source_acquisition": "fixed-local-bundle",
        "bundle_input": {"path": str(bundle), "bytes": args.bundle_bytes,
                         "sha256": args.bundle_sha256},
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    def save():
        (evidence / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    save()
    def run(label, argv, timeout=300, required=True):
        paths = {channel: evidence / (label + "." + channel) for channel in ("stdout", "stderr")}
        start = time.monotonic()
        with paths["stdout"].open("xb") as stdout, paths["stderr"].open("xb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        stderr.write(b"Owned command did not terminate after timeout.\n")
                    code = 124
            except OSError as error:
                stderr.write((repr(error) + "\n").encode())
                code = 127
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": code,
               "timeout_seconds": timeout, "elapsed_seconds": round(time.monotonic() - start, 3)}
        for channel, path in paths.items():
            row[channel + "_path"] = str(path)
            row[channel + "_bytes"] = path.stat().st_size
            row[channel + "_sha256"] = sha_file(path)
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": code}), flush=True)
        if required:
            require(code == 0, "failed stage: " + label)
        return row, paths["stdout"].read_bytes()
    def git(label, *arguments, required=True):
        return run(label, ["git", "--no-replace-objects", *arguments], required=required)
    before_verified = False
    lane_exit = None
    try:
        for relative, expected in REQUIREMENTS.items():
            require(sha_file(SOURCE / relative) == expected, "prepared Python requirements changed: " + relative)
        _, raw = git("initial-head", "rev-parse", "HEAD")
        require(raw.decode().strip() == args.expected_start_head, "concurrent source HEAD change")
        _, raw = git("initial-status", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none")
        require(not raw.strip(), "source must be clean before fetch")
        run("pre-update-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        bundle_snapshot = verified_bundle_snapshot(bundle, args.bundle_bytes, args.bundle_sha256)
        result["bundle_before"] = bundle_snapshot
        save()
        git("local-bundle-verify", "bundle", "verify", str(bundle))
        verified_bundle_snapshot(bundle, args.bundle_bytes, args.bundle_sha256, bundle_snapshot)
        _, bundle_heads = git("local-bundle-list-heads", "bundle", "list-heads", str(bundle))
        require([line.split() for line in bundle_heads.decode("ascii").splitlines()]
                == [[args.head, "HEAD"]], "bundle must advertise only the exact candidate HEAD")
        verified_bundle_snapshot(bundle, args.bundle_bytes, args.bundle_sha256, bundle_snapshot)
        git("fetch-exact-local-bundle", "fetch", "--no-tags", "--no-recurse-submodules",
            "--no-write-fetch-head", "--no-auto-maintenance", str(bundle), "HEAD")
        result["bundle_after_fetch"] = verified_bundle_snapshot(bundle, args.bundle_bytes, args.bundle_sha256, bundle_snapshot)
        save()
        _, fetched = git("fetched-commit", "rev-parse", args.head + "^{commit}")
        require(fetched.decode().strip() == args.head, "fetched object is not the exact commit")
        _, fetched_tree = git("fetched-tree", "rev-parse", args.head + "^{tree}")
        require(fetched_tree.decode().strip() == args.tree, "fetched tree differs")
        git("fast-forward-ancestry", "merge-base", "--is-ancestor", args.expected_start_head, args.head)
        git("fast-forward", "merge", "--ff-only", "--no-edit", args.head)
        run("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"])
        for relative, expected in REQUIREMENTS.items():
            require(sha_file(SOURCE / relative) == expected, "final requirements need a separately reviewed environment")
        _, raw = run("rust-version", [str(TOOLCHAIN / "rustc"), "--version"])
        require(raw.decode().startswith("rustc 1.95.0 "), "Rust version differs")
        _, raw = run("cargo-version", [str(TOOLCHAIN / "cargo"), "--version"])
        require(raw.decode().startswith("cargo 1.95.0 "), "Cargo version differs")
        for label, python, wanted in (
            ("conformance", CONFORMANCE, {"numpy": "1.26.4", "cryptography": "50.0.2"}),
            ("runtime", RUNTIME, {"packaging": "26.3"}),
        ):
            program = ("import importlib.metadata as m,json,sys; expected=" + repr(wanted)
                       + "; actual={k:m.version(k) for k in expected}; "
                       + "assert actual==expected and sys.version_info[:2]==(3,12); "
                       + "print(json.dumps({'actual':actual,'python':sys.version,'executable':sys.executable}))")
            run(label + "-environment", [str(python), "-B", "-c", program])
        _, raw = run("verify-source-before", [str(CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-before.json")])
        identity = json.loads(raw)
        require(identity["tested_commit"] == args.head and identity["tested_tree"] == args.tree
                and identity["tracked_worktree_verified"] is True, "source identity differs")
        before_verified = True
        lane, _ = run("repository-truth", ["bash", "scripts/ci/ci_job.sh", "repository-truth"],
                      timeout=2700, required=False)
        lane_exit = lane["exit"]
        require(lane_exit == 0, "repository-truth failed or timed out")
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    finally:
        after_valid = False
        try:
            row, raw = run("verify-source-after", [str(CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
                "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-after.json")],
                required=False)
            if row["exit"] == 0 and before_verified:
                after = json.loads(raw)
                before = json.loads((evidence / "source-before.json").read_bytes())
                require(after == before, "full source before/after differs")
                after_valid = True
            else:
                errors.append("final source verification did not confirm the tested source")
        except Exception as error:
            errors.append("post-run verification: " + repr(error))
        result["lane_exit"] = lane_exit
        result["source_before_after_verified"] = after_valid
        result["status"] = "passed" if not errors and lane_exit == 0 and after_valid else "failed"
        result["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps({"status": result["status"], "head": args.head, "tree": args.tree,
                      "summary": str(evidence / "summary.json"),
                      "summary_sha256": sha_file(evidence / "summary.json")}), flush=True)
    return 0 if result["status"] == "passed" else 1

if __name__ == "__main__":
    sys.exit(main())
