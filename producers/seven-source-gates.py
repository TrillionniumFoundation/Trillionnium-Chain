#!/opt/homebrew/bin/python3
"""Run exactly seven local source gates, retaining every original output.

This does not execute hosted Host provisioning, publish refs, or grant hosted CI
qualification. The receipt is external to the immutable candidate.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys
ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
def sha(raw):
    return hashlib.sha256(raw).hexdigest()

PYTHON = "/opt/homebrew/bin/python3"
GATE_ENV = {
    "PATH": "/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONOPTIMIZE": "0",
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1",
}
def require(condition, message):
    if not condition:
        raise ValueError(message)
def require_unoptimized():
    if sys.flags.optimize != 0:
        raise RuntimeError("optimized Python disables publication guards")
def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)
def regular_bytes(path):
    path = pathlib.Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "file changed before read: " + str(path))
        raw = stream.read()
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "file changed during read: " + str(path))
    require(fingerprint(path.lstat()) == fingerprint(before),
            "file path changed during read: " + str(path))
    return raw
def gate_commands(head, evidence):
    evidence = pathlib.Path(evidence)
    def source(label):
        return [PYTHON, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                "--expected-head", head, "--output", str(evidence / ("source-" + label + ".json"))]
    return [
        ("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"]),
        ("verify-source-before", source("before")),
        ("repository-check", [PYTHON, "-B", "scripts/ci/check_repository.py"]),
        ("distributed-inventory-check", [PYTHON, "-B", "scripts/refresh_distributed_source_inventory.py", "--check"]),
        ("ci-contract", [PYTHON, "-B", "scripts/ci/check_ci_contract.py"]),
        ("pq-corpus", [PYTHON, "-B", "scripts/ci/check_pq_research_integration.py"]),
        ("verify-source-after", source("after")),
    ]
def validate_source_identity(raw, head, tree):
    value = strict_json(raw)
    expected = {
        "schema": "trnm-ci-source-v1", "kind": "head",
        "tested_commit": head, "tested_tree": tree, "candidate": head,
        "base": None, "prospective_merge": None,
        "tracked_worktree_verified": True, "tests_executed_by_identity_check": False,
    }
    require(isinstance(value, dict) and set(value) == set(expected) | {"tracked_entries", "tracked_bytes"},
            "source receipt field set differs")
    for key, wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key] == wanted,
                "source receipt identity differs: " + key)
    for key in ("tracked_entries", "tracked_bytes"):
        require(type(value[key]) is int and value[key] > 0, "empty or invalid source count: " + key)
    return value
def capture(argv, env, data=None, timeout=180):
    """Capture one owned process group; never retry a timed-out command."""
    try:
        process = subprocess.Popen(argv, cwd=SOURCE, env=env,
            stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as error:
        return subprocess.CompletedProcess(argv, 127, b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(data, timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired as expired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired as remaining:
            stdout, stderr = remaining.stdout or expired.stdout or b"", remaining.stderr or expired.stderr or b""
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            stderr += b"\nOwned process capture did not close after timeout; outcome UNKNOWN.\n"
        return subprocess.CompletedProcess(argv, 124, stdout, stderr)
def identity_snapshot(env):
    values = {}
    for name, args in (("head", ["rev-parse", "HEAD"]),
                       ("tree", ["rev-parse", "HEAD^{tree}"]),
                       ("status", ["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])):
        result = capture(["git", "--no-replace-objects", *args], env, timeout=60)
        require(result.returncode == 0, "identity read failed: " + name + ": " + result.stderr.decode(errors="replace"))
        values[name] = result.stdout.decode().strip()
    return values

def main():
    require_unoptimized()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    evidence = pathlib.Path(args.evidence_dir)
    require(evidence.is_absolute() and evidence.parent == ROOT
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", evidence.name),
            "evidence must be a direct canonical child of the authorized root")
    require(re.fullmatch(r"[0-9a-f]{40}", args.head) is not None
            and re.fullmatch(r"[0-9a-f]{40}", args.tree) is not None, "exact head/tree required")
    require(SOURCE.resolve(strict=True) == SOURCE and ROOT.resolve(strict=True) == ROOT,
            "source/evidence parent must be canonical")
    producer = ROOT / "run_final_prepublication_gates_v1.py"
    require(pathlib.Path(__file__).resolve(strict=True) == producer, "unexpected producer path")
    producer_sha = sha(regular_bytes(producer))
    evidence.mkdir(mode=0o700, exist_ok=False)
    env = os.environ.copy()
    env.update(GATE_ENV)
    receipt = {
        "schema": "root-final-prepublication-source-gates-v1",
        "head": args.head, "tree": args.tree, "source": str(SOURCE),
        "evidence_dir": str(evidence), "environment": GATE_ENV,
        "producer": {"path": str(producer), "sha256": producer_sha},
        "status": "running", "steps": [], "identities": {}, "source_observations": {},
        "errors": [], "hosted_ci_qualification": False,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    def save():
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    expected_identity = {"head": args.head, "tree": args.tree, "status": ""}
    try:
        receipt["identities"]["before"] = identity_snapshot(env)
        require(receipt["identities"]["before"] == expected_identity, "initial HEAD/tree/status differs")
        for label, argv in gate_commands(args.head, evidence):
            result = capture(argv, env, timeout=900)
            row = {"label": label, "cwd": str(SOURCE), "argv": argv, "exit": result.returncode}
            for channel, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
                path = evidence / (label + "." + channel)
                with path.open("xb") as stream:
                    stream.write(raw)
                row[channel + "_path"] = str(path)
                row[channel + "_bytes"] = len(raw)
                row[channel + "_sha256"] = sha(raw)
            row["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            receipt["steps"].append(row)
            save()
            print(json.dumps({"label": label, "exit": result.returncode}), flush=True)
        for phase in ("before", "after"):
            path = evidence / ("source-" + phase + ".json")
            raw = regular_bytes(path)
            step = next(x for x in receipt["steps"] if x["label"] == "verify-source-" + phase)
            require(raw == regular_bytes(pathlib.Path(step["stdout_path"])),
                    "source stdout/sidecar bytes differ: " + phase)
            value = validate_source_identity(raw, args.head, args.tree)
            receipt["source_observations"][phase] = {
                "path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": value}
        require(receipt["source_observations"]["before"]["identity"]
                == receipt["source_observations"]["after"]["identity"], "source before/after differ")
    except Exception as error:
        receipt["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try:
            receipt["identities"]["after"] = identity_snapshot(env)
            require(receipt["identities"]["after"] == expected_identity, "final HEAD/tree/status differs")
        except Exception as error:
            receipt["errors"].append(type(error).__name__ + ": " + str(error))
        passed = (not receipt["errors"] and len(receipt["steps"]) == 7
                  and all(type(x["exit"]) is int and x["exit"] == 0 for x in receipt["steps"]))
        receipt["status"] = "passed" if passed else "failed"
        receipt["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    raw = regular_bytes(evidence / "receipt.json")
    print(json.dumps({"status": receipt["status"], "receipt": str(evidence / "receipt.json"),
                      "sha256": sha(raw), "head": args.head, "tree": args.tree}), flush=True)
    return 0 if passed else 1
if __name__ == "__main__":
    sys.exit(main())
