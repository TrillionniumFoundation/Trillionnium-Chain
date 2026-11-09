from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys, time, traceback

repo = Path("/home/qq/work/chain-rejection-resource-owner-956149-20261108")
out = Path("/home/qq/work/chain-rejection-resource-owner-956149-results/c1-static")
expected_head = "8fed7514193e06058f4eaf18f362a8fb968ce96f"
expected_tree = "1ebc5d4c252eacb727da67945892a9ae0b8d76c4"

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def capture(argv):
    return subprocess.check_output(argv, cwd=repo, text=True).strip()

def identity():
    return {
        "head": capture(["git", "rev-parse", "HEAD"]),
        "tree": capture(["git", "rev-parse", "HEAD^{tree}"]),
        "status": capture(["git", "status", "--porcelain=v1", "--untracked-files=all"]),
    }

def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

def file_info(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

commands = [
    ("preflight", ["bash", "scripts/project-preflight.sh"]),
    ("source-before", ["python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
        "--expected-head", expected_head, "--output", str(out / "source-before.json")]),
    ("source-inventory", ["python3", "scripts/refresh_distributed_source_inventory.py", "--check"]),
    ("repository-markdown", ["python3", "scripts/ci/check_repository.py"]),
    ("ci-contract", ["python3", "scripts/ci/check_ci_contract.py"]),
    ("pq-integration", ["python3", "scripts/ci/check_pq_research_integration.py"]),
    ("negative-source-integrity", ["python3", "scripts/ci/test_ci_source_integrity.py"]),
    ("negative-repository", ["python3", "scripts/ci/test_repository.py"]),
    ("negative-pq-integration", ["python3", "scripts/ci/test_pq_research_integration.py"]),
    ("negative-ci-contract", ["python3", "scripts/ci/test_ci_contract.py"]),
    ("source-after", ["python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
        "--expected-head", expected_head, "--output", str(out / "source-after.json")]),
]

before = identity()
write_json(out / "identity-before.json", before)
if before["head"] != expected_head or before["tree"] != expected_tree or before["status"]:
    raise RuntimeError("C1 source identity mismatch before static gates")
environment = {
    "python": capture(["python3", "--version"]),
    "git": capture(["git", "--version"]),
    "platform": capture(["uname", "-a"]),
}
write_json(out / "environment.json", environment)
records = []
for index, (name, argv) in enumerate(commands, 1):
    record = {
        "index": index, "name": name, "argv": argv, "cwd": str(repo),
        "expected_head": expected_head, "expected_tree": expected_tree,
        "start_utc": now(), "state": "running",
    }
    path = out / f"{index:02d}-{name}.json"
    write_json(path, record)
    stdout_path = out / f"{index:02d}-{name}.stdout.log"
    stderr_path = out / f"{index:02d}-{name}.stderr.log"
    started = time.monotonic_ns()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.run(argv, cwd=repo, stdout=stdout, stderr=stderr)
    record.update({
        "end_utc": now(), "wall_ns": time.monotonic_ns() - started,
        "exit_code": process.returncode, "state": "completed",
        "stdout": file_info(stdout_path), "stderr": file_info(stderr_path),
        "identity_after": identity(),
    })
    write_json(path, record)
    records.append(record)
    print(json.dumps({"name": name, "exit_code": process.returncode,
                      "wall_ns": record["wall_ns"]}), flush=True)
    after = record["identity_after"]
    if after["head"] != expected_head or after["tree"] != expected_tree or after["status"]:
        raise RuntimeError("C1 source changed during static gate " + name)
    if name in ("preflight", "source-before") and process.returncode:
        raise RuntimeError("Admission/source gate refused; later gates not run")
after = identity()
write_json(out / "identity-after.json", after)
summary = {
    "schema": "pon-resource-owner-c1-static-receipt-v1",
    "source_before": before, "source_after": after,
    "tracked_identity_unchanged": before == after,
    "commands": records, "count": len(records),
    "passed": sum(r["exit_code"] == 0 for r in records),
    "failed": [{"name": r["name"], "exit_code": r["exit_code"]} for r in records if r["exit_code"]],
    "native_or_cargo_builds": False,
    "runner": file_info(Path(__file__)),
    "completed_utc": now(),
}
write_json(out / "summary.json", summary)
print(json.dumps({"summary": str(out / "summary.json"), "count": summary["count"],
                  "passed": summary["passed"], "failed": summary["failed"],
                  "tracked_identity_unchanged": summary["tracked_identity_unchanged"]}), flush=True)
sys.exit(0 if not summary["failed"] else 1)
