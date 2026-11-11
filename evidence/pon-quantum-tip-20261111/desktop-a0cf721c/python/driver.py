import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback

EXPECTED_HEAD = "a0cf721c0a3fd5bc034e010119d2b09d148de8ec"
EXPECTED_TREE = "0fee4598d69db92beea2845c6d939f059f2d14a3"
ROOT = Path("/home/qian-qi/work/chain-quantum-daa-final-a0cf721c-20261111").resolve()
OUT = Path("/home/qian-qi/work/chain-quantum-daa-final-a0cf721c-20261111-evidence-python").resolve()
if not ROOT.is_dir() or not (ROOT / ".git").exists():
    raise SystemExit("exact candidate worktree must already exist")
if OUT == ROOT or ROOT in OUT.parents:
    raise SystemExit("observations must be outside the source tree")
OUT.mkdir(parents=True, exist_ok=False)
ENV = dict(os.environ)
ENV.update({"CI": "true", "PYTHONDONTWRITEBYTECODE": "1",
            "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
            "RUST_TEST_THREADS": "1", "CARGO_TERM_COLOR": "never",
            "RUSTUP_TOOLCHAIN": "1.95.0",
            "TRNM_EXPECTED_SOURCE_SHA": EXPECTED_HEAD})
commands = []
issues = []
suites = []
observations = {}
def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()
def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)
def record(name, argv, expected_exit=0, timeout=1800):
    if re.fullmatch(r"[a-z][a-z0-9-]*", name) is None:
        raise ValueError("invalid recorder name")
    argv = [str(item) for item in argv]
    (OUT / (name + ".argv")).write_bytes(b"\0".join(os.fsencode(s) for s in argv) + b"\0")
    (OUT / (name + ".cwd")).write_text(str(ROOT) + "\n", encoding="utf-8")
    entry = {"name": name, "argv": argv, "cwd": str(ROOT),
             "started_utc": utc(), "expected_exit": expected_exit}
    commands.append(entry)
    emit({"command": name, "event": "started"})
    started = time.monotonic()
    try:
        with (OUT / (name + ".log")).open("xb") as log:
            completed = subprocess.run(argv, cwd=ROOT, env=ENV,
                                       stdout=log, stderr=subprocess.STDOUT,
                                       timeout=timeout, check=False)
        code = completed.returncode
        entry["timed_out"] = False
    except subprocess.TimeoutExpired:
        code = 124
        entry["timed_out"] = True
    except Exception as exc:
        code = 125
        entry["launch_error"] = repr(exc)
    entry.update({"finished_utc": utc(),
                  "elapsed_seconds": time.monotonic() - started,
                  "exit_code": code,
                  "passed": code == expected_exit and not entry.get("timed_out", False)})
    (OUT / (name + ".exit")).write_text(str(code) + "\n", encoding="ascii")
    if not entry["passed"]:
        issues.append({"command": name, "reason": "unexpected exit or timeout",
                       "exit_code": code, "expected_exit": expected_exit})
    write_json(OUT / (name + ".receipt.json"), entry)
    emit(entry)
    return entry["passed"]
def require(condition, description):
    if not condition:
        raise AssertionError(description)
def read_json(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))
def evidence_check(name, function):
    try:
        value = function()
        write_json(OUT / (name + ".json"), {"passed": True, "observation": value})
        observations[name] = value
        emit({"check": name, "passed": True, "observation": value})
        return True
    except Exception as exc:
        failure = {"check": name, "reason": str(exc), "exception": type(exc).__name__}
        issues.append(failure)
        write_json(OUT / (name + ".json"), {"passed": False, "failure": failure})
        emit({"check": name, "passed": False, "failure": failure})
        return False
def identity_check():
    before = read_json("source-before.json")
    require(before["tested_commit"] == EXPECTED_HEAD, "source commit mismatch")
    require(before["tested_tree"] == EXPECTED_TREE, "source tree mismatch")
    require(before.get("tracked_worktree_verified") is True, "full tracked source bytes were not verified")
    require(before.get("tracked_entries", 0) > 0 and before.get("tracked_bytes", 0) > 0, "empty tracked source verification")
    return before
def suite_check(name):
    raw = (OUT / (name + ".log")).read_text(encoding="utf-8")
    counts = re.findall(r"(?m)^Ran ([0-9]+) tests? in .+$", raw)
    require(len(counts) == 1, "expected exactly one unittest count footer: " + name)
    require(int(counts[0]) > 0, "empty unittest suite: " + name)
    require(re.search(r"(?m)^OK\s*$", raw) is not None, "missing unittest OK: " + name)
    row = {"name": name, "tests": int(counts[0])}
    suites.append(row)
    return row
def qualification_check():
    raw = read_json("qualification-request.log")
    require(raw.get("qualification_request") == "REFUSED_UNPROVED_JOINT_CONSENSUS",
            "explicit unproved-joint-consensus refusal missing")
    return {"observed_exit": 3, "qualification_request": raw["qualification_request"]}
def panel_check():
    generated = read_json("paired-run.log")
    replayed = read_json("paired-replay.log")
    report = read_json("paired/report.json")
    identity = read_json("source-before.json")
    rows = report["observations"]
    complete = sum(row["summary"]["termination"] == "horizon"
                   and row["summary"]["trace_limit_reached"] is False
                   for row in rows)
    require(len(rows) == complete == 72, "72 complete nontruncated horizons required")
    require(len(report["paired_comparisons"]) == 36, "36 paired comparisons required")
    require(generated["runs"] == 72 and generated["pairs"] == 36
            and generated["complete_horizon_runs"] == 72
            and generated["panel_complete"] is True,
            "generator panel completeness mismatch")
    require(replayed["replayed_runs"] == 72 and replayed["pairs"] == 36,
            "complete 72 seeded replay required")
    require(generated["release_ready"] is False and replayed["release_ready"] is False,
            "model observations cannot claim release qualification")
    require(report["source"] == report["source_after"], "runner source changed")
    require(report["source"]["git_head"] == identity["tested_commit"] == EXPECTED_HEAD,
            "runner commit mismatch")
    require(report["source"]["tree"] == identity["tested_tree"] == EXPECTED_TREE,
            "runner tree mismatch")
    require(generated["tested_commit"] == EXPECTED_HEAD
            and generated["tested_tree"] == EXPECTED_TREE,
            "generator exact source identity mismatch")
    return {"complete_horizon_runs": complete, "pairs": 36,
            "generator": generated, "replay": replayed,
            "tested_commit": EXPECTED_HEAD, "tested_tree": EXPECTED_TREE,
            "native_w1_verified": False, "cp_cg_cq_proved": False,
            "release_ready": False}
def unchanged_check():
    before = read_json("source-before.json")
    after = read_json("source-after.json")
    require(before == after, "source-before and source-after differ")
    return after
started_utc = utc()
write_json(OUT / "attempt.json", {
    "schema": "trnm-quantum-tip-desktop-attempt-v1",
    "expected_head": EXPECTED_HEAD, "expected_tree": EXPECTED_TREE,
    "started_utc": started_utc, "source_root": str(ROOT),
    "python": sys.version, "python_executable": sys.executable,
    "uname": list(os.uname()),
    "execution_facility": "desktop durable process",
    "scope": "actual local source-bound execution; not a GitHub Actions result",
    "native_w1_verified": False, "cp_cg_cq_proved": False, "release_ready": False,
})
try:
    ready = record("source-before", ["python3", "scripts/ci/verify_ci_source.py",
                   "--kind", "head", "--expected-head", EXPECTED_HEAD,
                   "--output", OUT / "source-before.json"])
    if ready:
        ready = evidence_check("source-identity", identity_check)
    if ready:
        ready = record("project-preflight", ["bash", "scripts/project-preflight.sh"])
    if ready:
        record("source-inventory", ["python3", "scripts/refresh_distributed_source_inventory.py", "--check"])
        record("corpus-pins", ["python3", "scripts/ci/check_pq_research_integration.py"])
        ordered = [
            ("network-tests", "formal/pon-nakamoto-v1/test_quantum_network_sim.py"),
            ("adversarial-tests", "formal/pon-nakamoto-v1/test_quantum_adversarial_search.py"),
            ("resource-clock-tests", "formal/pon-nakamoto-v1/test_quantum_resource_clock.py"),
            ("joint-tests", "formal/pon-nakamoto-v1/test_joint_consensus_qualification.py"),
            ("participation-tests", "formal/pon-nakamoto-v1/test_dynamic_participation_v1.py"),
            ("lifetime-tests", "scripts/ci/test_pq_lifetime_budget.py"),
            ("w1-lifetime-tests", "scripts/ci/test_w1_lifetime_ledger.py"),
            ("storage-evidence-tests", "scripts/ci/test_cell_storage_convergence_ci.py"),
            ("discovery-evidence-tests", "scripts/ci/test_cell_discovery_v3_ci.py"),
            ("ci-contract-tests", "scripts/ci/test_ci_contract.py"),
        ]
        for name, path in ordered:
            if record(name, ["python3", path]):
                evidence_check(name + "-footer", lambda name=name: suite_check(name))
        record("joint-contract", ["python3", "formal/pon-nakamoto-v1/joint_consensus_qualification.py", "--check"])
        if record("qualification-request", ["python3", "formal/pon-nakamoto-v1/joint_consensus_qualification.py", "--require-qualified"], expected_exit=3):
            evidence_check("qualification-refusal-check", qualification_check)
        record("ci-contract", ["python3", "scripts/ci/check_ci_contract.py"])
        if record("paired-run", ["python3", "formal/pon-nakamoto-v1/quantum_tip_measurement_campaign.py", "--out", OUT / "paired"]):
            if record("paired-replay", ["python3", "formal/pon-nakamoto-v1/quantum_tip_measurement_campaign.py", "--verify", OUT / "paired"]):
                evidence_check("panel-completeness", panel_check)
    else:
        issues.append({"reason": "preflight or exact source verification failed; suites and campaign not started"})
except BaseException as exc:
    issues.append({"reason": "batch exception", "exception": type(exc).__name__, "message": str(exc)})
    (OUT / "batch-exception.log").write_text(traceback.format_exc(), encoding="utf-8")
finally:
    try:
        if record("source-after", ["python3", "scripts/ci/verify_ci_source.py",
                  "--kind", "head", "--expected-head", EXPECTED_HEAD,
                  "--output", OUT / "source-after.json"]):
            evidence_check("source-unchanged", unchanged_check)
    except BaseException as exc:
        issues.append({"reason": "source-after exception", "exception": type(exc).__name__, "message": str(exc)})
    if len(suites) != 10:
        issues.append({"reason": "not all ten unittest suites completed successfully",
                       "successful_suites": len(suites)})
    if "panel-completeness" not in observations:
        issues.append({"reason": "complete paired panel and seeded replay not observed"})
    summary = {
        "schema": "trnm-quantum-tip-desktop-execution-v1",
        "expected_head": EXPECTED_HEAD, "expected_tree": EXPECTED_TREE,
        "started_utc": started_utc, "finished_utc": utc(),
        "execution_facility": "desktop durable process",
        "passed": not issues, "issues": issues,
        "unittest_suites": suites,
        "actual_unittest_tests": sum(suite["tests"] for suite in suites),
        "observations": observations, "commands": commands,
        "native_w1_verified": False, "cp_cg_cq_proved": False, "release_ready": False,
        "scope": "local exact-source conditional observations; independent of GitHub Actions",
    }
    write_json(OUT / "execution-summary.json", summary)
    files = {}
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and path.name != "execution-manifest.json":
            raw = path.read_bytes()
            files[path.relative_to(OUT).as_posix()] = {
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    write_json(OUT / "execution-manifest.json", {
        "schema": "trnm-quantum-tip-desktop-artifacts-v1",
        "expected_head": EXPECTED_HEAD, "expected_tree": EXPECTED_TREE,
        "files": files, "passed": not issues,
        "scope": "raw actual local observations; no native or quantum consensus qualification",
    })
    emit({"event": "batch-complete", "passed": not issues,
          "actual_unittest_tests": summary["actual_unittest_tests"],
          "issues": issues, "out": str(OUT)})
sys.exit(0 if not issues else 1)
