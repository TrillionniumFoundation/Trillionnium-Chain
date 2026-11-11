from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback

ROOT = Path("/home/qian-qi/work/chain-quantum-daa-final-a0cf721c-20261111")
OUT = Path("/home/qian-qi/work/chain-quantum-daa-final-a0cf721c-20261111-evidence-native")
TARGET = Path("/home/qian-qi/work/chain-quantum-daa-20261111-qdaa-native-target")
EXPECTED_HEAD = "a0cf721c0a3fd5bc034e010119d2b09d148de8ec"
EXPECTED_TREE = "0fee4598d69db92beea2845c6d939f059f2d14a3"
EXPECTED_TESTS = {
    "public_growth_v1_control_output_reserve_serves_head_but_not_paid_operations",
    "public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work",
    "public_growth_v1_raw_new_ops_are_refused_by_legacy_and_arithmetic_listeners",
    "public_growth_v1_real_listener_lost_ack_exact_query_reorg_and_cold_reopen",
    "public_growth_v1_rechecks_future_ancestry_before_new_and_duplicate_activation",
    "public_growth_v1_wire_profile_namespace_and_free_lane_cannot_be_confused",
}
REQUIRED_TESTS = {
    "public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work",
    "public_growth_v1_rechecks_future_ancestry_before_new_and_duplicate_activation",
}
OUT.mkdir(mode=0o755, exist_ok=False)
source_arg = sys.orig_argv[sys.orig_argv.index("-c") + 1]
with (OUT / "driver.py").open("x", encoding="utf-8") as handle:
    handle.write(source_arg)
env = os.environ.copy()
overrides = {
    "RUSTUP_TOOLCHAIN": "1.95.0",
    "CARGO_TARGET_DIR": str(TARGET),
    "CARGO_BUILD_JOBS": "2",
    "RUST_TEST_THREADS": "1",
    "CARGO_INCREMENTAL": "0",
    "CARGO_TERM_COLOR": "never",
    "PYTHONDONTWRITEBYTECODE": "1",
}
cargo_bin = Path("/home/qian-qi/.cargo/bin")
if cargo_bin.is_dir():
    overrides["PATH"] = str(cargo_bin) + os.pathsep + env.get("PATH", os.defpath)
env.update(overrides)
record = {
    "schema": "trnm-native-current-clock-exact-source-local-v1",
    "scope": "exact committed source; six native library current-clock tests and workspace formatting",
    "root": str(ROOT),
    "evidence": str(OUT),
    "expected_commit": EXPECTED_HEAD,
    "expected_tree": EXPECTED_TREE,
    "status": "STARTING",
    "started_unix": time.time(),
    "environment_overrides": overrides,
    "cargo_profiles_modified": False,
    "commands": [],
    "failures": [],
    "limitations": [
        "No common-prefix, chain-growth, chain-quality or quantum-security proof is claimed.",
        "The fixture does not directly inject a wall-clock rollback during unlocked W1 and owner reacquisition.",
        "Historical precommit red/green observations remain separate from this exact-source run.",
    ],
}
source_before_verified = False

def save():
    pending = OUT / "receipt.json.tmp"
    pending.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(pending, OUT / "receipt.json")

def capture(argv):
    return subprocess.check_output(argv, cwd=ROOT, env=env, text=True).strip()

def file_hash(relative):
    raw = (ROOT / relative).read_bytes()
    return {"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def run(label, argv, *, cwd=ROOT):
    record["status"] = "RUNNING_" + label
    item = {"label": label, "argv": argv, "cwd": str(cwd), "started_unix": time.time(), "log": label + ".log"}
    record["commands"].append(item)
    save()
    print("NATIVE_PHASE_START " + label, flush=True)
    with (OUT / item["log"]).open("xb") as output:
        completed = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    item["exit_code"] = completed.returncode
    item["finished_unix"] = time.time()
    item["seconds"] = item["finished_unix"] - item["started_unix"]
    raw = (OUT / item["log"]).read_bytes()
    item["log_bytes"] = len(raw)
    item["log_sha256"] = hashlib.sha256(raw).hexdigest()
    save()
    print("NATIVE_PHASE_END " + label + " exit=" + str(completed.returncode), flush=True)
    return completed.returncode, raw.decode("utf-8", errors="strict")

def required_run(label, argv, *, cwd=ROOT):
    code, text = run(label, argv, cwd=cwd)
    if code != 0:
        raise RuntimeError(label + " exited " + str(code))
    return text

def verify_source(label):
    required_run(label, ["/usr/bin/python3", "-B", "scripts/ci/verify_ci_source.py",
                        "--kind", "head", "--expected-head", EXPECTED_HEAD,
                        "--output", str(OUT / (label + ".json"))])
    identity = json.loads((OUT / (label + ".json")).read_text())
    assert identity["tested_commit"] == EXPECTED_HEAD, identity
    assert identity["tested_tree"] == EXPECTED_TREE, identity
    assert identity["tracked_worktree_verified"] is True, identity
    return identity

try:
    record["head_before"] = capture(["git", "rev-parse", "HEAD"])
    record["tree_before"] = capture(["git", "rev-parse", "HEAD^{tree}"])
    record["branch_before"] = capture(["git", "symbolic-ref", "--short", "HEAD"])
    record["git_status_before"] = capture(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    assert record["head_before"] == EXPECTED_HEAD
    assert record["tree_before"] == EXPECTED_TREE
    assert record["branch_before"].startswith("fix/")
    assert record["git_status_before"] == ""
    assert TARGET.is_dir(), "Previous owned target is absent"
    record["reused_target_owner"] = json.loads((TARGET / "native-qdaa-owner.json").read_text())
    assert record["reused_target_owner"]["task"] == "native-precommit-clock-guard"
    record["cargo_graph_before"] = [file_hash("trillionnium/Cargo.toml"), file_hash("trillionnium/Cargo.lock")]
    record["source_before"] = verify_source("source-before")
    source_before_verified = True
    required_run("project-preflight", ["bash", "scripts/project-preflight.sh"])
    versions = {}
    for command in ("rustc", "cargo", "rustfmt"):
        versions[command] = required_run(command + "-version", [command, "--version"]).strip()
    record["toolchain_versions"] = versions
    assert versions["rustc"].startswith("rustc 1.95.0 "), versions
    assert versions["cargo"].startswith("cargo 1.95.0 "), versions
    code, raw = run("native-current-clock",
                    ["cargo", "test", "--locked", "--lib", "-p", "trnm-pon-node", "public_growth_v1", "--", "--nocapture"],
                    cwd=ROOT / "trillionnium")
    if code != 0:
        record["failures"].append("native-current-clock exit=" + str(code))
    actual = re.findall(r"^test ingress::public_v3::growth::tests::(public_growth_v1[A-Za-z0-9_]+) \.\.\. ok$", raw, re.M)
    summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$", raw, re.M)
    native_selection = {
        "actual_passed_test_names": actual,
        "required_test_names": sorted(REQUIRED_TESTS),
        "expected_test_names": sorted(EXPECTED_TESTS),
        "summaries": summaries,
        "library_targets": re.findall(r"^.*Running unittests src/lib\.rs.*$", raw, re.M),
        "passed": code == 0 and len(actual) == len(set(actual)) == 6
                  and set(actual) == EXPECTED_TESTS and REQUIRED_TESTS <= set(actual)
                  and len(summaries) == 1 and summaries[0][:4] == ("6", "0", "0", "0")
                  and len(re.findall(r"Running unittests src/lib\.rs", raw)) == 1,
    }
    with (OUT / "native-selection.json").open("x") as handle:
        json.dump(native_selection, handle, indent=2, sort_keys=True)
        handle.write("\n")
    record["native_selection"] = native_selection
    if not native_selection["passed"]:
        record["failures"].append("native test selection or actual result failed")
    fmt_code, _ = run("native-format", ["cargo", "fmt", "--all", "--", "--check"], cwd=ROOT / "trillionnium")
    if fmt_code != 0:
        record["failures"].append("native-format exit=" + str(fmt_code))
except BaseException as error:
    record["failures"].append(repr(error))
    with (OUT / "driver-error.log").open("x") as handle:
        traceback.print_exc(file=handle)
finally:
    if source_before_verified:
        try:
            record["source_after"] = verify_source("source-after")
            record["source_identity_bytes_equal"] = (OUT / "source-before.json").read_bytes() == (OUT / "source-after.json").read_bytes()
            assert record["source_identity_bytes_equal"], "Source identity changed"
            record["cargo_graph_after"] = [file_hash("trillionnium/Cargo.toml"), file_hash("trillionnium/Cargo.lock")]
            assert record["cargo_graph_before"] == record["cargo_graph_after"], "Cargo graph changed"
            record["git_status_after"] = capture(["git", "status", "--porcelain=v1", "--untracked-files=all"])
            assert record["git_status_after"] == "", "Working tree became dirty"
        except BaseException as error:
            record["failures"].append("source-after: " + repr(error))
            with (OUT / "source-after-error.log").open("x") as handle:
                traceback.print_exc(file=handle)
    record["finished_unix"] = time.time()
    record["status"] = "PASSED" if not record["failures"] else "FAILED"
    save()
    entries = {}
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name != "manifest.json":
            data = path.read_bytes()
            entries[path.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    with (OUT / "manifest.json").open("x") as handle:
        json.dump({"source_commit": EXPECTED_HEAD, "source_tree": EXPECTED_TREE, "files": entries}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("NATIVE_EXACT_SOURCE_COMPLETE " + json.dumps({"status": record["status"], "failures": record["failures"], "evidence": str(OUT)}), flush=True)
sys.exit(0 if record["status"] == "PASSED" else 1)
