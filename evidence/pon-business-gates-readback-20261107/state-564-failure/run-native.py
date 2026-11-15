#!/usr/bin/env python3
"""Exact-source component validation; never executes either cost observation."""
import hashlib, json, os, pathlib, re, subprocess, sys, time

BASE = pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107")
ROOT = BASE / "work-state-cell-619"
OUT = BASE / "state-cell-native-validation-fixed-20261107"
OLD_OUT = BASE / "state-cell-native-validation-20261107"
OLD = json.loads((OLD_OUT / "validation.json").read_text())
PREP = json.loads((OUT / "preparation.json").read_text())
HEAD = PREP["commit"]
assert HEAD == "564bd23a656061e272c4af22029a4829d71b4f64"
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == HEAD
assert subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True) == ""
ENV = os.environ.copy()
for key in list(ENV):
    if key.startswith("OPENSSL_") or key.startswith("TRNM_PQ_OPENSSL") or key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    ):
        ENV.pop(key, None)
for line in (BASE / "local-build/provider.exports").read_text().splitlines():
    if line and not line.startswith("#"):
        key, value = line.split("=", 1)
        ENV[key] = value
ENV.update({
    "PATH": "/home/qian-qi/.cargo/bin:" + ENV.get("PATH", ""),
    "CARGO_HOME": str(BASE / "local-build/cargo"),
    "CARGO_TARGET_DIR": str(BASE / "local-build/followup-target"),
    "CARGO_BUILD_JOBS": "8",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "0",
    "CARGO_PROFILE_TEST_DEBUG": "0",
    "RUST_TEST_THREADS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
})
def sha(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()
provider = pathlib.Path(ENV["TRNM_PQ_OPENSSL"])
assert sha(provider) == ENV["TRNM_PQ_OPENSSL_SHA256"]
assert ENV["TRNM_PQ_OPENSSL_SHA256"] == "79bd5e815ce341387d8299e66419fb8a56ba952892df8e3edc967cab60e83437"
provider_version = subprocess.check_output([str(provider), "version"], env=ENV, text=True).strip()
assert provider_version.startswith("OpenSSL 3.5.9 "), provider_version

def rebound(argv):
    return [s.replace(OLD["commit"], HEAD).replace(str(OLD_OUT), str(OUT)) for s in argv]

labels = [
    "same-scan-values", "same-scan-errors", "same-scan-order", "same-scan-cancellation",
    "original-cell-types", "original-wire-edges", "original-count-cancel",
]
original_steps = {step["label"]: step for step in OLD["steps"]}
planned = [{"label": "preflight-build", "argv": ["/usr/bin/bash", "scripts/project-preflight.sh"]}]
planned.append({"label": "full-source-before", "argv": rebound(original_steps["full-source-before"]["argv"])})
for label in labels:
    planned.append({"label": label, "argv": rebound(original_steps[label]["argv"])})
    planned.append({"label": label + "-required", "argv": rebound(original_steps[label + "-required"]["argv"])})
planned.append({"label": "workspace-clippy", "argv": rebound(original_steps["workspace-clippy"]["argv"])})
after = {"label": "full-source-after", "argv": rebound(original_steps["full-source-after"]["argv"])}
manifest = {
    "schema": "trnm-same-scan-native-component-validation-v2",
    "commit": HEAD, "tree": PREP["tree"], "parent": PREP["parent"],
    "started_unix": time.time(), "result": "RUNNING", "current_step": None,
    "driver": {"path": str(pathlib.Path(__file__).resolve()), "sha256": sha(__file__)},
    "original_failed_validation": {"path": str(OLD_OUT / "validation.json"), "sha256": sha(OLD_OUT / "validation.json"),
                                   "result": OLD["result"], "retained": True},
    "preparation": {"path": str(OUT / "preparation.json"), "sha256": sha(OUT / "preparation.json")},
    "adoption_contract": PREP["adoption_contract"],
    "build_environment": {k: ENV.get(k) for k in (
        "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
        "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUST_TEST_THREADS",
        "OPENSSL_DIR", "OPENSSL_STATIC", "OPENSSL_CONF", "OPENSSL_MODULES", "TRNM_PQ_OPENSSL",
        "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION", "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    )},
    "provider_version": provider_version, "planned_steps": planned + [after], "steps": [],
    "stop_on_first_failure": True,
    "command_timeout_seconds": 6600,
    "concurrency": "Independent component builds may use a different target; no timing comparison or original Host business qualification.",
    "business_gate_pass_claimed": False, "performance_claimed": False,
    "benchmark_executed": False, "qualification": False,
}
DEST = OUT / "validation.json"
assert not DEST.exists()

def save():
    temporary = DEST.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n")
    temporary.replace(DEST)

def run(step):
    manifest["current_step"] = step["label"]
    save()
    print(json.dumps({"phase": "begin", **step}), flush=True)
    log = OUT / (step["label"] + ".log")
    started = time.monotonic()
    timed_out = False
    with log.open("xb") as output:
        try:
            result = subprocess.run(step["argv"], cwd=ROOT, env=ENV, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=6600)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
            timed_out = True
    record = {
        **step, "exit_code": code, "timed_out": timed_out,
        "seconds": time.monotonic() - started, "log": str(log),
        "bytes": log.stat().st_size, "sha256": sha(log),
    }
    manifest["steps"].append(record)
    save()
    print(json.dumps({"phase": "end", **record}), flush=True)
    return code

save()
failed = None
try:
    for step in planned:
        if run(step) != 0:
            failed = step["label"]
            break
except BaseException as error:
    manifest["driver_error"] = repr(error)
    failed = manifest["current_step"] or "driver"
finally:
    try:
        if run(after) != 0:
            failed = failed or after["label"]
    except BaseException as error:
        manifest["final_source_error"] = repr(error)
        failed = failed or "final-source-driver"
    before_path, after_path = OUT / "source-before.json", OUT / "source-after.json"
    if before_path.exists() and after_path.exists():
        manifest["full_source_receipts"] = {
            "before_sha256": sha(before_path), "after_sha256": sha(after_path),
            "byte_identical": before_path.read_bytes() == after_path.read_bytes(),
        }
        if not manifest["full_source_receipts"]["byte_identical"]:
            failed = failed or "source-changed"
    else:
        failed = failed or "source-receipt-missing"
    first_log = OUT / "records/same-scan-values.log"
    if first_log.exists():
        executed = []
        for line in first_log.read_text(errors="replace").splitlines():
            if "Running unittests" not in line:
                continue
            match = re.search(r"\(([^()]+)\)\s*$", line)
            if not match:
                continue
            binary = pathlib.Path(match.group(1))
            if not binary.is_absolute():
                binary = ROOT / binary
            if binary.is_file():
                executed.append({"path": str(binary), "bytes": binary.stat().st_size, "sha256": sha(binary),
                                 "origin": "actual first successful/attempted Cargo Running line"})
        manifest["executed_node_binaries"] = executed
    manifest["failed_step"] = failed
    manifest["finished_unix"] = time.time()
    manifest["current_step"] = None
    manifest["result"] = "COMPONENT_FAILURE_RETAINED" if failed else "COMPONENT_CONTROLS_PASS_BUSINESS_UNQUALIFIED"
    manifest["all_seven_exact_and_named_readers_passed"] = all(
        any(s["label"] == label and s["exit_code"] == 0 for s in manifest["steps"])
        and any(s["label"] == label + "-required" and s["exit_code"] == 0 for s in manifest["steps"])
        for label in labels
    )
    manifest["workspace_strict_clippy_passed"] = any(
        s["label"] == "workspace-clippy" and s["exit_code"] == 0 for s in manifest["steps"]
    )
    save()
    print(json.dumps({"phase": "finished", "result": manifest["result"],
                      "failed_step": failed, "manifest": str(DEST), "sha256": sha(DEST)}), flush=True)
sys.exit(1 if failed else 0)
