#!/usr/bin/env python3
"""One fixed 128-sample ABBA and one unchanged original large-parent case."""
import hashlib, json, math, os, pathlib, re, shutil, statistics, subprocess, sys, time
from fractions import Fraction

BASE = pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107")
ROOT = BASE / "work-state-cell-619"
NATIVE = BASE / "state-cell-native-validation-null-fixture-20261107"
OUT = BASE / "state-cell-cost-5fdf-20261107"
HEAD = "5fdf7c236bd0f63a2f544ec006a427d786e6b235"
TREE = "125c2a7a4330a134dbe5b073f38e76ba42bfd2bc"
EXPECTED_BINARY_SHA = "33f1377e8e703ab9d9a2376d6da39bc3e50d02d7f9a8fd43032954f6941e596a"
BINARY = BASE / "local-build/followup-target/debug/deps/trnm_pon_node-3d075b189916f208"
DEST = OUT / "cost-validation.json"

def sha(path):
    with pathlib.Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def file_record(path):
    p = pathlib.Path(path)
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": sha(p)}

def actual_running_paths(log):
    raw = pathlib.Path(log).read_text(errors="replace")
    paths = []
    for line in raw.splitlines():
        if "Running unittests" in line:
            m = re.search(r"\(([^()]+)\)\s*$", line)
            if not m:
                raise ValueError("unparseable Cargo Running line: " + line)
            p = pathlib.Path(m.group(1))
            paths.append(str(p if p.is_absolute() else ROOT / p))
    if len(paths) != 1 or paths[0] != str(BINARY):
        raise ValueError("Cargo actual Running path must be unique and equal planned binary: " + repr(paths))
    return paths

assert sys.argv[1:] == ["--exclusive-window-granted"], "Root exclusive cost window is required"
assert not DEST.exists(), "This is a one-shot execution; previous results must not be overwritten"
binding_path = OUT / "execution-binding.json"
binding = json.loads(binding_path.read_text())
assert binding["commit"] == HEAD and binding["tree"] == TREE
assert binding["binary"]["path"] == str(BINARY)
assert binding["binary"]["sha256"] == EXPECTED_BINARY_SHA
native = json.loads((NATIVE / "validation.json").read_text())
assert sha(NATIVE / "validation.json") == "44f67e6ef45eda8e5d123cbca9ce36222fe9ec9686b07f36704f51d658299ef8"
assert native["result"] == "COMPONENT_CONTROLS_PASS_BUSINESS_UNQUALIFIED"
assert native["all_seven_exact_and_named_readers_passed"] and native["workspace_strict_clippy_passed"]
assert native["full_source_receipts"]["byte_identical"]
assert sha(NATIVE / "cost-plan.json") == "2c9d8d16a1941b890cc5113d06de5f5d66c97c5b51292ea27baa0c07137e0544"
assert sha(NATIVE / "adoption-contract-v2.json") == "270d029283f07152da8feff2ceba6f23208289e820c9eb5d77eb5a7fc819279c"
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == HEAD
assert subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip() == TREE
assert subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True) == ""
assert sha(BINARY) == EXPECTED_BINARY_SHA
actual_running_paths(NATIVE / "records/same-scan-values.log")

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
    "CARGO_BUILD_JOBS": "8", "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
    "RUST_TEST_THREADS": "1", "GIT_OPTIONAL_LOCKS": "0",
})
assert sha(ENV["TRNM_PQ_OPENSSL"]) == "79bd5e815ce341387d8299e66419fb8a56ba952892df8e3edc967cab60e83437"
assert subprocess.check_output([ENV["TRNM_PQ_OPENSSL"], "version"], env=ENV, text=True).startswith("OpenSSL 3.5.9 ")
plan = json.loads((NATIVE / "cost-plan.json").read_text())
manifest = {
    "schema": "trnm-same-scan-fixed-cost-observation-v1",
    "commit": HEAD, "tree": TREE, "started_unix": time.time(),
    "execution_binding": file_record(binding_path),
    "original_cost_plan": file_record(NATIVE / "cost-plan.json"),
    "adoption_contract": file_record(NATIVE / "adoption-contract-v2.json"),
    "component_validation": file_record(NATIVE / "validation.json"),
    "driver": file_record(__file__), "result": "RUNNING", "current_step": None, "steps": [],
    "binary": file_record(BINARY), "command_timeout_seconds": 6600,
    "original_full_d26_failure_retained": {
        "log": str(BASE / "local-build/native-d26/records/node-lib-allfeatures.log"),
        "sha256": "15b4a44a2dcbdcaed3c2a8c07fabb884de5577d9daac5b039505b8d1ecb202d5",
        "original_failure": "PUBLIC_MUTATION_CPU_BUDGET",
        "overridden_by_this_observation": False,
    },
    "all_samples_retained": True, "discarded_samples": 0, "discarded_warmups": 0,
    "root_window_declaration": binding["root_window_declaration"],
    "environment": {k: ENV.get(k) for k in native["build_environment"]},
    "scope": "Actual complete SQL scans and State materialization; each invocation begins with no memo. Same unoptimized test binary contains literal original and candidate. Not whole-node CPU, disk-cold, original CI resources, History qualification, finality or TPS.",
    "business_qualification": False, "history_qualification": False,
    "original_resource_qualification": False, "whole_chain_quantum_security_qualified": False,
}

def save():
    temp = DEST.with_suffix(".json.tmp")
    temp.write_text(json.dumps(manifest, indent=2) + "\n")
    temp.replace(DEST)

def run(label, argv, cargo=False):
    manifest["current_step"] = label
    save()
    print(json.dumps({"phase": "begin", "label": label, "argv": argv}), flush=True)
    log = OUT / (label + ".log")
    before = file_record(BINARY) if cargo else None
    if before:
        assert before["sha256"] == EXPECTED_BINARY_SHA
    start = time.monotonic()
    timeout = False
    with log.open("xb") as stream:
        try:
            code = subprocess.run(argv, cwd=ROOT, env=ENV, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=6600).returncode
        except subprocess.TimeoutExpired:
            code, timeout = 124, True
    entry = {"label": label, "argv": argv, "exit_code": code, "timed_out": timeout,
             "seconds": time.monotonic() - start, "log": file_record(log)}
    if cargo:
        entry["binary_before"] = before
        entry["binary_after"] = file_record(BINARY)
        raw = OUT / "records" / (label + ".log")
        entry["native_log"] = file_record(raw) if raw.exists() else None
        try:
            entry["actual_running_paths"] = actual_running_paths(raw)
            entry["actual_binary_path_verified"] = True
            assert entry["binary_after"]["sha256"] == EXPECTED_BINARY_SHA
            assert entry["binary_before"] == entry["binary_after"]
            entry["binary_unchanged"] = True
        except Exception as error:
            entry["binary_binding_error"] = repr(error)
            code = code or 1
        receipt = OUT / "records" / (label + ".json")
        if receipt.exists():
            entry["source_command_receipt"] = file_record(receipt)
            source_record = json.loads(receipt.read_text())
            entry["source_unchanged"] = source_record.get("before") == source_record.get("after")
            if source_record.get("status") not in ("command_succeeded", "command_failed") or not entry["source_unchanged"]:
                code = code or 1
    entry["effective_exit_code"] = code
    manifest["steps"].append(entry)
    save()
    print(json.dumps({"phase": "end", "label": label, "exit_code": code, "seconds": entry["seconds"]}), flush=True)
    if code:
        raise RuntimeError(label + " failed with exit " + str(code))

def source(label):
    run(label, ["/usr/bin/python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
                "--expected-head", HEAD, "--output", str(OUT / (label + ".json"))])

def analyze():
    raw = OUT / "records/slot-scan-abba.log"
    samples = []
    errors = []
    for number, line in enumerate(raw.read_text(errors="replace").splitlines(), 1):
        if '"same-scan-canonical-row-abba-v1"' not in line:
            continue
        try:
            entry, end = json.JSONDecoder().raw_decode(line[line.index("{"):])
            if entry.get("schema") != "same-scan-canonical-row-abba-v1":
                raise ValueError("schema")
            entry["original_log_line"] = number
            samples.append(entry)
        except Exception as error:
            errors.append({"line": number, "error": repr(error), "raw": line})
    (OUT / "raw-samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    cases = [("small_adjacent",128,64,"1.05"),("small_all_miss",128,64,"1.05"),
             ("large_adjacent",2100,4080,"0.90"),("large_all_miss",2100,4080,"1.05")]
    expected = [(case,count,width,round_,position,path) for case,count,width,_ in cases
                for round_ in range(8) for position,path in enumerate(
                    ["literal_original","same_scan_decoding","same_scan_decoding","literal_original"])]
    if len(samples) != 128:
        errors.append({"sample_count": len(samples), "expected": 128})
    for row, want in zip(samples, expected):
        observed = tuple(row.get(k) for k in ("case","rows","value_string_bytes","round","position","path"))
        if observed != want:
            errors.append({"wrong_sequence": list(observed), "expected": list(want)})
        if not isinstance(row.get("thread_cpu_ns"), int) or row["thread_cpu_ns"] <= 0:
            errors.append({"bad_cpu": row})
        try:
            if int(row["wall_ns"]) <= 0 or str(int(row["wall_ns"])) != row["wall_ns"]:
                errors.append({"bad_wall": row})
        except Exception:
            errors.append({"bad_wall": row})
    def stats(values):
        ordered = sorted(values)
        return {"n":len(values),"median":statistics.median(values),
                "p95":ordered[math.ceil(0.95*len(values))-1],
                "min":ordered[0],"max":ordered[-1]}
    def med_fraction(values):
        a=sorted(values); return Fraction(a[7]+a[8], 2)
    result = {"schema":"trnm-same-scan-fixed-cost-analysis-v1","raw_samples":file_record(OUT / "raw-samples.json"),
              "expected_samples":128,"actual_samples":len(samples),"errors":errors,
              "p95_method":"nearest rank; with 16 samples/path p95 is the maximum",
              "discarded_samples":0,"discarded_warmups":0,"cases":[],
              "all_predeclared_component_conditions_met":False,
              "business_qualification":False,"performance_scope":"complete SQL scan and State materialization only"}
    if not errors:
        for case,count,width,limit in cases:
            subset = [r for r in samples if r["case"] == case]
            paths = {}
            for path in ("literal_original","same_scan_decoding"):
                rows = [r for r in subset if r["path"] == path]
                paths[path] = {"thread_cpu_ns":stats([r["thread_cpu_ns"] for r in rows]),
                               "wall_ns":stats([int(r["wall_ns"]) for r in rows])}
            ref = [r["thread_cpu_ns"] for r in subset if r["path"] == "literal_original"]
            cand = [r["thread_cpu_ns"] for r in subset if r["path"] == "same_scan_decoding"]
            ratio = med_fraction(cand) / med_fraction(ref)
            rounds = []
            for round_ in range(8):
                rr = [r for r in subset if r["round"] == round_]
                a = statistics.mean(r["thread_cpu_ns"] for r in rr if r["path"] == "literal_original")
                b = statistics.mean(r["thread_cpu_ns"] for r in rr if r["path"] == "same_scan_decoding")
                rounds.append({"round":round_,"reference_mean_thread_cpu_ns":a,
                               "candidate_mean_thread_cpu_ns":b,"candidate_reference_ratio":b/a})
            result["cases"].append({
                "case":case,"rows":count,"value_string_bytes":width,"paths":paths,
                "median_thread_cpu_candidate_reference_ratio":float(ratio),
                "exact_ratio_numerator":ratio.numerator,"exact_ratio_denominator":ratio.denominator,
                "predeclared_maximum_ratio":float(limit),"condition_met":ratio <= Fraction(limit),
                "median_wall_candidate_reference_ratio": paths["same_scan_decoding"]["wall_ns"]["median"] /
                                                        paths["literal_original"]["wall_ns"]["median"],
                "per_round":rounds})
        result["all_predeclared_component_conditions_met"] = all(c["condition_met"] for c in result["cases"])
    (OUT / "cost-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    manifest["cost_analysis"] = file_record(OUT / "cost-analysis.json")
    manifest["all_predeclared_component_cost_conditions_met"] = result["all_predeclared_component_conditions_met"]
    save()
    if errors:
        raise RuntimeError("ABBA raw observations incomplete or noncanonical")
    print(json.dumps({"phase":"analysis","case_ratios":[[c["case"],c["median_thread_cpu_candidate_reference_ratio"],
                                                       c["condition_met"]] for c in result["cases"]]}), flush=True)

failure = None
save()
try:
    run("preflight", ["/usr/bin/bash","scripts/project-preflight.sh"])
    preserved = OUT / "candidate-node-test-binary"
    with BINARY.open("rb") as src, preserved.open("xb") as dst:
        shutil.copyfileobj(src,dst,1024*1024)
    preserved.chmod(0o555)
    assert sha(preserved) == EXPECTED_BINARY_SHA
    manifest["preserved_binary"] = file_record(preserved)
    save()
    source("source-before")
    assert sha(OUT / "source-before.json") == native["full_source_receipts"]["before_sha256"]
    for item in plan["selectors"]:
        label, test = item["label"], item["test"]
        argv = ["/usr/bin/python3","scripts/ci/record_pq_native_command.py",
                "--kind","head","--candidate",HEAD,"--tested",HEAD,
                "--output",str(OUT / "records"),"--label",label,"--",
                "/home/qian-qi/.cargo/bin/cargo","+1.95.0","test","--locked","--offline",
                "--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","--all-features",
                test,"--",*item["libtest_args"]]
        run(label,argv,cargo=True)
        run(label+"-required",["/usr/bin/python3","scripts/ci/check_required_native_test.py",
                              str(OUT / "records" / (label+".log")),"--test",test])
        if label == "slot-scan-abba":
            analyze()
except BaseException as error:
    failure = manifest["current_step"] or "driver"
    manifest["failure"] = {"step":failure,"error":repr(error)}
finally:
    try:
        source("source-after")
        same = (OUT / "source-before.json").read_bytes() == (OUT / "source-after.json").read_bytes()
        manifest["source_receipts"] = {"before":file_record(OUT / "source-before.json"),
                                       "after":file_record(OUT / "source-after.json"),"byte_identical":same}
        if not same:
            failure = failure or "source-changed"
    except BaseException as error:
        manifest["final_source_error"] = repr(error)
        failure = failure or "final-source"
    manifest["binary_final"] = file_record(BINARY)
    if manifest["binary_final"]["sha256"] != EXPECTED_BINARY_SHA:
        failure = failure or "final-binary-changed"
    manifest["failed_step"] = failure
    manifest["current_step"] = None
    manifest["finished_unix"] = time.time()
    manifest["result"] = ("COST_EXECUTION_FAILURE_RETAINED" if failure else
                          "FIXED_COST_OBSERVATIONS_COMPLETE_BUSINESS_UNQUALIFIED")
    manifest["all_original_parameters_unchanged"] = True
    save()
    print(json.dumps({"phase":"finished","result":manifest["result"],"failed_step":failure,
                      "manifest":str(DEST),"sha256":sha(DEST)}),flush=True)
sys.exit(1 if failure else 0)
