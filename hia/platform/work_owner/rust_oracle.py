"""Run complete unchanged original Host/W1 methods against actual native frames."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import traceback
from hia.platform.paid_cpu.dependency import environment, captured_std, bound_build_environment, executable_interpreter
from hia.platform.transport_request.rust_oracle import command
from hia.platform.host_resource.rust_oracle import REQUIRED_TESTS
from .build import ROOT, HERE, identity, need, read_json, source_manifest, write_json
from .bundle import canonical_root, check_snapshot, original_manifest, require_output_and_target, validate_bundle
from .cases import corpus, original_cases, PROTOCOL_ONLY

RESOURCE = "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs"
PUBLIC = "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"
DECLARATIONS = {
    RESOURCE: b'\n#[cfg(test)]\nmod hia_work_owner_oracle {\n    include!("hia_work_owner_oracle.rs");\n}\n',
    PUBLIC: b'\n#[cfg(test)]\npub(crate) mod hia_work_owner_bridge {\n    include!("hia_work_owner_bridge.rs");\n}\n',
}
TEST = "host_kernel_parent::kernel_parent::resource_tests::hia_work_owner_oracle::same_worker_evaluate"
IGNORED = "host_kernel_parent::kernel_parent::relative_tests::relative_limit_child_probe"
MARKER = "HIA_WORK_OWNER_ORACLE:"

def original_artifact(events, isolated):
    rows = [event for event in events if event.get("reason") == "compiler-artifact"
            and event.get("target", {}).get("name") == "trnm_pon_node"
            and event["target"].get("kind") == ["lib"] and event.get("executable")
            and event.get("profile", {}).get("test") is True]
    need(len(rows) == 1, "No unique complete original Node library test executable")
    row = rows[0]
    need(Path(row["manifest_path"]) == isolated / "trillionnium/crates/trnm-pon-node/Cargo.toml"
         and Path(row["target"]["src_path"]) == isolated / "trillionnium/crates/trnm-pon-node/src/lib.rs",
         "Actual original test artifact has another source or target")
    return row

def compare(actual, native, cases):
    need([r["name"] for r in actual] == [r["name"] for r in cases],
         "Actual original complete case roster/order differs")
    rows = []
    for observed, frame, case in zip(actual, native, cases, strict=True):
        h = frame["header"]; differences = []
        for key, expected in (("domain", h["domain"]), ("code", h["code"]), ("progress", frame["progress"])):
            if observed.get(key) != expected: differences.append(key)
        if h["worker_tid"]:
            need(observed.get("joined") is True and type(observed["worker_tid"]) is int
                 and observed["main_tid"] != observed["worker_tid"] and observed["worker_tid"] > 0,
                 "Original did not execute and join a different actual worker")
            need(observed.get("actual_original_W1") is True
                 and observed.get("actual_original_Host_primitives") is True
                 and observed.get("actual_original_task_alive_and_final_resource") is True
                 and observed.get("production_fixed_parent_authority") is False
                 and observed.get("complete_Node_or_paid_checkpoint") is False,
                 "Actual original-method observation scope differs")
            for key, expected in (("host_calls", h["worker_host_calls"]), ("before_checks", h["pre_checks"]),
                                  ("after_checks", h["post_checks"]), ("work_code", h["work_code"])):
                if observed.get(key) != expected: differences.append(key)
            if observed.get("input_sha256") != hashlib.sha256(bytes.fromhex(case["request_hex"])).hexdigest():
                differences.append("input_sha256")
            if observed.get("before_values") != frame["host_before"][8:14]: differences.append("before_values")
            if not h["post_sample_error"]:
                if observed.get("after_values") != frame["host_after"][8:14]: differences.append("after_values")
                if observed.get("delta_values") != frame["host_after"][14:18]: differences.append("delta_values")
        if h["domain"] == 0:
            product = bytes.fromhex(observed["product_hex"])
            if len(product) != 16384 or hashlib.sha256(product).hexdigest() != frame["product_sha256"]:
                differences.append("product")
            for key in ("challenge_hex", "task_hex", "ticket_hex"):
                if observed.get(key) != frame[key]: differences.append(key)
        elif observed.get("product_hex") is not None:
            differences.append("failed-original-published-product")
        rows.append({"name": case["name"], "status": "PASS" if not differences else "FAIL",
                     "different_fields": differences, "actual_original": observed, "actual_native": frame})
    return rows

def original_comparison(repository, bundle, output, target):
    need(__debug__, "Original Work owner admission refuses optimized Python")
    environment()
    repository = canonical_root(repository); bundle = canonical_root(bundle)
    output, target = require_output_and_target(output, target, ROOT, repository, bundle)
    admitted = validate_bundle(bundle, repository, require_trace=True)
    standard = captured_std(); env = bound_build_environment(standard)
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "trnm.hia.work-owner-original.v1", "status": "FAIL",
              "retained_original_tests": [], "stages": [], "comparisons": [],
              "production_fixed_parent_authority": False, "whole_Node_or_paid_checkpoint_closed": False,
              "original_4s_16_service_gate_closed": False,
              "original_controlled_CLOCK1_fault_comparison": "OPEN",
              "native_protocol_controls_without_original_equivalent": sorted(PROTOCOL_ONLY)}
    fence = None; binary = None; binary_identity = None; original = admitted["original_sources"]
    try:
        cases = original_cases()
        actual_native = {case["name"]: row for case, row in zip(corpus(), admitted["native"], strict=True)}
        native = [actual_native[case["name"]] for case in cases]
        input_path = output / "cases.jsonl"
        input_path.write_bytes(b"".join((json.dumps(c, sort_keys=True, separators=(",", ":")) + "\n").encode() for c in cases))
        input_identity = identity(input_path)
        isolated = output / "isolated-source"; isolated.mkdir(mode=0o700)
        for relative, expected in original.items():
            source = repository / relative
            need(identity(source) == expected, "Original changed during copy: " + relative)
            destination = isolated / relative; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        prefixes = {}
        hooks = {
            "trillionnium/crates/trnm-pon-node/src/hia_work_owner_oracle.rs": (HERE / "rust_reference.rs").read_bytes(),
            "trillionnium/crates/trnm-pon-node/src/hia_work_owner_resource_fixture.rs":
                (ROOT / "hia/platform/host_resource/rust_reference.rs").read_bytes(),
            "trillionnium/crates/trnm-pon-node/src/ingress/hia_work_owner_bridge.rs": (HERE / "rust_bridge.rs").read_bytes(),
        }
        for relative, declaration in DECLARATIONS.items():
            path = isolated / relative; prefixes[relative] = path.read_bytes()
            need(b"mod hia_work_owner_" not in prefixes[relative], "Original already contains private observer")
            path.write_bytes(prefixes[relative] + declaration)
        for relative, raw in hooks.items():
            path = isolated / relative
            need(not path.exists(), "Private original child collides with production source")
            path.write_bytes(raw)
        hook_ids = {name: identity(isolated / name) for name in hooks}
        before = {"source_inputs": admitted["source_inputs"], "original_sources": original,
                  "native_bundle": admitted["snapshot"], "standard_library": standard,
                  "input": input_identity, "private_hooks": hook_ids,
                  "appended_declarations": {key: value.hex() for key, value in DECLARATIONS.items()},
                  "actual_cargo": standard["cargo_executable"], "actual_rustc": standard["compiler_executable"],
                  "target_dir": str(target), "original_histories": len(cases)}
        write_json(output / "source-before.json", before)
        def check():
            check_snapshot(bundle, admitted)
            need(original_manifest(repository) == original, "Complete original source graph changed")
            need(captured_std() == standard, "Bound compiler/std/runtime dependency changed")
            need(identity(input_path) == input_identity, "Exact original corpus changed")
            observed = {path.relative_to(isolated).as_posix() for path in isolated.rglob("*") if path.is_file()}
            need(observed == set(original) | set(hooks), "Isolated original file roster changed")
            for relative, expected in original.items():
                path = isolated / relative
                if relative in DECLARATIONS:
                    need(path.read_bytes() == prefixes[relative] + DECLARATIONS[relative],
                         "Complete original production prefix/declaration changed")
                else: need(identity(path) == expected, "Isolated original source changed: " + relative)
            for relative, expected in hook_ids.items():
                need(identity(isolated / relative) == expected, "Actual compiled private observer changed")
            if binary is not None:
                need(identity(binary) == binary_identity, "Independent original binary changed")
        fence = check; check()
        def call(argv, label, timeout=180, runtime=None):
            try:
                raw, row = command(argv, isolated, output, label, timeout=timeout,
                                   env=env if runtime is None else runtime)
                report["stages"].append(row); return raw
            except BaseException:
                path = output / label / "receipt.json"
                if path.exists(): report["stages"].append(read_json(path))
                raise
        raw = call([standard["cargo_executable"]["path"], "test", "--locked", "--manifest-path",
                    str(isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node", "--lib", "--no-run",
                    "--message-format=json", "--target-dir", str(target)], "cargo-original-test-build", 900)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        artifact = original_artifact(events, isolated)
        compiled = Path(artifact["executable"]).resolve(strict=True)
        binary_identity = identity(compiled)
        binary = output / "original-test-binary"
        shutil.copyfile(compiled, binary); binary.chmod(0o500)
        need(identity(binary) == binary_identity and binary.stat().st_nlink == 1,
             "Independent complete original binary copy differs")
        report["executable"] = {"path": str(binary), **binary_identity}
        report["compiled_executable"] = {"path": str(compiled), **binary_identity}
        report["interpreter"] = executable_interpreter(binary, standard)
        report["artifact"] = artifact
        check()
        runtime = {"PATH": env.get("PATH", "/usr/bin:/bin"), "TRNM_HIA_WORK_OWNER_CORPUS": str(input_path)}
        listed = call([str(binary), "--list"], "list-original-tests", 30, runtime)
        ignored_raw = call([str(binary), "--ignored", "--list"], "list-original-ignored-tests", 30, runtime)
        tests = {line.removesuffix(": test") for line in listed.decode().splitlines() if line.endswith(": test")}
        ignored = {line.removesuffix(": test") for line in ignored_raw.decode().splitlines()
                   if line.startswith("host_kernel_parent::kernel_parent::") and line.endswith(": test")}
        need(ignored == {IGNORED}, "Original ignored Host subprocess probe roster differs")
        relative_tests = isolated / "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_relative_tests.rs"
        need('#[ignore = "only invoked by the bounded nonregular-limit parent"]\nfn relative_limit_child_probe()'
             in relative_tests.read_text(), "Ignored original probe no longer belongs to its bounded parent tests")
        retained = sorted(name for name in tests if name.startswith("host_kernel_parent::kernel_parent::")
                          and "::hia_work_owner_oracle::" not in name and name not in ignored)
        need(TEST in tests and len(retained) == 44 and set(REQUIRED_TESTS) <= set(retained),
             "Mandatory complete original Host tests/observer were not linked")
        report["ignored_direct_probe"] = {"name": IGNORED, "ordinary_pass_claimed": False,
            "reason": "executed by its original bounded nonregular-limit parent tests"}
        for i, name in enumerate(retained):
            raw = call([str(binary), "--exact", name, "--nocapture", "--test-threads=1"],
                       "retained-original-" + str(i).zfill(3), 60, runtime)
            need("test result: ok. 1 passed; 0 failed;" in raw.decode(), "Retained original test did not execute")
            report["retained_original_tests"].append(name)
        raw = call([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
                   "actual-original-same-worker", 300, runtime)
        need("test result: ok. 1 passed; 0 failed;" in raw.decode(), "Actual original observer test did not execute")
        actual = [json.loads(line.split(MARKER, 1)[1]) for line in raw.decode().splitlines() if MARKER in line]
        report["comparisons"] = compare(actual, native, cases)
        report["passed"] = sum(r["status"] == "PASS" for r in report["comparisons"])
        report["total"] = len(report["comparisons"])
        report["actual_original_progress_points"] = sum(len(r["progress"]) for r in actual)
        report["actual_original_worker_histories"] = sum(r.get("joined") is True for r in actual)
        need(report["passed"] == report["total"] == 57, "Actual original Host/W1 methods differ from native")
        check(); report["status"] = "PASS"
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        if fence is not None:
            try:
                fence(); write_json(output / "source-after.json", before)
                report["source_after"] = "MATCH"; report["binary_after"] = "MATCH" if binary else "NOT_BUILT"
            except BaseException as error:
                report.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        else: report["source_after"] = "ADMISSION_DID_NOT_COMPLETE"
        write_json(output / "report.json", report)
    return report

def main():
    need(__debug__, "Work owner original CLI refuses optimized Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    report = original_comparison(args.repository, args.bundle, args.output, args.target_dir)
    print(json.dumps({key: report.get(key) for key in
        ("status", "passed", "total", "actual_original_progress_points", "source_after", "binary_after", "failure")},
        sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
