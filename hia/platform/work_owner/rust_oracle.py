"""Run complete unchanged original Host/W1 methods against actual native frames."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import stat
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
from .clock_comparison import run as compare_clock_faults
from .clock_evidence import TEST as CLOCK_TEST
from .paid_faults import TEST as PAID_CLOCK_TEST, run_original as compare_paid_clock_faults

RESOURCE = "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs"
PUBLIC = "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"
SCALAR = "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"
DECLARATIONS = {
    RESOURCE: b'\n#[cfg(test)]\nmod hia_work_owner_oracle {\n    include!("hia_work_owner_oracle.rs");\n}\n',
    PUBLIC: b'\n#[cfg(test)]\npub(crate) mod hia_work_owner_bridge {\n    include!("hia_work_owner_bridge.rs");\n}\n',
    SCALAR: b'\n#[cfg(test)]\npub(crate) mod hia_work_paid_probe { include!("hia_work_paid_probe.rs"); }\n',
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

def paid_observation_shape(observed):
    """Require the exact finite original Paid snapshots, including JSON types."""
    unsigned = lambda value: type(value) is int and 0 <= value < 1 << 64
    def credit(value):
        need(type(value) is str, "Original Paid credit decimal type")
        number = int(value)
        need(str(number) == value and -(1 << 127) <= number < 1 << 127,
             "Original Paid credit canonical extent")
    global_ = observed.get("paid_global")
    need(type(global_) is dict and set(global_) == {
        "poisoned", "unavailable", "in_flight", "credit_ns",
        "termination_reserved_ns", "verified_completions", "flow"},
        "Complete original Paid global field roster")
    need(all(type(global_[key]) is bool for key in ("poisoned", "unavailable"))
         and all(unsigned(global_[key]) for key in ("in_flight", "termination_reserved_ns",
                                                   "verified_completions")),
         "Original Paid global exact counter/latch types")
    credit(global_["credit_ns"])
    flow = global_["flow"]
    fields = {"initial_credit_ns", "credited_refill_ns", "discarded_refill_ns",
              "booked_reservation_ns", "live_debited_cpu_ns", "settlement_residual_cpu_ns",
              "settled_full_cpu_ns", "settlement_discard_ns"}
    need(type(flow) is dict and set(flow) == fields, "Complete original Paid flow field roster")
    credit(flow["initial_credit_ns"])
    need(all(unsigned(flow[key]) for key in fields - {"initial_credit_ns"}),
         "Original Paid flow exact counter types")
    if "paid_checkpoints" in observed:
        need(unsigned(observed["paid_checkpoints"]), "Original Paid checkpoint exact count type")
    receipt = observed.get("paid")
    if receipt is None:
        return
    cpu = {"owner_cpu_ns", "scoped_worker_cpu_ns", "total_cpu_ns",
           "live_paid_cpu_ns", "residual_cpu_ns"}
    workers = {"spawned_workers", "started_workers", "finished_workers", "known_workers"}
    need(type(receipt) is dict and set(receipt) == cpu | workers | {
        "schema", "live_refused", "accounting_unavailable"}
         and receipt["schema"] == "service-owner-scoped-thread-cpu-settlement-v1",
         "Complete original Paid settlement schema/field roster")
    need(all(receipt[key] is None or unsigned(receipt[key]) for key in cpu)
         and all(unsigned(receipt[key]) for key in workers)
         and all(type(receipt[key]) is bool for key in ("live_refused", "accounting_unavailable")),
         "Original Paid settlement exact Option/counter/latch types")

def settlement(observed, frame):
    """Compare original Paid facts and conservation, never independent CPU times.

    These predicates are the complete checks used by the retained real
    Work/Paid original run. Both implementations measure their own CPU clocks;
    equal nanosecond values across those separate runs are not required.
    """
    paid_observation_shape(observed)
    paid = frame["paid"]; owner = paid["owner"]; epoch = paid["epoch"]
    receipt = observed.get("paid")
    checkpoints = observed.get("paid_checkpoints", 0)
    need(type(checkpoints) is int and checkpoints == paid["checkpoint_calls"],
         "Original checkpoint invocation count")
    global_ = observed["paid_global"]
    need(type(global_["poisoned"]) is bool
         and global_["poisoned"] == (paid["global_poison"] != 0),
         "Actual original global poison")
    for key, index in (("in_flight", 6), ("termination_reserved_ns", 7), ("verified_completions", 8)):
        need(type(global_[key]) is int and global_[key] == epoch[index],
             "Actual original global " + key)
    if not global_["poisoned"]:
        need(type(global_["unavailable"]) is bool and global_["unavailable"] == (epoch[1] != 0),
             "Actual global Unknown")
    if receipt is None:
        need(owner[0] == 0 or observed.get("worker_panicked") is True
             or (type(observed.get("begin_error")) is int and observed["begin_error"] == owner[2] != 0),
             "Original omitted its returned Paid settlement")
        return
    mapping = {"owner_cpu_ns": (4, 5), "scoped_worker_cpu_ns": (6, 7),
               "total_cpu_ns": (8, 9), "live_paid_cpu_ns": (10, 11),
               "residual_cpu_ns": (12, 13)}
    for key, (some, value) in mapping.items():
        need((receipt[key] is not None) == bool(owner[some]), "Original known/Unknown " + key)
        if receipt[key] is not None:
            need(type(receipt[key]) is int and 0 <= receipt[key] < 1 << 64,
                 "Actual original u64 CPU field")
    for key, index in (("spawned_workers", 14), ("started_workers", 15),
                       ("finished_workers", 16), ("known_workers", 17)):
        need(type(receipt[key]) is int and receipt[key] == owner[index],
             "Original real scoped-worker count")
    for key, index in (("live_refused", 18), ("accounting_unavailable", 19)):
        need(type(receipt[key]) is bool and receipt[key] == (owner[index] != 0),
             "Original receipt failure latch")
    if receipt["total_cpu_ns"] is not None:
        need(receipt["total_cpu_ns"] == receipt["owner_cpu_ns"] + receipt["scoped_worker_cpu_ns"],
             "Original CPU union")
    if receipt["residual_cpu_ns"] is not None:
        need(receipt["residual_cpu_ns"] == receipt["total_cpu_ns"] - receipt["live_paid_cpu_ns"],
             "Original unique residual")

def original_hooks():
    """Only private test children accompany the complete original prefixes."""
    return {
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_clock.rs":
            (HERE / "rust_clock_reference.rs").read_bytes(),
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_oracle.rs":
            (HERE / "rust_reference.rs").read_bytes(),
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_resource_fixture.rs":
            (ROOT / "hia/platform/host_resource/rust_reference.rs").read_bytes(),
        "trillionnium/crates/trnm-pon-node/src/ingress/hia_work_owner_bridge.rs":
            (HERE / "rust_bridge.rs").read_bytes(),
        "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/hia_work_paid_probe.rs":
            (HERE / "rust_paid_reference.rs").read_bytes(),
    }

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
                 and observed.get("actual_original_finite_paid_work_checkpoints") is True
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
        paid_difference = None
        try:
            settlement(observed, frame)
        except (ValueError, KeyError, TypeError, IndexError) as error:
            differences.append("paid_settlement")
            paid_difference = repr(error)
        rows.append({"name": case["name"], "status": "PASS" if not differences else "FAIL",
                     "different_fields": differences, "paid_difference": paid_difference,
                     "actual_original": observed, "actual_native": frame})
    return rows

def capture_loader(standard):
    path = Path(standard["sysroot"]) / "lib"
    need(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
         "Normal compiler loader directory is not canonical")
    value = path.stat()
    need(stat.S_ISDIR(value.st_mode), "Normal compiler loader path is not a directory")
    # This is the actual selected compiler's directory, not the production
    # cgroup parent. Its complete metadata is fenced without inventing a new
    # permission restriction absent from the original SQLite build contract.
    return {"path": str(path), "device": value.st_dev, "inode": value.st_ino,
            "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid}

def capture_sqlite(events, isolated, target, output):
    crate = isolated / "trillionnium/crates/trnm-sqlite-io-boundary"
    prefix = "path+" + crate.as_uri() + "#"
    rows = [row for row in events if row.get("reason") == "build-script-executed"
            and type(row.get("package_id")) is str and row["package_id"].startswith(prefix)]
    need(len(rows) == 1, "Unique actual original SQLite boundary build result missing")
    row = rows[0]; environment = dict(row.get("env", []))
    need(row.get("cfgs") == ["trnm_sqlite_layout_witness"]
         and environment.get("TRNM_SQLITE3_BUILD_FENCE") == "sqlite-3.54.1-normal-native-linux-layout-v4"
         and environment.get("TRNM_SQLITE3_AMALGAMATION_SHA256") ==
             "0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52"
         and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in environment,
         "Unmodified original SQLite build qualification did not pass")
    need(b"trnm SQLite I/O boundary UNQUALIFIED" not in
         (output / "cargo-original-test-build/stderr.raw").read_bytes(),
         "Original SQLite gate emitted an unqualified warning")
    directory = Path(row["out_dir"]).absolute()
    need(directory.resolve(strict=True) == directory and target.resolve() in directory.parents,
         "Actual SQLite build output escaped the bound Cargo target")
    saved = output / "actual-sqlite-qualification"; saved.mkdir(mode=0o700)
    files = {}
    names = ("libtrnm_sqlite_layout_witness.a", "trnm-witness-symbols.stdout", "trnm-witness-symbols.stderr")
    pairs = [(directory / name, saved / name) for name in names]
    pairs += [(directory.parent / name, saved / ("build-script-" + name + ".raw")) for name in ("output", "stderr")]
    for source, destination in pairs:
        captured = identity(source)
        shutil.copyfile(source, destination)
        need(identity(source) == identity(destination) == captured, "Actual SQLite artifact copy changed")
        files[str(source)] = captured; files[str(destination)] = captured
    result = {"artifact": row, "build_fence": environment["TRNM_SQLITE3_BUILD_FENCE"], "files": files,
              "production_Node_execution_claimed": False}
    write_json(output / "actual-sqlite-qualification.json", result)
    return result, files

def original_comparison(repository, bundle, output, target):
    need(__debug__, "Original Work owner admission refuses optimized Python")
    environment()
    repository = canonical_root(repository); bundle = canonical_root(bundle)
    output, target = require_output_and_target(output, target, ROOT, repository, bundle)
    admitted = validate_bundle(bundle, repository, require_trace=True)
    standard = captured_std(); env = bound_build_environment(standard)
    loader = capture_loader(standard)
    need(not env.get("LD_LIBRARY_PATH"), "Caller loader override survived admission")
    env["LD_LIBRARY_PATH"] = loader["path"]
    rustdoc = Path(standard["compiler_executable"]["path"]).parent / "rustdoc"
    rustdoc_identity = identity(rustdoc); env["RUSTDOC"] = str(rustdoc)
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "trnm.hia.work-owner-original.v2", "status": "FAIL",
              "retained_original_tests": [], "stages": [], "comparisons": [],
              "production_fixed_parent_authority": False, "whole_Node_or_paid_checkpoint_closed": False,
              "original_4s_16_service_gate_closed": False,
              "original_controlled_CLOCK1_fault_comparison": "NOT_RUN",
              "original_paid_CLOCK_fault_comparison": "NOT_RUN",
              "native_protocol_controls_without_original_equivalent": sorted(PROTOCOL_ONLY)}
    fence = None; binary = None; binary_identity = None; sqlite_files = {}; original = admitted["original_sources"]
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
        hooks = original_hooks()
        for relative, declaration in DECLARATIONS.items():
            path = isolated / relative; prefixes[relative] = path.read_bytes()
            need(all(token not in prefixes[relative] for token in
                     (b"mod hia_work_owner_", b"mod hia_work_paid_probe")),
                 "Original already contains private observer")
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
                  "target_dir": str(target), "original_histories": len(cases),
                  "controlled_CLOCK1_profiles": 18, "derived_normal_compiler_loader": loader,
                  "actual_rustdoc": {"path": str(rustdoc), **rustdoc_identity},
                  "cargo_configuration": ["build.incremental=false"]}
        write_json(output / "source-before.json", before)
        def check():
            check_snapshot(bundle, admitted)
            need(original_manifest(repository) == original, "Complete original source graph changed")
            need(captured_std() == standard, "Bound compiler/std/runtime dependency changed")
            need(capture_loader(standard) == loader and identity(rustdoc) == rustdoc_identity,
                 "Derived normal compiler loader or rustdoc changed")
            for path, expected in sqlite_files.items():
                need(identity(Path(path)) == expected, "Actual SQLite witness changed")
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
        raw = call([standard["cargo_executable"]["path"], "--config", "build.incremental=false", "test", "--locked", "--manifest-path",
                    str(isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node", "--lib", "--no-run",
                    "--message-format=json", "--target-dir", str(target)], "cargo-original-test-build", 900)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        report["sqlite_qualification"], sqlite_files = capture_sqlite(events, isolated, target, output)
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
        need(TEST in tests and CLOCK_TEST in tests and PAID_CLOCK_TEST in tests and len(retained) == 44 and set(REQUIRED_TESTS) <= set(retained),
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
        check()
        report["original_controlled_CLOCK1_fault_comparison"] = "RUNNING"
        try:
            report["controlled_clock"] = compare_clock_faults(binary, binary_identity, output / "controlled-clock",
                                                             admitted, check=check)
            report["original_controlled_CLOCK1_fault_comparison"] = "PASS"
        except BaseException:
            report["original_controlled_CLOCK1_fault_comparison"] = "FAIL"
            raise
        report["original_paid_CLOCK_fault_comparison"] = "RUNNING"
        try:
            report["paid_clock_faults"] = compare_paid_clock_faults(binary, binary_identity,
                output / "paid-clock-faults", admitted, check=check)
            report["original_paid_CLOCK_fault_comparison"] = "PASS"
        except BaseException:
            report["original_paid_CLOCK_fault_comparison"] = "FAIL"
            raise
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
        paid_report = output / "paid-clock-faults/report.json"
        if paid_report.exists():
            report["paid_clock_faults_report"] = identity(paid_report)
        clock_report = output / "controlled-clock/report.json"
        if clock_report.exists():
            report["controlled_clock_report"] = identity(clock_report)
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
