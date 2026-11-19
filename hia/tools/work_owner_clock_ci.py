"""Independent complete-byte readers for Work owner primitive and original CLOCK additions.

This module never executes an original program, changes an auxv, injects a fault
or grants production authority. It rereads captured observations only.
"""
from __future__ import annotations
import hashlib
import io
import json
import lzma
import math
from pathlib import Path
import stat
import tarfile
import tempfile
from hia.platform.work_owner import cases
from hia.platform.work_owner.clock_comparison import original_input
from hia.platform.work_owner.clock_evidence import audit, TEST, validate_observer_controls
from hia.platform.work_owner.faults import profiles

RAW_NAMES = ("report.json", "events.jsonl", "stdout.raw", "stderr.raw")
CONTROL_SPECS = (
    ("positive-original-canonical-JSON", "private-raw-positive", True),
    ("panic-count-bool", "clock-EIO-2", False),
    ("host-count-float", "clock-EIO-2", False),
    ("retained-progress-bool", "clock-EIO-2", False),
    ("unbound-executed-image", "clock-EIO-2", False),
    ("worker-syscall-after-terminal", "clock-EIO-2", False),
    ("role-link-sequence-float", "clock-EIO-2", False),
    ("birth-event-float", "clock-EIO-2", False),
    ("clone-fallback-integer", "clock-EIO-2", False),
    ("join-still-live-clear-word", "clock-EIO-2", False),
    ("join-zero-without-consumed-libc-state", "clock-EIO-2", False),
    ("coherent-actual-counter-bytes", "clock-EIO-2", False),
    ("coherent-missing-counter-EOF", "clock-EIO-2", False),
    ("summary-auxv-disconnected", "clock-EIO-2", False),
    ("coherent-extra-auxv-word", "clock-EIO-2", False),
    ("summary-timespec-disconnected", "private-raw-positive", False),
    ("coherent-actual-deadline-overrun", "private-raw-positive", False),
    ("failed-clock-claims-timespec", "clock-EIO-2", False),
    ("omitted-actual-injection", "clock-EIO-2", False),
    ("paid-checkpoint-count-bool", "private-raw-positive", False),
    ("paid-checkpoint-count-omitted", "private-raw-positive", False),
    ("paid-live-not-retired", "private-raw-positive", False),
    ("paid-live-charge-disconnected", "private-raw-positive", False),
    ("paid-global-poison-type", "private-raw-positive", False),
    ("paid-global-credit-minted", "private-raw-positive", False),
    ("paid-global-extra-authority", "private-raw-positive", False),
    ("paid-settlement-union", "private-raw-positive", False),
    ("paid-settlement-residual", "private-raw-positive", False),
    ("coherent-paid-clock-role", "private-raw-positive", False),
    ("panic-paid-account-available", "clock-EIO-2", False),
    ("panic-paid-returned-settlement", "clock-EIO-2", False),
    ("positive-fault-after-restoration", "clock-EIO-2", True),
)
RAW_COUNTS = {"case_count": 177, "call_count": 9503, "buffer_count": 546,
              "snapshot_count": 7819, "logical_capture_bytes": 6012238470,
              "chunk_count": 19432, "physical_chunk_bytes": 73481101}


def primitive_summary(q, report):
    # bundle.validate_bundle has independently reconstructed every complete body
    # and guard already; this additional gate binds the public summary and counts.
    p = report["primitives"]
    raw = p.get("raw_evidence")
    q.need(p.get("raw_readback") == "PASS" and type(raw) is dict
           and raw.get("schema") == "trnm.hia.work-owner-primitive-bytes.v1"
           and raw.get("guards_and_complete_bodies_retained") is True,
           "Primitive complete guarded byte capture absent")
    q.need(all(type(raw.get(name)) is int and raw[name] == count for name, count in RAW_COUNTS.items()),
           "Primitive captured body/guard accounting differs")
    q.need(all(type(raw.get(name)) is int and raw[name] >= 0 for name in ("native_cpu_ns", "native_wall_ns"))
           and q.file_id(raw.get("manifest")) and q.file_id(raw.get("calls")),
           "Primitive actual timing or full raw identity has another type")
    return {"primitive_raw_guard_arenas_retained": True, "primitive_raw_evidence": raw,
            "primitive_actual_calls": 9503, "primitive_buffers": 546, "primitive_snapshots": 7819,
            "primitive_logical_capture_bytes": 6012238470, "primitive_chunk_count": 19432,
            "primitive_raw_readback": "PASS",
            "primitive_readback_scope": "All actual guarded backing buffers before/after all 9503 calls; complete 177-control roster independently reconstructed."}


def patch_bytes(q, archive, entries):
    """Read one exact regular-file patch; no extraction or permissive tar paths."""
    q.need(type(entries) is dict and set(entries) <= set(RAW_NAMES)
           and all(q.file_id(value) for value in entries.values()), "CLOCK patch roster or identity differs")
    packed = q.regular(archive).read_bytes()
    declared = sum(value["bytes"] for value in entries.values())
    q.need(declared <= 384 << 20, "CLOCK patch exceeds the captured finite profile")
    bound = declared + 4 * 1024 + 2 * tarfile.RECORDSIZE
    decoder = lzma.LZMADecompressor(memlimit=64 << 20)
    expanded = decoder.decompress(packed, max_length=bound + 1)
    q.need(len(expanded) <= bound and decoder.eof and not decoder.unused_data,
           "Truncated, concatenated or overlong CLOCK patch stream")
    result = {}; last_end = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as stream:
        for item in stream:
            q.need(item.name in entries and item.name not in result and item.isfile()
                   and item.type == tarfile.REGTYPE and not item.sparse and not item.pax_headers
                   and not item.linkname and item.mode == 0o600
                   and item.uid == item.gid == item.mtime == 0
                   and item.uname == item.gname == ""
                   and type(item.size) is int and item.size == entries[item.name]["bytes"],
                   "CLOCK patch member path/type/extent/metadata differs")
            with stream.extractfile(item) as member:
                raw = member.read()
            q.need(q.same(q.bytes_id(raw), entries[item.name]), "CLOCK patch full bytes differ")
            result[item.name] = raw
            last_end = item.offset_data + ((item.size + 511) // 512) * 512
    tail = expanded[last_end:]
    q.need(set(result) == set(entries) and 1024 <= len(tail) <= tarfile.RECORDSIZE + 1024
           and not any(tail) and len(expanded) % tarfile.RECORDSIZE == 0,
           "CLOCK patch omitted a member or hid trailing bytes")
    return result


def clock_reader_controls(q, directory, report, complete, source_inputs, executable, baseline, argv, env):
    q.need(type(report) is dict and report.get("schema") == "trnm.hia.work-owner-actual-clock-reader-controls.v2"
           and report.get("status") == "PASS" and report.get("failure") is None
           and report.get("source_after") == report.get("baseline_after") == "MATCH"
           and report.get("final_fence_failure") is None and q.same(report.get("source_inputs"), source_inputs)
           and type(report.get("actual_native_or_Rust_processes_executed_by_controls")) is int
           and report["actual_native_or_Rust_processes_executed_by_controls"] == 0
           and report.get("public_actual_reader_api") == "hia.platform.work_owner.clock_evidence.audit"
           and report.get("full_source_qualification_claimed_by_these_controls") is False,
           "Actual CLOCK reader control scope/source/fence differs")
    for key, count in (("count", 32), ("positive", 2), ("negative", 30)):
        q.need(type(report.get(key)) is int and report[key] == count, "CLOCK raw control count/type differs")
    rows = report.get("rows")
    q.need(type(rows) is list and len(rows) == len(CONTROL_SPECS)
           and [row.get("name") for row in rows] == [spec[0] for spec in CONTROL_SPECS],
           "Complete actual CLOCK reader control roster differs")
    templates = {}
    for label in ("private-raw-positive", "clock-EIO-2"):
        templates[label] = {name: q.regular(directory.parent / label / name).read_bytes() for name in RAW_NAMES}
    q.need(q.same(report.get("baseline"), {label: {name: q.bytes_id(raw) for name, raw in files.items()}
                                         for label, files in templates.items()}),
           "Raw-control baselines do not match the complete original captures")
    expected_files = {"report.json"}
    for row, (name, label, wanted) in zip(rows, CONTROL_SPECS, strict=True):
        expected_files.update((name + ".json", name + ".tar.xz"))
        q.need(q.same(q.read(directory / (name + ".json")), row)
               and row.get("baseline") == label and row.get("status") == "PASS"
               and row.get("expected_acceptance") is wanted and row.get("actual_acceptance") is wanted
               and (row.get("actual_failure") is None if wanted else type(row.get("actual_failure")) is str),
               "Actual CLOCK control result/type differs")
        ids = row.get("complete_mutated_raw")
        unchanged = row.get("unchanged_files_from_baseline")
        q.need(type(ids) is dict and set(ids) == set(RAW_NAMES) and all(q.file_id(x) for x in ids.values())
               and type(unchanged) is list and len(unchanged) == len(set(unchanged))
               and all(type(name) is str and name in RAW_NAMES for name in unchanged),
               "CLOCK mutant complete-byte map differs")
        archive = directory / (name + ".tar.xz")
        q.need(q.same(q.identity(archive), row.get("mutated_files_archive")), "CLOCK mutant archive differs")
        changed = {name: wanted_id for name, wanted_id in ids.items() if name not in unchanged}
        patch = patch_bytes(q, archive, changed)
        raw = {name: (templates[label][name] if name in unchanged else patch[name]) for name in RAW_NAMES}
        q.need(q.same({name: q.bytes_id(value) for name, value in raw.items()}, ids)
               and unchanged == [name for name in RAW_NAMES if raw[name] == templates[label][name]],
               "CLOCK raw patch/baseline reconstruction differs")
        with tempfile.TemporaryDirectory(prefix="hia-clock-ci-replay-") as temp:
            working = Path(temp)
            for name, value in raw.items():
                (working / name).write_bytes(value)
            profile = None if label == "private-raw-positive" else next(p for p in profiles() if p["name"] == label)
            accepted = False
            try:
                audit(working, argv=argv, environment=env, executable=executable,
                      baseline=baseline, profile=profile, disable_vdso=True)
                accepted = True
            except (ValueError, OSError, KeyError, IndexError, StopIteration, TypeError):
                pass
            q.need(accepted is wanted, "Complete retained CLOCK mutant changed its actual reader result")
    expected_files.update("working/" + name for name in RAW_NAMES)
    q.need(set(q.file_tree(directory)) == expected_files,
           "CLOCK raw controls contain missing, extra or unconsumed files")
    q.need(q.same(q.file_tree(directory / "working"), rows[-1]["complete_mutated_raw"]),
           "Restored final CLOCK control bytes differ")
    return {"original_clock_raw_controls": 32, "original_clock_raw_positive_controls": 2,
            "original_clock_raw_negative_controls": 30,
            "original_clock_raw_controls_report": q.identity(directory / "report.json")}


def observer_memory_controls(q, root, complete, source_inputs):
    """Require complete owned-memory and ordinal controls through their public raw reader."""
    directory = root / "observer-memory-controls"
    report = q.read(directory / "report.json")
    q.need(q.same(report, complete.get("observer_memory_controls"))
           and q.same(q.identity(directory / "report.json"), complete.get("observer_memory_controls_report")),
           "Original observer memory controls/report disconnected")
    actual = validate_observer_controls(directory, source_inputs=source_inputs, clock_root=root, complete=complete)
    expected = {"original_observer_memory_controls": 23, "original_observer_memory_positive_controls": 16,
                "original_observer_memory_negative_controls": 7, "original_observer_owned_memory_children": 1,
                "original_observer_clock_ordinal_replays": 20, "original_observer_memory_raw_reader_controls": 12,
                "original_observer_memory_raw_positive_controls": 2, "original_observer_memory_raw_negative_controls": 10,
                "original_observer_memory_controls_status": "PASS"}
    for name, key in (("report.json", "original_observer_memory_control_report"),
                      ("memory/report.json", "original_observer_memory_raw_report"),
                      ("reader-controls/report.json", "original_observer_memory_reader_report")):
        expected[key] = q.identity(directory / name)
    q.need(type(actual) is dict and q.same(actual, expected),
           "Complete original observer memory/ordinal control counts, scope or raw identities differ")
    return actual


def original_clock(q, directory, observed, report, admitted, executable):
    root = directory / "controlled-clock"
    complete = q.read(root / "report.json")
    q.need(q.same(complete, report.get("controlled_clock"))
           and q.same(q.identity(root / "report.json"), report.get("controlled_clock_report"))
           and complete.get("schema") == "trnm.hia.work-owner-original-clock-comparison.v2"
           and complete.get("status") == "PASS" and complete.get("failure") is None
           and complete.get("source_after") == complete.get("binary_after") == "MATCH"
           and complete.get("final_fence_failure") is None
           and q.same(complete.get("source_inputs"), admitted["source_inputs"])
           and q.same(complete.get("original_sources"), admitted["original_sources"])
           and type(complete.get("original_deadline_seconds")) is int and complete["original_deadline_seconds"] == 4
           and all(complete.get(name) is False for name in ("normal_vdso_fault_behavior_claimed",
               "production_fixed_parent_authority", "whole_Node_or_paid_checkpoint_closed",
               "original_4s_16_service_gate_closed")),
           "Original controlled CLOCK source/fence/profile differs")
    q.need(type(complete.get("positive_count")) is int and complete["positive_count"] == 2
           and type(complete.get("fault_count")) is int and complete["fault_count"] == 18,
           "Original controlled CLOCK counts/types differ")
    baseline, input_case = original_input()
    q.need(q.regular(root / "baseline.jsonl").read_bytes() == q.encode(input_case) + b"\n"
           and q.same(complete.get("input"), q.identity(root / "baseline.jsonl")),
           "Original CLOCK input lost its exact original-method projection")
    argv = [str(observed / "original-test-binary"), "--exact", TEST, "--nocapture", "--test-threads=1"]
    env = {"PATH": "/usr/bin:/bin", "TRNM_HIA_WORK_OWNER_CORPUS": str(observed / "controlled-clock/baseline.jsonl")}
    q.need(q.same(complete.get("argv"), argv) and q.same(complete.get("environment"), env)
           and q.same(complete.get("executable"), executable), "Actual original CLOCK invocation/binary differs")
    work = [("normal-vdso-positive", False, None), ("private-raw-positive", True, None)]
    work += [(p["name"], True, p) for p in profiles()]
    rows = complete.get("rows")
    q.need(type(rows) is list and len(rows) == 20
           and [row.get("name") for row in rows] == [item[0] for item in work],
           "Complete actual original CLOCK process roster differs")
    native = {row["name"]: row for row in admitted["report"]["clock_faults"]["rows"]}
    for row, (label, private, profile) in zip(rows, work, strict=True):
        path = root / label
        actual = audit(path, argv=argv, environment=env, executable=executable,
                       baseline=baseline, profile=profile, disable_vdso=private)
        trace = q.read(path / "report.json")
        duration = trace.get("duration_seconds")
        q.need(type(duration) in (int, float) and math.isfinite(duration) and duration > 0
               and q.same(q.read(path / "audit.json"), actual), "Actual CLOCK audit or duration differs")
        q.positive_test(q.regular(path / "stdout.raw").read_bytes(), TEST)
        expected = {"name": label, "status": "PASS", "audit": actual,
                    "trace_report": q.identity(path / "report.json"), "actual_seconds": duration,
                    "same_worker_paid_method_comparison": "PASS",
                    "independent_CPU_nanoseconds_equal": False}
        q.oracle.settlement(actual["observation"],
            admitted["native"][0] if profile is None else native[label]["physical"]["decoded"])
        if profile is not None:
            frame = native[label]["physical"]["decoded"]; header = frame["header"]; original = actual["observation"]
            values = [header[k] for k in ("domain", "code", "progress_count", "worker_host_calls", "alive_clocks",
                                          "pre_checks", "post_checks", "aggregate_samples", "joins")]
            q.need(q.same(values, [4, 1, profile["progress"], profile["worker_host_calls"], profile["ordinal"], 3, 0, 0, 1])
                   and q.same(frame["progress"], original["progress"]) and type(frame["product_bytes"]) is int
                   and frame["product_bytes"] == 0 and q.same(frame["host_after"], [0] * 32)
                   and original["worker_panicked"] is True and original["joined"] is True
                   and type(original["after_sample_attempts"]) is int and original["after_sample_attempts"] == 0
                   and original["product_hex"] is None, "Native/original actual CLOCK panic/join order differs")
            expected.update(actual_native_frame=frame,
                comparison_scope="actual panic class, retained progress, fresh Host order, real join and absent after-sampling/product",
                original_panic_relabelled_as_returned_error=False)
        q.need(q.same(row, expected), "Complete original CLOCK row differs from its full raw replay")
    controls = q.read(root / "actual-reader-controls/report.json")
    q.need(q.same(controls, complete.get("actual_raw_reader_controls")), "Original raw controls/report disconnected")
    result = clock_reader_controls(q, root / "actual-reader-controls", controls, complete,
                                   admitted["source_inputs"], executable, baseline, argv, env)
    result.update(observer_memory_controls(q, root, complete, admitted["source_inputs"]))
    result.update(original_controlled_CLOCK1_fault_comparison="PASS",
                  original_clock_positive_processes=2, original_clock_fault_processes=18,
                  original_clock_processes=20, original_clock_report=q.identity(root / "report.json"))
    return result


def sqlite_and_loader(q, directory, observed, before, report, events, standard, capture, live):
    from hia.platform.work_owner import rust_oracle as oracle
    loader = before.get("derived_normal_compiler_loader")
    q.need(type(loader) is dict and set(loader) == {"path", "device", "inode", "mode", "uid", "gid"}
           and loader["path"] == str(Path(standard["sysroot"]) / "lib")
           and all(type(loader[k]) is int and loader[k] >= 0 for k in ("device", "inode", "mode", "uid", "gid"))
           and stat.S_ISDIR(loader["mode"]) and q.same(before.get("cargo_configuration"), ["build.incremental=false"])
           and type(before.get("controlled_CLOCK1_profiles")) is int and before["controlled_CLOCK1_profiles"] == 18,
           "Actual normal compiler loader or exact Cargo profile differs")
    rustdoc = before.get("actual_rustdoc")
    q.need(type(rustdoc) is dict and set(rustdoc) == {"path", "bytes", "sha256"}
           and rustdoc["path"] == str(Path(standard["compiler_executable"]["path"]).parent / "rustdoc")
           and q.file_id({k: rustdoc[k] for k in ("bytes", "sha256")}),
           "Absolute actual rustdoc source binding differs")
    if live:
        q.need(q.same(oracle.capture_loader(standard), loader), "Actual compiler loader directory changed")
    if capture is not None:
        wanted = {k: rustdoc[k] for k in ("bytes", "sha256")}
        dest = capture / "original-dependencies/derived-rustdoc"
        if live:
            q.capture_file(Path(rustdoc["path"]), dest, wanted)
        else:
            q.need(q.same(q.identity(dest), wanted), "Captured actual rustdoc differs")
    crate = observed / "isolated-source/trillionnium/crates/trnm-sqlite-io-boundary"
    prefix = "path+" + crate.as_uri() + "#"
    selected = [row for row in events if row.get("reason") == "build-script-executed"
                and type(row.get("package_id")) is str and row["package_id"].startswith(prefix)]
    q.need(len(selected) == 1, "Unique actual SQLite build artifact absent")
    artifact = selected[0]; env = artifact.get("env")
    q.need(type(env) is list and all(type(row) is list and len(row) == 2 and all(type(x) is str for x in row) for row in env)
           and len({row[0] for row in env}) == len(env), "Actual SQLite build environment is malformed")
    env = dict(env)
    q.need(q.same(artifact.get("cfgs"), ["trnm_sqlite_layout_witness"])
           and env.get("TRNM_SQLITE3_BUILD_FENCE") == "sqlite-3.54.1-normal-native-linux-layout-v4"
           and env.get("TRNM_SQLITE3_AMALGAMATION_SHA256") == "0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52"
           and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in env
           and b"trnm SQLite I/O boundary UNQUALIFIED" not in q.regular(directory / "cargo-original-test-build/stderr.raw").read_bytes(),
           "Original unmodified SQLite qualification did not actually pass")
    record = q.read(directory / "actual-sqlite-qualification.json")
    q.need(q.same(record, report.get("sqlite_qualification")) and q.same(record.get("artifact"), artifact)
           and record.get("build_fence") == env["TRNM_SQLITE3_BUILD_FENCE"]
           and record.get("production_Node_execution_claimed") is False,
           "Actual SQLite qualification report differs")
    source = Path(artifact["out_dir"])
    q.need(source.is_absolute() and Path(before["target_dir"]) in source.parents,
           "Actual SQLite build directory escaped the bound target")
    names = ("libtrnm_sqlite_layout_witness.a", "trnm-witness-symbols.stdout", "trnm-witness-symbols.stderr")
    pairs = [(source / name, name) for name in names]
    pairs += [(source.parent / name, "build-script-" + name + ".raw") for name in ("output", "stderr")]
    expected = {}; observed_ids = {}
    for original, name in pairs:
        wanted = q.identity(directory / "actual-sqlite-qualification" / name)
        expected[str(original)] = wanted
        expected[str(observed / "actual-sqlite-qualification" / name)] = wanted
        observed_ids[name] = wanted
    q.need(q.same(record.get("files"), expected)
           and q.same(q.file_tree(directory / "actual-sqlite-qualification"), observed_ids),
           "Complete actual/captured SQLite witness bytes differ")
    return {"original_sqlite_build_fence": env["TRNM_SQLITE3_BUILD_FENCE"],
            "original_sqlite_qualification": q.identity(directory / "actual-sqlite-qualification.json"),
            "derived_normal_loader_identity": loader, "actual_rustdoc": rustdoc}
