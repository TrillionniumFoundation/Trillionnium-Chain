#!/usr/bin/env python3
"""Bind complete actual Work/Host evidence; this driver supplies no runtime authority."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import unittest

import hia.tests
from hia.tools import qualify_foundation_ci as base
from hia.tools import work_owner_clock_ci as next_evidence
from hia.tools import work_owner_transfer_ci as transfer
from hia.platform.work_owner import build, bundle, cases, rust_oracle as oracle

ROOT = build.ROOT
PREFIX = "hia-work-owner"
STAGE = "work-owner"
SCHEMA = "trnm.hia.work-owner-ci-binding.v4"
PACKAGE = "trnm.hia.work-owner-ci-evidence.v4"
REVIEW = "trnm.hia.work-owner-development-readback.v4"
READERS = ("hia/tools/qualify_work_owner_ci.py", "hia/tests/test_work_owner_ci.py",
           "hia/tools/qualify_foundation_ci.py", "hia/tools/work_owner_clock_ci.py",
           "hia/tools/work_owner_transfer_ci.py", "hia/tests/test_work_owner_transfer_ci.py",
           "hia/tools/qualify_work_handshake.py")
COUNTS = {"native_histories": 61, "native_progress_points": 27843,
          "primitive_controls": 177, "actual_syscall_traces": 3, "trace_controls": 27,
          "signal_controls": 14, "native_clock_fault_controls": 18,
          "original_histories": 57, "original_progress_points": 27841,
          "original_worker_histories": 56, "retained_original_test_count": 44,
          "original_process_stages": 48,
          "primitive_actual_calls": 9503, "primitive_buffers": 546, "primitive_snapshots": 7819,
          "primitive_logical_capture_bytes": 6012238470, "primitive_chunk_count": 19432,
          "original_clock_positive_processes": 2, "original_clock_fault_processes": 18,
          "original_clock_processes": 20, "original_clock_raw_controls": 32,
          "original_clock_raw_positive_controls": 2, "original_clock_raw_negative_controls": 30,
          "original_observer_memory_controls": 23, "original_observer_memory_positive_controls": 16,
          "original_observer_memory_negative_controls": 7, "original_observer_owned_memory_children": 1,
          "original_observer_clock_ordinal_replays": 20, "original_observer_memory_raw_reader_controls": 12,
          "original_observer_memory_raw_positive_controls": 2, "original_observer_memory_raw_negative_controls": 10,
          "native_paid_clock_processes": 16, "native_paid_clock_fault_processes": 15,
          "native_paid_clock_positive_processes": 1, "native_paid_clock_raw_reader_controls": 36,
          "native_paid_clock_raw_positive_controls": 2, "native_paid_clock_raw_negative_controls": 34,
          "original_paid_clock_processes": 17, "original_paid_clock_fault_processes": 15,
          "original_paid_clock_positive_processes": 2, "original_paid_clock_raw_reader_controls": 36,
          "original_paid_clock_raw_positive_controls": 2, "original_paid_clock_raw_negative_controls": 34}
SCOPES = ("production_fixed_parent_authority", "whole_Node_or_paid_checkpoint_closed",
          "original_4s_16_service_gate_closed", "physical_power_loss")
ROOT_LABELS = frozenset(("native", "original", "observations", "bootstrap", "capture"))
MAX_BYTES = 4 << 30


def need(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def same(first, second):
    return encode(first) == encode(second)


def object_hash(value):
    return hashlib.sha256(encode(value)).hexdigest()


def bytes_id(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def file_id(row):
    return (type(row) is dict and set(row) == {"bytes", "sha256"}
            and type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_BYTES
            and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None)


def member_name(value):
    need(type(value) is str and value and "\x00" not in value and "\\" not in value
         and "\n" not in value and "\r" not in value, "Unsafe evidence path")
    p = PurePosixPath(value)
    need(not p.is_absolute() and p.as_posix() == value and ".." not in p.parts
         and "." not in p.parts and len(value.encode()) <= 4096, "Noncanonical evidence path")
    return p


def regular(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, "Aliased file path: " + str(path))
    info = path.stat()
    need(stat.S_ISREG(info.st_mode), "Regular file required: " + str(path))
    return path


def identity(path):
    h = hashlib.sha256()
    size = 0
    with regular(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
            size += len(block)
        after = os.fstat(stream.fileno())
    current = Path(path).stat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
    need(fields(before) == fields(after) == fields(current) and size == before.st_size,
         "File changed during complete read: " + str(path))
    return {"bytes": size, "sha256": h.hexdigest()}


def read(path):
    return json.loads(regular(path).read_bytes(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def capture_file(source, destination, expected):
    need(file_id(expected) and identity(source) == expected, "Capture source differs")
    destination = Path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with regular(source).open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1 << 20)
    need(identity(destination) == identity(source) == expected, "Complete capture changed")


def file_tree(directory):
    directory = Path(directory).absolute()
    need(directory.resolve(strict=True) == directory and directory.is_dir(), "Canonical tree required")
    result = {}
    for path in sorted(directory.rglob("*")):
        name = path.relative_to(directory).as_posix()
        member_name(name)
        need(not path.is_symlink(), "Symbolic retained evidence")
        if path.is_dir():
            continue
        result[name] = identity(path)
    return result


def source_pair(directory, expected):
    before = read(directory / "source-before.json")
    after = read(directory / "source-after.json")
    need(same(before, after), "Complete CI source-before/after observations differ")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT).decode().strip()
    need(before.get("schema") == "trnm-ci-source-v1" and before.get("kind") == "head"
         and before.get("tested_commit") == before.get("candidate") == head == expected["git_head"]
         and before.get("tested_tree") == tree and before.get("tracked_worktree_verified") is True
         and type(before.get("tracked_entries")) is int and before["tracked_entries"] > 0
         and type(before.get("tracked_bytes")) is int and before["tracked_bytes"] > 0
         and before.get("tests_executed_by_identity_check") is False,
         "CI source observation does not bind the exact tested source")
    return {"before": identity(directory / "source-before.json"),
            "after": identity(directory / "source-after.json"), "observation": before}


def positive_test(raw, name):
    text = raw.decode()
    need(re.search(r"(?m)^test " + re.escape(name) + r" \.\.\. (?:ok)?", text) is not None,
         "Named original test is absent from its actual output")
    need(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None,
         "Original named test did not execute exactly one nonignored test")


def validate_primitives(report):
    """Read values and bind the independently reconstructed complete guarded arenas."""
    p = report["primitives"]
    need(p.get("schema") == "trnm.hia.work-owner-primitives.v1" and p.get("status") == "PASS"
         and p.get("production_authority") is False and p.get("actual_original_Rust") is False
         and p.get("mapping_profile") == "private RW capture then RX; no RWX mapping"
         and p.get("failure") is None and not p.get("final_fence_errors"),
         "Primitive execution scope or final fence differs")
    rows = p["rows"]
    need(type(p.get("count")) is int and p["count"] == len(rows) == 177,
         "Complete primitive observation roster required")
    lengths = list(range(130)) + [255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
        2047, 2048, 2049, 4095, 4096, 4097, 65535, 65536, 65537, 131135, 131136]
    expected = []
    for length in lengths:
        raw = bytes((i * 73 + length * 29 + 0xa5) & 255 for i in range(length))
        expected.append({"name": "sha-" + str(length), "kind": "sha", "status": "PASS",
                         "input": bytes_id(raw), "digest": hashlib.sha256(raw).hexdigest()})
    for name in ("input-bound", "output-short", "output-long", "arena-short"):
        expected.append({"name": "sha-" + name, "kind": "sha-bound", "status": "PASS"})
    mathematical = cases.corpus()[:4] + cases.corpus()[52:]
    for case, row in zip(mathematical, rows[154:167], strict=True):
        need(type(row.get("cpu_ns")) is int and row["cpu_ns"] >= 0,
             "Actual private arithmetic interval missing")
        raw = bytes.fromhex(case["request_hex"])
        expected.append({"name": case["name"], "kind": "work", "status": "PASS",
                         "return_code": case["code"], "progress": case["progress"],
                         "cpu_ns": row["cpu_ns"], "input": bytes_id(raw),
                         "product_sha256": hashlib.sha256(bytes.fromhex(case["product_hex"])).hexdigest()
                         if case["code"] == 0 else None,
                         "consumed_replay_and_cross_proof_rejected": True})
    for name in ("request-short", "event-short", "event-long", "arena-short"):
        expected.append({"name": name, "kind": "work-bound", "status": "PASS"})
    for name in ("foreign-tid", "foreign-generation", "foreign-role", "out-of-order-phase"):
        expected.append({"name": name, "kind": "owner-identity", "status": "PASS",
                         "fixture_is_production_authority": False})
    for name in ("paid", "paid-fixture"):
        expected.append({"name": name + "-standalone-constructor", "kind": "paid-constructor",
                         "status": "PASS", "initial_credit_ns": 2_000_000_000,
                         "foreign_tid_refused": True, "reinitialize_refused": True,
                         "fixture_is_production_authority": False})
    need(same(rows, expected), "Primitive digest/progress/product/extent/identity observations differ")
    return {"primitive_controls": 177, **next_evidence.primitive_summary(sys.modules[__name__], report)}


def native(directory, repository):
    admitted = bundle.validate_bundle(directory, repository, require_trace=True)
    report = admitted["report"]
    need(type(report.get("semantic_count")) is int and report["semantic_count"] == 61
         and type(report.get("progress_points")) is int and report["progress_points"] == 27843
         and report.get("actual_original_Rust") is False
         and all(report.get(name) is False for name in SCOPES[:3]),
         "Native exact counts or qualification scope changed")
    need(sum(len(row["progress"]) for row in admitted["native"]) == 27843,
         "Native progress count differs from all actual frames")
    primitives = validate_primitives(report)
    from hia.platform.work_owner.native_io import decode
    from hia.platform.work_owner.faults import profiles
    faults = report["clock_faults"]
    need(faults.get("original_Rust_fault_comparison") == "OPEN"
         and faults.get("production_fixed_parent_authority") is False
         and faults.get("ordinary_native_clock_values_supplied_by_caller") is False,
         "Native clock fault scope expanded")
    baseline = cases.corpus()[0]
    for row, profile in zip(faults["rows"], profiles(), strict=True):
        d = directory / "clock-faults" / profile["name"]
        observed = decode(regular(d / "stdout.raw").read_bytes())
        need(same(observed, row["physical"]["decoded"]), "Clock frame differs from actual bytes")
        h = observed["header"]
        need((h["domain"], h["code"], h["progress_count"], h["worker_host_calls"], h["alive_clocks"]) ==
             (4, 1, profile["progress"], profile["worker_host_calls"], profile["ordinal"])
             and h["pre_checks"] == 3 and h["post_checks"] == h["aggregate_samples"] == 0
             and h["joins"] == 1 and observed["host_after"] == [0] * 32
             and observed["product_bytes"] == 0
             and observed["progress"] == baseline["progress"][:profile["progress"]],
             "Clock panic did not preserve actual progress/join/error ordering")
        physical = row["physical"]
        need(type(physical.get("exit_code")) is int and physical["exit_code"] == 68
             and physical.get("failure") is None and physical.get("cleanup") is None
             and physical.get("stderr_hex") == ""
             and identity(d / "stdout.raw") == physical["stdout"]
             and identity(d / "stderr.raw") == physical["stderr"]
             and identity(d / "stderr.raw")["bytes"] == 0,
             "Actual controlled clock process did not complete as recorded")
    return admitted, {"native_report": identity(directory / "report.json"),
                      "native_histories": 61, "native_progress_points": 27843,
                      "actual_syscall_traces": 3, "trace_controls": 27, "signal_controls": 14,
                      "native_clock_fault_controls": 18, "physical_trace": "PASS",
                      "images": report["build"]["images"], **primitives, **admitted["paid_clock"]}


def original_stages(directory, report, retained):
    labels = ["cargo-original-test-build", "list-original-tests", "list-original-ignored-tests",
              *("retained-original-" + str(i).zfill(3) for i in range(44)),
              "actual-original-same-worker"]
    rows = report.get("stages")
    need(type(rows) is list and len(rows) == len(labels) == 48, "Exact 48 original stages required")
    result = {}
    for label, claimed in zip(labels, rows, strict=True):
        d = directory / label
        row = read(d / "receipt.json")
        need(same(row, claimed) and type(row.get("exit_code")) is int and row["exit_code"] == 0
             and row.get("timed_out") is False and row.get("cleanup") is None
             and type(row.get("elapsed_ns")) is int and row["elapsed_ns"] >= 0
             and type(row.get("wall_limit_seconds")) is int
             and row["wall_limit_seconds"] == (900 if label == "cargo-original-test-build" else
                 30 if label.startswith("list-original") else 300 if label == "actual-original-same-worker" else 60)
             and row.get("cleanup_limit_seconds") == 3,
             "Actual original stage did not complete within its unchanged profile: " + label)
        streams = {}
        for stream_name in ("stdout", "stderr"):
            raw = regular(d / (stream_name + ".raw")).read_bytes()
            need(type(row.get(stream_name + "_bytes")) is int
                 and bytes_id(raw) == {"bytes": row[stream_name + "_bytes"],
                                      "sha256": row[stream_name + "_sha256"]},
                 "Actual original raw stream differs: " + label + "/" + stream_name)
            streams[stream_name] = raw
        result[label] = (row, streams)
    return result


def dependencies(standard):
    result = {}
    sysroot = Path(standard["sysroot"])
    for name, expected in standard["sources"].items():
        member_name(name)
        result["std-source/" + name] = (sysroot / "lib/rustlib/src/rust" / name, expected)
    for name, expected in standard["binaries"].items():
        need(Path(name).name == name, "Malformed standard binary name")
        result["std-binary/" + name] = (Path(expected["path"]), {k: expected[k] for k in ("bytes", "sha256")})
    for name in ("compiler_executable", "cargo_executable"):
        expected = standard[name]
        result["tools/" + name] = (Path(expected["path"]), {k: expected[k] for k in ("bytes", "sha256")})
    for name, expected in standard["actual_host_dynamic_libraries"].items():
        key = "host-libraries/" + Path(name).name
        need(key not in result, "Duplicate captured host library")
        result[key] = (Path(name), expected)
    return result


def original_shape(row):
    """Require the concrete serde_json shapes emitted by the unchanged private Rust hook."""
    need(type(row) is dict, "Actual original observer row is not an object")
    unsigned = lambda value: type(value) is int and 0 <= value < (1 << 64)
    number = lambda key: key in row and unsigned(row[key])
    hex_value = lambda value, size: type(value) is str and re.fullmatch("[0-9a-f]{" + str(size * 2) + "}", value) is not None
    vector = lambda value, size: type(value) is list and len(value) == size and all(unsigned(item) for item in value)
    need(type(row.get("name")) is str and row["name"] and number("domain") and number("code"),
         "Actual original name/domain/code type differs")
    progress = row.get("progress")
    need(type(progress) is list and all(vector(point, 5) for point in progress),
         "Actual original progress is not a list of exact five-u64 observations")
    oracle.paid_observation_shape(row)
    if row.get("worker_tid") is None:
        minimal = {"name", "domain", "code", "progress", "product_hex", "worker_tid", "paid_global"}
        need(set(row) in (minimal, minimal | {"main_tid", "before_checks"})
             and row["domain"] == 3 and row["code"] > 0 and progress == []
             and row["product_hex"] is None,
             "Actual original pre-worker error shape differs")
        if "main_tid" in row:
            need(type(row["main_tid"]) is int and 0 < row["main_tid"] < (1 << 32)
                 and number("before_checks"), "Original pre-worker TID/check count type differs")
        return
    fields = {"name", "domain", "code", "error_text", "work_code", "progress", "product_hex",
              "challenge_hex", "task_hex", "ticket_hex", "main_tid", "worker_tid", "joined",
              "host_calls", "worker_checks", "before_checks", "after_checks", "before_values",
              "after_values", "delta_values", "gate_observed", "input_sha256",
              "actual_original_W1", "actual_original_Host_primitives",
              "actual_original_task_alive_and_final_resource", "fixture_uses_actual_AtomicBool_cancel_inputs",
              "production_fixed_parent_authority", "complete_Node_or_paid_checkpoint",
              "actual_original_finite_paid_work_checkpoints", "paid", "paid_checkpoints", "paid_global"}
    need(set(row) == fields, "Complete actual original worker observer field roster differs")
    need(all(type(row[name]) is int and 0 < row[name] < (1 << 32) for name in ("main_tid", "worker_tid"))
         and row["main_tid"] != row["worker_tid"]
         and all(number(name) for name in ("work_code", "host_calls", "worker_checks", "before_checks", "after_checks"))
         and row["worker_checks"] <= row["host_calls"], "Actual original worker identity/counter type differs")
    need(all(row[name] is True for name in ("joined", "actual_original_W1",
                  "actual_original_Host_primitives", "actual_original_task_alive_and_final_resource",
                  "fixture_uses_actual_AtomicBool_cancel_inputs", "actual_original_finite_paid_work_checkpoints"))
         and type(row["gate_observed"]) is bool
         and row["production_fixed_parent_authority"] is False
         and row["complete_Node_or_paid_checkpoint"] is False, "Actual original worker scope/Boolean type differs")
    need(vector(row["before_values"], 6)
         and ((row["after_values"] is None and row["delta_values"] is None)
              or (vector(row["after_values"], 6) and vector(row["delta_values"], 4)))
         and hex_value(row["input_sha256"], 32), "Actual original resource/input types differ")
    if row["domain"] == 0:
        need(row["code"] == row["work_code"] == 0 and row["error_text"] is None
             and hex_value(row["product_hex"], 16384)
             and all(hex_value(row[name], 32) for name in ("challenge_hex", "task_hex", "ticket_hex")),
             "Actual original successful statement shape differs")
    else:
        need(type(row["error_text"]) is str and row["error_text"]
             and all(row[name] is None for name in ("product_hex", "challenge_hex", "task_hex", "ticket_hex")),
             "Actual original failed statement shape differs")


def original(directory, repository, admitted, *, capture=None, live=True, expected_target=None):
    artifact_before = file_tree(directory)
    report = read(directory / "report.json")
    before = read(directory / "source-before.json")
    after = read(directory / "source-after.json")
    need(same(before, after) and same(before.get("source_inputs"), admitted["source_inputs"])
         and same(before.get("original_sources"), admitted["original_sources"])
         and same(before.get("native_bundle"), admitted["snapshot"])
         and report.get("schema") == "trnm.hia.work-owner-original.v2"
         and report.get("status") == "PASS" and report.get("failure") is None
         and report.get("final_fence_failure") is None and report.get("source_after") == "MATCH"
         and report.get("binary_after") == "MATCH", "Complete original source/native/binary fences required")
    need(all(report.get(k) is False for k in SCOPES[:3])
         and report.get("original_controlled_CLOCK1_fault_comparison") == "PASS"
         and report.get("original_paid_CLOCK_fault_comparison") == "PASS"
         and report.get("native_protocol_controls_without_original_equivalent") == sorted(cases.PROTOCOL_ONLY),
         "Original observation scope expanded")
    for key, count in (("passed", 57), ("total", 57), ("actual_original_progress_points", 27841),
                       ("actual_original_worker_histories", 56)):
        need(type(report.get(key)) is int and report[key] == count, "Original exact count differs: " + key)
    binary = directory / "original-test-binary"
    binary_id = identity(binary)
    need(binary_id["bytes"] > 0 and stat.S_IMODE(binary.stat().st_mode) == 0o500
         and binary.stat().st_nlink == 1, "Complete independent original executable absent or aliased")
    executed_path = Path(report["executable"]["path"])
    observed = executed_path.parent
    need(executed_path.is_absolute() and executed_path.name == "original-test-binary"
         and {k: report["executable"][k] for k in ("bytes", "sha256")} == binary_id
         and {k: report["compiled_executable"][k] for k in ("bytes", "sha256")} == binary_id,
         "Retained full original binary identity differs")
    if live:
        need(observed == directory, "Live original root differs from the actual observed executable")
    isolated = directory / "isolated-source"
    observed_isolated = observed / "isolated-source"
    declarations = {k: v.hex() for k, v in oracle.DECLARATIONS.items()}
    need(before.get("appended_declarations") == declarations, "Private original declaration differs")
    hooks = {
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_clock.rs":
            repository / "hia/platform/work_owner/rust_clock_reference.rs",
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_oracle.rs":
            repository / "hia/platform/work_owner/rust_reference.rs",
        "trillionnium/crates/trnm-pon-node/src/hia_work_owner_resource_fixture.rs":
            repository / "hia/platform/host_resource/rust_reference.rs",
        "trillionnium/crates/trnm-pon-node/src/ingress/hia_work_owner_bridge.rs":
            repository / "hia/platform/work_owner/rust_bridge.rs",
        "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/hia_work_paid_probe.rs":
            repository / "hia/platform/work_owner/rust_paid_reference.rs"}
    expected = dict(admitted["original_sources"])
    for name, declaration in oracle.DECLARATIONS.items():
        raw = regular(repository / name).read_bytes()
        need(bytes_id(raw) == admitted["original_sources"][name], "Original production prefix changed")
        expected[name] = bytes_id(raw + declaration)
        need(regular(isolated / name).read_bytes() == raw + declaration, "Original whole prefix/declaration differs")
    hook_ids = {name: identity(path) for name, path in hooks.items()}
    need(before.get("private_hooks") == hook_ids, "Compiled private hook identity differs")
    expected.update(hook_ids)
    need(file_tree(isolated) == expected, "Complete original copied source/private hook roster differs")
    standard = before["standard_library"]
    contract = read(repository / "hia/platform/paid_cpu/abi.json")["standard_library"]
    need(standard.get("schema") == "trnm.hia.paid-cpu-original-std-dependency.v1"
         and standard.get("commit") == contract["commit"]
         and bytes_id(standard["compiler"].encode())["sha256"] == contract["rustc_version_sha256"]
         and standard.get("sources") == contract["sources"]
         and {name: {k: row[k] for k in ("bytes", "sha256")} for name, row in standard["binaries"].items()}
             == contract["binaries"]
         and standard.get("normal_vdso_error_or_timing_behavior_claimed") is False
         and before.get("actual_cargo") == standard.get("cargo_executable")
         and before.get("actual_rustc") == standard.get("compiler_executable"),
         "Original exact Rust 1.95 source/binary/tool contract differs")
    from hia.platform.paid_cpu.dependency import captured_std, executable_interpreter
    if live:
        need(same(captured_std(), standard), "Actual original compiler/std/runtime dependencies changed")
        need(executable_interpreter(binary, standard) == report["interpreter"],
             "Actual full original ELF loader differs")
    if capture is not None:
        for name, (source, wanted) in dependencies(standard).items():
            destination = capture / "original-dependencies" / name
            if live:
                capture_file(source, destination, wanted)
            else:
                need(identity(destination) == wanted, "Retained exact original dependency differs")
    retained = report.get("retained_original_tests")
    need(type(retained) is list and len(retained) == len(set(retained)) == 44
         and all(type(name) is str for name in retained)
         and sorted(retained) == retained and set(oracle.REQUIRED_TESTS) <= set(retained),
         "Complete actual retained Host test roster differs")
    rows = original_stages(directory, report, retained)
    target = Path(before["target_dir"])
    need(target.is_absolute() and not bundle.overlap(target, observed)
         and not bundle.overlap(target, repository)
         and (expected_target is None or target == expected_target),
         "Actual Cargo target overlaps a protected tree or differs")
    build_argv = [standard["cargo_executable"]["path"], "--config", "build.incremental=false", "test", "--locked", "--manifest-path",
                  str(observed_isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node",
                  "--lib", "--no-run", "--message-format=json", "--target-dir", str(target)]
    need(rows["cargo-original-test-build"][0]["argv"] == build_argv
         and all(row[0].get("cwd") == str(observed_isolated) for row in rows.values()),
         "Actual original Cargo/working-directory entry differs")
    events = [json.loads(line, object_pairs_hook=unique)
              for line in rows["cargo-original-test-build"][1]["stdout"].splitlines() if line.startswith(b"{")]
    sqlite = next_evidence.sqlite_and_loader(sys.modules[__name__], directory, observed, before, report,
                                            events, standard, capture, live)
    artifact = oracle.original_artifact(events, observed_isolated)
    need(same(artifact, report["artifact"]) and artifact["executable"] == report["compiled_executable"]["path"]
         and target in Path(artifact["executable"]).parents,
         "Original full binary was not the unique actual Cargo test artifact")
    for label, argv in (("list-original-tests", [str(executed_path), "--list"]),
                        ("list-original-ignored-tests", [str(executed_path), "--ignored", "--list"])):
        need(rows[label][0]["argv"] == argv, "Actual original listing invocation differs")
    tests = {line.removesuffix(": test") for line in rows["list-original-tests"][1]["stdout"].decode().splitlines()
             if line.endswith(": test")}
    ignored = {line.removesuffix(": test")
               for line in rows["list-original-ignored-tests"][1]["stdout"].decode().splitlines()
               if line.startswith("host_kernel_parent::kernel_parent::") and line.endswith(": test")}
    need(ignored == {oracle.IGNORED} and oracle.TEST in tests and oracle.CLOCK_TEST in tests and oracle.PAID_CLOCK_TEST in tests, "Original ignored probe or private observer roster differs")
    linked = sorted(name for name in tests if name.startswith("host_kernel_parent::kernel_parent::")
                    and "::hia_work_owner_oracle::" not in name and name not in ignored)
    need(linked == retained and report.get("ignored_direct_probe") == {
        "name": oracle.IGNORED, "ordinary_pass_claimed": False,
        "reason": "executed by its original bounded nonregular-limit parent tests"},
        "Original ignored probe was counted as an ordinary test")
    for i, name in enumerate(retained):
        label = "retained-original-" + str(i).zfill(3)
        need(rows[label][0]["argv"] == [str(executed_path), "--exact", name, "--nocapture", "--test-threads=1"],
             "Actual retained test invocation differs")
        positive_test(rows[label][1]["stdout"], name)
    actual_stage = rows["actual-original-same-worker"]
    need(actual_stage[0]["argv"] == [str(executed_path), "--exact", oracle.TEST, "--nocapture", "--test-threads=1"],
         "Actual same-worker original entry differs")
    positive_test(actual_stage[1]["stdout"], oracle.TEST)
    inputs = cases.original_cases()
    corpus = b"".join(encode(case) + b"\n" for case in inputs)
    need(regular(directory / "cases.jsonl").read_bytes() == corpus
         and before.get("input") == bytes_id(corpus)
         and type(before.get("original_histories")) is int and before["original_histories"] == 57,
         "Actual original corpus changed or omitted an input")
    actual = [json.loads(line.split(oracle.MARKER, 1)[1], object_pairs_hook=unique)
              for line in actual_stage[1]["stdout"].decode().splitlines() if oracle.MARKER in line]
    native_map = {case["name"]: frame for case, frame in zip(cases.corpus(), admitted["native"], strict=True)}
    frames = [native_map[case["name"]] for case in inputs]
    for observation in actual:
        original_shape(observation)
    comparison = oracle.compare(actual, frames, inputs)
    need(same(comparison, report["comparisons"]) and len(comparison) == 57
         and all(row["status"] == "PASS" and row["different_fields"] == [] for row in comparison)
         and sum(len(row["progress"]) for row in actual) == 27841
         and sum(row.get("joined") is True for row in actual) == 56,
         "Complete original/native differential differs from actual stdout")
    clock = next_evidence.original_clock(sys.modules[__name__], directory, observed, report, admitted, binary_id)
    from hia.platform.work_owner.paid_fault_evidence import read_original as read_paid_original
    need(same(identity(directory / "paid-clock-faults/report.json"), report.get("paid_clock_faults_report")),
         "Original Paid fault report disconnected")
    paid = read_paid_original(directory / "paid-clock-faults", report["paid_clock_faults"],
        native=admitted["report"]["paid_clock_faults"], executable=binary_id,
        source_inputs=admitted["source_inputs"], original_sources=admitted["original_sources"],
        observed=observed / "paid-clock-faults")
    need(identity(binary) == binary_id and same(read(directory / "source-after.json"), before),
         "Original independent binary/source changed during readback")
    need(file_tree(directory) == artifact_before, "Complete original raw evidence changed during admission")
    return {"original_report": identity(directory / "report.json"), "original_binary": binary_id,
            "original_artifacts": artifact_before,
            "original_histories": 57, "original_progress_points": 27841,
            "original_worker_histories": 56, "retained_original_test_count": 44,
            "retained_original_tests": retained, "original_process_stages": 48,
            "original_rust": "PASS", "original_source_before": identity(directory / "source-before.json"),
            "original_source_after": identity(directory / "source-after.json"),
            "original_dependency": standard,
            "original_controlled_CLOCK1_fault_comparison": "PASS", **sqlite, **clock, **paid}


def assess(repository, native_directory, original_directory, capture=None, *, live=True, expected_target=None):
    admitted, result = native(native_directory, repository)
    result.update(original(original_directory, repository, admitted, capture=capture,
                           live=live, expected_target=expected_target))
    need(all(admitted["source_inputs"][name] == admitted["original_sources"][name]
             for name in set(admitted["source_inputs"]) & set(admitted["original_sources"])),
         "Overlapping original/HIA source identities disagree")
    sources = admitted["source_inputs"]
    if capture is not None:
        for name, wanted in sources.items():
            destination = capture / "source-inputs" / member_name(name)
            if live:
                capture_file(repository / name, destination, wanted)
            else:
                need(identity(destination) == wanted, "Complete captured native source differs")
    need(build.source_manifest() == sources and bundle.original_manifest(repository) == admitted["original_sources"],
         "Current full sources changed during actual evidence replay")
    bundle.check_snapshot(native_directory, admitted)
    result.update(source_inputs=sources, original_sources=admitted["original_sources"],
                  source_set_sha256=object_hash(sources),
                  original_source_set_sha256=object_hash(admitted["original_sources"]),
                  native_snapshot=admitted["snapshot"],
                  **{name: False for name in SCOPES})
    return result


def observations(root):
    return root / (PREFIX + "-observations")


def evidence_roots(root):
    return {"native": root / (PREFIX + "-native"), "original": root / (PREFIX + "-original"),
            "observations": observations(root), "capture": root / (PREFIX + "-capture"),
            "bootstrap": root / "hia-bootstrap"}


def ignored_capture(name):
    return name in {"observations/binding.log", "observations/packaging.log", "observations/readback.log"}


def evidence_inventory(roots, *, omit_binding=True):
    regular_files, specials = {}, {}
    def visit(path, name):
        member_name(name)
        if ignored_capture(name) or (omit_binding and name == "observations/binding.json"):
            return
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child, name + "/" + child.name)
        elif stat.S_ISREG(info.st_mode):
            regular_files[name] = identity(path)
        else:
            specials[name] = {"mode": stat.S_IMODE(info.st_mode), "type": stat.S_IFMT(info.st_mode),
                              "device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
                              "opened": False,
                              "link_text": os.readlink(path) if stat.S_ISLNK(info.st_mode) else None}
    for label, directory in roots.items():
        need(label in ROOT_LABELS, "Unexpected evidence root")
        if directory.exists() or directory.is_symlink():
            need(directory.resolve(strict=True) == directory and directory.is_dir(), "Aliased evidence root")
            visit(directory, label)
    return regular_files, specials


def check_binding(value, expected):
    need(type(value) is dict and value.get("schema") == SCHEMA and value.get("stage") == STAGE
         and value.get("status") == "PASS" and same(value.get("lineage"), expected)
         and value.get("pipeline") == "native-original-qualification-readback-v1"
         and value.get("complete_predecessor_regular_bytes_retained") is True
         and value.get("complete_predecessor_archives_retained") is True,
         "Work owner binding is failed or from another head/run/attempt")
    need(all(type(value.get(k)) is int and value[k] == count for k, count in COUNTS.items())
         and value.get("physical_trace") == value.get("original_rust") == "PASS",
         "Binding omits a complete actual stage")
    need(all(value.get(k) is False for k in SCOPES)
         and value.get("original_controlled_CLOCK1_fault_comparison") == "PASS"
         and value.get("original_paid_CLOCK_fault_comparison") == "PASS"
         and value.get("original_observer_memory_controls_status") == "PASS"
         and value.get("primitive_raw_guard_arenas_retained") is True
         and value.get("primitive_raw_readback") == "PASS"
         and value.get("original_sqlite_build_fence") == "sqlite-3.54.1-normal-native-linux-layout-v4",
         "Work owner binding scope expanded")
    need(type(value.get("source_inputs")) is dict and type(value.get("original_sources")) is dict
         and value["source_inputs"] and value["original_sources"]
         and {"hia/platform/work_owner/" + name for name in build.OWNED} <= set(value["source_inputs"])
         and all(file_id(row) for row in value["source_inputs"].values())
         and all(file_id(row) for row in value["original_sources"].values()),
         "Complete well-typed original/native source closure required")
    retained = value.get("retained_original_tests")
    need(type(retained) is list and len(retained) == len(set(retained)) == 44
         and retained == sorted(retained) and set(oracle.REQUIRED_TESTS) <= set(retained),
         "Binding lost required retained original tests")
    need(object_hash(value["source_inputs"]) == value.get("source_set_sha256")
         and object_hash(value["original_sources"]) == value.get("original_source_set_sha256"),
         "Complete source binding differs")
    files = value.get("evidence_files")
    need(type(files) is dict and files and object_hash(files) == value.get("evidence_set_sha256"),
         "Complete actual evidence inventory absent")
    for name, row in files.items():
        need(member_name(name).parts[0] in ROOT_LABELS and file_id(row), "Invalid evidence identity")
    for name, key in (("native/report.json", "native_report"), ("original/report.json", "original_report"),
                      ("original/original-test-binary", "original_binary"),
                      ("original/source-before.json", "original_source_before"),
                      ("original/source-after.json", "original_source_after"),
                      ("original/controlled-clock/report.json", "original_clock_report"),
                      ("original/controlled-clock/actual-reader-controls/report.json", "original_clock_raw_controls_report"),
                      ("original/controlled-clock/observer-memory-controls/report.json", "original_observer_memory_control_report"),
                      ("original/controlled-clock/observer-memory-controls/memory/report.json", "original_observer_memory_raw_report"),
                      ("original/controlled-clock/observer-memory-controls/reader-controls/report.json", "original_observer_memory_reader_report"),
                      ("original/actual-sqlite-qualification.json", "original_sqlite_qualification"),
                      ("native/paid-clock-faults/report.json", "native_paid_clock_report"),
                      ("native/paid-clock-faults/reader-controls/report.json", "native_paid_clock_reader_report"),
                      ("original/paid-clock-faults/report.json", "original_paid_clock_report"),
                      ("original/paid-clock-faults/reader-controls/report.json", "original_paid_clock_reader_report")):
        need(file_id(value.get(key)) and files.get(name) == value[key], "Mandatory full artifact missing: " + name)
    need(value["original_binary"]["bytes"] > 0, "Empty original binary is not evidence")
    raw = value.get("primitive_raw_evidence")
    need(type(raw) is dict and raw.get("guards_and_complete_bodies_retained") is True
         and all(type(raw.get(name)) is int and raw[name] == count
                 for name, count in next_evidence.RAW_COUNTS.items()),
         "Complete primitive byte evidence accounting is required")
    for name, key in (("native/primitives/raw-buffers/manifest.json", "manifest"),
                      ("native/primitives/raw-buffers/calls.jsonl", "calls")):
        need(file_id(raw.get(key)) and same(files.get(name), raw[key]),
             "Mandatory complete primitive byte artifact missing")
    need(set(value.get("ci_reader_sources", {})) == set(READERS)
         and all(file_id(row) for row in value["ci_reader_sources"].values()), "Complete CI reader source roster required")


def reader_paths():
    own = Path(__file__).resolve()
    return {"hia/tools/qualify_work_owner_ci.py": own,
            "hia/tests/test_work_owner_ci.py": own.parents[1] / "tests/test_work_owner_ci.py",
            "hia/tools/qualify_foundation_ci.py": Path(base.__file__).resolve(),
            "hia/tools/work_owner_clock_ci.py": Path(next_evidence.__file__).resolve(),
            "hia/tools/work_owner_transfer_ci.py": Path(transfer.__file__).resolve(),
            "hia/tests/test_work_owner_transfer_ci.py": own.parents[1] / "tests/test_work_owner_transfer_ci.py",
            "hia/tools/qualify_work_handshake.py": own.parent / "qualify_work_handshake.py"}


def reader_manifest():
    return {name: identity(path) for name, path in reader_paths().items()}


def control_roster():
    modules = ("hia.tests.test_work_owner_ci", "hia.tests.test_work_owner_transfer_ci",
               "hia.platform.work_owner.test_integrity",
               "hia.platform.work_owner.test_primitive_evidence", "hia.platform.work_owner.test_clock_evidence",
               "hia.platform.work_owner.test_paid_faults")
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    def names(value):
        if isinstance(value, unittest.TestSuite):
            return [name for child in value for name in names(child)]
        return [value.id()]
    roster = names(suite)
    need(len(roster) >= 12 and len(set(roster)) == len(roster)
         and not any("_FailedTest" in name for name in roster), "Mandatory source-control roster unavailable")
    return modules, roster


def controls(root, *, directory=None):
    out = (observations(root) if directory is None else directory) / "source-controls"
    out.mkdir(parents=True, mode=0o700)
    modules, roster = control_roster()
    argv = [sys.executable, "-P", "-B", "-m", "unittest", *modules, "-v"]
    paths = list(dict.fromkeys((str(Path(__file__).resolve().parents[2]), str(ROOT))))
    source_before = reader_manifest()
    start = time.monotonic_ns()
    child = subprocess.run(argv, cwd=ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                           "PYTHONPATH": os.pathsep.join(paths)}, capture_output=True, timeout=180)
    (out / "stdout.raw").write_bytes(child.stdout)
    (out / "stderr.raw").write_bytes(child.stderr)
    report = {"schema": "trnm.hia.work-owner-ci-source-controls.v1", "argv": argv, "cwd": str(ROOT),
              "interpreter": {"path": str(Path(sys.executable).resolve()), **identity(Path(sys.executable).resolve())},
              "exit_code": child.returncode, "elapsed_ns": time.monotonic_ns() - start,
              "tests": roster, "stdout": bytes_id(child.stdout), "stderr": bytes_id(child.stderr),
              "reader_sources": reader_manifest(), "reader_sources_before": source_before,
              "module_search_roots": paths}
    write_new(out / "report.json", report)
    validate_controls(out)
    return {"status": "PASS", "tests": len(roster), "report": identity(out / "report.json")}


def validate_controls(directory):
    report = read(directory / "report.json")
    need(report.get("schema") == "trnm.hia.work-owner-ci-source-controls.v1"
         and type(report.get("exit_code")) is int and report["exit_code"] == 0
         and type(report.get("elapsed_ns")) is int and report["elapsed_ns"] >= 0,
         "Actual mandatory source-control invocation failed")
    for name in ("stdout", "stderr"):
        need(identity(directory / (name + ".raw")) == report[name], "Source-control raw stream changed")
    text = regular(directory / "stderr.raw").read_text()
    roster = report["tests"]
    need(type(roster) is list and roster == control_roster()[1],
         "Complete source-control roster absent or changed")
    for name in roster:
        module_class, method = name.rsplit(".", 1)
        need(re.search(r"(?m)^" + re.escape(method) + r" \(" + re.escape(module_class) +
                       r"\." + re.escape(method) + r"\) \.\.\. ok$", text) is not None
             or re.search(r"(?m)^" + re.escape(method) + r" \(" + re.escape(module_class) +
                          r"\) \.\.\. ok$", text) is not None,
             "A required source control did not execute successfully")
    need(re.search(r"(?m)^Ran " + str(len(roster)) + r" tests? in [0-9.]+s$", text)
         and re.search(r"(?m)^OK$", text), "Source-control final result differs")
    need(report["reader_sources"] == report.get("reader_sources_before") == reader_manifest(),
         "Source-control reader source changed")
    need(type(report.get("argv")) is list and len(report["argv"]) >= 2
         and Path(report["argv"][0]).is_absolute()
         and report["argv"][1:] == ["-P", "-B", "-m", "unittest", *control_roster()[0], "-v"]
         and type(report.get("module_search_roots")) is list
         and report["module_search_roots"] and all(type(path) is str and Path(path).is_absolute()
             for path in report["module_search_roots"]),
         "Actual source-control entry differs")
    return {"source_control_tests": len(roster), "source_controls": identity(directory / "report.json")}


def verify_archive(archive, entries, *, destination=None):
    """Verify one complete XZ stream, exact tar roster/padding and every regular byte."""
    need(type(entries) is dict and entries, "Archive entry inventory absent")
    bound = 2 * tarfile.RECORDSIZE
    total = 0
    for name, row in entries.items():
        need(member_name(name).parts[0] in ROOT_LABELS and file_id(row), "Invalid archive member inventory")
        total += row["bytes"]
        need(total <= MAX_BYTES, "Evidence declared size exceeds the finite reader profile")
        bound += ((row["bytes"] + 511) // 512) * 512
        bound += 1024 + ((len(name.encode()) + 1023) // 512) * 512
    before = identity(archive)
    if destination is not None:
        destination = Path(destination).absolute()
        need(not destination.exists() and not destination.is_symlink()
             and destination.resolve() == destination, "Fresh canonical readback directory required")
    with tempfile.TemporaryFile() as expanded:
        decoder = lzma.LZMADecompressor(memlimit=64 << 20)
        expanded_size = 0
        with regular(archive).open("rb") as incoming:
            while not decoder.eof:
                block = incoming.read(1 << 20) if decoder.needs_input else b""
                need(block or not decoder.needs_input, "Truncated XZ stream")
                data = decoder.decompress(block, max_length=min(1 << 20, bound - expanded_size + 1))
                expanded_size += len(data)
                need(expanded_size <= bound, "XZ expands beyond the exact member profile")
                expanded.write(data)
            need(not decoder.unused_data and not incoming.read(1), "Trailing or concatenated XZ stream")
        expanded.seek(0)
        seen = set()
        last_end = 0
        with tarfile.open(fileobj=expanded, mode="r:") as tar:
            for member in tar:
                need(member.name in entries and member.name not in seen, "Missing, extra or duplicate tar member")
                seen.add(member.name)
                wanted = entries[member.name]
                need(member.isfile() and member.type == tarfile.REGTYPE and member.linkname == ""
                     and member.size == wanted["bytes"] and not member.sparse
                     and set(member.pax_headers) <= {"path"}
                     and member.mode == (0o500 if member.name == "original/original-test-binary" else 0o600)
                     and member.uid == member.gid == member.mtime == 0
                     and member.uname == member.gname == "", "Archive member metadata differs")
                h = hashlib.sha256()
                count = 0
                with tar.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1 << 20), b""):
                        h.update(block)
                        count += len(block)
                need({"bytes": count, "sha256": h.hexdigest()} == wanted, "Actual archive member bytes differ")
                last_end = member.offset_data + ((member.size + 511) // 512) * 512
        need(seen == set(entries), "Archive omitted a required full member")
        expanded.seek(last_end)
        tail = expanded.read(tarfile.RECORDSIZE + 1025)
        need(1024 <= len(tail) <= tarfile.RECORDSIZE + 1024 and not any(tail)
             and not expanded.read(1) and expanded_size % tarfile.RECORDSIZE == 0,
             "Noncanonical or hidden trailing tar bytes")
        if destination is not None:
            destination.mkdir(mode=0o700)
            expanded.seek(0)
            with tarfile.open(fileobj=expanded, mode="r:") as tar:
                for member in tar:
                    target = destination / member_name(member.name)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, target.open("xb") as out:
                        shutil.copyfileobj(source, out, 1 << 20)
                    target.chmod(member.mode)
                    need(identity(target) == entries[member.name], "Extracted complete bytes differ")
    need(identity(archive) == before, "Archive changed during full reread")
    return {"status": "PASS", "archive": before, "members": len(seen),
            "regular_bytes": total, "expanded_tar_bytes": expanded_size,
            "complete_XZ_stream_and_tar_padding": True}


def pack_roots(roots, output, expected=None, binding=None, precondition_error=None):
    """A failed/missing binding stays unqualified; packing never changes that fact."""
    output = Path(output)
    output.mkdir(mode=0o700)
    record = {"schema": PACKAGE, "stage": STAGE, "packing_status": "FAIL",
              "qualification_status": "NOT_BOUND", "lineage": expected,
              "entries": {}, "special_entries": {}, "capture_errors": [],
              "complete_original_test_binary_is_not_excluded": True,
              "complete_isolated_original_source_is_not_excluded": True,
              "qualification_status_not_changed_by_packaging": True}
    archive = output / "complete-evidence.tar.xz"
    try:
        files, specials = evidence_inventory(roots, omit_binding=False)
        record["special_entries"] = specials
        with tarfile.open(archive, "x:xz", preset=1) as tar:
            for name, wanted in sorted(files.items()):
                label, relative = name.split("/", 1)
                path = roots[label] / member_name(relative)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as incoming:
                    before = os.fstat(incoming.fileno())
                    need(stat.S_ISREG(before.st_mode) and before.st_size == wanted["bytes"],
                         "Capture path changed before opening")
                    h = hashlib.sha256()
                    class Reader:
                        def read(self, count):
                            raw = incoming.read(count)
                            h.update(raw)
                            return raw
                    member = tarfile.TarInfo(name)
                    member.size = before.st_size
                    member.mode = 0o500 if name == "original/original-test-binary" else 0o600
                    tar.addfile(member, Reader())
                    after = os.fstat(incoming.fileno())
                fields = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                need(fields(before) == fields(after) == fields(path.lstat())
                     and h.hexdigest() == wanted["sha256"], "Capture changed while streaming")
                record["entries"][name] = wanted
        record["archive_verification"] = verify_archive(archive, record["entries"])
        record["archive"] = record["archive_verification"]["archive"]
        need(same((files, specials), evidence_inventory(roots, omit_binding=False)),
             "Evidence roster or bytes changed during capture")
        need(precondition_error is None, "Live source/binding precondition failed: " + str(precondition_error))
        if binding is not None:
            check_binding(binding, expected)
            need(set(record["entries"]) == set(binding["evidence_files"]) | {"observations/binding.json"},
                 "Post-binding extra or missing evidence member")
            need(not specials and all(record["entries"].get(name) == row
                                      for name, row in binding["evidence_files"].items()),
                 "A bound actual artifact was omitted or changed")
            need(record["entries"].get("observations/binding.json") == bytes_id(
                regular(roots["observations"] / "binding.json").read_bytes()),
                "Actual binding bytes absent")
            source = roots["observations"] / "binding.json"
            capture_file(source, output / "binding.json", identity(source))
            record["binding"] = identity(output / "binding.json")
            record["qualification_status"] = "PASS"
        record["packing_status"] = "PASS"
    except BaseException as error:
        record["capture_errors"].append({"error": repr(error), "traceback": traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():
            record["partial_archive"] = identity(archive)
    finally:
        write_new(output / "package-manifest.json", record)
    need(record["packing_status"] == "PASS", "Packaging failed; partial bytes and failure record retained")
    return record


def review(repository, native_directory, original_directory, output):
    output.mkdir(mode=0o700)
    capture = output / "capture"
    capture.mkdir(mode=0o700)
    reader_before = reader_manifest()
    result = assess(repository, native_directory, original_directory, capture=capture)
    need(reader_manifest() == reader_before, "Development reader changed during actual replay")
    for name, wanted in reader_before.items():
        capture_file(reader_paths()[name], capture / "ci-readers" / member_name(name), wanted)
    result.update(development_reader_sources=reader_before, schema=REVIEW, status="PASS", actual_hosted_CI_claimed=False,
                  qualification_lineage="PRIVATE_DEVELOPMENT_REPLAY")
    write_new(output / "assessment.json", result)
    roots = {"native": native_directory, "original": original_directory,
             "capture": capture, "observations": output / "observations"}
    roots["observations"].mkdir(mode=0o700)
    capture_file(output / "assessment.json", roots["observations"] / "development-assessment.json",
                 identity(output / "assessment.json"))
    package = pack_roots(roots, output / "artifact")
    need(package["qualification_status"] == "NOT_BOUND", "Development replay cannot acquire CI lineage")
    return {"status": "PASS", "actual_hosted_CI_claimed": False, "assessment": identity(output / "assessment.json"),
            "package": identity(output / "artifact/package-manifest.json"), "archive": package["archive"]}


def readback(package_directory, output, *, require_qualified=False):
    package = read(package_directory / "package-manifest.json")
    need(package.get("schema") == PACKAGE and package.get("stage") == STAGE
         and package.get("packing_status") == "PASS" and package.get("capture_errors") == []
         and package.get("special_entries") == {}
         and package.get("complete_original_test_binary_is_not_excluded") is True
         and package.get("complete_isolated_original_source_is_not_excluded") is True
         and package.get("qualification_status_not_changed_by_packaging") is True,
         "Complete package required")
    if require_qualified:
        need(package.get("qualification_status") == "PASS",
             "Final CI readback requires an actually qualified complete package")
        expected = base.lineage()
        need(same(package.get("lineage"), expected), "Final CI package belongs to another head/run/attempt")
        check_binding(read(package_directory / "binding.json"), expected)
    archive = package_directory / "complete-evidence.tar.xz"
    need(identity(archive) == package.get("archive"), "Actual package archive identity differs")
    verification = verify_archive(archive, package["entries"], destination=output)
    need(same(verification, package.get("archive_verification")), "Written archive verification differs")
    need("original/original-test-binary" in package["entries"], "Complete original binary omitted")
    current = assess(ROOT, output / "native", output / "original", capture=output / "capture", live=False)
    if package.get("qualification_status") == "PASS":
        binding = read(package_directory / "binding.json")
        expected = base.lineage()
        check_binding(binding, expected)
        need(same(package.get("lineage"), expected) and same(identity(package_directory / "binding.json"), package["binding"])
             and regular(package_directory / "binding.json").read_bytes() ==
                 regular(output / "observations/binding.json").read_bytes(),
             "Transferred binding belongs to another actual run or differs")
        need(all(same(binding.get(key), value) for key, value in current.items()), "Raw evidence no longer reproduces binding")
        need(set(package["entries"]) == set(binding["evidence_files"]) | {"observations/binding.json"}
             and all(package["entries"].get(name) == row for name, row in binding["evidence_files"].items()),
             "Bound raw member absent, extra or changed")
        need(binding["ci_reader_sources"] == {name: identity(ROOT / name) for name in READERS},
             "Readback reader source differs from actual bound reader")
        for name, wanted in binding["ci_reader_sources"].items():
            need(identity(output / "capture/ci-readers" / member_name(name)) == wanted,
                 "Captured actual CI reader source differs")
        need(same(source_pair(output / "observations", expected), binding["source_observations"]),
             "Transferred full source-before/after differs")
        base.check_committed_sources({**binding["source_inputs"], **binding["original_sources"],
                                      **binding["ci_reader_sources"]}, ROOT)
        validate_controls(output / "observations/source-controls")
        transfer.validate_chain(sys.modules[__name__], {name: output / name for name in ROOT_LABELS}, binding)
        status = "QUALIFIED_COMPLETE_READBACK"
    else:
        need(package.get("qualification_status") == "NOT_BOUND" and package.get("lineage") is None,
             "Unknown or failed package binding cannot be promoted")
        prior = read(output / "observations/development-assessment.json")
        need(prior.get("schema") == REVIEW and prior.get("actual_hosted_CI_claimed") is False
             and prior.get("development_reader_sources") == reader_manifest()
             and all(same(prior.get(key), value) for key, value in current.items()),
             "Development raw replay differs")
        for name, wanted in prior["development_reader_sources"].items():
            need(identity(output / "capture/ci-readers" / member_name(name)) == wanted,
                 "Development captured reader bytes differ")
        status = "PRIVATE_DEVELOPMENT_READBACK_PASS"
    result = {"status": status, "archive": verification["archive"],
              "original_binary": current["original_binary"], **COUNTS,
              "qualification_status_not_changed_by_readback": True,
              "original_controlled_CLOCK1_fault_comparison": "PASS",
              "original_paid_CLOCK_fault_comparison": "PASS",
              "original_observer_memory_controls_status": current["original_observer_memory_controls_status"]}
    write_new(output / "readback-result.json", result)
    return result


def prerequisite(name):
    need(os.environ.get(name) == "success", "Actual prerequisite CI job did not succeed: " + name)


def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized CI evidence reader refused")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("controls", "native-controls", "native-pack", "native-unpack",
                                          "original-pack", "original-unpack", "qualify-pack",
                                          "review", "readback"))
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--original", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    need(not args.require_qualified or args.action == "readback",
         "Qualified-package requirement applies only to complete final readback")
    if args.action == "review":
        need(all(x is not None for x in (args.repository, args.native, args.original, args.output))
             and args.package is None, "Explicit isolated development replay paths required")
        result = review(bundle.canonical_root(args.repository), bundle.canonical_root(args.native),
                        bundle.canonical_root(args.original), args.output.absolute())
    elif args.action == "readback":
        need(args.package is not None and args.output is not None
             and args.repository is args.native is args.original is None, "Explicit package/readback paths required")
        if args.require_qualified:
            prerequisite("TRNM_WORK_QUALIFICATION_RESULT")
        result = readback(bundle.canonical_root(args.package), args.output.absolute(),
                          require_qualified=args.require_qualified)
    else:
        need(all(x is None for x in (args.repository, args.native, args.original, args.output, args.package)),
             "Hosted commands use only the actual runner roots")
        root = bundle.canonical_root(os.environ["RUNNER_TEMP"])
        module = sys.modules[__name__]
        if args.action == "controls":
            result = controls(root)
        elif args.action == "native-controls":
            result = controls(root, directory=transfer.stage_observations(module, root, "native"))
        elif args.action == "native-pack":
            result = transfer.pack_native(module, root)
        elif args.action == "original-pack":
            prerequisite("TRNM_WORK_NATIVE_RESULT")
            result = transfer.pack_original(module, root)
        elif args.action == "qualify-pack":
            prerequisite("TRNM_WORK_NATIVE_RESULT")
            prerequisite("TRNM_WORK_ORIGINAL_RESULT")
            result = transfer.qualify_pack(module, root)
        else:
            phase = args.action.removesuffix("-unpack")
            prerequisite("TRNM_WORK_" + phase.upper() + "_RESULT")
            result = transfer.read_transfer(module, root / (PREFIX + "-" + phase + "-download"),
                                           root / (PREFIX + "-" + phase + "-prior"), phase)
    print(json.dumps({key: value for key, value in result.items() if key not in {
        "source_inputs", "original_sources", "native_snapshot", "evidence_files", "entries", "original_artifacts",
        "ci_reader_sources", "original_dependency"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
