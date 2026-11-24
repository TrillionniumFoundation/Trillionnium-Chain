#!/usr/bin/env python3
"""Bounded raw readback of the existing corrected Bench tests, not a test runner."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "trnm.hia.bench-corrected-raw.v1"
COMPLETION = "trnm.hia.bench-corrected-completion.v1"
BOUND_INPUTS = (
    ".github/workflows/hia-bench-corrected-evidence.yml",
    "hia/tests/test_bench_reader_high_water.py", "hia/tests/rust_bench_reference.rs",
    "hia/tools/bench_corrected_evidence.py", "hia/tools/component_partition.py",
    "hia/platform/bench/main_build.py", "hia/platform/bench/main_emitter.hepta",
    "hia/src/bench/main_cli.hepta", "hia/src/executor/schedule.hepta", "hia/src/bench/workload.hepta",
    "hia/src/bench/report.hepta", "hia/src/bench/profile.hepta", "hia/src/bench/repeat.hepta",
    "hia/src/bench/digests.hepta", "hia/src/bench/environment.hepta",
    "hia/src/bench/main_diagnostics.hepta", "hia/src/bench/main_diagnostics.json",
    "hia/qualification/compiler-binding.json",
    "trillionnium/Cargo.lock",
    "trillionnium/crates/trnm-bench/src/main.rs", "trillionnium/crates/trnm-executor/src/lib.rs")
METHODS = tuple("hia.tests.test_bench_reader_high_water." + key for key in (
    "BenchReaderHighWater.test_corrected_mode_scope_and_native_replay_clock_bound",
    "BenchReaderHighWater.test_existing_elf_default_multiwriter_admission_remains_closed",
    "BenchReaderHighWater.test_native_defaults_match_corrected_rust_graph_profile_and_replay",
    "IndependentAccessGraphTests.test_membership_and_conflict_controls"))
ROWS = ((0, 32, 7, 3, 1, 0), (1, 20000, 2000, 3, 1, 0),
        (2, 20000, 2000, 3, 1, 0), (2, 20000, 2000, 3, 1, 4),
        (1, 20000, 1, 8, 1, 0), (1, 20000, 2000, 3, 1, 2), (2, 20000, 2000, 3, 1, 2))
OPERATIONS = (
    ("workload", "workload", b"BNCHGEN1"), ("schedule", "schedule", b"EXSCH001"),
    ("replay", "repeat", b"BNCHREP1"), ("digest-0", "digests", b"EXSCH001"),
    ("digest-1", "digests", b"EXSCOUT1"), ("profile", "profile", b"BPRO0001"),
    ("report", "report", b"BRPT0001"))
CALLS = {f"cohort-{i}-{op}": (source, magic) for i in range(len(ROWS)) for op, source, magic in OPERATIONS}
REFUSED = tuple(f"corrected-refused-{i}" for i in range(9)) + ("corrected-nonempty-env",)
COUNTS = {"corrected-count-0": 1, "corrected-count-2": 3,
          "corrected-count-1000": 1001, "corrected-delay": 5}
STAMP = b"schedule_semantics=reader-high-water-v1\n"
OUTSIDE = b"Bench native candidate: invocation outside admitted Bench scope\n"
OVER = b"--determinism-repeats exceeds bounded maximum 1000\n"
MAX_MEMBER, MAX_TOTAL, MAX_PACKED = 8 << 20, 96 << 20, 16 << 20
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def roster():
    paths = set()
    for label in CALLS:
        paths.update(f"raw/{label}.{stream}.raw" for stream in ("stdin", "stdout", "stderr"))
    for i in range(len(ROWS)):
        for label in ("corrected-observer", "corrected-cli", *(() if i == 0 else ("native-profile",))):
            paths.update(f"raw/cohort-{i}-{label}.{stream}.raw" for stream in ("stdout", "stderr"))
        paths.add(f"raw/cohort-{i}-corrected-profile.raw")
        if i:
            paths.add(f"raw/cohort-{i}-native-profile.file.raw")
    for label in (*REFUSED, *COUNTS, "corrected-count-over", "unbound-corrected-mixed",
                  "unbound-corrected-hot-streak", "unbound-profile-refused-mixed",
                  "unbound-profile-refused-hot-streak"):
        paths.update(f"raw/{label}.{stream}.raw" for stream in ("stdout", "stderr"))
    paths.update(f"raw/existing-{work}.stderr.raw" for work in ("mixed", "hot-streak"))
    return paths


def load_json(raw):
    def unique(pairs):
        result = dict(pairs)
        need(len(result) == len(pairs), "duplicate JSON field")
        return result
    def reject_constant(_):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def read_file(root, leaf, maximum=MAX_MEMBER):
    need(not root.is_symlink() and leaf == Path(leaf).name, "noncanonical capture path")
    fd = os.open(root / leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, f"invalid capture: {leaf}")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need(len(data) == before.st_size == after.st_size and
         (before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns),
         f"capture changed: {leaf}")
    return data


def checkout():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, timeout=15)
    need(not git("status", "--porcelain"), "unclean capture checkout")
    head, tree = git("show", "-s", "--format=%H %T").decode().split()
    return head, tree, {name: sha(git("show", "HEAD:" + name)) for name in BOUND_INPUTS}


def scope(local):
    return "local-focused" if local else "hosted-focused"


def completion(path, head, run, attempt, local, tree=None, source=None):
    raw = read_file(path.parent, path.name, 1 << 20)
    report = load_json(raw)
    need(set(report) == {"schema", "scope", "status", "head", "tree", "run_id", "attempt", "started",
         "finished", "test_count", "source_files"} and report["schema"] == COMPLETION
         and report["scope"] == scope(local) and report["status"] == "PASS"
         and (report["head"], report["run_id"], report["attempt"]) == (head, run, attempt)
         and report["test_count"] == len(METHODS) and sorted(report["started"]) == sorted(METHODS)
         and sorted(report["finished"]) == sorted(METHODS) and HEX40.fullmatch(report["tree"])
         and (tree is None or report["tree"] == tree)
         and (source is None or report["source_files"] == source),
         "wrong or incomplete actual focused qualification")
    return {"kind": scope(local), "sha256": sha(raw), "methods": list(METHODS)}


def execute_focused(capture, qualification, head, run, attempt, local):
    need(not capture.exists() and not qualification.exists() and not capture.is_symlink()
         and not qualification.is_symlink(), "focused output must be fresh")
    before = checkout()
    need(before[0] == head, "focused exact checkout moved")
    sys.path.insert(0, str(ROOT))
    from hia.tools.component_partition import ObservedResult, flatten, group_for
    suite = unittest.defaultTestLoader.loadTestsFromName("hia.tests.test_bench_reader_high_water")
    methods = [case.id() for case in flatten(suite)]
    need(sorted(methods) == sorted(METHODS) and all(group_for(x) == "general" for x in methods),
         "focused roster differs from official General methods")
    key = "HIA_BENCH_READER_HIGH_WATER_OBSERVATIONS"
    old = os.environ.get(key)
    try:
        os.environ[key] = str(capture.absolute())
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=ObservedResult).run(suite)
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old
    need(result.wasSuccessful() and not result.skipped and result.testsRun == len(METHODS)
         and sorted(result.started_tests) == sorted(result.finished_tests) == sorted(METHODS)
         and checkout() == before, "actual focused qualification failed")
    receipt = {"schema": COMPLETION, "scope": scope(local), "status": "PASS", "head": head,
               "tree": before[1], "run_id": run, "attempt": attempt, "started": result.started_tests,
               "finished": result.finished_tests, "test_count": result.testsRun, "source_files": before[2]}
    qualification.parent.mkdir(parents=True, exist_ok=True)
    with qualification.open("x") as out:
        out.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def process_identity(root, head, source):
    doc = load_json(read_file(root, "oracle-identity.json", 65536))
    fields = ("source_git_head", "semantics", "snapshot_sha256", "original_sources",
              "corrected_executor_sha256", "reader_map_updates", "rustc_and_cargo_pin",
              "cli_sha256", "adapter_sha256", "dependency_sha256")
    need(doc["test_only"] is True and doc["tracked_original_untouched"] is True, "oracle was not isolated")
    out = {key: doc[key] for key in fields}
    need(out["source_git_head"] == head and out["semantics"] == "reader-high-water-v1" and
         out["reader_map_updates"] == 4, "wrong actual corrected oracle")
    need(out["original_sources"] == {
        k.removeprefix("trillionnium/"): v for k, v in source.items() if k.startswith("trillionnium/")},
        "oracle source/lock mismatch")
    for key in ("snapshot_sha256", "corrected_executor_sha256", "cli_sha256", "adapter_sha256"):
        need(HEX64.fullmatch(out[key]), "invalid oracle executable/source hash")
    need(set(out["dependency_sha256"]) == {"clap", "sha2", "trnm_executor", "trnm_types"}
         and all(HEX64.fullmatch(x) for x in out["dependency_sha256"].values()), "invalid locked dependencies")
    return out


def fields(raw):
    lines = raw.splitlines()
    need(lines and lines[0] == b"bench_parallel_grouping", "invalid actual CLI report")
    pairs = [line.split(b"=", 1) for line in lines[1:]]
    result = dict(pairs)
    need(len(result) == len(pairs), "duplicate report key")
    return result


def normalized_profile(stdout):
    dynamic = {b"elapsed_ms"} | {b"profile.report." + k for k in (
        b"capture_started_at_epoch", b"capture_started_at_iso", b"capture_stamp",
        b"capture_stamp_epoch", b"elapsed_ms", b"path", b"artifact_basename")}
    return [line for line in stdout.splitlines()
            if line.partition(b"=")[0] not in dynamic and line != STAMP.rstrip(b"\n")]


def persistence(stdout, file):
    suffix = (f"profile.report.output_line_count={file.count(bytes([10]))}\n"
              f"profile.report.output_bytes={len(file)}\n").encode()
    need(file == stdout + suffix, "actual profile byte/fixed-point mismatch")


def compare_streams(manifest, read):
    events = manifest["calls"]
    need([e["label"] for e in events] == list(CALLS), "missing, extra or reordered native calls")
    for event in events:
        label = event["label"]
        kind, magic = CALLS[label]
        request = read(f"raw/{label}.stdin.raw")
        stdout = read(f"raw/{label}.stdout.raw")
        need(set(event) == {"label", "source", "request_bytes", "request_sha256", "output_bytes",
             "output_sha256", "scratch_bytes", "status", "unaligned_pointer_residues"} and
             event["source"] == kind and event["status"] == 0 and
             event["unaligned_pointer_residues"] == [1, 3, 5] and
             type(event["scratch_bytes"]) is int and 0 <= event["scratch_bytes"] <= 16 << 20 and
             request.startswith(magic) and len(request) == event["request_bytes"] and sha(request) == event["request_sha256"]
             and stdout[:8] == bytes(8) and len(stdout[8:]) == event["output_bytes"]
             and sha(stdout[8:]) == event["output_sha256"] and read(f"raw/{label}.stderr.raw") == b"",
             f"bad actual native ABI response/request: {label}")
    cohorts, effects = manifest["cohorts"], manifest["processes"]
    need([tuple(row["input"]) for row in cohorts] == list(ROWS) and len(effects) == len(ROWS),
         "corrected cohort/standalone roster differs")
    clock = effects[0]
    need(set(clock) == {"count_exact", "over_bound_started_calls", "delayed_replay_wall_ns",
                         "timed_first_schedule_ms"} and clock["count_exact"] == [1, 3, 1001]
         and clock["over_bound_started_calls"] == 0
         and clock["delayed_replay_wall_ns"] - clock["timed_first_schedule_ms"] * 1_000_000 >= 190_000_000,
         "wrong actual replay clock scope")
    for i, (params, rec) in enumerate(zip(ROWS, cohorts, strict=True)):
        prefix = f"raw/cohort-{i}"
        rust = read(prefix + "-corrected-observer.stdout.raw").split()
        need(len(rust) == 4 and read(prefix + "-corrected-observer.stderr.raw") == b"", "bad actual Rust oracle")
        input_hex, group_hex = rust[1:3]
        need(set(rec) == {"label", "input", "group_count", "independent_accesses", "conflicts",
                         "members", "input_sha256", "group_sha256", "profile_sha256",
                         "native_schedule_invocations_in_replay"}
             and input_hex.decode() == rec["input_sha256"] and group_hex.decode() == rec["group_sha256"]
             and rec["label"] == f"cohort-{i}" and rec["members"] == params[1] and rec["conflicts"] == 0
             and rec["native_schedule_invocations_in_replay"] == 3, "wrong corrected cohort identity")
        rust_frame, rust_schedule = (bytes.fromhex(rust[j].decode("ascii")) for j in (0, 3))
        workload = read(prefix + "-workload.stdout.raw")
        scheduled = read(prefix + "-schedule.stdout.raw")
        need(workload[8:] == struct.pack("<Q", len(rust_frame)) + rust_frame + b"\xA5" * 19
             and scheduled[8:8 + len(rust_schedule)] == rust_schedule
             and read(prefix + "-schedule.stdin.raw") == rust_frame,
             "native workload/schedule do not match actual locked Rust bytes")
        for idx, hex_hash in enumerate((input_hex, group_hex)):
            need(read(prefix + f"-digest-{idx}.stdout.raw")[8:40] == bytes.fromhex(hex_hash.decode()),
                 "native digest differs from corrected Rust")
        for suffix, persisted in [("corrected-cli", "corrected-profile.raw")] + (
                [("native-profile", "native-profile.file.raw")] if i else []):
            stdout = read(f"{prefix}-{suffix}.stdout.raw")
            need(read(f"{prefix}-{suffix}.stderr.raw") == b"", "actual CLI error")
            actual = fields(stdout)
            need(actual[b"determinism.input_sha256"] == input_hex and actual[b"determinism.groups_sha256"] == group_hex
                 and actual[b"determinism.replay_match"] == b"true", "actual CLI identity/replay differs")
            file = read(f"{prefix}-{persisted}")
            persistence(stdout, file)
            native = suffix == "native-profile"
            need(native == (STAMP in stdout), "incorrect semantics marker")
            if not native:
                need(sha(file) == rec["profile_sha256"], "wrong original profile receipt")
            else:
                need(normalized_profile(stdout) == normalized_profile(read(prefix + "-corrected-cli.stdout.raw")),
                     "native profile differs outside independently timed display fields")
                effect = effects[i]
                need(set(effect) == {"label", "profile_and_replay", "native_wall_ns", "native_elapsed_ms",
                                     "native_realtime_epoch", "native_profile_sha256", "original_profile_sha256",
                                     "native_profile_basename", "workload_frame_bytes", "scheduler_scratch_required",
                                     "separate_profile_namespace"}, "wrong actual profile receipt fields")
                elapsed = int(actual[b"elapsed_ms"])
                need(effect["label"] == rec["label"] and effect["profile_and_replay"] is True
                     and effect["separate_profile_namespace"] is True
                     and 0 < elapsed == effect["native_elapsed_ms"] <= effect["native_wall_ns"] // 1_000_000 + 1
                     and int(actual[b"profile.report.capture_started_at_epoch"]) == effect["native_realtime_epoch"]
                     and actual[b"profile.report.artifact_basename"] == effect["native_profile_basename"].encode()
                     and effect["native_profile_basename"].startswith("executor-profile-summary-reader-high-water-v1-")
                     and sha(file) == effect["native_profile_sha256"] and sha(read(prefix + "-corrected-profile.raw"))
                     == effect["original_profile_sha256"], "wrong actual profile receipt")
    for label in (*REFUSED, "unbound-profile-refused-mixed", "unbound-profile-refused-hot-streak",
                  "corrected-count-over"):
        need(read(f"raw/{label}.stdout.raw") == b"" and
             read(f"raw/{label}.stderr.raw") == (OVER if label.endswith("-over") else OUTSIDE),
             "unexpected refusal stream")
    for work in ("mixed", "hot-streak"):
        need(read(f"raw/existing-{work}.stderr.raw") == OUTSIDE
             and read(f"raw/unbound-corrected-{work}.stderr.raw") == b""
             and STAMP in read(f"raw/unbound-corrected-{work}.stdout.raw"),
             "existing/unbound source gate changed")
    for label, count in COUNTS.items():
        need(read(f"raw/{label}.stderr.raw") == b"S" * count and STAMP in read(f"raw/{label}.stdout.raw"),
             "actual replay-call marker mismatch")


def verify(archive, head, tree, run, attempt, local=False, qualification=None):
    carrier = read_file(archive.parent, archive.name, MAX_PACKED)
    with zipfile.ZipFile(io.BytesIO(carrier)) as z:
        infos = z.infolist()
        expected = roster() | {"manifest.json"}
        need(len(infos) == len(expected) and {i.filename for i in infos} == expected, "unexpected ZIP roster")
        need(sum(i.file_size for i in infos) <= MAX_TOTAL and all(
            0 <= i.file_size <= MAX_MEMBER and i.compress_type == zipfile.ZIP_DEFLATED
            and i.create_system == 3 and (i.external_attr >> 16) & 0o170000 == stat.S_IFREG
            and not i.flag_bits & 1
            for i in infos), "unsafe ZIP member")
        data = load_json(z.read("manifest.json"))
        need(set(data) == {"schema", "head", "tree", "run_id", "attempt", "completion", "source_files",
             "oracle", "calls", "cohorts", "processes", "machine", "raw"} and data["schema"] == SCHEMA and
             [data[k] for k in ("head", "tree", "run_id", "attempt")] == [head, tree, run, attempt],
             "wrong exact-source archive identity")
        need(data["completion"]["kind"] == (scope(local)) and
             data["completion"]["methods"] == list(METHODS) and HEX64.fullmatch(data["completion"]["sha256"]),
             "required test completion receipt missing")
        need(qualification is not None and data["completion"] == completion(
             qualification, head, run, attempt, local, tree, data["source_files"]),
             "missing or altered independent completion receipt")
        need(set(data["raw"]) == roster(), "raw index differs from allowed roster")
        need(set(data["source_files"]) == set(BOUND_INPUTS)
             and all(HEX64.fullmatch(x) for x in data["source_files"].values()), "missing source bindings")
        oracle = data["oracle"]
        need(set(oracle) == {"source_git_head", "semantics", "snapshot_sha256", "original_sources",
             "corrected_executor_sha256", "reader_map_updates", "rustc_and_cargo_pin", "cli_sha256",
             "adapter_sha256", "dependency_sha256"} and oracle["source_git_head"] == head
             and oracle["reader_map_updates"] == 4 and oracle["semantics"] == "reader-high-water-v1"
             and oracle["original_sources"] == {k.removeprefix("trillionnium/"): v
                  for k, v in data["source_files"].items() if k.startswith("trillionnium/")}
             and set(oracle["dependency_sha256"]) == {"clap", "sha2", "trnm_executor", "trnm_types"}
             and all(HEX64.fullmatch(x) for x in [oracle[k] for k in ("snapshot_sha256",
                 "corrected_executor_sha256", "cli_sha256", "adapter_sha256")] +
                 list(oracle["dependency_sha256"].values())), "wrong exact corrected oracle receipts")
        need(set(data["machine"]) == {name for name, _ in CALLS.values()} and all(
             set(v) == {"compiler_sha256", "artifact_sha256", "object_sha256", "compiler_wire_sha256"}
             and v["compiler_sha256"] == "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
             and all(HEX64.fullmatch(x) for x in v.values()) for v in data["machine"].values()),
             "wrong pinned native artifacts")
        for key, rec in data["raw"].items():
            raw = z.read(key)
            need(rec == {"bytes": len(raw), "sha256": sha(raw)}, "raw ZIP hash/extent differs: " + key)
        compare_streams(data, z.read)
    return {"status": "PASS", "scope": data["completion"]["kind"], "head": head, "tree": tree,
            "run_id": run, "attempt": attempt, "native_calls": len(data["calls"]),
            "methods": len(METHODS), "raw_members": len(data["raw"])}


def collect(root, archive, head, run, attempt, local, qualification):
    actual, tree, source = checkout()
    need(head == actual and not archive.exists() and not archive.is_symlink(), "wrong checkout or existing archive")
    complete = completion(qualification, head, run, attempt, local, tree, source)
    oracle = process_identity(root, head, source)
    obs = load_json(read_file(root, "observations.json", 2 << 20))
    need(obs["test_only"] is True and not obs["legacy_vulnerable_runtime_replayed"] and
         not obs["unmarked_elf_default_admission_expanded"] and not obs["production_activation"],
         "wrong evidence scope")
    manifest = {"schema": SCHEMA, "head": head, "tree": tree, "run_id": run, "attempt": attempt,
                "completion": complete, "source_files": source, "oracle": oracle,
                "calls": obs["actual_native_calls"], "cohorts": obs["cohorts"],
                "processes": obs["explicit_corrected_elf"], "machine": {
                    source: {k: v[k] for k in ("compiler_sha256", "artifact_sha256", "object_sha256",
                                               "compiler_wire_sha256")}
                    for source, v in obs["native_machine"].items()}, "raw": {}}
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=archive.parent) as path:
        candidate = Path(path) / "carrier.zip"
        total = 0
        with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as z:
            def retain(name, raw):
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                z.writestr(info, raw, compresslevel=3)
            for name in sorted(roster()):
                raw = read_file(root, name.removeprefix("raw/"))
                total += len(raw)
                need(total <= MAX_TOTAL, "raw allowlist exceeds bounded carrier")
                manifest["raw"][name] = {"bytes": len(raw), "sha256": sha(raw)}
                retain(name, raw)
            retain("manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        receipt = verify(candidate, head, tree, run, attempt, local, qualification)
        candidate.replace(archive)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "collect", "verify"))
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt", type=int)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--qualification", type=Path)
    parser.add_argument("--local-focused", action="store_true")
    args = parser.parse_args()
    need(HEX40.fullmatch(args.head) and (args.local_focused and args.run_id is None and args.attempt is None or
         not args.local_focused and re.fullmatch(r"[1-9][0-9]*", args.run_id or "") and
         type(args.attempt) is int and args.attempt > 0), "invalid command lineage")
    if args.action == "run":
        need(args.capture is not None and args.qualification is not None and args.archive is None
             and args.tree is None, "run needs fresh capture and receipt")
        result = execute_focused(args.capture, args.qualification, args.head, args.run_id,
                                 args.attempt, args.local_focused)
    elif args.action == "collect":
        need(args.archive is not None and args.capture is not None and args.qualification is not None and args.tree is None,
             "collection needs raw capture and actual execution report")
        result = collect(args.capture, args.archive, args.head, args.run_id, args.attempt,
                         args.local_focused, args.qualification)
    else:
        need(args.archive is not None and args.capture is None and args.qualification is not None
             and HEX40.fullmatch(args.tree or ""), "readback needs exact source tree and independent completion receipt")
        result = verify(args.archive, args.head, args.tree, args.run_id, args.attempt,
                        args.local_focused, args.qualification)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
