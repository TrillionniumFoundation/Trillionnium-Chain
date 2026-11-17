"""Pre-execution gates and strict observation boundaries for original CLOCK tracing."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from .clock_trace import admit, run
from .clock_evidence import Capture, TEST, compare_observation
from .cases import corpus, original_cases
from .faults import profiles

class ClockEvidence(unittest.TestCase):
    def fixture(self, root):
        binary = root / "binary"; binary.write_bytes(b"not executed by admission-only controls")
        data = root / "input.jsonl"; data.write_text("{}\n")
        argv = [str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"]
        env = {"PATH": "/usr/bin:/bin", "TRNM_HIA_WORK_OWNER_CORPUS": str(data)}
        return argv, env

    def test_exact_original_input_projection(self):
        from .clock_comparison import original_input
        baseline, actual = original_input()
        self.assertEqual(actual, original_cases()[0])
        self.assertEqual(actual["request_hex"], baseline["request_hex"])
        self.assertEqual(set(actual), {"name", "request_hex", "gate_stage", "gate_sequence",
                                       "actions", "signal", "delay_ms"})
        self.assertNotIn("gate_stage", baseline)

    def test_native_envelope_or_changed_control_cannot_be_original_input(self):
        from .clock_comparison import original_input
        initial = original_cases()[0]
        bad = [corpus()[0]]
        for key in ("gate_stage", "gate_sequence", "signal", "delay_ms"):
            omitted = copy.deepcopy(initial); omitted.pop(key); bad.append(omitted)
            for value in (False, 0.0, 1):
                altered = copy.deepcopy(initial); altered[key] = value; bad.append(altered)
        changed = copy.deepcopy(initial); changed["request_hex"] = "00"; bad.append(changed)
        changed = copy.deepcopy(initial); changed["actions"] = [{"kind": "replace_parent"}]; bad.append(changed)
        for value in bad:
            with self.subTest(value=value.get("name")), patch(
                "hia.platform.work_owner.clock_comparison.original_cases", return_value=[value]):
                with self.assertRaises(ValueError): original_input()

    def test_actual_normal_compiler_loader_identity(self):
        from hia.platform.paid_cpu.dependency import captured_std
        from .rust_oracle import capture_loader
        standard = captured_std()
        value = capture_loader(standard)
        actual = (Path(standard["sysroot"]) / "lib").stat()
        self.assertEqual(value, {"path": str(Path(standard["sysroot"]) / "lib"),
            "device": actual.st_dev, "inode": actual.st_ino, "mode": actual.st_mode,
            "uid": actual.st_uid, "gid": actual.st_gid})

    def test_loader_keeps_canonical_directory_identity(self):
        from .rust_oracle import capture_loader
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); library = root / "lib"; library.mkdir()
            library.chmod(0o775)
            self.assertEqual(capture_loader({"sysroot": str(root)})["mode"] & 0o777, 0o775)
            library.rmdir(); library.write_bytes(b"not a directory")
            with self.assertRaises(ValueError): capture_loader({"sysroot": str(root)})
            library.unlink(); actual = root / "actual"; actual.mkdir(); library.symlink_to(actual)
            with self.assertRaises(ValueError): capture_loader({"sysroot": str(root)})

    def test_exact_fault_admission_never_forks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); argv, env = self.fixture(root); output = root / "out"
            for profile in profiles():
                fault = {"clock_roles": [3], "clock_when": profile["ordinal"],
                         "clock_error": 5 if profile["errno"] == "EIO" else 22}
                self.assertEqual(admit(argv, output, True, env, fault, 45), output)
            self.assertFalse(output.exists())

    def test_bad_faults_refused_before_child_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); argv, env = self.fixture(root); output = root / "out"
            good = {"clock_roles": [3], "clock_when": 2, "clock_error": 5}
            changes = [
                {**good, "clock_when": 2.0}, {**good, "clock_when": True},
                {**good, "clock_roles": [3.0]}, {**good, "clock_roles": [1]},
                {**good, "clock_error": 5.0}, {**good, "clock_error": 4},
                {**good, "clock_when": 3, "unbound": 1},
                {**good, "clock_invalid": True}, {"clone_role": 1, "clone_when": 1},
            ]
            with patch("os.fork", side_effect=AssertionError("rejected input forked")):
                for fault in changes:
                    with self.subTest(fault=fault), self.assertRaises(ValueError):
                        run(argv, output, disable_vdso=True, env=env, fault=fault)
                with self.assertRaises(ValueError):
                    run(argv, output, disable_vdso=False, env=env, fault=good)
            self.assertFalse(output.exists())

    def test_argv_environment_and_timeout_are_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); argv, env = self.fixture(root); output = root / "out"
            invalid = [
                (argv[:-1], env, 45), ([*argv[:-1], "--test-threads=2"], env, 45),
                (argv, {**env, "LD_PRELOAD": "/unbound"}, 45),
                (argv, {**env, "PATH": "/unbound"}, 45), (argv, env, True),
                (argv, env, 45.0), (argv, env, 0), (argv, env, 91),
            ]
            with patch("os.fork", side_effect=AssertionError("rejected input forked")):
                for actual, environment, timeout in invalid:
                    with self.subTest(actual=actual, timeout=timeout), self.assertRaises(ValueError):
                        run(actual, output, env=environment, timeout=timeout)
            self.assertFalse(output.exists())

    def observation(self):
        baseline = corpus()[0]; profile = profiles()[0]
        value = {"schema": "trnm.hia.work-owner-original-clock-observation.v1",
            "name": baseline["name"],
            "input_sha256": __import__("hashlib").sha256(bytes.fromhex(baseline["request_hex"])).hexdigest(),
            "actual_original_W1": True, "actual_original_Host_primitives": True,
            "actual_original_task_alive_and_final_resource": True,
            "actual_original_std_scoped_spawn_and_join": True,
            "parent_retained_observation_after_actual_join": True, "joined": True,
            "production_fixed_parent_authority": False, "complete_Node_or_paid_checkpoint": False,
            "original_deadline_seconds": 4, "worker_panicked": True, "ordinary_finish_returned": False,
            "progress": baseline["progress"][:profile["progress"]],
            "host_calls": profile["worker_host_calls"], "host_checks": profile["worker_host_calls"],
            "before_checks": 3, "after_sample_attempts": 0, "after_checks": 0, "work_code": 0,
            "before_values": [10,20,3,40,64,2], "panic_payload": "synthetic gate control only",
            "after_values": None, "delta_values": None, "product_hex": None,
            "returned_domain": None, "returned_code": None}
        return baseline, profile, value

    def test_panic_observation_cannot_publish_normal_authority(self):
        baseline, profile, value = self.observation()
        compare_observation(value, baseline, profile)
        for key, replacement in (("joined", 1), ("worker_panicked", 1),
            ("ordinary_finish_returned", 0), ("production_fixed_parent_authority", 0),
            ("after_sample_attempts", False), ("after_checks", 0.0),
            ("before_checks", 3.0), ("work_code", False), ("returned_domain", 4),
            ("returned_code", 1), ("product_hex", ""), ("after_values", [0]*6),
            ("original_deadline_seconds", 4.0)):
            changed = copy.deepcopy(value); changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_observation(changed, baseline, profile)

    def test_retained_progress_distinguishes_json_types(self):
        baseline, profile, value = self.observation()
        changed = copy.deepcopy(value); changed["progress"][0][1] = False
        with self.assertRaises(ValueError): compare_observation(changed, baseline, profile)
        changed = copy.deepcopy(value); changed["progress"][0][0] = 64.0
        with self.assertRaises(ValueError): compare_observation(changed, baseline, profile)

    def test_capture_exact_regular_roster_and_fence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("report.json", "events.jsonl", "stdout.raw", "stderr.raw"):
                (root/name).write_bytes(b"sample")
            capture = Capture(root)
            try:
                self.assertEqual(capture.read("stdout.raw", 64), b"sample")
                replacement = root/"replacement"; replacement.write_bytes(b"sample")
                os.replace(replacement, root/"stdout.raw")
                with self.assertRaises(ValueError): capture.fence()
            finally: capture.close()
            (root/"extra").write_bytes(b"")
            with self.assertRaises(ValueError): Capture(root)

    def test_capture_rejects_links_and_nonregular_files(self):
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)/"evidence"; root.mkdir()
                for name in ("report.json","events.jsonl","stdout.raw","stderr.raw"):
                    (root/name).write_bytes(b"sample")
                path = root/"stdout.raw"; path.unlink()
                if kind == "symlink": path.symlink_to(root/"stderr.raw")
                elif kind == "hardlink": os.link(root/"stderr.raw", path)
                elif kind == "fifo": os.mkfifo(path)
                else: path.mkdir()
                captured = Capture(root)
                try:
                    with self.assertRaises(ValueError): captured.read("stdout.raw", 64)
                finally: captured.close()


def actual_controls(clock_root, complete, output):
    """Mutate actual completed captures; never manufacture a native/Rust positive."""
    import io
    import struct
    import tarfile
    import traceback
    from .build import need, source_manifest, write_json
    from .clock_evidence import Capture, audit, MARKER
    from .primitive_evidence import decoded, raw_identity, same
    root = Path(clock_root); output = Path(output)
    need(not output.exists(), "Fresh actual CLOCK reader controls required")
    output.mkdir(mode=0o700); working = output / "working"; working.mkdir(mode=0o700)
    before = source_manifest()
    need(same(before, complete["source_inputs"]), "Actual original CLOCK controls have another source")
    baseline = corpus()[0]
    admitted_rows = {row["name"]: row for row in complete["rows"]}
    need("private-raw-positive" in admitted_rows and "clock-EIO-2" in admitted_rows,
         "Actual CLOCK controls require both real positive and real fault captures")
    templates = {}
    for label in ("private-raw-positive", "clock-EIO-2"):
        capture = Capture(root / label)
        try:
            raw = {name: capture.read(name, 256 << 20) for name in ("report.json", "events.jsonl", "stdout.raw", "stderr.raw")}
            capture.fence()
        finally:
            capture.close()
        templates[label] = {"raw": raw, "identities": {name: raw_identity(value) for name, value in raw.items()},
                            "row": admitted_rows[label]}
    controls = {"schema": "trnm.hia.work-owner-actual-clock-reader-controls.v1", "status": "FAIL",
        "source_inputs": before, "baseline": {key: row["identities"] for key, row in templates.items()},
        "rows": [], "actual_native_or_Rust_processes_executed_by_controls": 0,
        "public_actual_reader_api": "hia.platform.work_owner.clock_evidence.audit",
        "full_source_qualification_claimed_by_these_controls": False}
    def load(label):
        raw = templates[label]["raw"]
        return {"report": decoded(raw["report.json"]),
                "events": [decoded(line) for line in raw["events.jsonl"].splitlines()],
                "stdout": raw["stdout.raw"], "stderr": raw["stderr.raw"]}
    def observation(data, function):
        lines = data["stdout"].splitlines(keepends=True)
        selected = [i for i, line in enumerate(lines) if MARKER in line]
        need(len(selected) == 1, "Actual original marker roster changed")
        index = selected[0]; prefix, text = lines[index].split(MARKER, 1)
        value = decoded(text); function(value)
        lines[index] = prefix + MARKER + json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        data["stdout"] = b"".join(lines)
    def worker(data):
        return next(int(tid) for tid, value in data["report"]["actual_roles"].items() if value["role"] == 3)
    def event(data, sequence):
        return next(row for row in data["events"] if row["sequence"] == sequence)
    def role_link(data):
        row = next(row for row in data["events"] if row["kind"] == "actual-role" and row["role"] == 3)
        row["actual_thread_link_exit"] = float(row["actual_thread_link_exit"])
    def after_exit(data):
        data["events"].append({"sequence": len(data["events"]) + 1, "kind": "syscall-entry",
            "tid": worker(data), "nr": 186, "args": [0] * 6})
    def birth_float(data):
        next(row for row in data["events"] if row["kind"] == "birth" and row["child"] == worker(data))["ptrace_event"] = 3.0
    def fallback_int(data):
        row = next(row for row in data["events"] if row["kind"] == "syscall-entry"
                   and row.get("logical_clone_fallback") is False)
        row["logical_clone_fallback"] = 0
    def live_join(data):
        entry = next(row for row in data["events"] if "join_marker_hex" in row)
        entry["join_child_tid_word"] = worker(data)
        row = next(row for row in data["events"] if row["kind"] == "actual-join")
        row["actual_child_tid_word"] = worker(data)
        data["report"]["actual_joins"][0]["actual_child_tid_word"] = worker(data)
    def unconsumed_join(data):
        entry = next(row for row in data["events"] if "join_marker_hex" in row)
        entry["join_child_tid_word"] = 0
        next(row for row in data["events"] if row["kind"] == "actual-join")["actual_child_tid_word"] = 0
        data["report"]["actual_joins"][0]["actual_child_tid_word"] = 0
    def counter_bytes(data):
        interval = data["report"]["actual_resource_intervals"][0]; read = interval["reads"][0]
        raw = bytes.fromhex(read["data_hex"]); changed = raw.replace(b"usage_usec 10\n", b"usage_usec 11\n")
        need(changed != raw and len(changed) == len(raw), "Actual counter byte mutant absent")
        read["data_hex"] = changed.hex()
        event(data, read["exit"])["actual_resource_read"]["data_hex"] = changed.hex()
    def counter_eof(data):
        interval = data["report"]["actual_resource_intervals"][0]; read = interval["reads"][-1]
        need(read["result"] == 0, "Actual counter EOF absent")
        read.update(result=1, data_hex="30")
        row = event(data, read["exit"])
        row.update(result=1, kernel_result_before_injection=1)
        row["actual_resource_read"].update(result=1, data_hex="30")
    def auxv_disconnected(data):
        data["report"]["auxv"]["environment_count"] += 1
    def auxv_extra_word(data):
        aux = data["report"]["auxv"]
        raw = bytearray.fromhex(aux["auxv_after_hex"])
        pairs = list(struct.iter_unpack("<QQ", raw))
        index = next(i for i, (key, value) in enumerate(pairs) if key not in (0, 33))
        struct.pack_into("<Q", raw, index * 16 + 8, pairs[index][1] ^ 1)
        aux["auxv_after_hex"] = raw.hex()
        next(row for row in data["events"] if row["kind"] == "exec")["auxv"] = copy.deepcopy(aux)
    def disconnected_timespec(data):
        row = next(row for row in reversed(data["report"]["actual_clock_calls"])
                   if row["tid"] == worker(data) and row["result"] == 0)
        row["nanoseconds"] = (row["nanoseconds"] + 1) % 1_000_000_000
        row["timespec_hex"] = struct.pack("<qq", row["seconds"], row["nanoseconds"]).hex()
    def over_deadline(data):
        main = next(int(tid) for tid, row in data["report"]["actual_roles"].items() if row["role"] == 1)
        initial = next(row for row in data["report"]["actual_clock_calls"] if row["tid"] == main and row["role"] == 1)
        selected = next(row for row in reversed(data["report"]["actual_clock_calls"]) if row["tid"] == worker(data))
        selected.update(seconds=initial["seconds"] + 4, nanoseconds=initial["nanoseconds"])
        selected["timespec_hex"] = struct.pack("<qq", selected["seconds"], selected["nanoseconds"]).hex()
        event(data, selected["exit"])["actual_timespec_hex"] = selected["timespec_hex"]
    def error_time(data):
        selected = next(row for row in data["report"]["actual_clock_calls"] if row["result"] < 0)
        event(data, selected["exit"])["actual_timespec_hex"] = bytes(16).hex()
    mutations = [
        ("panic-count-bool", "clock-EIO-2", lambda d: observation(d, lambda v: v.update(after_sample_attempts=False))),
        ("host-count-float", "clock-EIO-2", lambda d: observation(d, lambda v: v.update(host_calls=float(v["host_calls"])))),
        ("retained-progress-bool", "clock-EIO-2", lambda d: observation(d, lambda v: v["progress"][0].__setitem__(1, False))),
        ("unbound-executed-image", "clock-EIO-2", lambda d: next(r for r in d["events"] if r["kind"]=="exec").update(actual_executable="/foreign/original")),
        ("worker-syscall-after-terminal", "clock-EIO-2", after_exit),
        ("role-link-sequence-float", "clock-EIO-2", role_link),
        ("birth-event-float", "clock-EIO-2", birth_float),
        ("clone-fallback-integer", "clock-EIO-2", fallback_int),
        ("join-still-live-clear-word", "clock-EIO-2", live_join),
        ("join-zero-without-consumed-libc-state", "clock-EIO-2", unconsumed_join),
        ("coherent-actual-counter-bytes", "clock-EIO-2", counter_bytes),
        ("coherent-missing-counter-EOF", "clock-EIO-2", counter_eof),
        ("summary-auxv-disconnected", "clock-EIO-2", auxv_disconnected),
        ("coherent-extra-auxv-word", "clock-EIO-2", auxv_extra_word),
        ("summary-timespec-disconnected", "private-raw-positive", disconnected_timespec),
        ("coherent-actual-deadline-overrun", "private-raw-positive", over_deadline),
        ("failed-clock-claims-timespec", "clock-EIO-2", error_time),
        ("omitted-actual-injection", "clock-EIO-2", lambda d: d["report"].update(injections=[])),
    ]
    def one(name, label, mutate, expected):
        data = load(label)
        if mutate is not None: mutate(data)
        encoded_events = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in data["events"])
        for key, raw in (("events", encoded_events), ("stdout", data["stdout"]), ("stderr", data["stderr"])):
            data["report"][key] = raw_identity(raw)
        files = {"report.json": (json.dumps(data["report"], sort_keys=True, separators=(",", ":"))+"\n").encode(),
                 "events.jsonl": encoded_events, "stdout.raw": data["stdout"], "stderr.raw": data["stderr"]}
        for file, raw in files.items(): (working/file).write_bytes(raw)
        packed = output/(name+".tar.xz")
        with tarfile.open(packed, "x:xz", preset=6) as archive:
            for file, raw in sorted(files.items()):
                if raw == templates[label]["raw"][file]: continue
                item=tarfile.TarInfo(file); item.size=len(raw); item.mode=0o600; item.mtime=0
                archive.addfile(item, io.BytesIO(raw))
        profile = templates[label]["row"]["audit"]["profile"]
        accepted = False; failure = None
        try:
            audit(working, argv=complete["argv"], environment=complete["environment"],
                  executable=complete["executable"], baseline=baseline, profile=profile, disable_vdso=True)
            accepted = True
        except (ValueError, OSError, KeyError, IndexError, StopIteration, TypeError) as error:
            failure = repr(error)
        row = {"name": name, "baseline": label, "status": "PASS" if accepted is expected else "FAIL",
            "expected_acceptance": expected, "actual_acceptance": accepted, "actual_failure": failure,
            "complete_mutated_raw": {name: raw_identity(raw) for name, raw in files.items()},
            "mutated_files_archive": raw_identity(packed.read_bytes()),
            "unchanged_files_from_baseline": [name for name, raw in files.items() if raw == templates[label]["raw"][name]]}
        write_json(output/(name+".json"), row); controls["rows"].append(row)
        print(json.dumps({"original_clock_reader_control": name, "status": row["status"],
                          "accepted": accepted, "failure": failure}, sort_keys=True), flush=True)
        need(row["status"] == "PASS", "Actual CLOCK raw reader accepted/refused the wrong complete evidence")
    try:
        one("positive-original-canonical-JSON", "private-raw-positive", None, True)
        for name, label, function in mutations: one(name, label, function, False)
        one("positive-fault-after-restoration", "clock-EIO-2", None, True)
        need(len(controls["rows"]) == 20, "Actual original CLOCK reader control roster differs")
        controls.update(status="PASS", positive=2, negative=18, count=20)
    except BaseException as error:
        controls.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        try:
            need(same(source_manifest(), before), "Actual CLOCK control source changed")
            for label, template in templates.items():
                capture = Capture(root/label)
                try:
                    for name, expected in template["identities"].items():
                        need(same(raw_identity(capture.read(name,256<<20)), expected), "Actual original baseline changed")
                    capture.fence()
                finally: capture.close()
            controls["source_after"]="MATCH"; controls["baseline_after"]="MATCH"
        except BaseException as error:
            controls.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        write_json(output/"report.json", controls)
    need(controls["status"] == "PASS", "Actual original CLOCK raw control failure")
    return controls

if __name__ == "__main__":
    unittest.main()
