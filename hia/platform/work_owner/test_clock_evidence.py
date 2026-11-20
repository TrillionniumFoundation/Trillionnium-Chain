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
                fault = {"clock_roles": [3], "clock_when": profile["clock_syscall_ordinal"],
                         "clock_error": 5 if profile["errno"] == "EIO" else 22}
                self.assertEqual(admit(argv, output, True, env, fault, 45), output)
            self.assertFalse(output.exists())

    def test_bad_faults_refused_before_child_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); argv, env = self.fixture(root); output = root / "out"
            good = {"clock_roles": [3], "clock_when": 6, "clock_error": 5}
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
        value = {"schema": "trnm.hia.work-owner-original-clock-observation.v2",
            "name": baseline["name"],
            "input_sha256": __import__("hashlib").sha256(bytes.fromhex(baseline["request_hex"])).hexdigest(),
            "actual_original_W1": True, "actual_original_Host_primitives": True,
            "actual_original_task_alive_and_final_resource": True,
            "actual_original_finite_paid_work_checkpoints": True,
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

    def paid_clock_fixture(self, profile=None, disable_vdso=True):
        # Deliberately synthetic reader input, not native/original execution.
        from .clock_evidence import clock_plan
        plan, checkpoints = clock_plan(profile, disable_vdso)
        rows=[];cpu=[];clock3=100
        for index,(kind,clock_id,logical) in enumerate(plan,1):
            injected=profile is not None and kind=="work" and logical==profile["ordinal"]
            nanos=(clock3 if clock_id==3 else 1_000_000+index)
            if clock_id==3:cpu.append(clock3);clock3+=10
            error=5 if profile is None or profile["errno"]=="EIO" else 22
            rows.append({"clock_id":clock_id,"role":3,"role_index":0,"role_clock_ordinal":index,
                "tid":102,"result":-error if injected else 0,"seconds":0,"nanoseconds":nanos,
                "injected":{"kind":"clock","error":error,"original_syscall_skipped":True} if injected else None})
        charged=cpu[-1 if profile else -2]-cpu[0]
        total=None if profile else cpu[-1]-cpu[0]
        residual=None if profile else cpu[-1]-cpu[-2]
        booked=100_000_000 if profile else 0
        value={"worker_tid":102,"paid_checkpoints":checkpoints,
            "paid_live":{"poisoned":False,"unavailable":False,"refused":False,"charged_ns":charged,
                         "registered_threads":0,"termination_reserved":False},
            "paid_global":{"poisoned":False,"unavailable":profile is not None,"in_flight":0,
                "credit_ns":str(2_000_000_000-booked-charged-(residual or 0)),
                "termination_reserved_ns":0,"verified_completions":0,
                "flow":{"initial_credit_ns":"2000000000","credited_refill_ns":0,"discarded_refill_ns":0,
                    "booked_reservation_ns":booked,"live_debited_cpu_ns":charged,
                    "settlement_residual_cpu_ns":residual or 0,"settled_full_cpu_ns":total or 0,
                    "settlement_discard_ns":0}},
            "paid":None if profile else {"schema":"service-owner-scoped-thread-cpu-settlement-v1",
                "owner_cpu_ns":total,"scoped_worker_cpu_ns":0,"total_cpu_ns":total,
                "live_paid_cpu_ns":charged,"residual_cpu_ns":residual,"spawned_workers":0,
                "started_workers":0,"finished_workers":0,"known_workers":0,
                "live_refused":False,"accounting_unavailable":False}}
        return value,rows

    def test_complete_work_paid_clock_roles_and_all_eighteen_faults(self):
        from .clock_evidence import clock_plan, paid_clock_observation, original_constructor_clocks
        main_rows=[{"tid":91,"role":1,"role_index":0,"role_clock_ordinal":i,"clock_id":1,
                    "result":0,"seconds":1,"nanoseconds":i*10,"entry":i*10,"exit":i*10+1}
                   for i in (1,2,3)]
        ledger={"clocks":main_rows,"roles":{91:{"marker_exit":1}}}
        self.assertEqual(original_constructor_clocks(ledger,91,40,50),main_rows[0])
        for index,key,value in ((1,"role_clock_ordinal",2.0),(1,"clock_id",3),
                                (2,"seconds",0),(2,"exit",41)):
            bad=copy.deepcopy(ledger);bad["clocks"][index][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                original_constructor_clocks(bad,91,40,50)
        for index in (1,2):
            bad=copy.deepcopy(ledger);del bad["clocks"][index]
            with self.subTest(omitted_constructor=index),self.assertRaises(ValueError):
                original_constructor_clocks(bad,91,40,50)
        plan,checkpoints=clock_plan(None,True)
        self.assertEqual((len(plan),checkpoints),(4406,1100))
        self.assertEqual(sum(row[0]=="work" for row in plan),2200)
        self.assertEqual(sum(row[1]==3 for row in plan),1103)
        self.assertEqual(plan[-5:],[("work",1,2200),("finish-checkpoint-cpu",3,None),
            ("finish-checkpoint-wall",1,None),("settlement-cpu",3,None),("settlement-wall",1,None)])
        self.assertEqual(len(clock_plan(None,False)[0]),1103)
        for private in (False,True):
            value,rows=self.paid_clock_fixture(disable_vdso=private)
            result=paid_clock_observation(value,rows,None,private)
            self.assertEqual(result["cleanup"],"finish")
            self.assertEqual(result["paid_cpu_calls"],1103)
            self.assertEqual(result["paid_wall_calls"],1103 if private else 0)
        self.assertEqual(len(profiles()),18)
        for profile in profiles():
            value,rows=self.paid_clock_fixture(profile)
            result=paid_clock_observation(value,rows,profile,True)
            self.assertEqual(result["expected_fault"]["clock_when"],profile["clock_syscall_ordinal"])
            self.assertEqual(result["paid_checkpoints"],profile["ordinal"]//2)
            self.assertEqual(result["cleanup"],"drop")
            self.assertEqual([row["clock_id"] for row in rows[-3:]],[3,1,1])
        _,rows=self.paid_clock_fixture(profiles()[0])
        self.assertEqual([row["clock_id"] for row in rows],[3,1,1,3,1,1,3,1,1])
        self.assertEqual([r["role_clock_ordinal"] for r in rows if r["injected"]],[6])

    def test_paid_clock_reader_rejects_invented_cleanup_receipts_or_role_aliases(self):
        from .clock_evidence import paid_clock_observation
        profile=profiles()[0];value,rows=self.paid_clock_fixture(profile)
        clock_variants=[]
        for index,key,replacement in ((0,"clock_id",1),(0,"tid",True),(0,"role",2),
            (0,"role_index",0.0),(0,"role_clock_ordinal",True),(5,"result",0),
            (6,"result",-5),(6,"nanoseconds",99),(7,"nanoseconds",0)):
            changed=copy.deepcopy(rows);changed[index][key]=replacement
            clock_variants.append(changed)
        clock_variants += [rows[:-1],rows+rows[-1:],rows[:5]+rows[6:]]
        for changed in clock_variants:
            with self.assertRaises(ValueError):paid_clock_observation(value,changed,profile,True)
        variants=[
            (("paid_checkpoints",),True),(("paid_checkpoints",),0),
            (("paid_live","charged_ns"),0),(("paid_live","registered_threads"),1),
            (("paid_live","termination_reserved"),True),(("paid_live","unavailable"),True),
            (("paid_global","unavailable"),False),(("paid_global","poisoned"),0),
            (("paid_global","in_flight"),1),(("paid_global","verified_completions"),1),
            (("paid_global","credit_ns"),"2000000000"),
            (("paid_global","flow","booked_reservation_ns"),0),
            (("paid_global","flow","live_debited_cpu_ns"),0),
            (("paid_global","flow","settled_full_cpu_ns"),1),(("paid",),{})]
        for path,replacement in variants:
            changed=copy.deepcopy(value);target=changed
            for key in path[:-1]:target=target[key]
            target[path[-1]]=replacement
            with self.subTest(path=path),self.assertRaises(ValueError):
                paid_clock_observation(changed,rows,profile,True)
        normal,normal_rows=self.paid_clock_fixture()
        for key,replacement in (("owner_cpu_ns",None),("total_cpu_ns",0),("residual_cpu_ns",0),
                                ("live_refused",0),("known_workers",1),("schema","unbound")):
            changed=copy.deepcopy(normal);changed["paid"][key]=replacement
            with self.subTest(receipt=key),self.assertRaises(ValueError):
                paid_clock_observation(changed,normal_rows,None,True)

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
    controls = {"schema": "trnm.hia.work-owner-actual-clock-reader-controls.v2", "status": "FAIL",
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
        selected = next(row for row in data["report"]["actual_clock_calls"]
                        if row["tid"] == worker(data) and row.get("role_clock_ordinal") == 4402)
        selected.update(seconds=initial["seconds"] + 4, nanoseconds=initial["nanoseconds"])
        selected["timespec_hex"] = struct.pack("<qq", selected["seconds"], selected["nanoseconds"]).hex()
        event(data, selected["exit"])["actual_timespec_hex"] = selected["timespec_hex"]
    def paid_clock_role(data):
        row=next(r for r in data["report"]["actual_clock_calls"] if r["tid"]==worker(data) and r["role"]==3)
        row["clock_id"]=1
        event(data,row["entry"])["args"][0]=1
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
        ("paid-checkpoint-count-bool", "private-raw-positive", lambda d: observation(d, lambda v: v.update(paid_checkpoints=True))),
        ("paid-checkpoint-count-omitted", "private-raw-positive", lambda d: observation(d, lambda v: v.update(paid_checkpoints=v["paid_checkpoints"]-1))),
        ("paid-live-not-retired", "private-raw-positive", lambda d: observation(d, lambda v: v["paid_live"].update(registered_threads=1))),
        ("paid-live-charge-disconnected", "private-raw-positive", lambda d: observation(d, lambda v: v["paid_live"].update(charged_ns=v["paid_live"]["charged_ns"]+1))),
        ("paid-global-poison-type", "private-raw-positive", lambda d: observation(d, lambda v: v["paid_global"].update(poisoned=0))),
        ("paid-global-credit-minted", "private-raw-positive", lambda d: observation(d, lambda v: v["paid_global"].update(credit_ns=str(int(v["paid_global"]["credit_ns"])+1)))),
        ("paid-global-extra-authority", "private-raw-positive", lambda d: observation(d, lambda v: v["paid_global"].update(production_authority=True))),
        ("paid-settlement-union", "private-raw-positive", lambda d: observation(d, lambda v: v["paid"].update(total_cpu_ns=v["paid"]["total_cpu_ns"]+1))),
        ("paid-settlement-residual", "private-raw-positive", lambda d: observation(d, lambda v: v["paid"].update(residual_cpu_ns=v["paid"]["residual_cpu_ns"]+1))),
        ("coherent-paid-clock-role", "private-raw-positive", paid_clock_role),
        ("panic-paid-account-available", "clock-EIO-2", lambda d: observation(d, lambda v: v["paid_global"].update(unavailable=False))),
        ("panic-paid-returned-settlement", "clock-EIO-2", lambda d: observation(d, lambda v: v.update(paid={}))),
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
        need(len(controls["rows"]) == 32, "Actual original CLOCK reader control roster differs")
        controls.update(status="PASS", positive=2, negative=30, count=32)
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



def run_owned_memory(output):
    """Execute 23 physical memory controls against this process's new stopped child."""
    import ctypes
    import hashlib
    import mmap
    import signal
    import traceback
    from . import clock_trace as trace
    from .build import need, source_manifest, write_json
    from .clock_evidence import OBSERVER_SCOPE, OBSERVER_MEMORY_RAW, validate_owned_memory
    from .primitive_evidence import raw_identity, same
    output = Path(output)
    need(__debug__ and output.is_absolute() and output.resolve() == output and not output.exists(),
         "Fresh absolute owned memory control output required")
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
         "Owned memory controls require no pre-existing process alarm")
    before = source_manifest(); output.mkdir(mode=0o700)
    report = {"schema": "trnm.hia.work-owner-observer-owned-memory.v1", "status": "FAIL",
        "source_inputs": before, "source_after": "NOT_CHECKED", "control_count": 0,
        "positive": 0, "negative": 0, "owned_child": None, "raw": {}, **OBSERVER_SCOPE}
    pid = None; reaped = False; read_fd = None; write_fd = None; arena = None; previous_alarm = None
    operations = []
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        need(type(page) is int and page == trace.PAGE_BYTES == 4096,
             "Owned memory controls require the actual qualified x86-64 page size")
        arena = mmap.mmap(-1, page * 4, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                          prot=mmap.PROT_READ | mmap.PROT_WRITE)
        address = ctypes.addressof(ctypes.c_char.from_buffer(arena))
        data = bytearray((index * 17 + 11) % 256 for index in range(page * 4))
        strings = (("plain", 64, b"owned/read-only/path"),
            ("cross-page", page - 13, b"across-readable-pages/" + b"x" * 43),
            ("last-readable-byte-terminator", 2 * page - 23, b"z" * 22),
            ("empty-readonly", 3 * page + 64, b""))
        for _, offset, value in strings:
            data[offset:offset + len(value) + 1] = value + b"\0"
        data[512:576] = b"q" * 64; arena[:] = data
        expected = bytes(data[:2 * page] + data[3 * page:])
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                trace.LIBC.mprotect.restype = ctypes.c_int
                trace.LIBC.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                need(trace.LIBC.mprotect(address, 2 * page, mmap.PROT_READ) == 0
                     and trace.LIBC.mprotect(address + 2 * page, page, 0) == 0
                     and trace.LIBC.mprotect(address + 3 * page, page, mmap.PROT_READ) == 0,
                     "Actual owned memory permissions could not be installed")
                trace.ptrace(0, 0); os.kill(os.getpid(), signal.SIGSTOP)
                observed = arena[:2 * page] + arena[3 * page:]
                payload = (json.dumps({"pid": os.getpid(), "bytes": len(observed),
                    "sha256": hashlib.sha256(observed).hexdigest()},
                    sort_keys=True, separators=(",", ":")) + "\n").encode()
                need(os.write(write_fd, payload) == len(payload), "Child self-readback write incomplete")
                os._exit(0)
            except BaseException as error:
                try: os.write(write_fd, (json.dumps({"failure": repr(error)}) + "\n").encode())
                except BaseException: pass
                os._exit(125)
        os.close(write_fd); write_fd = None
        def timeout(signum, frame):
            raise TimeoutError("Owned memory controls exceeded twenty seconds")
        previous_alarm = signal.signal(signal.SIGALRM, timeout); signal.alarm(20)
        actual, initial_status = os.waitpid(pid, 0)
        if actual == pid and (os.WIFEXITED(initial_status) or os.WIFSIGNALED(initial_status)):
            reaped = True
        need(actual == pid and os.WIFSTOPPED(initial_status)
             and os.WSTOPSIG(initial_status) == signal.SIGSTOP,
             "Actual owned child did not stop before any memory read")
        trace.ptrace(0x4200, pid, 0, 0x100000)
        (output / "child-status.raw").write_bytes(Path(f"/proc/{pid}/status").read_bytes())
        (output / "maps-before.raw").write_bytes(Path(f"/proc/{pid}/maps").read_bytes())
        captured = trace.bytes_at(pid, address, 2 * page) + trace.bytes_at(pid, address + 3 * page, page)
        (output / "owned-readonly-before.raw").write_bytes(captured)
        need(captured == expected, "Actual owned initial memory differs from the fixed allocation")
        def peek_bytes(at, extent):
            need(0 <= extent <= 65536 and (at > 0 or extent == 0), "Bounded PEEK control required")
            value = bytearray()
            while len(value) < extent:
                cursor = at + len(value); aligned = cursor & ~7
                chunk = trace.peek(pid, aligned).to_bytes(8, "little")[cursor - aligned:]
                value.extend(chunk[:extent - len(value)])
            return bytes(value)
        def peek_string(at, limit=4096):
            value = bytearray()
            while len(value) < limit:
                cursor = at + len(value); aligned = cursor & ~7
                chunk = trace.peek(pid, aligned).to_bytes(8, "little")[cursor - aligned:]
                chunk = chunk[:limit - len(value)]
                if b"\0" in chunk:
                    value.extend(chunk.split(b"\0", 1)[0]); return bytes(value)
                value.extend(chunk)
            raise ValueError("Bounded PEEK string omitted its terminator")
        reads = ((0, 1), (1, 7), (7, 9), (63, 32), (257, 257), (page - 13, 80),
                 (page - 1, 2), (page + 17, 513), (2 * page - 8, 8),
                 (3 * page + 16, 128), (4 * page - 17, 17))
        for offset, extent in reads:
            peeked = peek_bytes(address + offset, extent)
            bulk = trace.bytes_at(pid, address + offset, extent)
            operations.append({"name": "complete-read-%d-%d" % (offset, extent), "pid": pid,
                "offset": offset, "extent": extent, "old_PEEK_hex": peeked.hex(),
                "new_bulk_hex": bulk.hex(), "status": "PASS"})
            need(peeked == bulk == bytes(data[offset:offset + extent]),
                 "Actual complete PEEK and bulk memory differ")
        for name, offset, expected_string in strings:
            peeked = peek_string(address + offset); bulk = trace.cstring(pid, address + offset)
            operations.append({"name": "cstring-" + name, "pid": pid, "offset": offset,
                "limit": 4096, "old_PEEK_hex": peeked.hex(), "new_bulk_hex": bulk.hex(), "status": "PASS"})
            need(peeked == bulk == expected_string, "Actual complete PEEK and bulk C strings differ")
        target = ctypes.create_string_buffer(16)
        local = trace.IOVec(ctypes.addressof(target), 16)
        remote = trace.IOVec(address + 2 * page - 8, 16)
        ctypes.set_errno(0)
        returned = trace.LIBC.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        kernel = {"pid": pid, "offset": 2 * page - 8, "requested": 16,
                  "returned": returned, "errno": ctypes.get_errno(),
                  "retained_prefix_hex": target.raw[:max(0, returned)].hex()}
        write_json(output / "kernel-transfer.json", kernel)
        need(returned == 8 and target.raw[:8] == expected[2 * page - 8:2 * page],
             "Actual kernel did not expose the bounded partial transfer")
        negatives = (
            ("strict-actual-short-read", "bytes", 2 * page - 8, 16,
             "ValueError", None, "Actual owned memory read was incomplete"),
            ("fully-unreadable-page", "bytes", 2 * page, 16, "OSError", 14, None),
            ("cstring-unreadable-page", "cstring", 2 * page, 4096, "OSError", 14, None),
            ("cstring-no-terminator-in-bound", "cstring", 512, 32,
             "ValueError", None, "Actual C string omitted bounded terminator"),
            ("negative-memory-extent", "bytes", 0, -1,
             "ValueError", None, "Private bounded memory read"),
            ("oversized-memory-extent", "bytes", 0, 65537,
             "ValueError", None, "Private bounded memory read"),
            ("missing-nonempty-address", "null", 0, 1,
             "ValueError", None, "Actual memory read address absent"),
        )
        for name, operation, offset, extent, kind, errno, message in negatives:
            caught = None
            try:
                if operation == "cstring": trace.cstring(pid, address + offset, extent)
                else: trace.bytes_at(pid, 0 if operation == "null" else address + offset, extent)
            except (ValueError, OSError) as error:
                caught = error
            need(caught is not None, "Actual memory negative was accepted: " + name)
            row = {"name": name, "pid": pid, "operation": operation, "offset": offset,
                   "extent": extent, "status": "PASS", "rejected": True,
                   "error_type": type(caught).__name__,
                   "errno": caught.errno if isinstance(caught, OSError) else None,
                   "message": None if isinstance(caught, OSError) else str(caught)}
            operations.append(row)
            need((row["error_type"], row["errno"], row["message"]) == (kind, errno, message),
                 "Actual memory negative failed for another reason: " + name)
        empty = trace.bytes_at(pid, 0, 0); empty_peek = peek_bytes(0, 0)
        need(empty == empty_peek == b"", "Actual zero-extent control changed")
        operations.append({"name": "zero-extent-no-read", "pid": pid, "status": "PASS",
                           "old_PEEK_hex": empty_peek.hex(), "new_bulk_hex": empty.hex()})
        (output / "maps-after.raw").write_bytes(Path(f"/proc/{pid}/maps").read_bytes())
        after = trace.bytes_at(pid, address, 2 * page) + trace.bytes_at(pid, address + 3 * page, page)
        (output / "owned-readonly-after.raw").write_bytes(after)
        need(after == captured, "Actual owned memory changed while stopped")
        trace.ptrace(7, pid, 0, 0)
        actual, terminal = os.waitpid(pid, 0)
        if actual == pid and (os.WIFEXITED(terminal) or os.WIFSIGNALED(terminal)):
            reaped = True
        need(actual == pid and reaped and os.WIFEXITED(terminal) and os.WEXITSTATUS(terminal) == 0,
             "Actual owned child did not exit zero and reap")
        pieces = []; total = 0
        while True:
            piece = os.read(read_fd, 4096)
            if not piece: break
            total += len(piece); need(total <= 4096, "Child self-readback exceeded its complete bound")
            pieces.append(piece)
        (output / "child-self-readback.raw").write_bytes(b"".join(pieces))
        report["owned_child"] = {"pid": pid, "parent_pid": os.getpid(), "address": address,
            "page_bytes": page, "initial_wait_status": initial_status, "terminal_wait_status": terminal,
            "exit_code": os.WEXITSTATUS(terminal), "reaped": reaped, "ptrace_exitkill": True}
        report.update(status="PASS", control_count=len(operations), positive=16, negative=7)
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        if previous_alarm is not None:
            signal.alarm(0); signal.signal(signal.SIGALRM, previous_alarm)
        if pid and not reaped:
            # A terminal wait is recorded immediately, before any assertion.
            # Only our unreaped child can remain eligible for this cleanup.
            try:
                actual, status = os.waitpid(pid, os.WNOHANG)
                if actual == pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    reaped = True
            except ChildProcessError:
                reaped = True
            if not reaped:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try:
                    actual, status = os.waitpid(pid, 0)
                    reaped = actual == pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status))
                except ChildProcessError:
                    reaped = True
            report["failure_cleanup_reaped"] = reaped
        for descriptor in (read_fd, write_fd):
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: pass
        if arena is not None: arena.close()
        (output / "memory-operations.jsonl").write_bytes(b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in operations))
        report["raw"] = {name: raw_identity((output / name).read_bytes()) for name in OBSERVER_MEMORY_RAW
                         if (output / name).is_file()}
        try:
            need(same(source_manifest(), before), "Owned memory control sources changed")
            report["source_after"] = "MATCH"
        except BaseException as error:
            report.update(status="FAIL", source_after="FAIL", source_failure=repr(error))
        write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Actual owned observer memory controls failed: " + str(report.get("failure")))
    return validate_owned_memory(output, source_inputs=before)

def actual_observer_memory_reader_controls(memory, output, *, source_inputs):
    """Retain and reread complete physical evidence plus ten precise byte mutants."""
    from .build import need, source_manifest, write_json
    from .clock_evidence import (Capture, OBSERVER_MEMORY_RAW, OBSERVER_SCOPE,
        OBSERVER_READER_SPECS, OBSERVER_READER_FAILURES, observer_mutation,
        observer_control_outcome, validate_observer_reader_controls)
    from .primitive_evidence import raw_identity, same
    memory = Path(memory); output = Path(output)
    need(output.is_absolute() and output.resolve() == output and not output.exists(),
         "Fresh observer raw reader control output required")
    capture = Capture(memory, exact_names=("report.json", *OBSERVER_MEMORY_RAW))
    try:
        raw = {name: capture.read(name, 2 << 20) for name in ("report.json", *OBSERVER_MEMORY_RAW)}
        baseline = {name: raw_identity(value) for name, value in raw.items()}
        output.mkdir(mode=0o700)
        report = {"schema": "trnm.hia.work-owner-observer-memory-reader-controls.v1",
            "status": "FAIL", "source_inputs": source_inputs, "source_after": "NOT_CHECKED",
            "baseline_after": "NOT_CHECKED", "baseline": baseline, "rows": [],
            "count": 0, "positive": 0, "negative": 0,
            "actual_owned_children_executed_by_reader_controls": 0, **OBSERVER_SCOPE}
        try:
            need(same(source_manifest(), source_inputs), "Observer reader sources changed before controls")
            for name, expected in OBSERVER_READER_SPECS:
                directory = output / name; directory.mkdir(mode=0o700)
                changed = observer_mutation(raw, name)
                for file, value in changed.items(): (directory / file).write_bytes(value)
                acceptance, failure = observer_control_outcome(directory, source_inputs=source_inputs)
                row = {"name": name, "status": "PASS" if acceptance is expected
                       and failure == OBSERVER_READER_FAILURES.get(name) else "FAIL",
                    "expected_acceptance": expected, "actual_acceptance": acceptance,
                    "actual_failure": failure,
                    "raw": {file: raw_identity(value) for file, value in changed.items()}}
                report["rows"].append(row)
                print(json.dumps({"observer_memory_reader": name, "status": row["status"],
                                  "failure": failure}, sort_keys=True), flush=True)
                need(row["status"] == "PASS", "Observer actual raw control had another outcome: " + name)
            report.update(status="PASS", count=12, positive=2, negative=10)
        except BaseException as error:
            report.update(failure=repr(error))
        finally:
            try:
                capture.fence()
                need(same(source_manifest(), source_inputs), "Observer reader sources changed after controls")
                report["source_after"] = report["baseline_after"] = "MATCH"
            except BaseException as error:
                report.update(status="FAIL", final_fence_failure=repr(error))
            write_json(output / "report.json", report)
        need(report["status"] == "PASS", "Observer raw memory control failure: " + str(report.get("failure")))
        validate_observer_reader_controls(output, source_inputs=source_inputs, baseline=baseline)
        return report
    finally:
        capture.close()

def actual_observer_controls(clock_root, complete, output):
    """Run the separate owned-memory gate and replay all twenty original streams."""
    import traceback
    from .build import need, source_manifest, write_json, identity
    from .clock_evidence import OBSERVER_SCOPE, observer_clock_replays, validate_observer_controls
    from .primitive_evidence import same
    clock_root = Path(clock_root); output = Path(output)
    need(output == clock_root / "observer-memory-controls" and output.is_absolute()
         and output.resolve() == output and not output.exists(),
         "Fresh observer controls under the actual original clock root required")
    before = source_manifest()
    need(same(before, complete["source_inputs"]), "Observer gate has another original clock source")
    output.mkdir(mode=0o700)
    report = {"schema": "trnm.hia.work-owner-observer-controls.v1", "status": "FAIL",
        "source_inputs": before, "source_after": "NOT_CHECKED", "memory": None,
        "memory_report": None, "reader_controls_report": None, "clock_ordinal_replays": [],
        "memory_count": 23, "memory_positive": 16, "memory_negative": 7,
        "owned_children": 1, "clock_ordinal_replay_count": 20,
        "reader_count": 12, "reader_positive": 2, "reader_negative": 10, **OBSERVER_SCOPE}
    try:
        memory = run_owned_memory(output / "memory")
        report["memory"] = memory; report["memory_report"] = identity(output / "memory/report.json")
        actual_observer_memory_reader_controls(output / "memory", output / "reader-controls",
                                               source_inputs=before)
        report["reader_controls_report"] = identity(output / "reader-controls/report.json")
        report["clock_ordinal_replays"] = observer_clock_replays(clock_root, complete)
        report["status"] = "PASS"
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        try:
            need(same(source_manifest(), before), "Observer complete gate sources changed")
            report["source_after"] = "MATCH"
        except BaseException as error:
            report.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Actual observer memory/ordinal gate failed: " + str(report.get("failure")))
    parent = {**complete, "observer_memory_controls": report,
              "observer_memory_controls_report": identity(output / "report.json")}
    validate_observer_controls(output, source_inputs=before, clock_root=clock_root, complete=parent)
    return report

if __name__ == "__main__":
    unittest.main()
