"""Actual short local-process controls; no test produces a W1 proof or payment."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import w1_generation_target_v2 as target


def short_process_request(root, *, sleep=0):
    """Finite test process only: no prover, verifier, funding or payment."""
    script = root / "actual_short_child.py"
    script.write_text("from pathlib import Path\nimport time\n"
                      f"with Path({str(root / 'invocations')!r}).open('a') as f: f.write('one\\n')\n"
                      f"time.sleep({sleep!r})\n")
    python = str(Path(sys.executable).resolve())
    now = time.monotonic_ns()
    return {"schema": target.NAMESPACE, "target_instance": "actual-short-process-test",
            "operation": "01" * 32, "task_scope": "02" * 32, "statement": "03" * 32,
            "provider_namespace": "04" * 32, "execution_source_commitment": "05" * 32,
            "target_backend_sha256": target.file_sha(target.__file__),
            "clock_domain": target.clock_domain("actual-short-process-test"),
            "winner_monotonic_ns": now - 1, "deadline_monotonic_ns": now + 10_000_000_000,
            "argv": [python, str(script)], "cwd": str(root),
            "file_pins": {python: target.file_sha(python), str(script): target.file_sha(script)},
            "environment": {"PATH": "/usr/bin:/bin", "RAYON_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1"},
            "cpus": [min(os.sched_getaffinity(0))], "total_threads": 1,
            "containment": "process-group-research", "cleanup_grace_ns": 1_000_000_000}


def add_339_real_file_pins(request, root):
    """Match the failed request's pin count with new, actually hashed files."""
    padding = "x" * max(0, 150 - len(str(root)))
    for i in range(337):
        path = root / (f"pin-{i:03d}-" + padding)
        path.write_bytes(f"actual parser test input {i}\n".encode())
        request["file_pins"][str(path)] = target.file_sha(path)
    request["deadline_monotonic_ns"] = time.monotonic_ns() + 60_000_000_000
    return request


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.children = []
        original = target.subprocess.Popen
        def retained(*args, **kwargs):
            child = original(*args, **kwargs)
            self.children.append(child)
            return child
        self.popen_patch = patch.object(target.subprocess, "Popen", side_effect=retained)
        self.popen_patch.start()

    def tearDown(self):
        try:
            for child in self.children:
                try:
                    child.wait(timeout=2)
                except target.subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        finally:
            self.popen_patch.stop()

    def request(self, root, *, sleep=0):
        return short_process_request(root, sleep=sleep)

    def wait_result(self, db, op):
        until = time.monotonic() + 15
        while time.monotonic() < until:
            row = target.read_operation(db, op)
            if row["result"] is not None:
                return row
            time.sleep(.02)
        self.fail("actual short process did not publish its retained result")

    def test_actual_process_cold_replay_and_cross_journal_fence_no_second_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            first = self.wait_result(db, r["operation"])
            self.assertTrue(first["result"]["command_success"])
            self.assertIsNotNone(first["result"]["child_identity"])
            self.assertFalse(first["result"]["all_owned_processes_terminal"])
            self.assertEqual(first["state"], "termination-unknown")
            self.assertFalse(first["result"]["can_authorize_payment"])
            db.close()
            replay = target.dispatch(args)
            self.assertEqual(replay["worker"], first["worker"])
            self.assertEqual((root / "invocations").read_text(), "one\n")
            changed = copy.deepcopy(r)
            changed["operation"] = "ff" * 32
            changed["statement"] = "fe" * 32
            request.write_bytes(target.canonical(changed))
            with self.assertRaises(sqlite3.IntegrityError):
                target.dispatch(args)
            self.assertEqual((root / "invocations").read_text(), "one\n")

    def test_actual_running_cancel_is_sticky_and_not_a_resource_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root, sleep=5)
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            until = time.monotonic() + 5
            while not (root / "invocations").exists() and time.monotonic() < until:
                time.sleep(.02)
            self.assertTrue((root / "invocations").exists())
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE operations SET cancel=1 WHERE operation=?", (r["operation"],))
            db.execute("COMMIT")
            finished = self.wait_result(db, r["operation"])
            self.assertTrue(finished["cancel"])
            self.assertTrue(finished["result"]["sticky_cancel"])
            self.assertFalse(finished["result"]["command_success"])
            self.assertEqual(finished["result"]["cause"], "cancelled")
            self.assertFalse(finished["result"]["all_owned_processes_terminal"])
            replay = target.dispatch(args)
            self.assertTrue(replay["sticky_cancel"])
            self.assertEqual((root / "invocations").read_text(), "one\n")

    def test_changed_proof_plan_and_argv_cannot_reuse_real_original_operation(self):
        # The child is a real bounded local fixture, not a W1 prover. What is
        # tested is the durable target's actual complete-request fence, shared
        # by real heavy commands and independent of a claimed plan label.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            first_plan = {"segment_workers": 2, "compression_mode": "balanced", "compression_workers": 2, "rayon_threads": 4}
            second_plan = {"segment_workers": 1, "compression_mode": "sequential", "compression_workers": 1, "rayon_threads": 8}
            r["proof_plan"] = first_plan
            r["argv"].extend(["--synthetic-plan-binding", target.canonical(first_plan).decode()])
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            retained = self.wait_result(db, r["operation"])
            db.close()
            changed = copy.deepcopy(r)
            changed["proof_plan"] = second_plan
            changed["argv"][-1] = target.canonical(second_plan).decode()
            request.write_bytes(target.canonical(changed))
            with self.assertRaisesRegex(ValueError, "operation replay mismatch"):
                target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            after = target.read_operation(db, r["operation"])
            self.assertEqual(after["request_sha256"], retained["request_sha256"])
            self.assertEqual(after["worker"], retained["worker"])
            self.assertEqual((root / "invocations").read_text(), "one\n")
            self.assertEqual(len(self.children), 1)
            db.close()

    def test_expired_deadline_and_changed_clock_refuse_before_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            r["deadline_monotonic_ns"] = r["winner_monotonic_ns"] + 1
            with self.assertRaisesRegex(ValueError, "deadline expired"):
                target.request_check(r, r["target_instance"])
            r["deadline_monotonic_ns"] = time.monotonic_ns() + 5_000_000_000
            r["clock_domain"] = "ff" * 32
            with self.assertRaisesRegex(ValueError, "continuity UNKNOWN"):
                target.request_check(r, r["target_instance"])
            self.assertFalse((root / "invocations").exists())

    def test_recursive_population_cannot_hide_behind_empty_direct_members(self):
        # Files model kernel readback, not a claim of actual cgroup execution.
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            (group / "cgroup.procs").write_text("")
            (group / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            nested = group / "nested"
            nested.mkdir()
            (nested / "cgroup.procs").write_text("12345\n")
            observed = target.cgroup_observation(group)
            self.assertEqual(observed["members"], [12345])
            self.assertFalse(observed["recursive_empty"])
            self.assertIsNone(observed["all_descendants_reaped"])
            (nested / "cgroup.procs").write_text("")
            self.assertFalse(target.cgroup_observation(group)["recursive_empty"])
            (group / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            self.assertTrue(target.cgroup_observation(group)["recursive_empty"])

    def test_missing_hierarchical_events_and_replaced_identity_remain_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            (group / "cgroup.procs").write_text("")
            with self.assertRaises(FileNotFoundError):
                target.cgroup_observation(group)
            (group / "cgroup.events").write_text("populated 0\npopulated 0\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                target.cgroup_observation(group)
            (group / "cgroup.events").write_text("populated 0\n")
            identity = target.cgroup_identity(group)
            identity["inode"] += 1
            with self.assertRaisesRegex(ValueError, "identity changed"):
                target.cgroup_observation(group, identity)

    def test_tree_change_during_observation_cannot_be_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            (group / "cgroup.procs").write_text("")
            (group / "cgroup.events").write_text("populated 0\n")
            original = target.cgroup_identity
            count = 0
            def changed(path):
                nonlocal count
                count += 1
                result = original(path)
                if count >= 3:
                    result["inode"] += 1
                return result
            with patch.object(target, "cgroup_identity", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "tree changed"):
                    target.cgroup_observation(group)

    def test_339_real_pins_over_64k_use_shared_preflight_and_dispatch_loader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = add_339_real_file_pins(self.request(root), root)
            self.assertEqual(len(r["file_pins"]), 339)
            compact = target.canonical(r)
            raw = (json.dumps(r, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
            self.assertGreater(len(compact), 65536)
            self.assertGreater(len(raw), 65536)
            self.assertLess(len(raw), target.MAX_REQUEST)
            request = root / "request.json"
            request.write_bytes(raw)
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            with patch.object(target, "load_request", wraps=target.load_request) as loader:
                with patch.object(sys, "argv", [target.__file__, "preflight", "--root", args.root,
                                               "--target", args.target, "--request", args.request]), \
                     redirect_stdout(io.StringIO()) as printed:
                    target.main()
                self.assertTrue(json.loads(printed.getvalue())["request_valid_now"])
                self.assertFalse(Path(args.root).exists())
                self.assertEqual(len(self.children), 0)
                target.dispatch(args)
                self.assertEqual(loader.call_args_list, [unittest.mock.call(args.request, args.target)] * 2)
            db, _ = target.open_db(args.root, args.target, False)
            row = self.wait_result(db, r["operation"])
            self.assertTrue(row["result"]["command_success"])
            self.assertFalse(row["result"]["can_authorize_payment"])
            self.assertEqual(db.execute("SELECT request FROM operations").fetchone()[0], compact)
            self.assertEqual(row["request_sha256"], target.sha(compact))
            db.close()
            replay = target.dispatch(args)
            self.assertEqual(replay["worker"], row["worker"])
            self.assertEqual((root / "invocations").read_text(), "one\n")
            self.assertEqual(len(self.children), 1)

    def test_raw_cap_exact_plus_one_and_actual_read_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            request = root / "request.json"
            compact = target.canonical(r)
            self.assertEqual(target.MAX_REQUEST, 131072)
            base_open = Path.open
            reads = []
            class ObservedStream:
                def __init__(self, stream):
                    self.stream = stream
                def __enter__(self):
                    return self
                def __exit__(self, *unused):
                    self.stream.close()
                def read(self, amount):
                    data = self.stream.read(amount)
                    reads.append((amount, len(data), self.stream.tell()))
                    return data
            def observe(path, mode="r", *args, **kwargs):
                stream = base_open(path, mode, *args, **kwargs)
                return ObservedStream(stream) if path == request and mode == "rb" else stream
            for size in (target.MAX_REQUEST, target.MAX_REQUEST + 1, target.MAX_REQUEST * 16):
                request.write_bytes(compact + b" " * (size - len(compact)))
                reads.clear()
                with patch.object(Path, "open", observe):
                    if size == target.MAX_REQUEST:
                        self.assertEqual(target.load_request(request, r["target_instance"]), r)
                    else:
                        with self.assertRaisesRegex(ValueError, "request size"):
                            target.load_request(request, r["target_instance"])
                consumed = min(size, target.MAX_REQUEST + 1)
                self.assertEqual(reads, [(target.MAX_REQUEST + 1, consumed, consumed)])
            self.assertFalse((root / "invocations").exists())

    def test_ambiguous_json_nonfinite_and_nonobject_reject_before_target_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = root / "request.json"
            args = SimpleNamespace(root=str(root / "never-created"), target="actual-short-process-test", request=str(request))
            cases = [(b'{"outer":{"key":1,"key":2}}', "duplicate"),
                     (b'{"key":1,"key":2}', "duplicate"),
                     (b'{"outer":[NaN]}', "nonfinite"), (b'{"outer":[Infinity]}', "nonfinite"),
                     (b'{"outer":[-Infinity]}', "nonfinite"), (b'{"outer":[1e999]}', "nonfinite"),
                     (b'{"outer":[-1e999]}', "nonfinite"),
                     (b'[]', "object"), (b'null', "object"), (b'"object"', "object"),
                     (b'{}', "required fields")]
            for raw, error in cases:
                with self.subTest(raw=raw):
                    request.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, error):
                        target.dispatch(args)
                    self.assertFalse(Path(args.root).exists())
            self.assertEqual(len(self.children), 0)

    def test_strict_request_shape_and_current_binding_reject_before_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.request(root)
            request = root / "request.json"
            args = SimpleNamespace(root=str(root / "never-created"), target=original["target_instance"], request=str(request))
            for key, value in (("schema", "v3"), ("target_instance", "another-target"),
                               ("operation", True), ("statement", []), ("target_backend_sha256", "ff" * 32),
                               ("winner_monotonic_ns", True), ("deadline_monotonic_ns", 1.0),
                               ("cwd", None), ("argv", "not-list"), ("file_pins", []),
                               ("environment", []), ("cpus", [[0]]), ("cpus", [True]),
                               ("total_threads", True), ("cleanup_grace_ns", 1.0)):
                changed = copy.deepcopy(original)
                changed[key] = value
                with self.subTest(key=key, value=value):
                    request.write_bytes(target.canonical(changed))
                    with self.assertRaises(ValueError):
                        target.dispatch(args)
                    self.assertFalse(Path(args.root).exists())
            self.assertEqual(len(self.children), 0)

    def test_raw_utf8_only_and_legacy_nonascii_canonical_bytes_are_unchanged(self):
        # This is the original V2 encoding, including literal UTF-8. The raw
        # request admission policy must not turn into an ASCII re-encoding cap.
        expected = '{"a":[1,true,null],"z":"模型é"}'.encode("utf-8")
        self.assertEqual(target.canonical({"z": "模型é", "a": [1, True, None]}), expected)
        self.assertEqual(target.MAX_RESULT, 65536)
        self.assertEqual(target.NAMESPACE, "trnm-w1-generation-posix-target-v2")
        self.assertEqual(target.APPLICATION_ID, 0x57475432)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            r["annotation"] = "模型é"
            compact = target.canonical(r)
            self.assertLess(len(compact), 65536)
            request = root / "request.json"
            request.write_bytes(compact)
            self.assertEqual(target.canonical(target.load_request(request, r["target_instance"])), compact)
            digest = target.sha(compact)
            request.write_text(json.dumps(r, sort_keys=True, indent=2), encoding="utf-8")
            self.assertEqual(target.sha(target.canonical(target.load_request(request, r["target_instance"]))), digest)
            for encoding in ("utf-16", "utf-16-le", "utf-32"):
                request.write_bytes(json.dumps(r).encode(encoding))
                with self.assertRaises(ValueError):
                    target.load_request(request, r["target_instance"])
            request.write_bytes(b'\xff')
            with self.assertRaises(UnicodeDecodeError):
                target.load_request(request, r["target_instance"])

    def test_retained_v2_blob_is_not_reinterpreted_using_the_inbound_raw_cap(self):
        # A synthetic retained-format BLOB tests the read policy only; no
        # dispatch, successful work, historical provenance or payment is claimed.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            r["retained_extension"] = "x" * (target.MAX_REQUEST + 1)
            encoded = target.canonical(r)
            db, _ = target.open_db(root / "retained-only", r["target_instance"], True)
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?,'intent',0,NULL,NULL)",
                       (r["operation"], r["task_scope"], r["statement"], encoded, target.sha(encoded)))
            db.close()
            db, _ = target.open_db(root / "retained-only", r["target_instance"], False)
            observed = target.read_operation(db, r["operation"])
            self.assertEqual(target.canonical(observed["request"]), encoded)
            self.assertEqual(observed["request_sha256"], target.sha(encoded))
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (2,))
            db.close()
            self.assertEqual(len(self.children), 0)


if __name__ == "__main__":
    unittest.main()
