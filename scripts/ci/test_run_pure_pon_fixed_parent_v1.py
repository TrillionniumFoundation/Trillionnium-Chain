#!/usr/bin/env python3
"""Lightweight fixture ownership/failure controls; no systemd/cgroup operation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run_pure_pon_fixed_parent_v1 as fixture


def context():
    directory = lambda inode: {"device": 3, "inode": inode, "uid": 0, "gid": 0, "mode": stat.S_IFDIR | 0o755}
    regular = {"device": 3, "inode": 12, "uid": 0, "gid": 0, "mode": stat.S_IFREG | 0o644}
    nonce = "a" * 32
    manager = {"Description": "Owned PoN finite fixed-parent CI fixture " + nonce, "Transient": "yes",
               "ControlGroup": "/trnmponpublic.slice", "ActiveState": "active", "InvocationID": "b" * 32}
    return {"schema": fixture.CONTEXT_SCHEMA, "parent_path": str(fixture.PARENT),
            "owner_nonce": nonce, "leaf_path": str(fixture.PARENT / ("owned-" + nonce + ".group")),
            "parent_identity": directory(10), "leaf_identity": directory(11),
            "migration_file_identity": regular, "runner_uid": 1001, "runner_gid": 1001, "root_fixture_pid": 7000,
            "limits": copy.deepcopy(fixture.LIMITS), "expected_head": "1" * 40, "expected_tree": "2" * 40,
            "boot_id": "11111111-2222-3333-4444-555555555555", "outer_cgroup": "0::/system.slice/owned-test.service\n",
            "manager_identity": manager, "initial_root_open": {"identity": regular, "opening_euid": 0,
              "open_flags": os.O_WRONLY | os.O_CLOEXEC, "descriptor_flags": 1, "kernel_enforced_write_zero_only": False},
            "physical_authentication": False, "production_qualified": False, "kernel_enforced_write_zero_only": False}


def snapshot(expected=None, *, start=1, end=2, cpu=1000, periods=100, throttled=5):
    expected = expected or context()
    cpu_raw = (f"usage_usec {cpu}\nuser_usec {cpu}\nsystem_usec 0\nnr_periods {periods}\n"
               f"nr_throttled {throttled}\nthrottled_usec {throttled * 10}\n")
    raw = {"cpu.stat": cpu_raw, "memory.current": "1024\n", "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
           "pids.current": "0\n", "cgroup.procs": "", "cgroup.threads": "", "cgroup.events": "populated 0\nfrozen 0\n",
           "cgroup.type": "domain\n"}
    return {"schema": "pon-fixed-parent-kernel-snapshot-v1", "started_monotonic_ns": start, "ended_monotonic_ns": end,
            "complete": True, "errors": [], "boot_id": expected["boot_id"],
            "parent": {"identity": copy.deepcopy(expected["parent_identity"]),
                       "values": {**raw, **{k: v + "\n" for k, v in fixture.LIMITS.items()},
                                  "cgroup.subtree_control": "cpu memory pids\n"}},
            "leaf": {"identity": copy.deepcopy(expected["leaf_identity"]),
                     "values": {**raw, "cgroup.max.descendants": "0\n"}}}


def process_row(expected=None, phase="baseline", binary="/synthetic/pressure", pid=90000):
    expected = expected or context()
    return {"schema": "pon-fixed-parent-controller-process-v1", "phase": phase,
            "command": ["/usr/bin/setpriv", "--reuid", str(expected["runner_uid"]), "--regid", str(expected["runner_gid"]),
                        "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                        "--", binary, "--exact", "fixed_parent::fixed_parent_receiver_phase_v1", "--ignored",
                        "--nocapture", "--test-threads=1"], "inherited_descriptor": copy.deepcopy(expected["initial_root_open"]),
            "pid": pid, "started_monotonic_ns": 10, "ended_monotonic_ns": 100, "returncode": 0, "actual_reaped_returncode": 0,
            "error": None, "stdout_truncated": False, "stderr_truncated": False, "forced_controller_group_cleanup": False,
            "owned_group_cleanup_attempted": True, "owned_group_cleanup_error": None, "original_phase_window_ns": 30_000_000_000,
            "original_call_deadline_ns": 2_000_000_000, "outer_controller_limit_seconds": 600}


class TerminalControls(unittest.TestCase):
    def test_success_requires_both_original_terminal_and_final_reap(self):
        self.assertTrue(fixture.process_complete(process_row()))
        for field, value in (("returncode", 7), ("actual_reaped_returncode", 7), ("actual_reaped_returncode", None),
                             ("returncode", False), ("actual_reaped_returncode", False), ("reap_error", "lost child"),
                             ("error", "timeout"), ("owned_group_cleanup_attempted", False),
                             ("owned_group_cleanup_error", "permission"), ("forced_controller_group_cleanup", True),
                             ("stdout_truncated", True), ("stderr_truncated", True)):
            with self.subTest(field=field, value=value):
                row = process_row()
                row[field] = value
                self.assertFalse(fixture.process_complete(row))

    def test_known_members_and_unknowns_cannot_be_empty(self):
        self.assertTrue(fixture.empty(snapshot()))
        for scope, field, raw in (("parent", "cgroup.procs", "123\n"), ("leaf", "cgroup.threads", "456\n"),
                                  ("parent", "pids.current", "1\n"), ("leaf", "cgroup.events", "populated 1\n"),
                                  ("leaf", "cgroup.events", "frozen 0\n")):
            with self.subTest(scope=scope, field=field):
                value = snapshot()
                value[scope]["values"][field] = raw
                self.assertFalse(fixture.empty(value))
        value = snapshot()
        value["complete"] = False
        self.assertFalse(fixture.empty(value))

    def test_duplicate_or_noninteger_kernel_fields_are_rejected(self):
        for raw in ("populated 0\npopulated 0\n", "populated unknown\n", "populated -1\n", "populated\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fixture.kernel_pairs(raw)

    def test_duplicate_nonfinite_json_is_rejected(self):
        for raw in (b'{"x":1,"x":1}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fixture.strict_json(raw)

    def test_only_owned_topology_pseudofiles_are_writable(self):
        for name in ("cgroup.procs", "cpu.max", "memory.max", "../cgroup.procs"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixture.write_at(-1, name, "0\n")


class UnitFileAbsenceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.owner = fixture.Owner(self.output)
        self.capability = {"euid": 0, "github_actions": "true", "runner_environment": "github-hosted",
                           "systemd_present": True, "cgroup_root_writable": True, "fixed_parent_exists": False}

    def reply(self, **changes):
        return {"label": "absence-unit-files-by-patterns", "command": fixture.unit_file_absence_command(),
                "returncode": 0, "error": None, "stdout": "a(ss) 0\n", "stderr": "", **changes}

    def capture(self, code=0, stdout=b"a(ss) 0\n", stderr=b""):
        return subprocess.CompletedProcess(fixture.unit_file_absence_command(), code, stdout, stderr)

    def rejected_create(self, capture):
        loaded = subprocess.CompletedProcess(fixture.loaded_unit_absence_command(), 0, b"", b"")
        with patch.object(fixture, "host_capability", return_value=self.capability), \
             patch.object(fixture.os.path, "lexists", return_value=False), \
             patch.object(fixture.subprocess, "run", side_effect=[loaded, capture]) as process, \
             self.assertRaises(ValueError):
            self.owner.create()
        self.assertEqual(process.call_count, 2)
        self.assertFalse(self.owner.creation_attempted)
        self.assertFalse(self.owner.started_by_fixture)
        self.assertEqual([row["label"] for row in self.owner.commands],
                         ["absence-list-units", "absence-unit-files-by-patterns"])
        row = json.loads((self.output / "manager-command-02.json").read_bytes())
        self.assertEqual(row, self.owner.commands[1])
        return row

    def test_query_uses_empty_state_filter_and_only_exact_fixed_unit(self):
        self.assertEqual(fixture.unit_file_absence_command(), [
            "/usr/bin/busctl", "--system", "call", "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
            "ListUnitFilesByPatterns", "asas", "0", "1", "trnmponpublic.slice"])

    def test_only_typed_empty_array_is_absence(self):
        fixture.require_unit_file_absence(self.reply())
        for raw in ("", "0\n", "as 0\n", "a(ss)\n0\n", "a(ss) 0\na(ss) 0\n",
                    "a(ss) 0 trailing\n", 'a(ss) 1 "/etc/systemd/system/trnmponpublic.slice" "enabled"\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fixture.require_unit_file_absence(self.reply(stdout=raw))

    def test_typed_empty_array_does_not_override_exit_error_or_warning(self):
        for changes in ({"returncode": 1}, {"returncode": -9}, {"returncode": None},
                        {"returncode": False}, {"error": "capture failed"}, {"stderr": "warning\n"},
                        {"command": ["/usr/bin/systemctl", "list-unit-files", fixture.UNIT]},
                        {"label": "absence-list-unit-files"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                fixture.require_unit_file_absence(self.reply(**changes))

    def test_present_unit_is_refused_before_creation(self):
        raw = b'a(ss) 1 "/etc/systemd/system/trnmponpublic.slice" "enabled"\n'
        row = self.rejected_create(self.capture(stdout=raw))
        self.assertEqual(row["returncode"], 0)
        self.assertEqual(row["stdout"], raw.decode())

    def test_silent_nonzero_query_is_retained_and_not_absence(self):
        row = self.rejected_create(self.capture(code=1, stdout=b""))
        self.assertEqual((row["returncode"], row["stdout"], row["stderr"], row["error"]), (1, "", "", None))

    def test_unsupported_method_is_retained_and_rejected(self):
        row = self.rejected_create(self.capture(code=1, stderr=b"Call failed: Unknown method ListUnitFilesByPatterns\n"))
        self.assertEqual(row["returncode"], 1)
        self.assertIn("Unknown method", row["stderr"])

    def test_query_capture_timeout_is_retained_and_rejected(self):
        row = self.rejected_create(subprocess.TimeoutExpired(fixture.unit_file_absence_command(), 30))
        self.assertIsNone(row["returncode"])
        self.assertIn("timed out", row["error"])

    def test_typed_empty_query_reaches_only_mocked_creation_boundary(self):
        original = self.owner.command
        def command(label, argv):
            if label == "create-owned-runtime-unit":
                self.assertEqual(argv, fixture.transient_unit_command(self.owner.description))
                raise RuntimeError("synthetic creation boundary; no host operation")
            return original(label, argv)
        loaded = subprocess.CompletedProcess(fixture.loaded_unit_absence_command(), 0, b"", b"")
        with patch.object(fixture, "host_capability", return_value=self.capability), \
             patch.object(fixture.os.path, "lexists", return_value=False), \
             patch.object(fixture.subprocess, "run", side_effect=[loaded, self.capture()]) as process, \
             patch.object(self.owner, "command", side_effect=command), \
             self.assertRaisesRegex(RuntimeError, "synthetic creation boundary"):
            self.owner.create()
        self.assertEqual(process.call_count, 2)
        self.assertTrue(self.owner.creation_attempted)
        self.assertFalse(self.owner.started_by_fixture)
        fixture.require_unit_file_absence(self.owner.commands[1])


class OwnershipControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "trnmponpublic.slice"
        self.output = self.root / "output"
        self.output.mkdir()
        self.scope = patch.object(fixture, "PARENT", self.parent)
        self.scope.start()
        self.addCleanup(self.scope.stop)
        self.owner = fixture.Owner(self.output)
        self.calls = []

    def manager(self, *, foreign=False):
        return {"Description": "foreign" if foreign else self.owner.description, "Transient": "yes",
                "ControlGroup": "/trnmponpublic.slice", "ActiveState": "active", "InvocationID": "b" * 32}

    def command(self, label, argv):
        self.calls.append((label, argv))
        if label == "cleanup-inspect-loaded-name":
            return fixture.UNIT + " loaded active active synthetic\n"
        if label == "inspect-owned-unit":
            return "".join(k + "=" + v + "\n" for k, v in self.manager().items())
        if label == "stop-only-owned-runtime-unit":
            for child in self.parent.iterdir():
                child.unlink()
            self.parent.rmdir()
            return ""
        raise AssertionError("unexpected synthetic manager command: " + label)

    def partial(self):
        self.owner.creation_attempted = True
        self.parent.mkdir()
        for name, value in (("cgroup.procs", ""), ("cgroup.threads", ""), ("cgroup.events", "populated 0\n"),
                            ("pids.current", "0\n")):
            (self.parent / name).write_text(value)

    def cleanup(self):
        with patch.object(self.owner, "command", side_effect=self.command):
            original = fixture.identity
            with patch.object(fixture, "identity", side_effect=lambda info: {**original(info), "uid": 0, "gid": 0}):
                return self.owner.cleanup()

    def test_no_creation_never_touches_preexisting_assets(self):
        self.parent.mkdir()
        result = self.cleanup()
        self.assertTrue(result["complete"])
        self.assertFalse(result["attempted"])
        self.assertEqual(self.calls, [])
        self.assertTrue(self.parent.is_dir())

    def test_owned_empty_partial_creation_is_cleaned_without_leaf(self):
        self.partial()
        result = self.cleanup()
        self.assertTrue(result["complete"])
        self.assertFalse(self.parent.exists())
        self.assertEqual([c[0] for c in self.calls],
                         ["cleanup-inspect-loaded-name", "inspect-owned-unit", "stop-only-owned-runtime-unit"])

    def test_populated_partial_creation_refuses_stop(self):
        self.partial()
        (self.parent / "cgroup.procs").write_text("123\n")
        result = self.cleanup()
        self.assertFalse(result["complete"])
        self.assertIn("POPULATED", result["error"])
        self.assertTrue(self.parent.exists())
        self.assertNotIn("stop-only-owned-runtime-unit", [c[0] for c in self.calls])

    def test_partial_foreign_child_is_not_removed(self):
        self.partial()
        (self.parent / "foreign").mkdir()
        result = self.cleanup()
        self.assertFalse(result["complete"])
        self.assertTrue((self.parent / "foreign").is_dir())
        self.assertNotIn("stop-only-owned-runtime-unit", [c[0] for c in self.calls])

    def test_replaced_parent_is_not_stopped(self):
        self.partial()
        self.owner.parent_identity = {**fixture.identity(self.parent.stat()), "uid": 0, "gid": 0}
        self.owner.parent_identity["inode"] += 1
        result = self.cleanup()
        self.assertFalse(result["complete"])
        self.assertIn("CHANGED", result["error"])
        self.assertNotIn("stop-only-owned-runtime-unit", [c[0] for c in self.calls])

    def test_foreign_manager_nonce_is_not_adopted(self):
        self.partial()
        original = self.command
        def command(label, argv):
            if label == "inspect-owned-unit":
                self.calls.append((label, argv))
                return "".join(k + "=" + v + "\n" for k, v in self.manager(foreign=True).items())
            return original(label, argv)
        with patch.object(self.owner, "command", side_effect=command):
            result = self.owner.cleanup()
        self.assertFalse(result["complete"])
        self.assertIn("IDENTITY", result["error"])
        self.assertNotIn("stop-only-owned-runtime-unit", [c[0] for c in self.calls])

    def test_create_refuses_existing_parent_before_any_manager_call(self):
        capability = {"euid": 0, "github_actions": "true", "runner_environment": "github-hosted",
                      "systemd_present": True, "cgroup_root_writable": True, "fixed_parent_exists": True}
        with patch.object(fixture, "host_capability", return_value=capability), \
             patch.object(self.owner, "command") as command, self.assertRaisesRegex(ValueError, "EXISTING_PARENT"):
            self.owner.create()
        command.assert_not_called()
        self.assertFalse(self.owner.creation_attempted)


class BindingControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in fixture.core_binding_paths():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"" if name.endswith(".log") else b"{}\n")

    def test_empty_original_streams_are_retained(self):
        result = fixture.bind_files(self.root, fixture.PHASES)
        self.assertTrue(result["complete"])
        empty = [r for r in result["files"] if r["path"].endswith(".log")]
        self.assertTrue(empty)
        self.assertTrue(all(r["bytes"] == 0 and r["sha256"] == hashlib.sha256(b"").hexdigest() for r in empty))

    def test_missing_file_stays_incomplete_and_other_rows_remain(self):
        (self.root / "context.json").unlink()
        result = fixture.bind_files(self.root, fixture.PHASES)
        self.assertFalse(result["complete"])
        self.assertIsNotNone(result["files"][0]["error"])
        self.assertTrue(any(r["path"] == "source-after.json" and r["error"] is None for r in result["files"]))

    def test_symlink_is_never_followed(self):
        victim = self.root / "context.json"
        victim.unlink()
        victim.symlink_to(self.root / "source-before.json")
        result = fixture.bind_files(self.root, fixture.PHASES)
        self.assertFalse(result["complete"])
        self.assertIsNotNone(result["files"][0]["error"])

    def test_total_byte_bound_is_independent_of_per_file_bound(self):
        with patch.object(fixture, "CAPTURE_LIMIT", 5):
            result = fixture.bind_files(self.root, fixture.PHASES)
        self.assertFalse(result["complete"])
        self.assertTrue(any("TOTAL_BOUND" in (r["error"] or "") for r in result["files"]))


if __name__ == "__main__":
    unittest.main()
