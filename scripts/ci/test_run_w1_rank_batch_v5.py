#!/usr/bin/env python3
"""Actual subprocess failures/timeouts for the V5 accounting owner."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import run_w1_rank_batch_v5 as runner
import public_host_ci_observation as host_observation
capture = runner.capture


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "wait4"), "Linux wait4 owner")
class CaptureTests(unittest.TestCase):
    def run_code(self, code, timeout=2):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        observed = capture([sys.executable, "-c", code], root, "run", timeout=timeout, cwd=root)
        return root, observed

    def test_success_retains_both_streams_and_whole_process_cpu(self):
        root, observed = self.run_code("import sys; print('complete'); print('diagnostic', file=sys.stderr); sum(i*i for i in range(300000))")
        self.assertEqual(observed["exit_code"], 0)
        self.assertGreater(observed["wait4_cpu_ns"], 0)
        self.assertGreater(observed["wait4_maxrss_kib"], 0)
        self.assertEqual((root / observed["stdout"]).read_text(), "complete\n")
        self.assertEqual((root / observed["stderr"]).read_text(), "diagnostic\n")
        self.assertFalse(observed["global_cpu_complete"])
        self.assertFalse(observed["global_memory_peak_observed"])

    def test_nonzero_preserves_partial_rows_costs_and_actual_exit(self):
        root, observed = self.run_code("import sys; print('partial', flush=True); sum(i*i for i in range(200000)); sys.exit(7)")
        self.assertEqual((observed["exit_code"], observed["process_exit_code"]), (7, 7))
        self.assertEqual((root / observed["stdout"]).read_text(), "partial\n")
        self.assertGreater(observed["wait4_cpu_ns"], 0)

    def test_timeout_keeps_all_prior_work_and_signal_status(self):
        root, observed = self.run_code("print('before-timeout', flush=True)\nwhile True: pass", timeout=0.15)
        self.assertTrue(observed["timed_out"])
        self.assertEqual(observed["exit_code"], 124)
        self.assertLess(observed["process_exit_code"], 0)
        self.assertGreater(observed["wait4_cpu_ns"], 0)
        self.assertEqual((root / observed["stdout"]).read_text(), "before-timeout\n")

    def test_successful_leader_does_not_leave_a_background_log_writer(self):
        root, observed = self.run_code("import os,time\np=os.fork()\nif p==0:\n time.sleep(0.2)\n open('escaped-output','w').write('late')\n os._exit(0)\nos._exit(0)")
        self.assertEqual(observed["exit_code"], 0)
        time.sleep(0.3)
        self.assertFalse((root / "escaped-output").exists())

    def test_launch_failure_and_existing_logs_are_not_success_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed = capture([str(root / "missing-executable")], root, "run", timeout=1, cwd=root)
            self.assertFalse(observed["executed"])
            self.assertIsNone(observed["exit_code"])
            self.assertIsNone(observed["wait4_cpu_ns"])
            self.assertIn("launch_error", observed)
            with self.assertRaises(FileExistsError):
                capture([sys.executable, "-c", "pass"], root, "run", timeout=1, cwd=root)

    def test_compiler_multicall_symlink_keeps_its_invocation_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "multicall-launcher"
            launcher.write_text("#!/bin/sh\ncase \"$0\" in */rustc) printf 'compiler path preserved\\n';; *) exit 9;; esac\n")
            launcher.chmod(0o755)
            link = root / "rustc"
            link.symlink_to(launcher)
            with patch.object(runner.shutil, "which", return_value=str(link)):
                selected = runner.discover_tool("rustc")
            good = capture([str(selected), "-vV"], root, "kept-name", timeout=2, cwd=root)
            bad = capture([str(selected.resolve()), "-vV"], root, "lost-name", timeout=2, cwd=root)
            self.assertEqual(selected, link)
            self.assertEqual(good["exit_code"], 0)
            self.assertEqual(bad["exit_code"], 9)
            self.assertEqual((root / good["stdout"]).read_text(), "compiler path preserved\n")
            with patch.object(runner.shutil, "which", return_value=None):
                with self.assertRaises(ValueError):
                    runner.discover_tool("rustc")


@unittest.skipUnless(sys.platform == "linux", "Linux cgroup observation controls")
class CurrentCgroupObservationTests(unittest.TestCase):
    """Synthetic namespace files test observations, never Host authority."""
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.mount = self.root / "cgroup"
        self.leaf = self.mount / "a/b"
        self.leaf.mkdir(parents=True)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        for path in (self.mount, self.mount / "a", self.leaf):
            for name in host_observation._CURRENT_LIMITS:
                (path / name).write_text("max\n")
        device = self.mount.stat().st_dev
        self.device = f"{os.major(device)}:{os.minor(device)}"
        self.membership = self.proc / "cgroup"
        self.mountinfo = self.proc / "mountinfo"
        self.membership.write_text("0::/a/b\n")
        self.mountinfo.write_text(self.mount_row())

    def mount_row(self, root="/", filesystem="cgroup2", device=None, point=None, identifier=51):
        encoded = str(point or self.mount).replace("\\", "\\134").replace(" ", "\\040")
        return f"{identifier} 25 {device or self.device} {root} {encoded} rw - {filesystem} cgroup rw\n"

    def observe(self, *, drift=False):
        actual_read = host_observation._current_cgroup_text
        member_reads = 0
        def redirect(path, limit, errors, device=None):
            nonlocal member_reads
            if path == Path("/proc/self/cgroup"):
                path = self.membership
                member_reads += 1
                if drift and member_reads == 2:
                    path.write_text("0::/a\n")
            elif path == Path("/proc/self/mountinfo"):
                path = self.mountinfo
            return actual_read(path, limit, errors, device)
        with patch.object(host_observation, "_current_cgroup_text", side_effect=redirect):
            return host_observation.current_cgroup_observation()

    def assert_unknown_authority(self, observed):
        for key in ("atomic_snapshot", "effective_quota_established",
                    "namespace_external_ancestors_observed", "native_child_membership_verified",
                    "consensus_or_model_authority"):
            self.assertIs(observed[key], False)

    def test_nonroot_membership_observes_actual_leaf_and_each_visible_ancestor(self):
        observed = self.observe()
        self.assertTrue(observed["membership_resolved"])
        self.assertTrue(observed["visible_limits_complete"])
        self.assertEqual(observed["resolved_path"], str(self.leaf))
        self.assertEqual([row["cgroup_path"] for row in observed["visible_ancestors"]],
                         ["/a/b", "/a", "/"])
        self.assertEqual(observed["membership_raw"], "0::/a/b\n")
        self.assert_unknown_authority(observed)

    def test_root_view_cannot_substitute_for_missing_actual_nonroot_group(self):
        for child in self.leaf.iterdir():
            child.unlink()
        self.leaf.rmdir()
        observed = self.observe()
        self.assertFalse(observed["membership_resolved"])
        self.assertFalse(observed["visible_limits_complete"])
        self.assertEqual(observed["visible_ancestors"], [])
        self.assertIn("mapping_error", observed)
        self.assert_unknown_authority(observed)

    def test_subtree_mount_does_not_claim_namespace_external_ancestors(self):
        self.membership.write_text("0::/outer/a/b\n")
        self.mountinfo.write_text(self.mount_row(root="/outer"))
        observed = self.observe()
        self.assertTrue(observed["membership_resolved"])
        self.assertEqual([row["cgroup_path"] for row in observed["visible_ancestors"]],
                         ["/outer/a/b", "/outer/a", "/outer"])
        self.assertEqual(observed["resolved_path"], str(self.leaf))
        self.assert_unknown_authority(observed)

    def test_wrong_unrelated_ambiguous_or_shadowed_mount_cannot_resolve_membership(self):
        minor = os.minor(self.mount.stat().st_dev) ^ 1
        cases = [
            self.mount_row(filesystem="tmpfs"), self.mount_row(root="/unrelated"),
            self.mount_row(device=f"{os.major(self.mount.stat().st_dev)}:{minor}"),
            self.mount_row() + self.mount_row(identifier=52),
            self.mount_row() + self.mount_row(filesystem="tmpfs", identifier=52),
            self.mount_row() + self.mount_row(root="/unrelated", identifier=52),
            self.mount_row() + self.mount_row(filesystem="tmpfs", point=self.leaf, identifier=52),
            self.mount_row() + self.mount_row(filesystem="tmpfs", point=self.leaf / "cpu.max", identifier=52),
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                self.mountinfo.write_text(raw)
                observed = self.observe()
                self.assertFalse(observed["membership_resolved"])
                self.assertFalse(observed["visible_limits_complete"])
                self.assertIn("mapping_error", observed)
                self.assert_unknown_authority(observed)

    def test_noncanonical_overdepth_and_oversized_paths_stay_unresolved(self):
        cases = ["/a/../b", "//a/b", "/a/./b",
                 "/" + "/".join(["x"] * (host_observation._CGROUP_DEPTH_LIMIT + 1)),
                 "/" + "x" * host_observation._CGROUP_PATH_LIMIT,
                 "/" + "x" * host_observation._CGROUP_PROC_LIMIT]
        for path in cases:
            with self.subTest(path_length=len(path)):
                self.membership.write_text("0::" + path + "\n")
                observed = self.observe()
                self.assertFalse(observed["membership_resolved"])
                self.assertFalse(observed["visible_limits_complete"])
                self.assert_unknown_authority(observed)
        self.membership.write_text("0::/a/b\n")
        self.mountinfo.write_text("x" * (host_observation._CGROUP_MOUNT_LIMIT + 1))
        observed = self.observe()
        self.assertFalse(observed["membership_resolved"])
        self.assertTrue(observed["read_errors"])

    def test_failed_limit_read_and_membership_drift_cannot_become_complete(self):
        (self.leaf / "cpu.max").unlink()
        observed = self.observe()
        self.assertTrue(observed["membership_resolved"])
        self.assertFalse(observed["visible_limits_complete"])
        self.assertEqual(observed["status"], "PARTIAL_OBSERVATION")
        self.assertIsNone(observed["visible_ancestors"][0]["limits"]["cpu.max"])
        self.assertTrue(observed["read_errors"])
        self.assert_unknown_authority(observed)
        (self.leaf / "cpu.max").write_text("max\n")
        drifted = self.observe(drift=True)
        self.assertFalse(drifted["membership_resolved"])
        self.assertFalse(drifted["visible_limits_complete"])
        self.assertIn("CONTEXT_CHANGED", drifted["mapping_error"])
        self.assert_unknown_authority(drifted)

    def test_escaped_mount_and_trailing_space_membership_preserve_exact_path(self):
        renamed = self.mount.with_name("cgroup view")
        self.mount.rename(renamed)
        self.mount = renamed
        self.leaf = self.mount / "a/b "
        self.leaf.mkdir()
        for name in host_observation._CURRENT_LIMITS:
            (self.leaf / name).write_text("max\n")
        self.membership.write_text("0::/a/b \n")
        self.mountinfo.write_text(self.mount_row())
        observed = self.observe()
        self.assertTrue(observed["membership_resolved"])
        self.assertEqual(observed["resolved_path"], str(self.leaf))
        self.assertEqual(observed["membership_path"], "/a/b ")
        self.assert_unknown_authority(observed)

    def test_fifo_read_refuses_with_a_bounded_real_child(self):
        # Regression to a blocking FIFO open times out this child, never the suite.
        import json
        import subprocess
        fifo = self.root / "limit-fifo"
        os.mkfifo(fifo)
        code = ("import json,sys; from pathlib import Path; "
                "sys.path.insert(0,sys.argv[1]); import public_host_ci_observation as h; "
                "errors={}; value=h._current_cgroup_text(Path(sys.argv[2]),128,errors); "
                "print(json.dumps({'value':value,'errors':errors}))")
        child = subprocess.run(
            [sys.executable, "-c", code, str(Path(host_observation.__file__).parent), str(fifo)],
            capture_output=True, text=True, timeout=2, check=True)
        observed = json.loads(child.stdout)
        self.assertIsNone(observed["value"])
        self.assertIn("REGULAR_KERNEL_FILE_REQUIRED", observed["errors"][str(fifo)])


if __name__ == "__main__":
    unittest.main()
