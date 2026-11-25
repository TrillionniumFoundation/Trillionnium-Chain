"""Readback controls for optional Settlement runner metadata."""
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.tools import settlement_runner_cpu as cpu


class RunnerCpuTests(unittest.TestCase):
    def test_leaf_and_ancestors_without_full_namespace_claim(self):
        with TemporaryDirectory() as folder:
            base = Path(folder)
            leaf = base / "job.scope" / "worker"
            leaf.mkdir(parents=True)
            (leaf / "cpu.max").write_text("max 100000\n")
            (leaf / "cpu.stat").write_text("usage_usec 8\nnr_throttled 2\nthrottled_usec 1\n")
            (leaf.parent / "cpu.max").write_text("50000 100000\n")

            def reader(path, cap):
                fake = {"/proc/self/cgroup": "0::/job.scope/worker\n",
                        "/proc/self/mountinfo":
                        "44 33 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"}
                return fake.get(str(path)) if str(path) in fake else cpu.read(path, cap)

            data = cpu.cgroup(reader, base)
            self.assertEqual(data["availability"], "observed")
            self.assertEqual(data["visible_quota_min"], [50000, 100000])
            self.assertEqual(data["leaf_counters"]["nr_throttled"], 2)
            self.assertTrue(data["visible_quota_chain_complete"])
            self.assertEqual(data["visible_quota_chain"], [[None, 100000], [50000, 100000], None])
            (leaf.parent / "cpu.max").unlink()
            self.assertFalse(cpu.cgroup(reader, base)["visible_quota_chain_complete"])

    def test_no_v2_and_ambiguous_membership_are_unavailable(self):
        for value in ("4:cpu:/job.scope\n", "0::/\n0::/other\n", "0::/../read\n"):
            with self.subTest(value=value):
                self.assertEqual(cpu.cgroup(lambda p, cap: value), {"availability": "unavailable"})

    def test_namespace_mount_prefix_and_unsupported_layout(self):
        mount = "44 33 0:22 /slice /sys/fs/cgroup rw - cgroup2 none rw\n"
        self.assertEqual(cpu.lineage("0::/slice/job\n", mount), (("job",), False))
        for value in ("0::/job\n", "0::/slice/Bad Path\n",
                      "0::/slice/./job\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cpu.lineage(value, mount)

    def test_counter_allowlist_malformed_and_numeric_caps(self):
        self.assertEqual(cpu.counters("usage_usec 12\nfuture_counter 1\n"), {"usage_usec": 12})
        for value in ("usage_usec -1", "usage_usec 2\nusage_usec 3", "wat 5"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cpu.counters(value)
        for value in ("2000 0", "bad 100", "1 2 3", "999999999999999999999 100"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cpu.quota(value)

    def test_caps_and_symlinks_fail_closed(self):
        with TemporaryDirectory() as folder:
            p = Path(folder) / "large"
            p.write_bytes(b"012345")
            with self.assertRaises(ValueError):
                cpu.read(p, 4)
            link = Path(folder) / "link"
            link.symlink_to(p)
            with self.assertRaises(OSError):
                cpu.read(link, 20)

    def test_output_only_real_affinity_and_cpu_model_allowlist(self):
        raw = "processor: 0\nmodel name: Demo CPU @ 2.30GHz\nserial: DO NOT EMIT\n"
        self.assertEqual(cpu.cpu_model(lambda p, cap: raw), ["Demo CPU @ 2.30GHz"])
        self.assertIsNone(cpu.cpu_model(lambda p, cap: "model name: invalid=value"))
        with patch.object(cpu.os, "sched_getaffinity", return_value={5, 7, 1}):
            self.assertEqual(cpu.affinity(), [1, 5, 7])
        with patch.object(cpu.os, "sched_getaffinity", side_effect=OSError):
            self.assertIsNone(cpu.affinity())

    def test_snapshot_rejects_unbound_identifiers_even_if_optimized(self):
        for values in (("unknown", "b" * 40, "1", "1"),
                       ("a" * 40, "b" * 40, "../../1", "1"),
                       ("a" * 40, "b" * 40, "1", "0")):
            with self.assertRaises(ValueError):
                cpu.snapshot("before", *values)

    def test_workflow_keeps_cpu_observations_separate_and_non_gating(self):
        text = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        before = text.index("      - name: Observe Settlement runner CPU before execution")
        execution = text.index("      - name: Execute the complete component and its independent reader")
        after = text.index("      - name: Observe Settlement runner CPU after execution")
        source = text.index("      - name: Recheck every committed source byte after success or failure")
        upload = text.index("      - name: Upload separate optional Settlement runner CPU observations")
        preceding = text.index("      - name: Upload the separate Settlement image identity diagnostic")
        self.assertTrue(before < execution < after < source < preceding < upload)
        for block, phase in ((text[before:execution], "before"),
                             (text[after:source], "after")):
            self.assertIn("matrix.component == 'settlement-engine'", block)
            self.assertIn("continue-on-error: true", block)
            self.assertIn("timeout 2s python3 -B -m hia.tools.settlement_runner_cpu", block)
            self.assertIn("--phase " + phase, block)
            self.assertNotIn("OWNER_ROOT", block)
            self.assertNotIn("OWNER_ARTIFACT", block)
        block = text[upload:].split("\n      - name: ", 1)[0]
        self.assertIn("continue-on-error: true", block)
        self.assertIn("if-no-files-found: ignore", block)
        self.assertIn("/settlement-runner-cpu/before.json", block)
        self.assertIn("/settlement-runner-cpu/after.json", block)
        self.assertNotIn("OWNER_ROOT", block)
        self.assertNotIn("OWNER_ARTIFACT", block)

    def test_cli_live_pair_is_scoped_and_exclusive(self):
        with TemporaryDirectory() as folder:
            cmd = [sys.executable, "-OO", "-B", "-m", "hia.tools.settlement_runner_cpu",
                   "--head", "a" * 40, "--tree", "b" * 40,
                   "--run-id", "8", "--run-attempt", "1", "--output-dir", folder]
            files = []
            for phase in ("before", "after"):
                p = subprocess.run(cmd + ["--phase", phase], check=True, cwd=ROOT,
                                   timeout=3, capture_output=True)
                self.assertEqual(p.stdout, b"")
                f = Path(folder) / (phase + ".json")
                self.assertEqual(f.stat().st_mode & 0o777, 0o600)
                self.assertLess(f.stat().st_size, 8000)
                data = json.loads(f.read_bytes())
                files.append(data)
                self.assertEqual(data["phase"], phase)
                self.assertEqual(data["schema"], cpu.SCHEMA)
                self.assertEqual(data["lineage"], {"head": "a" * 40, "tree": "b" * 40,
                                 "run_id": "8", "run_attempt": "1"})
                self.assertFalse(data["qualifies_execution"])
                self.assertNotIn("_local_identity", f.read_text())
            self.assertLess(files[0]["clock"]["monotonic_ns"], files[1]["clock"]["monotonic_ns"])
            self.assertEqual(files[0]["cgroup_v2"]["same_run_leaf_token"],
                             files[1]["cgroup_v2"]["same_run_leaf_token"])
            p = subprocess.run(cmd + ["--phase", "after"], cwd=ROOT, timeout=3, capture_output=True)
            self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
