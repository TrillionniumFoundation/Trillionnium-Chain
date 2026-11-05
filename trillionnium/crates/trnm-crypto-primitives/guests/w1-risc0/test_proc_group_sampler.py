"""Small parser/identity controls and actual bounded process-lifecycle checks."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from proc_group_sampler import ProcGroupSampler, parse_hwm, parse_stat

EVIDENCE_OUT = None  # An external test driver may retain the real short-run files.


def stat_bytes(pid, *, group=100, session=100, start=1000, user=3, system=2,
               rss=4, children_user=90000, children_system=80000):
    fields = [b"0"] * 22
    fields[0] = b"S"
    for index, value in [(2, group), (3, session), (11, user), (12, system),
                         (13, children_user), (14, children_system),
                         (19, start), (21, rss)]:
        fields[index] = str(value).encode()
    return str(pid).encode() + b" (discarded ) name (\n) " + b" ".join(fields) + b"\n"


class ParserAndIdentityControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.groups = {}
        self.sessions = {}
        (self.root / "self").mkdir()
        (self.root / "self/stat").write_bytes(stat_bytes(
            os.getpid(), group=os.getpgid(0), session=os.getsid(0)))

    def process(self, pid, children=(), **values):
        root = self.root / str(pid)
        self.groups[pid] = values.get("group", 100)
        self.sessions[pid] = values.get("session", 100)
        (root / "task" / str(pid)).mkdir(parents=True, exist_ok=True)
        (root / "stat").write_bytes(stat_bytes(pid, **values))
        (root / "status").write_bytes(b"VmHWM:\t64 kB\n")
        (root / "task" / str(pid) / "children").write_text(" ".join(map(str, children)))

    def sampler(self):
        def lookup(mapping, pid):
            if pid not in mapping:
                raise ProcessLookupError(pid)
            return mapping[pid]
        return ProcGroupSampler(100, io.StringIO(), proc_root=self.root,
                                ticks_per_second=100, page_bytes=4096,
                                group_lookup=lambda pid: lookup(self.groups, pid),
                                session_lookup=lambda pid: lookup(self.sessions, pid))

    def test_stat_framing_and_self_ticks_exclude_names_and_child_cpu(self):
        value = parse_stat(stat_bytes(100))
        self.assertEqual(value["user_ticks"], 3)
        self.assertEqual(value["system_ticks"], 2)
        self.assertNotIn("comm", value)
        self.assertNotIn("children_user", value)
        self.assertEqual(parse_hwm(b"VmHWM: 7 kB\n"), 7168)
        self.assertIsNone(parse_hwm(b"State: Z\n"))
        for bad in [b"truncated", stat_bytes(100, user=-1)]:
            with self.assertRaises(ValueError):
                parse_stat(bad)

    def test_only_owned_members_count_and_repeated_samples_do_not_double_count(self):
        self.process(100, children=(101, 101, 102))
        self.process(101, start=1001, user=11, system=5, rss=8)
        self.process(102, group=200, session=200, user=999999)
        # Reading this foreign member's status would produce a parse error.
        (self.root / "102/status").write_bytes(b"VmHWM: not_a_number kB\n")
        sampler = self.sampler()
        first = sampler.sample("started")
        self.assertEqual({value["pid"] for value in first["observations"]}, {100, 101})
        self.assertEqual(first["sampled_sum_rss_bytes"], 12 * 4096)
        self.process(101, start=1001, user=15, system=5, rss=6)
        sampler.sample("periodic")
        summary = sampler.summary()
        self.assertAlmostEqual(summary["observed_self_user_cpu_seconds_lower_bound"], 0.18)
        self.assertAlmostEqual(summary["observed_self_system_cpu_seconds_lower_bound"], 0.07)
        self.assertEqual(summary["partial_read_errors"], 0)
        self.assertEqual(summary["maximum_sampled_sum_rss_bytes"], 12 * 4096)

    def test_pid_reuse_has_a_distinct_identity_and_exit_retains_last_actual_data(self):
        self.process(100, children=(101,))
        self.process(101, start=1001, user=11)
        sampler = self.sampler()
        sampler.sample("started")
        self.process(101, start=2000, user=1)
        sampler.sample("periodic")
        self.assertEqual(sampler.summary()["observed_process_identities"], 3)
        self.assertAlmostEqual(sampler.summary()["observed_self_user_cpu_seconds_lower_bound"], 0.15)
        shutil.rmtree(self.root / "100")
        self.process(101, start=3000, user=999999)
        final = sampler.sample("terminated_timeout", after_exit=True)
        self.assertEqual(final["observations"], [])
        self.assertIsNone(final["sampled_sum_rss_bytes"])
        self.assertAlmostEqual(sampler.summary()["observed_self_user_cpu_seconds_lower_bound"], 0.15)
        self.assertEqual(len(sampler.summary()["last_observed_processes"]), 3)

    def test_missing_proc_identity_is_unavailable_not_zero_cost(self):
        sampler = self.sampler()
        sampler.sample("started")
        summary = sampler.summary()
        self.assertFalse(summary["leader_identity_available"])
        self.assertIsNone(summary["observed_self_user_cpu_seconds_lower_bound"])
        self.assertIsNone(summary["maximum_sampled_sum_rss_bytes"])

    def test_namespace_mismatch_or_unavailable_self_refuses_target_resource_reads(self):
        self.process(100, user=999999)
        own = self.root / "self/stat"
        cases = [
            stat_bytes(os.getpid() + 1, group=os.getpgid(0), session=os.getsid(0)),
            stat_bytes(os.getpid(), group=os.getpgid(0) + 1, session=os.getsid(0)),
            stat_bytes(os.getpid(), group=os.getpgid(0), session=os.getsid(0) + 1),
            b"truncated",
            None,
        ]
        for value in cases:
            with self.subTest(value=value):
                if value is None:
                    own.unlink()
                else:
                    own.write_bytes(value)
                with mock.patch.object(ProcGroupSampler, "_stat", side_effect=AssertionError(
                        "numeric target resource read before namespace identity matches")):
                    sampler = self.sampler()
                    sampler.sample("started")
                    sampler.sample("exit_observed", after_exit=True)
                summary = sampler.summary()
                self.assertFalse(summary["proc_self_identity_verified"])
                self.assertIsNotNone(summary["namespace_unavailable_reason"])
                self.assertFalse(summary["leader_identity_available"])
                self.assertEqual(summary["observed_process_identities"], 0)
                self.assertIsNone(summary["observed_self_user_cpu_seconds_lower_bound"])
                self.assertIsNone(summary["observed_self_system_cpu_seconds_lower_bound"])
                self.assertIsNone(summary["maximum_sampled_sum_rss_bytes"])


class ActualProcessControls(unittest.TestCase):
    def run_case(self, name, timeout, program, sampled):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, str(Path(__file__).with_name("measure_step.py")),
                       "--out", directory, "--name", name, "--timeout", str(timeout)]
            if sampled:
                command.append("--sample-proc-group")
            command.extend(["--", sys.executable, "-c", program])
            actual = subprocess.run(command, capture_output=True, text=True, timeout=35)
            root = Path(directory)
            report = json.loads((root / f"{name}.process.json").read_text())
            samples = (root / f"{name}.proc-group.jsonl")
            lines = [json.loads(line) for line in samples.read_text().splitlines()] if samples.exists() else []
            stdout = (root / f"{name}.stdout.log").read_text()
            if EVIDENCE_OUT is not None:
                destination = Path(EVIDENCE_OUT) / name
                destination.mkdir(parents=True, exist_ok=False)
                for source in root.iterdir():
                    shutil.copyfile(source, destination / source.name)
            return actual, report, lines, stdout

    def test_optional_flag_preserves_default_and_normal_exit_last_sample(self):
        actual, report, samples, _ = self.run_case("default", 5, "pass", False)
        self.assertEqual(actual.returncode, 0)
        self.assertNotIn("proc_group_sampling", report)
        self.assertEqual(samples, [])
        actual, report, samples, _ = self.run_case("normal", 5, "import time; time.sleep(0.1)", True)
        self.assertEqual(actual.returncode, 0)
        self.assertEqual(samples[-1]["event"], "exit_observed")
        self.assertTrue(report["proc_group_sampling"]["proc_self_identity_verified"])
        self.assertGreaterEqual(len(report["proc_group_sampling"]["last_observed_processes"]), 1)

    def test_real_grandchild_is_sampled_before_timeout_without_child_cpu_double_count(self):
        worker = "import time\nend=time.process_time()+0.1\nwhile time.process_time()<end: pass\ntime.sleep(60)"
        parent = ("import subprocess,sys,json\np=subprocess.Popen([sys.executable,'-c',"
                  + repr(worker) + "])\nprint(json.dumps({'owned_test_child_pid':p.pid}),flush=True)\np.wait()")
        actual, report, samples, stdout = self.run_case("timeout", 16, parent, True)
        self.assertEqual(actual.returncode, 124)
        self.assertTrue(report["timed_out"])
        self.assertEqual(report["returncode"], 124)
        child_pid = json.loads(stdout)["owned_test_child_pid"]
        summary = report["proc_group_sampling"]
        records = summary["last_observed_processes"]
        self.assertIn(child_pid, {value["pid"] for value in records})
        self.assertIn("periodic", {value["event"] for value in samples})
        self.assertEqual(samples[-1]["event"], "terminated_timeout")
        self.assertTrue(all(value["process_group_id"] == summary["process_group_id"]
                            and value["session_id"] == summary["process_group_id"] for value in records))
        expected = sum(value["maximum_observed_user_ticks"] for value in records) / summary["clock_ticks_per_second"]
        expected_system = sum(value["maximum_observed_system_ticks"] for value in records) / summary["clock_ticks_per_second"]
        self.assertEqual(summary["observed_self_user_cpu_seconds_lower_bound"], expected)
        self.assertEqual(summary["observed_self_system_cpu_seconds_lower_bound"], expected_system)
        self.assertGreater(expected + expected_system, 0.05)
        self.assertIsNotNone(summary["last_sample"])


if __name__ == "__main__":
    unittest.main()
