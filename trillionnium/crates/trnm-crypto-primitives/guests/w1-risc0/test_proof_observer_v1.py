"""Short real subprocess/pipe boundary controls, never a W1 proof or cost claim."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import proof_observer_v1 as observer

HERE = Path(__file__).resolve().parent
PYTHON = str(Path(sys.executable).resolve())


@unittest.skipUnless(sys.platform == "linux", "Linux observer controls")
class ProcessBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.case = 0

    def run_owner(self, program, *, timeout=2.0, caps=None, backend=None, phases=False, preexisting=None, setup=""):
        self.case += 1
        out = self.root / str(self.case)
        if preexisting is not None:
            out.mkdir()
            (out / "prove.stdout.log").write_bytes(preexisting)
        command = [PYTHON, "-c", program]
        if backend is not None:
            command.append(str(Path(backend).resolve()))
        parameters = {"backend_index": 3 if backend is not None else None,
                      "require_phases": phases, "sample_interval": 0.05}
        if caps is not None:
            parameters["stream_caps"] = caps
        # Subreaper state and wait4 ownership live only in this dedicated fresh
        # interpreter. The unittest parent is never made a subreaper/reaper.
        code = ("import sys,json;sys.dont_write_bytecode=True;"
                "sys.path.insert(0,sys.argv[1]);import proof_observer_v1 as o;"
                "exec(sys.argv[6]);"
                "r=o.run_observed(json.loads(sys.argv[2]),sys.argv[3],float(sys.argv[4]),"
                "**json.loads(sys.argv[5]));print(r['returncode'])")
        process = subprocess.run([PYTHON, "-B", "-c", code, str(HERE), json.dumps(command),
                                  str(out), str(timeout), json.dumps(parameters), setup],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        return out, json.loads((out / "prove.observer.json").read_text())

    def test_actual_stdout_json_and_wait4_remain_separate(self):
        out, report = self.run_owner('print("{\\\"synthetic_only\\\":true}")')
        self.assertEqual(report["returncode"], 0)
        self.assertEqual(json.loads((out / "prove.stdout.log").read_text()), {"synthetic_only": True})
        self.assertEqual(report["direct_wait4"]["pid"], report["leader_pid"])
        self.assertEqual(report["leader_exit_observation"]["pid"], report["leader_pid"])
        self.assertFalse(report["family_capture_complete"])
        self.assertIsNone(report["complete_family_cpu_seconds"])
        self.assertFalse(report["proof_qualification"])

    def test_actual_nonzero_preserves_original_error_bytes(self):
        out, report = self.run_owner('import os;os.write(2,b"synthetic-primary-failure\\n");raise SystemExit(7)')
        self.assertEqual(report["returncode"], 7)
        self.assertEqual(report["direct_wait4"]["returncode"], 7)
        self.assertEqual((out / "prove.stderr.log").read_bytes(), b"synthetic-primary-failure\n")

    def test_timeout_retains_partial_output_and_one_direct_reap(self):
        out, report = self.run_owner('import os,time;os.write(1,b"before-timeout\\n");time.sleep(60)', timeout=0.3)
        self.assertEqual(report["returncode"], 124)
        self.assertTrue(report["timed_out"])
        self.assertEqual((out / "prove.stdout.log").read_bytes(), b"before-timeout\n")
        pids = [report["direct_wait4"]["pid"], *[row["pid"] for row in report["adopted_wait4"]]]
        self.assertEqual(len(pids), len(set(pids)))
        self.assertEqual(report["direct_wait4"]["returncode"], -9)

    def test_output_cap_fails_and_preserves_exact_prefix(self):
        caps = dict(observer.STREAM_CAPS, stdout=512)
        out, report = self.run_owner('import os;os.write(1,b"a"*10000)', caps=caps)
        self.assertNotEqual(report["returncode"], 0)
        self.assertEqual(report["failure"], "stdout-output-limit")
        self.assertEqual((out / "prove.stdout.log").read_bytes(), b"a" * 512)
        self.assertTrue(report["streams"]["stdout"]["truncated"])

    def test_exited_leader_descendant_holding_pipe_is_cleaned_before_reap(self):
        program = ('import subprocess,sys;'
                   'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
                   'print(p.pid,flush=True)')
        out, report = self.run_owner(program)
        descendant = int((out / "prove.stdout.log").read_text())
        self.assertEqual(report["returncode"], 0)
        self.assertFalse(report["timed_out"])
        self.assertEqual([row["pid"] for row in report["adopted_wait4"]], [descendant])
        self.assertEqual(report["adopted_wait4"][0]["returncode"], -9)
        self.assertEqual(report["final_group_signal"], "SIGKILL")

    def test_closed_pipes_do_not_make_live_descendant_disappear(self):
        program = ('import subprocess,sys;'
                   'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],'
                   'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                   'print(p.pid,flush=True)')
        out, report = self.run_owner(program)
        descendant = int((out / "prove.stdout.log").read_text())
        self.assertEqual(report["returncode"], 0)
        self.assertIn(descendant, [row["pid"] for row in report["adopted_wait4"]])
        self.assertFalse(report["family_capture_complete"])

    def test_sdk_version_protocol_and_port_logs_use_distinct_streams(self):
        echo = str(Path(shutil.which("echo")).resolve())
        expected = subprocess.check_output([echo, "--version"])
        program = ('import subprocess,sys,json,hashlib;'
                   'v=subprocess.check_output([sys.argv[1],"--version"],close_fds=False);'
                   'p=subprocess.Popen([sys.argv[1],"--port","1234"],close_fds=False);'
                   'assert p.wait()==0;'
                   'print(json.dumps({"synthetic_version_sha":hashlib.sha256(v).hexdigest()}))')
        out, report = self.run_owner(program, backend=echo)
        self.assertEqual(report["returncode"], 0, report)
        self.assertEqual(json.loads((out / "prove.stdout.log").read_text()),
                         {"synthetic_version_sha": hashlib.sha256(expected).hexdigest()})
        self.assertEqual((out / "prove.backend-stdout.log").read_bytes(), b"--port 1234\n")
        self.assertEqual((out / "prove.backend-stderr.log").read_bytes(), b"")
        self.assertEqual(report["backend_before"], report["backend_after"])
        for pipe in report["backend_pipes"].values():
            self.assertEqual(pipe["read"]["inode"], pipe["write"]["inode"])

    def test_backend_cap_is_failure_and_does_not_block_pipe_until_timeout(self):
        echo = str(Path(shutil.which("echo")).resolve())
        caps = dict(observer.STREAM_CAPS, **{"backend-stdout": 1})
        program = ('import subprocess,sys;'
                   'p=subprocess.Popen([sys.argv[1],"--port","1234"],close_fds=False);p.wait()')
        out, report = self.run_owner(program, backend=echo, caps=caps)
        self.assertEqual(report["failure"], "backend-stdout-output-limit")
        self.assertFalse(report["timed_out"])
        self.assertEqual((out / "prove.backend-stdout.log").read_bytes(), b"-")

    def test_shim_rejects_other_protocol_even_with_successful_backend(self):
        echo = str(Path(shutil.which("echo")).resolve())
        program = ('import subprocess,sys;'
                   'p=subprocess.Popen([sys.argv[1],"--rpc"],close_fds=False);raise SystemExit(p.wait())')
        out, report = self.run_owner(program, backend=echo)
        self.assertEqual(report["direct_wait4"]["returncode"], 125)
        self.assertEqual((out / "prove.stderr.log").read_bytes(), b"proof observer shim rejected invocation\n")
        self.assertEqual((out / "prove.backend-stdout.log").read_bytes(), b"")

    def test_successful_child_without_required_host_journal_is_not_observer_success(self):
        out, report = self.run_owner('print("{}")', phases=True)
        self.assertEqual(report["direct_wait4"]["returncode"], 0)
        self.assertEqual(report["returncode"], 125)
        self.assertEqual(report["failure"], "host-phases-incomplete")
        self.assertEqual(report["host_phases"]["status"], "missing")

    def test_original_proof_profile_is_required_before_output_creation(self):
        command = ["/trusted/trnm-w1-risc0-host", "prove", "/trusted/r0vm", "guest", "input", "18", "receipt"]
        for name, timeout, changed in (("execute", 5400, command), ("prove", 5401, command),
                                       ("prove", 5399, command),
                                       ("prove", 5400, command[:5] + ["19", "receipt"])):
            out = self.root / "must-not-exist"
            with self.subTest(name=name, timeout=timeout, command=changed), self.assertRaises(observer.ObservationError):
                observer.observed_prove(changed, out, name, timeout)
            self.assertFalse(out.exists())

    def test_existing_raw_is_not_overwritten_or_relabelled_as_our_capture(self):
        out, report = self.run_owner('print("must not execute")', preexisting=b"original-sentinel")
        self.assertEqual(report["returncode"], 125)
        self.assertIsNone(report["direct_wait4"])
        self.assertEqual(report["streams"], {})
        self.assertEqual((out / "prove.stdout.log").read_bytes(), b"original-sentinel")

    def test_output_io_failure_still_reaps_child_and_writes_failure_receipt(self):
        for operation in ("write", "flush", "close"):
            setup = '''
import errno
original_open = o.Path.open
class FailedOutput:
    def __init__(self, stream): self.stream = stream
    def __getattr__(self, name): return getattr(self.stream, name)
    def write(self, data):
        if OP == 'write': raise OSError(errno.ENOSPC, 'synthetic-output-failure')
        return self.stream.write(data)
    def flush(self):
        if OP == 'flush': raise OSError(errno.ENOSPC, 'synthetic-output-failure')
        return self.stream.flush()
    def close(self):
        self.stream.close()
        if OP == 'close': raise OSError(errno.EIO, 'synthetic-close-failure')
def changed_open(path, *args, **kwargs):
    stream = original_open(path, *args, **kwargs)
    return FailedOutput(stream) if path.name == 'prove.stdout.log' else stream
o.Path.open = changed_open
'''.replace("OP", repr(operation))
            with self.subTest(operation=operation):
                _, report = self.run_owner('print("original-output")', setup=setup)
                self.assertEqual(report["returncode"], 125)
                self.assertIsNotNone(report["direct_wait4"])
                self.assertTrue(report["finite_cleanup_observed"])
                self.assertIsNotNone(report["failure"])

    def test_adopted_row_cap_is_incomplete_cleanup_even_when_leader_succeeds(self):
        # Fault-injected wait4 exhaustion tests the finite report bound. These
        # synthetic rows are explicitly not native family/cost observations.
        setup = '''
real_wait4 = o.wait4_row
counter = 0
def many_rows(pid, options):
    global counter
    if pid != -1: return real_wait4(pid, options)
    counter += 1
    return {'pid': 1000000 + counter, 'synthetic_only': True}
o.wait4_row = many_rows
'''
        _, report = self.run_owner('print("{}")', setup=setup)
        self.assertEqual(report["direct_wait4"]["returncode"], 0)
        self.assertEqual(len(report["adopted_wait4"]), 128)
        self.assertFalse(report["finite_cleanup_observed"])
        self.assertEqual(report["failure"], "adopted-cleanup-incomplete")
        self.assertEqual(report["returncode"], 125)


class PhaseBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "phases"
        self.rows = [{"schema": "pon-w1-host-phase-v1", "sequence": number, "pid": 123,
                      "elapsed_ns": number * 100, "event": event, "consensus_authority": False}
                     for number, event in enumerate(observer.PHASES)]

    def write(self, rows):
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def test_full_fixed_sequence_and_failed_prefix_are_distinct(self):
        self.write(self.rows)
        self.assertTrue(observer.phase_readback(self.path, 123)["complete"])
        prefix = deepcopy(self.rows[:4])
        prefix.append(dict(self.rows[4], event="host-failed"))
        self.write(prefix)
        parsed = observer.phase_readback(self.path, 123)
        self.assertFalse(parsed["complete"])
        self.assertEqual(parsed["status"], "parsed")
        self.assertEqual(parsed["events"][-1]["event"], "host-failed")

    def test_wrong_pid_missing_duplicate_backwards_and_boolean_time_fail(self):
        for change in ("pid", "missing", "duplicate", "backwards", "negative-first", "boolean", "after-failure"):
            rows = deepcopy(self.rows)
            if change == "pid":
                rows[3]["pid"] = 124
            elif change == "missing":
                del rows[3]
            elif change == "duplicate":
                rows.insert(3, rows[3])
            elif change == "backwards":
                rows[3]["elapsed_ns"] = 0
            elif change == "boolean":
                rows[0]["elapsed_ns"] = False
            elif change == "negative-first":
                rows[0]["elapsed_ns"] = -1
            else:
                rows[3]["event"] = "host-failed"
            self.write(rows)
            with self.subTest(change=change):
                self.assertFalse(observer.phase_readback(self.path, 123)["complete"])
                self.assertEqual(observer.phase_readback(self.path, 123)["status"], "partial-or-invalid")

    def test_duplicate_json_partial_line_overflow_and_symlink_are_refused(self):
        self.path.write_text(json.dumps(self.rows[0])[:-1] + ',"pid":123}\n')
        self.assertEqual(observer.phase_readback(self.path, 123)["error"], "phase-duplicate-key")
        self.path.write_text(json.dumps(self.rows[0]))
        self.assertFalse(observer.phase_readback(self.path, 123)["complete"])
        self.path.write_bytes(b"x" * (observer.PHASE_CAP + 1))
        with self.assertRaises(observer.ObservationError):
            observer.phase_readback(self.path, 123)
        self.path.unlink()
        self.path.symlink_to("/dev/null")
        with self.assertRaises(OSError):
            observer.phase_readback(self.path, 123)


if __name__ == "__main__":
    unittest.main()
