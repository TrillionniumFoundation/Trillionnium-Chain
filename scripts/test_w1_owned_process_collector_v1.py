#!/usr/bin/env python3
"""Actual finite Linux-process controls; no proof, resource invoice or payment."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

import w1_owned_process_collector_v1 as collector

SOURCE = Path(collector.__file__).resolve()
PYTHON = Path(sys.executable).resolve()
PYTHON_SHA = hashlib.sha256(PYTHON.read_bytes()).hexdigest()
BOOT = collector.boot_id()


def until_file(path, process=None, seconds=3):
    until = time.monotonic() + seconds
    while not path.exists():
        if process is not None and process.poll() is not None:
            raise AssertionError("control process exited before its actual marker")
        if time.monotonic() >= until:
            raise AssertionError("actual process marker not observed within bound")
        time.sleep(.01)


class CollectorControls(unittest.TestCase):
    def setUp(self):
        kept = os.environ.get("W1_COLLECTOR_CONTROL_ROOT")
        if kept:
            self.root = Path(kept) / self._testMethodName
            self.root.mkdir(parents=True, exist_ok=False)
            self.temporary = None
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix="w1-collector-control-")
            self.root = Path(self.temporary.name)
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        if self.temporary:
            self.temporary.cleanup()

    def argv(self, name, command, *, seconds=5, extra=(), deadline=None):
        out = self.root / name
        deadline = deadline or time.monotonic_ns() + int(seconds * 1e9)
        return [str(PYTHON), str(SOURCE), "--out", str(out), "--deadline-monotonic-ns", str(deadline),
                "--deadline-boot-id", BOOT, "--cleanup-grace-seconds", "2", "--cwd", str(self.root),
                "--executable-sha256", PYTHON_SHA, *extra, "--", *command], out, deadline

    def script(self, text, name="payload.py"):
        path = self.root / name
        path.write_text(text)
        return [str(PYTHON), str(path)]

    def start(self, name, command, **kwargs):
        pass_fds = kwargs.pop("pass_fds", ())
        argv, out, deadline = self.argv(name, command, **kwargs)
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=pass_fds, text=True)
        self.children.append(proc)
        return proc, out, deadline

    def finish(self, proc, out):
        stdout, stderr = proc.communicate(timeout=8)
        completed = time.monotonic_ns()
        observed = {"returncode": proc.returncode, "completed_monotonic_ns": completed, "boot_id": BOOT,
                    "stdout": stdout, "stderr": stderr, "collector_source_sha256": collector.file_digest(SOURCE)}
        (out.parent / (out.name + "-caller-observation.json")).write_text(json.dumps(observed, sort_keys=True))
        result = collector.read_result(out, proc.returncode, observed_boot_id=BOOT,
                                       observed_completed_monotonic_ns=completed)
        return result

    def test_actual_double_fork_new_session_root_exits_before_descendants(self):
        marker = self.root / "grandchild-finished"
        code = "import os,time\nfrom pathlib import Path\n" \
               "if os.fork(): os._exit(0)\nos.setsid()\n" \
               "if os.fork(): os._exit(0)\nos.setsid()\ntime.sleep(.20)\n" \
               f"Path({str(marker)!r}).write_text('actual grandchild finished')\nos._exit(0)\n"
        proc, out, deadline = self.start("collector", self.script(code))
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(marker.exists())
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertTrue(result["command_success"])
        records = result["result"]["wait4_records"]
        self.assertEqual(len(records), 3)
        self.assertTrue(all(row["returncode"] == 0 for row in records))
        self.assertEqual(result["result"]["final_echild"]["errno"], 10)
        self.assertEqual(result["result"]["original_deadline_monotonic_ns"], deadline)
        self.assertIsNone(result["gpu_ns"])
        self.assertFalse(result["resource_billing_complete"])

    def test_actual_internal_popen_status_and_external_sibling_are_preserved(self):
        sibling = subprocess.Popen([str(PYTHON), "-c", "import time,sys;time.sleep(.1);sys.exit(29)"])
        self.children.append(sibling)
        code = f"import subprocess,sys\np=subprocess.Popen([{str(PYTHON)!r},'-c','import sys;sys.exit(37)'])\nprint(p.wait(),flush=True)\nsys.exit(23)\n"
        proc, out, _ = self.start("collector", self.script(code))
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 23)
        self.assertEqual(sibling.wait(timeout=3), 29)
        self.assertEqual((out / "stdout.log").read_text().strip(), "37")
        self.assertEqual([row["returncode"] for row in result["result"]["wait4_records"]], [23])
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertFalse(result["command_success"])

    def test_actual_root_signal_is_not_translated_to_success(self):
        proc, out, _ = self.start("collector", self.script("import os,signal\nos.kill(os.getpid(),signal.SIGTERM)\n"))
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, -signal.SIGTERM)
        self.assertEqual(result["result"]["root_returncode"], -signal.SIGTERM)
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertFalse(result["command_success"])

    def long_tree(self):
        marker = self.root / "running"
        text = "import os,signal,time\nfrom pathlib import Path\n" \
               "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n" \
               "if os.fork(): os._exit(0)\nos.setsid()\n" \
               "if os.fork(): os._exit(0)\nos.setsid()\n" \
               f"Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(3)\n"
        return self.script(text), marker

    def test_actual_cancel_reaps_detached_ignoring_descendant(self):
        command, marker = self.long_tree()
        proc, out, _ = self.start("collector", command)
        until_file(marker, proc, seconds=5)
        proc.send_signal(signal.SIGTERM)
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM)
        self.assertEqual(result["result"]["cause"], "cancelled")
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertFalse(result["command_success"])
        self.assertIn(-signal.SIGKILL, [r["returncode"] for r in result["result"]["wait4_records"]])

    def test_actual_original_timeout_reaps_after_root_has_exited(self):
        command, marker = self.long_tree()
        proc, out, deadline = self.start("collector", command, seconds=.35)
        until_file(marker, proc)
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 124)
        self.assertEqual(result["result"]["cause"], "original-deadline")
        self.assertEqual(result["result"]["root_returncode"], 0)
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertFalse(result["deadline_qualified"])
        self.assertFalse(result["command_success"])
        self.assertGreaterEqual(result["result"]["completed_monotonic_ns"], deadline)

    def guarded(self, mode):
        marker = self.root / "payload-identity.json"
        command = self.script("import os,time,signal,json\nfrom pathlib import Path\n"
                              "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                              "raw=Path('/proc/self/stat').read_text();tail=raw[raw.rfind(')')+2:].split()\n"
                              f"Path({str(marker)!r}).write_text(json.dumps({{'pid':os.getpid(),'start_ticks':int(tail[19]),'boot_id':{BOOT!r}}}))\n"
                              "time.sleep(3)\n")
        argv, out, _ = self.argv("collector", command)
        helper = self.root / "guard.py"
        helper.write_text('''import ctypes,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import w1_owned_process_collector_v1 as c
c.enable_subreaper()
mode=sys.argv[2];argv=json.loads(sys.argv[3]);marker=Path(sys.argv[4]);output=Path(sys.argv[5])
def wait_marker():
 until=time.monotonic()+3
 while not marker.exists():
  if time.monotonic()>=until:raise RuntimeError('guard marker timeout')
  time.sleep(.01)
if mode=='kill':
 p=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 wait_marker();p.kill();code=p.wait(timeout=3)
 who=json.loads(marker.read_text());fd=c.stable_pidfd(who,c.boot_id())
 try:signal.pidfd_send_signal(fd,signal.SIGKILL)
 finally:os.close(fd)
 waited,status,usage=os.wait4(who['pid'],0)
 output.write_text(json.dumps({'collector_returncode':code,'completed_monotonic_ns':time.monotonic_ns(),
                              'orphan_reaped_by_guard':waited,'orphan_status':status}))
else:
 launch=Path(sys.argv[6]);pidpath=output.with_suffix('.pid')
 launch.write_text('import subprocess,os,time\\nfrom pathlib import Path\\n'
                  +'p=subprocess.Popen('+repr(argv)+',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\\n'
                  +'Path('+repr(str(pidpath))+').write_text(str(p.pid))\\n'
                  +'end=time.monotonic()+3\\n'
                  +'while not Path('+repr(str(marker))+').exists() and time.monotonic()<end: time.sleep(.01)\\n'
                  +'os._exit(0)\\n')
 owner=subprocess.Popen([sys.executable,str(launch)])
 wait_marker();owner_code=owner.wait(timeout=3)
 pid=int(pidpath.read_text());waited,status,usage=os.wait4(pid,0)
 output.write_text(json.dumps({'owner_returncode':owner_code,'collector_returncode':os.waitstatus_to_exitcode(status),
                              'completed_monotonic_ns':time.monotonic_ns(),'collector_reaped_by_guard':waited}))
''')
        evidence = self.root / "guard-observation.json"
        guard = subprocess.run([str(PYTHON), str(helper), str(SOURCE.parent), mode, json.dumps(argv),
                                str(marker), str(evidence), str(self.root / "lost-owner.py")],
                               capture_output=True, text=True, timeout=8)
        self.assertEqual(guard.returncode, 0, guard.stderr)
        observed = json.loads(evidence.read_text())
        return out, observed

    def test_actual_owner_lost_is_cleaned_without_treating_successful_root_as_success(self):
        out, observed = self.guarded("owner-lost")
        result = collector.read_result(out, observed["collector_returncode"], observed_boot_id=BOOT,
                                       observed_completed_monotonic_ns=observed["completed_monotonic_ns"])
        self.assertEqual(observed["owner_returncode"], 0)
        self.assertEqual(observed["collector_returncode"], 125)
        self.assertEqual(result["result"]["cause"], "owner-lost")
        self.assertTrue(result["collector_wait_domain_reaped"])
        self.assertFalse(result["command_success"])

    def test_actual_collector_sigkill_is_unknown_even_after_guard_reaps_orphan(self):
        out, observed = self.guarded("kill")
        self.assertEqual(observed["collector_returncode"], -signal.SIGKILL)
        self.assertTrue((out / "intent.json").exists())
        self.assertFalse((out / "result.json").exists())
        result = collector.read_result(out, observed["collector_returncode"], observed_boot_id=BOOT,
                                       observed_completed_monotonic_ns=observed["completed_monotonic_ns"])
        self.assertEqual(result["terminal_state"], "unknown")
        self.assertFalse(result["collector_wait_domain_reaped"])
        self.assertFalse(result["can_authorize_payment"])

    def test_actual_output_limit_is_bounded_and_fails_without_losing_root_status(self):
        code = "import os,time\nos.write(1,b'x'*8192)\ntime.sleep(3)\n"
        proc, out, _ = self.start("collector", self.script(code), extra=("--max-log-bytes", "1024"))
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 125)
        self.assertEqual(result["result"]["cause"], "output-limit")
        self.assertEqual((out / "stdout.log").stat().st_size, 1024)
        self.assertTrue(result["result"]["streams"]["stdout"]["truncated"])
        self.assertTrue(result["collector_wait_domain_reaped"])

    def test_actual_exec_closes_inherited_fd_and_rejects_direct_shebang(self):
        inherited = (self.root / "must-not-survive-exec").open("w")
        try:
            code = "import os,json\nvalues=[]\nfor name in os.listdir('/proc/self/fd'):\n try: values.append(os.readlink('/proc/self/fd/'+name))\n except FileNotFoundError: pass\nprint(json.dumps(values))\n"
            proc, out, _ = self.start("collector", self.script(code), pass_fds=(inherited.fileno(),))
            result = self.finish(proc, out)
        finally:
            inherited.close()
        self.assertTrue(result["command_success"])
        names = json.loads((out / "stdout.log").read_text())
        self.assertFalse(any("must-not-survive-exec" in name or "events.jsonl" in name or "anon_inode" in name for name in names))
        script = self.root / "direct-script"
        script.write_text("#!/bin/sh\necho should-not-execute\n")
        script.chmod(0o755)
        argv, rejected, _ = self.argv("shebang", [str(script)])
        argv[argv.index("--executable-sha256") + 1] = collector.file_digest(script)
        run = subprocess.run(argv, capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 125)
        self.assertIn("pinned ELF required", (rejected / "collector-failure.json").read_text())
        self.assertFalse((rejected / "result.json").exists())

    def test_real_pidfd_rejects_wrong_birth_and_fifo_reads_do_not_block(self):
        who = collector.process_identity(os.getpid(), BOOT)
        changed = dict(who, start_ticks=who["start_ticks"] + 1)
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaisesRegex(ValueError, "PID birth changed"):
            collector.stable_pidfd(changed, BOOT)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        start = time.monotonic()
        for read in (collector.bounded, collector.file_digest):
            with self.assertRaisesRegex(ValueError, "regular"):
                read(fifo)
        self.assertLess(time.monotonic() - start, .5)

    def test_actual_post_fork_identity_failure_reaps_gated_root_without_exec(self):
        marker = self.root / "must-not-execute"
        command = self.script("from pathlib import Path\n" + f"Path({str(marker)!r}).write_text('bad')\n")
        argv, out, _ = self.argv("collector", command)
        fault = self.root / "inject-post-fork-read-error.py"
        fault.write_text("import os,sys\n" + f"sys.path.insert(0,{str(SOURCE.parent)!r})\n"
                         "import w1_owned_process_collector_v1 as c\n"
                         "original=c.process_identity\nfailed=False\n"
                         "def fail_once(pid,boot):\n global failed\n"
                         " if pid not in (os.getpid(),os.getppid()) and not failed:\n"
                         "  failed=True\n  raise OSError('actual post-fork proc read fault control')\n"
                         " return original(pid,boot)\n"
                         "c.process_identity=fail_once\n" + f"sys.exit(c.main({argv[2:]!r}))\n")
        proc = subprocess.Popen([str(PYTHON), str(fault)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(proc)
        result = self.finish(proc, out)
        self.assertEqual(proc.returncode, 125)
        self.assertFalse(marker.exists())
        self.assertEqual(result["result"]["final_echild"]["errno"], 10)
        self.assertEqual(len(result["result"]["wait4_records"]), 1)
        record = result["result"]
        row = record["wait4_records"][0]
        self.assertEqual(record["cause"], "launch-error")
        self.assertEqual(record["error"], "OSError: actual post-fork proc read fault control")
        self.assertFalse(record["records_truncated"])
        self.assertTrue(collector.same_identity(row["identity_before_reap"], record["root_identity"]))
        self.assertEqual(row["identity_before_reap"]["parent"], record["collector_identity"]["pid"])
        self.assertEqual(row["returncode"], record["root_returncode"])
        status = row["wait4_status"]
        self.assertEqual(os.waitstatus_to_exitcode(status), record["root_returncode"])
        events = [json.loads(line) for line in (out / "events.jsonl").read_text().splitlines()]
        self.assertFalse(any(event["kind"] == "root-exec-released" for event in events))
        self.assertFalse(any(event["kind"] == "signal"
                             and event["value"]["signal"] == signal.SIGTERM
                             and collector.same_identity(event["value"]["identity"], record["root_identity"])
                             for event in events))
        cleanup = [event for event in events
                   if event["kind"] == "cleanup-started" and event["value"]["cause"] == "launch-error"]
        self.assertEqual(len(cleanup), 1)
        if os.WIFEXITED(status):
            self.assertEqual(os.WEXITSTATUS(status), 125)
            self.assertEqual(row["waitid_si_code"], os.CLD_EXITED)
            self.assertEqual(row["waitid_si_status"], 125)
        else:
            self.assertTrue(os.WIFSIGNALED(status))
            signum = os.WTERMSIG(status)
            self.assertEqual(signum, signal.SIGKILL)
            self.assertEqual(row["returncode"], -signum)
            self.assertEqual(row["waitid_si_code"], os.CLD_KILLED)
            self.assertEqual(row["waitid_si_status"], signum)
            sent = [event for event in events
                    if event["kind"] == "signal"
                    and event["value"]["signal"] == signum
                    and event["value"]["outcome"] == "sent"
                    and collector.same_identity(event["value"]["identity"], record["root_identity"])]
            self.assertTrue(sent, "the recorded root signal must come from this collector's cleanup")
            self.assertTrue(any(cleanup[0]["monotonic_ns"] <= event["monotonic_ns"]
                                <= row["reaped_monotonic_ns"] for event in sent))
        self.assertFalse(result["result"]["root_exec_released"])
        self.assertFalse(result["command_success"])
        self.assertFalse(result["collector_wait_domain_reaped"])

    def test_reader_strict_types_identity_clock_and_actual_terminal_binding(self):
        proc, out, deadline = self.start("collector", self.script("print('actual source record')\n"))
        result = self.finish(proc, out)
        self.assertTrue(result["command_success"])
        self.assertEqual(collector.read_result(out)["terminal_state"], "unknown")
        self.assertFalse(collector.read_result(out, 0)["command_success"])
        late = collector.read_result(out, 0, observed_boot_id=BOOT, observed_completed_monotonic_ns=deadline)
        self.assertFalse(late["command_success"])
        self.assertFalse(late["deadline_qualified"])
        self.assertEqual(collector.read_result(out, -9)["terminal_state"], "unknown")
        with self.assertRaisesRegex(ValueError, "integer, not bool"):
            collector.read_result(out, False)
        original = json.loads((out / "result.json").read_text())
        mutations = [("wrapper_returncode", False), ("command_success_before_handoff", "yes"),
                     ("collector_wait_domain_reaped", 1), ("original_deadline_monotonic_ns", float(deadline)),
                     ("gpu_ns", 0), ("resource_billing_complete", True)]
        for index, (field, value) in enumerate(mutations):
            clone = self.root / f"malformed-{index}"
            shutil.copytree(out, clone)
            record = copy.deepcopy(original)
            record[field] = value
            (clone / "result.json").write_text(json.dumps(record))
            with self.subTest(field=field), self.assertRaises(ValueError):
                collector.read_result(clone, 0)
        malformed = self.root / "invalid.json"
        for raw in (b'{"a":1e400}', b'{"a":NaN}', b'{"a":1,"a":2}', '{"a":1}'.encode('utf-16')):
            malformed.write_bytes(raw)
            with self.assertRaises((ValueError, UnicodeError)):
                collector.read_json(malformed)

    def test_original_clock_gate_and_nonlinux_never_execute_payload(self):
        command = self.script("raise AssertionError('must never execute')\n")
        argv, out, _ = self.argv("expired", command, deadline=time.monotonic_ns() - 1)
        run = subprocess.run(argv, capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 125)
        self.assertIn("original boot/deadline mismatch", (out / "collector-failure.json").read_text())
        argv, out, _ = self.argv("nonlinux", command)
        code = "import sys;sys.path.insert(0," + repr(str(SOURCE.parent)) + ");import w1_owned_process_collector_v1 as c;sys.platform='darwin';sys.exit(c.main(" + repr(argv[2:]) + "))"
        run = subprocess.run([str(PYTHON), "-c", code], capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 125)
        self.assertIn("Linux subreaper required", (out / "collector-failure.json").read_text())

    def test_actual_generation_dispatch_worker_exec_chain_is_wrapped_without_status_theft(self):
        target_path = Path(os.environ.get("W1_COLLECTOR_TARGET", str(SOURCE.with_name("w1_generation_target_v2.py")))).resolve()
        self.assertTrue(target_path.is_file(), "real retained generation target source required")
        spec = importlib.util.spec_from_file_location("collector_control_target", target_path)
        target = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(target)
        invocation = self.root / "actual-target-invocation"
        payload = self.root / "target-payload.py"
        payload.write_text("import time\nfrom pathlib import Path\n" + f"Path({str(invocation)!r}).write_text('one real target child')\ntime.sleep(.2)\n")
        now = time.monotonic_ns()
        deadline = now + 5_000_000_000
        request = {"schema": target.NAMESPACE, "target_instance": "actual-collector-target-control",
                   "operation": "01" * 32, "task_scope": "02" * 32, "statement": "03" * 32,
                   "provider_namespace": "04" * 32, "execution_source_commitment": "05" * 32,
                   "target_backend_sha256": target.file_sha(target_path),
                   "clock_domain": target.clock_domain("actual-collector-target-control"),
                   "winner_monotonic_ns": now - 1, "deadline_monotonic_ns": deadline,
                   "argv": [str(PYTHON), str(payload)], "cwd": str(self.root),
                   "file_pins": {str(PYTHON): PYTHON_SHA, str(payload): collector.file_digest(payload)},
                   "environment": {"PATH": "/usr/bin:/bin", "RAYON_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                   "cpus": [min(os.sched_getaffinity(0))], "total_threads": 1,
                   "containment": "process-group-research", "cleanup_grace_ns": 1_000_000_000}
        request_path = self.root / "new-target-request.json"
        request_path.write_text(json.dumps(request))
        dbroot = self.root / "new-target-state"
        command = [str(PYTHON), str(target_path), "dispatch", "--root", str(dbroot),
                   "--target", request["target_instance"], "--request", str(request_path)]
        proc, out, _ = self.start("collector", command, deadline=deadline)
        result = self.finish(proc, out)
        self.assertTrue(result["command_success"])
        self.assertEqual(invocation.read_text(), "one real target child")
        db, _ = target.open_db(dbroot, request["target_instance"], False)
        try:
            row = target.public_readback(db, request["operation"], request["target_instance"])
        finally:
            db.close()
        (self.root / "actual-target-readback.json").write_text(json.dumps(row, sort_keys=True))
        self.assertTrue(row["result"]["direct_child_reaped"])
        self.assertEqual(row["result"]["exit_code"], 0)
        self.assertIsNone(row["result"]["all_descendants_reaped"])
        worker = row["worker"]["identity"]
        self.assertTrue(any(collector.same_identity(r["identity_before_reap"], worker)
                            for r in result["result"]["wait4_records"]))
        self.assertFalse(row["result"]["can_authorize_payment"])


class ClosedExecGateSignalControls(unittest.TestCase):
    """Deterministic signal ordering; actual fork/wait4 controls remain above."""

    def closed_gate_collector(self, *, grace=2, released=False, closed=True):
        value = collector.Collector.__new__(collector.Collector)
        value.args = types.SimpleNamespace(cleanup_grace_seconds=grace)
        value.cleanup_started = 1_000_000_000
        value.root_pid = 101
        value.root_exec_released = released
        value.root_exec_gate_closed = closed
        value.root_returncode = None
        value.owned = {
            (101, 11): {"identity": {"pid": 101}, "pidfd": 51, "signals": set()},
            (102, 12): {"identity": {"pid": 102}, "pidfd": 52, "signals": set()},
        }
        value.events = []
        value.emit = lambda kind, item: value.events.append((kind, item))
        return value

    def test_closed_unreleased_gate_defers_term_without_extending_original_kill_threshold(self):
        for grace, threshold in ((2, 250_000_000), (.1, 50_000_000)):
            with self.subTest(cleanup_grace_seconds=grace):
                value = self.closed_gate_collector(grace=grace)
                with mock.patch.object(collector.time, "monotonic_ns") as clock, \
                        mock.patch.object(collector.signal, "pidfd_send_signal", create=True) as send:
                    # Force cleanup to run before the gated root consumes EOF.
                    # The descendant is not covered by the root's exec gate.
                    for elapsed in (0, threshold - 1):
                        clock.return_value = value.cleanup_started + elapsed
                        value.signal_owned()
                    self.assertEqual(send.call_args_list, [mock.call(52, signal.SIGTERM)])
                    self.assertEqual(value.owned[(101, 11)]["signals"], set())
                    self.assertIsNone(value.root_returncode)

                    # The exact original escalation boundary must still kill
                    # both identities if no terminal wait record has arrived.
                    clock.return_value = value.cleanup_started + threshold
                    value.signal_owned()
                    self.assertEqual(send.call_args_list, [
                        mock.call(52, signal.SIGTERM),
                        mock.call(51, signal.SIGKILL),
                        mock.call(52, signal.SIGKILL),
                    ])
                    self.assertEqual(value.owned[(101, 11)]["signals"], {signal.SIGKILL})
                    self.assertEqual(value.owned[(102, 12)]["signals"], {signal.SIGTERM, signal.SIGKILL})
                    self.assertIsNone(value.root_returncode)
                    clock.return_value += 1
                    value.signal_owned()
                    self.assertEqual(send.call_count, 3)
                self.assertEqual([event[1]["signal"] for event in value.events],
                                 [signal.SIGTERM, signal.SIGKILL, signal.SIGKILL])

    def test_released_root_or_unconfirmed_gate_keeps_original_term_cleanup(self):
        for released, closed in ((True, True), (False, False), (True, False)):
            with self.subTest(root_exec_released=released, root_exec_gate_closed=closed):
                value = self.closed_gate_collector(released=released, closed=closed)
                with mock.patch.object(collector.time, "monotonic_ns",
                                       return_value=value.cleanup_started), \
                        mock.patch.object(collector.signal, "pidfd_send_signal", create=True) as send:
                    value.signal_owned()
                    self.assertEqual(send.call_args_list, [
                        mock.call(51, signal.SIGTERM), mock.call(52, signal.SIGTERM)])
                    value.signal_owned()
                    self.assertEqual(send.call_count, 2)
                self.assertIsNone(value.root_returncode)
                self.assertEqual([event[1]["signal"] for event in value.events],
                                 [signal.SIGTERM, signal.SIGTERM])


if __name__ == "__main__":
    unittest.main()
