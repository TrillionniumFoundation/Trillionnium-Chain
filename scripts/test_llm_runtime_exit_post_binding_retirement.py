"""Bound-worker ESRCH component controls, not a natural model qualification.

The deterministic cases explicitly simulate procfs/pidfds. The native case uses
the original held task directory/status FD, real PIDFD_THREAD/POLLIN, real roster
removal and kernel read ESRCH. Only the exit-only State/PF_EXITING/no-mm field
view is controlled to enter the short acquisition stage deterministically. PID,
namespace, starttime, Threads and FD identities remain real. The first RSS
sample and final wait4 high-water/CPU are real; the missing-RSS field view is
controlled. Raw and transformed fields and the unchanged deadline are retained.
"""

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import select
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_worker_observation as worker
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_binding_pending as pending_fixtures
import test_llm_runtime_exit_worker_observation as fixtures


class PostBindingRetirementTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.WorkerPidfdTests()
        self.capture_fixture = pending_fixtures.BindingTerminalPendingTests()
        self.capture_fixture.setUp()

    def capture(self, state, ordinal=5, component="status", **kwargs):
        return self.capture_fixture.capture(
            state, ordinal, component, injected_errno=errno.ESRCH, **kwargs
        )

    def assert_pending(self, observed, task="10002"):
        record = observed.record
        self.assertFalse(observed.baseline_qualified)
        self.assertFalse(observed.failed)
        self.assertEqual(record["schema"], "llm-owned-postbinding-terminal-pending-v1")
        self.assertEqual(record["transition"], "binding-acquisition-pending-owned-wait4")
        self.assertTrue(record["complete_prebinding_classification"])
        self.assertFalse(record["complete_worker_pidfd_acquisition"])
        event = record["bound_worker_terminal_event"]
        self.assertEqual(event["task"], task)
        self.assertEqual(event["read_errno"], errno.ESRCH)
        self.assertTrue(event["revents"] & select.POLLIN)
        self.assertEqual(event["original_starttime"], observed.baseline_starts[task])
        self.assertEqual(event["original_namespace"], list(observed.bindings[task]["namespace"]))
        self.assertNotIn("rss_bytes", record)
        self.assertNotIn("retirement_closed_by", record)
        self.assertNotIn("worker_terminal_events", record)
        self.assertTrue(observed.initial_capture.pending)

    def test_bound_esrch_in_each_postbinding_read_retains_only_pending(self):
        for ordinal in (5, 6, 7):
            for component in ("status", "stat"):
                with self.subTest(ordinal=ordinal, component=component), self.fixture.proc() as state:
                    observed = self.capture(state, ordinal, component)
                    try:
                        self.assert_pending(observed)
                        interruption = observed.record["acquisition_interruption"]
                        self.assertEqual(interruption["component"], component)
                        self.assertEqual(interruption["phase"], "worker-pidfd-recheck" if ordinal == 7
                                         else "post-bind-double-frontier")
                        self.assertEqual(set(observed.prebinding_record["frontier_before"]), set(observed.names))
                        self.assertIsNotNone(observed.recheck())
                        self.assert_pending(observed)
                        self.assertTrue(observed.belongs_to(501, state.held, state.token))
                        for descriptor in (*observed.task_fds.values(), *observed.thread_fds.values()):
                            os.fstat(descriptor)
                    finally:
                        observed.close()
                    os.fstat(state.held)

    def test_unbound_esrch_and_postbinding_other_errors_still_refuse(self):
        for ordinal, number in ((3, errno.ESRCH), (4, errno.ESRCH),
                                (5, errno.EACCES), (6, errno.EIO), (7, errno.EBADF)):
            for component in ("status", "stat"):
                with self.subTest(ordinal=ordinal, number=number, component=component), self.fixture.proc() as state:
                    with self.assertRaises((OSError, ValueError)):
                        self.capture_fixture.capture(state, ordinal, component, injected_errno=number)
                    for descriptor in state.identities:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

    def test_bound_esrch_requires_exact_original_worker_terminal_event(self):
        events = {
            "absent": lambda fd: [],
            "zero": lambda fd: [(fd, 0)],
            "hup-only": lambda fd: [(fd, select.POLLHUP)],
            "error": lambda fd: [(fd, select.POLLIN | select.POLLERR)],
            "invalid": lambda fd: [(fd, select.POLLIN | select.POLLNVAL)],
            "wrong-fd": lambda fd: [(fd + 1000, select.POLLIN)],
            "duplicate": lambda fd: [(fd, select.POLLIN), (fd, select.POLLIN)],
        }
        for label, value in events.items():
            with self.subTest(label=label), self.fixture.proc() as state:
                state.events = value
                with self.assertRaises((OSError, ValueError)):
                    self.capture(state)

    def test_terminal_event_cannot_replace_original_binding_or_held_identity(self):
        changes = {
            "binding-missing": lambda o: o.bindings.pop("10002"),
            "birth-changed": lambda o: o.bindings["10002"].update(starttime=o.baseline_starts["10002"] + 1),
            "namespace-changed": lambda o: o.bindings["10002"].update(namespace=(10002, 509)),
            "task-fd-changed": lambda o: o.task_signatures.update({"10002": (0, 0, 0)}),
            "pidfd-changed": lambda o: o.thread_signatures.update({"10002": (0, 0, 0)}),
            "owner-changed": lambda o: setattr(o, "held_signature", (0, 0, 0)),
            "late": lambda o: setattr(o, "sample_started_ns", time.monotonic_ns() - worker.MAX_DRAIN_NS - 1),
        }
        for label, change in changes.items():
            with self.subTest(label=label), self.fixture.proc() as state:
                holder = {}
                original_bind = worker.WorkerPidfdObservation._bind_workers
                original_retire = self.capture_fixture.fixture.retire

                def bind(observed):
                    original_bind(observed)
                    holder["observation"] = observed

                def retire(current):
                    original_retire(current)
                    change(holder["observation"])

                with patch.object(worker.WorkerPidfdObservation, "_bind_workers", bind), \
                        patch.object(self.capture_fixture.fixture, "retire", side_effect=retire):
                    with self.assertRaises((OSError, ValueError)):
                        self.capture(state)

    def test_event_does_not_qualify_live_reappearing_or_other_missing_worker(self):
        for mode in ("live", "reappearing", "other-missing", "new-task"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                original_retire = self.capture_fixture.fixture.retire
                if mode == "other-missing":
                    self.fixture.additional_worker(state)

                def retire(current):
                    if mode == "live":
                        current.terminal.add("10002")
                        return
                    original_retire(current)
                    if mode == "reappearing":
                        (current.root / "retired-10002").rename(current.root / "task/10002")
                    elif mode == "other-missing":
                        self.fixture.retire(current, "10003")
                    elif mode == "new-task":
                        self.fixture.additional_worker(current)

                with patch.object(self.capture_fixture.fixture, "retire", side_effect=retire):
                    with self.assertRaises((OSError, ValueError)):
                        self.capture(state)

    def test_successful_bad_status_is_not_erased_by_later_bound_esrch(self):
        for ordinal in (5, 6, 7):
            for change in (lambda raw: raw + "VmRSS:\t0 kB\n",
                           lambda raw: raw.replace("PPid:\t10000", "PPid:\t10009"),
                           lambda raw: raw.replace("Threads:\t2", "Threads:\t1")):
                with self.subTest(ordinal=ordinal, change=change), self.fixture.proc() as state:
                    original = base._read
                    count = 0

                    def read(descriptor, component):
                        nonlocal count
                        raw = original(descriptor, component)
                        if os.readlink(f"/proc/self/fd/{descriptor}").endswith("/10002") and component == "status":
                            count += 1
                            if count == ordinal:
                                return change(raw)
                        return raw

                    with patch.object(base, "_read", side_effect=read), self.assertRaises(ValueError):
                        self.capture(state, ordinal, "stat")

    def test_postbinding_leader_and_group_esrch_still_refuse(self):
        for kind in ("leader", "group"):
            with self.subTest(kind=kind), self.fixture.proc() as state:
                original_bind, original_read = worker.WorkerPidfdObservation._bind_workers, base._read
                holder = {}

                def bind(observed):
                    original_bind(observed)
                    holder["observation"] = observed

                def read(descriptor, component):
                    observed = holder.get("observation")
                    if observed is not None and component == "status" and descriptor == (
                            observed.group_fd if kind == "group" else observed.task_fds["10001"]):
                        raise ProcessLookupError(errno.ESRCH, "explicit leader/group read fixture")
                    return original_read(descriptor, component)

                with patch.object(worker.WorkerPidfdObservation, "_bind_workers", bind), \
                        patch.object(base, "_read", side_effect=read), self.assertRaises(OSError):
                    self.fixture.observation(state)
                self.assertTrue(holder["observation"].failed)

    def test_roster_change_after_first_retention_check_is_not_hidden(self):
        for mode in ("other-missing", "reappearing", "new-task"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                self.fixture.additional_worker(state)
                original_names = worker.WorkerPidfdObservation._initial_names
                changed = False

                def names(observed):
                    nonlocal changed
                    result = original_names(observed)
                    if "10002" in state.terminal and not changed:
                        changed = True
                        if mode == "other-missing":
                            self.fixture.retire(state, "10003")
                        elif mode == "reappearing":
                            (state.root / "retired-10002").rename(state.root / "task/10002")
                        else:
                            (state.root / "task/10004").mkdir()
                    return result

                with patch.object(worker.WorkerPidfdObservation, "_initial_names", names), \
                        self.assertRaisesRegex(ValueError, "frontier-change|initial-task-set"):
                    self.capture(state)
                self.assertTrue(changed)

    def test_one_loss_from_three_threads_does_not_cover_a_later_other_loss(self):
        with self.fixture.proc() as state:
            self.fixture.additional_worker(state)
            observed = self.capture(state)
            try:
                self.assert_pending(observed)
                self.assertEqual(set(observed.bindings), {"10002", "10003"})
                self.assertEqual(observed.record["tasks"], ["10001", "10003"])
                self.assertIsNotNone(observed.recheck())
                self.fixture.retire(state, "10003")
                with self.assertRaisesRegex(ValueError, "exit-worker-frontier-change"):
                    observed.recheck()
                self.assertTrue(observed.failed)
                self.assertFalse(observed.belongs_to(501, state.held, state.token))
                with self.assertRaisesRegex(ValueError, "sticky-failure"):
                    observed.recheck()
            finally:
                observed.close()

    def test_previous_v4_source_receipt_remains_closed(self):
        profile = runtime.exit_observation_profile(worker.PROFILE)
        profile["observer_source_sha256"] = "b083f9e9271a286c78d819aca82e00506532ad1fc4da664a619a408b52fcfa10"
        # On the unchanged baseline this is still its own valid receipt. This
        # becomes a new-source refusal only after the proposed source changes.
        current = hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest()
        if current != profile["observer_source_sha256"]:
            with self.assertRaisesRegex(ValueError, "OBSERVER_BINDING"):
                runtime.exit_observation_class(profile)
        else:
            self.assertIs(runtime.exit_observation_class(profile), worker.WorkerPidfdObservation)
        self.assertEqual(profile["maximum_drain_ns"], 100_000_000)

    def _native_case(self, mode):
        """Real kernel/wait4 mechanics, controlled exit-only field view only."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ready, allocate, allocated = [directory / name for name in ("ready", "allocate", "allocated")]
            release_worker, joined, release_group = [directory / name for name in ("release-worker", "joined", "release-group")]
            state = dict(classifying=False, samples=0, status_opens=0, field_views=[], kernel_errors=[],
                         mode=mode, control_scope="State/PF_EXITING/missing-RSS view controlled; real PID/ns/starttime/Threads/FDs, first RSS, final wait4 high-water/CPU and time")
            original_child, original_rss = runtime._Wait4Child, runtime.current_rss
            original_open, original_read, original_path_open = os.open, base._read, Path.open
            original_pidfd = os.pidfd_open

            def wait_file(path, deadline):
                while not path.exists():
                    self.assertLess(time.monotonic_ns(), deadline, "bounded actual child scheduling hook")
                    time.sleep(0.0002)

            def create(*args, **kwargs):
                child = original_child(*args, **kwargs)
                state["child"] = child
                state["identity"] = base._pidfd_identity(child.pid, child.termination_fd)
                return child

            def controlled(raw, component, source):
                if component == "status":
                    fields = base._status(raw)
                    leader = base._one(fields, "Pid") == state["identity"][0]
                    view = "".join(
                        "State:\tZ (controlled fixture)\n" if leader and row.startswith("State:") else row
                        for row in raw.splitlines(keepends=True) if not row.startswith("VmRSS:")
                    )
                else:
                    prefix, suffix = raw.rsplit(") ", 1)
                    values = suffix.split()
                    if int(prefix.partition(" (")[0]) == state["identity"][0]:
                        values[0] = "Z"
                    values[6] = str(int(values[6]) | base.PF_EXITING)
                    values[20] = values[21] = "0"
                    view = prefix + ") " + " ".join(values) + "\n"
                state["field_views"].append(dict(source=source, component=component, raw=raw, controlled=view))
                return view

            def path_open(path, *args, **kwargs):
                handle = original_path_open(path, *args, **kwargs)
                if state["classifying"] and str(path) == f"/proc/{state['identity'][0]}/status":
                    with handle:
                        return io.StringIO(controlled(handle.read(), "status", str(path)))
                return handle

            def pidfd_open(pid, flags=0):
                descriptor = original_pidfd(pid, flags)
                if flags == worker.PIDFD_THREAD:
                    state["thread_fd"] = descriptor
                    state["thread_signature"] = base._signature(descriptor)
                    state["thread_fdinfo"] = base._proc_fields(Path(f"/proc/self/fdinfo/{descriptor}"))
                    state["proc_tid"] = base._one(state["thread_fdinfo"], "Pid")
                return descriptor

            def opened(path, flags, mode_bits=0o777, *, dir_fd=None):
                descriptor = original_open(path, flags, mode_bits, dir_fd=dir_fd)
                if state["classifying"] and path == "status" and dir_fd is not None:
                    held_path = os.readlink(f"/proc/self/fd/{dir_fd}")
                    if held_path == f"/proc/{state['identity'][0]}/task/{state.get('proc_tid')}":
                        state["status_opens"] += 1
                        # Binding has read the same task four times already.
                        # At this point open succeeded; the original _read's
                        # next handle.read must produce the actual kernel error.
                        if state["status_opens"] == 2:
                            state["held_task_signature"] = base._signature(dir_fd)
                            state["opened_status_signature"] = base._signature(descriptor)
                            release_worker.write_text("release only this actual worker\n")
                            deadline = time.monotonic_ns() + worker.MAX_DRAIN_NS
                            poller = select.poll()
                            poller.register(state["thread_fd"], select.POLLIN)
                            events = []
                            while not events and time.monotonic_ns() < deadline:
                                events = poller.poll(1)
                            self.assertTrue(events and events[0][0] == state["thread_fd"] and events[0][1] & select.POLLIN)
                            wait_file(joined, deadline)
                            state["kernel_events"] = events
                            state["roster_after"] = os.listdir(f"/proc/{state['identity'][0]}/task")
                            self.assertNotIn(str(state["proc_tid"]), state["roster_after"])
                            self.assertEqual(base._signature(state["thread_fd"]), state["thread_signature"])
                return descriptor

            def read(descriptor, component):
                source = os.readlink(f"/proc/self/fd/{descriptor}")
                try:
                    raw = original_read(descriptor, component)
                except OSError as error:
                    state["kernel_errors"].append(dict(source=source, component=component,
                        error_type=type(error).__name__, error_errno=error.errno))
                    raise
                return controlled(raw, component, source) if state["classifying"] else raw

            def observe(pid):
                state["samples"] += 1
                wait_file(ready, time.monotonic_ns() + 800_000_000)
                if state["samples"] == 1:
                    actual = original_rss(pid)
                    self.assertIsInstance(actual, int)
                    self.assertGreater(actual, 0)
                    self.assertLess(actual, 32 * 1024**2)
                    state["actual_first_rss"] = actual
                    allocate.write_text("allocate before the controlled missing sample\n")
                    return actual
                wait_file(allocated, time.monotonic_ns() + 800_000_000)
                state["classifying"] = True
                actual = original_rss(pid)
                observed = runtime._RSS_EXIT_OBSERVATION.get()
                state["record"] = observed.record if observed is not None else None
                state["baseline_qualified"] = getattr(observed, "baseline_qualified", None)
                state["constructor_failed"] = getattr(observed, "failed", None)
                if mode != "late":
                    release_group.write_text("allow exact owned group wait4\n")
                return actual

            program = """
from pathlib import Path
import json,os,sys,threading,time
root=Path(sys.argv[1])
def wait(name):
    while not (root/name).exists(): time.sleep(0.0002)
t=threading.Thread(target=lambda:wait('release-worker')); t.start()
(root/'ready').write_text(json.dumps([os.getpid(),t.native_id]))
wait('allocate'); material=bytearray(64*1024*1024)
(root/'allocated').write_text('actual allocation complete')
t.join(); (root/'joined').write_text('actual worker joined')
wait('release-group'); raise SystemExit(int(sys.argv[2]))
"""
            budget = dict(wall_seconds=2, rss_bytes=(32 if mode == "overcap" else 128) * 1024**2)
            try:
                with patch.object(runtime, "_Wait4Child", side_effect=create), \
                        patch.object(runtime, "current_rss", side_effect=observe), \
                        patch.object(Path, "open", path_open), patch.object(os, "open", side_effect=opened), \
                        patch.object(os, "pidfd_open", side_effect=pidfd_open), \
                        patch.object(base, "_read", side_effect=read):
                    result = runtime.supervise([sys.executable, "-c", program, str(directory),
                        "7" if mode == "nonzero" else "0"], directory / "run", budget,
                        exit_observation=runtime.exit_observation_profile(worker.PROFILE))
            finally:
                if "child" in state:
                    state["child"].finish()
            state.pop("child", None)
            state["result"] = result
            state["kernel"] = os.uname().release
            output = os.environ.get("TRNM_POSTBIND_EVIDENCE_DIR")
            if output:
                with (Path(output) / f"native-{mode}.json").open("x") as handle:
                    json.dump(state, handle, indent=2)
                    handle.write("\n")
            print("postbinding native component", json.dumps(dict(mode=mode, kernel_errors=state["kernel_errors"],
                events=state.get("kernel_events"), outcome=result["outcome"], stop_reason=result["stop_reason"],
                exact_wait4=result["cleanup_method"], baseline_qualified=state["baseline_qualified"])))
            self.assertEqual(state["samples"], 2)
            self.assertEqual(len(state["kernel_errors"]), 1)
            self.assertEqual(state["kernel_errors"][0]["error_errno"], errno.ESRCH)
            self.assertEqual(state["kernel_errors"][0]["component"], "status")
            self.assertTrue(result["waited_child_reaped"])
            self.assertTrue(result["owned_child_reap_resolved"])
            self.assertEqual(result["cleanup_method"], "wait4")
            self.assertGreater(result["waited_child_peak_rss_bytes"], 64 * 1024**2)
            self.assertGreaterEqual(result["child_cpu_ns"], 0)
            self.assertEqual(result["sampled_peak_rss_bytes"], state["actual_first_rss"])
            self.assertFalse(state["baseline_qualified"])
            self.assertFalse(state["constructor_failed"])
            self.assertEqual(state["record"]["schema"], "llm-owned-postbinding-terminal-pending-v1")
            self.assertEqual(state["record"]["acquisition_interruption"]["phase"], "post-bind-double-frontier")
            self.assertEqual(state["record"]["bound_worker_terminal_event"]["task"], str(state["proc_tid"]))
            self.assertEqual(state["record"]["bound_worker_terminal_event"]["revents"], state["kernel_events"][0][1])
            self.assertEqual(result["exit_observation_profile"]["maximum_drain_ns"], 100_000_000)
            return result

    def test_native_held_proc_read_esrch_and_pidfd_event_use_actual_owned_wait4(self):
        result = self._native_case("valid")
        self.assertEqual(result["outcome"], "success")
        self.assertIsNone(result["stop_reason"])
        self.assertEqual(result["exit_code"], 0)
        record = result["exit_cleanup_observation"]
        self.assertEqual(record["outcome"], "terminal-wait4")
        self.assertEqual(record["retirement_closed_by"], "exact-owned-child-terminal-wait4")
        self.assertLessEqual(record["completed_ns"] - record["missing_sample_ns"], 100_000_000)

    def test_native_terminal_event_does_not_bypass_exit_rss_or_original_deadline(self):
        for mode in ("nonzero", "overcap", "late"):
            with self.subTest(mode=mode):
                result = self._native_case(mode)
                self.assertEqual(result["outcome"], "failed")
                if mode == "nonzero":
                    self.assertEqual(result["exit_code"], 7)
                elif mode == "overcap":
                    self.assertEqual(result["stop_reason"], "rss-budget-exceeded")
                else:
                    self.assertEqual(result["stop_reason"], "rss-exit-cleanup-observation-unavailable")
                    record = result["exit_cleanup_observation"]
                    self.assertGreaterEqual(record["completed_ns"] - record["missing_sample_ns"], 100_000_000)
                    if record["error"] == "ExitObservationError":
                        self.assertEqual(record["recheck_refusal"]["refusal_code"], "exit-worker-deadline")
                    else:
                        self.assertEqual(record["error"], "exit-cleanup-deadline")
                    self.assertNotIn("retirement_closed_by", record)


if __name__ == "__main__":
    unittest.main()
