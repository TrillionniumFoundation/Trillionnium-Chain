"""A disappearing already-proved worker may retain, never release, its owner.

Procfs/task-pidfd races below are explicit fixtures. These tests are not a
reproduction of the historical model run's unidentified constructor substage.
"""

import contextlib
import errno
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_worker_observation as worker
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_worker_observation as fixtures
import test_llm_runtime_rss_owner as owner_fixtures


class BindingTerminalPendingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.WorkerPidfdTests()

    def capture(
        self,
        state,
        ordinal,
        component="stat",
        *,
        bad_status=None,
        injected_errno=None,
        remove=True,
        pid=501,
    ):
        original = base._read
        count = 0
        triggered = False

        def read(descriptor, field):
            nonlocal count, triggered
            path = os.readlink(f"/proc/self/fd/{descriptor}")
            if path.endswith("/10002") and field == component:
                count += 1
                if count == ordinal:
                    triggered = True
                    raw = original(descriptor, field) if bad_status else None
                    if remove:
                        self.fixture.retire(state)
                    if bad_status:
                        return bad_status(raw)
                    if injected_errno is not None:
                        raise OSError(injected_errno, "explicit acquisition fixture")
            return original(descriptor, field)

        with patch.object(base, "_read", side_effect=read):
            observed = worker.WorkerPidfdObservation(
                pid,
                state.held,
                state.token,
                base._status((state.root / "status").read_text()),
                time.monotonic_ns(),
            )
        self.assertTrue(triggered)
        return observed

    def assert_pending(self, state, observed):
        self.assertFalse(observed.baseline_qualified)
        self.assertEqual(
            observed.record["schema"], "llm-owned-binding-terminal-pending-v1"
        )
        self.assertEqual(
            observed.record["transition"], "binding-acquisition-pending-owned-wait4"
        )
        self.assertTrue(observed.record["complete_prebinding_classification"])
        self.assertFalse(observed.record["complete_worker_pidfd_acquisition"])
        self.assertEqual(observed.record["pending_retired_tasks"], ["10002"])
        self.assertNotIn("worker_terminal_events", observed.record)
        self.assertNotIn("rss_bytes", observed.record)
        self.assertNotIn("retirement_closed_by", observed.record)
        self.assertTrue(observed.belongs_to(501, state.held, state.token))

    def test_held_worker_enoent_in_each_acquisition_read_keeps_original_pending(self):
        # Reads 1/2 are the complete prebinding double frontier. 3/4 are
        # before/after pidfd_open, 5/6 the second complete frontier, 7 the
        # final binding recheck. No pidfd_open/fdinfo failure is substituted.
        for ordinal in range(3, 8):
            for component in ("status", "stat"):
                with (
                    self.subTest(ordinal=ordinal, component=component),
                    self.fixture.proc() as state,
                ):
                    observed = self.capture(state, ordinal, component)
                    handles = [
                        *observed.task_fds.values(),
                        *observed.thread_fds.values(),
                    ]
                    try:
                        self.assert_pending(state, observed)
                        self.assertIsNotNone(observed.recheck())
                        self.assert_pending(state, observed)
                        for descriptor in handles:
                            os.fstat(descriptor)
                        child = SimpleNamespace(
                            pid=501,
                            termination_fd=state.held,
                            observation_error=None,
                            waited_peak_rss_bytes=8192,
                            waited_cpu_ns=1500,
                            reap=lambda: "terminal",
                        )
                        reason, record = runtime._drain_exit_cleanup(
                            child,
                            observed,
                            state.token,
                            time.monotonic_ns(),
                            {"wall_seconds": 2},
                            exit_observation=runtime.exit_observation_profile(
                                worker.PROFILE
                            ),
                        )
                        self.assertIsNone(reason)
                        self.assertEqual(
                            record["retirement_closed_by"],
                            "exact-owned-child-terminal-wait4",
                        )
                    finally:
                        observed.close()
                    for descriptor in handles:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    os.fstat(state.held)

    def test_successfully_read_bad_status_is_sticky_before_later_stat_enoent(self):
        mutations = {
            "pid": lambda raw: raw.replace("Pid:\t10002", "Pid:\t10009"),
            "parent": lambda raw: raw.replace("PPid:\t10000", "PPid:\t10009"),
            "tgid": lambda raw: raw.replace("Tgid:\t10001", "Tgid:\t10009"),
            "namespace": lambda raw: raw.replace(
                "NSpid:\t10002 502", "NSpid:\t10002 509"
            ),
            "group-namespace": lambda raw: raw.replace(
                "NStgid:\t10001 501", "NStgid:\t10001 509"
            ),
            "rss": lambda raw: raw + "VmRSS:\t0 kB\n",
            "count-decrease": lambda raw: raw.replace("Threads:\t2", "Threads:\t1"),
            "count-increase": lambda raw: raw.replace("Threads:\t2", "Threads:\t3"),
            "state": lambda raw: raw.replace("State:\tR", "State:\tQ"),
        }
        for ordinal in (3, 4, 5, 6, 7):
            for label, change in mutations.items():
                with (
                    self.subTest(ordinal=ordinal, label=label),
                    self.fixture.proc() as state,
                ):
                    with self.assertRaises(ValueError):
                        self.capture(state, ordinal, "status", bad_status=change)
                    for descriptor in state.identities:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

    def test_other_task_read_errors_and_enoent_without_roster_loss_refuse(self):
        for number, remove in (
            (errno.EACCES, True),
            (errno.EIO, True),
            (errno.ESRCH, True),
            (errno.ENOENT, False),
        ):
            with (
                self.subTest(number=number, remove=remove),
                self.fixture.proc() as state,
            ):
                with self.assertRaises((OSError, ValueError)):
                    self.capture(state, 3, injected_errno=number, remove=remove)
                for descriptor in state.identities:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_pidfd_open_or_fdinfo_failure_is_not_a_held_task_read(self):
        for mode in ("open", "fdinfo"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                original_open, original_fields = worker.os.pidfd_open, base._proc_fields

                def opened(pid, flags):
                    if mode == "open":
                        raise ProcessLookupError(errno.ESRCH, "explicit pidfd fixture")
                    return original_open(pid, flags)

                def fields(path):
                    if mode == "fdinfo" and str(path).startswith("/proc/self/fdinfo/"):
                        raise FileNotFoundError(errno.ENOENT, "explicit fdinfo fixture")
                    return original_fields(path)

                with (
                    patch.object(worker.os, "pidfd_open", side_effect=opened),
                    patch.object(base, "_proc_fields", side_effect=fields),
                    self.assertRaises(OSError),
                ):
                    self.fixture.observation(state)
                for descriptor in state.identities:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_group_or_leader_read_failure_never_creates_binding_pending(self):
        for kind in ("group", "leader"):
            with self.subTest(kind=kind), self.fixture.proc() as state:
                original = worker.WorkerPidfdObservation._bind_workers

                def bind(observed):
                    original(observed)
                    path = (
                        state.root / "status"
                        if kind == "group"
                        else state.root / "task/10001/status"
                    )
                    path.unlink()

                with (
                    patch.object(worker.WorkerPidfdObservation, "_bind_workers", bind),
                    self.assertRaises(OSError),
                ):
                    self.fixture.observation(state)
                for descriptor in state.identities:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_real_supervise_and_owned_wait4_close_only_with_original_resource_rules(
        self,
    ):
        # Only proc/task-pidfd classification is synthetic. The original
        # supervisor creates the real process and held pidfd, and executes its
        # actual wait4, CPU/RSS receipt and finalizer; no terminal receipt mock.
        original_child = runtime._Wait4Child
        original_identity = base._pidfd_identity
        for mode in ("valid", "nonzero", "overcap", "late"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as directory,
                contextlib.ExitStack() as stack,
            ):
                directory = Path(directory)
                ready, release = directory / "ready", directory / "release"
                holder, observed_records = {}, []

                def create(*args, **kwargs):
                    child = original_child(*args, **kwargs)
                    holder["child"] = child
                    identity = original_identity(child.pid, child.termination_fd)
                    self.assertEqual(identity[2][-1], child.pid)
                    state = stack.enter_context(self.fixture.proc())
                    state.held = child.termination_fd
                    holder["state"] = state
                    return child

                def observe(pid):
                    stop = time.monotonic() + 0.8
                    while not ready.exists():
                        self.assertLess(
                            time.monotonic(), stop, "bounded real child setup"
                        )
                        time.sleep(0.001)
                    state = holder["state"]
                    owner = runtime._RSS_OWNER_CONTEXT.get()
                    self.assertEqual((owner[0], owner[1]), (pid, state.held))
                    state.token = owner[2]
                    observed = self.capture(state, 4, pid=pid)
                    self.assertFalse(observed.baseline_qualified)
                    if mode == "late":
                        observed.sample_started_ns -= worker.MAX_DRAIN_NS + 1
                    observed_records.append(observed.record)
                    runtime._RSS_EXIT_OBSERVATION.set(observed)
                    release.write_text("complete this actual owned child\n")
                    return None

                command = [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys,time; "
                    "x=bytearray(16*1024*1024); Path(sys.argv[1]).write_text('ready'); "
                    "exec('while not Path(sys.argv[2]).exists(): time.sleep(0.001)'); "
                    "raise SystemExit(int(sys.argv[3]))",
                    str(ready),
                    str(release),
                    "7" if mode == "nonzero" else "0",
                ]
                budget = dict(
                    wall_seconds=2,
                    rss_bytes=(1024**2 if mode == "overcap" else 128 * 1024**2),
                )
                try:
                    with (
                        patch.object(runtime, "_Wait4Child", side_effect=create),
                        patch.object(runtime, "current_rss", side_effect=observe),
                    ):
                        result = runtime.supervise(
                            command,
                            directory / "run",
                            budget,
                            exit_observation=runtime.exit_observation_profile(
                                worker.PROFILE
                            ),
                        )
                finally:
                    if "child" in holder:
                        holder["child"].finish()
                self.assertEqual(len(observed_records), 1)
                self.assertEqual(
                    result["outcome"], "success" if mode == "valid" else "failed"
                )
                self.assertTrue(result["waited_child_reaped"])
                self.assertTrue(result["owned_child_reap_resolved"])
                self.assertGreater(result["waited_child_peak_rss_bytes"], 0)
                self.assertGreaterEqual(result["child_cpu_ns"], 0)
                if mode == "valid":
                    self.assertEqual(result["exit_code"], 0)
                    self.assertEqual(
                        result["exit_cleanup_observation"]["outcome"], "terminal-wait4"
                    )
                elif mode == "overcap":
                    self.assertEqual(result["stop_reason"], "rss-budget-exceeded")
                elif mode == "late":
                    self.assertEqual(
                        result["exit_cleanup_observation"]["outcome"], "failed"
                    )
                else:
                    self.assertEqual(result["exit_code"], 7)

    def test_pending_unknown_wrong_wait_and_missing_receipts_cannot_close(self):
        for mode in (
            "unknown",
            "wrong-pid",
            "error",
            "missing-rss",
            "missing-cpu",
            "wrong-token",
        ):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                observed = self.capture(state, 4)
                child = SimpleNamespace(
                    pid=501,
                    termination_fd=state.held,
                    observation_error="wait4:conflict"
                    if mode in ("wrong-pid", "error")
                    else None,
                    waited_peak_rss_bytes=None if mode == "missing-rss" else 8192,
                    waited_cpu_ns=None if mode == "missing-cpu" else 1000,
                    reap=lambda: (
                        "unknown" if mode in ("unknown", "wrong-pid") else "terminal"
                    ),
                )
                try:
                    reason, result = runtime._drain_exit_cleanup(
                        child,
                        observed,
                        object() if mode == "wrong-token" else state.token,
                        time.monotonic_ns(),
                        {"wall_seconds": 2},
                        exit_observation=runtime.exit_observation_profile(
                            worker.PROFILE
                        ),
                    )
                    self.assertIsNotNone(reason)
                    self.assertEqual(result["outcome"], "failed")
                    self.assertNotIn("retirement_closed_by", result)
                finally:
                    observed.close()

    def test_original_whole_deadline_cannot_be_replaced_by_new_pending_window(self):
        with self.fixture.proc() as state:
            observed = self.capture(state, 4)
            child = SimpleNamespace(
                pid=501,
                termination_fd=state.held,
                observation_error=None,
                waited_peak_rss_bytes=8192,
                waited_cpu_ns=1000,
                reap=lambda: "terminal",
            )
            try:
                reason, result = runtime._drain_exit_cleanup(
                    child,
                    observed,
                    state.token,
                    time.monotonic_ns() - 3_000_000_000,
                    {"wall_seconds": 2},
                    exit_observation=runtime.exit_observation_profile(worker.PROFILE),
                )
                self.assertIsNotNone(reason)
                self.assertEqual(result["outcome"], "failed")
            finally:
                observed.close()

    def test_constructor_failure_diagnostic_comes_from_actual_current_rss_call(self):
        helper = owner_fixtures.RssSupervisionTests()
        with self.fixture.proc() as state:
            child = helper.child_control()
            child.termination_fd = state.held
            original_open, original_fields = Path.open, base._proc_fields
            proc = {
                "/proc/self/status": "Pid:\t10000\nNSpid:\t10000 500\n",
                f"/proc/self/fdinfo/{state.held}": "Pid:\t10001\nNSpid:\t10001 501\n",
                "/proc/10001/status": state.fixture.status(),
            }

            def open_path(path, *args, **kwargs):
                return (
                    io.StringIO(proc[str(path)])
                    if str(path) in proc
                    else original_open(path, *args, **kwargs)
                )

            def fields(path):
                if str(path).startswith("/proc/self/fdinfo/"):
                    raise FileNotFoundError(
                        errno.ENOENT, "private message must not be copied"
                    )
                return original_fields(path)

            with (
                patch.object(runtime, "_Wait4Child", return_value=child),
                patch.object(runtime.os, "getpid", return_value=500),
                patch.object(
                    runtime.os,
                    "wait4",
                    side_effect=[(0, 0, None), (501, 0, helper.usage())],
                ),
                patch.object(runtime.signal, "pidfd_send_signal"),
                patch.object(Path, "open", open_path),
                patch.object(base, "_proc_fields", side_effect=fields),
            ):
                result = runtime.supervise(
                    ["real current_rss; synthetic fdinfo disappearance"],
                    state.root / "run",
                    helper.BUDGET,
                    exit_observation=runtime.exit_observation_profile(worker.PROFILE),
                )
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["exit_code"], 0)
            detail = result["rss_gap_diagnostic"]["missing_sample_detail"]
            failure = detail["same_sample_exit_acquisition_failure"]
            self.assertEqual(failure["phase"], "worker-pidfd-bind")
            self.assertEqual(failure["error_errno"], errno.ENOENT)
            self.assertTrue(failure["diagnostic_only"])
            self.assertLessEqual(len(failure["source_frames"]), 16)
            self.assertNotIn("private message", str(failure))

    def test_legacy_sources_unchanged_and_previous_v4_source_receipt_refused(self):
        hashes = {
            "llm_runtime_pilot.py": "65ccc6454befd96fa5ce1f5bdde2c56cb6cbb741cf495b8d24a758039f99f755",
            "llm_runtime_exit_observation.py": "c1aa0ab8889e2cbe2efd8cc80ae4f9bbb52b464aebc756a51cc5bd872c3dd086",
            "llm_runtime_exit_subset_observation.py": "c24af5385011acdf898a9b899f73f64c660c30dae0fadcda6e6957f80f501aff",
        }
        for name, expected in hashes.items():
            self.assertEqual(
                hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest(),
                expected,
            )
        profile = runtime.exit_observation_profile(worker.PROFILE)
        profile["observer_source_sha256"] = (
            "880502d0be61ba5d8b9598e46eb13a0ef4621c5606251f2c45696f57a90fe57b"
        )
        with self.assertRaisesRegex(ValueError, "OBSERVER_BINDING"):
            runtime.exit_observation_class(profile)


if __name__ == "__main__":
    unittest.main()
