"""Initial-capture races are pending receipts, never measurements or model proof."""

import errno
import hashlib
import io
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_worker_observation as worker
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_worker_observation as worker_fixtures
import test_llm_runtime_rss_owner as owner_fixtures


class InitialTerminalPendingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = worker_fixtures.WorkerPidfdTests()

    def capture(self, state, mode):
        self.fixture.additional_worker(state)
        original_names, original_read = base._task_names, base._read
        count = 0
        triggered = False

        def names(descriptor):
            nonlocal count, triggered
            count += 1
            if mode == "task-set" and count == 2:
                triggered = True
                self.fixture.retire(state, "10003")
            return original_names(descriptor)

        def read(descriptor, component):
            nonlocal triggered
            path = os.readlink(f"/proc/self/fd/{descriptor}")
            if (
                mode == "enoent"
                and path.endswith("/10003")
                and component == "stat"
                and not triggered
            ):
                triggered = True
                self.fixture.retire(state, "10003")
            return original_read(descriptor, component)

        initial = base._status((state.root / "status").read_text())
        with (
            patch.object(base, "_task_names", side_effect=names),
            patch.object(base, "_read", side_effect=read),
        ):
            observed = worker.WorkerPidfdObservation(
                501, state.held, state.token, initial, time.monotonic_ns()
            )
        self.assertTrue(triggered)
        return observed

    def assert_pending(self, observed, state):
        self.assertFalse(observed.baseline_qualified)
        self.assertEqual(state.opened, [])
        self.assertEqual(
            observed.record["schema"], "llm-owned-initial-terminal-pending-v1"
        )
        self.assertEqual(
            observed.record["transition"], "initial-capture-pending-owned-wait4"
        )
        self.assertFalse(observed.record["complete_initial_classification"])
        self.assertNotIn("rss_bytes", observed.record)
        self.assertNotIn("retirement_closed_by", observed.record)
        self.assertTrue(observed.belongs_to(501, state.held, state.token))

    def test_initial_task_set_shrink_keeps_pending_until_exact_wait4(self):
        with self.fixture.proc() as state:
            observed = self.capture(state, "task-set")
            try:
                self.assert_pending(observed, state)
                calls = iter(("live", "terminal"))
                child = SimpleNamespace(
                    pid=501,
                    termination_fd=state.held,
                    observation_error=None,
                    waited_peak_rss_bytes=8192,
                    waited_cpu_ns=1500,
                    reap=lambda: next(calls),
                )
                reason, result = runtime._drain_exit_cleanup(
                    child,
                    observed,
                    state.token,
                    time.monotonic_ns(),
                    dict(wall_seconds=2),
                    exit_observation=runtime.exit_observation_profile(worker.PROFILE),
                )
                self.assertIsNone(reason)
                self.assertEqual(result["outcome"], "terminal-wait4")
                self.assertEqual(
                    result["retirement_closed_by"], "exact-owned-child-terminal-wait4"
                )
            finally:
                observed.close()

    def test_initial_worker_stat_enoent_retains_validated_prefix_without_full_proof(
        self,
    ):
        with self.fixture.proc() as state:
            observed = self.capture(state, "enoent")
            try:
                self.assert_pending(observed, state)
                self.assertEqual(
                    observed.record["interruptions"][0]["error_errno"], errno.ENOENT
                )
                self.assertEqual(
                    observed.record["interruptions"][0]["component"], "stat"
                )
                self.assertIn("10002", observed.record["validated_tasks"])
                self.assertEqual(
                    observed.record["validated_tasks"]["10002"]["state"], "R"
                )
                self.assertEqual(
                    observed.record["validated_tasks"]["10002"]["vsize"], 0
                )
                self.assertIsNotNone(observed.recheck())
            finally:
                observed.close()

    def test_constructor_refusal_is_retained_in_same_owner_slot_before_racing_terminal_wait4(
        self,
    ):
        with self.fixture.proc() as state:
            (state.root / "task/10002/stat").write_text(
                state.fixture.stat(10002, "R", flags=0)
            )
            context = runtime._RSS_OWNER_CONTEXT.set((501, state.held, state.token))
            selected = runtime._RSS_EXIT_CLASS.set(worker.WorkerPidfdObservation)
            output = runtime._RSS_EXIT_OBSERVATION.set(None)
            try:
                with self.assertRaises(ValueError):
                    self.fixture.observation(state)
                failed = runtime._RSS_EXIT_OBSERVATION.get()
                self.assertIs(type(failed), worker.WorkerPidfdObservation)
                self.assertFalse(failed.belongs_to(501, state.held, state.token))
                self.assertFalse(
                    failed.terminal_belongs_to(501, state.held, state.token)
                )
                self.assertTrue(failed.closed)
                self.assertEqual(failed.task_fds, {})
                os.fstat(state.held)
            finally:
                runtime._RSS_EXIT_OBSERVATION.reset(output)
                runtime._RSS_EXIT_CLASS.reset(selected)
                runtime._RSS_OWNER_CONTEXT.reset(context)

    def test_pending_late_wait4_uses_both_original_deadlines(self):
        for mode in ("sample", "whole"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                observed = self.capture(state, "task-set")
                now = [observed.sample_started_ns + 10_000_000]
                start = (
                    observed.sample_started_ns
                    if mode == "sample"
                    else observed.sample_started_ns - 1_950_000_000
                )
                deadline = min(
                    observed.sample_started_ns + worker.MAX_DRAIN_NS,
                    start + 2_000_000_000,
                )

                def reap():
                    now[0] = deadline + 1
                    return "terminal"

                child = SimpleNamespace(
                    pid=501,
                    termination_fd=state.held,
                    observation_error=None,
                    waited_peak_rss_bytes=8192,
                    waited_cpu_ns=1500,
                    reap=reap,
                )
                try:
                    with patch.object(
                        runtime.time, "monotonic_ns", side_effect=lambda: now[0]
                    ):
                        reason, record = runtime._drain_exit_cleanup(
                            child,
                            observed,
                            state.token,
                            start,
                            dict(wall_seconds=2),
                            exit_observation=runtime.exit_observation_profile(
                                worker.PROFILE
                            ),
                        )
                    self.assertIsNotNone(reason)
                    self.assertEqual(record["outcome"], "failed")
                finally:
                    observed.close()

    def test_pending_requires_exact_wait4_and_valid_nonzero_resources(self):
        helper = owner_fixtures.RssSupervisionTests()
        for mode in (
            "wrong-pid",
            "echild",
            "missing-rusage",
            "zero-rss",
            "negative-cpu",
        ):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                observed = self.capture(state, "task-set")
                child = helper.child_control()
                child.termination_fd = state.held
                receipt = (
                    502 if mode == "wrong-pid" else 501,
                    0,
                    None
                    if mode == "missing-rusage"
                    else helper.usage(
                        peak=0 if mode == "zero-rss" else 8192,
                        user=-1 if mode == "negative-cpu" else 0.01,
                    ),
                )
                fault = (
                    ChildProcessError(errno.ECHILD, "explicit fixture")
                    if mode == "echild"
                    else None
                )
                try:
                    with patch.object(
                        runtime.os, "wait4", side_effect=fault, return_value=receipt
                    ):
                        reason, record = runtime._drain_exit_cleanup(
                            child,
                            observed,
                            state.token,
                            time.monotonic_ns(),
                            dict(wall_seconds=2),
                            exit_observation=runtime.exit_observation_profile(
                                worker.PROFILE
                            ),
                        )
                    self.assertIsNotNone(reason)
                    self.assertEqual(record["outcome"], "failed")
                    self.assertIsNotNone(child.observation_error)
                finally:
                    observed.close()

    def test_pending_full_owner_rejects_overcap_nonzero_exit_and_timeout_despite_final_exit0(
        self,
    ):
        helper = owner_fixtures.RssSupervisionTests()
        for mode in ("valid", "overcap", "nonzero", "late"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                child = helper.child_control()
                child.termination_fd = state.held

                def observe(_):
                    state.token = runtime._RSS_OWNER_CONTEXT.get()[2]
                    observed = self.capture(state, "task-set")
                    if mode == "late":
                        observed.sample_started_ns -= worker.MAX_DRAIN_NS + 1
                    runtime._RSS_EXIT_OBSERVATION.set(observed)
                    return None

                usage = helper.usage(peak=256 * 1024 if mode == "overcap" else 8192)
                with (
                    patch.object(runtime, "_Wait4Child", return_value=child),
                    patch.object(
                        runtime.os,
                        "wait4",
                        side_effect=[
                            (0, 0, None),
                            (501, 256 if mode == "nonzero" else 0, usage),
                        ],
                    ),
                    patch.object(runtime, "current_rss", side_effect=observe),
                    patch.object(runtime.signal, "pidfd_send_signal"),
                ):
                    result = runtime.supervise(
                        ["synthetic initial capture; exact original wait4 owner"],
                        state.root / "result",
                        helper.BUDGET,
                        exit_observation=runtime.exit_observation_profile(
                            worker.PROFILE
                        ),
                    )
                self.assertEqual(
                    result["outcome"], "success" if mode == "valid" else "failed"
                )
                self.assertTrue(result["waited_child_reaped"])
                if mode == "overcap":
                    self.assertEqual(result["stop_reason"], "rss-budget-exceeded")
                if mode == "late":
                    self.assertEqual(result["exit_code"], 0)
                    self.assertEqual(
                        result["exit_cleanup_observation"]["outcome"], "failed"
                    )

    def test_observed_bad_status_or_stat_cannot_be_erased_by_later_enoent(self):
        for mode in (
            "pid",
            "parent",
            "namespace",
            "rss",
            "state",
            "flags",
            "kthread",
            "vsize",
            "pages",
        ):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                self.fixture.additional_worker(state)
                original = base._read
                component = (
                    "stat"
                    if mode in ("flags", "kthread", "vsize", "pages")
                    else "status"
                )

                def read(descriptor, name):
                    raw = original(descriptor, name)
                    if (
                        os.readlink(f"/proc/self/fd/{descriptor}").endswith("/10003")
                        and name == component
                    ):
                        if name == "stat":
                            raw = state.fixture.stat(
                                10003,
                                "Z",
                                flags=0
                                if mode == "flags"
                                else 4 | base.PF_KTHREAD
                                if mode == "kthread"
                                else 4,
                                vsize=4096 if mode == "vsize" else 0,
                                rss=1 if mode == "pages" else 0,
                            )
                        else:
                            changes = {
                                "pid": ("Pid:\t10003", "Pid:\t10009"),
                                "parent": ("PPid:\t10000", "PPid:\t10009"),
                                "namespace": ("NSpid:\t10003 503", "NSpid:\t10009 503"),
                                "state": ("State:\tZ", "State:\tQ"),
                            }
                            raw = (
                                raw + "VmRSS:\t0 kB\n"
                                if mode == "rss"
                                else raw.replace(*changes[mode])
                            )
                        self.fixture.retire(state, "10003")
                    return raw

                with (
                    patch.object(base, "_read", side_effect=read),
                    self.assertRaises(ValueError),
                ):
                    self.fixture.observation(state)

    def test_successful_task_count_decrease_cannot_rebound_before_or_after_enoent(self):
        for mode in ("next-task", "next-leader", "then-enoent"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                self.fixture.additional_worker(state)
                original = base._read
                changed = False

                def read(descriptor, component):
                    nonlocal changed
                    path = os.readlink(f"/proc/self/fd/{descriptor}")
                    raw = original(descriptor, component)
                    target = "10002" if mode == "next-task" else "10003"
                    if (
                        path.endswith("/" + target)
                        and component == "status"
                        and not changed
                    ):
                        changed = True
                        if mode == "then-enoent":
                            self.fixture.retire(state, target)
                            leader = state.root / "status"
                            leader.write_text(
                                leader.read_text().replace("Threads:\t2", "Threads:\t3")
                            )
                        return raw.replace("Threads:\t3", "Threads:\t2")
                    return raw

                with (
                    patch.object(base, "_read", side_effect=read),
                    self.assertRaises(ValueError),
                ):
                    self.fixture.observation(state)
                self.assertTrue(changed)

    def test_unknown_reads_malformed_fields_and_partial_constructor_fds_refuse(self):
        for mode in ("eacces", "eio", "malformed"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                original_read, original_open = base._read, worker.os.open
                opened = []

                def open_fd(*args, **kwargs):
                    descriptor = original_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                def read(descriptor, name):
                    if (
                        os.readlink(f"/proc/self/fd/{descriptor}").endswith("/10002")
                        and name == "status"
                    ):
                        if mode == "malformed":
                            return "malformed\n"
                        raise OSError(
                            errno.EACCES if mode == "eacces" else errno.EIO,
                            "explicit fixture",
                        )
                    return original_read(descriptor, name)

                with (
                    patch.object(worker.os, "open", side_effect=open_fd),
                    patch.object(base, "_read", side_effect=read),
                    self.assertRaises((OSError, ValueError, KeyError)),
                ):
                    self.fixture.observation(state)
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                os.fstat(state.held)

    def test_pending_new_tid_reappearance_changed_birth_and_reused_fd_are_sticky(self):
        for mode in ("new-tid", "reappear", "birth", "task-fd", "owner-fd"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                observed = self.capture(state, "task-set")
                if mode in ("new-tid", "reappear"):
                    (
                        state.root
                        / "task"
                        / ("10004" if mode == "new-tid" else "10003")
                    ).mkdir()
                elif mode == "birth":
                    (state.root / "task/10002/stat").write_text(
                        state.fixture.stat(10002, "R", start=999)
                    )
                else:
                    replacement = os.open(state.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.dup2(
                            replacement,
                            state.held
                            if mode == "owner-fd"
                            else observed.task_fds["10002"],
                        )
                    finally:
                        os.close(replacement)
                try:
                    with self.assertRaises(ValueError):
                        observed.recheck()
                    self.assertFalse(
                        observed.terminal_belongs_to(501, state.held, state.token)
                    )
                    with self.assertRaisesRegex(ValueError, "sticky-failure"):
                        observed.recheck()
                finally:
                    observed.close()

    def test_actual_current_rss_failed_constructor_blocks_immediate_terminal_in_import_and_main(
        self,
    ):
        # Execute the unchanged pilot definitions in a second, distinct module;
        # its ContextVars must be used when the real entry point is __main__.
        main = ModuleType("explicit_pilot_definitions_without_cli")
        main.__file__ = runtime.__file__
        exec(
            compile(Path(runtime.__file__).read_bytes(), runtime.__file__, "exec"),
            main.__dict__,
        )
        main.__name__ = "__main__"
        helper = owner_fixtures.RssSupervisionTests()
        for module in (runtime, main):
            with self.subTest(module=module.__name__), self.fixture.proc() as state:
                (state.root / "task/10002/stat").write_text(
                    state.fixture.stat(10002, "R", flags=0)
                )
                child = helper.child_control()
                child.termination_fd = state.held
                original_open = Path.open
                identity = "Pid:\t10001\nNSpid:\t10001 501\n"
                proc = {
                    "/proc/self/status": "Pid:\t10000\nNSpid:\t10000 500\n",
                    f"/proc/self/fdinfo/{state.held}": identity,
                    "/proc/10001/status": state.fixture.status(),
                }

                def open_path(path, *args, **kwargs):
                    return (
                        io.StringIO(proc[str(path)])
                        if str(path) in proc
                        else original_open(path, *args, **kwargs)
                    )

                profile = module.exit_observation_profile(worker.PROFILE)
                with (
                    patch.dict(sys.modules, {"__main__": main}),
                    patch.object(module, "_Wait4Child", return_value=child),
                    patch.object(module.os, "getpid", return_value=500),
                    patch.object(
                        module.os,
                        "wait4",
                        side_effect=[(0, 0, None), (501, 0, helper.usage())],
                    ),
                    patch.object(module.signal, "pidfd_send_signal"),
                    patch.object(Path, "open", open_path),
                ):
                    result = module.supervise(
                        ["real current_rss, synthetic proc and wait4"],
                        state.root / "result",
                        helper.BUDGET,
                        exit_observation=profile,
                    )
                self.assertEqual(result["exit_code"], 0)
                self.assertTrue(result["waited_child_reaped"])
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(
                    result["stop_reason"], "rss-exit-cleanup-observation-unavailable"
                )
                self.assertEqual(
                    result["rss_gap_diagnostic"]["missing_sample_detail"][
                        "same_sample_exit_classification"
                    ]["result"],
                    "unavailable",
                )

    def test_failed_slot_never_overwrites_an_earlier_result_or_foreign_owner(self):
        for mode in ("prior", "wrong-token", "wrong-pid", "wrong-fd", "wrong-class"):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                (state.root / "task/10002/stat").write_text(
                    state.fixture.stat(10002, "R", flags=0)
                )
                prior = object() if mode == "prior" else None
                context = runtime._RSS_OWNER_CONTEXT.set(
                    (
                        502 if mode == "wrong-pid" else 501,
                        state.held + 100 if mode == "wrong-fd" else state.held,
                        object() if mode == "wrong-token" else state.token,
                    )
                )
                selected = runtime._RSS_EXIT_CLASS.set(
                    base.ExitOnlyObservation
                    if mode == "wrong-class"
                    else worker.WorkerPidfdObservation
                )
                output = runtime._RSS_EXIT_OBSERVATION.set(prior)
                try:
                    with self.assertRaises(ValueError):
                        self.fixture.observation(state)
                    self.assertIs(runtime._RSS_EXIT_OBSERVATION.get(), prior)
                finally:
                    runtime._RSS_EXIT_OBSERVATION.reset(output)
                    runtime._RSS_EXIT_CLASS.reset(selected)
                    runtime._RSS_OWNER_CONTEXT.reset(context)

    def test_frozen_original_model_and_v2_v3_bytes_and_old_v4_profile_refusal(self):
        expected = {
            "llm_runtime_pilot.py": "65ccc6454befd96fa5ce1f5bdde2c56cb6cbb741cf495b8d24a758039f99f755",
            "llm_runtime_exit_observation.py": "c1aa0ab8889e2cbe2efd8cc80ae4f9bbb52b464aebc756a51cc5bd872c3dd086",
            "llm_runtime_exit_subset_observation.py": "c24af5385011acdf898a9b899f73f64c660c30dae0fadcda6e6957f80f501aff",
        }
        for name, digest in expected.items():
            self.assertEqual(
                hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest(),
                digest,
            )
        profile = runtime.exit_observation_profile(worker.PROFILE)
        profile["observer_source_sha256"] = (
            "aae68f92393e5e88c5aaa02095b5990200c121834bec05d8b3a11cd3f09ffc50"
        )
        with self.assertRaisesRegex(ValueError, "OBSERVER_BINDING"):
            runtime.exit_observation_class(profile)
        self.assertNotIn(
            "exit_observation", runtime.experiment_plan({"explicit": "fixture"})
        )
        with patch.object(
            worker,
            "_InitialTerminalPending",
            side_effect=AssertionError("new path forbidden"),
        ):
            for name in runtime.EXIT_PROFILES[1:3]:
                with self.fixture.proc() as state:
                    observed = runtime.exit_observation_class(
                        runtime.exit_observation_profile(name)
                    )(
                        501,
                        state.held,
                        state.token,
                        base._status(state.fixture.status()),
                        time.monotonic_ns(),
                    )
                    observed.close()

    def test_real_owned_wait4_closes_only_synthetic_initial_roster_gap(self):
        # Only the initial extra task/count is a race fixture. The child, proc
        # identities, held pidfd, exclusive wait4 and resource receipt are real.
        child = None
        observed = None
        start = time.monotonic_ns()
        try:
            child = runtime._Wait4Child(
                [sys.executable, "-c", "x=bytearray(16*1024*1024);print(len(x))"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            poller = select.poll()
            poller.register(child.termination_fd, select.POLLIN)
            self.assertTrue(
                poller.poll(1000),
                "actual child must finish within the original two-second owner budget",
            )
            identity = base._pidfd_identity(child.pid, child.termination_fd)
            leader = base._proc_fields(Path(f"/proc/{identity[0]}/status"))
            self.assertEqual(leader["State"][0], "Z")
            self.assertNotIn("VmRSS", leader)
            leader["Threads"] = ["2"]  # Explicit synthetic initial count.
            absent = "2147483647"
            self.assertFalse(Path(f"/proc/{identity[0]}/task/{absent}").exists())
            original = base._task_names
            calls = 0

            def names(descriptor):
                nonlocal calls
                calls += 1
                actual = original(descriptor)
                return (
                    tuple(sorted((*actual, absent), key=int)) if calls == 1 else actual
                )

            owner = object()
            with patch.object(base, "_task_names", side_effect=names):
                observed = worker.WorkerPidfdObservation(
                    child.pid, child.termination_fd, owner, leader, time.monotonic_ns()
                )
            reason, result = runtime._drain_exit_cleanup(
                child,
                observed,
                owner,
                start,
                dict(wall_seconds=2),
                exit_observation=runtime.exit_observation_profile(worker.PROFILE),
            )
            self.assertIsNone(reason)
            self.assertEqual(result["outcome"], "terminal-wait4")
            self.assertEqual(child.returncode, 0)
            self.assertTrue(child.reaped)
            self.assertGreater(child.waited_peak_rss_bytes, 0)
            self.assertGreaterEqual(child.waited_cpu_ns, 0)
            self.assertLessEqual(
                result["completed_ns"], observed.sample_started_ns + worker.MAX_DRAIN_NS
            )
            self.assertEqual(
                base._proc_fields(Path(f"/proc/self/fdinfo/{child.termination_fd}"))[
                    "Pid"
                ],
                ["-1"],
            )
        finally:
            if observed is not None:
                observed.close()
            if child is not None:
                child.finish()


if __name__ == "__main__":
    unittest.main()
