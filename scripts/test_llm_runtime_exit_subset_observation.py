"""V3 boundary fixtures and real live-thread refusal; no model qualification."""
import copy
import builtins
import errno
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_subset_observation as subset
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_observation as exit_fixtures
import test_llm_runtime_rss_owner as owner_fixtures


class TerminalSubsetTests(unittest.TestCase):
    def setUp(self):
        self.fixture = exit_fixtures.ExitObservationTests()

    def observation(self, held, token):
        return subset.TerminalSubsetObservation(501, held, token,
            base._status(self.fixture.status()), time.monotonic_ns())

    def retire(self, root, name='10002'):
        # Explicit filesystem fixture, not evidence of an actual thread exit.
        (root/'task'/name).rename(root/('pending-'+name))
        names = list((root/'task').iterdir())
        for path in [root/'status', *(name/'status' for name in names)]:
            raw = path.read_text()
            for count in (1, 2, 3):
                raw = raw.replace('Threads:\t'+str(count), 'Threads:\t'+str(len(names)))
            path.write_text(raw)

    def test_subset_is_pending_and_keeps_all_original_handles_and_starts(self):
        with self.fixture.proc() as (root, held, token):
            observed = self.observation(held, token)
            handles, starts = dict(observed.task_fds), dict(observed.baseline_starts)
            original_sample_ns = observed.sample_started_ns
            try:
                self.retire(root)
                record = observed.recheck()
                self.assertEqual(record['transition'], 'pending-terminal-subset')
                self.assertEqual(record['tasks'], ['10001'])
                self.assertEqual(record['pending_retired_tasks'], ['10002'])
                self.assertEqual(observed.task_fds, handles)
                self.assertEqual(observed.baseline_starts, starts)
                self.assertEqual(observed.sample_started_ns, original_sample_ns)
                self.assertEqual(record['sample_started_ns'], original_sample_ns)
                for descriptor in handles.values(): os.fstat(descriptor)
                self.assertNotIn('rss_bytes', record)
                self.assertNotIn('retirement_closed_by', record)
                self.assertTrue(observed.belongs_to(501, held, token))
            finally: observed.close()
            for descriptor in handles.values():
                with self.assertRaises(OSError): os.fstat(descriptor)

    def test_initial_unknown_live_or_memory_task_cannot_be_laundered_by_later_shrink(self):
        for changes in (dict(flags=0), dict(flags=4|base.PF_KTHREAD), dict(vsize=4096), dict(rss=1)):
            with self.subTest(changes=changes), self.fixture.proc() as (root, held, token):
                (root/'task/10002/stat').write_text(self.fixture.stat(10002, 'R', **changes))
                with self.assertRaises(base.ExitObservationError): self.observation(held, token)
        with self.fixture.proc() as (root, held, token):
            observed = self.observation(held, token)
            try:
                (root/'task/10002/stat').write_text(self.fixture.stat(10002, 'R', flags=0))
                with self.assertRaises(base.ExitObservationError): observed.recheck()
                self.retire(root)
                with self.assertRaisesRegex(base.ExitObservationError, 'sticky-failure'): observed.recheck()
                self.assertFalse(observed.belongs_to(501, held, token))
            finally: observed.close()

    def test_addition_reappearance_and_cross_frontier_shrink_are_sticky(self):
        for mode in ('addition', 'reappearance', 'between-frontiers'):
            with self.subTest(mode=mode), self.fixture.proc() as (root, held, token):
                observed = self.observation(held, token)
                try:
                    if mode == 'addition': (root/'task/10003').mkdir()
                    elif mode == 'reappearance':
                        self.retire(root); observed.recheck(); (root/'task/10002').mkdir()
                    else:
                        original = observed._subset_frontier
                        def racing_frontier():
                            result = original()
                            if len(result[0]) == 2: self.retire(root)
                            return result
                        observed._subset_frontier = racing_frontier
                    with self.assertRaises(base.ExitObservationError): observed.recheck()
                    with self.assertRaisesRegex(base.ExitObservationError, 'sticky-failure'): observed.recheck()
                finally: observed.close()

    def test_shrink_with_remaining_running_task_is_refused(self):
        with self.fixture.proc() as (root, held, token):
            third = root/'task/10003'; third.mkdir()
            (third/'status').write_text(self.fixture.status(10003, 'R'))
            (third/'stat').write_text(self.fixture.stat(10003, 'R'))
            for path in [root/'status', *(p/'status' for p in (root/'task').iterdir())]:
                path.write_text(path.read_text().replace('Threads:\t2', 'Threads:\t3'))
            observed = self.observation(held, token)
            try:
                self.retire(root)
                with self.assertRaisesRegex(base.ExitObservationError, 'remaining-not-zombie'): observed.recheck()
                self.assertEqual(observed.active_names, ('10001', '10002', '10003'))
            finally: observed.close()

    def test_remaining_identity_memory_read_fault_and_retained_fd_reuse_refuse(self):
        for mode in ('starttime', 'namespace', 'memory', 'read-fault', 'retired-fd-reuse', 'owner'):
            with self.subTest(mode=mode), self.fixture.proc() as (root, held, token):
                observed = self.observation(held, token)
                try:
                    self.retire(root)
                    if mode == 'starttime':
                        (root/'task/10001/stat').write_text(self.fixture.stat(start=54321))
                    elif mode == 'namespace':
                        p = root/'task/10001/status'; p.write_text(p.read_text().replace('10001 501', '10001 502'))
                    elif mode == 'memory':
                        (root/'task/10001/stat').write_text(self.fixture.stat(rss=1))
                    elif mode == 'read-fault': (root/'task/10001/stat').unlink()
                    elif mode == 'retired-fd-reuse':
                        fd = os.open(root, os.O_RDONLY|os.O_DIRECTORY)
                        try: os.dup2(fd, observed.task_fds['10002'])
                        finally: os.close(fd)
                    else: observed.held_signature = (0, 0, 0)
                    with self.assertRaises((OSError, ValueError)): observed.recheck()
                    self.assertTrue(observed.failed)
                finally: observed.close()

    def test_original_deadline_and_real_receipt_requirements_remain(self):
        # Mocked wait states test dispatch only; they are not OS/model evidence.
        for mode in ('terminal', 'still-live', 'late', 'unknown', 'missing-rss', 'missing-cpu', 'owner'):
            with self.subTest(mode=mode), self.fixture.proc() as (root, held, token):
                observed = self.observation(held, token)
                self.retire(root); observed.recheck()
                child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                    waited_peak_rss_bytes=8192, waited_cpu_ns=1500,
                    reap=lambda: 'terminal' if mode not in ('still-live','unknown') else
                        'live' if mode == 'still-live' else 'unknown')
                if mode in ('late','still-live'): observed.sample_started_ns -= subset.MAX_DRAIN_NS+1
                if mode == 'missing-rss': child.waited_peak_rss_bytes = None
                if mode == 'missing-cpu': child.waited_cpu_ns = None
                try:
                    reason, record = runtime._drain_exit_cleanup(child, observed,
                        object() if mode == 'owner' else token, time.monotonic_ns(), dict(wall_seconds=2),
                        exit_observation=runtime.exit_observation_profile(subset.PROFILE))
                    self.assertEqual(record['outcome'], 'terminal-wait4' if mode == 'terminal' else 'failed')
                    if mode == 'terminal':
                        self.assertIsNone(reason)
                        self.assertEqual(record['terminal_retired_tasks'], ['10002'])
                        self.assertEqual(record['retirement_closed_by'], 'exact-owned-child-terminal-wait4')
                    else: self.assertEqual(reason, 'rss-exit-cleanup-observation-unavailable')
                finally: observed.close()

    def test_schema_profile_and_all_reused_sources_have_distinct_bindings(self):
        self.assertEqual(subset.MAX_DRAIN_NS, 100_000_000)
        self.assertEqual(subset.MAX_DRAIN_NS, base.MAX_DRAIN_NS)
        plans = [runtime.experiment_plan({'fixture': True}, exit_observation=p) for p in runtime.EXIT_PROFILES]
        self.assertEqual([runtime.plan_exit_profile(p) for p in plans], list(runtime.EXIT_PROFILES))
        self.assertEqual(len({runtime.identity(p) for p in plans}), 3)
        self.assertEqual(plans[2]['schema'], 'llm-runtime-public-pilot-plan-v3')
        for field in plans[2]['exit_observation']:
            changed = copy.deepcopy(plans[2]); changed['exit_observation'].pop(field)
            with self.subTest(missing=field), self.assertRaises(ValueError): runtime.validate_plan(changed)
        for schema in (plans[0]['schema'], plans[1]['schema']):
            changed = copy.deepcopy(plans[2]); changed['schema'] = schema
            with self.subTest(schema=schema), self.assertRaises(ValueError): runtime.validate_plan(changed)
        changed = copy.deepcopy(plans[1]); changed['schema'] = plans[2]['schema']
        with self.assertRaises(ValueError): runtime.validate_plan(changed)
        for field, value in (('maximum_drain_ns',100_000_001),
                             ('base_observer_source_sha256','0'*64),
                             ('observer_source_sha256','0'*64),
                             ('diagnostic_source_sha256','0'*64)):
            changed = copy.deepcopy(plans[2]); changed['exit_observation'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): runtime.validate_plan(changed)
        for name, key, value in (('training_budget','wall_seconds',1801),
                                ('training_budget','rss_bytes',16*1024**3+1),
                                ('inference_budget','wall_seconds',601),
                                ('inference_budget','rss_bytes',8*1024**3+1)):
            changed = copy.deepcopy(plans[2]); changed[name][key] = value
            with self.subTest(budget=name,key=key), self.assertRaises(ValueError): runtime.validate_plan(changed)

    def test_original_supervisor_caps_and_typed_profile_mismatch_fail_closed(self):
        # Existing exact-wait4 fixtures qualify predicates, not real resources.
        helper = owner_fixtures.RssSupervisionTests()
        for mode in ('valid','overcap','late','v2-under-v3','v3-under-v2'):
            with self.subTest(mode=mode), self.fixture.proc() as (root, held, _):
                child = helper.child_control(); child.termination_fd = held
                usage = helper.usage(peak=256*1024 if mode == 'overcap' else 8192)
                profile = base.PROFILE if mode == 'v3-under-v2' else subset.PROFILE
                expected_type = base.ExitOnlyObservation if profile == base.PROFILE else subset.TerminalSubsetObservation
                def observe(pid):
                    self.assertIs(runtime._RSS_EXIT_CLASS.get(), expected_type)
                    _, descriptor, owner = runtime._RSS_OWNER_CONTEXT.get()
                    if mode == 'v2-under-v3':
                        observed = base.ExitOnlyObservation(501, descriptor, owner,
                            base._status(self.fixture.status()), time.monotonic_ns())
                    else:
                        observed = self.observation(descriptor, owner)
                        self.retire(root); observed.recheck()
                    if mode == 'late': observed.sample_started_ns -= subset.MAX_DRAIN_NS+1
                    runtime._RSS_EXIT_OBSERVATION.set(observed)
                    return None
                with patch.object(runtime, '_Wait4Child', return_value=child), \
                        patch.object(runtime.os,'wait4',side_effect=[(0,0,None),(501,0,usage)]), \
                        patch.object(runtime,'current_rss',side_effect=observe), \
                        patch.object(runtime.signal,'pidfd_send_signal'):
                    result = runtime.supervise(['explicit owned-wait4 boundary fixture'], root/'result',
                        helper.BUDGET, exit_observation=runtime.exit_observation_profile(profile))
                self.assertEqual(result['outcome'], 'success' if mode == 'valid' else 'failed')
                self.assertEqual(result['stop_reason'], None if mode == 'valid' else
                    'rss-budget-exceeded' if mode == 'overcap' else 'rss-exit-cleanup-observation-unavailable')
                self.assertTrue(result['owned_child_reap_resolved'])

    def test_v2_plan_and_typed_terminal_path_never_import_the_v3_module(self):
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name == 'llm_runtime_exit_subset_observation':
                raise AssertionError('V2 must not execute an unbound V3 import')
            return original_import(name, *args, **kwargs)
        with self.fixture.proc() as (_, held, token):
            observed = base.ExitOnlyObservation(501, held, token,
                base._status(self.fixture.status()), time.monotonic_ns())
            child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                waited_peak_rss_bytes=8192, waited_cpu_ns=1500, reap=lambda:'terminal')
            try:
                with patch.object(builtins,'__import__',side_effect=guarded_import):
                    plan = runtime.experiment_plan({'fixture':True}, exit_observation=base.PROFILE)
                    runtime.validate_plan(plan)
                    self.assertIs(runtime.exit_observation_class(plan['exit_observation']), base.ExitOnlyObservation)
                    reason, record = runtime._drain_exit_cleanup(child, observed, token,
                        time.monotonic_ns(), dict(wall_seconds=2), exit_observation=plan['exit_observation'])
                self.assertIsNone(reason)
                self.assertEqual(record['outcome'], 'terminal-wait4')
            finally: observed.close()

    def test_same_call_failure_context_and_unknown_errno_remain_failed(self):
        with self.fixture.proc() as (root, held, token):
            observed = self.observation(held, token)
            (root/'task/10003').mkdir()
            child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                waited_peak_rss_bytes=8192, waited_cpu_ns=1500, reap=lambda:'live')
            try:
                reason, record = runtime._drain_exit_cleanup(child, observed, token,
                    time.monotonic_ns(), dict(wall_seconds=2),
                    exit_observation=runtime.exit_observation_profile(subset.PROFILE))
                self.assertEqual(reason, 'rss-exit-cleanup-observation-unavailable')
                self.assertEqual(record['recheck_refusal']['refusal_code'], 'exit-subset-task-set')
                self.assertEqual(record['same_call_subset_failure']['observed_tasks'], ['10001','10002','10003'])
                self.assertTrue(record['same_call_subset_failure']['diagnostic_only'])
            finally: observed.close()
        self.assertEqual(runtime._exit_recheck_refusal(OSError(errno.EIO,'private-canary'))['error_errno'], errno.EIO)

    def test_real_zombie_leader_with_live_userspace_thread_is_still_refused(self):
        program = ('import ctypes,threading,time;'
            'threading.Thread(target=lambda:time.sleep(5),daemon=True).start();'
            'ctypes.CDLL(None).pthread_exit(None)')
        with tempfile.TemporaryDirectory() as temporary:
            result = runtime.supervise([sys.executable,'-c',program], Path(temporary)/'live-thread',
                dict(wall_seconds=2,rss_bytes=128*1024**2),
                exit_observation=runtime.exit_observation_profile(subset.PROFILE))
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
        self.assertEqual(result['rss_gap_diagnostic']['leader_state'], 'Z')


if __name__ == '__main__': unittest.main()
