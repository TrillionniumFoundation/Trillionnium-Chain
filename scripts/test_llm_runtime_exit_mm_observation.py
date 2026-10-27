"""V5 original-sample controls; fixtures are not model or kernel evidence."""
import builtins
import contextlib
import copy
import errno
import io
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_mm_observation as mm
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_observation as exit_controls
import test_llm_runtime_rss_owner as owner_controls


class MmObservationTests(unittest.TestCase):
    @contextlib.contextmanager
    def proc(self, state='R', flags=base.PF_EXITING):
        fixture = exit_controls.ExitObservationTests()
        with fixture.proc() as (root, held, token):
            (root/'stat').write_text(fixture.stat(state=state, flags=flags))
            (root/'status').write_text(fixture.status(state=state))
            (root/'task/10001/stat').write_text(fixture.stat(state=state, flags=flags))
            (root/'task/10001/status').write_text(fixture.status(state=state))
            yield root, held, token, fixture

    def observe(self, held, token):
        sample = mm._BeforeStatusSample(501, held, token)
        try:
            return sample.finish(sample.fields, sample.sample_started_ns)
        finally:
            sample.close()

    def test_r_state_requires_prior_complete_pf_exiting_and_no_memory_credit(self):
        with self.proc() as (_, held, token, _):
            observed = self.observe(held, token)
            try:
                value = observed.recheck()
                self.assertEqual(value['profile'], mm.PROFILE)
                self.assertEqual(value['original_leader_state'], 'R')
                self.assertEqual(set(value['prior_stat_frontier']), {'10001', '10002'})
                self.assertLessEqual(value['prior_frontier_completed_ns'], value['sample_started_ns'])
                self.assertFalse(value['resource_release_authorized'])
                self.assertFalse(value['arbitrary_process_descendants_closed'])
                self.assertNotIn('rss_bytes', value)
                self.assertTrue(observed.belongs_to(501, held, token))
            finally:
                observed.close()
            os.fstat(held)

    def test_old_zombie_only_profile_still_refuses_running_leader(self):
        with self.proc() as (root, held, token, _):
            with self.assertRaisesRegex(base.ExitObservationError, 'exit-leader'):
                base.ExitOnlyObservation(501, held, token,
                    base._status((root/'status').read_text()), time.monotonic_ns())

    def test_later_pf_exiting_cannot_retrofit_original_missing_sample(self):
        with self.proc(flags=0) as (root, held, token, fixture):
            sample = mm._BeforeStatusSample(501, held, token)
            try:
                (root/'stat').write_text(fixture.stat(state='R'))
                (root/'task/10001/stat').write_text(fixture.stat(state='R'))
                with self.assertRaisesRegex(base.ExitObservationError, 'no-prior-frontier'):
                    sample.finish(sample.fields, sample.sample_started_ns)
            finally:
                sample.close()

    def test_live_kthread_memory_and_wrong_prior_identity_refuse(self):
        for change in [dict(flags=0), dict(flags=4 | base.PF_KTHREAD), dict(vsize=4096),
                       dict(rss=1), dict(state='T'), dict(pid=10003)]:
            with self.subTest(change=change), self.proc() as (root, held, token, fixture):
                values = dict(pid=10002, state='R'); values.update(change)
                (root/'task/10002/stat').write_text(fixture.stat(**values))
                with self.assertRaises(base.ExitObservationError):
                    self.observe(held, token)

    def test_complete_bounded_thread_set_is_required(self):
        for mode in ('missing-leader', 'new-task', 'too-many'):
            with self.subTest(mode=mode), self.proc() as (root, held, token, _):
                if mode == 'missing-leader':
                    (root/'task/10001').rename(root/'task/10003')
                elif mode == 'too-many':
                    for tid in range(10003, 10003+base.MAX_TASKS):
                        (root/'task'/str(tid)).mkdir()
                if mode == 'new-task':
                    sample = mm._BeforeStatusSample(501, held, token)
                    try:
                        (root/'task/10003').mkdir()
                        with self.assertRaises(base.ExitObservationError):
                            sample.finish(sample.fields, sample.sample_started_ns)
                    finally:
                        sample.close()
                else:
                    with self.assertRaises(base.ExitObservationError): self.observe(held, token)

    def test_copied_diagnostic_wrong_timestamp_and_plain_dict_cannot_grant_authority(self):
        with self.proc() as (_, held, token, _):
            sample = mm._BeforeStatusSample(501, held, token)
            try:
                for fields, timestamp in ((copy.deepcopy(sample.fields), sample.sample_started_ns),
                                          (sample.fields, sample.sample_started_ns+1)):
                    with self.assertRaisesRegex(base.ExitObservationError, 'no-prior-frontier'):
                        sample.finish(fields, timestamp)
                with self.assertRaisesRegex(base.ExitObservationError, 'same-sample-capability'):
                    mm.MmDetachedObservation(dict(sample.__dict__), sample.fields, sample.sample_started_ns)
            finally:
                sample.close()

    def test_starttime_change_between_original_sample_and_capture_refuses(self):
        with self.proc() as (root, held, token, fixture):
            sample = mm._BeforeStatusSample(501, held, token)
            try:
                (root/'task/10002/stat').write_text(fixture.stat(10002, 'R', start=999))
                with self.assertRaisesRegex(base.ExitObservationError, 'prior-starttime'):
                    sample.finish(sample.fields, sample.sample_started_ns)
            finally:
                sample.close()

    def test_namespace_count_observable_rss_and_changed_frontier_refuse(self):
        for mode in ('namespace', 'count', 'rss', 'starttime', 'live'):
            with self.subTest(mode=mode), self.proc() as (root, held, token, fixture):
                observed = self.observe(held, token)
                try:
                    if mode in ('starttime', 'live'):
                        (root/'task/10002/stat').write_text(fixture.stat(10002, 'R',
                            start=999 if mode == 'starttime' else 12345,
                            flags=0 if mode == 'live' else 4))
                    else:
                        value = fixture.status(10002, 'R')
                        if mode == 'namespace': value = value.replace('NStgid:\t10001 501', 'NStgid:\t10001 502')
                        if mode == 'count': value = value.replace('Threads:\t2', 'Threads:\t3')
                        if mode == 'rss': value += 'VmRSS:\t0 kB\n'
                        (root/'task/10002/status').write_text(value)
                    with self.assertRaises(base.ExitObservationError): observed.recheck()
                finally:
                    observed.close()

    def test_held_descriptor_reuse_and_pidfd_identity_change_refuse(self):
        for mode in ('task-fd', 'pidfd-identity'):
            with self.subTest(mode=mode), self.proc() as (root, held, token, _):
                observed = self.observe(held, token)
                try:
                    if mode == 'task-fd':
                        replacement = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                        try: os.dup2(replacement, observed.task_fds['10002'])
                        finally: os.close(replacement)
                        with self.assertRaises(base.ExitObservationError): observed.recheck()
                    else:
                        with patch.object(base, '_pidfd_identity', return_value=(10001,10000,(10001,502))):
                            with self.assertRaises(base.ExitObservationError): observed.recheck()
                finally:
                    observed.close()

    def test_current_rss_keeps_one_original_status_boundary(self):
        for active in (False, True):
            with self.subTest(active=active), self.proc(flags=0 if active else 4) as (root, held, token, _):
                if active: (root/'status').write_text((root/'status').read_text()+'VmRSS:\t8192 kB\n')
                contexts = [(runtime._RSS_OWNER_CONTEXT, (501,held,token)),
                    (runtime._RSS_EXIT_CLASS, mm.MmDetachedObservation),
                    (runtime._RSS_EXIT_OBSERVATION, None), (runtime._RSS_READ_TRACE, {})]
                tokens = [(var, var.set(value)) for var,value in contexts]
                original = Path.open
                def opened(path, *args, **kwargs):
                    if str(path) == '/proc/self/status':
                        return io.StringIO('Pid: 10000\nNSpid: 10000 500\n')
                    if str(path) == f'/proc/self/fdinfo/{held}':
                        return io.StringIO('Pid: 10001\nNSpid: 10001 501\n')
                    return original(path, *args, **kwargs)
                try:
                    with patch.object(Path, 'open', opened), patch.object(runtime.os, 'getpid', return_value=500):
                        result = runtime.current_rss(501)
                    observed = runtime._RSS_EXIT_OBSERVATION.get()
                    if active:
                        self.assertEqual(result, 8192*1024); self.assertIsNone(observed)
                    else:
                        self.assertIsNone(result); self.assertIs(type(observed), mm.MmDetachedObservation)
                        self.assertEqual(runtime._RSS_READ_TRACE.get()['same_sample_exit_classification']['result'],
                                         'typed-observation-created')
                        observed.close()
                    os.fstat(held)
                finally:
                    for var, token in reversed(tokens): var.reset(token)

    def test_new_plan_source_and_drain_cap_are_exact_and_old_default_unchanged(self):
        self.assertEqual(runtime.experiment_plan({'fixture':True})['schema'], 'llm-runtime-public-pilot-plan-v1')
        plan = runtime.experiment_plan({'fixture':True}, exit_observation=mm.PROFILE)
        self.assertEqual(runtime.validate_plan(plan)['schema'], 'llm-runtime-public-pilot-plan-v5')
        self.assertIs(runtime.exit_observation_class(plan['exit_observation']), mm.MmDetachedObservation)
        for field, value in [('profile', base.PROFILE), ('maximum_drain_ns',100_000_001),
                            ('observer_source_sha256','0'*64), ('base_observer_source_sha256','0'*64)]:
            changed = copy.deepcopy(plan); changed['exit_observation'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): runtime.validate_plan(changed)
        changed = copy.deepcopy(plan); changed['schema'] = 'llm-runtime-public-pilot-plan-v2'
        with self.assertRaises(ValueError): runtime.validate_plan(changed)

    def test_legacy_owned_rss_does_not_import_the_v5_dependency(self):
        imported = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == 'llm_runtime_exit_mm_observation':
                raise AssertionError('legacy profile imported V5')
            return imported(name, *args, **kwargs)
        for profile in runtime.EXIT_PROFILES[1:4]:
            selected = runtime.exit_observation_class(runtime.exit_observation_profile(profile))
            owner = runtime._RSS_OWNER_CONTEXT.set((501,17,object()))
            kind = runtime._RSS_EXIT_CLASS.set(selected)
            try:
                with self.subTest(profile=profile), owner_controls.RssIdentityTests().proc() as (_, opened, closed), \
                        patch.object(builtins, '__import__', side_effect=guard):
                    self.assertEqual(runtime.current_rss(501), 8192*1024)
                    opened.assert_not_called(); closed.assert_not_called()
            finally:
                runtime._RSS_EXIT_CLASS.reset(kind); runtime._RSS_OWNER_CONTEXT.reset(owner)

    def test_expired_wall_unknown_owner_and_invalid_wait4_refuse(self):
        for mode in ('drain', 'wall', 'unknown', 'owner', 'invalid-receipt', 'changed-task'):
            with self.subTest(mode=mode), self.proc() as (root, held, token, _):
                observed = self.observe(held, token)
                child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                    waited_peak_rss_bytes=8192, waited_cpu_ns=1500, reap=lambda:'live')
                start = time.monotonic_ns()
                if mode == 'drain': observed.sample_started_ns -= mm.MAX_DRAIN_NS+1
                if mode == 'wall': start -= 3*10**9
                if mode == 'unknown': child.reap = lambda:'unknown'
                if mode == 'changed-task': (root/'task/10003').mkdir()
                if mode == 'invalid-receipt': child.reap=lambda:'terminal'; child.waited_cpu_ns=None
                try:
                    reason, record = runtime._drain_exit_cleanup(child, observed,
                        object() if mode == 'owner' else token, start, dict(wall_seconds=2),
                        exit_observation=runtime.exit_observation_profile(mm.PROFILE))
                    self.assertEqual(reason, 'rss-exit-cleanup-observation-unavailable')
                    self.assertEqual(record['outcome'], 'failed')
                finally:
                    observed.close()

    def test_original_wait4_and_rss_cap_still_control_supervisor_outcome(self):
        helper = owner_controls.RssSupervisionTests()
        for mode in ('valid', 'overcap', 'invalid', 'unknown', 'late', 'missing-frontier'):
            with self.subTest(mode=mode), self.proc() as (root, held, _, _):
                child = helper.child_control(); child.termination_fd = held
                usage = helper.usage(peak=256*1024 if mode == 'overcap' else 0 if mode == 'invalid' else 8192)
                waits = [(0,0,None)] + ([OSError(errno.EIO,'controlled wait4 unknown')] if mode == 'unknown' else [])
                waits += [(501,0,usage)]
                def observe(_):
                    if mode != 'missing-frontier':
                        _, descriptor, owner = runtime._RSS_OWNER_CONTEXT.get()
                        observed = self.observe(descriptor, owner)
                        if mode == 'late': observed.sample_started_ns -= mm.MAX_DRAIN_NS+1
                        runtime._RSS_EXIT_OBSERVATION.set(observed)
                    return None
                with patch.object(runtime,'_Wait4Child',return_value=child), \
                        patch.object(runtime.os,'wait4',side_effect=waits), \
                        patch.object(runtime,'current_rss',side_effect=observe), \
                        patch.object(runtime.signal,'pidfd_send_signal'), \
                        patch.object(runtime,'reconcile_unobserved_exit',side_effect=AssertionError('no retrospective fallback')):
                    result = runtime.supervise(['explicit fixture'], root/'result', helper.BUDGET,
                        exit_observation=runtime.exit_observation_profile(mm.PROFILE))
                self.assertEqual(result['outcome'], 'success' if mode == 'valid' else 'failed')
                self.assertEqual(result['stop_reason'], None if mode == 'valid' else
                    'rss-budget-exceeded' if mode == 'overcap' else 'rss-exit-cleanup-observation-unavailable')
                self.assertEqual(result['exit_code'], 0)
                self.assertTrue(result['waited_child_reaped'])
                if mode == 'valid': self.assertEqual(result['waited_child_peak_rss_bytes'], 8192*1024)


if __name__ == '__main__':
    unittest.main()
