"""V4 adversarial fixtures and own tiny-child ABI tests; no model qualification."""
import builtins
import contextlib
import copy
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_subset_observation as subset
import llm_runtime_exit_worker_observation as worker
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_observation as fixtures
import test_llm_runtime_rss_owner as owner_fixtures


class WorkerPidfdTests(unittest.TestCase):
    @contextlib.contextmanager
    def proc(self):
        fixture = fixtures.ExitObservationTests()
        with fixture.proc() as (root, held, token):
            control = root/'explicit-fake-pidfd'; control.write_text('fixture, not kernel evidence\n')
            state = SimpleNamespace(root=root, held=held, token=token, fixture=fixture,
                                    terminal=set(), events=None, identities={}, opened=[])
            def opened(pid, flags):
                self.assertEqual(flags, worker.PIDFD_THREAD)
                descriptor = os.open(control, os.O_RDONLY)
                state.identities[descriptor] = str(pid+9500)
                state.opened.append((pid, flags))
                return descriptor
            original_fields = base._proc_fields
            def fields(path):
                if str(path) == '/proc/self/status':
                    return dict(Pid=['10000'], NSpid=['10000', str(os.getpid())])
                if str(path).startswith('/proc/self/fdinfo/'):
                    descriptor = int(path.name)
                    name = state.identities[descriptor]
                    return dict(Pid=[name], NSpid=[name, str(int(name)-9500)])
                return original_fields(path)
            class Poll:
                def register(self, descriptor, mask): self.descriptor = descriptor
                def poll(self, timeout):
                    if state.events is not None: return state.events(self.descriptor)
                    return [(self.descriptor, select.POLLIN|select.POLLHUP)] if state.identities[self.descriptor] in state.terminal else []
            with patch.object(worker.os, 'pidfd_open', side_effect=opened), \
                    patch.object(base, '_proc_fields', side_effect=fields), \
                    patch.object(worker.select, 'poll', Poll):
                yield state

    def observation(self, state):
        return worker.WorkerPidfdObservation(501, state.held, state.token,
            base._status(state.fixture.status()), time.monotonic_ns())

    def retire(self, state, name='10002'):
        state.terminal.add(name)
        directory = state.root/'task'/name
        for path in directory.iterdir(): path.unlink()
        directory.rename(state.root/('retired-'+name))
        names = list((state.root/'task').iterdir())
        for path in [state.root/'status', *(p/'status' for p in names)]:
            path.write_text(''.join('Threads:\t'+str(len(names))+'\n' if line.startswith('Threads:') else line
                for line in path.read_text().splitlines(keepends=True)))

    def additional_worker(self, state):
        third=state.root/'task/10003'; third.mkdir()
        (third/'status').write_text(state.fixture.status(10003,'Z'))
        (third/'stat').write_text(state.fixture.stat(10003,'Z'))
        for path in [state.root/'status', *(p/'status' for p in (state.root/'task').iterdir())]:
            path.write_text(path.read_text().replace('Threads:\t2','Threads:\t3'))

    def test_full_initial_binding_worker_terminal_pending_and_all_handles_retained(self):
        with self.proc() as state:
            observed = self.observation(state)
            handles = [*observed.task_fds.values(), *observed.thread_fds.values()]
            try:
                self.assertEqual(state.opened, [(502, worker.PIDFD_THREAD)])
                self.assertEqual(observed.bindings['10002']['namespace'], (10002,502))
                self.retire(state)
                record = observed.recheck()
                self.assertEqual(record['tasks'], ['10001'])
                self.assertEqual(record['pending_retired_tasks'], ['10002'])
                self.assertEqual(record['worker_terminal_events']['10002']['revents'], 17)
                self.assertNotIn('rss_bytes', record)
                self.assertNotIn('retirement_closed_by', record)
                self.assertTrue(observed.belongs_to(501,state.held,state.token))
                for descriptor in handles: os.fstat(descriptor)
            finally: observed.close()
            for descriptor in handles:
                with self.assertRaises(OSError): os.fstat(descriptor)
            os.fstat(state.held)

    def test_midfrontier_enoent_requires_two_new_complete_frontiers_in_same_call(self):
        with self.proc() as state:
            observed = self.observation(state)
            original = base._read; triggered = False
            def read(directory, name):
                nonlocal triggered
                if directory == observed.task_fds['10002'] and name == 'stat' and not triggered:
                    triggered = True; self.retire(state)
                return original(directory,name)
            try:
                with patch.object(base,'_read',side_effect=read): record = observed.recheck()
                self.assertEqual(record['frontier_before'], record['frontier_after'])
                self.assertEqual(record['tasks'], ['10001'])
                self.assertEqual(len(record['interrupted_frontiers']), 1)
                self.assertEqual(record['interrupted_frontiers'][0]['error_errno'], errno.ENOENT)
                self.assertEqual(record['interrupted_frontiers'][0]['reading_component'], 'stat')
                self.assertEqual(record['worker_terminal_events']['10002']['read_errno'], errno.ENOENT)
            finally: observed.close()

    def test_observed_bad_status_cannot_be_erased_by_later_stat_enoent_and_event(self):
        for component in ('status','stat'):
            with self.subTest(component=component), self.proc() as state:
                observed = self.observation(state); original=base._read
                def read(descriptor,name):
                    raw=original(descriptor,name)
                    if descriptor==observed.task_fds['10002'] and name==component:
                        raw=raw+'VmRSS:\t0 kB\n' if name=='status' else state.fixture.stat(10002,'R',flags=0)
                        self.retire(state)
                    return raw
                try:
                    with patch.object(base,'_read',side_effect=read), self.assertRaisesRegex(ValueError,'not-exit-only'):
                        observed.recheck()
                    self.assertIn('10002',state.terminal)
                    with self.assertRaisesRegex(ValueError,'sticky-failure'): observed.recheck()
                    self.assertFalse(observed.belongs_to(501,state.held,state.token))
                finally: observed.close()

    def test_acquisition_or_two_complete_frontiers_crossing_original_deadline_refuse(self):
        with self.proc() as state:
            original=worker.WorkerPidfdObservation._check_bindings
            def late(observed):
                original(observed);observed.sample_started_ns-=worker.MAX_DRAIN_NS+1
            with patch.object(worker.WorkerPidfdObservation,'_check_bindings',late), \
                    self.assertRaisesRegex(ValueError,'worker-deadline'):
                self.observation(state)
        with self.proc() as state:
            observed=self.observation(state); original=observed._worker_frontier;calls=0
            def frontier(candidate):
                nonlocal calls
                result=original(candidate);calls+=1
                if calls==2: observed.sample_started_ns-=worker.MAX_DRAIN_NS+1
                return result
            try:
                with patch.object(observed,'_worker_frontier',side_effect=frontier), \
                        self.assertRaisesRegex(ValueError,'worker-deadline'): observed.recheck()
                self.assertTrue(observed.failed)
            finally: observed.close()

    def test_reaped_fdinfo_marker_does_not_replace_binding_and_closed_pidfd_refuses(self):
        with self.proc() as state:
            observed=self.observation(state);original=dict(observed.bindings['10002'])
            try:
                self.retire(state);state.identities[observed.thread_fds['10002']]='-1'
                state.events=lambda descriptor:[(descriptor,select.POLLIN|select.POLLHUP)]
                record=observed.recheck()
                self.assertEqual(observed.bindings['10002'],original)
                self.assertEqual(record['worker_bindings']['10002']['namespace'],[10002,502])
                self.assertEqual(record['worker_terminal_events']['10002']['original_namespace'],[10002,502])
            finally: observed.close()
        with self.proc() as state:
            observed=self.observation(state);os.close(observed.thread_fds['10002'])
            with self.assertRaises(OSError): observed.recheck()
            self.assertTrue(observed.failed)
            with self.assertRaises(OSError): observed.close()

    def test_two_worker_races_each_consume_a_new_proof_and_recapture_stable_frontiers(self):
        with self.proc() as state:
            self.additional_worker(state); observed=self.observation(state)
            original=base._read
            def read(directory,name):
                if name=='stat' and directory==observed.task_fds['10002'] and '10002' not in state.terminal:
                    self.retire(state,'10002')
                elif name=='stat' and directory==observed.task_fds['10003'] and '10003' not in state.terminal:
                    self.retire(state,'10003')
                return original(directory,name)
            try:
                with patch.object(base,'_read',side_effect=read): record=observed.recheck()
                self.assertEqual(record['pending_retired_tasks'],['10002','10003'])
                self.assertEqual(len(record['interrupted_frontiers']),2)
                self.assertEqual(record['tasks'],['10001'])
                self.assertEqual(record['frontier_before'],record['frontier_after'])
                self.assertEqual(len(observed.thread_fds),2)
            finally: observed.close()

    def test_missing_worker_without_exact_held_terminal_event_is_sticky(self):
        for mode in ('none','hup','err','nval','wrong-fd','other-errno'):
            with self.subTest(mode=mode), self.proc() as state:
                observed = self.observation(state)
                try:
                    self.retire(state)
                    masks = dict(hup=select.POLLHUP,err=select.POLLERR,nval=select.POLLNVAL)
                    if mode == 'none': state.events = lambda fd: []
                    elif mode == 'wrong-fd': state.events = lambda fd: [(state.held,select.POLLIN)]
                    elif mode == 'other-errno': state.events = lambda fd: (_ for _ in ()).throw(OSError(errno.EIO,'private'))
                    else: state.events = lambda fd: [(fd,masks[mode])]
                    with self.assertRaises((OSError,ValueError)): observed.recheck()
                    with self.assertRaisesRegex(ValueError,'sticky-failure'): observed.recheck()
                finally: observed.close()

    def test_acquisition_unsupported_disappeared_changed_or_wrong_identity_refuses(self):
        for mode in ('unsupported','denied','missing','namespace','starttime','fdinfo'):
            with self.subTest(mode=mode), self.proc() as state:
                original = worker.os.pidfd_open
                def opened(pid, flags):
                    if mode in ('unsupported','denied'):
                        raise OSError(errno.EINVAL if mode=='unsupported' else errno.EPERM,'closed failure')
                    descriptor = original(pid,flags)
                    if mode == 'missing': self.retire(state)
                    elif mode == 'namespace':
                        p=state.root/'task/10002/status'; p.write_text(p.read_text().replace('10002 502','10002 503'))
                    elif mode == 'starttime': (state.root/'task/10002/stat').write_text(state.fixture.stat(10002,'R',start=999))
                    else: state.identities[descriptor] = '10003'
                    return descriptor
                with patch.object(worker.os,'pidfd_open',side_effect=opened), self.assertRaises((OSError,ValueError)):
                    self.observation(state)
                self.assertLessEqual(len(state.opened),1)

    def test_original_unknown_task_is_not_qualified_by_retiring(self):
        for change in (dict(flags=0),dict(flags=4|base.PF_KTHREAD),dict(vsize=4096),dict(rss=1)):
            with self.subTest(change=change), self.proc() as state:
                (state.root/'task/10002/stat').write_text(state.fixture.stat(10002,'R',**change))
                with self.assertRaises(ValueError): self.observation(state)
                self.assertEqual(state.opened,[])

    def test_leader_loss_addition_reappearance_and_fd_reuse_refuse(self):
        for mode in ('leader','addition','reappearance','proc-fd','thread-fd','starttime'):
            with self.subTest(mode=mode), self.proc() as state:
                observed = self.observation(state)
                try:
                    if mode == 'leader': (state.root/'task/10001/status').unlink()
                    elif mode == 'addition': (state.root/'task/10003').mkdir()
                    elif mode == 'reappearance':
                        self.retire(state); observed.recheck(); (state.root/'task/10002').mkdir()
                    elif mode == 'starttime':
                        (state.root/'task/10002/stat').write_text(state.fixture.stat(10002,'R',start=999))
                    else:
                        descriptor = observed.task_fds['10002'] if mode=='proc-fd' else observed.thread_fds['10002']
                        replacement=os.open(state.root,os.O_RDONLY|os.O_DIRECTORY)
                        try: os.dup2(replacement,descriptor)
                        finally: os.close(replacement)
                    with self.assertRaises((OSError,ValueError)): observed.recheck()
                    self.assertTrue(observed.failed)
                finally: observed.close()

    def test_remaining_non_zombie_and_unproved_cross_frontier_changes_refuse(self):
        with self.proc() as state:
            third=state.root/'task/10003'; third.mkdir()
            (third/'status').write_text(state.fixture.status(10003,'R'))
            (third/'stat').write_text(state.fixture.stat(10003,'R'))
            for p in [state.root/'status', *(p/'status' for p in (state.root/'task').iterdir())]:
                p.write_text(p.read_text().replace('Threads:\t2','Threads:\t3'))
            observed=self.observation(state)
            try:
                self.retire(state)
                # Keep the fixture's remaining count consistent so Z is the refusal.
                for p in [state.root/'status',state.root/'task/10001/status',third/'status']:
                    p.write_text(p.read_text().replace('Threads:\t3','Threads:\t2'))
                with self.assertRaisesRegex(ValueError,'remaining-not-zombie'): observed.recheck()
            finally: observed.close()

    def test_recapture_without_new_proved_retirement_and_changed_frontier_refuse(self):
        for mode in ('no-progress','unknown-after-first','worker-without-event','deadline'):
            with self.subTest(mode=mode), self.proc() as state:
                observed=self.observation(state); original=observed._worker_frontier; calls=0
                def frontier(candidate):
                    nonlocal calls
                    if mode=='no-progress': raise worker._Recapture
                    result=original(candidate);calls+=1
                    if calls==1:
                        if mode=='unknown-after-first': (state.root/'task/10003').mkdir()
                        else:
                            self.retire(state);state.terminal.clear()
                    return result
                try:
                    if mode=='deadline': observed.sample_started_ns-=worker.MAX_DRAIN_NS+1
                    with patch.object(observed,'_worker_frontier',side_effect=frontier), self.assertRaises(ValueError):
                        observed.recheck()
                    self.assertTrue(observed.failed)
                finally: observed.close()

    def test_original_deadline_resources_and_exact_owned_wait4_still_govern(self):
        for mode in ('valid','late','unknown','missing-rss','missing-cpu','owner'):
            with self.subTest(mode=mode), self.proc() as state:
                observed=self.observation(state); self.retire(state); observed.recheck()
                child=SimpleNamespace(pid=501,termination_fd=state.held,observation_error=None,
                    waited_peak_rss_bytes=None if mode=='missing-rss' else 8192,
                    waited_cpu_ns=None if mode=='missing-cpu' else 1500,
                    reap=lambda:'unknown' if mode=='unknown' else 'terminal')
                if mode=='late': observed.sample_started_ns-=worker.MAX_DRAIN_NS+1
                try:
                    reason,record=runtime._drain_exit_cleanup(child,observed,
                        object() if mode=='owner' else state.token,time.monotonic_ns(),dict(wall_seconds=2),
                        exit_observation=runtime.exit_observation_profile(worker.PROFILE))
                    self.assertEqual(record['outcome'],'terminal-wait4' if mode=='valid' else 'failed')
                    self.assertIsNone(reason) if mode=='valid' else self.assertIsNotNone(reason)
                    if mode=='valid': self.assertEqual(record['terminal_retired_tasks'],['10002'])
                finally: observed.close()

    def test_exact_schema_and_every_source_binding_and_legacy_no_import(self):
        plan=runtime.experiment_plan({'explicit':'fixture'},exit_observation=worker.PROFILE)
        self.assertEqual(plan['schema'],'llm-runtime-public-pilot-plan-v4')
        self.assertIs(runtime.exit_observation_class(plan['exit_observation']),worker.WorkerPidfdObservation)
        for key in plan['exit_observation']:
            changed=copy.deepcopy(plan); changed['exit_observation'].pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError): runtime.validate_plan(changed)
        for key in ('observer_source_sha256','base_observer_source_sha256','diagnostic_source_sha256','maximum_drain_ns'):
            changed=copy.deepcopy(plan);changed['exit_observation'][key]='0'*64 if key.endswith('sha256') else 100_000_001
            with self.subTest(changed=key), self.assertRaises(ValueError): runtime.validate_plan(changed)
        for profile in runtime.EXIT_PROFILES[:-1]:
            wrong=runtime.experiment_plan({'explicit':'fixture'},exit_observation=profile)
            changed=copy.deepcopy(plan); changed['schema']=wrong['schema']
            with self.assertRaises(ValueError): runtime.validate_plan(changed)
        imported=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=='llm_runtime_exit_worker_observation': raise AssertionError('unbound V4 import')
            return imported(name,*args,**kwargs)
        with patch.object(builtins,'__import__',side_effect=guard):
            for profile,kind in ((base.PROFILE,base.ExitOnlyObservation),(subset.PROFILE,subset.TerminalSubsetObservation)):
                legacy=runtime.experiment_plan({'fixture':True},exit_observation=profile)
                runtime.validate_plan(legacy)
                self.assertIs(runtime.exit_observation_class(legacy['exit_observation']),kind)
                with fixtures.ExitObservationTests().proc() as (_,held,token):
                    observed=kind(501,held,token,base._status(fixtures.ExitObservationTests().status()),time.monotonic_ns())
                    child=SimpleNamespace(pid=501,termination_fd=held,observation_error=None,
                        waited_peak_rss_bytes=8192,waited_cpu_ns=1500,reap=lambda:'terminal')
                    try:
                        reason,result=runtime._drain_exit_cleanup(child,observed,token,time.monotonic_ns(),
                            dict(wall_seconds=2),exit_observation=legacy['exit_observation'])
                        self.assertIsNone(reason);self.assertEqual(result['outcome'],'terminal-wait4')
                    finally: observed.close()

    def test_supervisor_original_caps_and_exact_typed_v4_dispatch(self):
        helper=owner_fixtures.RssSupervisionTests()
        for mode in ('valid','overcap','late','v3-under-v4','v4-under-v3'):
            with self.subTest(mode=mode), self.proc() as state:
                child=helper.child_control();child.termination_fd=state.held
                usage=helper.usage(peak=256*1024 if mode=='overcap' else 8192)
                profile=subset.PROFILE if mode=='v4-under-v3' else worker.PROFILE
                def observe(pid):
                    _,descriptor,owner=runtime._RSS_OWNER_CONTEXT.get()
                    if mode=='v3-under-v4':
                        observed=subset.TerminalSubsetObservation(501,descriptor,owner,
                            base._status(state.fixture.status()),time.monotonic_ns())
                    else:
                        observed=worker.WorkerPidfdObservation(501,descriptor,owner,
                            base._status(state.fixture.status()),time.monotonic_ns())
                        self.retire(state);observed.recheck()
                    if mode=='late': observed.sample_started_ns-=worker.MAX_DRAIN_NS+1
                    runtime._RSS_EXIT_OBSERVATION.set(observed)
                    return None
                with patch.object(runtime,'_Wait4Child',return_value=child), \
                        patch.object(runtime.os,'wait4',side_effect=[(0,0,None),(501,0,usage)]), \
                        patch.object(runtime,'current_rss',side_effect=observe), \
                        patch.object(runtime.signal,'pidfd_send_signal'):
                    result=runtime.supervise(['explicit own wait4 fixture'],state.root/'result',
                        helper.BUDGET,exit_observation=runtime.exit_observation_profile(profile))
                self.assertEqual(result['outcome'],'success' if mode=='valid' else 'failed')
                self.assertTrue(result['owned_child_reap_resolved'])

    def test_real_zombie_leader_with_live_user_worker_remains_refused(self):
        program=('import ctypes,threading,time;'
            'threading.Thread(target=lambda:time.sleep(5),daemon=True).start();'
            'ctypes.CDLL(None).pthread_exit(None)')
        with tempfile.TemporaryDirectory() as directory:
            result=runtime.supervise([sys.executable,'-c',program],Path(directory)/'owned-live-worker',
                dict(wall_seconds=2,rss_bytes=128*1024**2),
                exit_observation=runtime.exit_observation_profile(worker.PROFILE))
        self.assertEqual(result['stop_reason'],'rss-observation-unavailable')
        self.assertEqual(result['rss_gap_diagnostic']['leader_state'],'Z')

    def test_real_own_worker_pidfd_event_and_missing_proc_are_not_group_completion(self):
        # ABI probe only. Its handshake timeouts do not qualify the 100ms observer.
        program=('import json,os,sys,threading;'
            't=threading.Thread(target=lambda:os.read(int(sys.argv[1]),1));t.start();'
            'print(json.dumps([os.getpid(),t.native_id]),flush=True);'
            'sys.stdin.readline();t.join();print("joined",flush=True);sys.stdin.readline()')
        release_r,release_w=os.pipe(); child=None; group=None; descriptor=None; task=None; waited=False
        def line():
            poller=select.poll();poller.register(child.stdout.fileno(),select.POLLIN)
            self.assertTrue(poller.poll(2000),'own child handshake deadline')
            return child.stdout.readline()
        try:
            child=subprocess.Popen([sys.executable,'-c',program,str(release_r)],pass_fds=(release_r,),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            os.close(release_r); release_r=None
            pid,tid=json.loads(line());self.assertEqual(pid,child.pid)
            group=os.pidfd_open(pid,0)
            try: descriptor=os.pidfd_open(tid,worker.PIDFD_THREAD)
            except OSError as error:
                if error.errno in (errno.EINVAL,errno.ENOSYS): self.skipTest('kernel ABI unavailable; observer refuses it')
                raise
            signature=base._signature(descriptor)
            identity=base._proc_fields(Path(f'/proc/self/fdinfo/{descriptor}'))
            self.assertEqual(base._namespace(identity,'NSpid')[-1],tid)
            task=os.open(f'/proc/{pid}/task/{tid}',os.O_RDONLY|os.O_DIRECTORY)
            before=base._stat(base._read(task,'stat'))
            self.assertEqual(before['pid'],tid)
            os.write(release_w,b'x');child.stdin.write(b'join\n');child.stdin.flush()
            self.assertEqual(line().strip(),b'joined')
            poller=select.poll();poller.register(descriptor,select.POLLIN)
            events=poller.poll(1000); self.assertTrue(events and events[0][1]&select.POLLIN)
            group_poll=select.poll();group_poll.register(group,select.POLLIN)
            self.assertEqual(group_poll.poll(0),[])
            self.assertEqual(os.wait4(pid,os.WNOHANG)[0],0)
            with self.assertRaises(FileNotFoundError): base._read(task,'status')
            self.assertEqual(base._signature(descriptor),signature)
            child.stdin.write(b'finish\n');child.stdin.flush()
            self.assertTrue(group_poll.poll(1000))
            actual,status,usage=os.wait4(pid,0);waited=True;child.returncode=os.waitstatus_to_exitcode(status)
            self.assertEqual((actual,child.returncode),(pid,0));self.assertGreater(usage.ru_maxrss,0)
        finally:
            if child is not None:
                if not waited:
                    if group is not None: signal.pidfd_send_signal(group,signal.SIGKILL)
                    else: child.kill()
                    _,status,_=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
                child.stdin.close();child.stdout.close()
            for fd in (task,descriptor,group,release_r,release_w):
                if fd is not None: os.close(fd)


if __name__=='__main__': unittest.main()
