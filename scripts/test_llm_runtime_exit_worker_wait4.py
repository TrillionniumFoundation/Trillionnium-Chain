"""Real owned-wait4 regressions for V4, never full-model qualification."""
import contextlib
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_worker_observation as worker
import llm_runtime_pilot as runtime
import test_llm_runtime_exit_worker_observation as fixtures


class WorkerWait4Tests(unittest.TestCase):
    @contextlib.contextmanager
    def owned_zombie(self):
        # Real spawn and held pidfd. No Popen wait/poll, competing reaper or model.
        child=runtime._Wait4Child([sys.executable,'-c','import sys;sys.stdin.buffer.read(1)'],
            stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        observed=None;token=object()
        try:
            child.stdin.write(b'x');child.stdin.flush()
            poller=select.poll();poller.register(child.termination_fd,select.POLLIN)
            self.assertTrue(poller.poll(2000),'own child failed to become a waitable zombie')
            visible,_,_=base._pidfd_identity(child.pid,child.termination_fd)
            leader=base._proc_fields(Path(f'/proc/{visible}/status'))
            self.assertEqual(leader['State'][0],'Z')
            observed=worker.WorkerPidfdObservation(child.pid,child.termination_fd,token,
                leader,time.monotonic_ns())
            self.assertTrue(observed.belongs_to(child.pid,child.termination_fd,token))
            yield child,observed,token
        finally:
            if observed is not None: observed.close()
            child.stdin.close()
            child.finish()

    def test_real_wait4_erases_live_fdinfo_but_retained_owner_capability_closes(self):
        with self.owned_zombie() as (child,observed,token):
            descriptor=child.termination_fd;signature=base._signature(descriptor)
            reason,record=runtime._drain_exit_cleanup(child,observed,token,
                time.monotonic_ns(),dict(wall_seconds=2),
                exit_observation=runtime.exit_observation_profile(worker.PROFILE))
            self.assertIsNone(reason)
            self.assertEqual(record['outcome'],'terminal-wait4')
            self.assertEqual(record['retirement_closed_by'],'exact-owned-child-terminal-wait4')
            self.assertTrue(child.reaped and child.reap_resolved and child.owned_exit_observed)
            self.assertIsNone(child.observation_error)
            self.assertEqual(child.returncode,0)
            self.assertGreater(child.waited_peak_rss_bytes,0)
            self.assertGreaterEqual(child.waited_cpu_ns,0)
            self.assertLessEqual(record['completed_ns'],observed.sample_started_ns+worker.MAX_DRAIN_NS)
            identity=base._proc_fields(Path(f'/proc/self/fdinfo/{descriptor}'))
            self.assertEqual((identity['Pid'],identity['NSpid']),(['-1'],['-1']))
            self.assertEqual(base._signature(descriptor),signature)
            self.assertTrue(observed.terminal_belongs_to(child.pid,descriptor,token))
            self.assertFalse(observed.terminal_belongs_to(child.pid,descriptor,object()))
            self.assertFalse(observed.terminal_belongs_to(child.pid+1,descriptor,token))
            duplicate=os.dup(descriptor)
            try: self.assertFalse(observed.terminal_belongs_to(child.pid,duplicate,token))
            finally: os.close(duplicate)
            # The terminal capability is not a relaxation of live/recheck rules.
            self.assertFalse(observed.belongs_to(child.pid,descriptor,token))
            with self.assertRaises(ValueError): observed.recheck()
            self.assertFalse(observed.terminal_belongs_to(child.pid,descriptor,token))

    def test_real_wait4_wrong_token_or_replaced_same_fd_refuses_terminal_closure(self):
        for mode in ('owner-token','replaced-fd'):
            with self.subTest(mode=mode), self.owned_zombie() as (child,observed,token):
                original=child.reap
                def reap():
                    state=original()
                    if state=='terminal':
                        if mode=='owner-token': observed.owner_token=object()
                        else:
                            replacement=os.open('/dev/null',os.O_RDONLY)
                            try: os.dup2(replacement,child.termination_fd)
                            finally: os.close(replacement)
                    return state
                with patch.object(child,'reap',side_effect=reap):
                    reason,record=runtime._drain_exit_cleanup(child,observed,token,
                        time.monotonic_ns(),dict(wall_seconds=2),
                        exit_observation=runtime.exit_observation_profile(worker.PROFILE))
                self.assertTrue(child.reaped and child.reap_resolved)
                self.assertEqual(reason,'rss-exit-cleanup-observation-unavailable')
                self.assertEqual(record['outcome'],'failed')
                self.assertNotIn('retirement_closed_by',record)

    def test_dead_live_identity_cannot_reach_reap_or_terminal_capability(self):
        fixture=fixtures.WorkerPidfdTests()
        with fixture.proc() as state:
            observed=fixture.observation(state)
            child=SimpleNamespace(pid=501,termination_fd=state.held,observation_error=None,
                waited_peak_rss_bytes=8192,waited_cpu_ns=1500,
                reap=Mock(side_effect=AssertionError('pre-reap owner must refuse')))
            try:
                with patch.object(base,'_pidfd_identity',side_effect=ValueError('exit-held-pidfd')), \
                        patch.object(observed,'terminal_belongs_to',side_effect=AssertionError('unreachable')) as terminal:
                    reason,record=runtime._drain_exit_cleanup(child,observed,state.token,
                        time.monotonic_ns(),dict(wall_seconds=2),
                        exit_observation=runtime.exit_observation_profile(worker.PROFILE))
                    self.assertIsNotNone(reason);self.assertEqual(record['outcome'],'failed')
                    child.reap.assert_not_called();terminal.assert_not_called()
                    with self.assertRaises(ValueError): observed.recheck()
                self.assertTrue(observed.failed)
            finally: observed.close()

    def test_unknown_wrong_wait_or_missing_receipt_never_uses_terminal_capability(self):
        fixture=fixtures.WorkerPidfdTests()
        for mode in ('unknown','wrong-pid','terminal-error','missing-rss','missing-cpu'):
            with self.subTest(mode=mode), fixture.proc() as state:
                observed=fixture.observation(state)
                child=SimpleNamespace(pid=501,termination_fd=state.held,
                    observation_error='wait4:wrong-pid' if mode in ('wrong-pid','terminal-error') else None,
                    waited_peak_rss_bytes=None if mode=='missing-rss' else 8192,
                    waited_cpu_ns=None if mode=='missing-cpu' else 1500,
                    reap=lambda:'unknown' if mode in ('unknown','wrong-pid') else 'terminal')
                try:
                    with patch.object(observed,'terminal_belongs_to',side_effect=AssertionError('unreachable')) as terminal:
                        reason,record=runtime._drain_exit_cleanup(child,observed,state.token,
                            time.monotonic_ns(),dict(wall_seconds=2),
                            exit_observation=runtime.exit_observation_profile(worker.PROFILE))
                    self.assertIsNotNone(reason);self.assertEqual(record['outcome'],'failed')
                    terminal.assert_not_called()
                finally: observed.close()


if __name__=='__main__': unittest.main()
