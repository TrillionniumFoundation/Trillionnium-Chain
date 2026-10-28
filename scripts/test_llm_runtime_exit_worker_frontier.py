"""Synthetic count-crossing regressions; no model or kernel-exit qualification."""
import contextlib
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as base
import llm_runtime_exit_worker_observation as worker
import test_llm_runtime_exit_worker_observation as fixtures


class WorkerFrontierTests(unittest.TestCase):
    def setUp(self): self.fixture=fixtures.WorkerPidfdTests()

    @contextlib.contextmanager
    def counts(self, observed, values):
        original=base._read;sequence=iter(values)
        def read(descriptor,name):
            raw=original(descriptor,name)
            if descriptor==observed.group_fd and name=='status':
                try: count=next(sequence)
                except StopIteration: return raw
                return ''.join('Threads:\t'+str(count)+'\n' if line.startswith('Threads:') else line
                    for line in raw.splitlines(keepends=True))
            return raw
        with patch.object(base,'_read',side_effect=read): yield

    def test_zero_recapture_and_matching_count_retirement_keep_original_origin(self):
        with self.fixture.proc() as state:
            observed=self.fixture.observation(state);origin=observed.sample_started_ns
            try:
                self.assertEqual(observed.recheck()['interrupted_frontiers'],[])
                self.fixture.retire(state)
                record=observed.recheck()
                self.assertEqual(record['interrupted_frontiers'],[])
                self.assertEqual(record['pending_retired_tasks'],['10002'])
                self.assertEqual(observed.sample_started_ns,origin)
            finally: observed.close()

    def test_one_fresh_event_discards_old_count_then_requires_two_complete_frontiers(self):
        with self.fixture.proc() as state:
            observed=self.fixture.observation(state);origin=observed.sample_started_ns
            self.fixture.retire(state);complete=[];original=observed._worker_frontier
            def frontier(candidate):
                result=original(candidate);complete.append(result[0]);return result
            try:
                with self.counts(observed,[2]), patch.object(observed,'_worker_frontier',side_effect=frontier):
                    record=observed.recheck()
                self.assertEqual(complete,[('10001',),('10001',)])
                self.assertEqual(record['frontier_before'],record['frontier_after'])
                self.assertEqual(record['pending_retired_tasks'],['10002'])
                interruption=record['interrupted_frontiers'][0]['count_interruption']
                self.assertEqual(interruption['reported_threads'],2)
                self.assertEqual(interruption['prior_active_tasks'],['10001','10002'])
                self.assertEqual(interruption['observed_tasks'],['10001'])
                self.assertEqual(interruption['newly_proved_retired_tasks'],['10002'])
                self.assertEqual(observed.sample_started_ns,origin)
                events=dict(observed.retirements)
                self.assertEqual(observed.recheck()['interrupted_frontiers'],[])
                self.assertEqual(observed.retirements,events)
                self.assertNotIn('retirement_closed_by',record)
                self.assertNotIn('rss_bytes',record)
            finally: observed.close()

    def test_ending_names_crossing_discards_the_whole_incomplete_frontier(self):
        with self.fixture.proc() as state:
            observed=self.fixture.observation(state);original_read=base._read;stale=False
            complete=[];original_frontier=observed._worker_frontier
            def read(descriptor,name):
                nonlocal stale
                raw=original_read(descriptor,name)
                if descriptor==observed.task_fds['10002'] and name=='stat': self.fixture.retire(state)
                if descriptor==observed.group_fd and name=='status' and state.terminal and not stale:
                    stale=True;return raw.replace('Threads:\t1','Threads:\t2')
                return raw
            def frontier(candidate):
                result=original_frontier(candidate);complete.append(result[0]);return result
            try:
                with patch.object(base,'_read',side_effect=read), \
                        patch.object(observed,'_worker_frontier',side_effect=frontier): record=observed.recheck()
                self.assertEqual(complete,[('10001',),('10001',)])
                self.assertEqual(len(record['interrupted_frontiers']),1)
                self.assertEqual(record['interrupted_frontiers'][0]['count_interruption']['reported_threads'],2)
            finally: observed.close()

    def test_repeated_old_count_cannot_reuse_the_same_terminal_proof(self):
        with self.fixture.proc() as state:
            observed=self.fixture.observation(state);self.fixture.retire(state)
            original=observed._retire
            try:
                with self.counts(observed,[2,2]), patch.object(observed,'_retire',wraps=original) as retire, \
                        self.assertRaisesRegex(ValueError,'frontier-change'): observed.recheck()
                self.assertEqual(retire.call_count,1)
                self.assertEqual(len(observed.failure_context['interrupted_frontiers']),1)
                self.assertEqual(observed.active_names,('10001','10002'))
                self.assertEqual(observed.pending_retired,())
                with self.assertRaisesRegex(ValueError,'sticky-failure'): observed.recheck()
            finally: observed.close()

    def test_unknown_or_intermediate_count_is_not_an_old_complete_set(self):
        for mode in ('excess','intermediate','zero'):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                if mode=='intermediate': self.fixture.additional_worker(state)
                observed=self.fixture.observation(state)
                self.fixture.retire(state)
                if mode=='intermediate': self.fixture.retire(state,'10003')
                try:
                    with self.counts(observed,[dict(excess=3,intermediate=2,zero=0)[mode]]), \
                            self.assertRaises(ValueError): observed.recheck()
                    self.assertTrue(observed.failed)
                    self.assertEqual(observed.failure_context['interrupted_frontiers'],[])
                finally: observed.close()

    def test_multi_call_transitions_use_current_committed_set_and_original_deadline(self):
        with self.fixture.proc() as state:
            self.fixture.additional_worker(state)
            observed=self.fixture.observation(state);origin=observed.sample_started_ns
            try:
                self.fixture.retire(state)
                with self.counts(observed,[3]): first=observed.recheck()
                self.assertEqual(observed.active_names,('10001','10003'))
                self.assertEqual(first['pending_retired_tasks'],['10002'])
                self.fixture.retire(state,'10003')
                with self.counts(observed,[2]): second=observed.recheck()
                self.assertEqual(observed.active_names,('10001',))
                self.assertEqual(second['pending_retired_tasks'],['10002','10003'])
                self.assertEqual(sum(len(r['interrupted_frontiers']) for r in (first,second)),2)
                self.assertEqual(len(observed.thread_fds),2)
                self.assertEqual(observed.sample_started_ns,origin)
                self.assertEqual(observed.recheck()['interrupted_frontiers'],[])
                with self.counts(observed,[2]), self.assertRaisesRegex(ValueError,'frontier-change'):
                    observed.recheck()  # Previously committed retirements are never fresh evidence.
            finally: observed.close()

    def test_recapture_crossing_original_100ms_does_not_reset_the_clock(self):
        with self.fixture.proc() as state:
            observed=self.fixture.observation(state);self.fixture.retire(state)
            origin=observed.sample_started_ns;expired=False;original=observed._retire
            def retire(*args,**kwargs):
                nonlocal expired
                result=original(*args,**kwargs);expired=True;return result
            def now(): return origin+worker.MAX_DRAIN_NS+1 if expired else origin+1
            try:
                with self.counts(observed,[2]), patch.object(observed,'_retire',side_effect=retire), \
                        patch.object(worker.time,'monotonic_ns',side_effect=now), \
                        self.assertRaisesRegex(ValueError,'worker-deadline'): observed.recheck()
                self.assertEqual(observed.sample_started_ns,origin)
                self.assertEqual(len(observed.failure_context['interrupted_frontiers']),1)
                self.assertTrue(observed.failed)
            finally: observed.close()

    def test_synthetic_maximum_workers_consume_at_most_one_proof_each(self):
        # A fixed synthetic clock isolates the progress bound, not real timing.
        with self.fixture.proc() as state:
            for number in range(10002,10001+base.MAX_TASKS):
                directory=state.root/'task'/str(number);directory.mkdir(exist_ok=True)
                (directory/'status').write_text(state.fixture.status(number,'Z').replace('Threads:\t2','Threads:\t32'))
                (directory/'stat').write_text(state.fixture.stat(number,'Z'))
            for path in (state.root/'status',state.root/'task/10001/status'):
                path.write_text(path.read_text().replace('Threads:\t2','Threads:\t32'))
            observed=self.fixture.observation(state);origin=observed.sample_started_ns
            original=base._read;stale=False
            def read(descriptor,name):
                nonlocal stale
                raw=original(descriptor,name)
                remaining=[p.name for p in (state.root/'task').iterdir() if p.name!='10001']
                if name=='stat' and remaining and descriptor==observed.task_fds[max(remaining,key=int)]:
                    self.fixture.retire(state,max(remaining,key=int))
                if descriptor==observed.group_fd and name=='status' and state.terminal and not stale:
                    stale=True
                    raw=''.join('Threads:\t32\n' if line.startswith('Threads:') else line
                        for line in raw.splitlines(keepends=True))
                return raw
            try:
                with patch.object(base,'_read',side_effect=read), \
                        patch.object(worker.time,'monotonic_ns',return_value=origin+1): record=observed.recheck()
                self.assertEqual(len(record['interrupted_frontiers']),base.MAX_TASKS-1)
                self.assertEqual(len(record['worker_terminal_events']),base.MAX_TASKS-1)
                self.assertEqual(record['tasks'],['10001'])
                self.assertEqual(record['frontier_before'],record['frontier_after'])
                self.assertEqual(observed.sample_started_ns,origin)
            finally: observed.close()

    def test_illegal_worker_fields_seen_before_another_retirement_stay_sticky(self):
        for component in ('status','stat'):
            with self.subTest(component=component), self.fixture.proc() as state:
                self.fixture.additional_worker(state);observed=self.fixture.observation(state)
                original=base._read
                def read(descriptor,name):
                    raw=original(descriptor,name)
                    if descriptor==observed.task_fds['10002'] and name==component:
                        raw=raw+'VmRSS:\t0 kB\n' if name=='status' else state.fixture.stat(10002,'R',flags=0)
                        self.fixture.retire(state,'10003')
                    return raw
                try:
                    with patch.object(base,'_read',side_effect=read), \
                            self.assertRaisesRegex(ValueError,'not-exit-only'): observed.recheck()
                    self.assertEqual(observed.failure_context['interrupted_frontiers'],[])
                    self.assertTrue(observed.failed)
                    with self.assertRaisesRegex(ValueError,'sticky-failure'): observed.recheck()
                finally: observed.close()

    def test_remaining_or_second_frontier_fault_cannot_commit_count_recapture(self):
        for mode in ('running-remaining','second-frontier-stat','second-frontier-reappearance'):
            with self.subTest(mode=mode), self.fixture.proc() as state:
                if mode=='running-remaining':
                    self.fixture.additional_worker(state)
                    (state.root/'task/10003/status').write_text(state.fixture.status(10003,'R'))
                    (state.root/'task/10003/stat').write_text(state.fixture.stat(10003,'R'))
                    # Restore the full initial count before qualification.
                    p=state.root/'task/10003/status';p.write_text(p.read_text().replace('Threads:\t2','Threads:\t3'))
                observed=self.fixture.observation(state);old=len(observed.active_names)
                self.fixture.retire(state);original=observed._worker_frontier;complete=0
                def frontier(candidate):
                    nonlocal complete
                    result=original(candidate);complete+=1
                    if complete==1:
                        if mode=='second-frontier-stat':
                            (state.root/'task/10001/stat').write_text(state.fixture.stat(rss=1))
                        elif mode=='second-frontier-reappearance': (state.root/'task/10002').mkdir()
                    return result
                try:
                    with self.counts(observed,[old]), patch.object(observed,'_worker_frontier',side_effect=frontier), \
                            self.assertRaises(ValueError): observed.recheck()
                    self.assertTrue(observed.failed)
                    self.assertEqual(observed.pending_retired,())
                    self.assertEqual(len(observed.failure_context['interrupted_frontiers']),1)
                finally: observed.close()


if __name__=='__main__': unittest.main()
