"""Ordinary-FD/synthetic facts only: valid cgroup placement and models NOT_RUN."""
import ctypes
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import llm_runtime_kernel_aggregate as aggregate


@unittest.skipUnless(sys.implementation.name == 'cpython' and
    sys.version_info[:3] == (3, 12, 3), 'controlled ABI requires CPython 3.12.3')
class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.native = kernel.build_controlled_native()
        self.temporary = tempfile.TemporaryDirectory()
        self.cap = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.cap is not None:
            for slot in self.cap._fd_owners:
                if slot[1] >= 0: self.native.release_owned(slot)
            self.native.operation = None
        self.native.close()
        self.temporary.cleanup()

    def fixture(self):
        cap = object.__new__(aggregate._AggregateOperation)
        cap.native = self.native; cap.owner = object(); cap.nodes = []
        cap.memory = 8*1024**3
        cap.closed = cap.failed = cap.consumed = cap.native_refused_without_child = False
        cap.fact = cap.child = cap.spawn_owner = None
        cap._verify_locked = Mock()
        cap._fd_owners = [(ctypes.c_int*4)(0, -1, -1, -1) for _ in range(16)]
        cap.operation = Path(self.temporary.name)
        fd = os.open(cap.operation, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        cap._fd_owners[0][1] = fd
        cap.nodes.append((cap.operation, fd, kernel.proc._signature(fd), {}))
        self.native.operation = self.cap = cap
        fields = {'cgroup.procs': '', 'pids.current': '0\n',
            'cgroup.events': 'populated 0\nfrozen 0\n',
            'cgroup.stat': 'nr_descendants 0\nnr_dying_descendants 0\n',
            'memory.current': '0\n', 'memory.swap.current': '0\n',
            'memory.peak': '1048576\n', 'memory.events': 'oom 0\noom_kill 0\n',
            'cpu.stat': 'usage_usec 100\nuser_usec 90\nsystem_usec 10\n'}
        for name, value in fields.items(): (cap.operation/name).write_text(value)
        return cap

    def owned_terminal(self, cap):
        # Real default wait4 owner and original FD, but synthetic cgroup fields.
        with open(os.devnull, 'wb') as output:
            child = runtime._Wait4Child(['/bin/true'], stdout=output, stderr=subprocess.STDOUT)
        self.addCleanup(child.finish)
        self.assertEqual(child.reap(0), 'terminal')
        child.kernel_operation = cap
        cap.spawn_owner = child; cap.consumed = True
        cap.child = (child.pid, child.termination_fd, kernel.proc._signature(child.termination_fd))
        self.addCleanup(setattr, child, 'kernel_operation', None)
        return child

    def test_real_owned_wait4_plus_synthetic_empty_charge_zero_creates_private_fact_only(self):
        cap = self.fixture(); child = self.owned_terminal(cap)
        record = cap.terminal_record(child.pid, child.termination_fd)
        self.assertIs(type(cap.fact), aggregate._TerminalAggregateFact)
        self.assertEqual(record['reservation'], 'RETAINED')
        self.assertEqual(record['outer_reconciliation'], 'UNKNOWN')
        self.assertFalse(record['authorization'])
        self.assertEqual(cap.fact.counters['memory.current'], '0\n')
        self.assertIs(cap.fact.operation, cap)
        record['counters']['memory.current'] = '999\n'
        self.assertEqual(cap.fact.counters['memory.current'], '0\n')
        with self.assertRaises(TypeError): cap.fact.counters['memory.current'] = '1\n'
        with self.assertRaisesRegex(ValueError, 'outer-reconciliation'):
            cap.close(cap.owner)
        self.assertIs(self.native.operation, cap)

    def test_unreaped_wrong_or_cleanup_only_owner_cannot_create_fact(self):
        for mode in ('live', 'wrong', 'cleanup', 'error', 'echild'):
            with self.subTest(mode=mode):
                cap = self.fixture(); child = self.owned_terminal(cap)
                if mode == 'live': child.reaped = False
                elif mode == 'cleanup': child.cleanup_method = 'waitpid-after-wait4-fault'
                elif mode == 'error': child.observation_error = 'unknown'
                elif mode == 'echild': child.no_waitable_child_observed = True
                with self.assertRaises(ValueError):
                    cap.terminal_record(child.pid+1 if mode == 'wrong' else child.pid, child.termination_fd)
                self.assertIsNone(cap.fact)
                # Restore the real already-reaped receipt only for fixture cleanup.
                child.reaped = True; child.kernel_operation = None
                for slot in cap._fd_owners:
                    if slot[1] >= 0: self.native.release_owned(slot)
                self.native.operation = None

    def test_live_process_remaining_charge_dying_and_malformed_fields_retain(self):
        failures = {'cgroup.procs': '123\n', 'pids.current': '1\n',
            'cgroup.events': 'populated 1\n',
            'cgroup.stat': 'nr_descendants 0\nnr_dying_descendants 1\n',
            'memory.current': '1\n', 'memory.swap.current': '1\n',
            'memory.events': 'oom 0\noom 1\n', 'cpu.stat': 'usage_usec -1\n'}
        for name, bad in failures.items():
            with self.subTest(name=name):
                cap = self.fixture(); child = self.owned_terminal(cap)
                (cap.operation/name).write_text(bad)
                with self.assertRaises(ValueError): cap.terminal_record(child.pid, child.termination_fd)
                self.assertIsNone(cap.fact); self.assertTrue(cap.failed)
                self.assertIs(self.native.operation, cap)
                child.kernel_operation = None
                for slot in cap._fd_owners:
                    if slot[1] >= 0: self.native.release_owned(slot)
                self.native.operation = None

    def test_after_raw_read_recheck_and_second_empty_are_required(self):
        for change in ('limit', 'charge', 'counter'):
            cap = self.fixture(); child = self.owned_terminal(cap)
            if change == 'limit': cap._verify_locked.side_effect = [None, ValueError('changed-limit')]
            original = aggregate._raw
            def changed(fd):
                raw = original(fd)
                if change == 'charge': (cap.operation/'memory.current').write_text('1\n')
                if change == 'counter': (cap.operation/'cpu.stat').write_text('usage_usec 101\n')
                return raw
            with patch.object(aggregate, '_raw', side_effect=changed), self.assertRaises(ValueError):
                cap.terminal_record(child.pid, child.termination_fd)
            self.assertIsNone(cap.fact)
            child.kernel_operation = None
            for slot in cap._fd_owners:
                if slot[1] >= 0: self.native.release_owned(slot)
            self.native.operation = None

    def test_caller_fact_constructor_and_wrong_cap_type_refuse_before_spawn(self):
        with self.assertRaises(ValueError): aggregate._TerminalAggregateFact(object(), {}, 0)
        with tempfile.TemporaryDirectory() as temporary, patch.object(runtime, '_Wait4Child') as launch:
            with self.assertRaises(ValueError):
                runtime.supervise(['/bin/true'], Path(temporary)/'x',
                    dict(wall_seconds=2, rss_bytes=8*1024**3), _aggregate_operation={})
            launch.assert_not_called()

    def test_old_cap_and_new_cap_cannot_be_mixed(self):
        cap = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                runtime.supervise(['/bin/true'], Path(temporary)/'x',
                    dict(wall_seconds=2, rss_bytes=8*1024**3),
                    _controlled_operation=cap, _aggregate_operation=cap)

    def test_native_invalid_group_refusal_keeps_original_owner_then_allows_nochild_close(self):
        cap = self.fixture()
        cap.allow_exec = Mock(side_effect=AssertionError('must not exec'))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(OSError):
            runtime.supervise(['/bin/true'], Path(temporary)/'x',
                dict(wall_seconds=2, rss_bytes=cap.memory), _aggregate_operation=cap)
        self.assertTrue(cap.native_refused_without_child)
        self.assertIs(type(cap.spawn_owner), runtime._Wait4Child)
        self.assertIsNone(cap.fact)
        cap.allow_exec.assert_not_called()
        cap.close(cap.owner)
        self.assertIsNone(self.native.operation)

    def test_descriptor_replacement_and_unknown_never_close(self):
        cap = self.fixture(); cap.consumed = True; cap.spawn_owner = object()
        other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.dup2(other, cap.nodes[0][1])
            with self.assertRaises(ValueError): cap.close(cap.owner)
            os.fstat(cap.nodes[0][1]); self.assertIs(self.native.operation, cap)
        finally: os.close(other)

    def test_aggregate_postclone_handoff_interruptions_reap_same_actual_child_and_retain_cap(self):
        for fault in (KeyboardInterrupt, MemoryError, BaseException):
            with self.subTest(fault=fault.__name__):
                cap = self.fixture(); children = []
                descriptors_before = set(os.listdir('/proc/self/fd'))
                cap.allow_exec = Mock(side_effect=AssertionError('must not enter payload'))
                def native(group, output, exe, argv, env, result):
                    ack = os.pipe2(os.O_CLOEXEC); error = os.pipe2(os.O_CLOEXEC)
                    child = subprocess.Popen([sys.executable, '-c', f'import os; os.read({ack[0]}, 1)'],
                        pass_fds=(ack[0], error[1]), stdout=subprocess.DEVNULL)
                    children.append(child)
                    result[:] = (child.pid, os.pidfd_open(child.pid), ack[1], error[0])
                    os.close(ack[0]); os.close(error[1])
                    raise fault('synthetic-native-return')
                failure = result = None
                with patch.object(self.native, 'spawn', side_effect=native), tempfile.TemporaryDirectory() as temporary:
                    try:
                        result = runtime.supervise(['/bin/true'], Path(temporary)/'x',
                            dict(wall_seconds=2, rss_bytes=cap.memory), _aggregate_operation=cap)
                    except BaseException as error: failure = error
                self.assertTrue(cap.spawn_owner.reaped)
                self.assertEqual(list(cap.spawn_owner._kernel_handoff)[1:], [-1]*3)
                for child in children:
                    with self.assertRaises(ChildProcessError): os.waitpid(child.pid, os.WNOHANG)
                    child.returncode = 0
                self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors_before)
                if fault is MemoryError:
                    self.assertIsNone(failure); self.assertEqual(result['outcome'], 'failed')
                else: self.assertIsInstance(failure, fault)
                with self.assertRaisesRegex(ValueError, 'outer-reconciliation'): cap.close(cap.owner)
                for slot in cap._fd_owners:
                    if slot[1] >= 0: self.native.release_owned(slot)
                self.native.operation = None

    def acquisition_fixture(self, memory_bytes=8*1024**3, controller_budget=None):
        root = Path(self.temporary.name)/'mount'; unit = root/'user.slice'/'fixture.service'
        controller = unit/'controller'; leaf = unit/('aggregate-'+'a'*32)
        controller.mkdir(parents=True); leaf.mkdir()
        quota = controller_budget or dict(memory_bytes=128*1024**2, cpu_quota_us=100000, tasks=16)
        for path in (root/'user.slice', unit, controller, leaf):
            fields = dict(kernel._FIXED, **{'memory.max': str(16*1024**3)+'\n'})
            if path == unit:
                fields.update({'cgroup.max.descendants': '2\n', 'cgroup.max.depth': '1\n',
                    'cgroup.procs': '', 'cgroup.stat': 'nr_descendants 2\nnr_dying_descendants 0\n'})
            if path == controller:
                fields.update({'memory.max': str(quota['memory_bytes'])+'\n',
                    'cpu.max': str(quota['cpu_quota_us'])+' 100000\n',
                    'pids.max': str(quota['tasks'])+'\n'})
            if path == leaf:
                fields.update({'memory.max': str(memory_bytes)+'\n',
                    'cpu.max': str(400000-quota['cpu_quota_us'])+' 100000\n',
                    'pids.max': str(256-quota['tasks'])+'\n'})
            if path in (controller, leaf):
                fields.update({'cgroup.max.descendants': '0\n', 'cgroup.subtree_control': ''})
            if path == leaf:
                fields.update({'cgroup.procs': '', 'pids.current': '0\n',
                    'cgroup.events': 'populated 0\n',
                    'cgroup.stat': 'nr_descendants 0\nnr_dying_descendants 0\n',
                    'memory.current': '0\n', 'memory.swap.current': '0\n', 'memory.peak': '0\n',
                    'memory.events': 'oom 0\n', 'cpu.stat': 'usage_usec 0\n'})
            for name, value in fields.items(): (path/name).write_text(value)
        real_read = Path.read_text
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        mount_id = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines())['mnt_id'].strip()
        os.close(fd)
        def read(path, *args, **kwargs):
            if str(path) == '/proc/self/cgroup': return '0::/user.slice/fixture.service/controller\n'
            if str(path) == '/proc/self/mountinfo': return f'{mount_id} 0 0:0 / {root} rw - cgroup2 cgroup rw\n'
            return real_read(path, *args, **kwargs)
        shown = dict(InvocationID='1'*32, ControlGroup='/user.slice/fixture.service',
            MainPID=str(os.getpid()), Delegate='yes', DelegateSubgroup='controller')
        observed = subprocess.CompletedProcess([], 0, ''.join(k+'='+v+'\n' for k,v in shown.items()))
        def acquire(action=None):
            # All membership/mount/systemd claims here are explicitly synthetic.
            with patch.object(kernel, '_ROOT', root), patch.object(Path, 'read_text', read), \
                    patch.dict(os.environ, {'INVOCATION_ID': '1'*32}), \
                    patch.object(aggregate.subprocess, 'run', return_value=observed):
                cap = aggregate.acquire_aggregate_mechanics(self.native, unit='fixture.service',
                    invocation='1'*32, operation=str(leaf), memory_bytes=memory_bytes,
                    controller_budget=quota, owner=self)
                self.cap = cap
                return action(cap) if action is not None else cap
        return leaf, unit, controller, observed, acquire

    def test_synthetic_acquisition_reads_controller_and_parent_caps_and_closes_before_spawn(self):
        leaf, unit, controller, observed, acquire = self.acquisition_fixture()
        self.cap = cap = acquire()
        self.assertEqual(cap.nodes[0][0], leaf)
        self.assertEqual(len(cap.nodes), 4)
        self.assertEqual(cap.nodes[0][3]['memory.max'], str(8*1024**3)+'\n')
        self.assertEqual(cap.nodes[0][3]['cpu.max'], '300000 100000\n')
        self.assertEqual(cap.nodes[0][3]['pids.max'], '240\n')
        self.assertIs(self.native.operation, cap)
        cap.close(self); self.assertIsNone(self.native.operation)

    def test_parser_failure_keeps_first_diagnostic_through_original_nochild_cleanup(self):
        for target, name in (('leaf', 'cpu.stat'), ('unit', 'cgroup.stat')):
            with self.subTest(target=target):
                leaf, unit, controller, observed, acquire = self.acquisition_fixture()
                path = dict(leaf=leaf, unit=unit)[target]/name
                raw = 'unreviewed.key 0\n'
                path.write_text(raw)
                before = set(os.listdir('/proc/self/fd'))
                with self.assertRaises(aggregate.AggregateCounterError) as caught: acquire()
                expected = 'aggregate' if target == 'leaf' else 'unit'
                self.assertEqual(caught.exception.counter_diagnostic,
                    (expected+'/'+name, raw, 'aggregate-counter-format'))
                self.assertIsNone(self.native.operation)
                self.assertEqual(set(os.listdir('/proc/self/fd')), before)
                import shutil
                shutil.rmtree(Path(self.temporary.name)/'mount')

    def test_declared_16g_aggregate_plus_controller_refuses_before_any_group_fd(self):
        leaf, unit, controller, observed, acquire = self.acquisition_fixture(memory_bytes=16*1024**3)
        descriptors_before = set(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(ValueError, 'aggregate-controller-headroom'):
            acquire()
        self.assertIsNone(self.native.operation)
        self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors_before)

    def test_initial_freshness_failure_retains_exact_first_raw_without_extra_read(self):
        # Real ordinary owned FDs, but all group/membership claims are fixtures.
        cases = [
            ({'memory.peak': '4096\n'}, 'memory.peak', '4096\n'),
            ({'cpu.stat': 'usage_usec 1\n'}, 'cpu.stat', 'usage_usec 1\n'),
            ({'memory.events': 'oom 1\n'}, 'memory.events', 'oom 1\n'),
            ({'memory.peak': '4096\n', 'cpu.stat': 'usage_usec 1\n',
              'memory.events': 'oom 1\n'}, 'memory.peak', '4096\n'),
            ({'cpu.stat': 'usage_usec 1\n', 'memory.events': 'oom 1\n'},
             'cpu.stat', 'usage_usec 1\n'),
        ]
        for fields, filename, raw in cases:
            with self.subTest(fields=fields):
                import shutil
                mount = Path(self.temporary.name)/'mount'
                if mount.exists(): shutil.rmtree(mount)
                leaf, unit, controller, observed, acquire = self.acquisition_fixture()
                for name, text in fields.items(): (leaf/name).write_text(text)
                before = set(os.listdir('/proc/self/fd'))
                read = kernel._text
                reads = []
                def observed_read(fd, name):
                    reads.append(name)
                    return read(fd, name)
                with patch.object(kernel, '_text', side_effect=observed_read), \
                        self.assertRaises(kernel.KernelBudgetError) as caught:
                    acquire()
                error = caught.exception
                self.assertEqual(str(error), 'aggregate-not-fresh')
                self.assertIsInstance(error, aggregate.AggregateCounterError)
                self.assertEqual(error.counter_diagnostic,
                    ('aggregate/'+filename, raw, 'aggregate-not-fresh'))
                for name in ('memory.peak', 'cpu.stat', 'memory.events'):
                    self.assertEqual(reads.count(name), 1)
                (leaf/filename).write_text('0\n' if filename == 'memory.peak' else 'usage_usec 0\n')
                self.assertEqual(error.counter_diagnostic.raw, raw)
                self.assertIsNone(self.native.operation)
                self.assertEqual(set(os.listdir('/proc/self/fd')), before)
                import shutil
                shutil.rmtree(Path(self.temporary.name)/'mount')

    def test_exact_memory_headroom_and_positive_cpu_task_partition_bind_actual_fields(self):
        quota = dict(memory_bytes=8*1024**3, cpu_quota_us=300000, tasks=250)
        leaf, unit, controller, observed, acquire = self.acquisition_fixture(controller_budget=quota)
        self.cap = cap = acquire()
        self.assertEqual(cap.nodes[0][3]['memory.max'], str(8*1024**3)+'\n')
        self.assertEqual(cap.nodes[1][3]['memory.max'], str(8*1024**3)+'\n')
        self.assertEqual(cap.nodes[0][3]['cpu.max'], '100000 100000\n')
        self.assertEqual(cap.nodes[0][3]['pids.max'], '6\n')
        cap.close(self)

    def test_mutating_caller_budget_during_preparation_cannot_reopen_headroom(self):
        quota = dict(memory_bytes=128*1024**2, cpu_quota_us=100000, tasks=16)
        leaf, unit, controller, observed, acquire = self.acquisition_fixture(controller_budget=quota)
        original = aggregate._source; fired = False
        def changed():
            nonlocal fired
            if not fired:
                fired = True
                quota['memory_bytes'] = 16*1024**3
                (controller/'memory.max').write_text(str(quota['memory_bytes'])+'\n')
            return original()
        with patch.object(aggregate, '_source', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'aggregate-finite-limits'): acquire()
        self.assertIsNone(self.native.operation)

    def test_synthetic_acquisition_rejects_unbounded_or_changed_parent_controller_and_used_leaf(self):
        for target, name, value in (('unit', 'memory.max', 'max\n'),
                ('unit', 'cgroup.max.descendants', 'max\n'), ('unit', 'cgroup.max.depth', 'max\n'),
                ('unit', 'cgroup.stat', 'nr_descendants 3\nnr_dying_descendants 0\n'),
                ('unit', 'cgroup.stat', 'nr_descendants 2\nnr_dying_descendants 1\n'),
                ('unit', 'cgroup.procs', '123\n'),
                ('controller', 'memory.max', 'max\n'), ('controller', 'cpu.max', 'max 100000\n'),
                ('controller', 'pids.max', 'max\n'), ('leaf', 'cgroup.max.descendants', 'max\n'),
                ('leaf', 'cpu.max', '400000 100000\n'), ('leaf', 'pids.max', '256\n'),
                ('leaf', 'memory.peak', '1\n'), ('leaf', 'cpu.stat', 'usage_usec 1\n')):
            with self.subTest(target=target, name=name):
                leaf, unit, controller, observed, acquire = self.acquisition_fixture()
                path = dict(leaf=leaf, unit=unit, controller=controller)[target]/name
                original = path.read_text(); path.write_text(value)
                descriptors_before = set(os.listdir('/proc/self/fd'))
                with self.assertRaises(ValueError): acquire()
                self.assertIsNone(self.native.operation)
                self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors_before)
                path.write_text(original)
                import shutil
                shutil.rmtree(Path(self.temporary.name)/'mount')

    def test_headroom_arithmetic_refuses_before_membership_io_or_registration(self):
        base = dict(memory_bytes=128*1024**2, cpu_quota_us=100000, tasks=16)
        for memory, controller in ((16*1024**3, base),
                (8*1024**3, dict(base, cpu_quota_us=400000)),
                (8*1024**3, dict(base, tasks=256)),
                (8*1024**3, dict(base, memory_bytes=8*1024**3+1))):
            with self.subTest(memory=memory, controller=controller), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('membership IO')), \
                    patch.object(aggregate.os, 'open', side_effect=AssertionError('group FD')):
                with self.assertRaisesRegex(ValueError, 'aggregate-controller-headroom'):
                    aggregate.acquire_aggregate_mechanics(self.native, unit='fixture.service',
                        invocation='1'*32, operation='/not-a-group', memory_bytes=memory,
                        controller_budget=controller, owner=self)
                self.assertIsNone(self.native.operation)

    def test_foreign_thread_acquisition_refuses_before_io_or_slot_change(self):
        def foreign():
            with patch.object(Path, 'read_text', side_effect=AssertionError('foreign IO')):
                with self.assertRaisesRegex(ValueError, 'owner-thread'):
                    aggregate.acquire_aggregate_mechanics(self.native, unit='fixture.service',
                        invocation='1'*32, operation='/not-a-group', memory_bytes=16*1024**3,
                        controller_budget={}, owner=self)
        with ThreadPoolExecutor(max_workers=1) as pool: pool.submit(foreign).result()
        self.assertIsNone(self.native.operation)

    def test_real_signal_reentry_during_acquisition_refuses_and_outer_close_retries(self):
        leaf, unit, controller, observed, acquire = self.acquisition_fixture()
        failures = []; original = aggregate._source; fired = False
        def handler(signum, frame):
            try:
                aggregate.acquire_aggregate_mechanics(self.native, unit='fixture.service',
                    invocation='1'*32, operation=str(leaf), memory_bytes=8*1024**3,
                    controller_budget={}, owner=self)
            except ValueError as error: failures.append(str(error))
        def source():
            nonlocal fired
            if not fired:
                fired = True; os.kill(os.getpid(), signal.SIGUSR1)
            return original()
        previous = signal.signal(signal.SIGUSR1, handler)
        try:
            with patch.object(aggregate, '_source', side_effect=source): self.cap = acquire()
        finally: signal.signal(signal.SIGUSR1, previous)
        self.assertEqual(failures, ['kernel-native-lifecycle-busy'])
        self.assertEqual(self.native._busy._recursion_count(), 0)
        self.cap.close(self); self.cap.close(self)
        self.assertIsNone(self.native.operation)

    def test_actual_held_directory_and_limits_or_invocation_change_is_sticky(self):
        for change in ('parent-limit', 'controller-limit', 'path', 'fd', 'invocation', 'source'):
            with self.subTest(change=change):
                leaf, unit, controller, observed, acquire = self.acquisition_fixture()
                def action(cap):
                    if change == 'parent-limit': (unit/'memory.max').write_text('max\n')
                    elif change == 'controller-limit': (controller/'pids.max').write_text('max\n')
                    elif change == 'path': leaf.rename(leaf.with_name('removed')); leaf.mkdir()
                    elif change == 'invocation': observed.stdout = observed.stdout.replace('1'*32, '2'*32)
                    elif change == 'fd':
                        other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
                        try: os.dup2(other, cap.nodes[0][1])
                        finally: os.close(other)
                    with patch.object(aggregate, '_source', return_value='changed' if change == 'source' else cap.source):
                        with self.assertRaises(ValueError): cap.verify()
                    self.assertTrue(cap.failed)
                    with self.assertRaisesRegex(ValueError, 'sticky'): cap.verify()
                acquire(action)
                # A replaced descriptor is never authority to close its new target.
                for slot in self.cap._fd_owners:
                    if slot[1] >= 0: self.native.release_owned(slot)
                self.native.operation = None
                import shutil
                shutil.rmtree(Path(self.temporary.name)/'mount')


if __name__ == '__main__': unittest.main()
