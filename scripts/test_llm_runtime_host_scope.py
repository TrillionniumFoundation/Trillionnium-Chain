"""Real transport/ordinary-FD controls; cgroup/systemd namespace NOT_RUN.

The full layout fixture uses ordinary temporary files and a mock manager. Its
positive path is a contract check, never evidence of native scope admission.
"""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import llm_runtime_host_scope as host
import llm_runtime_host_scope_io as bus
import llm_runtime_kernel_owned as kernel


def owned_slot_snapshot(cap):
    return tuple((tuple(slot), signature) for slot, signature in cap._fds)


class HostScopeTests(unittest.TestCase):
    def test_scope_request_binds_original_pid_exact_limits_and_no_auxiliary_unit(self):
        unit = 'trnm-host-'+'a'*32+'.scope'
        args = bus.scope_request(unit, os.getpid())
        self.assertEqual(args[:3], [unit, 'fail', '10'])
        self.assertEqual(args[3:7], ['PIDs', 'au', '1', str(os.getpid())])
        self.assertEqual(args[7:13], ['DelegateControllers', 'as', '3', 'cpu', 'memory', 'pids'])
        self.assertEqual(args[-1], '0')
        for key, value in [('MemoryMax', str(17*1024**3)), ('MemorySwapMax', '0'),
            ('CPUQuotaPerSecUSec', '5000000'), ('CPUQuotaPeriodUSec', '100000'),
            ('TasksMax', '272')]:
            index = args.index(key)
            self.assertEqual(args[index+1:index+3], ['t', value])
        self.assertNotIn('ExecStart', args)
        self.assertNotIn('DelegateSubgroup', args)

    def test_request_refuses_unbounded_or_reused_namespace_shapes(self):
        for unit, pid in [('old.service', 1), ('trnm-host-'+'a'*32+'.scope', 0),
            ('trnm-host-'+'a'*32+'.scope', True), ('trnm-host-'+'a'*32+'.scope', 2**31)]:
            with self.subTest(unit=unit, pid=pid), self.assertRaises(ValueError):
                bus.scope_request(unit, pid)

    def test_transport_reads_both_real_pipes(self):
        raw = bus._command([sys.executable, '-c',
            'import sys; sys.stderr.write("diagnostic"); sys.stdout.write("response")'])
        self.assertEqual(raw, b'response')

    def test_transport_refuses_actual_oversized_stdout_and_stderr(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), self.assertRaisesRegex(ValueError, 'output-bound'):
                bus._command([sys.executable, '-c',
                    'import sys; sys.'+stream+'.buffer.write(b"x"*131072)'])

    def test_transport_timeout_never_becomes_success(self):
        with self.assertRaisesRegex(ValueError, 'timeout-unknown'):
            bus._command([sys.executable, '-c', 'import time; time.sleep(4)'])

    def test_typed_response_bound_and_single_result_are_required(self):
        self.assertEqual(bus.checked_data(b'{"type":"o","data":["/job/1"]}', 'o'), '/job/1')
        for value in [b'x'*65537, b'{"type":"s","data":["/job/1"]}',
                      b'{"type":"o","data":[]}', b'{"type":"o","data":[1,2]}']:
            with self.subTest(value=value[:40]), self.assertRaises(ValueError):
                bus.checked_data(value, 'o')

    def test_real_busctl_property_shapes_are_not_method_result_tuples(self):
        # Shapes independently observed by read-only calls on the real manager.
        for signature, value in [('s', 'scope'), ('b', True), ('t', 272),
            ('ay', list(range(16))), ('as', ['cpu', 'memory', 'pids'])]:
            raw = json.dumps({'type': signature, 'data': value}).encode()
            self.assertEqual(bus.checked_data(raw, signature, property_value=True), value)
        with self.assertRaises(ValueError):
            bus.checked_data(b'{"type":"s","data":["scope"]}', 's', property_value=True)
        with self.assertRaises(ValueError):
            bus.checked_data(b'{"type":"b","data":1}', 'b', property_value=True)

    def test_ancestor_ceilings_allow_headroom_but_are_never_a_reservation(self):
        host._ancestor_allows({'memory.max': 'max\n', 'pids.max': 'max\n', 'cpu.max': 'max 100000\n'})
        values = {'memory.max': str(17*1024**3)+'\n', 'pids.max': '272\n',
                  'cpu.max': '1000000 200000\n'}
        host._ancestor_allows(values)
        for key, value in [('memory.max', str(17*1024**3-1)+'\n'),
            ('pids.max', '271\n'), ('cpu.max', '499999 100000\n'),
            ('cpu.max', 'max 0\n'), ('pids.max', str(2**64)+'\n')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                host._ancestor_allows(dict(values, **{key: value}))

    def test_original_observed_core_sched_counter_is_accepted_without_open_dotted_keys(self):
        self.assertEqual(host._fields('usage_usec 0\ncore_sched.force_idle_usec 0\n'),
                         {'usage_usec': 0, 'core_sched.force_idle_usec': 0})
        for value in ['other.counter 0\n', 'usage_usec 0\nusage_usec 1\n',
                      'core_sched.force_idle_usec '+str(2**64)+'\n']:
            with self.subTest(value=value), self.assertRaises(ValueError): host._fields(value)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        cap = object.__new__(host.HostScopeAdmission)
        cap._lock = kernel._native_rlock()
        cap._pid, cap._thread = os.getpid(), threading.current_thread()
        cap._started = cap._ready = cap._failed = cap._closed = False
        cap._fds, cap._groups, cap._namespaces, cap._ancestors = [], {}, {}, []
        cap._native = kernel.build_controlled_native()
        self.addCleanup(cap._native.close)
        cap._unit = 'trnm-host-'+'a'*32+'.scope'
        cap._operation_name = 'operation-'+'b'*32
        cap._unit_path = cap._invocation = cap._job = None
        cap._original_membership = '0::/user.slice/original.scope\n'
        proc = root/'proc'; proc.mkdir(); (proc/'cgroup').write_text(cap._original_membership)
        cap._proc = cap._hold(str(proc))
        cap._owner = Mock()  # Synthetic proc/mount fixture, explicitly not a native grant.
        cap._check_mount = Mock()
        cap._manager = Mock()
        cap._manager.call.side_effect = lambda method, *_: (
            '/org/freedesktop/systemd1/job/123' if method == 'StartTransientUnit'
            else '/org/freedesktop/systemd1/unit/trnm_2dhost')
        control = '/user.slice/user-1000.slice/user@1000.service/app.slice/'+cap._unit
        cap._manager_readback = Mock(return_value=control)
        paths = {}
        def populate(role, path):
            paths[role] = path
            fields = dict(host._limits(role), **{'cgroup.type': 'domain\n',
                'cgroup.procs': '', 'cgroup.subtree_control': '',
                'cgroup.stat': 'nr_descendants 0\nnr_dying_descendants 0\n',
                'pids.current': '0\n', 'cgroup.events': 'populated 0\nfrozen 0\n',
                'memory.current': '0\n', 'memory.swap.current': '0\n', 'memory.peak': '0\n',
                'cpu.stat': 'usage_usec 0\nnr_periods 0\n'})
            if role == 'scope':
                fields.update({'cgroup.max.depth': 'max\n', 'cgroup.max.descendants': 'max\n',
                               'cgroup.procs': str(cap._pid)+'\n'})
            for name, value in fields.items(): (path/name).write_text(value)
        def open_scope(_):
            path = root/'scope'; path.mkdir(); populate('scope', path)
            (proc/'cgroup').write_text('0::'+control+'\n')
            fd = cap._hold(str(path))
            cap._groups['scope'] = (None, control, fd, kernel.proc._signature(fd))
            return fd
        cap._open_original_scope = open_scope
        original_group = cap._group
        def group(role, parent, name):
            fd = original_group(role, parent, name)
            path = Path('/proc/self/fd/'+str(fd)).resolve()
            populate(role, path)
            for parent_role, parent_path in paths.items():
                descendants = sum(1 for p in paths.values() if p != parent_path and parent_path in p.parents)
                (parent_path/'cgroup.stat').write_text(
                    'nr_descendants '+str(descendants)+'\nnr_dying_descendants 0\n')
            return fd
        cap._group = group
        writes = []
        def write(fd, name, value):
            path = Path('/proc/self/fd/'+str(fd)).resolve()
            writes.append((path.name, name, value))
            if name == 'cgroup.procs':
                for p in paths.values(): (p/name).write_text('')
                suffix = str(path.relative_to(paths['scope']))
                (proc/'cgroup').write_text('0::'+control+'/'+suffix+'\n')
            if name == 'cgroup.subtree_control':
                self.assertEqual((path/'cgroup.procs').read_text(), '')
                value = 'cpu memory pids\n'
            (path/name).write_text(value)
        cap._write = write
        def cleanup():
            for slot, _ in reversed(cap._fds):
                if slot[1] >= 0: cap._native.release_owned(slot)
            cap._fds.clear()
        self.addCleanup(cleanup)
        return cap, paths, writes

    def test_synthetic_layout_uses_two_empty_root_transitions_and_h_hard_limits(self):
        cap, paths, writes = self.fixture()
        cap.admit()
        self.assertTrue(cap._ready)
        self.assertFalse(cap._failed)
        self.assertEqual((paths['scope']/'cgroup.max.depth').read_text(), 'max\n')
        self.assertEqual((paths['host']/'cgroup.max.depth').read_text(), '2\n')
        self.assertEqual((paths['host']/'cgroup.max.descendants').read_text(), '4\n')
        self.assertEqual([row[0] for row in writes if row[1] == 'cgroup.procs'], ['host', 'observer'])
        self.assertFalse(any(row[0] == 'scope' and row[1] != 'cgroup.subtree_control' for row in writes))
        self.assertNotIsInstance(cap, kernel._ControlledOperation)
        for name in ('spawn', 'terminal_record', 'settle', 'refund'):
            self.assertFalse(hasattr(cap, name))
        cap.verify()

    def test_scope_request_unknown_is_sticky_and_cannot_close_or_retry(self):
        cap, _, _ = self.fixture()
        cap._manager.call.side_effect = TimeoutError('unknown manager outcome')
        original_slots = owned_slot_snapshot(cap)
        with self.assertRaises(TimeoutError): cap.admit()
        self.assertTrue(cap._started)
        self.assertTrue(cap._failed)
        self.assertFalse(cap._ready)
        held = list(cap._fds)
        with self.assertRaisesRegex(ValueError, 'one-original-request'): cap.admit()
        with self.assertRaisesRegex(ValueError, 'original-effect-retained'): cap.close_before_effect()
        self.assertEqual(cap._fds, held)
        self.assertEqual(owned_slot_snapshot(cap), original_slots)
        self.assertEqual(cap._manager.call.call_count, 1)

    def test_changed_limit_or_late_charge_refuses_without_cleaning_up(self):
        for role, name, value in [('host', 'cgroup.max.descendants', 'max\n'),
            ('operation', 'memory.current', '4096\n'), ('controller', 'memory.peak', '1\n'),
            ('aggregate', 'pids.current', '1\n'), ('aggregate', 'cpu.stat', 'usage_usec 1\n')]:
            with self.subTest(role=role, name=name):
                cap, paths, _ = self.fixture(); cap.admit()
                (paths[role]/name).write_text(value)
                with self.assertRaises(ValueError): cap.verify()
                self.assertTrue(cap._failed)
                self.assertFalse(cap._ready)
                self.assertEqual((paths[role]/name).read_text(), value)
                self.assertTrue(paths['scope'].exists())
                with self.assertRaises(ValueError): cap.verify()

    def test_old_group_is_not_adopted_and_original_held_fds_remain(self):
        cap, paths, _ = self.fixture()
        original = cap._group
        def collide(role, parent, name):
            if role == 'operation': os.mkdir(name, dir_fd=parent)
            return original(role, parent, name)
        cap._group = collide
        with self.assertRaises(FileExistsError): cap.admit()
        self.assertTrue(cap._failed)
        self.assertTrue((paths['host']/cap._operation_name).is_dir())
        self.assertGreater(len(cap._fds), 1)

    def test_original_owner_cannot_be_copied_or_serialized(self):
        import pickle
        cap, _, _ = self.fixture()
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation), self.assertRaises(TypeError): operation(cap)

    def test_fstat_failure_keeps_real_opened_fd_in_original_owner_slot(self):
        cap, _, _ = self.fixture()
        fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        with patch.object(kernel.proc, '_signature', side_effect=InterruptedError('injected fstat')):
            with self.assertRaises(InterruptedError): cap._retain(fd)
        self.assertEqual(cap._fds[-1][0][1], fd)
        self.assertIsNone(cap._fds[-1][1])
        os.fstat(fd)  # Still held, not silently untracked.
        cap.close_before_effect()
        self.assertTrue(cap._closed)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_partial_close_keeps_native_closed_slot_and_retries_remaining_owner(self):
        cap, _, _ = self.fixture()
        first = cap._retain(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC))
        last = cap._retain(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC))
        signature = kernel.proc._signature
        def interrupted(fd):
            if fd == first: raise InterruptedError('injected before remaining close')
            return signature(fd)
        with patch.object(kernel.proc, '_signature', side_effect=interrupted):
            with self.assertRaises(InterruptedError): cap.close_before_effect()
        self.assertEqual(cap._fds[-1][0][1], -1)
        os.fstat(first)
        with self.assertRaises(OSError): os.fstat(last)
        cap.close_before_effect()  # Skips the original native-cleared last slot.
        self.assertTrue(cap._closed)
        with self.assertRaises(OSError): os.fstat(first)

    def test_owned_fd_snapshot_detects_controlled_mutable_slot_or_signature_change(self):
        # Real held descriptors, synthetic bookkeeping changes only. No manager
        # request occurs and the ordinary fixture teardown closes its own FDs;
        # no mutated capability is admitted, reused or settled.
        for mutation in ('slot', 'signature'):
            with self.subTest(mutation=mutation):
                cap, _, _ = self.fixture()
                fd = cap._retain(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC))
                before = owned_slot_snapshot(cap)
                shallow = list(cap._fds)
                if mutation == 'slot':
                    cap._fds[-1][0][0] = 5  # Explicit test-only error-state mutation.
                else:
                    cap._fds[-1][1] = ('controlled-signature-change',)
                self.assertEqual(cap._fds, shallow)  # Shows why the old copy missed it.
                with self.assertRaises(AssertionError):
                    self.assertEqual(owned_slot_snapshot(cap), before)
                os.fstat(fd)  # Mutation neither closed nor replaced the real FD.
                self.assertFalse(cap._started)
                self.assertFalse(cap._ready)
                cap._manager.call.assert_not_called()

    def test_constructor_cleanup_fault_carries_same_original_native_slot_owner(self):
        native = kernel.build_controlled_native()
        self.addCleanup(native.close)
        release = native.release_owned
        def uncertain_close(slot):
            release(slot)  # Real native close-and-clear, then injected status failure.
            slot[0] = 5
            return 5
        native.release_owned = uncertain_close
        with patch.object(kernel, 'build_controlled_native', return_value=native), \
             patch.object(kernel.proc, '_signature', side_effect=InterruptedError('injected first fstat')):
            with self.assertRaises(kernel.KernelOwnedCloseRequired) as caught:
                host.prepare_host_scope()
        cap = caught.exception.capability
        self.assertIs(cap._native, native)
        self.assertEqual(cap._fds[0][0][0], 5)
        self.assertEqual(cap._fds[0][0][1], -1)
        self.assertFalse(cap._started)
        self.assertFalse(cap._closed)
        native.release_owned = release
        cap._fds[0][0][0] = 0  # Test-only release after preserving the injected error.
        cap.close_before_effect()
        self.assertTrue(cap._closed)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HostScopeTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'scope': 'ordinary FD and bounded transport only; native namespace NOT_RUN',
        'run': result.testsRun, 'skipped': len(result.skipped), 'success': result.wasSuccessful()}))
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
