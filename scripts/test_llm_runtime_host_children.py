"""Same-owner preparation controls using ordinary files/FDs and mocked manager.

No systemd/cgroup namespace, native C/A birth, wait4 or resource qualification.
"""
import copy
import os
import sys
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import test_llm_runtime_host_scope as legacy


class ChildPreparationTests(unittest.TestCase):
    def fixture(self):
        return legacy.HostScopeTests.fixture(self)

    def consumed(self):
        cap, paths, writes = legacy.HostScopeTests.leaf_fixture(self)
        cap._first_pristine_failure = None  # Align ordinary fixture with constructor.
        fact = cap.admit_fresh_leaf()
        cap.consume_fresh_leaf(fact)
        (paths['operation']/'memory.events').write_text('low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n')
        original = cap._group
        def group(role, parent, name):
            fd = original(role, parent, name)
            # Modeled metadata charge written to real ordinary files. This is
            # deliberately not an observed native kernel byte decomposition.
            amount = 258048*(1 if role == 'controller' else 2)
            for meter in ('memory.current', 'memory.peak'):
                (paths['operation']/meter).write_text(str(amount)+'\n')
            return fd
        cap._group = group
        return cap, paths, writes, fact

    def assert_unknown(self, cap):
        self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')
        self.assertTrue(cap._failed)
        self.assertFalse(cap._ready)
        self.assertFalse(cap._closed)
        snapshot = legacy.owned_slot_snapshot(cap)
        for invoke in (cap.prepare_fresh_child_groups, cap.verify_child_preparation,
                       cap.close_before_effect):
            with self.assertRaises(ValueError): invoke()
            self.assertEqual(legacy.owned_slot_snapshot(cap), snapshot)
        return snapshot

    def test_same_original_cap_creates_exact_children_and_keeps_full_u_charge(self):
        cap, paths, writes, fact = self.consumed()
        before = len(cap._fds); native = cap._native
        pristine, original = [], cap._require_pristine
        def check(role, fd):
            pristine.append(role)
            return original(role, fd)
        cap._require_pristine = check
        self.assertIsNone(cap.prepare_fresh_child_groups())
        self.assertEqual(cap._leaf_phase, 'CHILD_GROUPS_PREPARED')
        self.assertFalse(cap._ready)
        self.assertIs(cap._leaf_fact, fact)
        self.assertIs(cap._native, native)
        self.assertEqual(len(cap._fds), before+2)
        self.assertEqual(tuple(cap._groups), ('scope','host','observer','operation','controller','aggregate'))
        self.assertEqual(pristine, ['controller','controller','aggregate'])
        self.assertEqual((paths['operation']/'memory.current').read_text(), '516096\n')
        self.assertEqual((paths['operation']/'memory.peak').read_text(), '516096\n')
        for role in ('controller','aggregate'):
            for name, value in host._limits(role).items():
                self.assertEqual((paths[role]/name).read_text(), value)
            self.assertEqual((paths[role]/'cgroup.procs').read_text(), '')
        self.assertIsNone(cap.verify_child_preparation())
        self.assertNotIn('operation', pristine)
        for name in ('spawn','prepare_children','retire','settle','refund','terminal_record'):
            self.assertFalse(hasattr(cap,name))
        self.assertEqual([r[0] for r in writes if r[1]=='cgroup.procs'],['host','observer'])
        self.assertIsNone(cap._first_pristine_failure)
        # Exercise the actual existing consumer's type gate before it can create
        # an output directory or spawn anything; this phase is not its authority.
        output = paths['operation']/'must-not-run'
        with self.assertRaisesRegex(ValueError, 'AGGREGATE_BUDGET_INTERFACE'):
            runtime.supervise([sys.executable, '-c', 'raise SystemExit(9)'], output,
                dict(wall_seconds=8, rss_bytes=8*1024**3), _aggregate_operation=cap)
        self.assertFalse(output.exists())
        self.assertEqual(cap._leaf_phase, 'CHILD_GROUPS_PREPARED')
        self.assertFalse(cap._ready)

    def test_unconsumed_fact_and_legacy_cap_cannot_start_the_new_phase(self):
        for mode in ('legacy','unconsumed'):
            with self.subTest(mode=mode):
                cap, paths, _ = (self.fixture() if mode=='legacy' else
                                  legacy.HostScopeTests.leaf_fixture(self))
                if mode=='unconsumed': cap.admit_fresh_leaf()
                slots=legacy.owned_slot_snapshot(cap)
                with self.assertRaisesRegex(ValueError,'consumed-leaf-required'):
                    cap.prepare_fresh_child_groups()
                self.assertEqual(legacy.owned_slot_snapshot(cap),slots)
                self.assertFalse('controller' in paths or 'aggregate' in paths)
                self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')

    def test_existing_child_name_is_refused_without_adoption_or_removal(self):
        cap, paths, _, _ = self.consumed()
        old=paths['operation']/'controller';old.mkdir();(old/'canary').write_bytes(b'keep')
        slots=legacy.owned_slot_snapshot(cap)
        with self.assertRaises(ValueError): cap.prepare_fresh_child_groups()
        self.assertEqual((old/'canary').read_bytes(),b'keep')
        self.assertEqual(legacy.owned_slot_snapshot(cap),slots)
        self.assert_unknown(cap)

    def test_actual_eexist_race_and_hold_failure_retain_the_attempt(self):
        for failure in ('mkdir-race','hold-after-mkdir'):
            with self.subTest(failure=failure):
                cap, paths, _, _ = self.consumed()
                old_group=cap._group;old_hold=cap._hold
                if failure=='mkdir-race':
                    def group(role,parent,name):
                        if role=='controller':
                            (paths['operation']/name).mkdir()
                            (paths['operation']/name/'canary').write_bytes(b'keep')
                        return old_group(role,parent,name)
                    cap._group=group
                else:
                    def hold(name,parent=None):
                        if name=='controller': raise OSError('after real mkdir')
                        return old_hold(name,parent)
                    cap._hold=hold
                slots=legacy.owned_slot_snapshot(cap)
                with self.assertRaises(OSError): cap.prepare_fresh_child_groups()
                self.assertEqual(cap._child_preparation_attempt,'controller')
                self.assertTrue((paths['operation']/'controller').is_dir())
                self.assertEqual(legacy.owned_slot_snapshot(cap),slots)
                self.assert_unknown(cap)

    def test_partial_first_and_second_child_fault_keeps_original_error_and_all_slots(self):
        for role in ('controller','aggregate'):
            for error in (OSError('write/readback unknown'),MemoryError('allocation'),KeyboardInterrupt()):
                with self.subTest(role=role,error=type(error).__name__):
                    cap, paths, _, _ = self.consumed()
                    configure=cap._configure
                    def fail(target,fd):
                        configure(target,fd)
                        if target==role: raise error
                    cap._configure=fail
                    with self.assertRaises(type(error)): cap.prepare_fresh_child_groups()
                    self.assertTrue((paths['operation']/role).is_dir())
                    self.assertEqual(cap._child_preparation_attempt,role)
                    original=cap._first_child_preparation_error
                    self.assertIs(original[2],error)
                    self.assertEqual(original[1],role)
                    self.assert_unknown(cap)
                    self.assertIs(cap._first_child_preparation_error,original)
                    for _,_,fd,_ in cap._groups.values(): os.fstat(fd)

    def test_post_birth_u_budget_or_actual_leaf_use_is_never_exempted(self):
        cases=[('operation','memory.current',str(16*1024**3+1)+'\n'),
            ('operation','memory.peak',str(16*1024**3+1)+'\n'),
            ('operation','memory.swap.current','1\n'),('operation','pids.current','1\n'),
            ('operation','cpu.stat','usage_usec 1\n'),('operation','cgroup.events','populated 1\n'),
            ('operation','memory.events','max 1\n'),('controller','memory.current','1\n'),
            ('aggregate','memory.peak','1\n'),('aggregate','pids.current','1\n')]
        for role,name,raw in cases:
            with self.subTest(role=role,name=name):
                cap,paths,_,_=self.consumed();cap.prepare_fresh_child_groups()
                (paths[role]/name).write_text(raw)
                with self.assertRaises(ValueError):cap.verify_child_preparation()
                self.assertEqual((paths[role]/name).read_text(),raw)
                self.assert_unknown(cap)

    def test_identity_limits_topology_manager_source_and_ancestor_changes_refuse(self):
        for mode in ('replace','limit','topology','dying','manager','source','ancestor'):
            with self.subTest(mode=mode):
                cap,paths,_,_=self.consumed();cap.prepare_fresh_child_groups()
                if mode=='replace':
                    paths['aggregate'].rename(paths['operation']/'kept-old')
                    paths['aggregate'].mkdir()
                elif mode=='limit':(paths['controller']/'memory.max').write_text('max\n')
                elif mode=='topology':(paths['aggregate']/'foreign').mkdir()
                elif mode=='dying':(paths['operation']/'cgroup.stat').write_text('nr_descendants 2\nnr_dying_descendants 1\n')
                elif mode=='manager':cap._manager_readback.side_effect=TimeoutError('manager identity unknown')
                elif mode=='source':cap._leaf_fact._binding=('wrong-source',)
                else:
                    cap._ancestors=[(cap._groups['scope'][2],{'memory.max':'max\n'})]
                with self.assertRaises((ValueError,TimeoutError)):cap.verify_child_preparation()
                self.assert_unknown(cap)

    def test_actual_cross_thread_owner_guard_and_legacy_verify_fail_sticky(self):
        cap,paths,_,_=self.consumed();cap.prepare_fresh_child_groups()
        owner=host.HostScopeAdmission._owner.__get__(cap)
        cap._owner=owner
        failures=[]
        def foreign():
            try:cap.verify_child_preparation()
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=foreign);thread.start();thread.join()
        self.assertEqual(len(failures),1)
        self.assertIn('original-pid-thread-required',str(failures[0]))
        cap._owner=lambda:None  # Fixture-only cleanup; not a production owner handoff.
        self.assert_unknown(cap)
        other,_,_,_=self.consumed();other.prepare_fresh_child_groups()
        with self.assertRaises(ValueError):other.verify()
        self.assertEqual(other._leaf_phase,'UNKNOWN_RETAINED')
        self.assertFalse(other._ready)

    def test_phase_cannot_reenter_or_serialize_into_a_new_owner(self):
        cap,paths,_,_=self.consumed();cap.prepare_fresh_child_groups()
        slots=legacy.owned_slot_snapshot(cap)
        for copy_cap in (copy.copy,copy.deepcopy):
            with self.assertRaises(TypeError):copy_cap(cap)
        with self.assertRaises(ValueError):cap.prepare_fresh_child_groups()
        self.assert_unknown(cap)
        self.assertEqual(legacy.owned_slot_snapshot(cap),slots)


if __name__=='__main__':unittest.main(verbosity=2)
