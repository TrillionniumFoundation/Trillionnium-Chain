"""Deterministic atomic step/UNKNOWN controls, ordinary own directories only.

Pause adapters exist only in this test's compiled source copy. They add no
production hook, worker, retry or cgroup qualification. All old controls remain.
"""
import ctypes
import errno
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_owned as kernel
import test_llm_runtime_retirement_activation as previous
import test_llm_runtime_host_retirement as modeled

STOP=0x80000000


class RetirementStepCommitTests(unittest.TestCase):
    input=previous.RetirementActivationTests.input
    prepare=previous.RetirementActivationTests.prepare
    ready=previous.RetirementActivationTests.ready
    finished=previous.RetirementActivationTests.finished
    fixture=previous.RetirementActivationTests.fixture

    def library(self):
        # Current source: pause immediately before/after its actual strong CAS.
        # Historical f69: insert a pause immediately before the old irreversible
        # call, after its last check. No old safety check/body is removed.
        raw=kernel._bytes(kernel._RETIREMENT_C)
        prototype=b'''\nint review_step_cas(_Atomic unsigned *, unsigned *, unsigned, memory_order, memory_order);
void review_legacy_pause(unsigned);
'''
        anchor=b'#include <sys/mman.h>\n'
        self.assertEqual(raw.count(anchor),1)
        raw=raw.replace(anchor,anchor+prototype)
        needle=b'atomic_compare_exchange_strong_explicit(&trnm_retirement.step_state'
        if needle in raw:
            self.assertEqual(raw.count(needle),1)
            raw=raw.replace(needle,b'review_step_cas(&trnm_retirement.step_state')
        else:
            # Exact retained legacy behavior plus these three synchronization
            # calls only, allowing a reproducible RED rather than lucky timing.
            for old,new in [
                (b'    if (unlinkat(trnm_retirement.parent, name, AT_REMOVEDIR))',
                 b'    review_legacy_pause(bit == 1U ? 1U : 3U);\n    if (unlinkat(trnm_retirement.parent, name, AT_REMOVEDIR))'),
                (b'    error = trnm_kernel_release_owned_v1(slot);',
                 b'    review_legacy_pause(bit == 1U ? 2U : 4U);\n    error = trnm_kernel_release_owned_v1(slot);'),
                (b'        error = trnm_kernel_close_v1(trnm_retirement.child, 2U);',
                 b'        review_legacy_pause(5U);\n        error = trnm_kernel_close_v1(trnm_retirement.child, 2U);')]:
                self.assertEqual(raw.count(old),1);raw=raw.replace(old,new)
        raw+=b'''
static unsigned review_target_step, review_after_commit;
static _Atomic unsigned review_step_entered, review_step_released;
void review_step_arm(unsigned step, unsigned after) {
    review_target_step = step; review_after_commit = after;
}
static void review_step_pause(unsigned step, unsigned after) {
    if (step == review_target_step && after == review_after_commit) {
        atomic_store(&review_step_entered, 1);
        while (!atomic_load(&review_step_released)) usleep(1000);
    }
}
int review_step_cas(_Atomic unsigned *value, unsigned *expected, unsigned desired,
        memory_order success, memory_order failure) {
    review_step_pause(desired, 0);
    int committed = atomic_compare_exchange_strong_explicit(value, expected, desired, success, failure);
    if (committed) review_step_pause(desired, 1);
    return committed;
}
void review_legacy_pause(unsigned step) { review_step_pause(step, 0); }
unsigned review_step_blocked(void) { return atomic_load(&review_step_entered); }
void review_step_continue(void) { atomic_store(&review_step_released, 1); }
'''
        temporary=tempfile.TemporaryDirectory(prefix='trnm-step-test-source-')
        self.addCleanup(temporary.cleanup)
        target=Path(temporary.name)/'retirement-paused.c';target.write_bytes(raw)
        # Reuse exactly the existing own-dir/child fixture and test-only parent
        # filesystem wrapper. Production retains its real CGROUP2 rejection.
        with patch.object(kernel,'_RETIREMENT_C',target):
            lib=previous.RetirementActivationTests.library(self)
        lib.review_step_arm.argtypes=[ctypes.c_uint,ctypes.c_uint]
        return lib

    def paused(self,step,after,seconds=.8):
        values=self.fixture(seconds=seconds)
        lib,root,owned,child,out,deadline,args=values
        lib.review_step_arm(step,after)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0)
        while not lib.review_step_blocked():
            self.assertLess(time.monotonic_ns(),deadline);time.sleep(.001)
        return values

    def assert_effects(self,root,owned,child,completed):
        self.assertEqual((root/'aggregate').exists(),completed<1)
        self.assertEqual(owned[0][1]==-1,completed>=2)
        self.assertEqual((root/'controller').exists(),completed<3)
        self.assertEqual(owned[1][1]==-1,completed>=4)
        self.assertEqual(child[1]==-1,completed>=5)

    def test_cancel_wins_before_each_commit_no_new_effect_or_remaining_fd_close(self):
        for step in range(1,6):
            with self.subTest(step=step):
                lib,root,owned,child,out,deadline,args=self.paused(step,0)
                try:
                    self.assertEqual(lib.trnm_kernel_retirement_retain_v1(out),0)
                finally:lib.review_step_continue()
                self.finished(lib,out,deadline)
                # Assert actual effects first: retained f69 really fails here,
                # not merely because it lacks the new private word23 field.
                self.assertEqual(out[20],(1 << (step-1))-1)
                self.assert_effects(root,owned,child,step-1)
                self.assertEqual((out[0],out[1],out[23]),(5,errno.ECANCELED,STOP|step-1))
                self.assertEqual(out[8],deadline)
                self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)

    def test_commit_wins_then_cancel_only_that_step_can_finish(self):
        for step in range(1,6):
            with self.subTest(step=step):
                lib,root,owned,child,out,deadline,args=self.paused(step,1)
                try:
                    self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
                    self.assertEqual(out[23],step)
                    self.assertEqual(out[20],(1 << (step-1))-1)
                    self.assert_effects(root,owned,child,step-1)
                    self.assertEqual(lib.trnm_kernel_retirement_retain_v1(out),0)
                finally:lib.review_step_continue()
                self.finished(lib,out,deadline)
                self.assertEqual((out[0],out[1],out[20],out[23]),
                    (5,errno.ECANCELED,(1 << step)-1,STOP|step))
                self.assert_effects(root,owned,child,step)
                self.assertEqual(out[8],deadline)
                self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)

    def test_expired_after_commit_records_only_committed_step_and_keeps_original_cutoff(self):
        lib,root,owned,child,out,deadline,args=self.paused(1,1,.25)
        try:
            time.sleep(max(0,(deadline-time.monotonic_ns())/10**9)+.01)
            self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
            self.assertEqual((out[0],out[1],out[20],out[23]),(4,errno.ETIMEDOUT,0,STOP|1))
            self.assert_effects(root,owned,child,0)
        finally:lib.review_step_continue()
        self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20],out[23]),(4,errno.ETIMEDOUT,1,STOP|1))
        self.assert_effects(root,owned,child,1)
        self.assertEqual(out[8],deadline)


class RetirementStepPhaseTests(unittest.TestCase):
    fixture=modeled.HostRetirementTests.fixture
    prepared=modeled.HostRetirementTests.prepared
    binding=modeled.HostRetirementTests.binding
    launch=modeled.HostRetirementTests.launch
    terminal=modeled.HostRetirementTests.terminal

    def test_private_layout2_rejects_illegal_steps_and_stop_without_close_or_release(self):
        for state,progress in [(6,0),(16,0),(STOP|6,0),(1,3),(STOP|1,1)]:
            with self.subTest(state=state,progress=progress):
                launch,op,cap,paths,child=self.terminal()
                def activate(*args):
                    launch._retirement[0]=6;launch._retirement[19]=1
                    launch._retirement[20]=progress;launch._retirement[23]=state
                    return 0
                op.native.activate_retirement=Mock(side_effect=activate)
                before=[tuple(slot) for slot,_ in cap._fds]
                if state==STOP|1:
                    result=op._retire_children()
                    self.assertFalse(result['child_unlink_and_close_proven'])
                    self.assertFalse(result['whole_u_terminal'])
                    self.assertEqual(result['reservation'],'RETAINED')
                else:
                    with self.assertRaisesRegex(ValueError,'effect-identity'):op._retire_children()
                self.assertEqual([tuple(slot) for slot,_ in cap._fds],before)
                self.assertGreater(child._kernel_handoff[1],2)
                self.assertTrue(op.failed)


if __name__=='__main__':unittest.main(verbosity=2)
