"""Actual one-shot native worker effects on ordinary own empty directories.

Only the test wrapper substitutes parent filesystem qualification, explicitly;
production still refuses ordinary directories. This is not cgroup retirement,
funding, Whole-U zero, or a release test. No external process/group is changed.
"""
import ctypes
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import llm_runtime_kernel_owned as kernel
import test_llm_runtime_retirement_slot as preparation


class RetirementActivationTests(unittest.TestCase):
    input = preparation.RetirementPreparationTests.input
    prepare = preparation.RetirementPreparationTests.prepare
    ready = preparation.RetirementPreparationTests.ready
    expired = preparation.RetirementPreparationTests.expired

    def library(self, fault=0):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-retirement-activation-test-')
        self.addCleanup(temporary.cleanup)
        source = b'''#define fstatfs review_statfs
#define unlinkat review_unlinkat
#define close review_close
'''+kernel._bytes(kernel._C)+b'\n'+kernel._bytes(kernel._RETIREMENT_C)+b'''
#undef fstatfs
#undef unlinkat
#undef close
extern int fstatfs(int, struct statfs *);
extern int unlinkat(int, const char *, int);
extern int close(int);
static int review_parent = -1, review_aggregate = -1, review_fault;
static _Atomic unsigned review_calls, review_entered, review_release;
static _Atomic int review_effect_tid;
void review_configure(int parent, int aggregate, int fault) {
    review_parent = parent; review_aggregate = aggregate; review_fault = fault;
}
int review_statfs(int fd, struct statfs *value) {
    int result = fstatfs(fd, value);
    if (!result && fd == review_parent && review_fault != 9) value->f_type = TRNM_CGROUP2_MAGIC;
    return result;
}
int review_unlinkat(int parent, const char *name, int flags) {
    if (parent == review_parent) {
        atomic_store(&review_effect_tid, (int)syscall(SYS_gettid));
        unsigned call = atomic_fetch_add(&review_calls, 1) + 1;
        if ((review_fault == 1 && call == 1) || (review_fault == 2 && call == 2)) {
            errno = EPERM; return -1;
        }
        if (review_fault == 3 && call == 1) {
            atomic_store(&review_entered, 1);
            while (!atomic_load(&review_release)) usleep(1000);
        }
    }
    return unlinkat(parent, name, flags);
}
int review_close(int fd) {
    int result = close(fd);
    if (fd == review_aggregate && review_fault == 4) { errno = EIO; return -1; }
    return result;
}
unsigned review_count(void) { return atomic_load(&review_calls); }
int review_tid(void) { return atomic_load(&review_effect_tid); }
int review_blocked(void) { return atomic_load(&review_entered); }
void review_continue(void) { atomic_store(&review_release, 1); }
'''
        output = Path(temporary.name)/'activation.so'
        built = subprocess.run(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra',
            '-Werror','-pthread','-x','c','-','-o',str(output)], input=source,capture_output=True)
        self.assertEqual(built.returncode,0,built.stderr.decode())
        lib = ctypes.CDLL(str(output))
        words, slots = ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int)
        lib.trnm_kernel_retirement_prepare_v1.argtypes = [ctypes.c_int,words,ctypes.c_char_p,
            ctypes.c_size_t,ctypes.c_uint64,words]
        lib.trnm_kernel_retirement_prepare_v1.restype = ctypes.c_int
        lib.trnm_kernel_retirement_snapshot_v1.argtypes = [words]
        lib.trnm_kernel_retirement_snapshot_v1.restype = ctypes.c_int
        lib.trnm_kernel_retirement_activate_v1.argtypes = [ctypes.c_int,slots,slots,slots,words,
            ctypes.c_uint64,words]
        lib.trnm_kernel_retirement_activate_v1.restype = ctypes.c_int
        lib.trnm_kernel_retirement_retain_v1.argtypes = [words]
        lib.trnm_kernel_retirement_retain_v1.restype = ctypes.c_int
        lib.review_configure.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_int]
        return lib

    def fixture(self, fault=0, seconds=.8):
        lib=self.library();values=self.input();output=values[3]
        temporary=tempfile.TemporaryDirectory(prefix='trnm-retirement-owned-targets-')
        self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        for name in ('aggregate','controller'):(root/name).mkdir()
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        self.addCleanup(os.close,parent)
        owned=[]
        for name in ('aggregate','controller'):
            fd=os.open(root/name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            owned.append((ctypes.c_int*4)(0,fd,-1,-1))
        # A real direct own child is exact-wait4'ed while its original pidfd is
        # retained. This qualifies only native close/order, not the C/A proof.
        pid=os.fork()
        if pid==0:os._exit(0)
        fd=os.pidfd_open(pid)
        self.assertEqual(os.wait4(pid,0)[0],pid)
        child=(ctypes.c_int*4)(pid,fd,-1,-1)
        def cleanup():
            for slot in owned+[child]:
                if slot[1]>=0:os.close(slot[1]);slot[1]=-1
        self.addCleanup(cleanup)
        identity=(ctypes.c_uint64*12)(*(kernel.proc._signature(parent)+
            kernel.proc._signature(owned[0][1])+kernel.proc._signature(owned[1][1])+
            kernel.proc._signature(child[1])))
        lib.review_configure(parent,owned[0][1],fault)
        error,deadline=self.prepare(lib,values,seconds)
        self.assertEqual(error,0);self.ready(lib,output,deadline)
        args=(parent,*owned,child,identity,deadline,output)
        return lib,root,owned,child,output,deadline,args

    def finished(self,lib,output,deadline):
        # Only observing the original attempt, not resubmitting any effect.
        while not output[17]:
            self.assertLess(time.monotonic_ns(),deadline+10**9)
            self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
            if not output[17]:time.sleep(.001)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
        until=deadline+10**9
        while Path('/proc/self/task/'+str(output[4])).exists():
            self.assertLess(time.monotonic_ns(),until);time.sleep(.001)

    def test_same_preborn_worker_actual_A_then_C_then_original_pidfd_closed_once(self):
        lib,root,owned,child,out,deadline,args=self.fixture()
        worker=out[4];tasks=set(Path('/proc/self/task').iterdir())
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0)
        self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[19],out[20],out[21],out[22]),(7,0,1,31,1,0))
        self.assertEqual(lib.review_count(),2);self.assertEqual(lib.review_tid(),worker)
        self.assertNotEqual(worker,threading.get_native_id())
        self.assertEqual((owned[0][1],owned[1][1],child[1]),(-1,-1,-1))
        self.assertFalse((root/'aggregate').exists());self.assertFalse((root/'controller').exists())
        self.assertFalse(set(Path('/proc/self/task').iterdir())-tasks)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)
        self.assertGreater(out[9],0) # Root/map/history still retained after actual effects.

    def test_first_remove_error_retains_every_original_slot_and_no_second_attempt(self):
        lib,root,owned,child,out,deadline,args=self.fixture(1)
        saved=[tuple(v) for v in owned+[child]]
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0);self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20],out[21]),(5,errno.EPERM,0,1))
        self.assertEqual([tuple(v) for v in owned+[child]],saved)
        self.assertTrue((root/'aggregate').is_dir());self.assertTrue((root/'controller').is_dir())
        self.assertEqual(lib.review_count(),1)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)

    def test_second_remove_error_keeps_C_and_pidfd_after_actual_A_retirement(self):
        lib,root,owned,child,out,deadline,args=self.fixture(2)
        saved=[tuple(v) for v in [owned[1],child]]
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0);self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20]),(5,errno.EPERM,3))
        self.assertFalse((root/'aggregate').exists());self.assertTrue((root/'controller').is_dir())
        self.assertEqual(owned[0][1],-1);self.assertEqual([tuple(v) for v in [owned[1],child]],saved)
        self.assertEqual(lib.review_count(),2)

    def test_blocked_remove_past_same_cutoff_records_actual_removal_but_retains_FDs_and_C(self):
        lib,root,owned,child,out,deadline,args=self.fixture(3,.25)
        saved=[tuple(v) for v in owned+[child]]
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0)
        while not lib.review_blocked():
            self.assertLess(time.monotonic_ns(),deadline);time.sleep(.001)
        time.sleep(max(0,(deadline-time.monotonic_ns())/10**9)+.01)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
        self.assertEqual((out[0],out[1],out[20],out[21],out[17]),(4,errno.ETIMEDOUT,0,0,0))
        self.assertEqual([tuple(v) for v in owned+[child]],saved)
        self.assertTrue(Path('/proc/self/task/'+str(out[4])).exists())
        lib.review_continue();self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20],out[21]),(4,errno.ETIMEDOUT,1,1))
        self.assertEqual([tuple(v) for v in owned+[child]],saved)
        self.assertFalse((root/'aggregate').exists());self.assertTrue((root/'controller').is_dir())
        self.assertEqual(lib.review_count(),1)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)

    def test_close_error_preserves_first_errno_and_remaining_C_pidfd(self):
        lib,root,owned,child,out,deadline,args=self.fixture(4)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0);self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20]),(5,errno.EIO,3))
        self.assertEqual((owned[0][0],owned[0][1]),(errno.EIO,-1))
        self.assertGreaterEqual(owned[1][1],3);self.assertGreaterEqual(child[1],3)
        self.assertFalse((root/'aggregate').exists());self.assertTrue((root/'controller').is_dir())

    def test_production_filesystem_gate_refuses_ordinary_parent_without_any_effect(self):
        lib,root,owned,child,out,deadline,args=self.fixture(9)
        saved=[tuple(v) for v in owned+[child]]
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EINVAL)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
        self.assertEqual((out[0],out[1],out[19],out[20]),(5,errno.EINVAL,1,0))
        self.assertEqual([tuple(v) for v in owned+[child]],saved)
        self.assertEqual(lib.review_count(),0)
        self.assertTrue((root/'aggregate').is_dir());self.assertTrue((root/'controller').is_dir())
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)
        self.finished(lib,out,deadline)

    def test_foreign_thread_and_identity_substitution_cannot_start_effect(self):
        lib,root,owned,child,out,deadline,args=self.fixture()
        seen=[]
        thread=threading.Thread(target=lambda:seen.append(lib.trnm_kernel_retirement_activate_v1(*args)))
        thread.start();thread.join();self.assertEqual(seen,[errno.EPERM]);self.assertEqual(out[19],0)
        args[4][4]+=1 # Same held A, wrong original inode binding.
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.ESTALE)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
        self.assertEqual((out[1],out[19],out[20]),(errno.ESTALE,1,0))
        self.assertEqual(lib.review_count(),0)
        self.finished(lib,out,deadline)

    def test_actual_thread_disappearance_requires_final_same_slot_observation(self):
        # Force the real observation window: the original worker is still in
        # its bounded test syscall after expiry; /proc check sees it disappear
        # after the first snapshot. Assertions/cutoff/effects stay unchanged.
        lib=preparation.RetirementPreparationTests.library(self,'blocked-wait')
        values=self.input();out=values[3]
        error,deadline=self.prepare(lib,values,.1)
        self.assertEqual(error,0);self.ready(lib,out,deadline)
        while not lib.review_entered():
            self.assertLess(time.monotonic_ns(),deadline);time.sleep(.001)
        time.sleep(max(0,(deadline-time.monotonic_ns())/10**9)+.01)
        actual_exists=Path.exists;worker=Path('/proc/self/task/'+str(out[4]));observed=[]
        def check(path):
            if path==worker:
                observed.append(out[17])
                while actual_exists(path):
                    self.assertLess(time.monotonic_ns(),deadline+10**9);time.sleep(.001)
                return False
            return actual_exists(path)
        with patch.object(Path,'exists',check):self.expired(lib,out,deadline)
        self.assertEqual(observed,[0,1])
        self.assertEqual((out[0],out[1],out[17]),(4,errno.ETIMEDOUT,1))

    def test_original_owner_retention_latch_stops_after_inflight_remove_before_same_cutoff(self):
        lib,root,owned,child,out,deadline,args=self.fixture(3)
        saved=[tuple(v) for v in owned+[child]]
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),0)
        while not lib.review_blocked():
            self.assertLess(time.monotonic_ns(),deadline);time.sleep(.001)
        seen=[]
        thread=threading.Thread(target=lambda:seen.append(lib.trnm_kernel_retirement_retain_v1(out)))
        thread.start();thread.join();self.assertEqual(seen,[errno.EPERM])
        self.assertEqual(lib.trnm_kernel_retirement_retain_v1((ctypes.c_uint64*24)()),errno.EPERM)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(out),0)
        self.assertEqual(out[1],0)
        self.assertEqual(lib.trnm_kernel_retirement_retain_v1(out),0)
        self.assertLess(time.monotonic_ns(),deadline)
        lib.review_continue();self.finished(lib,out,deadline)
        self.assertEqual((out[0],out[1],out[20],out[21]),(5,errno.ECANCELED,1,1))
        self.assertEqual(out[8],deadline)
        self.assertEqual([tuple(v) for v in owned+[child]],saved)
        self.assertFalse((root/'aggregate').exists());self.assertTrue((root/'controller').is_dir())
        self.assertEqual(lib.review_count(),1)
        self.assertEqual(lib.trnm_kernel_retirement_activate_v1(*args),errno.EALREADY)
        self.assertEqual(lib.trnm_kernel_retirement_retain_v1(out),errno.EALREADY)


if __name__=='__main__':unittest.main(verbosity=2)
