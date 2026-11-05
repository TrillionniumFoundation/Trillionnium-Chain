"""Real native preparation in O's current cgroup, never fresh-host retirement.

No cgroup is created, moved, changed or removed. No model/funding/Whole-U fact.
Fault builds interpose only the named preparation syscall; production has none.
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

import llm_runtime_kernel_owned as kernel


class RetirementPreparationTests(unittest.TestCase):
    def library(self, fault=None):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-retirement-preparation-test-')
        self.addCleanup(temporary.cleanup)
        source = kernel._bytes(kernel._C)+b'\n'+kernel._bytes(kernel._RETIREMENT_C)
        if fault == 'create':
            source = b'#define pthread_create review_create\n'+source+b'''
#undef pthread_create
int review_create(pthread_t *thread, const pthread_attr_t *attributes,
        void *(*start)(void *), void *arg) {
    (void)thread; (void)attributes; (void)start; (void)arg;
    return EAGAIN;
}
'''
        elif fault == 'protect':
            source = b'#define mprotect review_protect\n'+source+b'''
#undef mprotect
int review_protect(void *address, size_t size, int protection) {
    (void)address; (void)size; (void)protection; errno = EPERM; return -1;
}
'''
        elif fault == 'blocked-wait':
            source = b'#define syscall review_syscall\n'+source+b'''
#undef syscall
extern long syscall(long, ...);
static _Atomic int review_wait_entered;
long review_syscall(long number, ...) {
    if (number == SYS_gettid) return syscall(SYS_gettid);
    if (number == SYS_futex) {
        atomic_store(&review_wait_entered, 1);
        usleep(400000); errno = ETIMEDOUT; return -1;
    }
    errno = ENOSYS; return -1;
}
int review_entered(void) { return atomic_load(&review_wait_entered); }
'''
        output = Path(temporary.name)/'preparation.so'
        built = subprocess.run(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra',
            '-Werror','-pthread','-x','c','-','-o',str(output)], input=source,capture_output=True)
        self.assertEqual(built.returncode,0,built.stderr.decode())
        lib = ctypes.CDLL(str(output))
        words = ctypes.POINTER(ctypes.c_uint64)
        lib.trnm_kernel_retirement_prepare_v1.argtypes = [ctypes.c_int,words,ctypes.c_char_p,
            ctypes.c_size_t,ctypes.c_uint64,words]
        lib.trnm_kernel_retirement_prepare_v1.restype = ctypes.c_int
        lib.trnm_kernel_retirement_snapshot_v1.argtypes = [words]
        lib.trnm_kernel_retirement_snapshot_v1.restype = ctypes.c_int
        return lib

    def input(self):
        fd = os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        self.addCleanup(os.close,fd)
        identity = (ctypes.c_uint64*3)(*kernel.proc._signature(fd))
        membership = Path('/proc/thread-self/cgroup').read_bytes()
        output = (ctypes.c_uint64*24)()
        return fd,identity,membership,output

    def prepare(self,lib,values,seconds=.3):
        fd,identity,membership,output = values
        deadline = time.monotonic_ns()+int(seconds*10**9)
        error = lib.trnm_kernel_retirement_prepare_v1(fd,identity,membership,len(membership),deadline,output)
        return error,deadline

    def ready(self,lib,output,deadline):
        while output[0] in (1,2):
            self.assertLess(time.monotonic_ns(),deadline)
            self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
            if output[0] in (1,2):time.sleep(.001)
        self.assertEqual(output[0],3)
        self.assertEqual(output[1],0)

    def expired(self,lib,output,deadline):
        # Test wait only; neither product deadline nor native slot is renewed.
        until=deadline+10**9
        while time.monotonic_ns()<until:
            self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
            if output[0] == 4 and not Path('/proc/self/task/'+str(output[4])).exists():break
            time.sleep(.001)
        self.assertEqual(output[0],4)
        self.assertEqual(output[1],errno.ETIMEDOUT)
        # Thread disappearance follows the earlier snapshot. Observe the same
        # original slot once more; never assert on its pre-exit cached words.
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
        self.assertEqual(output[17],1) # Wait finished only, not resource-return authority.
        self.assertFalse(Path('/proc/self/task/'+str(output[4])).exists())

    def test_real_preborn_thread_same_O_membership_stack_and_guard_maps(self):
        lib=self.library();values=self.input();output=values[3]
        before=set(Path('/proc/self/task').iterdir())
        error,deadline=self.prepare(lib,values,1.)
        self.assertEqual(error,0);self.ready(lib,output,deadline)
        worker=Path('/proc/self/task/'+str(output[4]))
        self.assertEqual(set(Path('/proc/self/task').iterdir())-before,{worker})
        self.assertEqual((output[2],output[3]),(os.getpid(),threading.get_native_id()))
        self.assertEqual((worker/'cgroup').read_bytes(),values[2])
        self.assertEqual(tuple(output[5:8]),tuple(values[1]))
        self.assertEqual(output[8],deadline)
        self.assertEqual(output[10],1024**2+2*output[13])
        self.assertEqual(output[11],output[9]+output[13]);self.assertEqual(output[12],1024**2)
        self.assertLessEqual(output[11],output[18]);self.assertLess(output[18],output[11]+output[12])
        def permission(address):
            return next(row.split()[1] for row in Path('/proc/self/maps').read_text().splitlines()
                if int(row.split('-')[0],16)<=address<int(row.split()[0].split('-')[1],16))
        self.assertEqual(permission(output[9]),'---p')
        self.assertEqual(permission(output[11]),'rw-p')
        self.assertEqual(permission(output[11]+output[12]),'---p')
        self.expired(lib,output,deadline)
        self.assertEqual(permission(output[9]),'---p')
        self.assertEqual(permission(output[11]),'rw-p') # No map/root release after expiry.

    def test_repeated_prepare_uses_no_second_thread_or_mapping(self):
        lib=self.library();values=self.input();output=values[3]
        error,deadline=self.prepare(lib,values,1.)
        self.assertEqual(error,0);self.ready(lib,output,deadline)
        saved=tuple(output);tasks=set(Path('/proc/self/task').iterdir())
        second=(values[0],values[1],values[2],(ctypes.c_uint64*24)())
        self.assertEqual(self.prepare(lib,second)[0],errno.EALREADY)
        self.assertEqual(tuple(second[3]),(0,)*24)
        self.assertEqual(set(Path('/proc/self/task').iterdir()),tasks)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
        self.assertEqual(tuple(output),saved)
        self.expired(lib,output,deadline)
        self.assertEqual(self.prepare(lib,second)[0],errno.EALREADY)

    def test_foreign_thread_and_different_output_buffer_cannot_observe_slot(self):
        lib=self.library();values=self.input();output=values[3]
        error,deadline=self.prepare(lib,values,1.)
        self.assertEqual(error,0);self.ready(lib,output,deadline)
        seen=[]
        thread=threading.Thread(target=lambda:seen.append(lib.trnm_kernel_retirement_snapshot_v1(output)))
        thread.start();thread.join()
        self.assertEqual(seen,[errno.EPERM])
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1((ctypes.c_uint64*24)()),errno.EPERM)
        self.expired(lib,output,deadline)

    def test_ordinary_directory_refuses_before_mapping_or_thread(self):
        lib=self.library();values=self.input()
        with tempfile.TemporaryDirectory() as temporary:
            fd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                wrong=(fd,(ctypes.c_uint64*3)(*kernel.proc._signature(fd)),values[2],values[3])
                self.assertEqual(self.prepare(lib,wrong)[0],errno.EINVAL)
                self.assertEqual(tuple(values[3]),(0,)*24)
            finally:os.close(fd)

    def test_wrong_membership_keeps_same_unknown_slot_without_thread_or_retry(self):
        lib=self.library();values=self.input();wrong=(values[0],values[1],b'0::/wrong\n',values[3])
        before=set(Path('/proc/self/task').iterdir())
        self.assertEqual(self.prepare(lib,wrong)[0],errno.EINVAL)
        self.assertEqual((values[3][0],values[3][9],values[3][16]),(5,0,0))
        self.assertEqual(set(Path('/proc/self/task').iterdir()),before)
        second=(values[0],values[1],values[2],(ctypes.c_uint64*24)())
        self.assertEqual(self.prepare(lib,second)[0],errno.EALREADY)

    def test_thread_creation_refusal_retains_guarded_mapping_no_retry(self):
        lib=self.library('create');values=self.input();before=set(Path('/proc/self/task').iterdir())
        self.assertEqual(self.prepare(lib,values)[0],errno.EAGAIN)
        self.assertEqual((values[3][0],values[3][1],values[3][16]),(5,errno.EAGAIN,0))
        self.assertGreater(values[3][9],0);self.assertEqual(values[3][10],1024**2+2*values[3][13])
        self.assertEqual(set(Path('/proc/self/task').iterdir()),before)
        self.assertEqual(self.prepare(lib,(values[0],values[1],values[2],(ctypes.c_uint64*24)()))[0],errno.EALREADY)

    def test_protection_refusal_retains_single_mapping_without_thread(self):
        lib=self.library('protect');values=self.input();before=set(Path('/proc/self/task').iterdir())
        self.assertEqual(self.prepare(lib,values)[0],errno.EPERM)
        self.assertEqual((values[3][0],values[3][1],values[3][16]),(5,errno.EPERM,0))
        self.assertGreater(values[3][9],0)
        self.assertEqual(set(Path('/proc/self/task').iterdir()),before)

    def test_expired_input_never_creates_a_worker_or_resets_cutoff(self):
        lib=self.library();values=self.input()
        for deadline in (1,time.monotonic_ns()+9*10**9):
            self.assertEqual(lib.trnm_kernel_retirement_prepare_v1(values[0],values[1],values[2],
                len(values[2]),deadline,values[3]),errno.EINVAL)
            self.assertEqual(tuple(values[3]),(0,)*24)

    def test_cutoff_latches_unknown_while_original_worker_is_still_blocked(self):
        lib=self.library('blocked-wait');values=self.input();output=values[3]
        error,deadline=self.prepare(lib,values,.1)
        self.assertEqual(error,0);self.ready(lib,output,deadline)
        while not lib.review_entered():
            self.assertLess(time.monotonic_ns(),deadline);time.sleep(.001)
        time.sleep(max(0,(deadline-time.monotonic_ns())/10**9)+.01)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),0)
        self.assertEqual((output[0],output[1],output[17]),(4,errno.ETIMEDOUT,0))
        self.assertTrue(Path('/proc/self/task/'+str(output[4])).exists())
        self.assertGreater(output[9],0)
        self.assertEqual(self.prepare(lib,(values[0],values[1],values[2],(ctypes.c_uint64*24)()))[0],errno.EALREADY)
        self.expired(lib,output,deadline)


if __name__=='__main__':unittest.main(verbosity=2)
