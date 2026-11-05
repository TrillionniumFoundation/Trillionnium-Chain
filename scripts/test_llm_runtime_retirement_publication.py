"""Retirement publication controls; original nine preparation tests stay intact.

Only own native threads and read-only current cgroup handles are used. Guarded
bad-pointer controls run in finite child processes; no production test hook.
"""
import ctypes
import errno
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import llm_runtime_kernel_owned as kernel
import test_llm_runtime_retirement_slot as original


class RetirementPublicationTests(unittest.TestCase):
    input = original.RetirementPreparationTests.input
    prepare = original.RetirementPreparationTests.prepare
    ready = original.RetirementPreparationTests.ready
    expired = original.RetirementPreparationTests.expired
    library = original.RetirementPreparationTests.library

    def paused_library(self):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-retirement-publication-test-')
        self.addCleanup(temporary.cleanup)
        source = b'#define getpid review_getpid\n'+kernel._bytes(kernel._C)+b'\n'+kernel._bytes(kernel._RETIREMENT_C)
        source += b'''
#undef getpid
static _Atomic int review_entered, review_released;
pid_t review_getpid(void) {
    if (atomic_exchange(&review_entered, 1) == 0) {
        uint64_t bound = trnm_now_ns()+UINT64_C(1000000000);
        while (!atomic_load(&review_released) && trnm_before(bound)) sched_yield();
    }
    return (pid_t)syscall(SYS_getpid);
}
int review_initializing(void) { return atomic_load(&review_entered); }
void review_release(void) { atomic_store(&review_released, 1); }
'''
        output = Path(temporary.name)/'paused.so'
        built = subprocess.run(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra',
            '-Werror','-pthread','-x','c','-','-o',str(output)],input=source,capture_output=True)
        self.assertEqual(built.returncode,0,built.stderr.decode())
        return output

    def test_empty_snapshot_refuses_before_owner_or_output_reads(self):
        lib=self.library();output=(ctypes.c_uint64*24)()
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(output),errno.EAGAIN)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(None),errno.EAGAIN)
        self.assertEqual(tuple(output),(0,)*24)

    def test_nonzero_first_output_claims_one_failed_slot_without_reset(self):
        lib=self.library();values=self.input();values[3][7]=41
        self.assertEqual(self.prepare(lib,values)[0],errno.EINVAL)
        self.assertEqual((values[3][0],values[3][1],values[3][9],values[3][16]),(5,errno.EINVAL,0,0))
        second=(values[0],values[1],values[2],(ctypes.c_uint64*24)())
        self.assertEqual(self.prepare(lib,second)[0],errno.EALREADY)
        self.assertEqual(lib.trnm_kernel_retirement_snapshot_v1(values[3]),0)
        self.assertEqual((values[3][0],values[3][1]),(5,errno.EINVAL))

    def run_guard_control(self,mode):
        library=self.paused_library() if mode=='initializing' else Path(self.library()._name)
        script=r'''
import ctypes,errno,json,os,pathlib,resource,sys,threading,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=ctypes.CDLL(sys.argv[1]);mode=sys.argv[2];wordp=ctypes.POINTER(ctypes.c_uint64)
prepare=lib.trnm_kernel_retirement_prepare_v1
prepare.argtypes=[ctypes.c_int,wordp,ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64,wordp]
prepare.restype=ctypes.c_int
snapshot=lib.trnm_kernel_retirement_snapshot_v1;snapshot.argtypes=[wordp];snapshot.restype=ctypes.c_int
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
page=os.sysconf('SC_PAGESIZE');address=libc.mmap(None,page,3,0x22,-1,0)
assert address is not None and address!=ctypes.c_void_p(-1).value
guard=ctypes.cast(address,wordp);badtext=ctypes.cast(address,ctypes.c_char_p)
fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
meta=os.fstat(fd);identity=(ctypes.c_uint64*3)(meta.st_dev,meta.st_ino,meta.st_mode)
membership=pathlib.Path('/proc/thread-self/cgroup').read_bytes();deadline=time.monotonic_ns()+10**9
output=(ctypes.c_uint64*24)();thread=None;result=[];saved=[]
def producer():
 error=prepare(fd,identity,membership,len(membership),deadline,output)
 result.append(error)
 while error==0 and output[0] in (1,2):
  assert time.monotonic_ns()<deadline;assert snapshot(output)==0;time.sleep(.001)
 saved.append(list(output))
try:
 if mode=='initializing':
  thread=threading.Thread(target=producer);thread.start()
  while not lib.review_initializing():
   assert time.monotonic_ns()<deadline;time.sleep(.001)
  assert libc.mprotect(address,page,0)==0
  try:
   assert snapshot(output)==errno.EAGAIN
   assert snapshot(guard)==errno.EAGAIN
   assert prepare(-1,guard,badtext,page,0,guard)==errno.EALREADY
  finally:lib.review_release()
  thread.join(2);assert not thread.is_alive() and result==[0] and saved[0][0]==3
 else:
  # Use the SAME output page: another prepare must not read the page that the
  # original owner's snapshot can write. It also must not validate other inputs.
  assert prepare(fd,identity,membership,len(membership),deadline,guard)==0
  while guard[0] in (1,2):
   assert time.monotonic_ns()<deadline;assert snapshot(guard)==0;time.sleep(.001)
  assert guard[0]==3;worker=guard[4]
  assert libc.mprotect(address,page,0)==0
  assert prepare(fd,identity,membership,len(membership),deadline,guard)==errno.EALREADY
  assert prepare(-1,guard,badtext,page,0,guard)==errno.EALREADY
  assert libc.mprotect(address,page,3)==0
  saved.append([0,0,0,0,worker])
 worker=saved[0][4];until=deadline+10**9
 while pathlib.Path('/proc/self/task/'+str(worker)).exists():
  assert time.monotonic_ns()<until;time.sleep(.001)
 print(json.dumps({'mode':mode,'unpublished_snapshot':'EAGAIN' if mode=='initializing' else None,
  'occupied_guarded_buffer':'EALREADY','actual_worker_ended':True,'scope':'read-only current cgroup component; no retirement/WholeU'}))
finally:
 if mode=='initializing':lib.review_release()
 if thread is not None:thread.join(2)
 assert libc.mprotect(address,page,3)==0
 assert libc.munmap(address,page)==0
 os.close(fd)
'''
        result=subprocess.run([sys.executable,'-c',script,str(library),mode],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('"occupied_guarded_buffer": "EALREADY"',result.stdout)
        self.assertIn('"actual_worker_ended": true',result.stdout)
        print(result.stdout.strip())

    def test_paused_initializer_refuses_foreign_snapshot_and_prepare_before_reads(self):
        self.run_guard_control('initializing')

    def test_occupied_original_output_guard_page_is_never_read_by_prepare(self):
        self.run_guard_control('occupied')


if __name__=='__main__':unittest.main(verbosity=2)
