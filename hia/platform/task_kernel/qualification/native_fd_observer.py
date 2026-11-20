from pathlib import Path
import concurrent.futures
import ctypes
import errno
import hashlib
import json
import os
import struct
import sys
import threading

root=Path(sys.argv[1]);lib=ctypes.CDLL(str(root/'native-fd.so'))
new=lib.trnm_task_owner_new;new.argtypes=[];new.restype=ctypes.c_void_p
invoke=lib.trnm_task_owner_invoke;invoke.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
free=lib.trnm_task_owner_free;free.argtypes=[ctypes.c_void_p]
release=lib.trnm_task_owner_result_free;release.argtypes=[ctypes.c_void_p]
fault=lib.trnm_test_fd_fault;fault.argtypes=[ctypes.c_int64,ctypes.c_int]
observe=lib.trnm_test_fd_observation;observe.argtypes=[ctypes.c_int];observe.restype=ctypes.c_uint64
report={'status':'FAIL','finalized':False,'calls':[],'cases':[],'claim':'native boundary fixtures only; no TaskKernel business qualification'}
def write():(root/'native-fd-observations.json').write_text(json.dumps(report,indent=2)+'\n')
write()
path=os.fsencode(root/'native-fd-target')
def closed(fd):
    try:os.fstat(fd);return False
    except OSError as e:
        if e.errno!=errno.EBADF:raise
        return True
def call(owner,mode,record=True):
    raw=b'TKFD0001'+struct.pack('<QQ',mode,len(path))+path
    s=ctypes.create_string_buffer(raw);result=ctypes.c_void_p();size=ctypes.c_uint64()
    code=invoke(owner,s,len(raw),ctypes.byref(result),ctypes.byref(size))
    data=ctypes.string_at(result,size.value) if result else b''
    published=bool(result)
    if result:release(result)
    row={'input':raw.hex(),'mode':mode,'code':code,'published':published,'bytes':size.value,'actual_output':data.hex()}
    if record:report['calls'].append(row);write()
    assert s.raw[:len(raw)]==raw
    return row,data

for mode,expected,malloc_fail,calloc_fail in [(0,0,-1,0),(1,104,-1,0),(2,103,-1,1),(3,104,-1,0),(4,103,0,0),(5,103,1,0),(6,100,-1,0),(9,103,-1,0)]:
    fault(-1,0);owner=new();assert owner;fault(malloc_fail,calloc_fail)
    row,data=call(owner,mode);observations=[observe(i) for i in range(6)]
    last=observations[3];fd_closed=None if last==(1<<64)-1 else closed(last)
    record={'mode':mode,'expected':expected,'actual':row,'allocation_and_syscall_observations':observations,'last_opened_fd_is_closed':fd_closed}
    report['cases'].append(record);write()
    assert row['code']==expected
    if expected:assert not row['published'] and row['bytes']==0 and not data
    else:assert row['published'] and len(data)==8
    if mode!=4:assert observations[1]==observations[2]==1 and fd_closed is True
    else:assert observations[1]==observations[2]==0 and fd_closed is None
    fault(-1,0)
    again,_=call(owner,0)
    assert again['code']==(104 if expected in [103,104] else 0)
    if expected in [103,104]:assert observe(1)==0
    free(owner)

read_data=bytes(range(256))*513
(root/'native-fd-target').write_bytes(read_data)
fault(-1,0);owner=new();assert owner;fault(-1,0)
read_row,read_result=call(owner,8)
report['native_read_success']={'actual':read_row,'observations':[observe(i) for i in range(7)],'source_bytes':len(read_data),'source_sha256':hashlib.sha256(read_data).hexdigest()};write()
assert read_row['code']==0 and read_result==struct.pack('<QQQ',0,len(read_data),0)+read_data
assert observe(1)==observe(2)==observe(6)==1
assert closed(observe(3));free(owner)
fault(-1,0);owner=new();assert owner;fault(-1,1)
read_row,read_result=call(owner,8)
report['native_read_capacity_allocation_failure']={'actual':read_row,'observations':[observe(i) for i in range(7)]};write()
assert read_row['code']==103 and not read_row['published'] and not read_result
assert observe(1)==observe(2)==1 and observe(6)==0 and closed(observe(3))
fault(-1,0);again,_=call(owner,0);assert again['code']==104 and observe(1)==0;free(owner)

fault(-1,0);owners=[new() for _ in range(8)];assert all(owners);fault(-1,0)
def nonce_thread(index):
    rows=[]
    for _ in range(32):
        row,data=call(owners[index],7,False);rows.append(row)
        assert row['code']==0 and row['published'] and len(data)==8
    return rows
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        concurrent_rows=[row for group in pool.map(nonce_thread,range(8)) for row in group]
    report['concurrent_nonce_calls']=concurrent_rows
    report['concurrent_syscall_observations']=[observe(i) for i in range(6)];write()
    values=[struct.unpack('<Q',bytes.fromhex(row['actual_output']))[0] for row in concurrent_rows]
    assert sorted(values)==list(range(256))
    assert observe(1)==observe(2)==256
finally:
    for owner in owners:free(owner)
report.update(status='PASS',finalized=True,serial_calls=len(report['calls']),concurrent_calls=len(concurrent_rows));write()
print(json.dumps({'status':'PASS','serial_calls':len(report['calls']),'concurrent_calls':len(concurrent_rows),'actual_allocation_failure_cases':4,'explicit_hia_oom_cleanup_cases':1}))
