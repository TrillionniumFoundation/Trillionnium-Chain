"""Unaligned, exclusive real pointers and sequential reuse of one native arena.

The foreign caller owns three disjoint allocations. Reusing them after a call
returns does not authorize simultaneous read/write aliases. No claim is made
that an arbitrary foreign caller's overlapping pointers are a supported ABI.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_node_settings import (
    SOURCE, OUT_MIN, WORK_MIN, GENESIS_TIME, CAPACITY, request, expected_snapshot,
)


WORKER = r'''
import base64,ctypes,fcntl,hashlib,json,os,resource,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CPU,(55,55))
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(4,0,0,0,0):
    raise OSError(ctypes.get_errno(),'disable core dump')
raw=open(request['library'],'rb').read()
digest=hashlib.sha256(raw).hexdigest()
if digest!=request['sha256']:
    raise ValueError('changed native artifact')
fd=os.memfd_create('settings-unaligned-private-owner',os.MFD_ALLOW_SEALING)
try:
    p=0
    while p<len(raw):
        n=os.write(fd,raw[p:])
        if n<=0:raise OSError('short artifact capture')
        p+=n
    fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
    if fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))!=15:
        raise ValueError('artifact is not fully sealed')
    library=ctypes.CDLL('/proc/self/fd/'+str(fd))
finally:
    os.close(fd)
fn=library.f0
fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3
fn.restype=ctypes.c_uint64
def allocate(size,residue,fill):
    storage=ctypes.create_string_buffer(size+64)
    ctypes.memset(ctypes.addressof(storage),0x69,ctypes.sizeof(storage))
    begin=16+((residue-ctypes.addressof(storage))%8)
    address=ctypes.addressof(storage)+begin
    ctypes.memset(address,fill,size)
    return storage,begin,size,address,storage.raw
def content(allocation):
    a,b,n,_,_=allocation
    return a.raw[b:b+n]
def guarded(allocation):
    a,b,n,_,old=allocation
    return a.raw[:b]==old[:b] and a.raw[b+n:]==old[b+n:]
residues=request['residues']
source=allocate(13,residues[0],0x73)
output=allocate(16421,residues[1],0xa5)
work=allocate(300074,residues[2],0x5b)
ranges=[(x[3],x[3]+x[2])for x in (source,output,work)]
for i,(left,end)in enumerate(ranges):
    for right,other_end in ranges[i+1:]:
        if max(left,right)<min(end,other_end):
            raise ValueError('foreign regions must be exclusively owned')
answers=[]
for step in request['steps']:
    data=base64.b64decode(step['input'],validate=True)
    if not len(data)<=13 or not 0<=step['out_len']<=output[2] or not 0<=step['work_len']<=work[2]:
        raise ValueError('private test extent')
    ctypes.memmove(source[3],data,len(data))
    ctypes.memset(output[3],0xa5,output[2])
    input_before=content(source)
    output_before=content(output)
    before=content(work)
    started=time.monotonic_ns()
    result=fn(source[3],len(data),output[3],step['out_len'],work[3],step['work_len'])
    elapsed=time.monotonic_ns()-started
    status,value=result>>32,result&0xffffffff
    changed=content(work)
    out=content(output)
    length=value if value<0xfffffff0 else 0
    answers.append({'abi_status':status,'value':value,'output_hex':out[:length].hex(),
        'input_unchanged':content(source)==input_before,
        'output_tail_unchanged':out[length:]==output_before[length:],
        'work_tail_unchanged':changed[300000:]==before[300000:],
        'outside_borrow_unchanged':changed[step['work_len']:]==before[step['work_len']:],
        'work_unchanged':changed==before,
        'guards_unchanged':all(guarded(x)for x in (source,output,work)),
        'residues':[x[3]%8 for x in (source,output,work)],'arena_address':work[3],
        'work_len':step['work_len'],'elapsed_ns':elapsed})
print(json.dumps({'sha256':digest,'cases':answers,
    'host_compiler_modules_loaded':sorted(x for x in sys.modules if x=='hepta' or x.startswith('hepta.'))}))
'''


class SettingsPrivateMemory(unittest.TestCase):
    observations = []

    def test_unaligned_repeated_success_error_and_capacity_in_one_arena(self):
        steps = [
            (None, OUT_MIN, WORK_MIN),
            ((1 << 63) - 1, OUT_MIN + 37, WORK_MIN + 37),
            (0, OUT_MIN + 37, WORK_MIN),
            (1800000000, OUT_MIN + 37, WORK_MIN + 37),
            (1, OUT_MIN, WORK_MIN - 1),
            (1, OUT_MIN - 1, WORK_MIN),
            (None, OUT_MIN, WORK_MIN),
        ]
        with NativeModule(SOURCE, byte_exports=('f0',)) as native:
            for residues in ((1, 3, 5), (7, 0, 2)):
                sent = {'library': str(native.library), 'sha256': native.artifact_sha256,
                        'residues': residues,
                        'steps': [{'input': base64.b64encode(request(time)).decode(),
                                   'out_len': out_len, 'work_len': work_len}
                                  for time, out_len, work_len in steps]}
                result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', WORKER],
                    input=json.dumps(sent), text=True, capture_output=True, timeout=60, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed['sha256'], native.artifact_sha256)
                self.assertEqual(observed['host_compiler_modules_loaded'], [])
                self.assertEqual(len(observed['cases']), len(steps))
                self.assertEqual(len({row['arena_address'] for row in observed['cases']}), 1)
                for row, (timestamp, out_len, work_len) in zip(observed['cases'], steps):
                    self.assertEqual(row['abi_status'], 0)
                    self.assertEqual(tuple(row['residues']), residues)
                    for field in ('input_unchanged', 'output_tail_unchanged', 'work_tail_unchanged',
                                  'outside_borrow_unchanged', 'guards_unchanged'):
                        self.assertIs(row[field], True, field)
                    if out_len < OUT_MIN or work_len < WORK_MIN:
                        self.assertEqual(row['value'], CAPACITY)
                        self.assertTrue(row['work_unchanged'])
                    elif timestamp == 0:
                        self.assertEqual(row['value'], GENESIS_TIME)
                    else:
                        expected = expected_snapshot(timestamp)
                        self.assertEqual(row['value'], len(expected))
                        self.assertEqual(bytes.fromhex(row['output_hex']), expected)
                self.observations.append(observed)


if __name__ == '__main__':
    unittest.main()
