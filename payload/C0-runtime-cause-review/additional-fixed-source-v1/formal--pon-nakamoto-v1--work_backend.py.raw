"""Explicit native M01 work bridge; oracle remains independently executable.

The installed binary is a trusted local component. No successful mock/fallback supplies
work validity when a native backend was explicitly chosen and failed.
"""
import os,struct
from pathlib import Path
import work_oracle as oracle
from bounded_process import run_bounded
from contract_wire import H
Q=oracle.Q;N=oracle.N;CELLS=oracle.CELLS
task_id=oracle.task_id
# This never constructs a verified-work result or replaces the installed verifier.
precheck=oracle.precheck

def native(mode,data,limit):
    path=Path(os.environ['TRNM_NATIVE_WORK'])
    if not path.is_file():raise ValueError('NATIVE_WORK_UNAVAILABLE')
    result=run_bounded([str(path),mode],data,stdout_limit=limit,stderr_limit=4096)
    if result.returncode:raise ValueError('NATIVE_WORK_INVALID')
    return result.stdout

def prove(challenge,a,b):
    if not os.environ.get('TRNM_NATIVE_WORK'):return oracle.prove(challenge,a,b)
    if len(challenge)!=32 or len(a)!=CELLS or len(b)!=CELLS:raise ValueError('WORK_LENGTH')
    if any(type(v)is not int or not 0<=v<Q for v in [*a,*b]):raise ValueError('FIELD')
    proof=native('prove',challenge+struct.pack('<'+'I'*(CELLS*2),*a,*b),49188)
    if len(proof)!=49188:raise ValueError('NATIVE_WORK_LENGTH')
    return proof

def verify(challenge,task,target,proof):
    if not os.environ.get('TRNM_NATIVE_WORK'):return oracle.verify(challenge,task,target,proof)
    if any(len(v)!=32 for v in [challenge,task,target])or len(proof)!=49188:raise ValueError('WORK_LENGTH')
    data=challenge+task+target+proof
    observed=native('verify',data,32)
    if observed!=H('native-work-verification',data):raise ValueError('NATIVE_WORK_CONTEXT')
    return H('ticket',challenge,proof[-32:]),list(struct.unpack('<'+'I'*CELLS,proof[4+2*CELLS*4:4+3*CELLS*4]))
