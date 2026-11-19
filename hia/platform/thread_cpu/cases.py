"""Deterministic command histories for original and native ThreadCpuStamp.

Real-clock histories contain no caller-supplied clock values. The separately
labelled ptrace cases exercise the actual syscall-output conversion path with
an explicitly injected timespec; they never count as real-clock positives.
"""
from __future__ import annotations
import copy
import struct

U64=(1<<64)-1
SIGN=1<<63


def command(op,*,target=0,stamp=None,save=None,argument=0,positive=False):
    return {'op':op,'target':target,'stamp':stamp,'save':save,
            'argument':argument,'positive':positive}


def scenario(name,commands,*,fixture=False,injection=None,clock_value=None):
    return {'name':name,'commands':commands,'fixture':fixture,
            'injection':injection,'controlled_timespec':clock_value,
            'actual_clock_positive':injection is None}


def timespec_value(seconds,nanoseconds):
    if seconds<0 or nanoseconds<0 or nanoseconds>=1000000000:
        return None
    value=seconds*1000000000+nanoseconds
    return value if value<=U64 else None


def corpus():
    C=command
    rows=[]
    for target in (0,1):
        prefix=[C(6)] if target else []
        suffix=[C(7)] if target else []
        rows.append(scenario('real_basic_'+str(target),prefix+[
            C(1,target=target,save='a'),C(5,target=target,argument=100000),
            C(3,target=target,stamp='a',positive=True),
            C(5,target=target,argument=50000),
            C(3,target=target,stamp='a',positive=True),
            C(4,target=target,stamp='a')]+suffix))
        for copies in (1,2,4,8,16):
            ops=prefix+[C(1,target=target,save='root')]
            for i in range(copies):
                ops+=[C(2,target=1-target if target else 0,stamp='root',save='c'+str(i))]
            ops+=[C(5,target=target,argument=60000)]
            for i in range(copies):
                ops+=[C(3,target=target,stamp='c'+str(i),positive=True),
                      C(5,target=target,argument=5000),
                      C(4,target=target,stamp='c'+str(i))]
            ops+=[C(4,target=target,stamp='root',positive=True)]+suffix
            rows.append(scenario('real_independent_clones_'+str(target)+'_'+str(copies),ops))
    rows.append(scenario('real_cross_identity',[
        C(1,save='main'),C(2,stamp='main',save='other'),C(6),
        C(2,target=1,stamp='main',save='foreign'),
        C(3,target=1,stamp='foreign'),C(4,target=1,stamp='foreign'),
        C(5,argument=30000),C(3,stamp='main',positive=True),
        C(1,target=1,save='worker'),C(2,stamp='worker',save='worker_copy'),
        C(3,stamp='worker_copy'),C(5,target=1,argument=40000),
        C(3,target=1,stamp='worker',positive=True),
        C(4,target=1,stamp='worker_copy',positive=True),
        C(4,target=1,stamp='worker'),C(7),
        C(4,stamp='main'),C(4,stamp='other',positive=True)]))
    rows.append(scenario('real_cross_thread_value_drop',[
        C(1,save='main'),C(2,stamp='main',save='main_copy'),C(6),
        C(8,target=1,stamp='main_copy'),C(1,target=1,save='worker'),
        C(2,stamp='worker',save='worker_copy'),C(8,stamp='worker_copy'),
        C(5,target=1,argument=10000),C(4,target=1,stamp='worker',positive=True),
        C(7),C(8,stamp='main')]))
    for count in (1,2,4,8,16):
        ops=[]
        for i in range(count):
            name='worker'+str(i)
            ops+=[C(6),C(1,target=1,save=name),C(5,target=1,argument=1000)]
            if i:
                old='worker'+str(i-1)
                ops+=[C(3,target=1,stamp=old),
                      C(2,stamp=old,save='oldcopy'+str(i)),
                      C(4,stamp='oldcopy'+str(i)),
                      C(4,target=1,stamp=old)]
            ops+=[C(7)]
        ops+=[C(2,stamp='worker'+str(count-1),save='last_copy'),
              C(4,stamp='last_copy'),C(4,stamp='worker'+str(count-1))]
        rows.append(scenario('real_thread_retirement_'+str(count),ops))
    for target in (0,1):
        ops=([C(6)] if target else [])+[
            C(1,target=target,save='a'),
            C(129,target=target,stamp='a',argument=U64),
            C(3,target=target,stamp='a'),C(3,target=target,stamp='a'),
            C(2,target=1-target if target else 0,stamp='a',save='b'),
            C(1,target=target,save='still_available'),
            C(5,target=target,argument=10000),
            C(4,target=target,stamp='still_available',positive=True),
            C(4,target=target,stamp='a'),C(4,target=target,stamp='b')]
        if target:ops+=[C(7)]
        rows.append(scenario('private_rewind_retains_baseline_'+str(target),ops,fixture=True))
    for error in ('EINTR','EINVAL','ENOSYS','EIO'):
        rows.append(scenario('clock_errno_start_'+error,
            [C(1,save='none'),C(1,save='available'),C(4,stamp='available')],
            injection='clock_gettime:error='+error+':when=1'))
        rows.append(scenario('clock_errno_checkpoint_'+error,
            [C(1,save='a'),C(5,argument=10000),C(3,stamp='a'),
             C(5,argument=10000),C(3,stamp='a',positive=True),C(4,stamp='a')],
            injection='clock_gettime:error='+error+':when=2'))
        rows.append(scenario('clock_errno_finish_'+error,
            [C(1,save='a'),C(2,stamp='a',save='b'),C(4,stamp='a'),
             C(5,argument=10000),C(3,stamp='b',positive=True),C(4,stamp='b')],
            injection='clock_gettime:error='+error+':when=2'))
    second_limit=U64//1000000000
    nano_limit=U64%1000000000
    values=[(-1,0),(0,-1),(0,0),(0,1),(0,999999999),(0,1000000000),
            (1,0),(1,1),(second_limit-1,999999999),(second_limit,0),
            (second_limit,nano_limit),(second_limit,nano_limit+1),
            (second_limit,999999999),(second_limit+1,0),((1<<63)-1,0),
            (-1,1),(1,(1<<63)-1),(-(1<<63),0),(0,-(1<<63)),(-1,-1)]
    for i,(seconds,nanos) in enumerate(values):
        wire=struct.pack('<qq',seconds,nanos).hex()
        rows.append(scenario('controlled_timespec_'+str(i),
            [C(1,save='sample')],
            injection='clock_gettime:retval=0:poke_exit=@arg2='+wire+':when=1',
            clock_value={'seconds':seconds,'nanoseconds':nanos,
                         'expected':timespec_value(seconds,nanos)}))
    # Append to the complete original 53-row prefix; persistent ptrace faults
    # prove the one permitted backend fallback also terminates on its error.
    for error in ('EINTR','EINVAL','ENOSYS','EIO'):
        rows.append(scenario('clock_persistent_errno_start_'+error,
            [C(1,save='none')],
            injection='clock_gettime:error='+error+':when=1+'))
        rows.append(scenario('clock_persistent_errno_checkpoint_'+error,
            [C(1,save='a'),C(3,stamp='a'),C(2,stamp='a',save='b'),
             C(8,stamp='a'),C(8,stamp='b')],
            injection='clock_gettime:error='+error+':when=2+'))
        rows.append(scenario('clock_persistent_errno_finish_'+error,
            [C(1,save='a'),C(2,stamp='a',save='b'),C(4,stamp='a'),
             C(2,stamp='b',save='c'),C(8,stamp='b'),C(8,stamp='c')],
            injection='clock_gettime:error='+error+':when=2+'))
    names=[row['name'] for row in rows]
    if len(names)!=len(set(names)):
        raise ValueError('Duplicate Thread CPU history')
    return copy.deepcopy(rows)
