"""Physical and original-compatible qualification of the finite thread owner."""
from __future__ import annotations
import argparse
import copy
import ctypes
import json
import os
import re
from pathlib import Path
import signal
import struct
import sys
import traceback
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.build import new_output,sha256,write_json
from .build import Build
from .cases import corpus
from .native_io import Native,frame,handle,need,U64
from .trace_audit import audit_trace,complete_calls


def corpus_bytes():
    return b''.join(json.dumps(case,sort_keys=True,separators=(',',':')).encode()+b'\n'
                    for case in corpus())


def comparison_from_receipts(case,rows):
    """Reduce actual native receipts while checking independent handle history."""
    need(len(rows)==len(case['commands'])+1,'Native receipt history extent differs')
    objects={};baseline={};owners={}
    result=[]
    for command,row in zip(case['commands'],rows[1:],strict=True):
        op=command['op'];name=command['stamp'];save=command['save']
        need(row['op']==op and row['lane']==command['target'],'Native executed another primitive or actual lane')
        before=baseline.get(name)
        owner=owners.get(name)
        owned=None if owner is None else owner==(row['life'],row['tid'])
        consumed=False
        controlled=None
        if op in (1,2):
            if row['some']:
                need(save is not None and save not in objects,'Invalid native object publication label')
                objects[save]=handle(row)
                baseline[save]=row['baseline_after']
                if op==1:
                    owners[save]=(row['life'],row['tid'])
                else:
                    need(name in objects and row['baseline_before']==before
                         and row['baseline_after']==before,'Clone failed to preserve original baseline')
                    owners[save]=owner
            else:
                need(op==1 and row['status']==1,'Unexpected primitive construction failure')
            if case['controlled_timespec'] is not None:
                controlled=row['baseline_after'] if row['some'] else None
                need(controlled==case['controlled_timespec']['expected'],
                     'Native actual syscall timespec conversion differs')
        elif op==3:
            need(name in objects and row['baseline_before']==before,'Checkpoint did not use this copy baseline')
            if row['some']:
                need(owned is True and row['baseline_after']>=before
                     and row['baseline_after']-before==row['delta'],'Checkpoint delta/update differ')
                baseline[name]=row['baseline_after']
            else:
                need(row['baseline_after']==before,'Failed checkpoint changed baseline')
        elif op in (4,8):
            need(name in objects and row['baseline_before']==before
                 and row['baseline_after']==0,'Finish did not consume the exact original copy')
            if row['some']:
                need(op==4 and owned is True,'Foreign native thread finished an interval')
            if op==8:
                need(row['status']==0 and row['some']==0,'Explicit value drop sampled or required original owner identity')
            consumed=True
            del objects[name];del baseline[name];del owners[name]
        elif op==129:
            need(case['fixture'] and name in objects and row['baseline_before']==before
                 and row['baseline_after']==command['argument'],'Private baseline fixture differs')
            baseline[name]=row['baseline_after']
        else:
            need(op in (5,6,7) and row['status']==0 and row['some']==0,'Native control operation failed')
        if op in (3,4) and owned is False:
            need(row['some']==0 and row['status']==2,'Different actual thread identity accepted')
        need(row['active']==len(objects),'Native live-stamp cardinality differs')
        positive=None
        if command['positive']:
            need(row['some']==1 and row['delta']>0,'Mandatory actual CPU interval is not positive')
            positive=True
        result.append({'op':op,'target':command['target'],'some':bool(row['some']),
            'active':len(objects),'consumed':consumed,'owner_same':owned,
            'baseline_invariant':True,'positive_requirement_met':positive,
            'checksum':row['checksum'],'controlled_value':controlled,
            'births':row['births'],'joins':row['joins']})
    return result


def run_case(images,case,output):
    image=images[bool(case['fixture'])]
    stamps={}
    with Native(image,output,fixture=case['fixture'],trace=True,injection=case['injection']) as native:
        for command in case['commands']:
            name=command['stamp']
            stamp=stamps.get(name) if name is not None else None
            if name is not None:
                need(stamp is not None,'Case references an unpublished stamp')
            row=native.request(command['op'],command['target'],stamp,command['argument'])
            if row['some'] and command['op'] in (1,2):
                stamps[command['save']]=handle(row)
            if command['op']==6 and row['status']==0:
                native.observe_threads(row)
        receipts=copy.deepcopy(native.rows)
    trace=audit_trace((output/'syscalls.raw').read_text(),bytes(native.input),
            bytes(native.stdout),fixture=case['fixture'],injection=case['injection'])
    compared=comparison_from_receipts(case,receipts)
    result={'name':case['name'],'status':'PASS','native_image_sha256':sha256(image),
        'fixture':case['fixture'],'actual_clock_positive':case['actual_clock_positive'],
        'controlled_syscall_result_fixture':case['injection'] is not None,
        'comparison':compared,'receipts':receipts,'trace':trace,
        'physical':str(output/'physical.json')}
    write_json(output/'case.json',result)
    return result


def normal_trace(native,output,**kwargs):
    return audit_trace((output/'syscalls.raw').read_text(),bytes(native.input),
                       bytes(native.stdout),**kwargs)


def observed_signal_eintr(text,tid):
    """Observe a live return; complete signal pairing is still audited later."""
    # strace pads short decimal TIDs with horizontal whitespace. Do not let
    # whitespace matching cross a newline into a different task's trace.
    pattern=re.compile(r'^'+str(tid)+r'[ \t]+(?:rt_sigreturn|<\.\.\. rt_sigreturn resumed>).*?= -1 EINTR\b',re.MULTILINE)
    return pattern.search(text) is not None


def actual_signal_control(image,output):
    """Interrupt only this captured native process, after observing blocking."""
    output.parent.mkdir(parents=True,exist_ok=True)
    delivered=[]
    libc=ctypes.CDLL(None,use_errno=True)
    libc.syscall.restype=ctypes.c_long
    def wait_blocked(tid,number):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            raw=(Path('/proc')/str(tid)/'syscall').read_text().strip()
            if raw.split()[0]==str(number):
                return raw
            time.sleep(.002)
        raise ValueError('Owned native thread did not block in the expected syscall')
    def wait_return(tid):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if observed_signal_eintr((output/'syscalls.raw').read_text(),tid):
                return
            time.sleep(.002)
        raise ValueError('Actual delivered SIGUSR1 did not produce an observed EINTR return')
    with Native(image,output,trace=True) as native:
        born=native.request(6);native.observe_threads(born)
        for tid,number in ((native.main_tid,0),(born['worker_tid'],202)):
            blocked=wait_blocked(tid,number)
            result=libc.syscall(ctypes.c_long(234),ctypes.c_int(native.main_tid),
                               ctypes.c_int(tid),ctypes.c_int(signal.SIGUSR1))
            need(result==0,'tgkill failed for the owned actual native thread: '+str(ctypes.get_errno()))
            wait_return(tid);wait_blocked(tid,number)
            delivered.append({'tid':tid,'blocked_syscall':blocked,'tgkill_result':result})
        started=native.request(1,1);stamp=handle(started)
        native.request(5,1,argument=100000)
        checked=native.request(3,1,stamp)
        need(checked['some']==1 and checked['delta']>0,'Real signal interruption lost the CPU interval')
        need(native.request(4,1,stamp)['some']==1,'Post-signal original finish failed')
        need(native.request(7)['joins']==1,'Signal-interrupted real worker was not joined')
    checked=normal_trace(native,output)
    need({(row['tid'],row['syscall']) for row in checked['actual_signal_interruptions']}
         =={(native.main_tid,'read'),(born['worker_tid'],'futex')},
         'Actual signal controls did not cover both native blocking primitives')
    raw=(output/'syscalls.raw').read_text()
    refused=[]
    variants=[
        ('missing-delivery','\n'.join(line for line in raw.splitlines() if '--- SIGUSR1 ' not in line)+'\n'),
        ('wrong-signal',raw.replace('SIGUSR1','SIGUSR2')),
        ('wrong-sigreturn',raw.replace('-1 EINTR (Interrupted system call)','0')),
        ('missing-restart',raw.replace('? ERESTARTSYS (To be restarted if SA_RESTART is set)','-1 EINTR (Interrupted system call)')),
    ]
    for name,mutated in variants:
        need(mutated!=raw,'Signal trace mutation did not change bytes')
        error=None
        try:
            audit_trace(mutated,bytes(native.input),bytes(native.stdout))
        except (ValueError,RuntimeError) as caught:
            error=str(caught)
        need(error is not None,'Signal audit accepted an incomplete real-kernel sequence: '+name)
        refused.append({'name':name,'status':'REFUSED','failure':error,'trace_sha256':sha256(mutated.encode())})
    return {'name':'actual-sigusr1-read-and-private-futex-eintr','status':'PASS',
            'actual_deliveries':delivered,'trace':checked,'signal_trace_refusals':refused,
            'ptrace_return_or_data_injected':False,
            'shared-clear-tid-wait-signal-interruption-qualified':False}


def controls(images,output):
    image=images[False]
    output.mkdir(mode=0o700)
    result=[actual_signal_control(image,output/'actual-sigusr1-interruptions')]
    cap_path=output/'capacity-capabilities'
    with Native(image,cap_path,trace=True) as native:
        stamps=[]
        for _ in range(64):
            stamps.append(handle(native.request(1)))
        full=native.request(1)
        need(full['status']==4 and full['active']==64 and full['some']==0,'Full registry minted an extra stamp')
        clone=native.request(2,stamp=stamps[0])
        need(clone['status']==4 and clone['active']==64 and clone['clocks']==full['clocks'],'Full clone partially changed state')
        forged=(stamps[0][0],stamps[0][1]^1,stamps[0][2])
        wrong=native.request(4,stamp=forged)
        need(wrong['status']==5 and wrong['active']==64,'Forged capability consumed a real stamp')
        first=native.request(4,stamp=stamps[0])
        need(first['some']==1 and first['active']==63,'Valid consuming finish failed')
        fresh=native.request(1);fresh_handle=handle(fresh)
        need(fresh_handle[0]>stamps[-1][0] and fresh['active']==64,'Reused slot reset object serial')
        stale=native.request(3,stamp=stamps[0])
        need(stale['status']==5 and stale['clocks']==fresh['clocks'],'Old consumed serial revived after slot reuse')
        wrong_serial=(stamps[0][0],fresh_handle[1],fresh_handle[2])
        need(native.request(4,stamp=wrong_serial)['status']==5,'New capability revived an earlier object serial')
        for stamp in stamps[1:]+[fresh_handle]:
            need(native.request(4,stamp=stamp)['some']==1,'Existing live object lost during capacity controls')
        need(native.rows[-1]['active']==0,'Capacity control leaked a stamp')
    audit=normal_trace(native,cap_path)
    result.append({'name':'capacity-and-unforgeable-handle-profile','status':'PASS','trace':audit})
    profile_path=output/'protocol-profile'
    with Native(image,profile_path,trace=True) as native:
        absent=native.request(1,1)
        need(absent['status']==7 and absent['active']==0,'Absent worker became a fake execution lane')
        need(native.request(7)['status']==7,'Absent worker join succeeded')
        born=native.request(6);native.observe_threads(born)
        already=native.request(6)
        need(already['status']==8 and already['births']==1 and already['worker_life']==2,'Duplicate worker creation changed generation')
        for op in (0,9,128,129,130,131,132,U64):
            row=native.request(op)
            need(row['status']==6 and row['clocks']==0 and row['active']==0,'Production admitted an unsupported fixture/request')
        malformed=[bytearray(frame(1)),bytearray(frame(1)),bytearray(frame(1))]
        malformed[0][0]^=1;malformed[1][56]=1;malformed[2][16]=2
        for raw in malformed:
            row=native.request(1,raw=bytes(raw));need(row['status']==6,'Noncanonical request admitted')
        need(native.request(7)['joins']==1,'Actual profile-control child not joined')
    result.append({'name':'production-input-identity-boundary','status':'PASS','trace':normal_trace(native,profile_path)})
    for error in ('EINTR','EIO'):
        path=output/('entropy-'+error)
        injection='getrandom:error='+error+':when=1'
        with Native(image,path,trace=True,injection=injection) as native:
            row=native.request(1)
            if error=='EINTR':
                need(row['some']==1 and row['clocks']==1,'Entropy EINTR retried CPU instead of only entropy')
            else:
                need(row['status']==11 and row['active']==0 and row['handle']==0,'Failed entropy published a stamp')
                row=native.request(1)
                need(row['some']==1 and row['handle']==1,'Failed entropy consumed an object serial')
            need(native.request(4,stamp=handle(row))['some']==1,'Entropy recovery lost original primitive')
        result.append({'name':'real-entropy-errno-'+error,'status':'PASS','trace':normal_trace(native,path,injection=injection)})
    path=output/'clone-error'
    injection='clone:error=EAGAIN:when=1'
    with Native(image,path,trace=True,injection=injection) as native:
        failed=native.request(6)
        need(failed['status']==10 and failed['births']==0 and failed['worker_life']==0
             and failed['next_life']==2,'Failed clone published a lifetime')
        born=native.request(6);native.observe_threads(born)
        need(born['status']==0 and born['births']==1 and born['worker_life']==2,'Failed clone consumed the next real generation')
    result.append({'name':'actual-clone-failure-no-generation','status':'PASS','trace':normal_trace(native,path,injection=injection)})
    # These are separately compiled, literal-entry private fixtures. They never
    # accept a caller generation or TID, and cannot establish OS TID reuse.
    path=output/'private-generation-exhaustion'
    with Native(images[True],path,fixture=True,trace=True) as native:
        forced=native.request(130)
        need(forced['status']==0 and forced['next_life']==U64,'Private generation bound not installed')
        refused=native.request(6)
        need(refused['status']==9 and refused['births']==0 and refused['worker_life']==0
             and refused['next_life']==U64,'Generation overflow allowed an unowned child')
        live=native.request(1)
        need(live['some']==1,'Generation refusal corrupted the main lifetime')
        need(native.request(8,stamp=handle(live))['active']==0,'Main stamp drop failed after generation refusal')
    checked=normal_trace(native,path,fixture=True)
    need(checked['actual_births']==0,'Exhausted generation reached actual clone')
    result.append({'name':'private-generation-exhaustion-before-clone','status':'PASS',
                   'private_fixture':True,'trace':checked})
    path=output/'private-stamp-serial-exhaustion'
    with Native(images[True],path,fixture=True,trace=True) as native:
        live=native.request(1);stamp=handle(live)
        need(native.request(131)['next_stamp']==U64,'Private serial bound not installed')
        before=native.rows[-1]['clocks']
        for op,selected in [(1,None),(2,stamp)]:
            refused=native.request(op,stamp=selected)
            need(refused['status']==4 and refused['active']==1
                 and refused['clocks']==before,'Exhausted serial performed a partial operation')
        checked=native.request(3,stamp=stamp)
        need(checked['some']==1,'Serial exhaustion invalidated an existing interval')
        dropped=native.request(8,stamp=stamp)
        need(dropped['active']==0 and dropped['clocks']==checked['clocks'],'Drop sampled CPU')
        need(native.request(1)['status']==4,'Slot release reset an exhausted object serial')
    result.append({'name':'private-object-serial-never-wraps','status':'PASS',
                   'private_fixture':True,'trace':normal_trace(native,path,fixture=True)})
    path=output/'private-same-numeric-tid-old-generation'
    with Native(images[True],path,fixture=True,trace=True) as native:
        first=native.request(6);native.observe_threads(first)
        original=native.request(1,1);old=handle(original)
        need(native.request(7)['joins']==1,'First real worker did not join')
        second=native.request(6);native.observe_threads(second)
        need(second['worker_life']>first['worker_life'],'Actual child generation reused')
        altered=native.request(132,1,old)
        need(altered['status']==0 and altered['tid']==second['worker_tid']
             and altered['baseline_after']==original['baseline_after'],
             'Private TID alias changed the saved baseline or executing identity')
        copied=native.request(2,0,old);copy_handle=handle(copied)
        need(copied['baseline_after']==original['baseline_after'],'Old generation clone lost its baseline')
        before=copied['clocks']
        rejected=native.request(3,1,old)
        need(rejected['status']==2 and rejected['clocks']==before
             and rejected['baseline_after']==original['baseline_after'],
             'Matching numeric TID revived a retired generation')
        finished=native.request(4,1,old)
        need(finished['status']==2 and finished['clocks']==before and finished['active']==1,
             'Foreign-generation finish did not consume exactly one copy')
        dropped=native.request(8,1,copy_handle)
        need(dropped['status']==0 and dropped['active']==0 and dropped['clocks']==before,
             'Value drop improperly required the saved generation')
        need(native.request(7)['joins']==2,'Second real worker did not join')
    result.append({'name':'private-same-numeric-tid-old-generation','status':'PASS',
        'private_fixture':True,'actual_kernel_tid_reuse_claim':False,
        'private_alias_uses_actual_current_gettid':True,
        'trace':normal_trace(native,path,fixture=True)})
    # Every incomplete fixed-size frame must close with a protocol failure,
    # after actual worker exit/join, including bytes that resemble another op.
    for extent in range(64):
        path=output/('partial-frame-'+str(extent))
        with Native(image,path,trace=True) as native:
            born=native.request(6);need(born['status']==0,'Partial-frame control failed to create actual child')
            data=frame(1,1)[:extent]
            if data:
                sent=os.write(native.process.stdin.fileno(),data)
                need(sent==len(data),'Partial-frame control short write')
                native.input.extend(data)
            native.finish(expected_exit=70 if extent else 0)
        audit=normal_trace(native,path,expected_exit=70 if extent else 0)
        result.append({'name':'actual-incomplete-frame-'+str(extent),'status':'PASS','trace':audit})
    path=output/'sigkill-no-receipt'
    native=Native(image,path,trace=True)
    try:
        born=native.request(6);native.observe_threads(born)
        stamp=native.request(1,1);need(stamp['some']==1,'SIGKILL control did not create actual worker stamp')
        before=len(native.stdout);tids=[native.main_tid,born['worker_tid']]
        os.kill(native.main_tid,signal.SIGKILL)
        native.process.wait(timeout=10)
        native.stdout.extend(native.process.stdout.read())
        native.abort()
        need(native.returncode!=0 and len(native.stdout)==before,'SIGKILL manufactured a successful terminal receipt')
        need(all(not (Path('/proc')/str(tid)).exists() for tid in tids),'Owned killed native thread remained alive')
        result.append({'name':'actual-sigkill-no-terminal-receipt','status':'PASS',
                       'exit_code':native.returncode,'actual_tids':tids,
                       'ordinary_join_success_claim':False})
    finally:
        native.abort()
    return result


def trace_negative_controls(physical,output):
    root=Path(physical['physical']).parent
    raw=(root/'syscalls.raw').read_text()
    data_in=(root/'stdin.raw').read_bytes();data_out=(root/'stdout.raw').read_bytes()
    rows=[]
    calls,_=complete_calls(raw)
    join_word=next(call['value'] for call in calls if call['name']=='mmap')+8192
    child=physical['trace']['children'][0]['tid']
    forbidden=(str(physical['trace']['main_tid'])+' futex('+hex(join_word)+
               ', FUTEX_WAIT_PRIVATE, '+str(child)+', NULL) = 0\n')
    # Add the forbidden effect before the real terminal syscall. This control
    # does not depend on whether the short genuine join happened to block.
    terminal=raw.rfind(str(physical['trace']['main_tid'])+' exit_group(')
    need(terminal>=0,'Missing actual terminal call in trace control')
    private_wait=raw[:terminal]+forbidden+raw[terminal:]
    lines=raw.splitlines(keepends=True)
    lifetime=physical['trace']['children'][0]
    extra_tid=str(child)+' gettid() = '+str(child)+'\n'
    after=lifetime['exit_line']
    before=lifetime['clone_start_line']-1
    after_exit=''.join(lines[:after])+extra_tid+''.join(lines[after:])
    before_birth=''.join(lines[:before])+extra_tid+''.join(lines[before:])
    variants=[
        ('wrong-clock',raw.replace('CLOCK_THREAD_CPUTIME_ID','CLOCK_MONOTONIC',1),data_out),
        ('private-clear-tid-wait',private_wait,data_out),
        ('worker-effect-after-exit',after_exit,data_out),
        ('worker-effect-before-birth',before_birth,data_out),
        ('removed-parent-settid',raw.replace('|CLONE_PARENT_SETTID','',1),data_out),
        ('wrong-stack-protection',raw.replace('1056768, PROT_NONE','1056768, PROT_READ|PROT_WRITE',1),data_out),
        ('missing-child-exit','\n'.join(line for line in raw.splitlines() if ' exit(0)' not in line)+'\n',data_out),
        ('duplicated-native-exec',raw+raw.splitlines()[0]+'\n',data_out),
        ('extra-syscall',raw+str(physical['trace']['main_tid'])+' getuid() = 1000\n',data_out),
        ('truncated-stdout',raw,data_out[:-1]),
        ('changed-stdout',raw,bytes([data_out[0]^1])+data_out[1:]),
        ('unfinished-syscall',raw+str(physical['trace']['main_tid'])+' gettid( <unfinished ...>\n',data_out),
    ]
    for name,mutated,stdout in variants:
        need(mutated!=raw or stdout!=data_out,'Trace negative control did not change evidence')
        refused=False;error=None
        try:
            audit_trace(mutated,data_in,stdout)
        except (ValueError,RuntimeError) as caught:
            refused=True;error=str(caught)
        need(refused,'Trace audit accepted tampering: '+name)
        rows.append({'name':name,'status':'REFUSED','failure':error,
                     'mutated_trace_sha256':sha256(mutated.encode())})
    write_json(output/'trace-negative-controls.json',{'status':'PASS','controls':rows})
    return rows


def qualify(output):
    if not __debug__:
        raise RuntimeError('Thread CPU qualification refuses optimized Python')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    report={'schema':'trnm.hia.thread-cpu-qualification.v1','status':'FAIL',
            'original_rust_compared':False,'whole_node_or_paid_account_qualified':False,
            'kernel_tid_reuse_qualification_claim':False,'errors':[]}
    build=None
    try:
        build=Build(output/'build');built=build.build();report['build']=built
        images={False:build.executable,True:build.fixture_executable}
        raw=corpus_bytes();(output/'cases.jsonl').write_bytes(raw)
        report['cases']={'bytes':len(raw),'sha256':sha256(raw)}
        semantic=[]
        report['semantic']=semantic
        for case in corpus():
            row=run_case(images,case,output/('semantic-'+case['name']))
            semantic.append(row)
            write_json(output/'semantic-progress.json',{'completed':len(semantic),'last':case['name']})
        report['semantic']=semantic
        report['controls']=controls(images,output/'controls')
        selected=next(row for row in semantic if row['name']=='real_cross_identity')
        report['trace_negative_controls']=trace_negative_controls(selected,output)
        build.check_pin()
        report.update(status='PASS',source_inputs=built['source_inputs'],
            semantic_histories=len(semantic),operations=sum(len(row['comparison']) for row in semantic),
            protocol_controls=len(report['controls']),trace_refusal_controls=len(report['trace_negative_controls']),
            actual_clock_positive_histories=sum(row['actual_clock_positive'] for row in semantic),
            controlled_syscall_histories=sum(row['controlled_syscall_result_fixture'] for row in semantic),
            all_native_syscall_traces='PASS',source_inputs_stable=True)
    except BaseException as error:
        report['errors'].append({'failure':repr(error),'traceback':traceback.format_exc()})
        raise
    finally:
        if build is not None:
            try:
                build.check_pin()
                report['source_after']='MATCH'
            except BaseException as error:
                report['source_after']='FAIL';report['errors'].append({'source_after_failure':repr(error)})
                report['status']='FAIL'
        write_json(output/'report.json',report)
    need(report['status']=='PASS','Thread CPU final source fence failed')
    return report


def main():
    if not __debug__:
        raise RuntimeError('Thread CPU qualification refuses optimized Python')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--require-trace',action='store_true',help='All runs already require actual independent ptrace traces')
    args=parser.parse_args()
    result=qualify(args.output)
    print(json.dumps({key:result[key] for key in ('status','semantic_histories','operations',
        'protocol_controls','trace_refusal_controls','actual_clock_positive_histories')},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
