"""Strict independent audit of native thread lifecycle and clock syscall traces."""
from __future__ import annotations
import errno
import hashlib
import re
import struct
from .native_io import decode, need

CLONE_FLAGS='CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID'
HEX=r'0x[0-9a-f]+'
CALL=re.compile(r'^([a-z0-9_]+)\((.*)\)\s+=\s+(.+)$')
PID=re.compile(r'^(?:\[pid\s+)?(\d+)(?:\])?\s+(.*)$')
RESULT=re.compile(r'^(-?\d+|0x[0-9a-f]+|\?)(?:\s|$)')
ERRORS={'EINTR':4,'EAGAIN':11,'EINVAL':22,'ENOSYS':38,'EIO':5,'EPERM':1,'EPIPE':32}


def c_string(text,start=0):
    need(start<len(text) and text[start]=='"','Expected a complete C string')
    data=bytearray();i=start+1
    escapes={'a':7,'b':8,'t':9,'n':10,'v':11,'f':12,'r':13,'"':34,'\\':92}
    while i<len(text):
        ch=text[i];i+=1
        if ch=='"':
            return bytes(data),i
        if ch!='\\':
            need(32<=ord(ch)<127,'Noncanonical literal trace byte')
            data.append(ord(ch));continue
        need(i<len(text),'Truncated trace escape')
        ch=text[i];i+=1
        if ch in escapes:
            data.append(escapes[ch])
        elif ch in '01234567':
            token=ch
            while i<len(text) and len(token)<3 and text[i] in '01234567':
                token+=text[i];i+=1
            value=int(token,8);need(value<256,'Octal byte overflow');data.append(value)
        elif ch=='x':
            need(i+2<=len(text) and re.fullmatch('[0-9a-fA-F]{2}',text[i:i+2]) is not None,'Invalid hex trace escape')
            data.append(int(text[i:i+2],16));i+=2
        else:
            raise ValueError('Unsupported trace escape')
    raise ValueError('Unclosed trace string')


def complete_calls(text):
    pending={};calls=[];signals=[]
    for line_number,line in enumerate(text.splitlines(),1):
        need(bool(line.strip()),'Empty trace line')
        match=PID.fullmatch(line)
        need(match is not None,'Missing trace PID')
        tid=int(match[1]);body=match[2]
        if body.startswith('--- '):
            need(re.fullmatch(r'--- SIGUSR1 \{[^{}]*\} ---',body) is not None,'Unexpected native signal')
            signals.append({'tid':tid,'line':line_number,'text':body});continue
        if body.startswith('+++'):
            need(body=='+++ exited with 0 +++','Unclean trace exit notification')
            continue
        resumed=re.fullmatch(r'<\.\.\. ([a-z0-9_]+) resumed>(.*)',body)
        if resumed:
            need(tid in pending,'Resume without an unfinished syscall')
            start,first=pending.pop(tid)
            need(first.startswith(resumed[1]+'('),'Mismatched syscall resume')
            body=first+resumed[2]
        else:
            start=line_number
            need(tid not in pending,'Second native syscall while one is unfinished')
        if body.endswith(' <unfinished ...>'):
            need(not resumed,'A resumed call cannot become unfinished twice')
            pending[tid]=(start,body[:-len(' <unfinished ...>')]);continue
        call=CALL.fullmatch(body)
        need(call is not None,'Unsupported complete trace call: '+body[:160])
        result=RESULT.match(call[3]);need(result is not None,'Unsupported raw syscall result')
        value=None if result[1]=='?' else int(result[1],0)
        calls.append({'tid':tid,'name':call[1],'args':call[2],'result':call[3],
                      'value':value,'start':start,'end':line_number})
    need(not pending,'Incomplete native syscall trace')
    need(bool(calls),'Empty native trace')
    return calls,signals


def clock_value(call):
    if call['value']!=0:
        need(re.fullmatch(r'CLOCK_THREAD_CPUTIME_ID, '+HEX,call['args']) is not None,
             'Failed clock used another clock or pointer profile')
        return None
    match=re.fullmatch(r'CLOCK_THREAD_CPUTIME_ID, \{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}',call['args'])
    need(match is not None,'Clock result omitted its complete timespec')
    seconds=int(match[1]);nanos=int(match[2])
    if seconds<0 or nanos<0 or nanos>=1000000000:
        return None
    value=seconds*1000000000+nanos
    return value if value<(1<<64) else None


def io_call(call):
    args=call['args'];m=re.match(r'^(\d+), ',args);need(m is not None,'Invalid native I/O descriptor')
    descriptor=int(m[1]);position=m.end()
    if position<len(args) and args[position]=='"':
        raw,position=c_string(args,position)
    else:
        m2=re.match(HEX,args[position:]);need(m2 is not None,'Missing native I/O buffer')
        position+=m2.end();raw=None
    tail=re.fullmatch(r', (\d+)',args[position:]);need(tail is not None,'Truncated native I/O')
    count=int(tail[1]);value=call['value']
    if value is not None and value>=0:
        need(raw is not None,'Successful native I/O omitted its bytes')
        need(0<=value<=count,'Impossible native I/O length')
        need(len(raw)==(value if call['name']=='read' else count),'Trace I/O bytes were abbreviated')
    return descriptor,raw,count,value


def random_call(call):
    args=call['args']
    if args.startswith('"'):
        raw,position=c_string(args)
    else:
        match=re.match(HEX,args);need(match is not None,'Missing random output pointer')
        position=match.end();raw=None
    tail=re.fullmatch(r', (\d+), 0',args[position:]);need(tail is not None,'Random source flags changed')
    count=int(tail[1]);need(0<count<=16,'Random request exceeds capability size')
    value=call['value']
    if value is not None and value>=0:
        need(raw is not None and len(raw)==value and value<=count,'Abbreviated or impossible random result')
    return raw,value


def validate_injections(calls,injection):
    """Bind explicit ptrace faults to actual TID ordinals and exact bytes."""
    marked=[]
    for call in calls:
        marker=re.search(r' \(INJECTED(?:: (?:args, retval|args|retval))?\)$',call['result'])
        need('INJECTED' not in call['result'] or marker is not None,
             'Unrecognized injected syscall annotation')
        if marker is not None:
            marked.append((call,marker[0].strip()))
    if injection is None:
        need(not marked,'Unexpected controlled syscall in a real-kernel-clock history')
        return []
    error=re.fullmatch(r'(clock_gettime|getrandom|clone):error=([A-Z0-9_]+):when=([1-9][0-9]*)(\+?)',injection)
    timespec=re.fullmatch(r'clock_gettime:retval=0:poke_exit=@arg2=([0-9a-f]{32}):when=([1-9][0-9]*)',injection)
    need(error is not None or timespec is not None,'Unsupported controlled syscall fixture')
    name=error[1] if error is not None else 'clock_gettime'
    ordinal=int(error[3] if error is not None else timespec[2])
    persistent=error is not None and error[4]=='+'
    need(bool(marked),'Controlled history contains no actually injected syscall')
    if not persistent:
        need(len(marked)==1,'Controlled history must contain exactly one actually injected syscall')
    thread=marked[0][0]['tid']
    need(all(call['tid']==thread and call['name']==name for call,_ in marked),
         'A different actual thread or syscall received the controlled result')
    same_thread=[entry for entry in calls if entry['tid']==thread and entry['name']==name]
    positions=[next(i for i,entry in enumerate(same_thread,1) if entry is call)
               for call,_ in marked]
    expected_positions=list(range(ordinal,len(same_thread)+1)) if persistent else [ordinal]
    need(positions==expected_positions,
         'Controlled result affected another syscall ordinal on this actual thread')
    if persistent:
        # The declared cases execute their clock primitive on one actual lane.
        # Refuse a second thread whose omitted marks could escape this audit.
        need(not any(entry['name']==name and entry['tid']!=thread for entry in calls),
             'Persistent controlled syscall escaped its one actual execution thread')
    for call,annotation in marked:
        if name=='clock_gettime':
            need(call['args'].startswith('CLOCK_THREAD_CPUTIME_ID, '),
                 'Controlled result affected another clock')
        if error is not None:
            actual=re.match(r'^-1 ([A-Z0-9_]+) \(',call['result'])
            need(annotation=='(INJECTED)' and call['value']==-1 and actual is not None
                 and actual[1]==error[2],'Actual injected errno or annotation differs')
        else:
            expected=bytes.fromhex(timespec[1])
            actual=re.fullmatch(r'CLOCK_THREAD_CPUTIME_ID, \{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}',call['args'])
            need(annotation=='(INJECTED: args, retval)' and call['value']==0 and actual is not None,
                 'Controlled timespec lacks both actual output-byte and return injection')
            # strace may print a negative signed tv_nsec as its unsigned bits.
            # Accept one representable 64-bit field and compare all 16 bytes.
            observed=(int(actual[1]),int(actual[2]))
            need(all(-(1<<63)<=field<(1<<64) for field in observed),
                 'Trace timespec field exceeds its actual 64-bit representation')
            wire=struct.pack('<QQ',*(field&((1<<64)-1) for field in observed))
            need(wire==expected,'Actual complete 16-byte injected timespec differs')
    return [call for call,_ in marked]


def clock_errno(call):
    if call['value']==0:
        return 0
    match=re.match(r'^-1 ([A-Z0-9_]+) \(',call['result'])
    need(call['value']==-1 and match is not None,'Unexpected actual clock syscall return')
    number=getattr(errno,match[1],None)
    need(type(number) is int and 0<number<4096,'Unrecognized actual clock errno')
    return number


def primitive_clock_result(samples):
    """Audit the exact locked rustix dynamic-call/fallback return contract."""
    need(1<=len(samples)<=2,'Primitive clock attempt count is outside its bounded backend')
    first_error=clock_errno(samples[0])
    expected=1 if first_error in (0,errno.EINVAL) else 2
    need(len(samples)==expected,'Primitive clock omitted or added a backend fallback')
    need(all(call['tid']==samples[0]['tid'] for call in samples),
         'Clock fallback moved to another actual thread')
    for call in samples:
        clock_value(call)
    final=samples[-1]
    return clock_value(final),(-clock_errno(final))&((1<<64)-1)


def pair_actual_signal_interruptions(calls,signals):
    """Account for the kernel's restart pseudo-result without inventing I/O.

    With the reviewed handler's absent SA_RESTART, strace records ERESTARTSYS,
    signal delivery, and a real rt_sigreturn(-EINTR). Require that complete
    sequence on the same actual TID before treating the interrupted call as
    returning EINTR to native code.
    """
    used_signals=set();used_returns=set();result=[]
    for call in calls:
        if call['value'] is not None or call['result']!='? ERESTARTSYS (To be restarted if SA_RESTART is set)':
            continue
        need(call['name'] in ('read','futex'),'Unexpected restarted native effect')
        later=sorted((entry for entry in calls
            if entry['tid']==call['tid'] and entry['start']>call['end']),
            key=lambda entry:entry['start'])
        need(bool(later),'Restart pseudo-result lacks a real signal return')
        returned=later[0]
        need(returned['name']=='rt_sigreturn' and returned['args']=='{mask=[]}'
             and returned['value']==-1 and returned['result']=='-1 EINTR (Interrupted system call)',
             'Restarted native effect did not actually return EINTR')
        delivered=[entry for entry in signals if entry['tid']==call['tid']
                   and call['end']<entry['line']<returned['start']]
        need(len(delivered)==1,'Interrupted native effect lacks one actual delivered signal')
        delivered=delivered[0]
        need(re.fullmatch(r'--- SIGUSR1 \{si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=\d+, si_uid=\d+\} ---',
                          delivered['text']) is not None,'Signal delivery profile differs')
        need(delivered['line'] not in used_signals and returned['start'] not in used_returns,
             'One signal return was counted twice')
        used_signals.add(delivered['line']);used_returns.add(returned['start'])
        result.append({'tid':call['tid'],'syscall':call['name'],
                       'interrupted_line':call['end'],'signal_line':delivered['line'],
                       'sigreturn_line':returned['end']})
        call['raw_restart_result']=call['result']
        call['value']=-1
        call['result']='-1 EINTR (actual SIGUSR1 and rt_sigreturn)'
        call['actual_signal_interrupted']=True
    need(used_signals=={entry['line'] for entry in signals},
         'Unaccounted native signal delivery')
    need(used_returns=={entry['start'] for entry in calls if entry['name']=='rt_sigreturn'},
         'Unaccounted native signal return')
    return result


def audit_trace(text,stdin,stdout,*,fixture=False,injection=None,expected_exit=0):
    if not __debug__:
        raise RuntimeError('Thread trace audit refuses optimized Python')
    calls,signals=complete_calls(text)
    injected=validate_injections(calls,injection)
    interruptions=pair_actual_signal_interruptions(calls,signals)
    first=min(calls,key=lambda x:x['start']);main=first['tid']
    need(first['name']=='execve' and first['value']==0,'Trace must start at native exec')
    need(re.fullmatch(r'"/proc/self/fd/\d+", \["/proc/self/fd/\d+"\], \["PATH="\]',first['args']) is not None,'Native executable/environment profile differs')
    maps=[c for c in calls if c['name']=='mmap']
    need(len(maps)==3 and all(c['tid']==main and c['value'] is not None and c['value']>0 for c in maps),'Unexpected native mappings')
    for call,expected in zip(maps,[
        'NULL, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0',
        'NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0',
        'NULL, 1056768, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0']):
        need(call['args']==expected,'Native mapping flags or length changed')
        need(call['value']%4096==0,'Unaligned native mapping')
    adapter,state,stack=(c['value'] for c in maps)
    intervals=[(adapter,adapter+16384),(state,state+65536),(stack,stack+1056768)]
    need(all(a1<=b0 or b1<=a0 for i,(a0,a1) in enumerate(intervals) for b0,b1 in intervals[i+1:]),'Native private mappings overlap')
    protects=[c for c in calls if c['name']=='mprotect']
    need(len(protects)==1 and protects[0]['tid']==main and protects[0]['value']==0
         and protects[0]['args']==hex(stack+4096)+', 1048576, PROT_READ|PROT_WRITE',
         'Worker stack guard boundaries changed')
    actions=[c for c in calls if c['name']=='rt_sigaction']
    need(len(actions)==2 and all(c['tid']==main and c['value']==0 for c in actions),'Unexpected native signal setup')
    need(actions[0]['args']=='SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=0}, NULL, 8','SIGPIPE profile changed')
    signal=re.fullmatch(r'SIGUSR1, \{sa_handler=('+HEX+r'), sa_mask=\[\], sa_flags=SA_RESTORER, sa_restorer=('+HEX+r')\}, NULL, 8',actions[1]['args'])
    need(signal is not None and 0x4000b0<=int(signal[1],16)<0x40081c
         and 0x4000b0<=int(signal[2],16)<0x40081c,'Signal code leaves reviewed adapter')
    clones=[c for c in calls if c['name']=='clone' and c['value'] is not None and c['value']>0]
    children=[]
    for index,call in enumerate(clones):
        need(call['tid']==main,'Only the real main native lane may create a worker')
        expected=('child_stack='+hex(stack+1052672)+', flags='+CLONE_FLAGS+
                  ', parent_tid=['+str(call['value'])+'], child_tidptr='+hex(adapter+8192))
        need(call['args']==expected,'clone does not bind the actual aligned parent-set/child-clear join word')
        tid=call['value'];need(tid!=main,'Child is not an actual distinct thread')
        children.append({'tid':tid,'life':index+2,'clone':call})
    tids={main}|{row['tid'] for row in children}
    need(all(c['tid'] in tids for c in calls),'Unexpected thread in native trace')
    need(all(s['tid'] in tids for s in signals),'Signal delivered to an unknown native thread')
    permitted={'execve','mmap','mprotect','rt_sigaction','gettid','clock_gettime','getrandom',
               'read','write','clone','futex','exit','exit_group','rt_sigreturn'}
    need(all(c['name'] in permitted for c in calls),'Unexpected native syscall effect')
    need(sum(c['name']=='execve' for c in calls)==1,'Unexpected second exec')
    exits=[c for c in calls if c['name']=='exit']
    groups=[c for c in calls if c['name']=='exit_group']
    need(len(exits)==len(children) and all(c['tid']!=main and c['args']=='0' and c['value'] is None for c in exits),'Worker did not finish with its own SYS_exit')
    need(len(groups)==1 and groups[0]['tid']==main and groups[0]['args']==str(expected_exit)
         and groups[0]['value'] is None,'Native main did not terminate cleanly')
    need(all(c is groups[0] or c['end']<groups[0]['start'] for c in calls),
         'Native trace contains effects after process termination')
    for i,child in enumerate(children):
        matching=[c for c in exits if c['tid']==child['tid'] and c['start']>child['clone']['start']
                  and (i+1==len(children) or c['end']<children[i+1]['clone']['start'])]
        need(len(matching)==1,'Worker stack or lifetime reused before actual retirement')
        child['exit']=matching[0]
        need(child['exit']['end']<groups[0]['start'],'Main terminated before actual worker exit')
        observed=[c for c in calls if c['name']=='gettid' and c['tid']==child['tid']
                  and child['clone']['start']<c['start']<child['exit']['end']]
        need(bool(observed) and all(c['value']==child['tid'] for c in observed),'Missing actual child gettid/ready identity')
    for call in calls:
        if call['tid']!=main:
            lifetime=[child for child in children if child['tid']==call['tid']
                and child['clone']['start']<call['start']
                and call['end']<=child['exit']['end']]
            need(len(lifetime)==1,'Worker syscall lies outside one actual birth/exit lifetime')
        if call['name']=='gettid':
            need(call['args']=='' and call['value']==call['tid'],'gettid receipt is not the executing thread')
        if call['name']=='clone' and call not in clones:
            need(call['tid']==main and call['value']==-1 and '(INJECTED)' in call['result']
                 and injection is not None,'Unqualified failed native clone')
            expected=('child_stack='+hex(stack+1052672)+', flags='+CLONE_FLAGS+
                      ', parent_tid='+hex(adapter+8192)+', child_tidptr='+hex(adapter+8192))
            need(call['args']==expected,'Failed clone changed the guarded stack or private join word')
        if call['name']=='futex':
            match=re.fullmatch(r'('+HEX+r'), (FUTEX_WAIT_PRIVATE|FUTEX_WAKE_PRIVATE|FUTEX_WAIT), (\d+)(?:, NULL)?',call['args'])
            need(match is not None,'Unsupported futex operation')
            address=int(match[1],16);operation=match[2];value=int(match[3])
            if address==adapter+8192:
                need(operation=='FUTEX_WAIT' and call['tid']==main and value in tids-{main},
                     'Kernel clear_child_tid must use shared WAIT on the actual child')
            elif address==adapter+8196:
                need((operation=='FUTEX_WAIT_PRIVATE' and call['tid']==main and value==0)
                     or (operation=='FUTEX_WAKE_PRIVATE' and call['tid']!=main and value==1),
                     'Native child-ready handshake changed')
            elif address==adapter+8200:
                need((operation=='FUTEX_WAKE_PRIVATE' and value==1)
                     or (operation=='FUTEX_WAIT_PRIVATE' and value==(1 if call['tid']==main else 0)),
                     'Native serial turn handoff changed')
            else:
                raise ValueError('Futex address outside private lifecycle metadata')
            need(call['value'] in (0,1) or (call['value']==-1 and re.match(r'-1 (EAGAIN|EINTR)\b',call['result']) is not None),
                 'Unqualified futex result')
        if call['name']=='clock_gettime':
            clock_value(call)
            if '(INJECTED)' in call['result']:
                need(injection is not None,'Unexpected injected native clock')
    observed_in=bytearray();observed_out=bytearray();packets=bytearray()
    samples=[];entropy=bytearray();clock_count=0;rows=[];last_complete=first['end']
    for call in sorted(calls,key=lambda x:x['end']):
        if call['name']=='clock_gettime':
            clock_count+=1;samples.append(call)
        elif call['name']=='getrandom':
            data,value=random_call(call)
            if value is not None and value>0:entropy.extend(data)
        elif call['name']=='read':
            descriptor,data,count,value=io_call(call)
            need(descriptor==0 and call['tid']==main and 0<count<=64,'Unexpected native input stream or lane')
            need(value is not None and (value>=0 or (value==-1 and re.match(r'-1 EINTR\b',call['result']) is not None)),
                 'Unqualified native input error')
            if value>0:observed_in.extend(data)
        elif call['name']=='write':
            descriptor,data,count,value=io_call(call)
            need(descriptor==1 and 0<count<=224,'Unexpected native output stream')
            if value is None or value<0:
                raise ValueError('Successful trace corpus includes failed output')
            observed_out.extend(data[:value]);packets.extend(data[:value])
            while len(packets)>=224:
                raw=bytes(packets[:224]);del packets[:224]
                row=decode(raw)
                need(row['fixture']==int(fixture) and row['tid']==call['tid'],'Receipt was written by a different execution thread')
                expected_life=1
                if call['tid']!=main:
                    active=[ch for ch in children if ch['tid']==call['tid']
                        and ch['clone']['start']<call['start']<ch['exit']['end']]
                    need(len(active)==1,'Receipt has no unique live native generation')
                    expected_life=active[0]['life']
                need(row['life']==expected_life and row['lane']==int(call['tid']!=main),'Native generation differs from actual birth/retirement')
                need(row['clocks']==clock_count and all(x['tid']==call['tid'] for x in samples),'A receipt counted another thread clock')
                need(row['births']==sum(ch['clone']['end']<call['end'] for ch in children),'Birth count is not backed by successful actual clone')
                need(row['joins']==sum(ch['exit']['end']<call['end'] for ch in children),'Join count precedes actual worker exit')
                op=row['op']
                if op in (1,3,4) and row['status'] in (0,1,3,11):
                    value,result_bits=primitive_clock_result(samples)
                    need(row['clock_result']==result_bits,'Receipt clock result differs from final actual attempt')
                    if row['some']:
                        need(value is not None,'Failed actual clock manufactured a valid stamp')
                        if op==1:
                            need(row['baseline_after']==value,'Stamp baseline differs from actual syscall timespec')
                        else:
                            need(value>=row['baseline_before'] and row['delta']==value-row['baseline_before'],
                                 'Native interval differs from actual checked CPU subtraction')
                            need(row['baseline_after']==(value if op==3 else 0),'Checkpoint/consumption baseline differs')
                    elif row['status']==1:
                        need(value is None,'Native rejected a valid clock as unavailable')
                    elif row['status']==3:
                        need(value is not None and value<row['baseline_before'],'Rewind result differs from actual CPU timespec')
                elif op in (1,3,4) and row['status']==9 and samples:
                    # The diagnostic count cannot wrap after the first failed
                    # call; this finite resource refusal is not clock None.
                    need(len(samples)==1 and row['clocks']==(1<<64)-1
                         and clock_errno(samples[0]) not in (0,errno.EINVAL)
                         and row['clock_result']==(-clock_errno(samples[0]))&((1<<64)-1),
                         'Diagnostic capacity refusal does not match its actual first attempt')
                else:
                    need(not samples,'A nonclock operation or wrong-thread call sampled CPU')
                if op in (1,2) and row['some']:
                    need(bytes(entropy)==struct.pack('<QQ',row['cap0'],row['cap1']),'Published capability differs from actual kernel random bytes')
                else:
                    need(not entropy or row['status']==11,'Unexpected capability entropy acquisition')
                samples=[];entropy.clear();rows.append(row);last_complete=call['end']
    need(not packets and not samples and not entropy,'Trace ends inside an unreported native operation')
    need(bytes(observed_in)==stdin and bytes(observed_out)==stdout,'Syscall I/O differs from captured native byte streams')
    need(len(stdout)==len(rows)*224 and bool(rows),'Incomplete receipt corpus')
    return {'status':'PASS','raw_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'syscalls':len(calls),'receipts':len(rows),'main_tid':main,
            'children':[{'tid':x['tid'],'life':x['life'],'clone_start_line':x['clone']['start'],
                         'exit_line':x['exit']['end']} for x in children],
            'actual_clock_calls':clock_count,'actual_clock_thread_ids':sorted({c['tid'] for c in calls if c['name']=='clock_gettime'}),
            'actual_births':len(children),'actual_exits':len(exits),
            'actual_signal_interruptions':interruptions,
            'actual_injected_syscall_count':len(injected),
            'kernel_tid_reuse_observed':len({x['tid'] for x in children})!=len(children),
            'native_join_zero_guard_bound_to_adapter':True,
            'memory_load_of_join_word_visible_in_strace':False,
            'controlled_syscall_result_fixture':injection is not None,
            'host_supplied_runtime_clock_or_identity':False,
            'full_node_or_paid_account':False}
