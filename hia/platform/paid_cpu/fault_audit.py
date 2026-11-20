"""Audit real finite-account faults without reclassifying diagnostic receipts as successful operations."""
from pathlib import Path
import sys,re,json,struct,hashlib,traceback
from hia.platform.thread_cpu.trace_audit import complete_calls,io_call
HEX=r'0x[0-9a-f]+'
FLAGS='CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID'
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def identity(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def parse_clock(c):
 m=re.fullmatch(r'(CLOCK_MONOTONIC|CLOCK_THREAD_CPUTIME_ID), (.*)',c['args'])
 need(m is not None,'Unexpected clock authority')
 if c['value']!=0:
  need(re.fullmatch(HEX,m[2]) is not None,'Failed clock omitted actual pointer')
  return m[1],None
 fields=re.fullmatch(r'\{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}',m[2])
 need(fields is not None,'Successful clock omitted its complete timespec')
 seconds,nanos=int(fields[1]),int(fields[2])
 if seconds<0 or nanos<0 or nanos>=1000000000:return m[1],None
 value=seconds*1000000000+nanos
 return m[1],value if value<(1<<64) else None
def validate_injections(calls,injections):
 specs={}
 for instruction in injections:
  error=re.fullmatch(r'(clock_gettime|clone):error=([A-Z0-9_]+):when=([1-9][0-9]*)',instruction)
  value=re.fullmatch(r'clock_gettime:retval=0:poke_exit=@arg2=([0-9a-f]{32}):when=([1-9][0-9]*)',instruction)
  need(error is not None or value is not None,'Unknown fixed fault instruction')
  name=error[1] if error else 'clock_gettime'
  need(name not in specs,'Duplicate syscall injection profile')
  specs[name]={'ordinal':int(error[3] if error else value[2]),'error':error[2] if error else None,'bytes':None if error else bytes.fromhex(value[1])}
 observed=[]
 for tid in {c['tid'] for c in calls}:
  for name,spec in specs.items():
   rows=[c for c in calls if c['tid']==tid and c['name']==name]
   for ordinal,c in enumerate(rows,1):
    marked='INJECTED' in c['result']
    need(marked==(ordinal==spec['ordinal']),'Actual syscall fault ordinal differs on this thread')
    if not marked:continue
    if spec['error']:
     need(c['value']==-1 and re.fullmatch(r'-1 '+spec['error']+r' \([^()]*\) \(INJECTED\)',c['result']) is not None,'Actual errno differs')
    else:
     need(c['result']=='0 (INJECTED: args, retval)','Both actual return and timespec bytes must be injected')
     m=re.fullmatch(r'(?:CLOCK_MONOTONIC|CLOCK_THREAD_CPUTIME_ID), \{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}',c['args'])
     need(m is not None and struct.pack('<QQ',int(m[1])&((1<<64)-1),int(m[2])&((1<<64)-1))==spec['bytes'],'Complete actual injected timespec differs')
    observed.append(c)
 need(observed and {c['name'] for c in observed}==set(specs),'Declared fault did not occur')
 need(all('INJECTED' not in c['result'] or c in observed for c in calls),'Unexpected fault injection')
 return observed
def audit(folder,row):
 raw=(folder/'syscalls.raw').read_text();calls,signals=complete_calls(raw);calls.sort(key=lambda c:c['start'])
 need(not signals,'Unexpected fault signal')
 allowed={'execve','mmap','mprotect','gettid','read','write','clock_gettime','clone','futex','exit','exit_group'}
 need(all(c['name'] in allowed for c in calls),'Fault path escaped native syscall capabilities')
 spec=row['injection'] if isinstance(row['injection'],list) else [row['injection']]
 injected=validate_injections(calls,spec)
 entries=[c for c in calls if c['name']=='execve'];need(len(entries)==1,'Native entry count differs')
 first=entries[0];main=first['tid']
 need(first['start']==1 and first['result']=='0'
  and re.fullmatch(r'"/proc/self/fd/(\d+)", \["/proc/self/fd/\1"\], \["PATH="\]',first['args']) is not None,'Native executable or environment differs')
 maps=[c for c in calls if c['name']=='mmap']
 need(len(maps)==2 and all(c['tid']==main for c in maps),'Unexpected fault-path mapping')
 need(maps[0]['args']=='NULL, 1544192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0'
  and maps[1]['args']=='NULL, 19021824, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0','Mapping capability differs')
 arena,stack=(c['value'] for c in maps)
 need(all(type(v) is int and 0<v<(1<<63) and v%4096==0 for v in (arena,stack)),'Invalid map')
 need(arena+1544192<=stack or stack+19021824<=arena,'Arena/stack alias')
 protects=[c for c in calls if c['name']=='mprotect']
 need(len(protects)==18,'Guarded stack roster incomplete')
 for index,c in enumerate(protects):
  need(c['tid']==main and c['args']==hex(stack+index*1056768+4096)+', 1048576, PROT_READ|PROT_WRITE' and c['result']=='0','Stack guard changed')
 children={};lanes={};failed=[];attempts=set()
 clones=[c for c in calls if c['name']=='clone']
 for c in clones:
  m=re.fullmatch(r'child_stack=('+HEX+r'), flags=([^,]+), parent_tid=(?:\[(\d+)\]|('+HEX+r')), child_tidptr=('+HEX+r')',c['args'])
  need(m is not None and m[2]==FLAGS,'Clone flags or ABI changed')
  offset=int(m[1],16)-stack-1052672
  need(offset>=0 and offset%1056768==0,'Stack does not belong to a private lane')
  lane=1+offset//1056768;cell=arena+512+lane*128
  need(1<=lane<=9 and lane not in attempts and int(m[5],16)==cell,'Unexpected lane reuse or clear-tid cell')
  attempts.add(lane)
  need((lane==1 and c['tid']==main) or (lane>1 and 1 in lanes and c['tid']==lanes[1]['tid']),'Native birth escaped real request parent')
  if c['value']==-1:
   need(c in injected and c['result']=='-1 EAGAIN (Resource temporarily unavailable) (INJECTED)'
    and m[3] is None and int(m[4],16)==cell,'Failed clone published a child')
   failed.append({'call':c,'lane':lane});continue
  tid=c['value']
  need(type(tid) is int and 0<tid<=2147483647 and tid!=main and tid not in children and c['result']==str(tid)
   and m[3] is not None and int(m[3]) in (0,tid),'Child identity differs')
  entry={'tid':tid,'lane':lane,'cell':cell,'parent':c['tid'],'birth':c}
  children[tid]=entry;lanes[lane]=entry
 need(not clones or protects[-1]['end']<clones[0]['start'],'Birth before full guarded setup')
 need(all(c['tid']==main or c['tid'] in children for c in calls),'Unknown actual syscall thread')
 exits=[c for c in calls if c['name']=='exit']
 need(len(exits)==len(children),'Missing actual native retirement')
 for tid,entry in children.items():
  retired=[c for c in exits if c['tid']==tid]
  need(len(retired)==1 and retired[0]['args']=='0' and retired[0]['result']=='?','Child did not execute SYS_exit')
  entry['exit']=retired[0]
 for c in calls:
  if c['tid']!=main:
   entry=children[c['tid']]
   need(entry['birth']['start']<c['start']<=c['end']<=entry['exit']['end'],'Fault syscall outside actual lifetime')
 stdin=(folder/'stdin.raw').read_bytes();stdout=(folder/'stdout.raw').read_bytes()
 need(len(stdin)==192,'Fault input missing')
 frame=struct.unpack('<24Q',stdin)
 need(frame==(0x3130304d4f444350,0,1,0,row['plan']['workers'],row['plan']['txs'],1000,19,1,0,0,0,*([0]*12)),'Work plan changed')
 reads=[c for c in calls if c['name']=='read']
 need(len(reads)==2 and all(c['tid']==main for c in reads),'Fault path input reads differ')
 need(io_call(reads[0])==(0,stdin,192,192) and io_call(reads[1])==(0,b'',1,0),'Actual complete input or EOF differs')
 writes=[c for c in calls if c['name']=='write']
 if stdout:
  need(len(stdout)==1536 and len(writes)==1 and writes[0]['tid']==main and io_call(writes[0])==(1,stdout,1536,1536),'Diagnostic bytes differ or were abbreviated')
  need(all(e['exit']['end']<writes[0]['start'] for e in children.values()),'Diagnostic preceded actual retirement')
 else:need(not writes,'Failed constructor wrote a diagnostic operation')
 terminal=[c for c in calls if c['name']=='exit_group']
 need(len(terminal)==1 and terminal[0]['tid']==main and terminal[0]['args']==str(row['expected_exit_for_capture'])
  and terminal[0]['result']=='?' and terminal[0]['end']==max(c['end'] for c in calls),'Actual terminal differs')
 per_tid={tid:[c for c in calls if c['tid']==tid] for tid in {main,*children}}
 cpu={tid:[] for tid in per_tid};wall=[]
 for tid,seq in per_tid.items():
  identities=[c for c in seq if c['name']=='gettid']
  need(identities and all(c['args']=='' and c['result']==str(tid) for c in identities),'Real thread identity changed')
  if tid!=main:need(seq[0] is identities[0],'Birth did not establish actual TID first')
  for index,c in enumerate(seq):
   if c['name']!='clock_gettime':continue
   clock,value=parse_clock(c)
   if clock=='CLOCK_THREAD_CPUTIME_ID':
    need(tid!=main and index>0 and seq[index-1]['name']=='gettid','CPU syscall not in its own registered execution thread')
    cpu[tid].append((c,value))
   else:wall.append(c)
   need(c['value']==0 or c in injected,'Uncontrolled kernel clock error')
  need(len(identities)==len(cpu[tid])+1,'Extra identity syscall outside birth/clock')
 # Every clock primitive attempt is accounted; successful invalid output is
 # allowed only at the exact independently checked injected timespec.
 for values in cpu.values():
  for c,v in values:need(v is not None or c in injected,'Unknown unmodified CPU timespec')
 ready={tid:0 for tid in children};gate=[];joins=[];mutex=[]
 for c in calls:
  if c['name']!='futex':continue
  m=re.fullmatch('('+HEX+r'), ([A-Z_]+), (\d+)(.*)',c['args'])
  need(m is not None,'Unexpected futex syntax')
  address,op,arg,tail=int(m[1],16),m[2],int(m[3]),m[4]
  wait=op in ('FUTEX_WAIT','FUTEX_WAIT_PRIVATE','FUTEX_WAIT_BITSET_PRIVATE')
  if wait:need(c['result']=='0' or re.fullmatch(r'-1 (?:EAGAIN|EINTR) \([^()]*\)',c['result']) is not None,'Unexpected wait result')
  else:need(op=='FUTEX_WAKE_PRIVATE' and type(c['value']) is int and 0<=c['value']<=arg and c['result']==str(c['value']),'Unexpected wake result')
  if address==arena+104:
   if wait:need(1 in lanes and c['tid']==lanes[1]['tid'] and op=='FUTEX_WAIT_PRIVATE' and arg==0 and tail==', NULL','Owner release wait differs')
   else:need(c['tid']==main and arg==2147483647 and tail=='','Owner release wake differs');gate.append(c)
   continue
  matched=[entry for entry in children.values() if address==entry['cell']+4]
  if matched:
   entry=matched[0]
   if wait:need(c['tid']==entry['parent'] and op=='FUTEX_WAIT_PRIVATE' and arg==0 and tail==', NULL' and c['start']>entry['birth']['end'],'Ready wait differs')
   else:
    need(c['tid']==entry['tid'] and arg==1 and tail=='' and c['start']>per_tid[c['tid']][0]['end'],'Actual ready publication differs')
    ready[c['tid']]+=1
   continue
  matched=[entry for entry in children.values() if address==entry['cell']]
  if matched:
   entry=matched[0]
   need(c['tid']==entry['parent'] and op=='FUTEX_WAIT' and arg==entry['tid'] and tail==', NULL' and c['start']>entry['birth']['end'],'Join was not on own clear-tid word')
   joins.append((c,entry));continue
  need(c['tid']!=main and address in (arena,arena+16,arena+48),'Mutex escaped private request/global/collector capability')
  if wait:need(op=='FUTEX_WAIT_BITSET_PRIVATE' and arg==2 and tail==', NULL, FUTEX_BITSET_MATCH_ANY','Mutex wait profile differs')
  else:need(arg==1 and tail=='','Mutex wake profile differs')
  mutex.append(c)
 need(all(n==1 for n in ready.values()),'Missing real child ready handshake')
 need(len(gate)==(0 if row['name']=='constructor-clock1-eio' else 1),'Owner release count differs')
 for tid in per_tid:
  order=[e['lane'] for c,e in joins if c['tid']==tid];need(order==sorted(order),'Fault path changed join creation order')
 if 1 in lanes:
  owner_tid=lanes[1]['tid'];workers=[e for e in children.values() if e['lane']>1]
  if workers and cpu[owner_tid]:
   need(max(e['exit']['end'] for e in workers)<cpu[owner_tid][-1][0]['start'],'Owner final clock preceded actual scope retirement')
 else:owner_tid=None;workers=[]
 wall.sort(key=lambda c:c['start'])
 for a,b in zip(wall,wall[1:]):need(a['end']<b['start'],'Locked global wall-clock calls overlapped')
 name=row['name']
 outcome={'name':name,'status':'ACTUAL_FAULT_TRACE_AND_SCOPED_OUTCOME_PASS',
  'syscalls':len(calls),'actual_children':len(children),'actual_worker_exits':len(workers),
  'actual_join_waits':len(joins),'actual_mutex_syscalls':len(mutex),
  'injections':[{'tid':c['tid'],'syscall':c['name'],'line':c['start'],'args':c['args'],'result':c['result']} for c in injected],
  'complete_original_fault_differential':False,
  'uncontended_lock_and_poison_order_evidence':'bound checked HIA and native adapter instructions; actual trace proves capability, clock failures and post-join diagnostic'}
 if not stdout:
  need(name=='constructor-clock1-eio' and not clones and len(wall)==1 and wall[0] in injected and not children,'Constructor failure minted an owner')
  outcome['operation_returned']=False;return outcome
 w=struct.unpack('<192Q',stdout);state=w[8:28];owner=w[64:128]
 need(w[0]==0x3130304343414350 and w[7]==main and w[2]==1 and w[3]==w[4]==int(owner_tid is not None),'Epoch receipt actual owner counts differ')
 need(state[0]==0x3130303055504350 and not any(w[128:]),'Wrong account or extra owner receipt')
 if owner_tid is None:
  need(name=='owner-first-start-refused' and w[6]==1 and len(failed)==1 and failed[0]['lane']==1
   and not any(owner) and state[6]==0 and state[1]==0,'Refused owner became an operation')
  outcome['operation_returned']=False;return outcome
 need(owner[0]==0x3130304e574f4350 and owner[1]==0 and owner[20]==owner_tid and owner[21]==2,'Owner receipt is not actual native birth')
 need(owner[14:18]==(len(workers),)*4,'All created worker intervals were not finished/known')
 # Exact classifications are original failure semantics, independent from
 # nondeterministic physical CPU amounts.
 if name in ('reserve-clock1-eio','reserve-clock1-invalid-timespec'):
  need(w[1]==1 and w[5]==1 and owner[22]==1 and state[6]==0 and not workers
   and all(owner[i]==0 for i in (4,6,8,10,12)),'Begin panic fabricated a returned operation or reservation')
  outcome['operation_returned']=False
 elif name=='settlement-clock1-eio':
  need(w[1]==1 and w[5]==1 and owner[22]==1 and state[6]==1 and owner[19]==1
   and all(owner[i]==1 for i in (4,6,8,10,12)),'Failed final lock clock returned or refunded an unsettled operation')
  outcome['operation_returned']=False
 elif name in ('live-clock3-einval','live-clock3-invalid-timespec'):
  need(w[1]==0 and state[1]==1 and state[6]==0 and owner[3]==1 and owner[22]==0
   and owner[4]==owner[6]==owner[8]==1 and owner[10]==owner[12]==0 and owner[19]==1,'Unknown live sample became zero/refund or erased known full CPU')
  successful=[v for c,v in cpu[owner_tid] if v is not None]
  need(len(successful)==3 and state[15]==successful[-2]-successful[0]
   and owner[5]==successful[-1]-successful[0],'Failed live sample changed the baseline or lost the later known debit')
  outcome['operation_returned']=True
 elif name=='outer-clock3-einval':
  need(w[1]==0 and state[1]==1 and state[6]==0 and owner[3]==0 and owner[4]==owner[8]==owner[12]==0
   and owner[10]==owner[6]==1 and owner[19]==1,'Unknown outer sample was fabricated or already-live CPU erased')
  successful=[v for c,v in cpu[owner_tid] if v is not None]
  need(len(successful)==2 and owner[11]==state[15]==successful[1]-successful[0],'Known final-live charge lost')
  outcome['operation_returned']=True
 elif name=='live-clock3-eio-fallback':
  need(w[1]==0 and state[1]==0 and state[6]==0 and owner[3]==0 and owner[19]==0
   and all(owner[i]==1 for i in (4,6,8,10,12)),'Original one-call fallback was not retained')
  failed_clock=[c for c,v in cpu[owner_tid] if v is None]
  need(len(failed_clock)==1 and failed_clock[0] in injected,'Unexpected CPU fallback failure')
  seq=[c for c,v in cpu[owner_tid]];at=seq.index(failed_clock[0]);need(at+1<len(seq) and seq[at+1]['value']==0,'Missing actual successful raw fallback')
  successful=[v for c,v in cpu[owner_tid] if v is not None]
  need(len(successful)==4 and owner[5]==successful[-1]-successful[0] and owner[11]==successful[-2]-successful[0]
   and owner[13]==successful[-1]-successful[-2],'Actual fallback interval/residual differs')
  outcome['operation_returned']=True
 elif name=='worker-global-request-clock1-einval':
  need(w[1]==1 and state[6]==1 and owner[3]==1002 and owner[19]==1
   and len(workers)==2 and any(parse_clock(c)[0]=='CLOCK_MONOTONIC' for c in injected if c['name']=='clock_gettime'),
   'Actual worker panic/poison did not win after complete join')
  outcome['operation_returned']=True
 elif name in ('partial-worker-two-start','partial-worker-four-start','partial-start-priority-over-clock-panic'):
  expected=3 if name=='partial-worker-four-start' else 1
  need(len(workers)==expected and owner[3]==1001 and len(failed)==1 and failed[0]['lane']==expected+2,
   'Partial start did not join every created worker before preserving WORKER_START')
  if name=='partial-start-priority-over-clock-panic':
   need(w[1]==1 and state[6]==1 and owner[19]==1,'Partial start ignored actual poisoned account')
  else:
   need(w[1]==0 and state[1]==0 and state[6]==0 and owner[19]==0
    and owner[9]==owner[5]+owner[7] and owner[13]==owner[9]-owner[11],'Known partial-scope actual CPU failed unique settlement')
  outcome['operation_returned']=True
 else:raise ValueError('Unreviewed physical fault label')
 return outcome
