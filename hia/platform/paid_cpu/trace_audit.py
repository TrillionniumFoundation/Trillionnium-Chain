"""Independent audit of the actual finite PaidCPU native account traces.
No counter here enters the native production ABI. Derived samples are used only
by a private original-Rust differential fixture after complete native capture.
"""
from pathlib import Path
import sys,json,re,hashlib,struct,traceback
from hia.platform.thread_cpu.trace_audit import complete_calls,io_call
FLAGS='CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID'
HEX=r'0x[0-9a-f]+'
MASK=(1<<64)-1
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
 raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def signed(low,high):
 value=low+(high<<64)
 return value-(1<<128) if high>>63 else value
def ns(clock):return clock['seconds']*1000000000+clock['nanos']
def difference(later,earlier):
 value=ns(later)-ns(earlier);need(value>=0,'Actual monotonic watermark reversed')
 return divmod(value,1000000000)
def audit(raw,stdin,stdout,plan):
 calls,signals=complete_calls(raw)
 calls.sort(key=lambda c:c['start'])
 need(not signals,'Unexpected native signal in positive account history')
 allowed={'execve','mmap','mprotect','gettid','read','write','clock_gettime','clone','futex','exit','exit_group'}
 need(all(c['name'] in allowed for c in calls),'Unexpected native syscall')
 need(all('INJECTED' not in c['result'] for c in calls),'Positive native capture contains injected results')
 entry=[c for c in calls if c['name']=='execve'];need(len(entry)==1,'Captured ELF entry count differs')
 first=entry[0];main=first['tid']
 need(first['start']==1 and first['result']=='0','Native entry result differs')
 need(re.fullmatch(r'"/proc/self/fd/(\d+)", \["/proc/self/fd/\1"\], \["PATH="\]',first['args']) is not None,'Unexpected ELF path or inherited environment')
 need(len(stdin)==192 and len(stdout)==1536,'Complete input or output frame missing')
 frame=struct.unpack('<24Q',stdin);words=struct.unpack('<192Q',stdout)
 expected=(0x3130304d4f444350,plan['cold'],plan['requests'],0)
 expected+=tuple(plan['profiles'][r][key] for r in range(2) for key in ('workers','txs','units','seed'))+(0,)*12
 need(frame==expected,'Actual input differs from recorded work plan')
 need(plan['cold'] in (0,1) and plan['requests'] in (1,2),'Invalid bounded account profile')
 need(all(p['workers'] in (1,2,4,8) and 0<=p['txs']<=32 and 0<=p['units']<=1000000 for p in plan['profiles']),'Outside finite executor profile')
 need(words[0]==0x3130304343414350 and words[7]==main,'Main receipt actual TID differs')
 need(words[1:7]==(0,plan['requests'],plan['requests'],plan['requests'],0,0),'Main creation/retirement result differs')
 owners={}
 for r in range(2):
  row=words[(r+1)*64:(r+2)*64]
  if r>=plan['requests']:
   need(not any(row),'Absent owner produced a receipt');continue
  need(row[0]==0x3130304e574f4350 and row[1]==r and row[21]==2+9*r and row[22]==0,'Owner identity or panic differs')
  need(row[2] in (0,2) and row[3]==0,'Unexpected owner error')
  if row[2]:
   need(row[2]==2 and plan['cold']==1 and row[19]==1,'Refused begin must not manufacture a settled operation')
   need(not any(row[j] for j in (4,6,8,10,12,14,15,16,17)),'Refused owner published fabricated settlement')
  else:
   need(all(row[j]==1 for j in (4,6,8,10,12)) and row[18]==0 and row[19]==0,'Positive owner contains unknown accounting')
   need(row[9]==row[5]+row[7] and row[9]>=row[11] and row[13]==row[9]-row[11],'Owner sum or unique residual differs')
  owners[r]={'row':row,'tid':row[20],'lane':1+9*r,'begin_error':row[2]}
 maps=[c for c in calls if c['name']=='mmap']
 need(len(maps)==2 and all(c['tid']==main for c in maps),'Unexpected mappings')
 need(maps[0]['args']=='NULL, 1544192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0','Private arena mapping differs')
 need(maps[1]['args']=='NULL, 19021824, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0','Guarded stacks mapping differs')
 arena,stack=(c['value'] for c in maps)
 need(all(type(v) is int and 0<v<(1<<63) and v%4096==0 for v in (arena,stack)),'Invalid native mapping')
 need(arena+1544192<=stack or stack+19021824<=arena,'Arena aliases thread stacks')
 protects=[c for c in calls if c['name']=='mprotect']
 need(len(protects)==18,'Missing guarded stack')
 for i,c in enumerate(protects):
  need(c['tid']==main and c['args']==hex(stack+i*1056768+4096)+', 1048576, PROT_READ|PROT_WRITE' and c['result']=='0','Stack guard extent or authority differs')
 need(maps[1]['end']<protects[0]['start'],'Protection before stack mapping')
 clones=[c for c in calls if c['name']=='clone'];by_tid={};by_lane={}
 need(bool(clones) and protects[-1]['end']<clones[0]['start'],'Birth preceded guarded stack construction')
 for c in clones:
  m=re.fullmatch(r'child_stack=('+HEX+r'), flags=([^,]+), parent_tid=\[(\d+)\], child_tidptr=('+HEX+r')',c['args'])
  need(m is not None and m[2]==FLAGS,'Native clone flags or ABI differs')
  offset=int(m[1],16)-stack-1052672
  need(offset>=0 and offset%1056768==0,'Child stack is not a private lane')
  lane=1+offset//1056768;tid=c['value'];cell=arena+512+lane*128
  need(1<=lane<=18 and lane not in by_lane and tid is not None and 0<tid<=2147483647 and tid!=main and tid not in by_tid,'Duplicate or invalid native birth')
  need(c['result']==str(tid) and int(m[3]) in (0,tid) and int(m[4],16)==cell,'Native returned TID or clear-tid cell differs')
  row={'lane':lane,'tid':tid,'parent':c['tid'],'birth':c,'cell':cell,'parent_tid_read':int(m[3])}
  by_tid[tid]=row;by_lane[lane]=row
 expected_lanes=set()
 for r,owner in owners.items():
  expected_lanes.add(owner['lane']);need(owner['lane'] in by_lane and by_lane[owner['lane']]['tid']==owner['tid'],'Owner receipt is not an actual child')
  need(by_lane[owner['lane']]['parent']==main,'Owner was not created by epoch owner')
  p=plan['profiles'][r];count=min(p['workers'],p['txs'])
  worker_count=count if count>1 and owner['begin_error']==0 else 0
  owner['worker_count']=worker_count
  need(owner['row'][14:18]==(worker_count,)*4,'Worker accounting differs from actual profile')
  for i in range(1,worker_count+1):
   lane=owner['lane']+i;expected_lanes.add(lane)
   need(lane in by_lane and by_lane[lane]['parent']==owner['tid'],'Worker is not born under its actual request owner')
  ownclones=[by_tid[c['value']]['lane'] for c in clones if c['tid']==owner['tid']]
  need(ownclones==list(range(owner['lane']+1,owner['lane']+worker_count+1)),'Original ascending scoped creation order differs')
 need(set(by_lane)==expected_lanes,'Actual birth roster differs')
 need([by_tid[c['value']]['lane'] for c in clones if c['tid']==main]==[owners[r]['lane'] for r in owners],'Epoch owner creation order differs')
 ids={main,*by_tid};need(all(c['tid'] in ids for c in calls),'Uncreated thread issued a syscall')
 exits=[c for c in calls if c['name']=='exit'];need(len(exits)==len(by_tid),'Missing child retirement')
 for tid,lane in by_tid.items():
  own=[c for c in exits if c['tid']==tid]
  need(len(own)==1 and own[0]['args']=='0' and own[0]['result']=='?','Child did not execute native SYS_exit(0)')
  lane['exit']=own[0]
 for c in calls:
  if c['tid']!=main:
   life=by_tid[c['tid']]
   need(life['birth']['start']<c['start']<=c['end']<=life['exit']['end'],'Child syscall lies outside one actual birth/exit lifetime')
 reads=[c for c in calls if c['name']=='read'];read_pos=0;eof=0
 for c in reads:
  fd,data,count,value=io_call(c)
  need(c['tid']==main and fd==0,'Native input authority escaped epoch owner')
  expected_count=192-read_pos if read_pos<192 else 1
  need(count==expected_count,'Input request was not exact remaining frame or EOF')
  if read_pos<192:
   need(value is not None and 0<value<=count and data==stdin[read_pos:read_pos+value],'Actual input byte stream differs')
   read_pos+=value
  else:
   need(value==0 and data==b'' and eof==0,'Missing actual complete-frame EOF')
   eof+=1
 need(read_pos==192 and eof==1,'Input frame or EOF was not read')
 writes=[c for c in calls if c['name']=='write'];write_pos=0
 for c in writes:
  fd,data,count,value=io_call(c)
  need(c['tid']==main and fd==1 and count==1536-write_pos,'Receipt output capability or bound differs')
  need(value is not None and 0<value<=count and data==stdout[write_pos:],'Receipt write omitted or changed bytes')
  need(all(row['exit']['end']<c['start'] for row in by_tid.values()),'Receipt preceded actual child retirement')
  write_pos+=value
 need(write_pos==1536,'Incomplete actual receipt write')
 final=[c for c in calls if c['name']=='exit_group']
 need(len(final)==1 and final[0]['tid']==main and final[0]['args']=='0' and final[0]['result']=='?' and final[0]['start']>writes[-1]['end'],'Epoch terminal differs')
 need(final[0]['end']==max(c['end'] for c in calls),'Extra syscall after epoch exit')
 clocks={tid:[] for tid in ids};cpus={tid:[] for tid in ids};walls={tid:[] for tid in ids}
 per_tid={tid:[c for c in calls if c['tid']==tid] for tid in ids}
 for tid,seq in per_tid.items():
  for i,c in enumerate(seq):
   if c['name']=='gettid':
    need(c['args']=='' and c['result']==str(tid),'Actual executing TID differs')
   if c['name']!='clock_gettime':continue
   m=re.fullmatch(r'(CLOCK_MONOTONIC|CLOCK_THREAD_CPUTIME_ID), \{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}',c['args'])
   need(m is not None and c['result']=='0','Positive clock lacks a complete real successful timespec')
   seconds,nanos=int(m[2]),int(m[3])
   need(-(1<<63)<=seconds<(1<<63) and 0<=nanos<1000000000,'Invalid real monotonic timespec')
   d={'seconds':seconds,'nanos':nanos,'line':c['start'],'end':c['end'],'tid':tid,'clock':m[1]}
   clocks[tid].append(d)
   if m[1]=='CLOCK_THREAD_CPUTIME_ID':
    need(i>0 and seq[i-1]['name']=='gettid' and seq[i-1]['end']<c['start'],'Measured thread identity was not sampled before its actual CPU clock')
    need(0<=ns(d)<(1<<64),'Actual CPU timespec is outside original u64 primitive')
    cpus[tid].append(d)
   else:walls[tid].append(d)
  got=[c for c in seq if c['name']=='gettid']
  need(len(got)==len(cpus[tid])+1,'Unexpected identity calls outside birth or CPU sampling')
  need(got and (tid==main or got[0] is seq[0]),'Native birth did not establish real identity first')
  for a,b in zip(cpus[tid],cpus[tid][1:]):need(ns(a)<=ns(b),'Actual CPU baseline rewound')
 need(not cpus[main] and len(walls[main])==1,'Epoch owner supplied or sampled request CPU')
 base=walls[main][0]
 need(reads[-1]['end']<base['line']<clones[0]['start'],'Constructor clock not between complete input and first birth')
 ready_wakes={tid:0 for tid in by_tid};gate_wakes=[];join_calls=[];mutex_calls=[]
 for c in calls:
  if c['name']!='futex':continue
  m=re.fullmatch('('+HEX+r'), ([A-Z_]+), (\d+)(.*)',c['args'])
  need(m is not None,'Unrecognized native futex ABI')
  address=int(m[1],16);op=m[2];arg=int(m[3]);tail=m[4]
  iswait=op in ('FUTEX_WAIT','FUTEX_WAIT_PRIVATE','FUTEX_WAIT_BITSET_PRIVATE')
  if iswait:
   need(c['result']=='0' or re.fullmatch(r'-1 (?:EAGAIN|EINTR) \([^()]*\)',c['result']) is not None,'Unexpected futex wait result')
  else:
   need(op=='FUTEX_WAKE_PRIVATE' and c['value'] is not None and 0<=c['value']<=arg and c['result']==str(c['value']),'Unexpected futex wake result')
  if address==arena+104:
   if op=='FUTEX_WAKE_PRIVATE':
    need(c['tid']==main and arg==2147483647 and tail=='','Owner release barrier differs');gate_wakes.append(c)
   else:
    need(c['tid'] in {r['tid'] for r in owners.values()} and op=='FUTEX_WAIT_PRIVATE' and arg==0 and tail==', NULL','Owner start wait differs')
   continue
  ready=[r for r in by_tid.values() if address==r['cell']+4]
  if ready:
   lane=ready[0]
   if op=='FUTEX_WAKE_PRIVATE':
    need(c['tid']==lane['tid'] and arg==1 and tail=='','Child ready wake escaped its private birth')
    ready_wakes[c['tid']]+=1
    need(c['start']>per_tid[c['tid']][0]['end'],'Ready preceded actual child gettid')
    if clocks[c['tid']]:need(c['end']<clocks[c['tid']][0]['line'],'Child sampled before publishing ready')
   else:
    need(c['tid']==lane['parent'] and op=='FUTEX_WAIT_PRIVATE' and arg==0 and tail==', NULL' and c['start']>lane['birth']['end'],'Parent ready wait differs')
   continue
  cells=[r for r in by_tid.values() if address==r['cell']]
  if cells:
   lane=cells[0]
   need(c['tid']==lane['parent'] and op=='FUTEX_WAIT' and arg==lane['tid'] and tail==', NULL' and c['start']>lane['birth']['end'],'Join did not wait on the actual clear-tid word')
   join_calls.append((c,lane));continue
  need(c['tid']!=main,'Epoch thread used a request-account mutex')
  lane=by_tid[c['tid']]['lane'];req=0 if lane<10 else 1
  need(address in (arena,arena+16+16*req,arena+48+16*req),'Mutex capability escaped this request or shared account')
  if iswait:need(op=='FUTEX_WAIT_BITSET_PRIVATE' and arg==2 and tail==', NULL, FUTEX_BITSET_MATCH_ANY','Contended mutex wait differs from locked native profile')
  else:need(arg==1 and tail=='','Mutex wake width differs')
  mutex_calls.append(c)
 need(all(n==1 for n in ready_wakes.values()),'Missing or duplicate real ready handshake')
 need(len(gate_wakes)==1,'Missing or duplicate owner release')
 need(max(c['end'] for c in clones if c['tid']==main)<gate_wakes[0]['start'],'Owner barrier released before all requested births')
 for parent in ids:
  joined=[lane['lane'] for c,lane in join_calls if c['tid']==parent]
  need(joined==sorted(joined),'Actual scoped join waits reordered handles')
 events=[];thread_summaries=[]
 for req,owner in owners.items():
  tid=owner['tid'];p=plan['profiles'][req];row=owner['row'];count=owner['worker_count']
  members=[by_lane[owner['lane']+i] for i in range(1,count+1)]
  actual_live=0;actual_full=0;actual_workers=0
  for lane in [by_tid[tid]]+members:
   t=lane['tid'];is_owner=t==tid
   txs=p['txs'] if is_owner and count==0 and owner['begin_error']==0 else (0 if is_owner else len(range(lane['lane']-owner['lane']-1,p['txs'],count)))
   c=cpus[t];w=walls[t]
   if is_owner and owner['begin_error']:
    need(len(c)==1 and len(w)==1 and c[0]['end']<w[0]['line'],'Refused begin sampled an extra interval')
    events.append({'kind':'reserve','request':req,'tid':t,'wall':w[0],'expected_error':owner['begin_error']})
    thread_summaries.append({'tid':t,'lane':lane['lane'],'role':'refused_owner','cpu_samples':1,'wall_samples':1})
    continue
   need(len(c)==txs+3 and len(w)==(txs+3 if is_owner else txs+1),'Actual role clock sequence count differs')
   if is_owner:
    need(c[0]['end']<w[0]['line'],'Reserve clock preceded real owner stamp')
    events.append({'kind':'reserve','request':req,'tid':t,'wall':w[0],'expected_error':0})
    if members:
     need(c[0]['end']<min(r['birth']['start'] for r in members),'Worker was born before owner stamp')
     need(max(r['exit']['end'] for r in members)<c[-2]['line'],'Operation completion preceded all actual worker exits')
   for i in range(txs+1):
    measured=ns(c[i+1])-ns(c[i])
    wall=w[i+1 if is_owner else i]
    need(c[i+1]['end']<wall['line']<c[i+2]['line'],'Live wall debit is not bracketed by actual same-thread samples')
    events.append({'kind':'charge_request_live' if i<txs else 'record_final_live','request':req,'tid':t,'wall':wall,'measured_ns':measured,'expected_error':0})
   full=ns(c[-1])-ns(c[0]);live=ns(c[-2])-ns(c[0]);residual=ns(c[-1])-ns(c[-2])
   need(full==live+residual,'Physical stamp attribution arithmetic differs')
   actual_live+=live;actual_full+=full
   if not is_owner:actual_workers+=full
   else:
    need(full==row[5] and c[-1]['end']<w[-1]['line'],'Actual owner full CPU differs')
    events.append({'kind':'settle_observed','request':req,'tid':t,'wall':w[-1],'residual_ns':row[13],'full_ns':row[9],'already_ns':row[11],'expected_settled':True})
   thread_summaries.append({'tid':t,'lane':lane['lane'],'role':'owner' if is_owner else 'scoped_worker','cpu_samples':len(c),'wall_samples':len(w),'full_ns':full,'live_ns':live,'residual_ns':residual,'txs':txs})
  if owner['begin_error']==0:
   need((actual_workers,actual_full,actual_live,actual_full-actual_live)==(row[7],row[9],row[11],row[13]),'Receipt is not the exact sum of actual thread CPU intervals')
   need(row[23]==(1<<p['txs'])-1,'Joined actual work mask differs')
   for tx in range(p['txs']):
    x=p['seed']^tx^(req+1)
    for step in range(p['units']):x=(x*1664525+1013904223+step)&MASK
    need(row[24+tx]==x,'Actual same-thread native HIA work result differs')
   need(not any(row[24+p['txs']:]),'Unassigned work emitted receipt bytes')
 allwall=sorted([w for ws in walls.values() for w in ws],key=lambda w:w['line'])
 need(allwall[0]==base and len(allwall)==len(events)+1,'Not every actual account clock is consumed')
 for a,b in zip(allwall,allwall[1:]):
  need(a['end']<b['line'],'Two actual global-account clock syscalls overlapped')
  need(ns(a)<=ns(b),'Actual global-account clock watermark reversed')
 events.sort(key=lambda e:e['wall']['line']);request_live={r:0 for r in owners}
 for event in events:
  sec,nanos=difference(event['wall'],base)
  event['relative_seconds']=sec;event['relative_nanos']=nanos;event['trace_line']=event['wall']['line']
  if event['kind'] in ('charge_request_live','record_final_live'):
   request_live[event['request']]+=event['measured_ns']
   need(request_live[event['request']]<(1<<64),'Accumulated actual request CPU overflowed')
   event['request_total_ns']=request_live[event['request']]
  if event['kind']=='settle_observed':
   need(event['already_ns']==request_live[event['request']],'Settlement did not consume every earlier actual live debit')
  del event['wall']
 state=words[8:28];need(state[0]==0x3130303055504350 and state[1]==0,'Final account state unavailable or wrong magic')
 need(state[6:10]==(0,0,0,1),'Outstanding principal or unknown telemetry after ordinary owners')
 updated={'seconds':state[4] if state[4]<(1<<63) else state[4]-(1<<64),'nanos':state[5]}
 need(ns(updated)==ns(allwall[-1]),'Final native watermark differs from last actual locked clock')
 need(signed(state[10],state[11])==(0 if plan['cold'] else 2000000000),'Constructor minted wrong principal')
 need(state[14]==0 and state[17]==state[15]+state[16],'Final live/residual/full ledger differs')
 need(sum(row['row'][9] for row in owners.values() if not row['begin_error'])==state[17],'Shared epoch paid CPU differs from actual settled owners')
 need(signed(state[2],state[3])==signed(state[10],state[11])+state[12]-state[15]-state[16]-state[18],'Final signed credit/flow identity differs')
 need(words[32]==1 and words[33]==state[17] and signed(words[34],words[35])==signed(state[2],state[3]) and words[36]==0,'Final flow observation differs')
 final_expected={'credit_ns':str(signed(state[2],state[3])),'unavailable':bool(state[1]),'in_flight':state[6],'termination_reserved_ns':state[7],'verified_completions':state[8],'flow_known':bool(state[9]),
  'updated_relative_seconds':difference(updated,base)[0],'updated_relative_nanos':difference(updated,base)[1],
  'initial_credit_ns':str(signed(state[10],state[11])),'credited_refill_ns':state[12],'discarded_refill_ns':state[13],'booked_reservation_ns':state[14],
  'live_debited_cpu_ns':state[15],'settlement_residual_cpu_ns':state[16],'settled_full_cpu_ns':state[17],'settlement_discard_ns':state[18]}
 return {'status':'ACTUAL_TRACE_AND_UNIQUE_RESIDUAL_PASS','main_tid':main,'real_children':len(by_tid),'syscalls':len(calls),'cpu_clock_calls':sum(map(len,cpus.values())),'wall_clock_calls':len(allwall),
 'actual_join_futex_calls':len(join_calls),'actual_mutex_calls':len(mutex_calls),'threads':sorted(thread_summaries,key=lambda r:r['lane']),
 'mutex_authority_evidence':'fixed checked HIA and literal adapter ownership gates plus every actual contended futex capability; uncontended userspace lock instructions do not emit syscalls',
 'replay':{'cold':bool(plan['cold']),'operations':events,'expected_final':final_expected},
 'actual_original_rust':False,'whole_paid_account_closed':False}
