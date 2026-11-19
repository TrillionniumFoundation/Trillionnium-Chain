"""Private x86-64 observation of this owner's actual original CLOCK fault child.
No attachment to existing processes. AT_SYSINFO_EHDR is changed only in the new
child's initial stack before its unmodified dynamic loader executes. This is a
controlled platform fixture, not normal-vDSO performance or retry evidence.
"""
from pathlib import Path
import ctypes,os,signal,struct,json,time,hashlib,traceback
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.ptrace.restype=ctypes.c_long
LIBC.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
class Regs(ctypes.Structure):
 _fields_=[(name,ctypes.c_ulonglong) for name in (
  'r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi',
  'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]
def need(value,message):
 if not value:raise ValueError(message)
def identity(path):
 p=Path(path);h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return {'bytes':p.stat().st_size,'sha256':h.hexdigest()}
def ptrace(req,pid,addr=0,data=0):
 ctypes.set_errno(0)
 a=ctypes.c_void_p(addr) if isinstance(addr,int) else addr
 d=ctypes.c_void_p(data) if isinstance(data,int) else data
 result=LIBC.ptrace(req,pid,a,d)
 if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()),(req,pid))
 return result
def regs(pid):
 value=Regs();ptrace(12,pid,0,ctypes.byref(value));return value
def peek(pid,address):return ptrace(2,pid,address,0)&((1<<64)-1)
def bytes_at(pid,address,n):
 need(0<=n<=65536,'Private bounded memory read')
 need(address>0 or n==0,'Actual memory read address absent')
 value=bytearray()
 while len(value)<n:
  cursor=address+len(value);aligned=cursor&~7
  raw=peek(pid,aligned).to_bytes(8,'little')[cursor-aligned:]
  value.extend(raw[:n-len(value)])
 return bytes(value)
def cstring(pid,address,limit=4096):
 need(address>0 and 0<limit<=4096,'Bounded actual C string required')
 result=bytearray()
 while len(result)<limit:
  cursor=address+len(result);aligned=cursor&~7
  raw=peek(pid,aligned).to_bytes(8,'little')[cursor-aligned:]
  raw=raw[:limit-len(result)]
  if b'\0' in raw:
   result.extend(raw.split(b'\0',1)[0]);return bytes(result)
  result.extend(raw)
 raise ValueError('Actual C string omitted bounded terminator')
def poke_bytes(pid,address,raw):
 for i in range(0,len(raw),8):
  part=raw[i:i+8]
  if len(part)<8:part+=bytes_at(pid,address+i+len(part),8-len(part))
  ptrace(5,pid,address+i,int.from_bytes(part,'little'))
 need(bytes_at(pid,address,len(raw))==raw,'Ptrace write did not read back')
def signed(n):return n-(1<<64) if n>>63 else n
def auxv_fixture(pid):
 r=regs(pid);start=r.rsp;argc=peek(pid,start);need(argc<=1024,'Unexpected argc')
 off=start+8*(argc+2);need(peek(pid,start+8*(argc+1))==0,'Missing argv terminator')
 env_count=0
 while peek(pid,off)!=0:
  env_count+=1;need(env_count<=4096,'Unexpected environment length');off+=8
 off+=8;rows=[]
 for _ in range(128):
  key=peek(pid,off);value=peek(pid,off+8);rows.append({'key':key,'value':value,'address':off})
  off+=16
  if key==0:break
 need(rows[-1]['key']==0,'Missing auxv terminator')
 selected=[x for x in rows if x['key']==33]
 need(len(selected)==1 and selected[0]['value']!=0,'No unique actual initial vDSO address')
 base=selected[0]['value'];need(bytes_at(pid,base,6)==b'\x7fELF\x02\x01','Actual vDSO is not ELF64')
 maps=Path(f'/proc/{pid}/maps').read_text()
 vdso=[line for line in maps.splitlines() if line.endswith('[vdso]')]
 need(len(vdso)==1 and int(vdso[0].split('-')[0],16)==base,'Auxv did not identify the actual vDSO mapping')
 before=bytes_at(pid,rows[0]['address'],len(rows)*16)
 poke_bytes(pid,selected[0]['address']+8,bytes(8))
 after=bytes_at(pid,rows[0]['address'],len(rows)*16)
 expect=bytearray(before);delta=selected[0]['address']+8-rows[0]['address'];expect[delta:delta+8]=bytes(8)
 need(after==bytes(expect),'Auxv changed outside its one AT_SYSINFO_EHDR value')
 return {'private_platform_fixture':True,'normal_vdso_behavior_claimed':False,
  'initial_stack_pointer':start,'argc':argc,'environment_count':env_count,
  'AT_SYSINFO_EHDR_before':base,'AT_SYSINFO_EHDR_after':0,'auxv_before_hex':before.hex(),
  'auxv_after_hex':after.hex(),'actual_vdso_mapping':vdso[0]}

def admit(argv,out,disable_vdso,env,fault,timeout):
 from .faults import profiles
 from .primitive_evidence import same
 need(__debug__,'Original CLOCK tracer refuses optimized Python')
 name='host_kernel_parent::kernel_parent::resource_tests::hia_work_owner_oracle::clock_fault_observation::actual_controlled_clock'
 need(type(argv) is list and len(argv)==5 and all(type(x) is str for x in argv)
      and argv[1:]==['--exact',name,'--nocapture','--test-threads=1'],'Exact private original CLOCK test argv required')
 executable=Path(argv[0])
 need(executable.is_absolute() and executable.resolve(strict=True)==executable and not executable.is_symlink(),
      'Canonical actual original CLOCK executable required')
 need(type(disable_vdso) is bool and type(timeout) is int and 1<=timeout<=90,'Private CLOCK observation profile differs')
 need(type(env) is dict and set(env)=={'PATH','TRNM_HIA_WORK_OWNER_CORPUS'}
      and all(type(x) is str for x in env.values()),'Exact private original runtime environment required')
 need(env['PATH']=='/usr/bin:/bin','Unbound original runtime PATH')
 corpus=Path(env['TRNM_HIA_WORK_OWNER_CORPUS'])
 need(corpus.is_absolute() and corpus.resolve(strict=True)==corpus and not corpus.is_symlink(),
      'Canonical original CLOCK corpus required')
 if fault is not None:
  allowed=[{'clock_roles':[3],'clock_when':p['ordinal'],'clock_error':5 if p['errno']=='EIO' else 22} for p in profiles()]
  need(disable_vdso and any(same(fault,row) for row in allowed),'Unreviewed private original CLOCK fault')
 destination=Path(out)
 need(destination.is_absolute() and destination.resolve()==destination and not destination.exists()
      and not destination.is_symlink(),'Fresh canonical private CLOCK output required')
 return destination

def run(argv,out,disable_vdso=False,env=None,fault=None,timeout=45):
 out=admit(argv,out,disable_vdso,env,fault,timeout);out.mkdir(mode=0o700)
 stdout=(out/'stdout.raw').open('xb');stderr=(out/'stderr.raw').open('xb')
 before=identity(argv[0]);events=[];pending={};alive=set();roster={};unknown={};clocks=[];aux=None;primary=None
 report={'schema':'trnm.hia.work-owner-original-clock-trace.v1','status':'FAIL',
  'argv':argv,'disable_vdso':disable_vdso,'environment':dict(env or {}),'executable_before':before}
 roles={};fired=[];gettid={};proc_tid={};spawn_fallback={};joins=[]
 resource_fds={};resource_intervals=[]
 start=time.monotonic();pid=os.fork()
 if pid==0:
  try:
   fd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd)
   os.dup2(stdout.fileno(),1);os.dup2(stderr.fileno(),2)
   ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP)
   os.execve(argv[0],argv,dict(env or {}))
  except BaseException:os._exit(124)
 stdout.close();stderr.close()
 def deadline(signum,frame):raise TimeoutError('Owned private ptrace run exceeded deadline')
 previous=signal.signal(signal.SIGALRM,deadline);signal.alarm(timeout)
 sequence=0
 def event(kind,tid,**kw):
  nonlocal sequence
  sequence+=1;value={'sequence':sequence,'kind':kind,'tid':tid,**kw};events.append(value);return value
 def resume(tid,sig=0):ptrace(24,tid,0,sig)
 try:
  p,status=os.waitpid(pid,0)
  need(p==pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'Owned TRACEME initial stop missing')
  ptrace(0x4200,pid,0,1|2|4|8|16|64|0x100000)
  alive.add(pid);roster[pid]={'parent':None,'birth':0};resume(pid)
  while alive:
   tid,status=os.waitpid(-1,0x40000000)
   need(tid in alive or os.WIFSTOPPED(status),'Unowned waitpid termination')
   if os.WIFEXITED(status) or os.WIFSIGNALED(status):
    terminal=event('terminal',tid,exit_code=os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
      signal=os.WTERMSIG(status) if os.WIFSIGNALED(status) else None)
    roster[tid]['terminal']=terminal;alive.remove(tid)
    if tid==pid:report['exit_code']=terminal['exit_code'];report['signal']=terminal['signal']
    pending.pop(tid,None);continue
   need(os.WIFSTOPPED(status),'Unexpected wait status')
   sig=os.WSTOPSIG(status);ev=status>>16
   if tid not in alive:
    need(sig==signal.SIGSTOP and ev==0,'Unknown stopped process')
    need(tid not in unknown,'Duplicate unknown child stop');unknown[tid]=status;continue
   if ev:
    if ev in (1,2,3):
     child=ctypes.c_ulonglong();ptrace(0x4201,tid,0,ctypes.byref(child));c=child.value
     need(c>0 and c not in roster,'Child identity was not fresh')
     call=pending.get(tid)
     need(call is not None and call['nr'] in (56,435) and 'actual_clone' in call,'Birth omitted actual clone entry')
     born=event('birth',tid,child=c,ptrace_event=ev)
     roster[c]={'parent':tid,'birth':born['sequence'],'clone_entry':call['sequence'],
                'child_tid_address':call['actual_clone']['child_tid']}
     alive.add(c)
     if c in unknown:unknown.pop(c);resume(c)
    elif ev==4:
     need(tid==pid and aux is None,'Unexpected second or child exec')
     actual=str(Path(f'/proc/{pid}/exe').resolve())
     need(actual==str(Path(argv[0]).resolve()),'Executed file differs from requested actual binary')
     if disable_vdso:aux=auxv_fixture(pid)
     else:aux={'private_platform_fixture':False,'auxv_unchanged':True}
     event('exec',tid,actual_executable=actual,auxv=aux)
    elif ev==6:
     value=ctypes.c_ulonglong();ptrace(0x4201,tid,0,ctypes.byref(value));event('exit-stop',tid,status=value.value)
    else:raise ValueError('Unexpected ptrace event '+str(ev))
    resume(tid);continue
   if sig==(signal.SIGTRAP|0x80):
    info=ctypes.create_string_buffer(128);n=ptrace(0x420e,tid,128,ctypes.byref(info))
    raw=bytes(info);op=raw[0];arch=struct.unpack_from('<I',raw,4)[0]
    need(arch==0xc000003e and op in (1,2),'Unexpected syscall ABI/stop')
    if op==1:
     nr=struct.unpack_from('<Q',raw,24)[0];args=list(struct.unpack_from('<6Q',raw,32))
     need(tid not in pending,'Overlapping syscall entry')
     row=event('syscall-entry',tid,nr=nr,args=args)
     if nr in (89,267):
      pointer=args[0] if nr==89 else args[1]
      name=cstring(tid,pointer)
      if name==b'/proc/thread-self':
       row['own_thread_link']={'path':name.decode(),'buffer':args[1] if nr==89 else args[2],'capacity':args[2] if nr==89 else args[3]}
     if nr in (2,257):
      name=cstring(tid,args[0] if nr==2 else args[1])
      row['actual_open']={'path_hex':name.hex(),'flags':args[1] if nr==2 else args[2],
                          'dirfd':None if nr==2 else signed(args[0])}
     if nr in (0,3) and args[0] in resource_fds:
      row['resource_interval']=resource_fds[args[0]]
     if nr==1 and args[0]==2 and args[2]==32:
      marker=bytes_at(tid,args[1],32)
      if marker.startswith(b'PCROLE01'):row['role_marker_hex']=marker.hex()
      if marker.startswith(b'PCJOIN01'):
       parent,child,panicked=struct.unpack('<3Q',marker[8:])
       need(parent==tid and child in roster and roster[child]['parent']==tid and panicked in (0,1),
            'Private join marker omitted actual owned child')
       address=roster[child]['child_tid_address']
       need(address>0 and address%4==0,'Actual child clear-tid address absent')
       row['join_marker_hex']=marker.hex()
       row['join_child_tid_address']=address
       row['join_child_tid_word']=int.from_bytes(bytes_at(tid,address,4),'little')
     if nr==228:
      row['clock_id']=signed(args[0]);row['clock_ordinal']=sum(1 for c in clocks if c['tid']==tid)+1
      if tid in roles:
       roles[tid]['clock_count']+=1;row['role']=roles[tid]['role'];row['role_index']=roles[tid]['index'];row['role_clock_ordinal']=roles[tid]['clock_count']
       selected=fault and row['role'] in fault.get('clock_roles',[]) and row['role_clock_ordinal']==fault.get('clock_when')
       if selected:
        need(row['clock_id']==1,'Fault targeted another clock')
        row['fault']={'kind':'clock','error':fault['clock_error']}
     if nr in (56,435):
      if nr==56:
       row['actual_clone']={'abi':'clone','flags':args[0],'stack':args[1],
        'parent_tid':args[2],'child_tid':args[3],'tls':args[4]}
      else:
       need(64<=args[1]<=88,'Original clone3 argument extent differs')
       captured=bytes_at(tid,args[0],args[1])
       words=struct.unpack('<11Q',captured+bytes(88-len(captured)))
       row['actual_clone']={'abi':'clone3','argument_hex':captured.hex(),'argument_bytes':args[1],
        **dict(zip(('flags','pidfd','child_tid','parent_tid','exit_signal','stack','stack_size','tls','set_tid','set_tid_size','cgroup'),words))}
     if nr==202:
      need(args[0]%4==0,'Original futex word is not naturally aligned')
      row['futex_word_before']=int.from_bytes(bytes_at(tid,args[0],4),'little')
     if nr in (56,435) and tid in roles:
      fallback=nr==56 and spawn_fallback.pop(tid,False)
      if not fallback:roles[tid]['spawn_count']+=1
      row['role_spawn_ordinal']=roles[tid]['spawn_count'];row['role']=roles[tid]['role'];row['role_index']=roles[tid]['index']
      row['logical_clone_fallback']=fallback
     if 'fault' in row:
      original=regs(tid);need(original.orig_rax==nr,'Entry register syscall differs')
      original.orig_rax=(1<<64)-1;ptrace(13,tid,0,ctypes.byref(original))
      need(regs(tid).orig_rax==(1<<64)-1,'Could not skip exactly selected qualification syscall')
      row['fault']['original_syscall_skipped']=True
     pending[tid]=row
    else:
     result=struct.unpack_from('<q',raw,24)[0];entry=pending.pop(tid,None)
     if entry is None:
      need(roster[tid]['parent'] is not None and result==0,'Syscall exit without matching entry')
      event('child-clone-return',tid,result=result)
     else:
      raw_result=result
      if 'fault' in entry:
       need(raw_result==-38,'Selected skipped syscall did not return ENOSYS')
       rule=entry['fault'];result=-rule['error']
       r=regs(tid);r.rax=result&((1<<64)-1);ptrace(13,tid,0,ctypes.byref(r))
       need(signed(regs(tid).rax)==result,'Injected result did not read back')
       fired.append({'tid':tid,'role':entry.get('role'),'role_index':entry.get('role_index'),
        'clock_id':entry.get('clock_id'),'clock_ordinal':entry.get('role_clock_ordinal'),
        'spawn_ordinal':entry.get('role_spawn_ordinal'),'entry':entry['sequence'],
        'rule':rule,'actual_skipped_result':raw_result,'injected_result':result})
      row=event('syscall-exit',tid,entry=entry['sequence'],nr=entry['nr'],result=result,kernel_result_before_injection=raw_result)
      if 'actual_open' in entry and result>=0:
       opened=entry['actual_open'];name=bytes.fromhex(opened['path_hex']).split(b'/')[-1]
       if name in (b'cpu.stat',b'memory.current',b'pids.current') and opened['flags']&3==0 and not opened['flags']&0x200000:
        need(result not in resource_fds,'Original resource FD reused before observed close')
        resource_fds[result]=len(resource_intervals)
        resource_intervals.append({'fd':result,'opened_by_tid':tid,'counter':name.decode(),
          'path_hex':opened['path_hex'],'dirfd':opened['dirfd'],'flags':opened['flags'],
          'open_entry':entry['sequence'],'open_exit':row['sequence'],'reads':[],'close':None})
      if 'resource_interval' in entry:
       number=entry['resource_interval'];captured=resource_intervals[number]
       need(resource_fds.get(entry['args'][0])==number,'Actual resource descriptor lineage changed')
       if entry['nr']==0:
        need(0<=result<=entry['args'][2] and result<=65536 and entry['args'][2]>0,
             'Original resource read failed or exceeded bounded byte capture')
        value=bytes_at(tid,entry['args'][1],result) if result else b''
        read={'tid':tid,'entry':entry['sequence'],'exit':row['sequence'],'requested':entry['args'][2],
              'result':result,'data_hex':value.hex()}
        row['actual_resource_read']=read;captured['reads'].append(read)
       else:
        need(entry['nr']==3 and result==0 and captured['close'] is None,'Original resource close differs')
        captured['close']={'tid':tid,'entry':entry['sequence'],'exit':row['sequence'],'result':result}
        resource_fds.pop(entry['args'][0])
      if 'own_thread_link' in entry:
       link=entry['own_thread_link']
       need(0<result<=link['capacity']<=65536,'Actual thread link read failed or unbounded')
       raw_link=bytes_at(tid,link['buffer'],result)
       expected=(str(pid)+'/task/'+str(tid)).encode()
       need(raw_link==expected,'Own /proc/thread-self did not return the actual traced TID')
       proc_tid[tid]=row['sequence'];row['own_thread_link_result_hex']=raw_link.hex()
      if entry['nr']==202:
       row['futex_word_after']=int.from_bytes(bytes_at(tid,entry['args'][0],4),'little')
      if 'actual_clone' in entry and result>0:
       parent_tid=entry['actual_clone']['parent_tid']
       if entry['actual_clone']['flags']&0x100000:
        need(parent_tid>0 and parent_tid%4==0,'Original parent-settid address invalid')
        row['parent_tid_word_after']=int.from_bytes(bytes_at(tid,parent_tid,4),'little')
      if entry['nr']==186:
       need(result==tid,'Actual gettid differs from traced task');gettid[tid]=row['sequence']
      if entry['nr']==435 and result==-38:spawn_fallback[tid]=True
      if 'role_marker_hex' in entry:
       need(result==32,'Role marker was not a complete actual write')
       marker=bytes.fromhex(entry['role_marker_hex']);declared,role,index=struct.unpack('<3Q',marker[8:])
       need(declared==tid and tid in proc_tid and proc_tid[tid]<entry['sequence'],'Role not bound to actual own kernel thread link')
       prior=roles.get(tid)
       need(role in (1,3) and index==0 and prior is None,'Unexpected private role or repeated transition')
       roles[tid]={'role':role,'index':index,'marker_entry':entry['sequence'],'marker_exit':row['sequence'],'clock_count':0,'spawn_count':0}
       event('actual-role',tid,role=role,index=index,actual_thread_link_exit=proc_tid[tid])
      if 'join_marker_hex' in entry:
       need(result==32,'Join marker was not a complete actual write')
       parent,child,panicked=struct.unpack('<3Q',bytes.fromhex(entry['join_marker_hex'])[8:])
       need(parent==tid and roles.get(tid,{}).get('role')==1 and roles.get(child,{}).get('role')==3,
            'Actual join role identity differs')
       # The bound glibc pthread_join consumes a kernel-cleared thread by storing -1.
       # Keep this post-join state distinct from actual zero observed at a futex return.
       need(entry['join_child_tid_word']==0xffffffff,'Actual original glibc join did not retain its consumed-thread state')
       joined=event('actual-join',tid,worker_tid=child,panicked=bool(panicked),
          marker_entry=entry['sequence'],marker_exit=row['sequence'],
          actual_child_tid_address=entry['join_child_tid_address'],actual_child_tid_word=entry['join_child_tid_word'])
       joins.append(joined)
      if entry['nr']==228:
       clock={'tid':tid,'ordinal':entry['clock_ordinal'],'clock_id':entry['clock_id'],
        'entry':entry['sequence'],'exit':row['sequence'],'result':result,
        'role':entry.get('role'),'role_index':entry.get('role_index'),'role_clock_ordinal':entry.get('role_clock_ordinal'),'injected':entry.get('fault')}
       if result==0:
        value=bytes_at(tid,entry['args'][1],16)
        row['actual_timespec_hex']=value.hex()
        clock.update(timespec_hex=value.hex(),seconds=struct.unpack_from('<q',value)[0],
          nanoseconds=struct.unpack_from('<q',value,8)[0])
       clocks.append(clock)
    resume(tid);continue
   if sig==signal.SIGSTOP and roster[tid]['parent'] is not None:
    event('child-initial-stop',tid);resume(tid);continue
   event('signal',tid,signal=sig);resume(tid,sig)
  need(not unknown,'Unassociated traced child')
  need(not resource_fds,'Original resource descriptors lack actual close observations')
  need(aux is not None,'No actual exec event')
  need(report.get('exit_code')==0 and report.get('signal') is None,'Actual original program failed')
  need(identity(argv[0])==before,'Actual original binary changed')
  if fault:need(bool(fired),'Declared fault was never reached in the actual original program')
  report.update(status='PASS',actual_clock_calls=clocks,roster=roster,auxv=aux,
    executable_after='MATCH',complete_owned_process_reaped=True,actual_roles=roles,fault=fault,injections=fired,
    actual_resource_intervals=resource_intervals,actual_joins=joins)
 except BaseException as error:
  primary=error;report.update(failure=repr(error),traceback=traceback.format_exc())
 finally:
  signal.alarm(0);signal.signal(signal.SIGALRM,previous)
  if alive or unknown:
   cleanup={"owned_tids_before":sorted(alive|set(unknown)),"signals":[],"complete":False}
   for target in sorted(alive|set(unknown)):
    try:os.kill(target,signal.SIGKILL);cleanup["signals"].append({"tid":target,"result":"sent"})
    except ProcessLookupError:cleanup["signals"].append({"tid":target,"result":"already_exited"})
   end=time.monotonic()+3
   while (alive or unknown) and time.monotonic()<end:
    try:
     tid,status=os.waitpid(-1,0x40000000|os.WNOHANG)
     if tid==0:time.sleep(0.005);continue
     if os.WIFEXITED(status) or os.WIFSIGNALED(status):
      alive.discard(tid);unknown.pop(tid,None)
     elif os.WIFSTOPPED(status):
      try:ptrace(7,tid,0,signal.SIGKILL)
      except ProcessLookupError:pass
    except ChildProcessError:
     alive.clear();unknown.clear();break
   cleanup.update(complete=not alive and not unknown,owned_tids_after=sorted(alive|set(unknown)))
   report["failure_cleanup"]=cleanup
   if not cleanup["complete"]:report["status"]="FAIL";report["cleanup_failure"]="Owned traced descendants were not reaped before the bound"
  report['duration_seconds']=time.monotonic()-start
  (out/'events.jsonl').write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in events))
  report['events']=identity(out/'events.jsonl');report['stdout']=identity(out/'stdout.raw');report['stderr']=identity(out/'stderr.raw')
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 if primary:raise primary
 return report
