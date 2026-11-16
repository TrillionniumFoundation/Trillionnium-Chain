"""Private x86-64 ptrace qualification of this process's own original child.
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
 return b''.join(peek(pid,address+i).to_bytes(8,'little') for i in range(0,n,8))[:n]
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
def run(argv,out,disable_vdso=False,env=None,fault=None,timeout=90):
 out=Path(out);out.mkdir(mode=0o700)
 stdout=(out/'stdout.raw').open('xb');stderr=(out/'stderr.raw').open('xb')
 before=identity(argv[0]);events=[];pending={};alive=set();roster={};unknown={};clocks=[];aux=None;primary=None
 report={'schema':'trnm.private.actual-original-ptrace-fault.v1','status':'FAIL',
  'argv':argv,'disable_vdso':disable_vdso,'executable_before':before}
 roles={};fired=[];gettid={};proc_tid={};spawn_fallback={}
 start=time.monotonic();pid=os.fork()
 if pid==0:
  try:
   fd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd)
   os.dup2(stdout.fileno(),1);os.dup2(stderr.fileno(),2)
   ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP)
   os.execve(argv[0],argv,{**os.environ,**(env or {})})
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
     born=event('birth',tid,child=c,ptrace_event=ev);roster[c]={'parent':tid,'birth':born['sequence']};alive.add(c)
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
      name=bytearray()
      for offset in range(0,256,8):
       part=bytes_at(tid,pointer+offset,8)
       if b'\0' in part:name.extend(part.split(b'\0',1)[0]);break
       name.extend(part)
      if bytes(name)==b'/proc/thread-self':
       row['own_thread_link']={'path':bytes(name).decode(),'buffer':args[1] if nr==89 else args[2],'capacity':args[2] if nr==89 else args[3]}
     if nr==1 and args[0]==2 and args[2]==32:
      marker=bytes_at(tid,args[1],32)
      if marker.startswith(b'PCROLE01'):row['role_marker_hex']=marker.hex()
     if nr==228:
      row['clock_id']=signed(args[0]);row['clock_ordinal']=sum(1 for c in clocks if c['tid']==tid)+1
      if tid in roles:
       roles[tid]['clock_count']+=1;row['role']=roles[tid]['role'];row['role_index']=roles[tid]['index'];row['role_clock_ordinal']=roles[tid]['clock_count']
       selected=fault and row['role'] in fault.get('clock_roles',[]) and row['role_clock_ordinal']==fault.get('clock_when')
       if selected:
        need(row['clock_id'] in (1,3),'Fault targeted non-account clock')
        row['fault']={'kind':'clock','error':fault.get('clock_error'),'invalid_timespec':fault.get('clock_invalid',False)}
     if nr in (56,435) and tid in roles:
      fallback=nr==56 and spawn_fallback.pop(tid,False)
      if not fallback:roles[tid]['spawn_count']+=1
      row['role_spawn_ordinal']=roles[tid]['spawn_count'];row['role']=roles[tid]['role'];row['role_index']=roles[tid]['index']
      row['logical_clone_fallback']=fallback
      if fault and row['role']==fault.get('clone_role') and row['role_spawn_ordinal']==fault.get('clone_when'):
       row['fault']={'kind':'clone','error':11}
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
       rule=entry['fault'];result=0 if rule.get('invalid_timespec') else -int(rule['error'])
       if rule.get('invalid_timespec'):
        poke_bytes(tid,entry['args'][1],struct.pack('<qq',0,1_000_000_000))
       r=regs(tid);r.rax=result&((1<<64)-1);ptrace(13,tid,0,ctypes.byref(r))
       need(signed(regs(tid).rax)==result,'Injected result did not read back')
       fired.append({'tid':tid,'role':entry.get('role'),'role_index':entry.get('role_index'),
        'clock_id':entry.get('clock_id'),'clock_ordinal':entry.get('role_clock_ordinal'),
        'spawn_ordinal':entry.get('role_spawn_ordinal'),'entry':entry['sequence'],
        'rule':rule,'actual_skipped_result':raw_result,'injected_result':result})
      row=event('syscall-exit',tid,entry=entry['sequence'],nr=entry['nr'],result=result,kernel_result_before_injection=raw_result)
      if 'own_thread_link' in entry:
       link=entry['own_thread_link']
       need(0<result<=link['capacity']<=65536,'Actual thread link read failed or unbounded')
       raw_link=bytes_at(tid,link['buffer'],result)
       expected=(str(pid)+'/task/'+str(tid)).encode()
       need(raw_link==expected,'Own /proc/thread-self did not return the actual traced TID')
       proc_tid[tid]=row['sequence'];row['own_thread_link_result_hex']=raw_link.hex()
      if entry['nr']==186:
       need(result==tid,'Actual gettid differs from traced task');gettid[tid]=row['sequence']
      if entry['nr']==435 and result==-38:spawn_fallback[tid]=True
      if 'role_marker_hex' in entry:
       need(result==32,'Role marker was not a complete actual write')
       marker=bytes.fromhex(entry['role_marker_hex']);declared,role,index=struct.unpack('<3Q',marker[8:])
       need(declared==tid and tid in proc_tid and proc_tid[tid]<entry['sequence'],'Role not bound to actual own kernel thread link')
       prior=roles.get(tid)
       need(role in (1,2,3,4) and index<8,'Unexpected private role')
       need((prior is None and role in (1,2,3)) or (prior is not None and prior['role']==1 and role==4),'Unexpected private role transition')
       roles[tid]={'role':role,'index':index,'marker_entry':entry['sequence'],'marker_exit':row['sequence'],'clock_count':0,'spawn_count':0}
       event('actual-role',tid,role=role,index=index,actual_thread_link_exit=proc_tid[tid])
      if entry['nr']==228:
       clock={'tid':tid,'ordinal':entry['clock_ordinal'],'clock_id':entry['clock_id'],
        'entry':entry['sequence'],'exit':row['sequence'],'result':result,
        'role':entry.get('role'),'role_index':entry.get('role_index'),'role_clock_ordinal':entry.get('role_clock_ordinal'),'injected':entry.get('fault')}
       if result==0:
        value=bytes_at(tid,entry['args'][1],16)
        clock.update(timespec_hex=value.hex(),seconds=struct.unpack_from('<q',value)[0],
          nanoseconds=struct.unpack_from('<q',value,8)[0])
       clocks.append(clock)
    resume(tid);continue
   if sig==signal.SIGSTOP and roster[tid]['parent'] is not None:
    event('child-initial-stop',tid);resume(tid);continue
   event('signal',tid,signal=sig);resume(tid,sig)
  need(not unknown,'Unassociated traced child')
  need(aux is not None,'No actual exec event')
  need(report.get('exit_code')==0 and report.get('signal') is None,'Actual original program failed')
  need(identity(argv[0])==before,'Actual original binary changed')
  if fault:need(bool(fired),'Declared fault was never reached in the actual original program')
  report.update(status='PASS',actual_clock_calls=clocks,roster=roster,auxv=aux,
    executable_after='MATCH',complete_owned_process_reaped=True,actual_roles=roles,fault=fault,injections=fired)
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
