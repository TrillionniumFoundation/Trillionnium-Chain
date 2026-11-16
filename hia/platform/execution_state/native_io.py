"""Bounded pipes for the actual sealed ELF; no State or Value execution here."""
from __future__ import annotations
import os, selectors, signal, struct, subprocess, time
from pathlib import Path
from hia.platform.build import sealed_executable
from .build import identity

OPCODES={'stats':0,'value.new':1,'value.clone':2,'value.export':3,'value.drop':4,
 'state.new':5,'state.clone':6,'state.drop':7,'state.put':8,'state.get':9,'state.remove':10,
 'state.export':11,'state.clear':12,'view.new':13,'view.get':14,'view.put':15,
 'view.scan':16,'view.drop':17,'patch.take':18,'patch.clone':19,'patch.current':20,
 'patch.apply':21,'patch.drop':22,'patch.export':23,'state.root':24,'state.prefix':25,
 'close':26,'value.eq':27}
CHILD_SECONDS=240
CLEANUP_SECONDS=3


def command(op:int,a:int=0,b:int=0,arg:int=0,key:bytes=b'',data:bytes=b'')->bytes:
    raw=b'SVP00001'+struct.pack('<7Q',op,a,b,arg,len(key),len(data),0)+key+data
    return struct.pack('<Q',len(raw))+raw


def decode(raw:bytes)->dict:
    if len(raw)<64 or raw[:8]!=b'SVPR0001':raise ValueError('Invalid native response header')
    op,sequence,status,result,n,objects,blocks=struct.unpack('<7Q',raw[8:64])
    if n!=len(raw)-64:raise ValueError('Invalid native response extent')
    return {'op':op,'sequence':sequence,'status':status,'result':result,'data_hex':raw[64:].hex(),'live_objects':objects,'live_blocks':blocks}


class Session:
    def __init__(self,elf:bytes,output:Path,*,seconds:float=CHILD_SECONDS,trace:bool=False,inject_mremap:bool=False):
        self.output=output;output.mkdir(mode=0o700);self.elf_identity=identity(elf);self.started=time.monotonic_ns();self.deadline=time.monotonic()+seconds;self.seconds=seconds
        self.stdin_log=(output/'stdin.raw').open('xb');self.stdout_log=(output/'stdout.raw').open('xb');self.stderr_log=(output/'stderr.raw').open('xb')
        self.attempted=0;self.written=0;self.received=0;self.stderr_bytes=0;self.buffer=bytearray();self.sequence=0;self.commands=[];self.closed=False;self.finished=False;self.cleanup=None;self.failure=None
        fd=sealed_executable(elf,'execution-state-owner')
        argv=['/proc/self/fd/'+str(fd)]
        self.instrumentation={'trace':trace,'mremap_errno_injected':inject_mremap}
        if inject_mremap and not trace:raise ValueError('Injection requires its actual syscall trace')
        if trace:
            argv=['/usr/bin/strace','-qq','-f','-xx','-s','128','-o',str(output/'syscalls.raw'),'-e','trace=mmap,mremap,mprotect,munmap,read,write,rt_sigaction,exit,exit_group']+(['-e','inject=mremap:error=ENOMEM:when=1'] if inject_mremap else [])+argv
        try:self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=output,env={'PATH':''},pass_fds=(fd,),start_new_session=True,umask=0o077,bufsize=0)
        finally:os.close(fd)
        for file in (self.process.stdin,self.process.stdout,self.process.stderr):os.set_blocking(file.fileno(),False)
        self.selector=selectors.DefaultSelector();self.selector.register(self.process.stdout,selectors.EVENT_READ,'stdout');self.selector.register(self.process.stderr,selectors.EVENT_READ,'stderr')
    def _read_ready(self,key):
        data=os.read(key.fileobj.fileno(),65536)
        if not data:self.selector.unregister(key.fileobj);return
        if key.data=='stdout':self.stdout_log.write(data);self.received+=len(data);self.buffer.extend(data)
        else:self.stderr_log.write(data);self.stderr_bytes+=len(data)
    def request_raw(self,raw:bytes)->dict:
        if self.finished or self.closed:raise RuntimeError('Session is closed')
        self.attempted+=len(raw);self.stdin_log.write(raw);offset=0;self.selector.register(self.process.stdin,selectors.EVENT_WRITE,'stdin');begin=time.monotonic_ns()
        try:
            while True:
                if offset==len(raw) and len(self.buffer)>=8:
                    n=struct.unpack_from('<Q',self.buffer)[0]
                    if n<64 or n>1<<31:raise ValueError('Impossible observed native response extent')
                    if len(self.buffer)>=n+8:
                        response=bytes(self.buffer[8:8+n]);del self.buffer[:8+n];result=decode(response);self.sequence+=1
                        if result['sequence']!=self.sequence:raise ValueError('Native response sequence differs')
                        result['elapsed_ns']=time.monotonic_ns()-begin;self.commands.append({'request':identity(raw),'response':identity(response),'actual':result});return result
                remain=self.deadline-time.monotonic()
                if remain<=0:raise TimeoutError('Actual native child budget expired')
                events=self.selector.select(min(remain,1.0))
                if not events and self.process.poll() is not None:raise RuntimeError('Native exited before its complete response: '+str(self.process.returncode))
                for key,mask in events:
                    if key.data=='stdin':
                        try:count=os.write(key.fileobj.fileno(),raw[offset:offset+65536])
                        except BlockingIOError:continue
                        if count<=0:raise RuntimeError('Nonpositive native stdin write')
                        offset+=count;self.written+=count
                        if offset==len(raw):self.selector.unregister(key.fileobj)
                    else:self._read_ready(key)
                if self.process.poll() is not None and not self.selector.get_map() and len(self.buffer)<8:raise RuntimeError('Native exited without a response')
        except BaseException as error:
            self.failure=repr(error)
            try:self.selector.unregister(self.process.stdin)
            except KeyError:pass
            raise
    def request(self,op:int,a:int=0,b:int=0,arg:int=0,key:bytes=b'',data:bytes=b'')->dict:
        result=self.request_raw(command(op,a,b,arg,key,data))
        if result['op']!=op:raise ValueError('Native operation echo differs')
        if op==26 and result['status']==0:self.closed=True
        return result
    def finish(self,*,allow_failure:bool=False)->dict:
        if self.finished:return self.receipt
        self.finished=True
        try:
            if self.process.poll() is None and not self.closed:
                begin=time.monotonic_ns()
                try:os.killpg(self.process.pid,signal.SIGKILL);outcome='sent'
                except ProcessLookupError:outcome='already_exited'
                self.cleanup={'signal':'SIGKILL','outcome':outcome,'elapsed_ns':time.monotonic_ns()-begin}
            self.process.stdin.close()
            deadline=time.monotonic()+CLEANUP_SECONDS
            while self.selector.get_map():
                left=deadline-time.monotonic()
                if left<=0:raise TimeoutError('Native stream cleanup did not finish')
                for key,mask in self.selector.select(min(left,0.2)):
                    if key.data=='stdin':self.selector.unregister(key.fileobj)
                    else:self._read_ready(key)
            self.process.wait(timeout=max(0.01,deadline-time.monotonic()))
        except BaseException as cleanup_error:
            self.cleanup={**(self.cleanup or {}),'error':repr(cleanup_error)}
            if self.process.poll() is None:
                try:os.killpg(self.process.pid,signal.SIGKILL);self.cleanup['final_signal']='sent'
                except ProcessLookupError:self.cleanup['final_signal']='already_exited'
                try:self.process.wait(timeout=CLEANUP_SECONDS)
                except BaseException as reap_error:self.cleanup['reap_error']=repr(reap_error)
        finally:
            self.selector.close()
            for file in (self.stdin_log,self.stdout_log,self.stderr_log):file.flush();file.close()
            self.process.stdout.close();self.process.stderr.close()
            self.receipt={'schema':'trnm.execution-state-native-process.v1','executable':self.elf_identity,'pid':self.process.pid,'exit_code':self.process.returncode,'clean_close':self.closed,'elapsed_ns':time.monotonic_ns()-self.started,'wall_limit_seconds':self.seconds,'cleanup_limit_seconds':CLEANUP_SECONDS,'cleanup':self.cleanup,'failure':self.failure,'stdin_attempted_bytes':self.attempted,'stdin_actual_write_bytes':self.written,'stdout_bytes':self.received,'stderr_bytes':self.stderr_bytes,'unconsumed_stdout_hex':self.buffer.hex(),'files':{name:identity((self.output/name).read_bytes()) for name in ('stdin.raw','stdout.raw','stderr.raw')},'commands':len(self.commands),'runtime_host_proxy':False,'instrumentation':self.instrumentation}
            if (self.output/'syscalls.raw').is_file():self.receipt['syscall_trace']=identity((self.output/'syscalls.raw').read_bytes())
            import json
            (self.output/'receipt.json').write_text(json.dumps(self.receipt,sort_keys=True,indent=2)+'\n')
        if not allow_failure and (self.process.returncode!=0 or not self.closed or self.stderr_bytes or self.buffer):raise RuntimeError('Native process did not close cleanly: '+str(self.receipt))
        return self.receipt


def execute(session:Session,steps:list[dict])->list[dict]:
    handles={};observations=[]
    for step in steps:
        op=OPCODES[step['op']]
        a=handles.get(step.get('a'),0);b=handles.get(step.get('b'),0)
        result=session.request(op,a,b,step.get('arg',0),bytes.fromhex(step.get('key_hex','')),bytes.fromhex(step.get('data_hex','')))
        if 'as' in step:handles[step['as']]=result['result']
        observation={key:result[key] for key in ('op','sequence','status','result','data_hex','live_objects')}
        expect=step.get('expect',{'status':0})
        for key,value in expect.items():
            if key=='result_nonzero':
                if bool(result['result'])!=value:raise AssertionError((step,observation))
            elif observation.get(key)!=value:raise AssertionError((step,observation))
        observations.append(observation)
    return observations
