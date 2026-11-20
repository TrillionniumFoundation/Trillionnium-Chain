"""Source-bound qualification of actual native stream operations and API reuse."""
from pathlib import Path
import argparse
import fcntl
import json
import os
import re
import select
import signal
import shutil
import socket
import struct
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]))
from hia.platform.build import sealed_executable,sha256,write_json,run_native
from hia.platform.reactor.build import Build,new_output
from hia.platform.reactor.contracts import Contracts
from hia.tools.qualify_platform import guard_source

FIELDS=['magic_bits','status','requested','read_bytes','written_bytes','start_ns','deadline_ns','terminal_ns',
        'eagain','eintr','partial_read','partial_write','epoll_timeout','epoll_ready','cancel','cause_bits',
        'close_errors','closed_count','chunks','operation_sequence','last_handle','calls','last_result_bits','last_phase']


class Child:
    def __init__(self,case,elf,*,mode=0,amount=8,budget=5000,cancel=0,
                 stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,args=None):
        self.case=case;self.elf=elf;self.events=[];self.input=b'';self.finished=False;self.cleanup_used=False
        fd=sealed_executable(elf,case.name)
        argv=['/proc/self/fd/'+str(fd),str(mode),str(amount),str(budget),str(cancel)] if args is None else ['/proc/self/fd/'+str(fd)]+args
        self.start=time.monotonic_ns()
        try:self.p=subprocess.Popen(argv,stdin=stdin,stdout=stdout,stderr=stderr,pass_fds=tuple([fd]+([cancel] if cancel else [])),cwd=case,env={'PATH':''},start_new_session=True,umask=0o077)
        finally:os.close(fd)
        self.pidfd=os.pidfd_open(self.p.pid)
        self.launch={'argv':argv,'cwd':str(case),'environment':{'PATH':''},'executable_sha256':sha256(elf),'pid':self.p.pid,'start_ns':self.start,
            'child_umask':'0077','stdio_parent_descriptors':[stdin,stdout,stderr],
            'communicate_limit_seconds':8,'cleanup_sigterm_seconds':1,'cleanup_sigkill_seconds':2}
        write_json(case/'launch.json',self.launch)

    def __enter__(self):return self

    def __exit__(self,kind,value,tb):
        try:
            if not self.finished:
                self.cleanup_used=True;start=time.monotonic_ns();actions=[];out=err=b'';failure=None
                try:
                    if self.p.poll() is None:
                        try:signal.pidfd_send_signal(self.pidfd,signal.SIGTERM);actions.append('SIGTERM_SENT')
                        except ProcessLookupError:actions.append('ALREADY_EXITED_BEFORE_SIGTERM')
                    try:out,err=self.p.communicate(timeout=1)
                    except subprocess.TimeoutExpired as timeout:
                        out,err=timeout.stdout or b'',timeout.stderr or b''
                        try:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL);actions.append('SIGKILL_SENT')
                        except ProcessLookupError:actions.append('ALREADY_EXITED_BEFORE_SIGKILL')
                        out,err=self.p.communicate(timeout=2)
                except BaseException as exc:
                    failure=type(exc).__name__+': '+str(exc)
                    if isinstance(exc,subprocess.TimeoutExpired):out,err=exc.stdout or b'',exc.stderr or b''
                    raise
                finally:
                    (self.case/'cleanup.stdout.raw').write_bytes(out or b'')
                    (self.case/'cleanup.stderr.raw').write_bytes(err or b'')
                    (self.case/'stdin.raw').write_bytes(self.input)
                    write_json(self.case/'cleanup.json',{**self.launch,'actions':actions,
                        'exit_code':self.p.returncode,'complete':self.p.returncode is not None,
                        'elapsed_ns':time.monotonic_ns()-start,'exception':failure,
                        'original_exception':None if value is None else type(value).__name__+': '+str(value),
                        'events':self.events,'external_cleanup_used':True,
                        'stdout_sha256':sha256(out or b''),'stderr_sha256':sha256(err or b''),
                        'counts_as_native_deadline_success':False})
        finally:os.close(self.pidfd)

    def snapshot(self):
        if self.p.poll() is not None:raise RuntimeError('child exited before required readiness')
        root=Path('/proc')/str(self.p.pid)
        fields=dict(line.split(':',1) for line in (root/'status').read_text().splitlines() if ':' in line)
        text=(root/'syscall').read_text().strip();words=text.split();nr=None;args=[];tokens=[]
        if words and words[0]!='running':
            nr=int(words[0],0)
            if nr>=0:args=[int(v,0) for v in words[1:7]]
        if nr==232 and args:
            info=(root/'fdinfo'/str(args[0])).read_text()
            tokens=[int(v,16) for v in re.findall(r'data:\s*([0-9a-fA-F]+)',info)]
        return {'monotonic_ns':time.monotonic_ns(),'syscall':nr,'arguments':args,'syscall_text':text,
                'state':fields['State'].strip(),'context_switches':int(fields['voluntary_ctxt_switches']),
                'sig_caught':int(fields['SigCgt'].strip(),16),'pending':int(fields['SigPnd'].strip(),16)|int(fields['ShdPnd'].strip(),16),
                'epoll_registered_tokens':tokens}

    def waiting(self,token=None,after=None):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            row=self.snapshot()
            if (row['syscall']==232 and row['state'].startswith('S') and len(row['arguments'])==6
                and row['arguments'][2]==2 and 1<=row['arguments'][3]<=100
                and row['sig_caught']&(1<<(signal.SIGUSR1-1)) and not row['pending']&(1<<(signal.SIGUSR1-1))
                and (token is None or token in row['epoll_registered_tokens'])
                and (after is None or row['context_switches']>after)):
                self.events.append(row);return row
            time.sleep(.002)
        raise TimeoutError('native epoll readiness not observed')

    def send(self,raw):
        self.p.stdin.write(raw);self.p.stdin.flush();self.input+=raw
        self.events.append({'action':'stdin-write','hex':raw.hex(),'monotonic_ns':time.monotonic_ns()})

    def send_signal(self):
        signal.pidfd_send_signal(self.pidfd,signal.SIGUSR1)
        self.events.append({'action':'SIGUSR1','monotonic_ns':time.monotonic_ns()})

    def await_exit(self,seconds=7):
        poller=select.poll();poller.register(self.pidfd,select.POLLIN)
        if not poller.poll(int(seconds*1000)):raise TimeoutError('native process did not reach its own terminal state')
        self.p.wait(timeout=1)

    def finish(self,expected=0,data=None,override=None,report=True):
        if data is not None:self.input+=data
        out,err=self.p.communicate(data,timeout=8)
        if override is not None:out=override
        out=out or b'';err=err or b'';self.finished=True
        end=time.monotonic_ns()
        (self.case/'stdin.raw').write_bytes(self.input);(self.case/'stdout.raw').write_bytes(out);(self.case/'stderr.raw').write_bytes(err)
        row={**self.launch,'exit_code':self.p.returncode,'expected_exit':expected,'end_ns':end,'elapsed_ns':end-self.start,
             'external_cleanup_used':self.cleanup_used,'stdout_bytes':len(out),'stdout_sha256':sha256(out),
             'stderr_bytes':len(err),'stderr_sha256':sha256(err),'events':self.events,'passed':self.p.returncode==expected and not self.cleanup_used}
        if report:
            row['passed'] &= len(err)==192
            if len(err)==192:
                obs=dict(zip(FIELDS,struct.unpack('<24Q',err)));obs['magic']=err[:8].decode(errors='replace');row['observation']=obs
                row['passed'] &= obs['magic']=='HIAIO001' and obs['status']==expected and obs['close_errors']==0
                row['passed'] &= self.start<=obs['start_ns']<=obs['terminal_ns']<=end
        write_json(self.case/'child-receipt.json',row)
        return row,out,err


class Suite:
    def __init__(self,output):
        self.output=output;self.build=Build(output/'build');self.build_receipt=self.build.build()
        self.elf=self.build.executable;self.context_elf=self.build.context_executable;self.rows=[]
    def case(self,name,fn):
        folder=self.output/name;folder.mkdir()
        try:row=fn(folder)
        except Exception as exc:row={'passed':False,'exception':type(exc).__name__+': '+str(exc)}
        row['case']=name;self.rows.append(row);write_json(folder/'result.json',row)
        print(json.dumps({'case':name,'passed':row['passed'],'observation':row.get('observation'),'exception':row.get('exception')}),flush=True)
        write_json(self.output/'partial.json',{'cases':self.rows})
    def ordinary(self,folder,amount=8):
        payload=(bytes(range(251))*((amount+250)//251))[:amount]
        with Child(folder,self.elf,amount=amount) as c:
            row,out,_=c.finish(data=payload)
            row['passed'] &= out==payload and row['observation']['read_bytes']==amount and row['observation']['written_bytes']==amount
            return row
    def short_read(self,folder):
        with Child(folder,self.elf) as c:
            before=c.waiting(token=4294967297)
            for part in (b'H',b'IA'):
                c.send(part);before=c.waiting(token=4294967297,after=before['context_switches'])
            row,out,_=c.finish(data=b'probe')
            row['passed'] &= out==b'HIAprobe' and row['observation']['partial_read']==2
            return row
    def interrupted(self,folder):
        with Child(folder,self.elf) as c:
            before=c.waiting(token=4294967297)
            for _ in range(2):
                c.send_signal();before=c.waiting(token=4294967297,after=before['context_switches'])
            row,out,_=c.finish(data=b'HIAprobe')
            row['passed'] &= out==b'HIAprobe' and row['observation']['eintr']==2
            return row
    def idle(self,folder,partial=False):
        with Child(folder,self.elf,budget=300 if partial else 5000) as c:
            before=c.waiting(token=4294967297)
            if partial:
                c.send(b'HIA');c.waiting(token=4294967297,after=before['context_switches'])
            c.await_exit()
            row,out,_=c.finish(expected=72)
            obs=row['observation'];row['passed'] &= out==b'' and obs['read_bytes']==(3 if partial else 0) and obs['written_bytes']==0
            row['passed'] &= obs['deadline_ns']<=obs['terminal_ns']<=obs['deadline_ns']+1_000_000_000
            row['deadline_external_signal_or_input_wakeup']=False
            return row
    def output_pipe(self,folder,timeout=False,cancelled=False):
        r,w=os.pipe2(os.O_CLOEXEC);fcntl.fcntl(w,fcntl.F_SETPIPE_SZ,4096)
        cr=cw=None
        if cancelled:cr,cw=os.pipe2(os.O_CLOEXEC)
        try:
            with Child(folder,self.elf,mode=2,amount=65536,budget=5000,stdout=w,cancel=cr or 0) as c:
                os.close(w);w=None;c.waiting(token=4294967298)
                if cancelled:
                    os.write(cw,b'!');c.await_exit(2)
                elif timeout:c.await_exit()
                os.set_blocking(r,False);chunks=[];limit=time.monotonic()+7
                while time.monotonic()<limit:
                    try:
                        chunk=os.read(r,65536)
                        if not chunk:break
                        chunks.append(chunk)
                    except BlockingIOError:
                        select.select([r],[],[],.1)
                else:raise TimeoutError('output drain exceeded bound')
                row,out,_=c.finish(expected=73 if cancelled else 72 if timeout else 0,override=b''.join(chunks))
                obs=row['observation'];row['passed'] &= obs['partial_write']>=1 and obs['eagain']>=1
                row['passed'] &= out==(bytes(range(256))*256)[:len(out)] and obs['written_bytes']==len(out)
                row['passed'] &= (0<len(out)<65536) if timeout or cancelled else len(out)==65536
                return row
        finally:
            os.close(r)
            if w is not None:os.close(w)
            if cr is not None:os.close(cr)
            if cw is not None:os.close(cw)
    def cancelled_read(self,folder,eof=False):
        r,w=os.pipe2(os.O_CLOEXEC)
        try:
            with Child(folder,self.elf,cancel=r) as c:
                c.waiting(token=4294967297)
                if eof:os.close(w);w=None
                else:os.write(w,b'!')
                c.await_exit(2)
                row,out,_=c.finish(expected=73)
                row['passed'] &= out==b'' and row['observation']['cancel']==1 and row['observation']['closed_count']==4
                return row
        finally:
            os.close(r)
            if w is not None:os.close(w)
    def eof(self,folder):
        with Child(folder,self.elf) as c:
            row,out,_=c.finish(expected=65,data=b'HIA')
            row['passed'] &= out==b'' and row['observation']['read_bytes']==3 and row['observation']['written_bytes']==0
            return row
    def epipe(self,folder):
        r,w=os.pipe();os.close(r)
        try:
            with Child(folder,self.elf,mode=2,amount=65536,stdout=w) as c:
                row,_,_=c.finish(expected=70)
                row['passed'] &= row['observation']['cause_bits']==(1<<64)-32 and row['observation']['written_bytes']==0
                return row
        finally:os.close(w)
    def regular(self,folder,output=False):
        file=folder/'canary';file.write_bytes(b'UNCHANGED')
        fd=os.open(file,os.O_RDWR if output else os.O_RDONLY)
        try:
            with Child(folder,self.elf,**({'stdout':fd} if output else {'stdin':fd})) as c:
                row,_,_=c.finish(expected=71,data=b'HIAprobe' if output else None)
                row['passed'] &= file.read_bytes()==b'UNCHANGED' and os.lseek(fd,0,os.SEEK_CUR)==0
                row['passed'] &= row['observation']['read_bytes']==0 and row['observation']['written_bytes']==0
                return row
        finally:os.close(fd)
    def socket_copy(self,folder,linger=False):
        peer,owned=socket.socketpair()
        owned.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        if linger:owned.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,1))
        original_flags=fcntl.fcntl(owned.fileno(),fcntl.F_GETFL)
        amount=65536;payload=bytes(range(256))*256
        try:
            with Child(folder,self.elf,amount=amount,stdin=owned.fileno(),stdout=owned.fileno()) as c:
                if linger:
                    row,_,_=c.finish(expected=71)
                    row['passed'] &= row['observation']['read_bytes']==row['observation']['written_bytes']==0
                    row['fd_flags_before']=original_flags;row['fd_flags_after']=fcntl.fcntl(owned.fileno(),fcntl.F_GETFL)
                    row['passed'] &= row['fd_flags_before']==row['fd_flags_after'] and row['observation']['closed_count']==0
                    return row
                owned.close()
                peer.settimeout(3);peer.sendall(payload)
                c.waiting(token=8589934594)
                chunks=[]
                while True:
                    chunk=peer.recv(65536)
                    if not chunk:break
                    chunks.append(chunk)
                row,out,_=c.finish(override=b''.join(chunks))
                row['passed'] &= out==payload and row['observation']['partial_write']>=1 and row['observation']['written_bytes']==amount
                return row
        finally:peer.close();owned.close()
    def args_refused(self,folder,args):
        with Child(folder,self.elf,args=args) as c:
            row,out,err=c.finish(expected=64,data=b'',report=False)
            row['passed'] &= not out and not err
            return row

    def retained_context(self,folder,deadline=False,prepared=False):
        with Child(folder,self.context_elf,mode=1 if prepared else 0,budget=1000 if deadline else 5000) as c:
            if deadline:
                c.waiting(token=4294967297);c.send(b'1234')
                c.waiting(token=12884901889);c.await_exit(3)
                row,out,_=c.finish(expected=72)
                obs=row['observation']
                row['passed'] &= out==b'1234' and obs['read_bytes']==obs['written_bytes']==0
                row['passed'] &= obs['operation_sequence']==3 and 1_000_000_000<=row['elapsed_ns']<3_000_000_000
                row['passed'] &= obs['deadline_ns']<=obs['terminal_ns']<=obs['deadline_ns']+1_000_000_000
                row['native_deadline_without_external_signal_or_input_wakeup']=True
            elif prepared:
                row,out,_=c.finish()
                row['passed'] &= out==bytes((i*37+11)&255 for i in range(17))
                row['passed'] &= row['observation']['written_bytes']==17 and row['observation']['read_bytes']==0
            else:
                row,out,_=c.finish(data=b'1234abcd')
                obs=row['observation']
                row['passed'] &= out==b'1234abcd' and obs['operation_sequence']==4
                row['passed'] &= obs['read_bytes']==obs['written_bytes']==4 and obs['closed_count']==3
            row['hia_caller_checks']=['quiescent tick idempotence','closed tick/close idempotence',
                'retained epoll and capability identity','generation invalidation','actual EBADF on owned descriptors after close']
            return row

    def full_diagnostics(self,folder):
        r,w=os.pipe2(os.O_CLOEXEC);fcntl.fcntl(w,fcntl.F_SETPIPE_SZ,4096)
        canary=b'D'*4096;os.write(w,canary)
        try:
            with Child(folder,self.elf,budget=500,stderr=w) as c:
                os.close(w);w=None;c.waiting(token=4294967297);c.await_exit(3)
                row,out,err=c.finish(expected=72,report=False)
                captured=os.read(r,8192)
                (folder/'diagnostic-channel.raw').write_bytes(captured)
                row['passed'] &= out==err==b'' and captured==canary
                row['passed'] &= 500_000_000<=row['elapsed_ns']<2_000_000_000
                row['diagnostic_delivered']=False
                row['native_deadline_without_external_signal_or_input_wakeup']=True
                return row
        finally:
            os.close(r)
            if w is not None:os.close(w)

    def socket_refused(self,folder,datagram=False):
        owned=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM)
        original=fcntl.fcntl(owned.fileno(),fcntl.F_GETFL)
        try:
            with Child(folder,self.elf,stdin=owned.fileno()) as c:
                row,out,_=c.finish(expected=71 if datagram else 70)
                row['fd_flags_before']=original;row['fd_flags_after']=fcntl.fcntl(owned.fileno(),fcntl.F_GETFL)
                row['inherited_socket_family']='AF_INET'
                obs=row['observation']
                row['passed'] &= out==b'' and obs['read_bytes']==obs['written_bytes']==obs['closed_count']==0
                row['passed'] &= original==row['fd_flags_after']
                if not datagram:row['passed'] &= obs['cause_bits']==(1<<64)-107
                return row
        finally:owned.close()

    def cancel_alias(self,folder):
        r,w=os.pipe2(os.O_CLOEXEC);cancel=os.dup(r);payload=b'HIAprobe';os.write(w,payload)
        try:
            with Child(folder,self.elf,stdin=r,cancel=cancel) as c:
                row,out,_=c.finish(expected=71)
                remaining=os.read(r,len(payload))
                row['queued_input_after_refusal_hex']=remaining.hex()
                row['passed'] &= out==b'' and remaining==payload
                row['passed'] &= row['observation']['read_bytes']==row['observation']['written_bytes']==0
                return row
        finally:os.close(r);os.close(w);os.close(cancel)

    def diagnostic_alias(self,folder):
        r,w=os.pipe2(os.O_CLOEXEC)
        try:
            with Child(folder,self.elf,stdout=w,stderr=w) as c:
                os.close(w);w=None
                row,out,err=c.finish(expected=71,data=b'HIAprobe',report=False)
                captured=os.read(r,4096)
                (folder/'shared-channel.raw').write_bytes(captured)
                row['passed'] &= out==err==captured==b''
                row['diagnostic_disabled_before_data_alias_refusal']=True
                return row
        finally:
            os.close(r)
            if w is not None:os.close(w)

    def tcp_stream(self,folder):
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        peer=owned=None
        try:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            peer=socket.create_connection(listener.getsockname(),timeout=3)
            owned,origin=listener.accept();listener.close()
            address=peer.getsockname()
            with Child(folder,self.elf,stdin=owned.fileno(),stdout=owned.fileno()) as c:
                owned.close();peer.sendall(b'HIAprobe');chunks=[]
                while True:
                    raw=peer.recv(1024)
                    if not raw:break
                    chunks.append(raw)
                row,out,_=c.finish(override=b''.join(chunks))
                row['passed'] &= out==b'HIAprobe' and row['observation']['read_bytes']==row['observation']['written_bytes']==8
                row['hosted_peer_address']=list(address);row['inherited_connected_family']='AF_INET'
                row['runtime_established_or_authenticated_peer']=False
                return row
        finally:
            listener.close()
            if peer is not None:peer.close()
            if owned is not None:owned.close()

    def trace(self):
        directory=self.output/'syscall-trace';directory.mkdir();tracer=shutil.which('strace')
        row={'executable_sha256':sha256(self.elf),'counted_as_required_control_pass':False,'instrumentation':'strace ptrace'}
        if not tracer:
            row.update(status='UNKNOWN',reason='STRACE_NOT_AVAILABLE');write_json(directory/'result.json',row);return row
        fd=sealed_executable(self.elf,'reactor-trace')
        argv=[tracer,'-f','-qq','-o',str(directory/'trace.raw'),'/proc/self/fd/'+str(fd),'0','8','5000','0']
        start=time.monotonic_ns();cleanup=None
        try:
            process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(fd,),cwd=directory,env={'PATH':''},start_new_session=True,umask=0o077)
        finally:os.close(fd)
        try:stdout,stderr=process.communicate(b'HIAprobe',timeout=8);timed_out=False
        except subprocess.TimeoutExpired:
            timed_out=True;cleanup_start=time.monotonic_ns()
            try:os.killpg(process.pid,signal.SIGKILL);outcome='sent'
            except ProcessLookupError:outcome='already_exited'
            stdout,stderr=process.communicate(timeout=3)
            cleanup={'signal':'SIGKILL','signal_outcome':outcome,'complete':process.returncode is not None,
                'elapsed_ns':time.monotonic_ns()-cleanup_start}
        (directory/'stdin.raw').write_bytes(b'HIAprobe');(directory/'stdout.raw').write_bytes(stdout);(directory/'stderr.raw').write_bytes(stderr)
        trace=(directory/'trace.raw').read_bytes() if (directory/'trace.raw').exists() else b''
        row.update(argv=argv,cwd=str(directory),environment={'PATH':''},tracer_sha256=sha256(Path(tracer).read_bytes()),
            exit_code=process.returncode,timed_out=timed_out,cleanup=cleanup,elapsed_ns=time.monotonic_ns()-start,
            wall_limit_seconds=8,cleanup_limit_seconds=3,stdout_hex=stdout.hex(),stderr_hex=stderr.hex(),
            trace_bytes=len(trace),trace_sha256=sha256(trace))
        if b'Operation not permitted' in stderr and b'ptrace' in stderr.lower():
            row.update(status='UNKNOWN',reason='PTRACE_EPERM',instrumentation_attempt='FAILED')
        elif process.returncode==0 and stdout==b'HIAprobe' and len(stderr)==192 and stderr[:8]==b'HIAIO001' and trace:
            row.update(status='CAPTURED',reason='raw trace retained; semantic ISA audit separate')
        else:row.update(status='UNKNOWN',reason='TRACE_ATTEMPT_FAILED',instrumentation_attempt='FAILED')
        write_json(directory/'result.json',row);return row

    def guard(self,folder,words):
        source=guard_source(words);(folder/'policy.hepta').write_bytes(source)
        policy=self.build.stage(self.build.compiler,source,'compile-'+folder.name)
        executable,identity=self.build.pack(policy,'pack-'+folder.name)
        with Child(folder,executable) as c:
            row,out,err=c.finish(expected=78,data=b'',report=False)
            row.update(source_sha256=sha256(source),command_words=words,
                same_emitter_sha256=sha256(self.build.emitter),guard_executable=identity)
            row['passed'] &= out==err==b''
            return row

    def pack_refusal(self,folder,payload):
        result,row=run_native(self.build.emitter,payload,folder,'native-pack')
        row['passed']=not row['timed_out'] and row['exit_code']==3 and not result and not row['stderr_hex']
        return row

    def repack(self,folder):
        result,row=run_native(self.build.emitter,self.build.policy,folder,'native-repack')
        row['passed']=not row['timed_out'] and row['exit_code']==0 and not row['stderr_hex'] and result==self.elf
        return row
    def run(self):
        self.case('zero-copy',lambda p:self.ordinary(p,0))
        self.case('copy-eight',self.ordinary)
        self.case('copy-two-mib',lambda p:self.ordinary(p,2097152))
        self.case('actual-short-reads',self.short_read)
        self.case('actual-epoll-eintr',self.interrupted)
        self.case('idle-read-native-deadline',self.idle)
        self.case('partial-read-native-deadline',lambda p:self.idle(p,True))
        self.case('actual-short-write-resumption',self.output_pipe)
        self.case('blocked-write-native-deadline',lambda p:self.output_pipe(p,timeout=True))
        self.case('cancel-read-through-pipe',self.cancelled_read)
        self.case('cancel-channel-eof',lambda p:self.cancelled_read(p,eof=True))
        self.case('cancel-after-partial-write',lambda p:self.output_pipe(p,cancelled=True))
        self.case('partial-eof',self.eof)
        self.case('actual-epipe',self.epipe)
        self.case('regular-input-refusal',self.regular)
        self.case('regular-output-refusal',lambda p:self.regular(p,output=True))
        self.case('connected-stream-socket-short-write',self.socket_copy)
        self.case('socket-active-linger-refusal',lambda p:self.socket_copy(p,linger=True))
        self.case('same-context-two-operations',self.retained_context)
        self.case('same-context-original-deadline',lambda p:self.retained_context(p,deadline=True))
        self.case('caller-prepared-write-window',lambda p:self.retained_context(p,prepared=True))
        self.case('full-diagnostic-pipe-native-deadline',self.full_diagnostics)
        self.case('datagram-refusal-before-flag-change',lambda p:self.socket_refused(p,datagram=True))
        self.case('unconnected-stream-refusal-before-flag-change',self.socket_refused)
        self.case('cancel-data-object-alias-refusal',self.cancel_alias)
        self.case('diagnostic-data-object-alias-refusal',self.diagnostic_alias)
        self.case('inherited-connected-tcp-stream',self.tcp_stream)
        for name,args in [('oversize-request',['0','2097153','5000','0']),('zero-budget',['0','8','0','0']),
                          ('invalid-cancel-alias',['0','8','5000','2']),('invalid-mode',['3','8','5000','0']),
                          ('bad-argc',['0','8']),('oversize-argument',['0','8','5'*65,'0'])]:
            self.case(name,lambda p,args=args:self.args_refused(p,args))
        guards={
            'unknown-syscall':[9999,0,0,0,0,0,0,0,1],
            'pointer-before-data':[1,1,127,1,0,0,0,2,1],
            'pointer-end-overflow':[1,1,131071,8,0,0,0,2,1],
            'wrong-pointer-mask':[1,1,128,8,0,0,0,0,1],
            'epoll-event-count':[232,0,128,3,100,0,0,2,1],
            'epoll-zero-timeout':[232,0,128,2,0,0,0,2,1],
            'epoll-oversize-timeout':[232,0,128,2,101,0,0,2,1],
            'fcntl-blocking-flags':[72,0,4,0,0,0,0,0,1],
            'epoll-delete-nonnull':[233,0,2,1,128,0,0,0,1],
            'sockopt-length-mismatch':[55,0,1,3,256,264,0,24,1],
            'sockopt-unknown-option':[55,0,1,999,256,264,0,24,1],
            'epoll-create-without-cloexec':[291,0,0,0,0,0,0,0,1],
            'getpeername-length-mismatch':[52,0,128,288,0,0,0,6,1],
        }
        for name,words in guards.items():self.case('guard-'+name,lambda p,words=words:self.guard(p,words))
        self.case('empty-policy-refusal',lambda p:self.pack_refusal(p,b''))
        self.case('oversize-policy-refusal',lambda p:self.pack_refusal(p,b'\0'*524289))
        self.case('exact-native-repack',self.repack)
        contracts=Contracts(self.output/'policy-contracts',self.build.api_executable).run()
        trace=self.trace();self.build.check_pin()
        passed=sum(r['passed'] for r in self.rows)
        contracts_passed=contracts['passed_control_count']==contracts['required_control_count']
        report={'schema':'trnm.hia.stream-reactor-qualification.v1',
                'status':'STREAM_REACTOR_PASS' if passed==len(self.rows) and contracts_passed else 'STREAM_REACTOR_FAIL',
                'build':self.build_receipt,'source_inputs':self.build.source_inputs,'source_inputs_stable':True,
                'controls':self.rows,'passed_control_count':passed,'required_control_count':len(self.rows),
                'syscall_trace':trace,
                'native_policy_contracts':contracts,
                'full_node_io_gate':'OPEN','regular_file_fsync_deadlines':'OPEN','hard_realtime_guarantee':False,
                'deadline_scope':'owned nonblocking FIFO or connected stream; kernel timeout, subject to OS scheduling',
                'runtime_host_language_used':False,'hosted_test_peer_and_observer':True,
                'native_no_wakeup_deadline':{'required_cases':['idle-read-native-deadline','blocked-write-native-deadline',
                    'full-diagnostic-pipe-native-deadline','same-context-original-deadline'],
                    'passed':all(r['passed'] for r in self.rows if r['case'] in {'idle-read-native-deadline',
                        'blocked-write-native-deadline','full-diagnostic-pipe-native-deadline','same-context-original-deadline'}),
                    'external_kill_signal_or_input_counts_as_success':False},
                'prior_blocking_probe_failure':'../qualification/development-observations.json (separate source/ELF identity; retained FAIL)',
                'qualification_scope':'one private stream owner/context, actual nonblocking I/O, finite cancellation/deadline and adapter guards',
                'unqualified_requirements':['regular file/open/fsync deadlines','socket establishment and SO_ERROR after EINPROGRESS',
                    'multi-connection scheduling','authenticated peer scope','durable owner integration','hostile same-process state mutation',
                    'hard real-time guarantee','general ET_REL static linker and arbitrary policy validation']}
        write_json(self.output/'report.json',report)
        print(json.dumps({'status':report['status'],'passed':passed,'required':len(self.rows),
            'policy_contracts_passed':contracts['passed_control_count'],'policy_contracts_required':contracts['required_control_count'],
            'native_no_wakeup_deadline':report['native_no_wakeup_deadline']['passed'],
            'trace':trace['status'],'report':str(self.output/'report.json')}),flush=True)
        return 0 if passed==len(self.rows) and contracts_passed else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv);output=new_output(args.output)
    try:return Suite(output).run()
    except Exception as exc:
        write_json(output/'failure.json',{'status':'FAIL','exception':type(exc).__name__+': '+str(exc),'full_node_io_gate':'OPEN'})
        raise


if __name__=='__main__':raise SystemExit(main())
