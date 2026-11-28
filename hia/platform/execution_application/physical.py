"""Actual process, three-capability and syscall controls for the application.

The private ABI fixture calls the compiled images directly. It obtains its
Prepared bytes from the actual Settings/PNX/SHA/Ed/preparation images; no host
signature verdict, application result or State algorithm is supplied.
"""
from __future__ import annotations
import argparse,copy,ctypes,fcntl,hashlib,json,mmap,os,re,signal,stat,struct,subprocess,time,traceback
from pathlib import Path
from hia.platform.build import sealed_executable
from hia.platform.execution_state.physical import Guarded
from hia.platform.execution_state.cases import tape
from .build import Build
from .source_graph import REPOSITORY,check_sources,identity,need,bound_corpus
from .native_io import Session,command
from .qualify import Observer
from . import cases


def write_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


class DirectImages:
    def __init__(self,images,directory):
        directory.mkdir(mode=0o700);self.directory=directory;self.images={};self.maps=[];self.calls=0;self.records=0
        self.stream=(directory/'private-calls.jsonl').open('x');self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        for name in ('settings','pnx','sha','ed','prepare_bridge','core','state'):
            raw=images[name];memory=mmap.mmap(-1,len(raw),prot=3);memory.write(raw)
            address=ctypes.addressof(ctypes.c_ubyte.from_buffer(memory))
            need(self.libc.mprotect(address,len(raw),5)==0,'Cannot make actual native image RX')
            fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(address)
            self.maps.append(memory);self.images[name]=(fn,identity(raw))
    def record(self,row):
        self.stream.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');self.stream.flush();self.records+=1
    def call(self,name,a,q,p):
        self.calls+=1;before=[x.read() for x in (a,q,p)]
        row={'kind':'native-call-start','index':self.calls,'image':name,'image_identity':self.images[name][1],
             'capacities':[a.n,q.n,p.n],'input_hex':before[0].hex(),'output_before_hex':before[1].hex(),'private_before_hex':before[2].hex()}
        self.record(row);result=self.images[name][0](a.address,a.n,q.address,q.n,p.address,p.n)
        after=[x.read() for x in (a,q,p)]
        self.record({**row,'kind':'native-call-complete','return':result,'input_after_hex':after[0].hex(),'output_after_hex':after[1].hex(),'private_after_hex':after[2].hex()})
        for item in (a,q,p):item.check()
        need(before[0]==after[0],'Actual readonly native input changed')
        return result
    def adapter_write(self,target,offset,raw,reason):
        before=target.read();ctypes.memmove(target.address+offset,raw,len(raw));target.check()
        self.record({'kind':'private-adapter-fixture-write','reason':reason,'offset':offset,'bytes_hex':raw.hex(),
                     'before_hex':before.hex(),'after_hex':target.read().hex(),'production_input':False})
    def close(self):
        self.stream.close()
        for memory in self.maps:memory.close()
        return {'path':'private/private-calls.jsonl',**identity((self.directory/'private-calls.jsonl').read_bytes()),
                'records':self.records,'actual_native_calls':self.calls,'full_three_buffer_bytes':True,'private_fixtures_are_production_inputs':False}


def private_controls(images,output,passed):
    direct=DirectImages(images,output/'private');owned=[]
    def buffer(n,raw=None,readonly=False):
        value=Guarded(n,raw,readonly);owned.append(value);return value
    def put(target,offset,raw,reason):direct.adapter_write(target,offset,raw,reason)
    try:
        context_input=buffer(5,b'SDV1\0',True);context=buffer(16384);scratch=buffer(1<<20)
        extent=direct.call('settings',context_input,context,scratch)
        need(576<=extent<=16384,'Actual Settings did not produce a context')
        s=buffer(196608);put(s,0,context.read()[:extent],'Copy actual native Settings result')
        put(s,50176,struct.pack('<Q',extent),'Retain actual Settings result extent')
        q=buffer(65536);completion=bytearray(65536)
        _,corpus,_=bound_corpus();transaction=corpus[0]['transactions'][0];wire=bytes.fromhex(transaction['wire_hex'])
        raw=b'APPLY001'+struct.pack('<4Q',1,transaction['height'],len(wire),0)+wire
        a=buffer(len(raw),raw,True);result=direct.call('prepare_bridge',a,q,s);rounds=0
        while result in (0,256):
            rounds+=1;need(rounds<=32,'Unexpected native preparation continuation count')
            if result==0:
                nr,address,size=struct.unpack_from('<3Q',q.read());name={4097:'pnx',4098:'sha',4099:'ed'}.get(nr)
                need(name is not None and 131072<=address<=327680 and address-131072+size<=s.n,'Invalid actual private crypto intent')
                payload=s.read()[address-131072:address-131072+size]
                crypto_input=buffer(len(payload),payload,True);crypto_output=buffer(32)
                code=direct.call(name,crypto_input,crypto_output,scratch)
                struct.pack_into('<Q',completion,0,code);completion[128:160]=crypto_output.read()
            struct.pack_into('<Q',completion,8,struct.unpack_from('<Q',s.read(),50000)[0])
            e=buffer(65536,bytes(completion),True);result=direct.call('prepare_bridge',e,q,s)
        ready=s.read()[:65536]
        need(result==512 and struct.unpack_from('<Q',ready,50128)[0]==1 and struct.unpack_from('<Q',ready,50136)[0]!=0,'Native preparation did not yield its private ready value')
        passed('private-prepared-produced-by-actual-settings-wire-hash-and-signature-images',native_continuations=rounds)
        heap=buffer(65536);state_out=buffer(512);state_in=buffer(64,command(5)[8:],True)
        need(direct.call('state',state_in,state_out,heap)==1,'Actual private State creation failed')
        base=struct.unpack_from('<Q',state_out.read(),32)[0];need(base!=0,'Actual State handle missing')
        for name,input_bytes,work_size in [('short-prepared',ready[:50183],4096),('short-private-work',ready,4095)]:
            a=buffer(len(input_bytes),input_bytes,True);o=buffer(4096,b'\x5b'*4096);p=buffer(work_size)
            before=p.read();need(direct.call('core',a,o,p)==9 and p.read()==before and o.read()==b'\x5b'*4096,'Short private ABI mutated output/work')
            passed(name+'-refused-before-mutation')
        for offset,value,label in [(50128,0,'not-ready'),(50136,0,'zero-generation')]:
            invalid=bytearray(ready);struct.pack_into('<Q',invalid,offset,value)
            a=buffer(len(invalid),bytes(invalid),True);o=buffer(4096,b'\x5b'*4096);p=buffer(131072)
            put(p,72,struct.pack('<Q',base),'Borrow actual State handle in private caller')
            before=p.read();need(direct.call('core',a,o,p)==9 and p.read()==before and o.read()==b'\x5b'*4096,'Invalid private Prepared was accepted')
            passed('private-fixture-'+label+'-refused',production_input=False)
        a=buffer(len(ready),ready,True);o=buffer(4096,b'\x5b'*4096);small=buffer(4096)
        put(small,72,struct.pack('<Q',base),'Borrow actual State handle in private caller');before=small.read()
        need(direct.call('core',a,o,small)==3,'Private application growth request missing')
        after=small.read();expected=bytearray(before);expected[32:40]=after[32:40];expected[216:224]=after[216:224]
        need(after==bytes(expected) and struct.unpack_from('<Q',after,32)[0]>small.n and struct.unpack_from('<Q',after,216)[0]==1 and o.read()==b'\x5b'*4096,'Growth partially initialized private application')
        passed('private-growth-reservation-before-application-or-state-mutation')
        p=buffer(131072);put(p,72,struct.pack('<Q',base),'Borrow actual State handle in private caller')
        need(direct.call('core',a,o,p)==7 and o.read()==b'\x5b'*4096,'Actual Prepared initialization did not yield private continuation')
        need(struct.unpack_from('<Q',p.read(),256)[0]==struct.unpack_from('<Q',ready,50136)[0],'Prepared generation changed during private initialization')
        passed('actual-prepared-private-initialization-keeps-generation-and-readonly-input')
        exhausted=buffer(196608);put(exhausted,0,context.read()[:extent],'Copy actual native Settings result')
        put(exhausted,50176,struct.pack('<Q',extent),'Retain actual Settings extent')
        put(exhausted,51008,struct.pack('<Q',(1<<64)-1),'Explicit private non-wrapping generation fixture')
        before=exhausted.read();output_before=q.read();a=buffer(len(raw),raw,True)
        need(direct.call('prepare_bridge',a,q,exhausted)==514 and exhausted.read()==before and q.read()==output_before,'Private generation exhaustion mutated or wrapped')
        passed('private-generation-exhaustion-before-new-ready-or-mutation',production_input=False)
        close=buffer(64,command(26)[8:],True)
        need(direct.call('state',close,state_out,heap)==4 and heap.read()==bytes(heap.n),'Actual private State close did not erase')
        passed('private-state-close-erases-owned-heap')
    finally:
        for item in reversed(owned):item.close()
        receipt=direct.close()
    return receipt


def stdio_refusal(elf,output,kind):
    output.mkdir(mode=0o700);pipes=[os.pipe() for _ in range(3)];all_fds=[fd for pair in pipes for fd in pair]
    child=[pipes[0][0],pipes[1][1],pipes[2][1]];parent=[pipes[0][1],pipes[1][0],pipes[2][0]];regular=None
    if kind in ('regular-stdin','regular-stdout','regular-stderr'):
        regular=output/'unchanged-file';regular.write_bytes(b'unchanged descriptor refusal\0\xff')
        index={'regular-stdin':0,'regular-stdout':1,'regular-stderr':2}[kind];fd=os.open(regular,os.O_RDONLY if index==0 else os.O_WRONLY);all_fds.append(fd);child[index]=fd
    elif kind=='stdout-stderr-alias':child[2]=child[1]
    elif kind=='stdin-write-end':child[0]=pipes[0][1]
    elif kind=='stdout-read-end':child[1]=pipes[1][0]
    elif kind.startswith('nonblocking-'):
        index={'nonblocking-stdin':0,'nonblocking-stdout':1,'nonblocking-stderr':2}[kind];os.set_blocking(child[index],False)
    else:raise ValueError(kind)
    metadata=[{'mode':os.fstat(fd).st_mode,'dev':os.fstat(fd).st_dev,'ino':os.fstat(fd).st_ino,'flags':fcntl.fcntl(fd,fcntl.F_GETFL)} for fd in child]
    before=None if regular is None else regular.read_bytes();fd=sealed_executable(elf,'application-stdio-refusal');process=None;cleanup=None
    started=time.monotonic_ns()
    try:
        process=subprocess.Popen(['/proc/self/fd/'+str(fd)],stdin=child[0],stdout=child[1],stderr=child[2],pass_fds=(fd,),env={'PATH':''},cwd=output,start_new_session=True,umask=0o077)
        for item in set(all_fds)-set(parent):os.close(item)
        all_fds=list(parent);os.close(parent[0]);all_fds.remove(parent[0]);process.wait(timeout=3)
        observed=[]
        for pipe in parent[1:]:
            os.set_blocking(pipe,False)
            try:data=os.read(pipe,65536)
            except BlockingIOError:data=b''
            observed.append(data)
        (output/'stdout.raw').write_bytes(observed[0]);(output/'stderr.raw').write_bytes(observed[1])
        need(process.returncode==64 and observed==[b'',b''] and (regular is None or regular.read_bytes()==before),'Invalid stdio reached an output or modified its file')
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3);cleanup='SIGKILL'
        for item in set(all_fds):
            try:os.close(item)
            except OSError:pass
        os.close(fd)
        receipt={'kind':kind,'exit_code':None if process is None else process.returncode,'actual_descriptors':metadata,'cleanup':cleanup,'elapsed_ns':time.monotonic_ns()-started,'executable':identity(elf),'unchanged_file':regular is None or regular.read_bytes()==before}
        write_json(output/'receipt.json',receipt)
    return receipt


def wait_exit(session):
    session.process.wait(timeout=max(.01,min(3.,session.deadline-time.monotonic())))


def malformed(session,raw,expected):
    try:session.exchange(raw);raise AssertionError('Malformed public frame produced a response')
    except (RuntimeError,BrokenPipeError):pass
    wait_exit(session);receipt=session.finish(allow_failure=True)
    need(receipt['exit_code']==expected and receipt['cleanup'] is None and b'APRESULT' not in (session.output/'stdout.raw').read_bytes(),'Malformed public input produced a Patch or wrong exit')
    return receipt


def open_callback(session):
    observer=Observer(session);handle=observer.state(5)['result']
    for key,value in cases.base().items():observer.put(handle,key.encode(),tape(value))
    raw=cases.wire(1,cases.public(1)+cases.u64(10))
    frame=b'APPLY001'+struct.pack('<4Q',handle,10,len(raw),1)+raw
    reply=session.exchange(struct.pack('<Q',len(frame))+frame)
    need(reply[:8]==b'APCALL01' and struct.unpack_from('<Q',reply,8)[0]==1,'Actual account callback not reached')
    return handle


def qualify(output,require_trace=False):
    output=output.absolute();need(output.resolve()==output and not output.exists() and REPOSITORY not in output.parents,'Fresh physical output outside repository required')
    output.mkdir(mode=0o700);builder=None;controls=[];sessions=[];private=[];primary=None;cleanup=[];source_errors=[];start=time.monotonic_ns()
    def passed(name,**details):controls.append({'name':name,'status':'PASS',**details});print(json.dumps({'physical_passed':name,'controls':len(controls)}),flush=True)
    def session(name,**kwargs):
        value=Session(builder.executable,output/name,**kwargs);sessions.append(value);return value
    try:
        builder=Build(output/'build');builder.build()
        for kind in ('regular-stdin','regular-stdout','regular-stderr','stdout-stderr-alias','stdin-write-end','stdout-read-end','nonblocking-stdin','nonblocking-stdout','nonblocking-stderr'):
            passed('actual-stdio-'+kind,receipt=stdio_refusal(builder.executable,output/('stdio-'+kind),kind))
        for name,raw,code in [('unknown-namespace',struct.pack('<Q',8)+b'UNKNOWN1',64),('external-prepared-import',struct.pack('<Q',16)+b'MPVALUE1'+bytes(8),64),('short-application',struct.pack('<Q',8)+b'APPLY001',64),('application-length-disagreement',struct.pack('<Q',40)+b'APPLY001'+struct.pack('<4Q',1,10,1,0),73),('invalid-callback-flag',struct.pack('<Q',40)+b'APPLY001'+struct.pack('<4Q',1,10,0,2),73)]:
            s=session(name);passed('actual-'+name+'-refused',process=malformed(s,raw,code))
        for name,ack in [('bad-magic',b'NOTACK00'+struct.pack('<QQ',1,0)),('stale-ordinal',b'APGO0001'+struct.pack('<QQ',2,0)),('invalid-action',b'APGO0001'+struct.pack('<QQ',1,2))]:
            s=session('callback-'+name);open_callback(s);passed('actual-account-callback-'+name+'-refused',process=malformed(s,ack,64))
        s=session('callback-truncated');open_callback(s);partial=b'APGO0001'+struct.pack('<Q',1)
        s.stdin_log.write(partial);s.attempted+=len(partial);s.written+=os.write(s.process.stdin.fileno(),partial);s.process.stdin.close();wait_exit(s)
        receipt=s.finish(allow_failure=True);need(receipt['exit_code']==74 and receipt['cleanup'] is None,'Truncated callback was not an actual I/O failure')
        passed('actual-truncated-account-callback-refused',process=receipt)
        s=session('abrupt-callback');old_handle=open_callback(s);os.killpg(s.process.pid,signal.SIGKILL);wait_exit(s);receipt=s.finish(allow_failure=True)
        need(receipt['exit_code']==-signal.SIGKILL,'Abrupt death not observed');passed('actual-sigkill-at-live-account-callback',process=receipt,clean_shutdown_claim=False)
        s=session('fresh-after-kill');stats=s.state(0);stale=s.state(9,old_handle,key=b'account:old')
        need(stats['live_objects']==0 and stats['live_blocks']==0 and stale['status']==65,'New process reused dead owner state')
        s.state(26);passed('actual-fresh-owner-after-abrupt-death',process=s.finish())
        s=session('closed-output');s.selector.unregister(s.process.stdout);s.process.stdout.close()
        raw=command(0);s.stdin_log.write(raw);s.attempted+=len(raw);s.written+=os.write(s.process.stdin.fileno(),raw);wait_exit(s)
        receipt=s.finish(allow_failure=True);need(receipt['exit_code']==74 and receipt['cleanup'] is None,'EPIPE did not become an observed I/O failure')
        passed('actual-closed-output-is-epipe-not-sigpipe-or-success',process=receipt)
        private.append(private_controls(builder.images,output,passed))
        s=session('large-value',trace=require_trace)
        base=cases.base();base[cases.account(0)]['unknown']={'ascii':'\u0000text','large':'x'*((1<<20)+1)}
        case=cases.history('physical-full-unknown-large-value',base,[cases.tx(1,cases.public(1)+cases.u64(10),root=True,expect='OK')])
        row=Observer(s).history(case);need(row['observations'][0]['root']['error']=='LIMIT','Original root limit was not deferred until root')
        s.state(26);receipt=s.finish();details={'process':receipt,'complete_observation':row,'new_value_or_state_limit':False}
        if require_trace:
            trace=(s.output/'syscalls.raw').read_text();moves=re.findall(r'mremap\((0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*MREMAP_MAYMOVE\)\s*=\s*(0x[0-9a-f]+)',trace)
            need(moves and any(old!=new for old,_,__,new in moves),'No actual relocating mremap observed')
            need('PROT_WRITE|PROT_EXEC' not in trace and 'PROT_EXEC|PROT_WRITE' not in trace,'Writable executable runtime mapping')
            need(re.search(r'mprotect\([^\n]*PROT_READ\)\s*=\s*0',trace) and re.search(r'munmap\([^\n]*\)\s*=\s*0',trace),'Missing actual captured-input protection or teardown')
            details.update(actual_relocations=[list(m) for m in moves],trace=identity((s.output/'syscalls.raw').read_bytes()))
        passed('actual-dynamic-unknown-value-through-application-and-full-state',**details)
        if require_trace:
            s=session('actual-enomem',trace=True,inject_mremap=True)
            try:s.state(1,data=tape('x'*5000));raise AssertionError('Injected native allocation should fail')
            except (RuntimeError,BrokenPipeError):pass
            wait_exit(s);receipt=s.finish(allow_failure=True);trace=(s.output/'syscalls.raw').read_text()
            need(receipt['exit_code']==72 and receipt['commands']==0 and receipt['cleanup'] is None,'Actual ENOMEM did not fail before an owned result')
            need(re.search(r'mremap\([^\n]*\)\s*=\s*-1 ENOMEM[^\n]*INJECTED',trace),'Actual kernel errno injection absent')
            passed('actual-kernel-enomem-without-partial-owned-result',process=receipt,explicit_errno_fixture=True,physical_memory_exhaustion_claim=False)
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        for s in sessions:
            if not s.finished:
                try:s.finish(allow_failure=True)
                except BaseException as error:cleanup.append({'path':str(s.output),'error':repr(error)})
        if builder is not None:
            for name,call in [('sources',lambda:check_sources(builder.inputs,builder.original)),('compiler',lambda:builder.pinned.check_pin() if builder.pinned else None)]:
                try:call()
                except BaseException as error:source_errors.append({'stage':name,'error':repr(error)})
        report={'schema':'trnm.execution-application-physical.v1','status':'PASS' if primary is None and not cleanup and not source_errors else 'FAIL',
            'build':None if builder is None else builder.report,'controls':controls,'controls_total':len(controls),'private_journals':private,
            'actual_processes':len(sessions)+sum(c['name'].startswith('actual-stdio-') for c in controls),'elapsed_ns':time.monotonic_ns()-start,
            'verification':{'primary_error':primary,'cleanup_errors':cleanup,'source_after':{'status':'PASS' if not source_errors else 'FAIL','errors':source_errors}},
            'trace_required':require_trace,'trace_status':'PASS' if require_trace and primary is None and not cleanup and not source_errors else 'FAIL' if require_trace else 'NOT_RUN',
            'private_fixtures_are_production_inputs':False,'runtime_host_proxy':False,'complete_node':False,'original_rust':'NOT_RUN'}
        write_json(output/'report.json',report);print(json.dumps({k:report[k] for k in ('status','controls_total','actual_processes','trace_status','elapsed_ns','verification')}),flush=True)
    return report


def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--require-trace',action='store_true');a=p.parse_args()
    return int(qualify(a.output,a.require_trace)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
