"""Actual owner lifetime, resource and private ABI controls. No Rust emulator."""
from __future__ import annotations
import argparse,ctypes,json,mmap,os,re,struct,time,traceback
from pathlib import Path
from .build import Build,check_sources,identity
from .cases import tape
from .native_io import Session,command,decode


class Guarded:
    def __init__(self,n,raw=None,readonly=False):
        self.n=n;page=mmap.PAGESIZE;self.span=((n+64+page-1)//page)*page;self.memory=mmap.mmap(-1,self.span+page*2,prot=3);self.base=ctypes.addressof(ctypes.c_ubyte.from_buffer(self.memory));self.address=self.base+page;self.libc=ctypes.CDLL(None,use_errno=True);self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        if self.libc.mprotect(self.base,page,0) or self.libc.mprotect(self.address+self.span,page,0):raise OSError(ctypes.get_errno(),'guard')
        if raw is not None:ctypes.memmove(self.address,raw,n)
        ctypes.memset(self.address+n,0xa7,self.span-n)
        if readonly and self.libc.mprotect(self.address,self.span,1):raise OSError(ctypes.get_errno(),'read-only')
    def read(self):return ctypes.string_at(self.address,self.n)
    def check(self):
        if ctypes.string_at(self.address+self.n,self.span-self.n)!=b'\xa7'*(self.span-self.n):raise AssertionError('Actual native ABI tail overwritten')
    def close(self):self.memory.close()


class PrivateCalls:
    def __init__(self,image,journal):
        self.code=mmap.mmap(-1,len(image),prot=3);self.code.write(image);ptr=ctypes.addressof(ctypes.c_ubyte.from_buffer(self.code));libc=ctypes.CDLL(None,use_errno=True);libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        if libc.mprotect(ptr,len(image),5):raise OSError(ctypes.get_errno(),'RX')
        self.fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(ptr);self.heap=Guarded(65536);self.rows=[];self.journal=journal;self.stream=journal.open('x');self.fixture_writes=0;self.records=0
    def record(self,row):
        self.stream.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');self.stream.flush();self.records+=1
    def invoke(self,raw,cap=512,hcap=None):
        a=Guarded(len(raw),raw,True);o=Guarded(cap,b'\x5b'*cap)
        try:
            before=self.heap.read();index=len(self.rows)+1
            started={'kind':'native-call-start','index':index,'input':identity(raw),'input_hex':raw.hex(),'output_capacity':cap,'heap_capacity':self.heap.n if hcap is None else hcap,'heap_before':identity(before),'heap_before_hex':before.hex(),'output_before_hex':o.read().hex()};self.record(started)
            result=self.fn(a.address,a.n,o.address,o.n,self.heap.address,self.heap.n if hcap is None else hcap)
            output=o.read();after=self.heap.read();row={**started,'kind':'native-call-complete','return':result,'input_after_hex':a.read().hex(),'output':identity(output),'output_hex':output.hex(),'heap_after':identity(after),'heap_after_hex':after.hex()};self.rows.append(row);self.record(row)
            a.check();o.check();self.heap.check()
            if a.read()!=raw:raise AssertionError('Actual readonly input changed')
            return result,output
        finally:a.close();o.close()
    def inject_counter(self,offset,value):
        if offset not in (48,64):raise ValueError('Only the two declared private fixture counters are injectable')
        before=self.heap.read();raw=struct.pack('<Q',value);ctypes.memmove(self.heap.address+offset,raw,8);after=self.heap.read();self.fixture_writes+=1
        self.record({'kind':'private-fixture-counter-write','offset':offset,'bytes_hex':raw.hex(),'native_calls_before':len(self.rows),'heap_before_hex':before.hex(),'heap_after_hex':after.hex(),'production_input':False})
    def call(self,op,a=0,b=0,arg=0,key=b'',data=b'',status=0):
        result,out=self.invoke(command(op,a,b,arg,key,data)[8:]);expected=4 if op==26 else 1
        if result!=expected:raise AssertionError(('private-return',op,result,expected))
        n=64+struct.unpack_from('<Q',out,40)[0];decoded=decode(out[:n])
        if decoded['status']!=status or out[n:]!=b'\x5b'*(len(out)-n):raise AssertionError(('private-status',op,decoded,status))
        return decoded
    def close(self):self.stream.close();self.heap.close();self.code.close()
    def receipt(self):return {'file':self.journal.name,**identity(self.journal.read_bytes()),'records':self.records,'completed_native_calls':len(self.rows),'private_fixture_writes':self.fixture_writes,'full_input_output_and_private_heap_bytes':True}


def qualify(output:Path):
    output=output.absolute();output.mkdir(mode=0o700);builder=None;controls=[];primary=None;source_errors=[];started=time.monotonic_ns();native_calls=0;private_journals=[]
    def passed(name,**details):controls.append({'name':name,'status':'PASS',**details})
    try:
        builder=Build(output/'build');built=builder.build()
        session=Session(builder.executable,output/'lifetimes')
        try:
            v=session.request(1,data=tape(7))['result'];copy=session.request(2,v)['result'];s=session.request(5)['result'];session.request(8,s,v,key=b'k');gone=session.request(3,v);assert gone['status']==65
            view=session.request(13,s)['result'];held=session.request(9,s,key=b'k')['result']
            for op in (7,10,12):assert session.request(op,s,key=b'k' if op==10 else b'')['status']==66
            assert session.request(8,s,held,key=b'k')['status']==66
            assert session.request(3,held)['data_hex']==tape(7).hex()
            assert session.request(9,copy,key=b'k')['status']==68
            patch=session.request(18,view,arg=91,data=b'\0receipt')['result'];assert session.request(14,view,key=b'k')['status']==65
            clone=session.request(19,patch)['result'];guard=session.request(13,s)['result'];before=session.request(23,patch)['data_hex'];assert session.request(21,patch,s)['status']==66;assert session.request(23,patch)['data_hex']==before
            session.request(17,guard);session.request(21,patch,s);assert session.request(20,patch,s)['status']==65
            assert session.request(20,clone,s)['result']==1
            session.request(4,copy);assert session.request(3,held)['data_hex']==tape(7).hex();session.request(22,clone);session.request(26)
        finally:receipt=session.finish(allow_failure=not session.closed)
        assert receipt['exit_code']==0 and receipt['clean_close'];native_calls+=receipt['commands'];passed('actual-process-consumption-borrow-clone-and-stale-handles',process=receipt)
        calls=PrivateCalls(builder.images['owner'],output/'private-abi-calls.jsonl')
        try:
            original=calls.heap.read()
            for cap,hcap in ((63,65536),(64,4095)):
                code,out=calls.invoke(command(5)[8:],cap=cap,hcap=hcap);assert code==6 and out==b'\x5b'*cap and calls.heap.read()==original
            passed('guarded-short-output-and-private-arena-no-mutation',actual_calls=2)
            state=calls.call(5)['result'];before=calls.heap.read();raw=command(1,data=tape('x'*3000))[8:];code,out=calls.invoke(raw)
            after=calls.heap.read();assert code==2 and out==b'\x5b'*len(out);assert before[:80]==after[:80] and before[88:]==after[88:] and struct.unpack_from('<Q',after,80)[0]>65536
            passed('heap-reservation-before-any-object-or-sequence-mutation',requested=struct.unpack_from('<Q',after,80)[0])
            value=calls.call(1,data=tape('x'*100))['result'];before=calls.heap.read();code,out=calls.invoke(command(3,value)[8:],cap=64);after=calls.heap.read();assert code==3 and out==b'\x5b'*64;assert before[:88]==after[:88] and before[96:]==after[96:]
            passed('output-reservation-before-object-mutation',requested=struct.unpack_from('<Q',after,88)[0])
            valid=tape({'a':[1,'x']})
            for n in range(len(valid)):
                row=calls.call(1,data=valid[:n],status=64)
                assert row['live_objects']==2
            calls.call(26);assert calls.heap.read()==bytes(calls.heap.n);passed('every-value-truncation-preserves-live-owner-and-close-erases-all',truncations=len(valid))
            native_calls+=len(calls.rows)
        finally:calls.close();private_journals.append(calls.receipt())
        calls=PrivateCalls(builder.images['owner'],output/'private-serial-calls.jsonl')
        try:
            calls.call(0);calls.inject_counter(48,(1<<64)-1)
            value=calls.call(1,data=tape(-0.0))['result'];assert value==(1<<64)-1;calls.call(1,data=tape(None),status=67);assert calls.call(3,value)['data_hex']==tape(-0.0).hex();calls.call(26);assert calls.heap.read()==bytes(calls.heap.n)
            passed('private-fixture-last-u64-serial-never-wraps-or-revives',fixture_private_counter=True,actual_calls=len(calls.rows));native_calls+=len(calls.rows)
        finally:calls.close();private_journals.append(calls.receipt())
        calls=PrivateCalls(builder.images['owner'],output/'private-sequence-calls.jsonl')
        try:
            calls.call(5);calls.inject_counter(64,(1<<64)-1);before=calls.heap.read();code,out=calls.invoke(command(1,data=tape(1))[8:]);assert code==6 and calls.heap.read()==before and out==b'\x5b'*len(out)
            passed('private-fixture-sequence-exhaustion-before-mutation',fixture_private_counter=True,actual_calls=len(calls.rows));native_calls+=len(calls.rows)
        finally:calls.close();private_journals.append(calls.receipt())
        session=Session(builder.executable,output/'real-relocation',trace=True)
        try:
            s=session.request(5)['result'];v=session.request(1,data=tape('z'*((1<<20)+1)))['result'];session.request(8,s,v,key=b'large');snapshot=session.request(6,s)['result'];got=session.request(9,snapshot,key=b'large')['result'];assert session.request(3,got)['data_hex']==tape('z'*((1<<20)+1)).hex();assert session.request(24,s)['status']==69;session.request(26)
        finally:receipt=session.finish(allow_failure=not session.closed)
        assert receipt['exit_code']==0;trace=(session.output/'syscalls.raw').read_text();moves=re.findall(r'mremap\((0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*MREMAP_MAYMOVE\)\s*=\s*(0x[0-9a-f]+)',trace);assert moves and any(old!=new for old,oldn,newn,new in moves)
        passed('actual-mremap-relocation-retains-full-value-and-owner-state',process=receipt,actual_mremaps=[list(m) for m in moves]);native_calls+=receipt['commands']
        session=Session(builder.executable,output/'actual-enomem',trace=True,inject_mremap=True)
        try:
            session.request(5)
            try:session.request(1,data=tape('x'*3000));raise AssertionError('Expected actual allocation refusal')
            except (RuntimeError,BrokenPipeError):pass
        finally:receipt=session.finish(allow_failure=True)
        trace=(session.output/'syscalls.raw').read_text();stderr=(session.output/'stderr.raw').read_bytes()
        assert receipt['exit_code']==72 and receipt['commands']==1 and len(stderr)==16 and stderr[:8]==b'SVPFAIL1' and struct.unpack_from('<Q',stderr,8)[0]==72
        assert re.search(r'mremap\([^\n]*\)\s*=\s*-1 ENOMEM[^\n]*INJECTED',trace)
        passed('actual-kernel-enomem-refusal-without-false-success-or-limit',process=receipt,explicit_kernel_fault_fixture=True);native_calls+=receipt['commands']
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if builder is not None:
            for name,check in (('compiler',builder.pinned.check_pin),('sources',lambda:check_sources(builder.inputs,builder.original))):
                try:check()
                except BaseException as error:source_errors.append({'stage':name,'error':repr(error)})
        report={'schema':'trnm.execution-state-physical.v1','status':'PASS' if primary is None and not source_errors else 'FAIL','build':None if builder is None else getattr(builder,'report',None),'controls':controls,'controls_total':len(controls),'actual_native_calls':native_calls,'private_call_journals':private_journals,'elapsed_ns':time.monotonic_ns()-started,'primary_error':primary,'source_after':{'status':'PASS' if not source_errors else 'FAIL','errors':source_errors},'private_counter_fixtures_are_production_inputs':False,'kernel_enomem_fixture_is_real_host_memory_exhaustion_claim':False,'original_rust':'NOT_RUN'}
        (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('status','controls_total','actual_native_calls','elapsed_ns','primary_error','source_after')},sort_keys=True),flush=True)
    return report


def main():
    if not __debug__:raise RuntimeError('Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();return int(qualify(a.output)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
