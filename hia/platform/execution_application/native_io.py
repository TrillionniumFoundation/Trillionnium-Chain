"""Actual pipe observations; preparation, application and State run only in HIA."""
from pathlib import Path
import json,os,selectors,struct,time
from hia.platform.execution_state.native_io import Session as StateSession,command,decode
from hia.platform.execution_state.build import identity
from hia.platform.execution_state.rust_oracle import need,load_json
from hia.platform.execution_prepare.native_io import parse_result as preparation_result

def parse_context(frame):
    need(frame[:8]==b'APREADY1' and len(frame)>=16,'Invalid application readiness')
    size=struct.unpack_from('<Q',frame,8)[0];s=frame[16:]
    need(size==len(s) and 576<=size<=16384,'Invalid actual context extent')
    need(s[:4]==b'SDO1' and struct.unpack_from('<I',s,4)[0]==size and s[8:16]==bytes(8),'Invalid native SDO1')
    count,rows,pl,ml,sl=struct.unpack_from('<5I',s,448)
    need(count==3 and rows==7 and 576+pl+ml+sl==size and s[468:480]==bytes(12),'Invalid context counts or reserved bytes')
    need(struct.unpack_from('<Q',s,16)[0]==1800000000,'Unexpected fixed-default timestamp')
    params=load_json(s[576:576+pl]);model=load_json(s[576+pl:576+pl+ml])
    need(type(params) is dict and type(model) is dict,'Invalid context JSON objects')
    return {'network':s[24:56].hex(),'parameters':s[56:88].hex(),'family':s[88:120].hex(),'plan':s[120:152].hex(),
        'params':params,'fees':list(struct.unpack_from('<25Q',s,248)),
        'evaluators':[s[480+32*i:512+32*i].hex() for i in range(3)],'snapshot':identity(s),'snapshot_hex':s.hex()}

class Session(StateSession):
    def __init__(self,elf,output,**kwargs):
        super().__init__(elf,output,**kwargs)
        self.frames=[];self.last_state_sequence=0
        try:
            self.ready=self.exchange(b'')
            if self.ready[:8]!=b'APREADY1' or len(self.ready)!=16+struct.unpack_from('<Q',self.ready,8)[0]:raise ValueError('Bad actual native context')
            self.context=self.ready[16:]
            if self.context[:4]!=b'SDO1' or struct.unpack_from('<I',self.context,4)[0]!=len(self.context):raise ValueError('Bad actual native SDO1')
            self.context_fields=parse_context(self.ready)
        except BaseException:
            self.finish(allow_failure=True)
            raise
    def exchange(self,raw):
        if self.finished or self.closed:raise RuntimeError('Closed native session')
        self.attempted+=len(raw);self.stdin_log.write(raw);offset=0
        if raw:self.selector.register(self.process.stdin,selectors.EVENT_WRITE,'stdin')
        start=time.monotonic_ns()
        try:
            while True:
                if offset==len(raw) and len(self.buffer)>=8:
                    size=struct.unpack_from('<Q',self.buffer)[0]
                    if size<16 or size>1<<31:raise ValueError('Bad native response extent')
                    if len(self.buffer)>=8+size:
                        response=bytes(self.buffer[8:8+size]);del self.buffer[:8+size]
                        self.frames.append({'sent_hex':raw.hex(),'received_hex':response.hex(),'elapsed_ns':time.monotonic_ns()-start})
                        return response
                remaining=self.deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Actual child budget exceeded')
                events=self.selector.select(min(1.,remaining))
                if not events and self.process.poll() is not None:raise RuntimeError('Native exited early: '+str(self.process.returncode))
                for key,mask in events:
                    if key.data=='stdin':
                        try:count=os.write(key.fileobj.fileno(),raw[offset:offset+65536])
                        except BlockingIOError:continue
                        if count<=0:raise RuntimeError('Native stdin did not progress')
                        offset+=count;self.written+=count
                        if offset==len(raw):self.selector.unregister(key.fileobj)
                    else:self._read_ready(key)
                if self.process.poll() is not None and not self.selector.get_map() and len(self.buffer)<8:raise RuntimeError('Native exited without complete frame')
        except BaseException as error:
            self.failure=repr(error)
            try:self.selector.unregister(self.process.stdin)
            except KeyError:pass
            raise
    def state(self,op,a=0,b=0,arg=0,key=b'',data=b''):
        raw=command(op,a,b,arg,key,data);response=self.exchange(raw);row=decode(response)
        if row['op']!=op or row['sequence']<=self.last_state_sequence:raise ValueError('Native state sequence/op mismatch')
        self.last_state_sequence=row['sequence'];self.commands.append(row)
        if op==26 and row['status']==0:self.closed=True
        return row
    def application(self,base,raw,height=10,callback=False,cancel_at=None):
        frame=b'APPLY001'+struct.pack('<4Q',base,height,len(raw),int(callback))+raw
        reply=self.exchange(struct.pack('<Q',len(frame))+frame);callbacks=[]
        while reply[:8]==b'APCALL01':
            sequence,size=struct.unpack_from('<QQ',reply,8)
            if len(reply)!=24+size or sequence!=len(callbacks)+1:raise ValueError('Malformed actual callback')
            callbacks.append(reply[24:].hex())
            ack=b'APGO0001'+struct.pack('<QQ',sequence,int(sequence==cancel_at))
            reply=self.exchange(ack)
        if reply[:8]==b'APRESULT':
            if len(reply)<96:raise ValueError('Truncated native application result')
            outcome,error,patch,fee,account_calls,receipt_len,error_len,generation,height,tag,reserved=struct.unpack_from('<11Q',reply,8)
            if reserved or len(reply)!=96+receipt_len+error_len:raise ValueError('Malformed native application result')
            need(outcome in (1,2,3,4,5) and ((outcome==1)==(error==0)),'Application outcome/error disagreement')
            need((outcome==1)==(patch!=0) and (outcome==1 or receipt_len==0),'Invalid private Patch/receipt transfer')
            need(outcome!=3 or error==254,'Panic classification differs')
            need(outcome!=4 or error==253,'Callback classification differs')
            need(outcome!=5 or error==255,'Invariant classification differs')
            need(generation!=0 and account_calls==(len(callbacks) if callback else account_calls),'Callback count/generation differs')
            result={'kind':'application','outcome':outcome,'error':error,'patch':patch,'fee':fee,'account_calls':account_calls,
              'receipt_hex':reply[96:96+receipt_len].hex(),'error_hex':reply[96+receipt_len:].hex(),
              'generation':generation,'height':height,'tag':tag,'callbacks':callbacks,'raw_hex':reply.hex()}
        elif reply[:8]==b'MPRESULT':
            if len(reply)!=96:raise ValueError('Malformed preparation error')
            preparation=preparation_result(reply)
            need(preparation['code']!=0 and not callbacks,'Preparation rejection contains a private value or application callback')
            result={'kind':'preparation','fields':list(struct.unpack('<11Q',reply[8:])),'callbacks':callbacks,'raw_hex':reply.hex()}
        else:raise ValueError('Unknown native application frame '+reply[:32].hex())
        self.commands.append(result);return result
    def finish(self,**kwargs):
        (self.output/'observed-frames.json').write_text(json.dumps(self.frames,sort_keys=True,indent=2)+'\n')
        return super().finish(**kwargs)


class ReplaySession(Session):
    """Read actual pipes and reproduce only the source-defined observer protocol.

    No State, signature, fee, application or Patch outcome is computed here.
    Every next request must equal the bytes actually sent to the native process.
    """
    def __init__(self,stdin,stdout):
        self.input=stdin;self.output_bytes=stdout;self.input_at=0;self.output_at=0
        self.closed=False;self.finished=False;self.commands=[];self.frames=[];self.last_state_sequence=0
        self.ready=self.exchange(b'');self.context=self.ready[16:];self.context_fields=parse_context(self.ready)
    def exchange(self,raw):
        need(not self.finished and not self.closed,'Exchange after native close')
        end=self.input_at+len(raw)
        need(end<=len(self.input) and self.input[self.input_at:end]==raw,'Actual native stdin differs from source-defined protocol')
        self.input_at=end;need(len(self.output_bytes)-self.output_at>=8,'Truncated actual native length')
        size=struct.unpack_from('<Q',self.output_bytes,self.output_at)[0];start=self.output_at+8
        need(size>=16 and size<=len(self.output_bytes)-start,'Truncated actual native frame')
        response=self.output_bytes[start:start+size];self.output_at=start+size
        self.frames.append({'sent_hex':raw.hex(),'received_hex':response.hex()});return response
    def finish(self,**kwargs):
        need(self.closed and self.input_at==len(self.input) and self.output_at==len(self.output_bytes),'Extra or missing actual native pipe bytes')
        self.finished=True
