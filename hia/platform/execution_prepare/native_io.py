"""Bounded transport observer for the actual native preparation process."""
from __future__ import annotations
import hashlib,json,os,selectors,struct,subprocess,time
from pathlib import Path

LIMIT_SECONDS=240
CLEANUP_SECONDS=3
U64=(1<<64)-1
NAMES={0:None,1:"ENCODING",2:"SERVICE_CONTRACT_PROFILE",3:"WORK_TASK_PROFILE",
       4:"PUBLIC_EVAL_PROFILE",5:"FACTOR_PROFILE",6:"EVOLUTION_PROFILE",
       7:"NETWORK",8:"EXPIRED",9:"SIGNATURE"}

def need(condition,message):
    if not condition:raise ValueError(message)

def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def words(raw):
    need(len(raw)%8==0,"Partial observation word")
    return struct.unpack("<"+"Q"*(len(raw)//8),raw)

def magic(value):
    return int.from_bytes(value,"little")

def frame(op,seq,*,height=0,body_len=0,generation=0):
    return struct.pack("<8Q",magic(b"MPREQ001"),op,seq,height,body_len,generation,0,0)

def parse_context(raw):
    need(len(raw)>=640 and raw[:8]==b"MPREADY1","Open framing")
    h=words(raw[:64]);s=raw[64:]
    need(h[1]==len(raw) and h[2]==len(s) and h[3:]==(0,)*5,"Complete open header")
    need(s[:4]==b"SDO1" and struct.unpack_from("<I",s,4)[0]==len(s),"SDO1 extent")
    need(s[8:16]==bytes(8) and s[468:480]==bytes(12),"SDO1 reserved")
    count,state_count,pl,ml,sl=struct.unpack_from("<5I",s,448)
    need(count==3 and state_count==7 and 576+pl+ml+sl==len(s),"SDO1 closed context")
    need(struct.unpack_from("<Q",s,16)[0]==1800000000,"Default timestamp")
    params=json.loads(s[576:576+pl]);model=json.loads(s[576+pl:576+pl+ml])
    need(isinstance(params,dict) and isinstance(model,dict),"Config objects")
    return {"raw_hex":raw.hex(),"snapshot_hex":s.hex(),"snapshot_identity":identity(s),
      "network_hex":s[24:56].hex(),"parameters_hex":s[56:88].hex(),
      "family_hex":s[88:120].hex(),"plan_hex":s[120:152].hex(),"genesis_hex":s[152:184].hex(),
      "root_hex":s[184:216].hex(),"task_hex":s[216:248].hex(),
      "timestamp":struct.unpack_from("<Q",s,16)[0],"params":params,"model":model,
      "base_fees":list(struct.unpack_from("<25Q",s,248)),"evaluators_hex":s[480:576].hex()}

def parse_result(raw):
    need(len(raw)==96 and raw[:8]==b"MPRESULT","Result framing")
    h=words(raw)
    need(h[2] in NAMES and h[3] in (0,1) and h[6]<=4 and h[7]<=5 and h[11]==0,"Result fields")
    if h[2]==0:
        need(h[3]==1 and h[6]==0 and h[7]==0 and h[8]==h[1] and h[10]==h[4]
             and h[4]==159+h[9] and h[4]<=2048,"Successful result complete")
    else:
        need(h[8:11]==(0,0,0),"Rejected result has no private value")
        need((h[2]==1)==(h[6]!=0) and (h[2]==9)==(h[7]!=0),"Error provenance")
        need(h[3]==int(h[2]==9),"Signature attempt order")
    return {"raw_hex":raw.hex(),"sequence":h[1],"code":h[2],"error":NAMES[h[2]],
      "signature_attempts":h[3],"encoded_length":h[4],"height":h[5],
      "codec_error":h[6],"strict_error":h[7],"generation":h[8],"payload_length":h[9]}

def parse_value(raw,result):
    need(len(raw)>=287 and raw[:8]==b"MPVALUE1","Value framing")
    h=words(raw[:64]);wire=raw[128:]
    need(h[1]==len(raw) and h[2]==result["generation"] and h[3]==result["height"]
         and h[4]==result["encoded_length"]==len(wire) and h[5]==result["payload_length"]
         and h[6:]==(1,0),"Complete private value header")
    need(wire[:4]==b"PNX1" and len(wire)==159+struct.unpack_from("<H",wire,93)[0],"Retained wire framing")
    return {"raw_hex":raw.hex(),"wire_hex":wire.hex(),"transaction_id_hex":raw[64:96].hex(),
      "signing_digest_hex":raw[96:128].hex(),"sender":wire[36:68].hex(),
      "network_hex":wire[4:36].hex(),"nonce":struct.unpack_from("<Q",wire,68)[0],
      "expiry":struct.unpack_from("<Q",wire,76)[0],"fee_limit":struct.unpack_from("<Q",wire,84)[0],
      "tag":wire[92],"payload_hex":wire[95:-64].hex(),"signature_hex":wire[-64:].hex()}

class Session:
    def __init__(self,executable:Path,output:Path,*,gate=None,bootstrap=None):
        self.output=output;output.mkdir(mode=0o700)
        self.executable=Path(executable)
        self.started=time.monotonic_ns();self.sequence=0;self.gate=gate;self.callback_sequence=0
        self.stdin=bytearray();self.stdout=bytearray();self.stderr=bytearray()
        self.progress=bytearray();self.replies=bytearray();self.pending=bytearray();self.gate_pending=bytearray()
        self.events=[];self.closed_streams=set();self.cleanup_errors=[];self.finished=None
        self.input_count=0;self.child=None;self.gw=None;self.gr=None
        owned=[];passed=[];self.owned_fds=owned
        try:
            if gate is not None:
                read_progress,write_progress=os.pipe()
                read_reply,write_reply=os.pipe()
                owned=[read_progress,write_progress,read_reply,write_reply]
                passed=[write_progress,read_reply];self.gw=read_progress;self.gr=write_reply
            else:write_progress=read_reply=U64
            self.child=subprocess.Popen([str(self.executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,pass_fds=tuple(passed),close_fds=True)
            for fd in passed:os.close(fd);owned.remove(fd)
            self.poller=selectors.DefaultSelector()
            for name,stream in (("stdout",self.child.stdout),("stderr",self.child.stderr)):
                os.set_blocking(stream.fileno(),False);self.poller.register(stream,selectors.EVENT_READ,name)
            os.set_blocking(self.child.stdin.fileno(),False)
            if self.gw is not None:
                os.set_blocking(self.gw,False);os.set_blocking(self.gr,False)
                self.poller.register(self.gw,selectors.EVENT_READ,"progress")
            self.owned_fds=owned
            initial=bootstrap if bootstrap is not None else struct.pack("<8Q",magic(b"MPBOOT01"),0,write_progress,read_reply,0,0,0,0)
            self.write(initial)
        except BaseException:
            if self.child is not None:self.cleanup()
            else:
                for fd in owned:
                    try:os.close(fd)
                    except OSError:pass
            raise
    def deadline(self):
        return time.monotonic()+LIMIT_SECONDS
    def write(self,raw,*,fd=None,reply=False):
        target=self.child.stdin.fileno() if fd is None else fd
        view=memoryview(raw);deadline=self.deadline();offset=0
        with selectors.DefaultSelector() as poller:
            poller.register(target,selectors.EVENT_WRITE)
            while offset<len(view):
                if time.monotonic()>=deadline:raise TimeoutError("Native transport write deadline")
                try:n=os.write(target,view[offset:])
                except BlockingIOError:
                    poller.select(min(.05,max(0,deadline-time.monotonic())));continue
                need(n>0,"Zero transport write")
                chunk=view[offset:offset+n]
                if reply:self.replies.extend(chunk)
                else:self.stdin.extend(chunk);self.input_count+=n
                offset+=n
    def pump(self,deadline):
        remain=deadline-time.monotonic()
        if remain<=0:raise TimeoutError("Native transport read deadline")
        ready=self.poller.select(min(.1,remain))
        for key,_ in ready:
            try:raw=os.read(key.fd,65536)
            except BlockingIOError:continue
            name=key.data
            if not raw:
                self.closed_streams.add(name);self.poller.unregister(key.fileobj);continue
            if name=="stdout":self.stdout.extend(raw);self.pending.extend(raw)
            elif name=="stderr":self.stderr.extend(raw)
            else:
                self.progress.extend(raw);self.gate_pending.extend(raw)
                while len(self.gate_pending)>=32:
                    block=bytes(self.gate_pending[:32]);del self.gate_pending[:32]
                    h=words(block)
                    need(h[0]==magic(b"MPPROG01") and h[1]==self.callback_sequence+1 and h[2] in (1,2),"Progress framing")
                    self.callback_sequence=h[1]
                    event={"sequence":h[1],"kind":h[2],"request_sequence":h[3],"raw_hex":block.hex()}
                    response=self.gate(event)
                    if isinstance(response,int):
                        need(response in (0,1),"Callback classification")
                        reply=struct.pack("<3Q",magic(b"MPGO0001"),h[1],response)
                    elif isinstance(response,bytes):reply=response
                    else:raise ValueError("Unknown callback behavior")
                    event["reply_hex"]=reply.hex();self.events.append(event)
                    self.write(reply,fd=self.gr,reply=True)
    def read(self,size):
        deadline=self.deadline()
        while len(self.pending)<size:
            if "stdout" in self.closed_streams:
                raise EOFError("Native stdout ended before complete response")
            self.pump(deadline)
        raw=bytes(self.pending[:size]);del self.pending[:size]
        return raw
    def open(self):
        header=self.read(64);h=words(header)
        need(header[:8]==b"MPREADY1" and 576<=h[2]<=16384,"Bounded context header")
        self.context=parse_context(header+self.read(h[2]))
        return self.context
    def command(self,op,*,height=0,raw=b"",generation=0):
        self.sequence+=1
        self.write(frame(op,self.sequence,height=height,body_len=len(raw),generation=generation)+raw)
        return self.sequence
    def prepare(self,raw,height):
        seq=self.command(1,height=height,raw=raw)
        result=parse_result(self.read(96))
        need(result["sequence"]==seq and result["height"]==height and result["encoded_length"]==len(raw),"Actual request binding")
        return result
    def value(self,result):
        self.command(2,generation=result["generation"])
        header=self.read(64);h=words(header)
        need(287<=h[1]<=2176,"Bounded private observation")
        return parse_value(header+self.read(h[1]-64),result)
    def clear(self):
        seq=self.command(3);raw=self.read(32);h=words(raw)
        need(raw[:8]==b"MPCLEAR1" and h[1]==seq and h[3]==0,"Clear response")
        return raw
    def close(self):
        seq=self.command(4);raw=self.read(32);h=words(raw)
        need(raw[:8]==b"MPCLOSED" and h[1]==seq and h[3]==0,"Close response")
        self.child.stdin.close()
        return self.finish()
    def snapshot(self):
        result={"pid":self.child.pid if self.child else None,
          "exit_code":self.child.poll() if self.child else None,"wall_ns":time.monotonic_ns()-self.started,
          "executable":identity(self.executable.read_bytes()),"stdin":identity(self.stdin),"stdin_written_bytes":self.input_count,
          "stdout":identity(self.stdout),"stderr":identity(self.stderr),"progress":identity(self.progress),
          "replies":identity(self.replies),"events":self.events,"cleanup_errors":list(self.cleanup_errors),
          "closed_streams":sorted(self.closed_streams),"pending_progress_bytes":len(self.gate_pending)}
        if len(self.stderr)==56:result["diagnostic"]=list(words(bytes(self.stderr)))
        for name,raw in (("stdin",self.stdin),("stdout",self.stdout),("stderr",self.stderr),("progress",self.progress),("replies",self.replies)):
            (self.output/(name+".raw")).write_bytes(raw)
        (self.output/"process.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        return result
    def finish(self):
        if self.finished is not None:return self.finished
        deadline=self.deadline()
        while self.child.poll() is None or "stdout" not in self.closed_streams or "stderr" not in self.closed_streams:
            self.pump(deadline)
        self.child.wait(timeout=CLEANUP_SECONDS)
        need(not self.gate_pending,"Partial progress at termination")
        self.finished=self.snapshot()
        return self.finished
    def cleanup(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()
            try:self.child.wait(timeout=CLEANUP_SECONDS)
            except BaseException as error:self.cleanup_errors.append(repr(error))
        if self.child is not None:
            # Preserve terminal bytes without invoking callbacks on an exited child.
            for name,stream in (("stdout",self.child.stdout),("stderr",self.child.stderr)):
                if stream is None or stream.closed:continue
                try:
                    os.set_blocking(stream.fileno(),False)
                    while True:
                        try:raw=os.read(stream.fileno(),65536)
                        except BlockingIOError:break
                        if not raw:self.closed_streams.add(name);break
                        getattr(self,name).extend(raw)
                        if name=="stdout":self.pending.extend(raw)
                except OSError as error:self.cleanup_errors.append(repr(error))
            if self.gw is not None:
                try:
                    while True:
                        try:raw=os.read(self.gw,65536)
                        except BlockingIOError:break
                        if not raw:self.closed_streams.add("progress");break
                        self.progress.extend(raw);self.gate_pending.extend(raw)
                except OSError as error:self.cleanup_errors.append(repr(error))
        for stream in (getattr(self.child,"stdin",None),getattr(self.child,"stdout",None),getattr(self.child,"stderr",None)):
            if stream is not None:
                try:stream.close()
                except OSError as error:self.cleanup_errors.append(repr(error))
        for fd in getattr(self,"owned_fds",[]):
            try:os.close(fd)
            except OSError as error:self.cleanup_errors.append(repr(error))
        self.owned_fds=[];self.gw=None;self.gr=None
        if hasattr(self,"poller"):self.poller.close()
