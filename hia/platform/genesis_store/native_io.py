"""Hosted observation of a real native process; no persistence or State algorithm."""
from __future__ import annotations
import fcntl,hashlib,json,os,resource,select,signal,stat,struct,subprocess,time
from pathlib import Path
from .build import need
LIMIT=(1<<64)-1
CHILD_SECONDS=240
CLEANUP_SECONDS=3
def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def request(op):
    return b"NGCMD001"+struct.pack("<Q",op)
def bootstrap(fd,mode=0,timestamp=None,workers=1,gate=(LIMIT,LIMIT)):
    return b"NGBOOT01"+struct.pack("<7Q",fd,mode,int(timestamp is not None),timestamp or 0,workers,*gate)
def snapshot(directory):
    result={}
    for path in sorted(directory.iterdir()):
        st=path.lstat()
        item={"mode":st.st_mode,"uid":st.st_uid,"gid":st.st_gid,"links":st.st_nlink,
              "dev":st.st_dev,"ino":st.st_ino,"bytes":st.st_size,"mtime_ns":st.st_mtime_ns,"ctime_ns":st.st_ctime_ns}
        if stat.S_ISREG(st.st_mode):
            raw=path.read_bytes();item["content"]=identity(raw)
        elif stat.S_ISLNK(st.st_mode):
            item["target"]=os.readlink(path)
        result[path.name]=item
    return result
def parse_record(raw):
    need(len(raw)>=512 and raw[:8]==b"NGSTATE1","Native record magic")
    q=lambda p:struct.unpack_from("<Q",raw,p)[0]
    need(q(8)==len(raw) and q(24)==1 and q(384)==7,"Native record extent/version")
    settings=raw[512:]
    need(576<=len(settings)<=16384 and settings[:4]==b"SDO1"
         and struct.unpack_from("<I",settings,4)[0]==len(settings),"Settings record")
    need(struct.unpack_from("<II",settings,8)==(0,0),"Settings flags/reserved fields")
    need(struct.unpack_from("<II",settings,448)==(3,7)
         and settings[468:480]==bytes(12),"Settings counts/reserved fields")
    params_n,model_n,state_n=struct.unpack_from("<III",settings,456)
    at=576+params_n+model_n
    need(q(400)==len(settings) and q(416)==512+at and q(392)==state_n
         and at+state_n==len(settings),"Native State offsets")
    params=json.loads(settings[576:576+params_n])
    model=json.loads(settings[576+params_n:at])
    state=settings[at:]
    need(state[:4]==b"SRV1" and struct.unpack_from("<I",state,4)[0]==7,"Native State framing")
    cursor=8;rows=[]
    for _ in range(7):
        need(cursor+8<=len(state),"State row header truncated")
        kn,vn=struct.unpack_from("<II",state,cursor);cursor+=8
        need(kn<=160 and vn<=4096 and cursor+kn+vn<=len(state),"State cell extent")
        key=state[cursor:cursor+kn].decode();cursor+=kn
        value=state[cursor:cursor+vn];cursor+=vn
        json.loads(value)
        rows.append({"key":key,"value_hex":value.hex()})
    need(cursor==len(state) and [r["key"] for r in rows]==sorted({r["key"] for r in rows}),"State row order")
    zero_fields=(16,192,200,216,224,232,304,312,320,328,336,352,360,368,376,408,440,448,456,464,472,480,488,496,504)
    need(all(q(p)==0 for p in zero_fields) and raw[240:304]==bytes(64),"Non-genesis catalog fields")
    need(q(208)==q(344)==1 and raw[160:192]==raw[96:128] and q(424)==512,"Genesis catalog cardinality")
    need(raw[32:160]==settings[24:88]+settings[152:216] and q(432)==struct.unpack_from("<Q",settings,16)[0],
         "Settings/catalog context differs")
    return {"record":identity(raw),"network":raw[32:64].hex(),"parameters":raw[64:96].hex(),
        "genesis":raw[96:128].hex(),"state_root":raw[128:160].hex(),
        "active_tip":raw[160:192].hex(),"generation":q(192),"slot":q(200),
        "height":q(216),"parent":None,"packet":None,"chainwork":raw[240:304].hex(),
        "rows":rows,"snapshot_rows":rows,
        "collections":{"blocks":q(208),"snapshots":q(344),"deltas":q(304),"events":q(312),
          "reorg":q(320),"steps":q(328),"reorg_lifecycle_v1":q(336),"ancestry_jump":q(408),
          "local_pool_metadata":q(352),"local_pool_groups":q(352),"local_pool_rows":q(352),
          "local_pool_removals":q(352),"peer_replay":q(360),"peer_request_audit":q(368),"peer_outbox":q(376)},
        "settings":{"params":params,"model_registry":model,
          "params_canonical_hex":settings[576:576+params_n].hex(),
          "model_registry_canonical_hex":settings[576+params_n:at].hex(),
          "network":settings[24:56].hex(),"parameters":settings[56:88].hex(),
          "family":settings[88:120].hex(),"plan":settings[120:152].hex(),
          "genesis_time":struct.unpack_from("<Q",settings,16)[0],
          "task":settings[216:248].hex(),"fees":list(struct.unpack_from("<25Q",settings,248)),
          "evaluators":[settings[480+32*i:512+32*i].hex() for i in range(3)]},
        "native_schema":"NGSTATE1/version1","schema_bytes_equal_to_sqlite":False}
def parse_success(stdout):
    need(len(stdout)>=320 and stdout[:8]==b"NGOPEN01" and stdout[256:264]==b"NGREAD01","Native response framing")
    size=struct.unpack_from("<Q",stdout,264)[0]
    need(len(stdout)==320+size,"Native complete READ response")
    data=stdout[320:];observed=parse_record(data)
    need(stdout[32:160]==data[32:160] and stdout[272:304]==data[128:160],"Native response identities")
    q=lambda p:struct.unpack_from("<Q",stdout,p)[0]
    need(q(8) in (0,1,2) and q(16)==len(data) and q(24) in (1,2,4,8),"Opened contract")
    need(stdout[160:192]==data[160:192] and q(192)==0 and q(200)==0 and q(208)==7
         and q(216)==struct.unpack_from("<Q",data,392)[0]
         and q(224)==struct.unpack_from("<Q",data,432)[0],"Complete opened catalog fields")
    need(stdout[232:256]==bytes(24) and stdout[304:320]==bytes(16),"Response reserved fields")
    observed.update(record_hex=data.hex(),opened_receipt_hex=stdout[:256].hex(),read_header_hex=stdout[256:320].hex())
    return observed,data

class Session:
    def __init__(self,executable:bytes,output:Path,directory:Path,*,mode=0,timestamp=None,workers=1,
                 gate=False,fd_override=None,boot_override=None,file_limit=None,stdout_closed=False,
                 extra_pass_fds=(),before_exec=None,trace_path=None):
        output.mkdir(mode=0o700);self.output=output;self.start=time.monotonic_ns()
        self.stdin=bytearray();self.stdout=bytearray();self.events_raw=bytearray();self.events=[];self.extra={};self.stdin_written=0
        self.gate_reader=None;self.gate_writer=None;self.finished=False
        self.meta={"executable":identity(executable),"mode":mode,"timestamp":timestamp,"workers":workers}
        image=os.memfd_create("native-genesis-owner",os.MFD_ALLOW_SEALING)
        cursor=0
        while cursor<len(executable):
            count=os.write(image,executable[cursor:]);need(count>0,"Sealed image short write");cursor+=count
        need(os.pread(image,len(executable),0)==executable,"Sealed executable readback")
        os.fchmod(image,0o500);fcntl.fcntl(image,1033,15)
        directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC) if fd_override is None else os.dup(fd_override)
        inherited=[image,directory_fd,*extra_pass_fds];close_parent=[image,directory_fd]
        pair=(LIMIT,LIMIT)
        if gate:
            event_r,event_w=os.pipe();resume_r,resume_w=os.pipe()
            pair=(event_w,resume_r);inherited.extend(pair);close_parent.extend(pair)
            self.gate_reader=event_r;self.gate_writer=resume_w
        self.transport={"image_fd":image,"directory_fd":directory_fd,"inherited_fds":tuple(inherited),"gate_fds":pair}
        payload=bootstrap(directory_fd,mode,timestamp,workers,pair)
        if boot_override is not None:payload=boot_override(payload,pair,directory_fd)
        def limits():
            resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
            if file_limit is not None:
                signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE,(file_limit,file_limit))
            if before_exec is not None:before_exec(directory_fd,tuple(inherited))
        argv=["/proc/self/fd/"+str(image)]
        self.trace_path=trace_path
        if trace_path is not None:
            tracer=Path("/usr/bin/strace")
            need(tracer.is_file() and not tracer.is_symlink(),"Actual syscall tracer unavailable")
            self.extra["tracer"]={"path":str(tracer),**identity(tracer.read_bytes())}
            argv=[str(tracer),"-f","-qq","-yy","-s","128","-o",str(trace_path),
                  "-e","trace=fsync,write,renameat2,openat,close,pread64,fstat,getdents64,flock","--",*argv]
        try:
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=tuple(inherited),
                env={"PATH":""},cwd=output,start_new_session=True,umask=0o077,preexec_fn=limits)
        finally:
            for fd in close_parent:os.close(fd)
        if stdout_closed:
            self.process.stdout.close();self.extra["stdout_reader_closed_before_boot"]=True
        self.send(payload)
    def send(self,data):
        self.stdin.extend(data)
        try:
            cursor=0
            while cursor<len(data):
                count=os.write(self.process.stdin.fileno(),data[cursor:])
                need(count>0,"Controller short stdin write")
                cursor+=count;self.stdin_written+=count
        except BrokenPipeError:
            self.extra["stdin_epipe"]=True
    def _read(self,fd,n):
        result=bytearray();deadline=self.start/1e9+CHILD_SECONDS
        while len(result)<n:
            remaining=deadline-time.monotonic()
            need(remaining>0,"Native read exceeded unchanged child budget")
            ready,_,_=select.select([fd],[],[],remaining)
            need(bool(ready),"Native read timed out")
            block=os.read(fd,n-len(result))
            need(bool(block),"Native response EOF")
            result+=block
            if fd==self.gate_reader:self.events_raw.extend(block)
            else:self.stdout.extend(block)
        return bytes(result)
    def opened(self):
        raw=self._read(self.process.stdout.fileno(),256)
        need(raw[:8]==b"NGOPEN01","Owner did not publish an opened receipt")
        return raw
    def gate_event(self):
        need(self.gate_reader is not None,"No diagnostic capability")
        raw=self._read(self.gate_reader,32)
        need(raw[:8]==b"NGCUT001","Diagnostic event framing")
        event={"sequence":struct.unpack_from("<Q",raw,8)[0],"tag":struct.unpack_from("<Q",raw,16)[0],
            "private_published_flag":struct.unpack_from("<Q",raw,24)[0],"raw_hex":raw.hex()}
        need(event["sequence"]==len(self.events)+1,"Diagnostic event order")
        self.events.append(event);return event
    def resume(self,byte=b"\1"):
        need(self.gate_writer is not None,"Gate already closed")
        os.write(self.gate_writer,byte)
    def advance(self,tag):
        while True:
            event=self.gate_event()
            if event["tag"]==tag:return event
            self.resume()
    def gate_eof(self):
        need(self.gate_writer is not None,"Gate already closed")
        os.close(self.gate_writer);self.gate_writer=None
    def kill(self):
        if self.process.poll() is None:
            try:os.killpg(self.process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    def finish(self,*,close=False,read=False,expect_running=False):
        if close:self.send((request(1) if read else b"")+request(2))
        timeout=max(0.001,self.start/1e9+CHILD_SECONDS-time.monotonic())
        timed_out=False
        try:
            if self.process.stdout.closed:
                self.process.stdout=None
            stdout,stderr=self.process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True;self.kill();stdout,stderr=self.process.communicate(timeout=CLEANUP_SECONDS)
        self.stdout.extend(stdout or b"");self.finished=True
        for name in ("gate_reader","gate_writer"):
            fd=getattr(self,name)
            if fd is not None:
                os.close(fd);setattr(self,name,None)
        for name,raw in (("stdin.raw",bytes(self.stdin)),("stdout.raw",bytes(self.stdout)),("stderr.raw",stderr),("events.raw",bytes(self.events_raw))):
            (self.output/name).write_bytes(raw)
        (self.output/"events.json").write_text(json.dumps(self.events,sort_keys=True,indent=2)+"\n")
        if self.trace_path is not None and self.trace_path.is_file():
            self.extra["syscall_trace"]={"path":str(self.trace_path),**identity(self.trace_path.read_bytes())}
        diagnostic=list(struct.unpack("<7Q",stderr)) if len(stderr)==56 else None
        row={"schema":"trnm.native-genesis-process.v1",**self.meta,"pid":self.process.pid,
            "exit_code":self.process.returncode,"timed_out":timed_out,"elapsed_ns":time.monotonic_ns()-self.start,
            "child_budget_seconds":CHILD_SECONDS,"cleanup_budget_seconds":CLEANUP_SECONDS,
            "stdin":identity(bytes(self.stdin)),"stdin_hex":bytes(self.stdin).hex(),
            "stdin_actual_hex":bytes(self.stdin[:self.stdin_written]).hex(),
            "stdin_actual_write_bytes":self.stdin_written,"stdout":identity(bytes(self.stdout)),"stderr":identity(stderr),
            "stderr_hex":stderr.hex(),"diagnostic":diagnostic,"events":self.events,
            "path":str(self.output),**self.extra}
        (self.output/"process.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
        return row,bytes(self.stdout)
    def cleanup(self):
        if not self.finished:
            self.kill()
            return self.finish()
        return None
