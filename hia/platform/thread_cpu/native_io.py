"""Physical driver for the finite in-process native ThreadCpuStamp owner.

This module supplies commands and observes raw receipts. It never supplies a
clock reading, TID, generation, authority verdict, or a replacement stamp result.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import time

REQUEST_MAGIC=b'TCREQ001'
RECEIPT_MAGIC=b'TCSTAMP1'
FIELDS=('magic','fixture','sequence','op','status','some','lane','tid','life',
        'handle','cap0','cap1','baseline_before','delta','baseline_after','births',
        'joins','clocks','active','clock_result','checksum','worker_tid',
        'worker_life','next_stamp','next_life','capacity','native_scope','reserved')
U64=(1<<64)-1


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def need(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def frame(op: int, target: int=0, handle=None, argument: int=0) -> bytes:
    ident,cap0,cap1=(0,0,0) if handle is None else handle
    values=(int.from_bytes(REQUEST_MAGIC,'little'),op,target,ident,cap0,cap1,argument,0)
    need(all(type(n) is int and 0<=n<=U64 for n in values),'Non-u64 request value')
    return struct.pack('<8Q',*values)


def decode(raw: bytes) -> dict:
    need(len(raw)==224,'Truncated receipt')
    row=dict(zip(FIELDS,struct.unpack('<28Q',raw)))
    need(raw[:8]==RECEIPT_MAGIC,'Unexpected receipt magic')
    need(row['fixture'] in (0,1) and row['some'] in (0,1),'Noncanonical receipt tag')
    need(row['lane'] in (0,1) and row['capacity']==64 and row['native_scope']==1
         and row['reserved']==0,'Unexpected finite native profile')
    need(0<row['tid']<=2147483647 and row['life']>0,'Missing actual native identity')
    need(row['status'] in range(12),'Unknown receipt status')
    if row['status']!=0:
        need(row['some']==0 and row['delta']==0,'Failed primitive manufactured CPU')
    if row['some']==0:
        need(row['delta']==0,'Absent interval manufactured CPU')
    return row


def handle(row: dict) -> tuple[int,int,int]:
    need(row['status']==0 and row['some']==1 and row['handle']>0,'No valid handle')
    need(row['cap0']!=0 or row['cap1']!=0,'Empty capability')
    return row['handle'],row['cap0'],row['cap1']


class Native:
    def __init__(self,image: bytes,output: Path,*,fixture=False,trace=False,
                 injection: str|None=None,timeout=20.0):
        if not __debug__:
            raise RuntimeError('Thread CPU physical validation refuses optimized Python')
        self.output=output
        output.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.image=image;self.fixture=int(fixture);self.timeout=timeout
        self.input=bytearray();self.stdout=bytearray();self.rows=[];self.observations=[]
        self.sequence=0;self.closed=False;self.returncode=None
        self.fd=os.memfd_create('trnm-hia-thread-cpu',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        try:
            position=0
            while position<len(image):
                written=os.write(self.fd,image[position:])
                need(written>0,'Short native image capture');position+=written
            os.fchmod(self.fd,0o500)
            fcntl.fcntl(self.fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
            need(fcntl.fcntl(self.fd,getattr(fcntl,'F_GET_SEALS',1034))&15==15,'Native image is not sealed')
            executable='/proc/self/fd/'+str(self.fd)
            argv=[executable]
            if trace:
                argv=['/usr/bin/strace','-f','-qq','-v','-s','4096','-o',str(output/'syscalls.raw')]
                if injection is not None:
                    argv+=['-e','inject='+injection]
                argv+=['--',executable]
            else:
                need(injection is None,'Injection requires real ptrace execution')
            self.error=(output/'stderr.raw').open('xb')
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=self.error,env={'PATH':''},pass_fds=(self.fd,),start_new_session=True)
        except BaseException:
            self._save()
            raise
        finally:
            os.close(self.fd)
        self.selector=selectors.DefaultSelector()
        self.selector.register(self.process.stdout,selectors.EVENT_READ)
        try:
            self.ready=self.receive()
            need(self.ready['fixture']==self.fixture and self.ready['sequence']==0
                 and self.ready['op']==0 and self.ready['status']==0
                 and self.ready['some']==0 and self.ready['lane']==0
                 and self.ready['life']==1 and self.ready['clocks']==0
                 and self.ready['active']==0 and self.ready['births']==0
                 and self.ready['joins']==0,'Invalid initial physical state')
            self.main_tid=self.ready['tid']
            self.observe_threads(self.ready)
        except BaseException:
            self.abort()
            raise

    def receive(self) -> dict:
        raw=bytearray();deadline=time.monotonic()+self.timeout
        while len(raw)<224:
            left=deadline-time.monotonic()
            need(left>0,'Native receipt timeout')
            events=self.selector.select(left)
            need(bool(events),'Native receipt timeout')
            chunk=os.read(self.process.stdout.fileno(),224-len(raw))
            need(bool(chunk),'Native EOF before complete receipt')
            raw.extend(chunk)
            self.stdout.extend(chunk)
        row=decode(bytes(raw))
        need(row['fixture']==self.fixture,'Production/fixture entry mismatch')
        self.rows.append(row)
        return row

    def request(self,op:int,target:int=0,stamp=None,argument:int=0,*,raw:bytes|None=None):
        data=frame(op,target,stamp,argument) if raw is None else raw
        position=0
        while position<len(data):
            written=os.write(self.process.stdin.fileno(),data[position:])
            need(written>0,'Short request write')
            self.input.extend(data[position:position+written]);position+=written
        self.sequence+=1
        row=self.receive()
        need(row['sequence']==self.sequence,'Sequence mismatch')
        if raw is None:
            need(row['op']==op,'Operation receipt mismatch')
        return row

    def observe_threads(self,row:dict):
        tids=[self.main_tid] if hasattr(self,'main_tid') else [row['tid']]
        if row['worker_tid']:
            tids.append(row['worker_tid'])
        observations=[]
        for tid in tids:
            status=Path('/proc')/str(tid)/'status'
            fields={}
            for line in status.read_text().splitlines():
                if ':' in line:
                    key,value=line.split(':',1);fields[key]=value.strip()
            leader=self.main_tid if hasattr(self,'main_tid') else row['tid']
            need(int(fields['Tgid'])==leader and int(fields['Pid'])==tid,'Receipt thread is not an actual member of this native process')
            executable=(Path('/proc')/str(tid)/'exe').read_bytes()
            need(executable==self.image,'Observed native thread executable differs')
            task=Path('/proc')/str(leader)/'task'/str(tid)
            need(task.is_dir(),'Native thread missing from actual task directory')
            observations.append({'tid':tid,'tgid':int(fields['Tgid']),
                'executable_sha256':sha256(executable),'threads':int(fields['Threads'])})
        self.observations.append({'sequence':row['sequence'],'threads':observations})
        return observations

    def finish(self,expected_exit=0):
        if self.closed:
            return self.returncode
        self.process.stdin.close()
        self.returncode=self.process.wait(timeout=self.timeout)
        tail=self.process.stdout.read()
        self.stdout.extend(tail)
        self._save()
        need(not tail,'Unsolicited native output at EOF')
        need(self.returncode==expected_exit,'Native exit differs: '+str(self.returncode))
        need(not (self.output/'stderr.raw').read_bytes(),'Unexpected native/tracer stderr')
        return self.returncode

    def abort(self):
        if hasattr(self,'process') and self.process.poll() is None:
            try:
                os.killpg(self.process.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=10)
        self.returncode=self.process.returncode if hasattr(self,'process') else None
        self._save()

    def _save(self):
        if self.closed:
            return
        self.closed=True
        if hasattr(self,'selector'):
            self.selector.close()
        if hasattr(self,'error'):
            self.error.close()
        for stream in [getattr(getattr(self,'process',None),'stdin',None),
                       getattr(getattr(self,'process',None),'stdout',None)]:
            if stream is not None and not stream.closed:
                stream.close()
        (self.output/'stdin.raw').write_bytes(self.input)
        (self.output/'stdout.raw').write_bytes(self.stdout)
        result={'image':{'bytes':len(self.image),'sha256':sha256(self.image)},
                'fixture':self.fixture,'exit_code':self.returncode,'receipts':self.rows,
                'observed_tasks':self.observations,
                'stdin':{'bytes':len(self.input),'sha256':sha256(self.input)},
                'stdout':{'bytes':len(self.stdout),'sha256':sha256(self.stdout)},
                'host_supplied_clock_or_tid':False}
        (self.output/'physical.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')

    def __enter__(self):
        return self

    def __exit__(self,kind,value,tb):
        if kind is None:
            try:self.finish()
            except BaseException:self.abort();raise
        else:self.abort()
