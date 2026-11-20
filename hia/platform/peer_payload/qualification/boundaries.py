"""Fresh original/native public-method histories and real filesystem mutations."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import signal
import stat
import struct
import subprocess
import time
import traceback

P = argparse.ArgumentParser()
P.add_argument('--native', type=Path, required=True)
P.add_argument('--original', type=Path, required=True)
P.add_argument('--fixtures', type=Path, required=True)
P.add_argument('--output', type=Path, required=True)
A = P.parse_args()
OUT = A.output.absolute(); OUT.mkdir(mode=0o700)
START = time.monotonic_ns(); DEADLINE = time.monotonic() + 240
REPORT = {'status': 'FAIL', 'cases': [], 'native_runtime_limit_seconds': 240,
    'cleanup_limit_seconds': 3, 'whole_payload_owner_qualified': False,
    'original_service_budget_qualified': False, 'fresh_cargo_tests_in_this_job': False,
    'poison_compared_through_subsequent_public_calls': True}
def identity(raw): return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
def u64(n): return struct.pack('<Q', n)
def word(b, at=0): return struct.unpack_from('<Q', b, at)[0]
def request(op, data=b''):
    body = u64(op) + data
    return u64(len(body)) + body
fixtures = json.loads(A.fixtures.read_bytes())
NS = bytes.fromhex(next(r['payload_hex'] for r in fixtures if r['name'] == 'namespace-0'))
FRAME = bytearray(bytes.fromhex(next(r['payload_hex'] for r in fixtures if r['name'] == 'frame-0'))[136:408])
FRAME[208:216] = u64(1); FRAME[216:224] = u64(0); FRAME = bytes(FRAME)
def frame(**changes):
    b = bytearray(FRAME)
    fields = dict(local=0,remote=32,scope=64,direction=96,epoch=104,run=112,
        network=144,session=176,generation=208,sequence=216,kind=224,length=232,fingerprint=240)
    for name,value in changes.items():
        value = u64(value) if isinstance(value,int) else value
        at=fields[name]; b[at:at+len(value)] = value
    return bytes(b)

class Process:
    def __init__(self, executable, root):
        self.root=root;self.responses=[];self.transcript=[];self.finished=False;self.nested=[]
        self.stderr=(root/'stderr.raw').open('wb')
        self.input=(root/'stdin.raw').open('wb');self.output=(root/'stdout.raw').open('wb')
        self.started=time.monotonic_ns()
        self.executable=Path(executable).absolute()
        self.executable_before=identity(self.executable.read_bytes())
        self.argv=[str(self.executable)]
        self.process=subprocess.Popen(self.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.stderr,cwd=root,env={'PATH':''},start_new_session=True,umask=0o077)
        self.pid=self.process.pid
        os.set_blocking(self.process.stdin.fileno(),False)
        os.set_blocking(self.process.stdout.fileno(),False)
    def deadline(self):
        left=DEADLINE-time.monotonic()
        if left<=0: raise TimeoutError('unchanged complete 240-second runtime limit')
        return min(left,15)
    def read(self,n):
        result=bytearray();end=time.monotonic()+self.deadline()
        while len(result)<n:
            left=min(end,DEADLINE)-time.monotonic()
            if left<=0:raise TimeoutError('public method response deadline')
            if not select.select([self.process.stdout],[],[],left)[0]:raise TimeoutError('public method response deadline')
            b=os.read(self.process.stdout.fileno(),n-len(result))
            if not b:raise RuntimeError(('short native/original response',self.process.poll(),len(result),n))
            result.extend(b);self.output.write(b);self.output.flush()
        return bytes(result)
    def call(self,op,data=b''):
        raw=request(op,data);self.input.write(raw);self.input.flush();at=0;end=time.monotonic()+self.deadline()
        while at<len(raw):
            left=min(end,DEADLINE)-time.monotonic()
            if left<=0 or not select.select([],[self.process.stdin],[],left)[1]:raise TimeoutError('request write deadline')
            at+=os.write(self.process.stdin.fileno(),raw[at:])
        head=self.read(8);n=word(head);assert 88<=n<=65536,n
        body=self.read(n);payload_n=word(body,80);assert payload_n==n-88
        code,errno,reason,inner,poison,count=struct.unpack_from('<6Q',body)
        row=dict(op=op,code=code,errno=errno,reason=reason,inner=inner,poison=poison,
            count=count,hash=body[48:80].hex(),payload_hex=body[88:].hex())
        self.responses.append(row)
        if op==9 and code==0:self.finished=True
        return row
    def close(self):
        shutdown_error = None
        code = None
        cleanup = None
        try:
            if not self.finished and self.process.poll() is None:
                self.call(9)
            self.process.stdin.close()
        except BaseException as error:
            shutdown_error = error
        finally:
            started = time.monotonic_ns()
            deadline = min(DEADLINE + 3, time.monotonic() + 3)
            if shutdown_error is not None and self.process.poll() is None:
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException as error:
                if shutdown_error is None:
                    shutdown_error = error
                if self.process.poll() is None:
                    try:
                        os.killpg(self.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
                    except BaseException:
                        code = self.process.poll()
            self.receipt = {'pid': self.pid, 'exit_code': code,
                'elapsed_ns': time.monotonic_ns() - self.started,
                'timed_out': isinstance(shutdown_error, (TimeoutError, subprocess.TimeoutExpired)),
                'reaped': code is not None, 'cleanup_windows': 1,
                'cleanup_limit_seconds': 3, 'cleanup_elapsed_ns': time.monotonic_ns() - started,
                'failure': repr(shutdown_error) if shutdown_error is not None else None,
                'family_reaping_observed_by_outer_collector': True}
            self.input.close(); self.output.close(); self.stderr.close()
            self.receipt.update(argv=self.argv,cwd=str(self.root),environment={'PATH':''},
                executable_before=self.executable_before,executable_after=identity(self.executable.read_bytes()),
                input=identity((self.root/'stdin.raw').read_bytes()),
                stdout=identity((self.root/'stdout.raw').read_bytes()),stderr=identity((self.root/'stderr.raw').read_bytes()))
            assert self.receipt['executable_after']==self.executable_before
            (self.root/'responses.json').write_text(json.dumps(self.responses,sort_keys=True,indent=2)+'\n')
            (self.root/'process.json').write_text(json.dumps(self.receipt,sort_keys=True,indent=2)+'\n')
        if shutdown_error is not None:
            raise shutdown_error
        assert code == 0 and self.receipt['cleanup_elapsed_ns'] <= 3_000_000_000, self.receipt

def open_store(p,path,ns=NS):
    raw=os.fsencode(path)
    return p.call(1,ns+u64(len(raw))+raw)
def normalized(row,base):
    result={k:v for k,v in row.items() if k!='poison'}
    if row['op']==5 and row['code']==0:
        raw=bytes.fromhex(row['payload_hex']);n=word(raw);a=raw[8:8+n];at=8+n
        m=word(raw,at);b=raw[at+8:at+8+m];tail=raw[at+8+m:]
        # Substitute only the isolated observer directory component. Keep
        # every leading/repeated slash, dot and all returned filename bytes;
        # canonicalization here would conceal a real public path difference.
        component=os.fsencode(base.parent.name)
        def isolated(raw):
            return b'/'.join(b'$OWNER' if part==component else part for part in raw.split(b'/'))
        a=isolated(a);b=isolated(b)
        result['payload_hex']=(u64(len(a))+a+u64(len(b))+b+tail).hex()
    return result
def files(base):
    result={}
    for path in sorted(base.rglob('*')):
        st=path.lstat();row={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'links':st.st_nlink}
        if stat.S_ISREG(st.st_mode):
            row.update(kind='regular',**identity(path.read_bytes()))
        elif stat.S_ISLNK(st.st_mode):
            row.update(kind='symlink',target=os.readlink(path).replace(str(base),'$CASE'))
        elif stat.S_ISDIR(st.st_mode):row.update(kind='directory')
        elif stat.S_ISFIFO(st.st_mode):row.update(kind='fifo')
        else:row.update(kind='other')
        result[str(path.relative_to(base))]=row
    return result
def execute(name,steps):
    rows=[]
    for label,executable in [('original',A.original),('native',A.native)]:
        root=OUT/(name+'-'+label);root.mkdir(mode=0o700)
        base=root/'work';base.mkdir(mode=0o700);path=base/'journal'
        p=Process(executable.absolute(),root);p.label=label
        try:
            steps(p,path,base)
        finally:p.close()
        observed={'responses':[normalized(r,base) for r in p.responses], 'files':files(base), 'nested':[{'directory':r['directory'],'responses':[normalized(v,base) for v in r['responses']], 'exit_code':r['process']['exit_code'],'timed_out':r['process']['timed_out'],'reaped':r['process']['reaped']} for r in p.nested]}
        (root/'observed.json').write_text(json.dumps(observed,sort_keys=True,indent=2)+'\n')
        rows.append(observed)
    result={'name':name,'calls':len(rows[0]['responses']),'status':'PASS' if rows[0]==rows[1] else 'FAIL'}
    REPORT['cases'].append(result)
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    assert rows[0]==rows[1],{'case':name,'original':rows[0],'native':rows[1]}
    print(json.dumps(result),flush=True)

def basic(p,path,base):
    open_store(p,path);p.call(5)
    key=FRAME[32:64]+FRAME[96:104]
    p.call(7,key);p.call(6,key+FRAME[176:208]);p.call(3,FRAME);p.call(2,FRAME);p.call(3,FRAME);p.call(2,FRAME)
    for name,value in [('fingerprint',bytes([88])*32),('kind',2),('length',7),('session',bytes([89])*32)]:
        p.call(3,frame(**{name:value}))
    p.call(2,frame(sequence=2));p.call(2,frame(sequence=1));p.call(3,frame(sequence=1))
    p.call(2,frame(generation=2,session=bytes([90])*32));p.call(2,frame(generation=3,session=FRAME[176:208]))
    p.call(2,frame(generation=(1<<64)-1,session=bytes([91])*32))
    p.call(7,key);p.call(6,key+FRAME[176:208]);p.call(5);p.call(4);p.call(8)
    open_store(p,path);p.call(3,FRAME);p.call(5)
def many_peers(p,path,base):
    open_store(p,path)
    for n in range(12):
        for direction in (1,2):
            r=bytes([100+n])*32;s=bytes([150+n])*32
            f=frame(remote=r,direction=direction,session=s)
            p.call(2,f);p.call(3,f);p.call(2,frame(remote=r,direction=direction,session=s,sequence=1))
            p.call(7,r+u64(direction));p.call(6,r+u64(direction)+s)
    p.call(8);open_store(p,path)
    for n in range(12):
        for direction in (1,2):
            r=bytes([100+n])*32;s=bytes([150+n])*32
            p.call(3,frame(remote=r,direction=direction,session=s));p.call(7,r+u64(direction));p.call(6,r+u64(direction)+s)
def invalid_frames(p,path,base):
    open_store(p,path)
    changes=[('local',bytes(32)),('remote',bytes(32)),('remote',FRAME[:32]),('scope',bytes(32)),
        ('direction',0),('direction',3),('run',bytes(32)),('network',bytes(32)),('session',bytes(32)),
        ('generation',0),('kind',0),('kind',256),('length',8*1024*1024+1),('fingerprint',bytes(32)),
        ('local',bytes([77])*32),('scope',bytes([78])*32),('run',bytes([79])*32),
        ('network',bytes([80])*32),('epoch',word(NS,128)^1)]
    for name,value in changes:
        p.call(2,frame(**{name:value}));p.call(3,frame(**{name:value}))
    p.call(2,FRAME);p.call(3,FRAME)
def tamper_after_open(kind):
    def steps(p,path,base):
        open_store(p,path);p.call(2,FRAME)
        target=base/('.journal.head-v1' if kind.startswith('head') else '.journal.lock-v1' if kind.startswith('lock') else 'journal')
        if kind.endswith('permission'):
            target.chmod(0o640);p.call(4);target.chmod(0o600);p.call(3,FRAME)
        elif kind.endswith('hardlink'):
            alias=base/'alias';os.link(target,alias);p.call(4);alias.unlink();p.call(3,FRAME)
        elif kind.endswith('replace') or kind.endswith('symlink'):
            saved=base/'saved';target.rename(saved)
            if kind.endswith('replace'):target.write_bytes(saved.read_bytes());target.chmod(0o600)
            else:target.symlink_to(saved)
            p.call(4);target.unlink();saved.rename(target);p.call(3,FRAME)
        elif kind=='wal-truncated':
            with path.open('r+b') as f:f.truncate(759)
            p.call(3,FRAME);p.call(3,FRAME);p.call(2,FRAME);p.call(5);p.call(4)
        elif kind=='wal-mutated':
            b=bytearray(path.read_bytes());b[400]^=1;path.write_bytes(b)
            p.call(3,FRAME);p.call(3,FRAME);p.call(2,FRAME);p.call(5)
        elif kind=='head-mutated':
            b=bytearray(target.read_bytes());b[83]^=1;target.write_bytes(b)
            p.call(3,FRAME);p.call(3,FRAME);p.call(2,FRAME);p.call(5)
        elif kind=='directory-permission':
            base.chmod(0o750);p.call(4);base.chmod(0o700);p.call(3,FRAME)
        else:raise ValueError(kind)
    return steps
def rollback(p,path,base):
    open_store(p,path);genesis=path.read_bytes();head=base/'.journal.head-v1';oldhead=head.read_bytes()
    p.call(2,FRAME);p.call(2,frame(sequence=1))
    path.write_bytes(genesis);head.write_bytes(oldhead)
    p.call(4);p.call(3,FRAME);p.call(2,FRAME);p.call(3,FRAME);p.call(5)
def open_fault(kind):
    def steps(p,path,base):
        ns=NS;chosen=os.fsencode(path)
        if kind=='namespace-zero':ns=bytes(32)+NS[32:]
        elif kind=='missing-parent':chosen=os.fsencode(base/'missing/journal')
        elif kind=='relative':chosen=b'journal'
        elif kind=='root':chosen=b'/'
        elif kind=='empty':chosen=b''
        elif kind=='dot-parent':chosen=os.fsencode(base)+b'/./journal'
        elif kind=='double-slash':chosen=os.fsencode(base).replace(b'/var/',b'//var//')+b'//journal'
        elif kind=='basename-dot':chosen=os.fsencode(path)+b'/.'
        elif kind=='basename-dotdot':chosen=os.fsencode(base)+b'/journal/..'
        elif kind=='parent-dotdot':chosen=os.fsencode(base)+b'/../work/journal'
        elif kind=='invalid-utf8':chosen=os.fsencode(base)+b'/journal\xff'
        elif kind=='nul-name':chosen=os.fsencode(base)+b'/journal\0x'
        elif kind=='nul-parent':chosen=os.fsencode(base)+b'\0/journal'
        elif kind=='empty-journal':path.write_bytes(b'');path.chmod(0o600)
        elif kind=='bad-journal-mode':path.write_bytes(b'');path.chmod(0o644)
        elif kind=='journal-directory':path.mkdir(mode=0o700)
        elif kind=='journal-symlink':path.symlink_to(base/'missing')
        elif kind=='head-collision':(base/'.journal.head-v1').write_bytes(b'x');(base/'.journal.head-v1').chmod(0o600)
        elif kind=='head-symlink-collision':(base/'.journal.head-v1').symlink_to(base/'missing')
        elif kind=='stale-temp':(base/'..journal.head-v1.tmp-old').write_bytes(b'x')
        elif kind=='lock-mode':(base/'.journal.lock-v1').write_bytes(b'');(base/'.journal.lock-v1').chmod(0o644)
        elif kind=='lock-directory':(base/'.journal.lock-v1').mkdir(mode=0o700)
        elif kind=='lock-symlink':(base/'.journal.lock-v1').symlink_to(base/'missing')
        elif kind=='parent-mode':base.chmod(0o750)
        elif kind=='parent-strict-mode':base.chmod(0o500)
        elif kind=='long-basename':chosen=os.fsencode(base)+b'/'+b'a'*256
        elif kind=='overlong-parent':chosen=os.fsencode(base)+b'/'+b'a'*4100+b'/j'
        else:raise ValueError(kind)
        open_store(p,chosen,ns)
        p.call(5);p.call(4)
    return steps

def directory_count(count):
    def steps(p,path,base):
        for i in range(count):(base/('ordinary-'+str(i).zfill(4))).write_bytes(b'')
        open_store(p,path);p.call(5);p.call(4);p.call(8);open_store(p,path);p.call(5)
    return steps
def basename_length(length):
    def steps(p,path,base):
        path=base/('j'*length)
        open_store(p,path);p.call(5);p.call(4);p.call(8);open_store(p,path);p.call(5)
    return steps
def namespace_mismatch(p,path,base):
    open_store(p,path);p.call(2,FRAME);p.call(8)
    changed=bytearray(NS);changed[32]^=1
    open_store(p,path,bytes(changed));p.call(5);p.call(4)
    open_store(p,path);p.call(3,FRAME);p.call(5)
def missing_after_close(kind):
    def steps(p,path,base):
        open_store(p,path);p.call(2,FRAME);p.call(8)
        target={'head':base/'.journal.head-v1','journal':path,'lock':base/'.journal.lock-v1'}[kind]
        target.unlink()
        open_store(p,path);p.call(5);p.call(3,FRAME);p.call(4)
    return steps
def ancestors(kind):
    def steps(p,path,base):
        top=base/'outer';top.mkdir(mode=0o700)
        inside=top/'inner';inside.mkdir(mode=0o700)
        chosen=inside/'journal'
        if kind=='symlink':
            alias=base/'alias';alias.symlink_to(top,target_is_directory=True);chosen=alias/'inner/journal'
        elif kind=='writable':top.chmod(0o777)
        elif kind=='shared':top.chmod(0o750)
        elif kind=='owner-readonly':top.chmod(0o500)
        elif kind=='create-nested':chosen=inside/'new/deeper/journal'
        elif kind=='parent-not-directory':
            (inside/'file').write_bytes(b'x');chosen=inside/'file/journal'
        else:raise ValueError(kind)
        open_store(p,chosen);p.call(5);p.call(4)
    return steps
def concurrent(kind):
    def steps(p,path,base):
        open_store(p,path);p.call(2,FRAME)
        root=p.root/'second';root.mkdir(mode=0o700)
        q=Process(A.original if p.label=='original' else A.native,root)
        try:
            open_store(q,path);q.call(5)
            if kind=='close-releases':
                p.call(8);open_store(q,path);q.call(3,FRAME);q.call(2,frame(sequence=1));q.call(5)
            elif kind=='second-namespace-does-not-evade-lock':
                changed=bytearray(NS);changed[96]^=1
                open_store(q,path,bytes(changed));q.call(5);p.call(3,FRAME)
            elif kind=='independent-file':
                other=base/'other';open_store(q,other);q.call(2,FRAME);p.call(3,FRAME);q.call(3,FRAME)
            elif kind=='renamed-lock-does-not-authorize-old-owner':
                lock=base/'.journal.lock-v1';lock.rename(base/'old-lock')
                open_store(q,path);p.call(3,FRAME);p.call(2,frame(sequence=1));q.call(3,FRAME)
            else:raise ValueError(kind)
        finally:q.close()
        p.nested.append({'directory':'second','responses':q.responses,'process':q.receipt})
    return steps
try:
    REPORT['native']=identity(A.native.read_bytes());REPORT['original']=identity(A.original.read_bytes())
    REPORT['fixtures']=identity(A.fixtures.read_bytes());REPORT['observer']=identity(Path(__file__).read_bytes())
    for count in (0,4093,4094,4095,4096,4097):execute('directory-entry-bound-'+str(count),directory_count(count))
    for length in (1,100,220,223,224,236,237,240,245,246,255,256):execute('basename-bound-'+str(length),basename_length(length))
    execute('closed-store-namespace-mismatch',namespace_mismatch)
    for kind in ('head','journal','lock'):execute('closed-store-missing-'+kind,missing_after_close(kind))
    for kind in ('symlink','writable','shared','owner-readonly','create-nested','parent-not-directory'):execute('ancestor-'+kind,ancestors(kind))
    for kind in ('close-releases','second-namespace-does-not-evade-lock','independent-file','renamed-lock-does-not-authorize-old-owner'):
        execute('simultaneous-owner-'+kind,concurrent(kind))
    assert len(REPORT['cases'])==32
    assert REPORT['native']==identity(A.native.read_bytes()) and REPORT['original']==identity(A.original.read_bytes())
    REPORT.update(status='PASS_ACTUAL_ORIGINAL_NATIVE_NAMESPACE_AND_LOCK_BOUNDARIES',
        paired_histories=len(REPORT['cases']),paired_calls=sum(r['calls'] for r in REPORT['cases']))
except BaseException as error:REPORT.update(failure=repr(error),traceback=traceback.format_exc());raise
finally:
    REPORT['elapsed_ns']=time.monotonic_ns()-START
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in REPORT.items() if k not in ('cases','traceback')}),flush=True)
