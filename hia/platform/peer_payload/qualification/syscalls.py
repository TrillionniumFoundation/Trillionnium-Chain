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
    def __init__(self, executable, root, injection=None):
        self.root=root;self.responses=[];self.transcript=[];self.finished=False
        self.stderr=(root/'stderr.raw').open('wb')
        self.input=(root/'stdin.raw').open('wb');self.output=(root/'stdout.raw').open('wb')
        self.started=time.monotonic_ns()
        self.executable=Path(executable).absolute()
        self.executable_before=identity(self.executable.read_bytes())
        self.argv=['/usr/bin/strace','-f','-qq','-yy','-s','4096','-o',str(root/'syscalls.raw')]+(['--inject='+injection] if injection else [])+[str(executable)]
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

import re
SYSCALLS=('openat','open','newfstatat','fstat','statx','read','write','fsync','lseek','flock','fchmod','rename','renameat','renameat2')
def trace_calls(path):
    rows=[]
    for line_index,line in enumerate(path.read_text().splitlines()):
        m=re.match(r'^(?:(\d+)\s+)?([a-z0-9_]+)\(',line)
        if m:
            rows.append({'index':line_index,'pid':int(m[1] or 0),'syscall':m[2],'line':line})
    counts={}
    for row in rows:
        counts[row['syscall']]=counts.get(row['syscall'],0)+1
        row['ordinal']=counts[row['syscall']]
    return rows
def comparison_files(base,tracee):
    result=files(base);answer={}
    for name,row in result.items():
        if name.startswith('..journal.head-v1.tmp-'):
            m=re.fullmatch(r'(\.\.journal\.head-v1\.tmp-)(\d+)-(\d+)-(\d+)',name)
            assert m and int(m[2])==tracee,('unbound temporary PID',name,tracee)
            name=m[1]+'$PID-'+m[3]+'-'+m[4]
        assert name not in answer
        answer[name]=row
    return answer
def history(label,executable,root,injection=None):
    root.mkdir(mode=0o700);base=root/'work';base.mkdir(mode=0o700);path=base/'journal'
    p=Process(executable.absolute(),root,injection)
    try:
        open_store(p,path)
        p.call(2,FRAME)
        p.call(3,FRAME)
        p.call(4)
        p.call(8)
        open_store(p,path)
        p.call(3,FRAME)
    finally:p.close()
    trace=trace_calls(root/'syscalls.raw')
    execs=[r for r in trace if r['syscall']=='execve' and str(executable) in r['line']]
    assert len(execs)==1 and execs[0]['pid']>0
    tracee=execs[0]['pid']
    stdout_writes=[r for r in trace if r['syscall']=='write' and re.match(r'^\d+\s+write\(1<',r['line'])]
    # Native replies may be split by the owner; the probe's first open and
    # first admit are each one <=136-byte write in both observed images.
    assert len(stdout_writes)>=2
    result={'responses':[normalized(r,base) for r in p.responses],
        'files':comparison_files(base,tracee)}
    (root/'observed.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    (root/'trace-calls.json').write_text(json.dumps(trace,sort_keys=True,indent=2)+'\n')
    return result,trace,stdout_writes,base
PROBES={}
def select_probes(trace,writes,base):
    phases={'open':[r for r in trace if r['index']<writes[0]['index']],
            'admit':[r for r in trace if writes[0]['index']<r['index']<writes[1]['index']]}
    answer={}
    def select(phase,label,names,predicate,last=False):
        values=[r for r in phases[phase] if r['syscall'] in names and predicate(r['line'])]
        assert values,(phase,label,'actual target absent')
        answer[phase+'-'+label]=values[-1 if last else 0]
    journal=str(base/'journal');head=str(base/'.journal.head-v1');lock=str(base/'.journal.lock-v1')
    isfd=lambda p:(lambda line:p+'>' in line)
    haspath=lambda p:(lambda line:p in line)
    stats=('fstat','newfstatat','statx')
    for phase in ('open','admit'):
        select(phase,'journal-write',('write',),isfd(journal))
        select(phase,'journal-fsync',('fsync',),isfd(journal))
        select(phase,'directory-fsync',('fsync',),isfd(str(base)))
        select(phase,'head-open',('openat','open'),lambda line:'..journal.head-v1.tmp-' in line)
        select(phase,'head-write',('write',),lambda line:'..journal.head-v1.tmp-' in line)
        select(phase,'head-fsync',('fsync',),lambda line:'..journal.head-v1.tmp-' in line)
        select(phase,'head-metadata',stats,lambda line:'..journal.head-v1.tmp-' in line)
        select(phase,'head-rename',('rename','renameat','renameat2'),lambda line:'..journal.head-v1.tmp-' in line)
        select(phase,'published-head-metadata',stats,haspath(head),last=True)
        select(phase,'published-directory-fsync',('fsync',),isfd(str(base)),last=True)
    select('open','directory-open',('openat','open'),lambda line:'"'+str(base)+'"' in line)
    select('open','lock-open',('openat','open'),haspath(lock))
    select('open','lock-flock',('flock',),isfd(lock))
    select('open','journal-open',('openat','open'),haspath(journal))
    select('open','journal-fchmod',('fchmod',),isfd(journal))
    select('open','journal-flock',('flock',),isfd(journal))
    select('admit','journal-metadata',stats,isfd(journal))
    select('admit','journal-seek',('lseek',),isfd(journal))
    select('admit','journal-read',('read',),isfd(journal))
    select('admit','head-read',('read',),isfd(head))
    return answer
def pair(name,phase=None,error=None):
    record={'name':name,'phase':phase,'errno':error,'status':'FAIL'};values=[]
    try:
        for label,executable in [('original',A.original),('native',A.native)]:
            root=OUT/(name+'-'+label)
            target=PROBES[label][phase] if phase else None
            injection=target['syscall']+':error='+error+':when='+str(target['ordinal']) if target else None
            result,trace,writes,base=history(label,executable,root,injection)
            if target:
                injected=[r for r in trace if '(INJECTED)' in r['line']]
                assert len(injected)==1,(label,name,injected)
                actual=injected[0]
                assert actual['syscall']==target['syscall'] and actual['ordinal']==target['ordinal']
                assert '= -1 '+error+' ' in actual['line'],actual
                # The exact original probe target is bound by full phase and
                # pathname, separately for the two actual implementations.
                target_suffix=phase.removeprefix('open-').removeprefix('admit-')
                if target_suffix.startswith('journal-'):assert str(base/'journal') in actual['line']
                elif target_suffix.startswith('lock-'):assert str(base/'.journal.lock-v1') in actual['line']
                elif 'directory' in target_suffix:assert str(base) in actual['line']
                elif target_suffix.startswith('head-'):assert '..journal.head-v1.tmp-' in actual['line'] or str(base/'.journal.head-v1') in actual['line']
                elif target_suffix=='published-head-metadata':assert str(base/'.journal.head-v1') in actual['line']
                else:raise ValueError(target_suffix)
                (root/'injection-selector.json').write_text(json.dumps({'probe':target,'injection':injection,'actual':actual},sort_keys=True,indent=2)+'\n')
            else:
                PROBES[label]=select_probes(trace,writes,base)
                (root/'selectors.json').write_text(json.dumps(PROBES[label],sort_keys=True,indent=2)+'\n')
            values.append(result)
        record.update(status='PASS' if values[0]==values[1] else 'FAIL',original=values[0],native=values[1])
    except BaseException as e:
        record.update(failure=repr(e),traceback=traceback.format_exc())
    REPORT['cases'].append(record)
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k not in ('original','native','traceback')}),flush=True)
    return record['status']=='PASS'
try:
    REPORT['native']=identity(A.native.read_bytes());REPORT['original']=identity(A.original.read_bytes())
    REPORT['fixtures']=identity(A.fixtures.read_bytes());REPORT['observer']=identity(Path(__file__).read_bytes())
    assert pair('probe')
    assert set(PROBES['original'])==set(PROBES['native']) and len(PROBES['original'])==30
    for phase in PROBES['original']:
        for error in ('EIO','EINTR'):
            pair(phase+'-'+error,phase,error)
    assert len(REPORT['cases'])==61
    assert REPORT['native']==identity(A.native.read_bytes()) and REPORT['original']==identity(A.original.read_bytes())
    REPORT.update(status='PASS_ACTUAL_ORIGINAL_NATIVE_SYSCALL_FAULTS' if all(r['status']=='PASS' for r in REPORT['cases']) else 'FAIL',
        paired_histories=len(REPORT['cases']),actual_fault_pairs=60,
        paired_calls=sum(len(r.get('original',{}).get('responses',[])) for r in REPORT['cases']),
        actual_strace_error_injection=True)
except BaseException as e:
    REPORT.update(failure=repr(e),traceback=traceback.format_exc())
finally:
    REPORT['elapsed_ns']=time.monotonic_ns()-START
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in REPORT.items() if k not in ('cases','traceback')}),flush=True)
raise SystemExit(0 if REPORT['status']=='PASS_ACTUAL_ORIGINAL_NATIVE_SYSCALL_FAULTS' else 1)
