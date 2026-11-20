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
        self.root=root;self.responses=[];self.transcript=[];self.finished=False
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

import re
from owned_trace import run as traced

def disk_after_cut(base,pid):
    source=files(base);answer={}
    for name,row in source.items():
        if name.startswith('..journal.head-v1.tmp-'):
            m=re.fullmatch(r'(\.\.journal\.head-v1\.tmp-)(\d+)-(\d+)-(\d+)',name)
            assert m and int(m[2])==pid,('unbound crashed process PID',name,pid)
            name=m[1]+'$PID-'+m[3]+'-'+m[4]
        assert name not in answer
        answer[name]=row
    return answer

def cut(phase):
    row={'name':phase,'status':'FAIL'};answers=[]
    try:
        for label,executable in [('original',A.original),('native',A.native)]:
            root=OUT/(phase+'-'+label);root.mkdir(mode=0o700)
            base=root/'work';base.mkdir(mode=0o700);path=base/'journal'
            raw=os.fsencode(path)
            payload=request(1,NS+u64(len(raw))+raw)+request(2,FRAME)+request(3,FRAME)+request(9)
            evidence=root/'trace'
            trace=traced(executable,payload,evidence,storage=base,target=phase,inject=False)
            assert trace['status']=='PASS' and trace['signal']==signal.SIGKILL
            assert len(trace['actions'])==1 and trace['actions'][0]['kind']=='SIGKILL-after-real-syscall'
            action=trace['actions'][0]
            entry=next(r for r in trace['events'] if r['sequence']==action['entry'])
            exit=next(r for r in trace['events'] if r['sequence']==action['exit'])
            assert entry['kind']=='entry' and exit['kind']=='exit' and exit['entry']==entry['sequence']
            assert entry['storage_stage']==phase and exit['storage_stage']==phase
            assert exit['kernel_result']==exit['result'] and exit['result']>=0
            output=(evidence/'stdout.raw').read_bytes()
            assert not (evidence/'stderr.raw').read_bytes()
            assert len(output)==(96 if phase.startswith('admit-') else 0)
            before=disk_after_cut(base,trace['pid'])
            saved=root/'before-reopen';saved.mkdir(mode=0o700)
            retained={}
            for item in sorted(base.rglob('*')):
                if item.is_file() and not item.is_symlink():
                    key=item.relative_to(base).as_posix();target=saved/key;target.parent.mkdir(parents=True,exist_ok=True)
                    raw=item.read_bytes();target.write_bytes(raw);retained[key]=identity(raw)
            (root/'before-reopen-files.json').write_text(json.dumps(retained,sort_keys=True,indent=2)+'\n')
            d=root/'reopened';d.mkdir(mode=0o700)
            p=Process(executable,d)
            try:
                open_store(p,path);p.call(3,FRAME);p.call(4);p.call(5)
            finally:p.close()
            result={'crashed_output_hex':output.hex(),'before_reopen':before,
                'reopened':[normalized(r,base) for r in p.responses],
                'after_reopen':disk_after_cut(base,trace['pid'])}
            (root/'observed.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
            answers.append(result)
        row.update(status='PASS' if answers[0]==answers[1] else 'FAIL',original=answers[0],native=answers[1])
    except BaseException as e:row.update(failure=repr(e),traceback=traceback.format_exc())
    REPORT['cases'].append(row)
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in row.items() if k not in ('original','native','traceback')}),flush=True)
try:
    REPORT['native']=identity(A.native.read_bytes());REPORT['original']=identity(A.original.read_bytes())
    REPORT['fixtures']=identity(A.fixtures.read_bytes());REPORT['observer']=identity(Path(__file__).read_bytes())
    REPORT['tracer']=identity(Path(__file__).with_name('owned_trace.py').read_bytes())
    for context in ('open','admit'):
        for stage in ('journal-write','journal-fsync','directory-fsync','head-write','head-fsync','head-rename','published-directory-fsync'):
            cut(context+'-'+stage)
    assert len(REPORT['cases'])==14
    assert REPORT['native']==identity(A.native.read_bytes()) and REPORT['original']==identity(A.original.read_bytes())
    REPORT.update(status='PASS_ACTUAL_ORIGINAL_NATIVE_DURABILITY_CUTS' if all(r['status']=='PASS' for r in REPORT['cases']) else 'FAIL',
        paired_histories=14,actual_successful_syscall_cuts=28,power_failure_claimed=False)
except BaseException as e:REPORT.update(failure=repr(e),traceback=traceback.format_exc())
finally:
    REPORT['elapsed_ns']=time.monotonic_ns()-START
    (OUT/'report.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in REPORT.items() if k not in ('cases','traceback')}),flush=True)
raise SystemExit(0 if REPORT['status']=='PASS_ACTUAL_ORIGINAL_NATIVE_DURABILITY_CUTS' else 1)
