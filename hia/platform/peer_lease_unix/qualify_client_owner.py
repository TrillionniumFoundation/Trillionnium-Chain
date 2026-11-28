"""Observe persistent native client values against the unchanged Rust public API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
import traceback

p=argparse.ArgumentParser()
p.add_argument('--native',type=Path,required=True)
p.add_argument('--original',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
out=a.output;out.mkdir(mode=0o700);fs=out/'fs';fs.mkdir(mode=0o700)
rows=[];sessions=[];listener=None;socket_pin=None;socket_replacement=None

def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def socket_identity(value):return {'device':value.st_dev,'inode':value.st_ino,'mode':value.st_mode}
def command(op,ident=0,arg0=0,arg1=0,payload=b''):
    return b'PLUO0001'+struct.pack('<9Q',op,ident,arg0,arg1,len(payload),0,0,0,0)+payload
def word(raw,at=0):return struct.unpack_from('<Q',raw,at)[0]
scope=bytes([1])*32+bytes([2])*32+b'\1'+struct.pack('<Q',9)+bytes([3])*32
token=scope+bytes([4])*32+struct.pack('<QQ',1,123)+bytes([5])*32
def request(method=1):return struct.pack('<Q',method)+scope+bytes([4])*32+struct.pack('<QQQ',1,123,1000)+bytes([5])*32
def frame(body):return b'TPLS'+struct.pack('<I',len(body))+body
VALID=frame(b'\1\0'+token)

class Session:
    def __init__(self,kind,exe):
        self.kind=kind;self.exe=exe;self.dir=out/kind;self.dir.mkdir(mode=0o700);self.sequence=0
        self.err=(self.dir/'stderr.raw').open('wb');self.started=time.monotonic_ns()
        self.child=subprocess.Popen(['strace','-f','-qq','-yy','-s','4096','-o',str(self.dir/'syscalls.raw'),str(exe)],
                                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True)
        os.set_blocking(self.child.stdin.fileno(),False);os.set_blocking(self.child.stdout.fileno(),False)
        deadline=time.monotonic()+2;self.tracee=None
        while time.monotonic()<deadline:
            proc=Path('/proc')/str(self.child.pid)/'task'/str(self.child.pid)/'children'
            children=proc.read_text().split() if proc.exists() else []
            if len(children)==1:
                candidate=int(children[0]);target=Path('/proc')/str(candidate)/'exe'
                if target.exists() and target.resolve()==exe.resolve():self.tracee=candidate;break
            if self.child.poll() is not None:break
            time.sleep(.005)
        if self.tracee is None:raise RuntimeError('Actual tracee identity unavailable')
        self.initial_fds=self.fd_count()
    def fd_count(self):return len(list((Path('/proc')/str(self.tracee)/'fd').iterdir()))
    def io(self,payload,deadline):
        sent=0;received=bytearray();expected=None
        while expected is None or len(received)<expected or sent<len(payload):
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError('Actual owner exchange exceeded 4 seconds')
            reads,writes,_=select.select([self.child.stdout.fileno()],
                [self.child.stdin.fileno()] if sent<len(payload) else [],[],left)
            if writes:
                n=os.write(self.child.stdin.fileno(),payload[sent:sent+65536]);assert n>0;sent+=n
            if reads:
                raw=os.read(self.child.stdout.fileno(),65536)
                if not raw:raise EOFError('Owner ended before response: '+str(self.child.poll()))
                with self.current_stdout.open('ab') as retained:retained.write(raw)
                received.extend(raw)
                if expected is None and len(received)>=32:
                    assert received[:8]==b'PLUR0001';expected=32+word(received,24)
                    assert expected<=4*1024*1024,'Unexpected response extent'
        assert len(received)==expected
        return bytes(received)
    def send(self,payload):
        self.sequence+=1;stem=f'{self.sequence:05d}';(self.dir/(stem+'.stdin.raw')).write_bytes(payload)
        self.current_stdout=self.dir/(stem+'.stdout.raw');self.current_stdout.write_bytes(b'')
        start=time.monotonic_ns()
        try:raw=self.io(payload,time.monotonic()+4)
        except BaseException as error:
            incomplete={'status':'INCOMPLETE_ACTUAL_EXCHANGE','error':repr(error),'index':self.sequence,
                        'input':identity(payload),'partial_stdout':identity(self.current_stdout.read_bytes()),
                        'process_exit_observed':self.child.poll(),'wall_ns':time.monotonic_ns()-start}
            (self.dir/(stem+'.receipt.json')).write_text(json.dumps(incomplete,sort_keys=True)+'\n');raise
        result={'index':self.sequence,'op':word(payload,8),'handle':word(payload,16),
                'input':identity(payload),'stdout':identity(raw),'category':word(raw,8),'code':word(raw,16),
                'payload_bytes':word(raw,24),'wall_ns':time.monotonic_ns()-start,
                'wall_limit_seconds':4,'cleanup_limit_seconds':3}
        (self.dir/(stem+'.receipt.json')).write_text(json.dumps(result,sort_keys=True)+'\n')
        return result,raw
    def finish(self,kill=False):
        if self.child.poll() is None:
            if kill:os.killpg(self.child.pid,signal.SIGKILL)
            else:self.child.stdin.close()
        try:self.child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.child.pid,signal.SIGKILL);self.child.wait(timeout=3)
        self.err.close()
        result={'exit_code':self.child.returncode,'commands':self.sequence,
                'elapsed_ns':time.monotonic_ns()-self.started,'tracee_pid':self.tracee,
                'executable':identity(self.exe.read_bytes()),
                'stderr':identity((self.dir/'stderr.raw').read_bytes()),
                'syscalls':identity((self.dir/'syscalls.raw').read_bytes()),'forced_cleanup':kill}
        (self.dir/'process.json').write_text(json.dumps(result,sort_keys=True)+'\n');return result

class Server:
    def __init__(self,reply,chunk=None,delay=0):
        self.reply=reply;self.chunk=chunk;self.delay=delay;self.stop=threading.Event()
        self.request=b'';self.sent=0;self.error=None;self.thread=threading.Thread(target=self.run)
    def run(self):
        conn=None
        try:
            listener.settimeout(.05)
            while not self.stop.is_set():
                try:conn,_=listener.accept();break
                except TimeoutError:continue
            if conn is None:return
            conn.settimeout(1)
            while len(self.request)<203:
                raw=conn.recv(203-len(self.request))
                if not raw:return
                self.request+=raw
            for at in range(0,len(self.reply),self.chunk or max(1,len(self.reply))):
                if self.stop.wait(self.delay):break
                raw=self.reply[at:at+(self.chunk or len(self.reply))];conn.sendall(raw);self.sent+=len(raw)
        except (BrokenPipeError,ConnectionResetError) as error:self.error=type(error).__name__
        except BaseException as error:self.error=repr(error)
        finally:
            if conn is not None:conn.close()
    def finish(self):
        self.stop.set();self.thread.join(2);assert not self.thread.is_alive()
        return {'request':identity(self.request),'request_hex':self.request.hex(),'sent':self.sent,'error':self.error}

def case(name,op,ident=0,arg0=0,arg1=0,payload=b'',reply=None,chunk=None,delay=0,expected=None):
    payload=command(op,ident,arg0,arg1,payload);pair=[];peers=[];entry={'name':name,'op':op,'handle':ident}
    before=sorted(x.name for x in fs.iterdir())
    try:
        for s in sessions:
            server=Server(reply,chunk,delay) if reply is not None else None
            if server:server.thread.start()
            try:pair.append(s.send(payload))
            finally:peers.append(server.finish() if server else None)
        checks={'exact_reply':pair[0][1]==pair[1][1],
                'no_client_filesystem_mutation':before==sorted(x.name for x in fs.iterdir())}
        if op==10:
            # The original observer exposes only its actual live object count.
            # Arena accounting is private HIA state, independently checked below.
            checks['exact_reply']=pair[0][1][:24]==pair[1][1][:24] and pair[0][1][32:]==pair[1][1][32:40]
            checks['native_stats_extent']=len(pair[1][1])==72
        if expected is not None:checks['expected_status']=(pair[0][0]['category'],pair[0][0]['code'])==expected
        if reply is not None:checks['same_actual_request']=peers[0]['request_hex']==peers[1]['request_hex'] and peers[0]['request']['bytes']==203
        entry.update(status='PASS' if all(checks.values()) else 'FAIL',checks=checks,
                     original=pair[0][0],native=pair[1][0],actual_peers=peers)
        if not all(checks.values()):
            entry.update(original_stdout=pair[0][1].hex(),native_stdout=pair[1][1].hex());raise AssertionError('Differential mismatch '+name)
        return pair[1][1][32:]
    except BaseException as error:
        entry.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        rows.append(entry)
        with (out/'progress.jsonl').open('a') as progress:progress.write(json.dumps(entry,sort_keys=True)+'\n')

def new(path,name):return word(case(name,1,payload=path,expected=(0,0)))
def clone(ident,name):return word(case(name,2,ident,expected=(0,0)))
def stats(name):return struct.unpack('<5Q',case(name,10,expected=(0,0)))
def call(name,ident,method=1,reply=VALID,expected=(0,0),**options):
    return case(name,8,ident,payload=request(method),reply=reply,expected=expected,**options)

processes=[];failure=None;accounting=[];fd_observations=[]
try:
    sessions=[Session('original',a.original),Session('native',a.native)]
    assert stats('initial-empty')==(0,0,0,0,0)
    # Both public observers have now reached their input loop, so transient
    # dynamic-loader descriptors cannot be mistaken for an owner leak.
    for session in sessions:session.initial_fds=session.fd_count()
    paths=[b'',b'relative',b'/',b'/tmp/../alias',b'/tmp/./dot',b'embedded\0nul',b'\xff\xfe',
           b'/'+b'x'*104,b'/'+b'x'*65536,b'/'+b'x'*(1<<20)]
    for i,path in enumerate(paths):
        ident=new(path,f'path-{i}-create');assert case(f'path-{i}-get',5,ident,expected=(0,0))==path
        copied=clone(ident,f'path-{i}-clone');case(f'path-{i}-drop-original',9,ident,expected=(0,0))
        assert case(f'path-{i}-clone-independent',5,copied,expected=(0,0))==path
        case(f'path-{i}-stale-handle',5,ident,expected=(100,100));case(f'path-{i}-drop-clone',9,copied,expected=(0,0))
        assert stats(f'path-{i}-empty')==(0,0,0,0,0)
    live=[]
    for i in range(513):live.append((new(b'object/'+str(i).encode(),f'many-create-{i}'),b'object/'+str(i).encode()))
    for i in range(0,len(live),17):
        ident,path=live[i];live.append((clone(ident,f'many-clone-{i}'),path))
    observed=stats('more-than-64-live');assert observed[0]==len(live)>513;accounting.append({'name':'more-than-64-live','values':observed})
    for i,(ident,path) in enumerate(reversed(live)):
        assert case(f'many-get-{i}',5,ident,expected=(0,0))==path
        case(f'many-drop-{i}',9,ident,expected=(0,0))
    assert stats('many-all-released')==(0,0,0,0,0)
    big=new(b'x'*65537,'reuse-large');keep=new(b'kept','reuse-kept');before=stats('reuse-before')
    case('reuse-release-large',9,big,expected=(0,0));small=new(b'small','reuse-small');after=stats('reuse-after')
    assert before[1:3]==after[1:3] and before[0]==after[0]==2
    accounting.append({'name':'released-large-block-reused','before':before,'after':after})
    case('reuse-release-small',9,small,expected=(0,0));case('reuse-release-kept',9,keep,expected=(0,0));assert stats('reuse-empty')==(0,0,0,0,0)

    path=fs/'lease.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));listener.listen(16);path.chmod(0o600)
    initial_socket=socket_identity(path.lstat());initial_parent=socket_identity(fs.lstat())
    assert stat.S_ISSOCK(initial_socket['mode']) and stat.S_IMODE(initial_socket['mode'])==0o600
    base=new(os.fsencode(path),'socket-create');case('socket-preflight',6,base,expected=(0,0));binding=case('socket-binding',7,base,expected=(0,0));assert len(binding)==32
    for method in (1,2,3,4):call('retained-method-'+str(method),base,method)
    for code in (1,6,12):call('rejection-'+str(code),base,reply=frame(bytes([1,1,code])),expected=(4,code))
    call('recover-after-rejections',base)
    call('malformed-reply',base,reply=b'NOPE'+bytes(4),expected=(3,20));call('recover-after-malformed',base)
    call('partial-eof',base,reply=VALID[:10],expected=(2,4099));call('recover-after-eof',base)
    case('set-expired-deadline',4,base,0,0,expected=(0,0));expired=clone(base,'clone-expired-deadline')
    call('expired-base',base,reply=None,expected=(2,4098));call('expired-clone',expired,reply=None,expected=(2,4098))
    case('timeout-clears-base-deadline',3,base,1,0,expected=(0,0));call('cleared-base-works',base)
    call('clone-still-expired',expired,reply=None,expected=(2,4098))
    independent=clone(base,'clone-independent-timeout');case('zero-base-timeout',3,base,0,0,expected=(0,0))
    call('base-now-zero',base,reply=None,expected=(2,4098));call('clone-keeps-timeout',independent)
    case('zero-timeout-preflight',6,base,expected=(0,0));assert case('zero-timeout-binding',7,base,expected=(0,0))==binding
    case('set-short-timeout',3,independent,0,150_000_000,expected=(0,0))
    call('retained-owner-single-read-deadline',independent,chunk=1,delay=.02,expected=(2,4098))
    case('restore-normal-timeout',3,independent,1,0,expected=(0,0));call('recover-after-deadline',independent)
    deadline=time.monotonic_ns()+700_000_000;seconds,nanos=divmod(deadline,1_000_000_000)
    case('set-shared-absolute-deadline',4,independent,seconds,nanos,expected=(0,0));shared=clone(independent,'clone-shared-deadline')
    call('first-before-absolute-deadline',independent);call('clone-before-absolute-deadline',shared)
    time.sleep(max(0,(deadline+30_000_000-time.monotonic_ns())/1_000_000_000))
    call('same-object-no-renewal',independent,reply=None,expected=(2,4098));call('clone-no-renewal',shared,reply=None,expected=(2,4098))
    case('reset-one-clone-timeout',3,shared,1,0,expected=(0,0));call('reset-clone-works',shared);call('other-stays-expired',independent,reply=None,expected=(2,4098))
    case('maximum-timeout',3,shared,(1<<64)-1,0,expected=(0,0));call('maximum-timeout-overflow',shared,reply=None,expected=(2,4098))
    deadline=time.monotonic_ns()+2_000_000_000;seconds,nanos=divmod(deadline,1_000_000_000)
    case('deadline-overrides-huge-timeout',4,shared,seconds,nanos,expected=(0,0));call('explicit-deadline-works',shared)
    invalid=new(b'relative','invalid-path-expired-owner');case('invalid-path-expired-setting',4,invalid,0,0,expected=(0,0))
    call('invalid-path-priority-before-expired-connect',invalid,reply=None,expected=(1,1002));case('invalid-path-drop',9,invalid,expected=(0,0))
    for s in sessions:
        observed=s.fd_count();fd_observations.append({'kind':s.kind,'before':s.initial_fds,'after_network_calls':observed});assert observed==s.initial_fds
    # Pin the pathname inode, not the unrelated sockfs inode of listener.fileno().
    # Without this live O_PATH reference, close/unlink/bind may reuse the same
    # inode and the unchanged public binding digest correctly remains equal.
    pin_flags=os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC
    socket_pin=os.open(path,pin_flags)
    pinned_before=socket_identity(os.fstat(socket_pin));pin_opened=time.monotonic_ns()
    assert pinned_before==initial_socket==socket_identity(path.lstat())
    assert stat.S_ISSOCK(pinned_before['mode'])
    listener.close();listener=None;path.unlink()
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));listener.listen(16);path.chmod(0o600)
    replacement_before=socket_identity(path.lstat());rebound_before=time.monotonic_ns()
    assert stat.S_ISSOCK(replacement_before['mode']) and stat.S_IMODE(replacement_before['mode'])==0o600
    assert (replacement_before['device'],replacement_before['inode'])!=(initial_socket['device'],initial_socket['inode'])
    rebound=case('same-object-observes-replaced-socket',7,shared,expected=(0,0));assert rebound!=binding
    pinned_after=socket_identity(os.fstat(socket_pin));replacement_after=socket_identity(path.lstat())
    parent_after=socket_identity(fs.lstat());rebound_after=time.monotonic_ns()
    assert pinned_after==pinned_before and replacement_after==replacement_before and parent_after==initial_parent
    os.close(socket_pin);socket_pin=None;pin_closed=time.monotonic_ns()
    socket_replacement={'schema':'trnm.hia.peer-unix.socket-replacement.v1','status':'PASS',
        'path_hex':os.fsencode(path).hex(),'parent_path_hex':os.fsencode(fs).hex(),
        'original_socket':initial_socket,'pinned_before_unlink':pinned_before,'pinned_after_capture':pinned_after,
        'replacement_before_capture':replacement_before,'replacement_after_capture':replacement_after,
        'parent_before':initial_parent,'parent_after':parent_after,'pin_open_flags':pin_flags,'pin_closed':True,
        'opened_ns':pin_opened,'rebound_before_ns':rebound_before,'rebound_after_ns':rebound_after,'closed_ns':pin_closed}
    replacement_raw=(json.dumps(socket_replacement,sort_keys=True)+'\n').encode()
    (out/'socket-replacement.json').write_bytes(replacement_raw)
    case('replacement-reset-timeout',3,shared,1,0,expected=(0,0));call('same-object-connects-fresh-socket',shared)
    for ident,name in ((base,'base'),(expired,'expired'),(independent,'independent'),(shared,'shared')):case('final-drop-'+name,9,ident,expected=(0,0))
    assert stats('final-zero-owned-objects')==(0,0,0,0,0)
    case('explicit-session-exit',11,expected=(0,0))
except BaseException as error:
    failure={'error':repr(error),'traceback':traceback.format_exc()}
finally:
    if socket_pin is not None:os.close(socket_pin)
    if listener is not None:listener.close()
    for session in sessions:processes.append(session.finish(kill=failure is not None))
report={'status':'PASS' if failure is None and all(x['status']=='PASS' for x in rows) and all(x['exit_code']==0 for x in processes) else 'FAIL',
        'total':len(rows),'passed':sum(x['status']=='PASS' for x in rows),'actual_native_calls':sessions[1].sequence if len(sessions)>1 else 0,
        'actual_original_calls':sessions[0].sequence if sessions else 0,'cases':rows,'failure':failure,'processes':processes,
        'native_private_arena_observations':accounting,'fd_observations':fd_observations,
        'socket_replacement':identity(replacement_raw) if socket_replacement is not None else None,
        'original_methods_are_unchanged':True,'runtime_fallback':False,
        'limits':{'borrowed_foreign_pointer_ABI_qualified':False,'concurrent_invocation_on_one_arena_qualified':False,
                  'whole_peer_owner_qualified':False,'original_service_budget_qualified':False,
                  'arena_mapping':'Retained grow-only native provider; freed logical blocks are reused; no physical mapping shrink claim'}}
(out/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('cases',)},sort_keys=True));raise SystemExit(report['status']!='PASS')
