"""Observe both actual daemon implementations, including finite hostile peers."""
import argparse,hashlib,json,os,pathlib,signal,socket,stat,struct,subprocess,time,traceback
from traced_process import finish_traced
p=argparse.ArgumentParser()
p.add_argument('--native',type=pathlib.Path,required=True)
p.add_argument('--original',type=pathlib.Path,required=True)
p.add_argument('--output',type=pathlib.Path,required=True)
a=p.parse_args();out=a.output;out.mkdir(mode=0o700);rows=[]
MAX=(1<<64)-1
def word(b,at=0):return struct.unpack_from('<Q',b,at)[0]
def ident(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def words(*v):return struct.pack('<'+'Q'*len(v),*v)
def frame(b):return b'TPLS'+struct.pack('<I',len(b))+b
SCOPE=b'\1'*32+b'\2'*32+b'\1'+words(9)+b'\3'*32
def token(scope=SCOPE,session=b'\4'*32,generation=1,expiry=0,hash_bytes=bytes(32)):
 return scope+session+words(generation,expiry)+hash_bytes
def request(op=1,t=None,ttl=30000):
 t=token() if t is None else t
 return frame(bytes([1,op])+t[:153]+words(ttl)+t[153:])
def config(s,j,ns=500_000_000):
 s=os.fsencode(s);j=os.fsencode(j);sec,nano=divmod(ns,1_000_000_000)
 return b'PLUN0001'+words(1,len(s),len(j),0,sec,nano)+s+j
def read_all(conn,timeout=4):
 conn.settimeout(timeout);data=bytearray()
 while True:
  try:b=conn.recv(65536)
  except ConnectionResetError:break
  if not b:break
  data+=b
 return bytes(data)
def normalized(b):
 if len(b)==195 and b[:10]==frame(bytes(187))[:8]+b'\1\0':
  return b[:155]+bytes(40)
 return b
def check_store(root):
 j=(root/'j').read_bytes();head=(root/'.j.head-v1').read_bytes()
 assert len(j)%236==0
 prior=bytes(32);result=[]
 for at in range(0,len(j),236):
  r=j[at:at+236];assert r[:5]==b'TPLR\1' and r[6:10]==struct.pack('<I',162)
  assert r[10:42]==prior and hashlib.sha256(r[:204]).digest()==r[204:]
  assert r[5]==r[42];prior=r[204:]
  result.append({'operation':r[5],'scope':r[43:148].hex(),'session':r[148:180].hex(),
    'generation':word(r,180),'expiry':word(r,188),'observed_now':word(r,196),'hash':prior.hex()})
 assert len(head)==80 and head[:8]==b'TPLH\1\0\0\0' and word(head,8)==len(result) and head[16:48]==prior
 assert head[48:]==hashlib.sha256(b'TPLH'+words(48)+head[:48]).digest()
 for path in [root/'j',root/'.j.head-v1',root/'j.lease-lock']:assert stat.S_IMODE(path.stat().st_mode)==0o600
 return result
class Daemon:
 def __init__(self,exe,root,ns=500_000_000,*,socket_path=None,journal_path=None,name='daemon'):
  self.root=root;self.directory=root/name;self.directory.mkdir(mode=0o700)
  self.fs=root/'fs';self.fs.mkdir(mode=0o700,exist_ok=True)
  self.path=self.fs/'s' if socket_path is None else socket_path
  self.journal=self.fs/'j' if journal_path is None else journal_path
  self.payload=config(self.path,self.journal,ns);(self.directory/'stdin.raw').write_bytes(self.payload)
  self.stdout=(self.directory/'stdout.raw').open('wb');self.stderr=(self.directory/'stderr.raw').open('wb')
  self.argv=['strace','-f','-qq','-yy','-s','4096','-o',str(self.directory/'syscalls.raw'),str(exe)]
  self.started=time.monotonic_ns()
  self.child=subprocess.Popen(self.argv,stdin=subprocess.PIPE,stdout=self.stdout,stderr=self.stderr,start_new_session=True)
  self.child.stdin.write(self.payload);self.child.stdin.close();self.operations=[];self.owner_exe=exe
 def ready(self):
  deadline=time.monotonic()+4
  while self.child.poll() is None and time.monotonic()<deadline:
   try:
    if stat.S_ISSOCK(pathlib.Path(self.path).lstat().st_mode) and stat.S_IMODE(pathlib.Path(self.path).stat().st_mode)==0o600:return
   except FileNotFoundError:pass
   time.sleep(.002)
  raise AssertionError(('daemon not ready',self.child.poll()))
 def exchange(self,label,data,*,fragments=None,half_close=False):
  started=time.monotonic_ns();d=self.directory/('request-'+str(len(self.operations)).zfill(4));d.mkdir()
  (d/'request.raw').write_bytes(data)
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
   c.settimeout(4);c.connect(str(self.path))
   if fragments:
    for i in range(0,len(data),fragments):c.sendall(data[i:i+fragments])
   else:c.sendall(data)
   if half_close:c.shutdown(socket.SHUT_WR)
   reply=read_all(c)
  (d/'response.raw').write_bytes(reply)
  self.operations.append({'label':label,'input':ident(data),'output':ident(reply),'elapsed_ns':time.monotonic_ns()-started})
  assert time.monotonic_ns()-started<4_000_000_000
  return reply
 def finish(self,*,terminal=False):
  code,termination=finish_traced(self.child,self.owner_exe,terminal=terminal)
  self.stdout.close();self.stderr.close()
  r={'argv':self.argv,'pid':self.child.pid,'exit_code':code,'terminal_expected':terminal,'operations':self.operations,'termination':termination,
    'executable':ident(self.owner_exe.read_bytes()),'elapsed_ns':time.monotonic_ns()-self.started,
    'input':ident(self.payload),'stdout':ident((self.directory/'stdout.raw').read_bytes()),
    'stderr':ident((self.directory/'stderr.raw').read_bytes()),'trace':ident((self.directory/'syscalls.raw').read_bytes())}
  (self.directory/'receipt.json').write_text(json.dumps(r,sort_keys=True)+'\n');return r
def pair(name,body):
 d=out/name;d.mkdir(mode=0o700);r={'name':name};answers=[]
 try:
  for label,exe in [('original',a.original),('native',a.native)]:
   root=d/label;root.mkdir(mode=0o700);answers.append(body(exe,root))
  r.update(status='PASS' if answers[0]==answers[1] else 'FAIL',original=answers[0],native=answers[1])
 except BaseException as e:r.update(status='FAIL',failure=repr(e),traceback=traceback.format_exc())
 rows.append(r);(out/'progress.json').write_text(json.dumps(rows,sort_keys=True)+'\n')
def error_case(exe,root,ns,suffix=None):
 fs=root/'fs';fs.mkdir(mode=0o700);s=fs/'s';j=fs/'j'
 if suffix=='relative':s='relative'
 if suffix=='collision':s=j
 if suffix=='occupied':s.write_bytes(b'preserve')
 daemon=Daemon(exe,root,ns,socket_path=s,journal_path=j)
 try:
  daemon.finish(terminal=True)
  reply=(daemon.directory/'stdout.raw').read_bytes();stderr=(daemon.directory/'stderr.raw').read_bytes()
  assert len(reply)==24 and reply[:8]==b'PLUR0001' and not stderr and daemon.child.returncode==0
  return {'reply':reply.hex(),'socket_present':pathlib.Path(s).exists() if suffix!='relative' else False,
    'journal_present':j.exists(),'filesystem':sorted(q.name for q in fs.iterdir())}
 finally:
  if daemon.child.poll() is None:daemon.finish()
for name,ns,suffix in [('zero-timeout',0,None),('zero-before-path',0,'relative'),('zero-before-collision',0,'collision'),
 ('zero-before-occupied',0,'occupied'),('max-timeout',MAX*1_000_000_000,None),
 ('poll-i64-overflow',(1<<63)*1_000_000_000,None),('positive-relative',1_000_000,'relative')]:
 pair(name,lambda exe,root,ns=ns,suffix=suffix:error_case(exe,root,ns,suffix))
def lifecycle(exe,root):
 daemon=Daemon(exe,root,1_000_000_000);answers=[]
 try:
  daemon.ready()
  def exchange(name,data,expect):
   raw=daemon.exchange(name,data);assert raw[9]==expect
   answers.append({'name':name,'response':normalized(raw).hex()});return raw
  acquired=exchange('acquire',request(),0)[10:]
  again=exchange('idempotent-acquire',request(),0)[10:];assert again==acquired
  exchange('busy',request(t=token(session=b'\5'*32,generation=2)),1)
  renewed=exchange('renew',request(2,acquired,60000),0)[10:]
  exchange('old-token-context',request(3,acquired,0),1)
  assert exchange('revalidate',request(3,renewed,0),0)[10:]==renewed
  released=exchange('release',request(4,renewed,0),0)[10:];assert word(released,145)==0
  exchange('missing',request(3,renewed,0),1)
  exchange('stale-generation',request(t=token(session=b'\6'*32,generation=1)),1)
  exchange('new-generation',request(t=token(session=b'\6'*32,generation=2)),0)
  records=check_store(daemon.fs);assert [x['operation'] for x in records]==[1,2,4,1]
  for x in records:
   if x['operation']!=4:assert x['expiry']>x['observed_now']
  return {'answers':answers,'durable_operations':[x['operation'] for x in records],'daemon_alive':daemon.child.poll() is None}
 finally:daemon.finish()
pair('complete-lifecycle',lifecycle)
def invalid_frames(exe,root):
 daemon=Daemon(exe,root,500_000_000);answers=[]
 try:
  daemon.ready();good=request();cases=[('bad-magic',b'BAD!'+struct.pack('<I',0)),
    ('too-large',b'TPLS'+struct.pack('<I',16385))]
  cases += [('complete-short-'+str(n),frame(good[8:8+n])) for n in range(195)]
  cases += [('trailing-'+str(n),frame(good[8:]+bytes(n-195))) for n in [196,256,4096,16384]]
  cases += [('eof-'+str(n),good[:n]) for n in [0,1,7,8,9,100,202]]
  for name,raw in cases:
   reply=daemon.exchange(name,raw,half_close=True);assert reply==b'';answers.append(name)
  assert check_store(daemon.fs)==[]
  reply=daemon.exchange('live-after-refusals',request());assert len(reply)==195
  return {'rejected':answers,'later_valid':normalized(reply).hex(),'alive':daemon.child.poll() is None}
 finally:daemon.finish()
pair('complete-malformed-frame-boundaries',invalid_frames)
def fragments(exe,root):
 daemon=Daemon(exe,root,1_000_000_000);answers=[]
 try:
  daemon.ready()
  for size in [1,2,3,7,8,16,64,201,203]:
   scope=SCOPE[:-32]+bytes([size%250+1])*32
   raw=daemon.exchange('fragment-'+str(size),request(t=token(scope=scope)),fragments=size)
   assert len(raw)==195;answers.append(normalized(raw).hex())
  assert len(check_store(daemon.fs))==9
  return answers
 finally:daemon.finish()
pair('fragmented-complete-requests',fragments)
def capacity(exe,root,count):
 daemon=Daemon(exe,root,250_000_000);held=[]
 try:
  daemon.ready()
  for _ in range(count):
   c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(4);c.connect(str(daemon.path));c.sendall(b'T');held.append(c)
  start=time.monotonic_ns();response=daemon.exchange('honest-at-capacity',request());elapsed=time.monotonic_ns()-start
  assert len(response)==195 and elapsed<2_000_000_000
  closed=0
  for c in held:
   if read_all(c)==b'':closed+=1
  assert closed==count
  assert len(check_store(daemon.fs))==1
  (root/'timing.json').write_text(json.dumps({'stalled_clients':count,'honest_elapsed_ns':elapsed})+'\n')
  return {'clients':count,'closed':closed,'honest_response':normalized(response).hex(),'alive':daemon.child.poll() is None}
 finally:
  for c in held:c.close()
  daemon.finish()
for count in [1,16,63,64,65,80]:pair('capacity-'+str(count),lambda exe,root,count=count:capacity(exe,root,count))
def shared_deadline(exe,root):
 daemon=Daemon(exe,root,150_000_000);c=None
 try:
  daemon.ready();c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(4);c.connect(str(daemon.path));raw=request()
  start=time.monotonic_ns();sent=0
  for b in raw[:20]:
   try:c.sendall(bytes([b]));sent+=1
   except (BrokenPipeError,ConnectionResetError):break
   time.sleep(.04)
  response=read_all(c);assert not response and sent<20 and time.monotonic_ns()-start<1_000_000_000
  assert check_store(daemon.fs)==[]
  valid=daemon.exchange('after-expired-peer',raw);assert len(valid)==195
  return {'partial_disconnected':True,'no_partial_mutation':True,'valid':normalized(valid).hex(),'alive':daemon.child.poll() is None}
 finally:
  if c:c.close()
  daemon.finish()
pair('one-absolute-connection-deadline',shared_deadline)
def restart(exe,root):
 daemon=Daemon(exe,root,1_000_000_000);second=None
 try:
  daemon.ready();first=daemon.exchange('acquire-before-restart',request());assert len(first)==195
  snapshot=(daemon.fs/'j').read_bytes();daemon.finish()
  assert daemon.child.poll() is not None;daemon.path.unlink()
  second=Daemon(exe,root,1_000_000_000,name='restarted');second.ready()
  again=second.exchange('idempotent-after-restart',request());assert first==again and (second.fs/'j').read_bytes()==snapshot
  assert second.exchange('revalidate-after-restart',request(3,first[10:],0))==first
  assert len(check_store(second.fs))==1
  return {'before':normalized(first).hex(),'after':normalized(again).hex(),'same_exact_token_within_implementation':True,'same_journal':True}
 finally:
  if daemon.child.poll() is None:daemon.finish()
  if second:second.finish()
pair('durable-restart-and-idempotence',restart)
report={'status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','passed':sum(r['status']=='PASS' for r in rows),
 'total':len(rows),'cases':rows,'actual_original_public_API':True,'actual_native_static_ELF':True,
 'normalization':'Only successful token expiry and record hash differ across independent real-time histories; each full journal digest chain and head is verified, and idempotent/restart tokens compare exactly within each implementation.'}
(out/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'passed':report['passed'],'total':report['total'],'failures':[r for r in rows if r['status']!='PASS']},sort_keys=True))
raise SystemExit(report['status']!='PASS')

