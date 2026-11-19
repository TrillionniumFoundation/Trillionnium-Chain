"""Observe both actual daemon implementations, including finite hostile peers."""
import argparse,hashlib,json,os,pathlib,signal,socket,stat,struct,subprocess,time,traceback,re
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
 def __init__(self,exe,root,ns=500_000_000,*,socket_path=None,journal_path=None,name='daemon',inject=None):
  self.root=root;self.directory=root/name;self.directory.mkdir(mode=0o700)
  self.fs=root/'fs';self.fs.mkdir(mode=0o700,exist_ok=True)
  self.path=self.fs/'s' if socket_path is None else socket_path
  self.journal=self.fs/'j' if journal_path is None else journal_path
  self.payload=config(self.path,self.journal,ns);(self.directory/'stdin.raw').write_bytes(self.payload)
  self.stdout=(self.directory/'stdout.raw').open('wb');self.stderr=(self.directory/'stderr.raw').open('wb')
  self.argv=['strace','-f','-qq','-yy','-s','4096','-o',str(self.directory/'syscalls.raw')]+(['--inject='+inject] if inject else [])+[str(exe)]
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
PROBES={}
def filesystem_state(root):
 journal=(root/'j').read_bytes();assert len(journal) in (0,236)
 last=bytes(32)
 if journal:
  assert journal[:5]==b'TPLR\1' and journal[5]==1 and journal[6:10]==struct.pack('<I',162)
  assert journal[10:42]==bytes(32) and journal[42:148]==b'\1'+SCOPE and journal[148:180]==b'\4'*32
  assert word(journal,180)==1 and word(journal,188)==word(journal,196)+30000
  assert hashlib.sha256(journal[:204]).digest()==journal[204:];last=journal[204:]
 result={'journal_records':len(journal)//236,'journal_mode':stat.S_IMODE((root/'j').stat().st_mode),'socket_present':(root/'s').exists(),'heads':[]}
 for p in sorted(root.iterdir()):
  if '.head-v1' not in p.name:continue
  b=p.read_bytes();assert len(b) in (0,80)
  if b:
   assert b[:8]==b'TPLH\1\0\0\0' and word(b,8) in (0,1)
   assert b[16:48]==(last if word(b,8) else bytes(32))
   assert b[48:]==hashlib.sha256(b'TPLH'+words(48)+b[:48]).digest()
  result['heads'].append({'kind':'temporary' if '.tmp-' in p.name else 'head','bytes':len(b),'count':word(b,8) if b else None,'mode':stat.S_IMODE(p.stat().st_mode)})
 (root.parent/'physical-state.json').write_text(json.dumps({'comparison':result,'files':[{'name':p.name,'mode':p.lstat().st_mode,**ident(p.read_bytes())} for p in sorted(root.iterdir()) if p.is_file()]},sort_keys=True,indent=2)+'\n')
 return result
def trace_calls(path):
 result=[]
 for index,line in enumerate(path.read_text().splitlines()):
  match=re.match(r'^(?:\d+\s+)?([a-z0-9_]+)\(',line)
  if match:result.append({'index':index,'syscall':match[1],'line':line})
 return result
def probe(exe,root):
 daemon=Daemon(exe,root,1_000_000_000);receipt=None
 try:
  daemon.ready();response=daemon.exchange('unmodified-acquire',request());assert len(response)==195
  receipt=daemon.finish();calls=trace_calls(daemon.directory/'syscalls.raw')
  auth=[x for x in calls if x['syscall']=='getsockopt' and 'SO_PEERCRED' in x['line']];assert len(auth)==1
  after=[x for x in calls if x['index']>auth[0]['index']]
  def select(name,values,last=False):
   assert values,(name,'missing actual probe syscall')
   selected=dict(values[-1] if last else values[0]);selected['ordinal']=sum(x['syscall']==selected['syscall'] and x['index']<=selected['index'] for x in calls);return selected
  selectors={}
  for phase,names,needle in [
   ('journal-write',('write',),str(daemon.fs/'j')+'>'),
   ('journal-metadata',('fstat','newfstatat','statx','fstat64'),str(daemon.fs/'j')+'>'),
   ('journal-fsync',('fsync',),str(daemon.fs/'j')+'>'),
   ('head-write',('write',),'..j.head-v1.tmp-'),
   ('head-fsync',('fsync',),'..j.head-v1.tmp-'),
   ('head-rename',('rename','renameat','renameat2'),'..j.head-v1.tmp-'),
   ('connection-read',('read','recvfrom','recvmsg'),'UNIX-STREAM'),
   ('connection-write',('write','sendto','sendmsg'),'UNIX-STREAM'),
   ('connection-nonblocking',('ioctl',),'FIONBIO')]:
   selectors[phase]=select(phase,[x for x in after if x['syscall'] in names and needle in x['line']])
  dirs=[x for x in after if x['syscall']=='fsync' and str(daemon.fs)+'>' in x['line']];assert len(dirs)==2
  selectors['prepublish-directory-fsync']=select('prepublish-directory-fsync',dirs)
  selectors['postpublish-directory-fsync']=select('postpublish-directory-fsync',dirs,last=True)
  selectors['peer-credentials']=select('peer-credentials',auth)
  selectors['poll']=select('poll',[x for x in calls if x['syscall'] in ('poll','ppoll') and 'UNIX-STREAM' in x['line']])
  selectors['accept']=select('accept',[x for x in calls if x['syscall'] in ('accept','accept4')])
  selectors['listener-nonblocking']=select('listener-nonblocking',[x for x in calls if x['syscall']=='ioctl' and 'FIONBIO' in x['line']])
  PROBES[str(exe)]=selectors;(root/'selectors.json').write_text(json.dumps(selectors,sort_keys=True,indent=2)+'\n')
  return {'response':normalized(response).hex(),'state':filesystem_state(daemon.fs),'phases':sorted(selectors)}
 finally:
  if receipt is None:daemon.finish()
pair('p000',probe)
def fault(exe,root,phase,errno,mode):
 selector=PROBES[str(exe)][phase];injection=selector['syscall']+':error='+errno+':when='+str(selector['ordinal'])
 (root/'injection-selector.json').write_text(json.dumps({'phase':phase,'probe':selector,'injection':injection,'mode':mode},sort_keys=True,indent=2)+'\n')
 daemon=Daemon(exe,root,1_000_000_000,inject=injection);receipt=None;responses=[]
 try:
  if mode=='startup-fatal':receipt=daemon.finish(terminal=True)
  else:
   daemon.ready();response=daemon.exchange('injected-acquire',request());responses.append(response)
   if mode=='fatal':
    assert response==b'',response.hex();receipt=daemon.finish(terminal=True)
   elif mode=='isolated':
    assert response==b'' and daemon.child.poll() is None
    response=daemon.exchange('healthy-after-injection',request());assert len(response)==195;responses.append(response)
    receipt=daemon.finish()
   elif mode=='retry':
    assert len(response)==195 and daemon.child.poll() is None
    response2=daemon.exchange('idempotent-after-retry',request());assert response2==response;responses.append(response2)
    receipt=daemon.finish()
   else:raise ValueError(mode)
  trace=trace_calls(daemon.directory/'syscalls.raw');injected=[x for x in trace if '(INJECTED)' in x['line']]
  assert len(injected)==1,injected
  actual=injected[0];assert actual['syscall']==selector['syscall'] and '= -1 '+errno+' ' in actual['line'],actual
  assert sum(x['syscall']==actual['syscall'] and x['index']<=actual['index'] for x in trace)==selector['ordinal']
  if phase.startswith('journal-'):assert str(daemon.fs/'j')+'>' in actual['line']
  elif phase.startswith('head-'):assert '..j.head-v1.tmp-' in actual['line'] and str(daemon.fs) in actual['line']
  elif 'directory-fsync' in phase:assert str(daemon.fs)+'>' in actual['line']
  elif phase in ('connection-read','connection-write'):assert 'UNIX-STREAM' in actual['line']
  elif phase=='peer-credentials':assert 'SO_PEERCRED' in actual['line']
  elif phase=='poll':assert 'UNIX-STREAM' in actual['line']
  elif phase.endswith('nonblocking'):assert 'FIONBIO' in actual['line']
  api=(daemon.directory/'stdout.raw').read_bytes()
  if mode.endswith('fatal'):
   value=5 if errno=='EIO' else 4
   assert api==b'PLUR0001'+words(2,value) and receipt['exit_code']==0,api.hex()
   assert not os.path.lexists(daemon.path)
  else:assert api==b''
  assert (daemon.directory/'stderr.raw').read_bytes()==b''
  state=filesystem_state(daemon.fs)
  if mode in ('retry','isolated'):assert state['journal_records']==1
  (root/'actual-injection.json').write_text(json.dumps(actual,sort_keys=True,indent=2)+'\n')
  return {'phase':phase,'errno':errno,'mode':mode,'responses':[normalized(r).hex() for r in responses],'api':api.hex(),'state':state,'exact_actual_target_verified':True}
 finally:
  if receipt is None:daemon.finish()
profiles=[]
for phase in ('peer-credentials','connection-nonblocking','journal-metadata','journal-write','journal-fsync','prepublish-directory-fsync','head-write','head-fsync','head-rename','postpublish-directory-fsync'):
 profiles.append((phase,'EIO','fatal'))
for phase in ('listener-nonblocking','accept','poll'):profiles.append((phase,'EIO','startup-fatal'))
for phase in ('journal-write','journal-fsync','prepublish-directory-fsync','head-write','head-fsync','postpublish-directory-fsync','connection-read','connection-write','accept','poll'):
 profiles.append((phase,'EINTR','retry'))
for phase in ('journal-metadata','head-rename'):profiles.append((phase,'EINTR','fatal'))
for phase in ('connection-read','connection-write'):profiles.append((phase,'EAGAIN','retry'))
profiles.extend([('connection-read','ECONNRESET','isolated'),('connection-write','EPIPE','isolated')])
for index,(phase,errno,mode) in enumerate(profiles,1):
 pair('f'+str(index).zfill(3),lambda exe,root,phase=phase,errno=errno,mode=mode:fault(exe,root,phase,errno,mode))
report={'schema':'trnm.hia.peer-unix-syscall-fault-development.v1','status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','passed':sum(r['status']=='PASS' for r in rows),'total':len(rows),'rows':rows,'claims':{'actual_strace_kernel_error_injection':True,'mock_business_results':False,'production_budget_qualification':False,'full_peer_retirement':False}}
(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'passed':report['passed'],'total':report['total'],'failures':[r for r in rows if r['status']!='PASS'],'report':ident((out/'report.json').read_bytes())},sort_keys=True))
raise SystemExit(0 if report['status']=='PASS' else 1)
