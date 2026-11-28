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
def digest_file(path):
 h=hashlib.sha256();size=0
 with path.open('rb') as stream:
  while block:=stream.read(1<<20):size+=len(block);h.update(block)
 return {'bytes':size,'sha256':h.hexdigest()}
def snapshot(root):
 result=[]
 for p in sorted(root.rglob('*')):
  st=p.lstat();row={'path':str(p.relative_to(root)),'mode':st.st_mode,'bytes':st.st_size,'device':st.st_dev,'inode':st.st_ino,'links':st.st_nlink}
  if stat.S_ISREG(st.st_mode):row.update(digest_file(p))
  elif stat.S_ISLNK(st.st_mode):row['target']=os.readlink(p)
  result.append(row)
 return result
def journal_record(path):
 raw=path.read_bytes();assert len(raw)==236
 assert raw[:5]==b'TPLR\1' and raw[5]==1 and raw[6:10]==struct.pack('<I',162)
 assert raw[10:42]==bytes(32) and raw[42]==1
 assert raw[43:148]==SCOPE and raw[148:180]==b'\4'*32 and word(raw,180)==1
 assert word(raw,188)==word(raw,196)+30000
 assert raw[204:]==hashlib.sha256(raw[:204]).digest()
 return raw
def unlocked(path):
 import fcntl
 with path.open('r+b') as stream:
  fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
  fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
 return True
def fatal_storage(exe,root,kind,replacement='owned'):
 daemon=Daemon(exe,root,1_000_000_000);c=None;replacement_socket=None;receipt=None
 try:
  daemon.ready();initial_head=(daemon.fs/'.j.head-v1').read_bytes()
  assert len(initial_head)==80 and word(initial_head,8)==0
  c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(4);c.connect(str(daemon.path))
  payload=request();c.sendall(payload[:1])
  old_stat=daemon.path.lstat();before_identity=(old_stat.st_dev,old_stat.st_ino)
  if kind=='journal-bound':
   with daemon.journal.open('r+b') as stream:stream.truncate(256*1024*1024+1)
   before_journal=digest_file(daemon.journal)
  elif kind=='anchor-directory':
   (daemon.fs/'.j.head-v1').unlink();(daemon.fs/'.j.head-v1').mkdir(mode=0o700)
   (daemon.fs/'.j.head-v1'/'marker').write_bytes(b'retain-replacement-directory')
  elif kind!='parent-inaccessible':raise ValueError(kind)
  if replacement=='socket':
   daemon.path.unlink();replacement_socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
   replacement_socket.bind(str(daemon.path));replacement_socket.listen(1);daemon.path.chmod(0o600)
  elif replacement=='regular':daemon.path.unlink();daemon.path.write_bytes(b'retain-replacement-file')
  elif replacement=='directory':daemon.path.unlink();daemon.path.mkdir(mode=0o700)
  elif replacement=='symlink':
   daemon.path.unlink();(daemon.fs/'marker').write_bytes(b'retain-symlink-target');daemon.path.symlink_to('marker')
  elif replacement=='absent':daemon.path.unlink()
  elif replacement=='same-inode-other-mode':daemon.path.chmod(0o777)
  elif replacement!='owned':raise ValueError(replacement)
  if replacement not in ('owned','absent','same-inode-other-mode'):
   replaced=daemon.path.lstat();assert (replaced.st_dev,replaced.st_ino)!=before_identity
   replacement_identity=(replaced.st_dev,replaced.st_ino,replaced.st_mode)
  if kind=='parent-inaccessible':daemon.fs.chmod(0)
  command_dir=daemon.directory/'fatal-request';command_dir.mkdir();(command_dir/'stdin.raw').write_bytes(payload)
  started=time.monotonic_ns();c.sendall(payload[1:]);reply=read_all(c);elapsed=time.monotonic_ns()-started
  (command_dir/'stdout.raw').write_bytes(reply)
  receipt=daemon.finish(terminal=True)
  assert elapsed<4_000_000_000
  if kind=='parent-inaccessible':daemon.fs.chmod(0o700)
  api=(daemon.directory/'stdout.raw').read_bytes()
  assert api[:8]==b'PLUR0001' and len(api)==24 and receipt['exit_code']==0
  assert (daemon.directory/'stderr.raw').read_bytes()==b''
  expected=(4,10) if kind=='journal-bound' else (2,13 if kind=='parent-inaccessible' else 21)
  assert (word(api,8),word(api,16))==expected,api.hex()
  assert reply==(frame(bytes([1,1,10])) if kind=='journal-bound' else b''),reply.hex()
  retained=(kind=='parent-inaccessible' or replacement not in ('owned','absent','same-inode-other-mode'))
  assert os.path.lexists(daemon.path)==retained
  if retained and replacement!='owned':
   after=daemon.path.lstat();assert (after.st_dev,after.st_ino,after.st_mode)==replacement_identity
  if replacement=='regular':assert daemon.path.read_bytes()==b'retain-replacement-file'
  if replacement=='directory':assert daemon.path.is_dir()
  if replacement=='symlink':assert os.readlink(daemon.path)=='marker' and (daemon.fs/'marker').read_bytes()==b'retain-symlink-target'
  if kind=='journal-bound':
   assert digest_file(daemon.journal)==before_journal
   assert (daemon.fs/'.j.head-v1').read_bytes()==initial_head
   durable={'journal_unchanged':True,'head_unchanged':True,'bytes':before_journal['bytes']}
  else:
   record=journal_record(daemon.journal)
   if kind=='anchor-directory':
    assert (daemon.fs/'.j.head-v1'/'marker').read_bytes()==b'retain-replacement-directory'
    temps=list(daemon.fs.glob('..j.head-v1.tmp-*'));assert len(temps)==1,[x.name for x in daemon.fs.iterdir()]
    head=temps[0].read_bytes();assert len(head)==80 and word(head,8)==1 and head[16:48]==record[204:]
    assert head[48:]==hashlib.sha256(b'TPLH'+words(48)+head[:48]).digest()
   else:assert (daemon.fs/'.j.head-v1').read_bytes()==initial_head
   durable={'journal_record_valid':True,'journal_records':1,'head_temp_retained':kind=='anchor-directory','head_unchanged':kind=='parent-inaccessible'}
  assert unlocked(daemon.fs/'j.lease-lock')
  physical=snapshot(daemon.fs);(root/'filesystem.json').write_text(json.dumps(physical,sort_keys=True,indent=2)+'\n')
  (command_dir/'receipt.json').write_text(json.dumps({'request':ident(payload),'response':ident(reply),'elapsed_ns':elapsed,'original_socket_device_inode':before_identity,'kernel_fault':'actual-owned-filesystem-mutation'},sort_keys=True)+'\n')
  return {'fatal':list(expected),'response':reply.hex(),'socket_retained':retained,'replacement':replacement,'lock_released':True,'durable':durable}
 finally:
  if kind=='parent-inaccessible':daemon.fs.chmod(0o700)
  if c:c.close()
  if replacement_socket:replacement_socket.close()
  if receipt is None:daemon.finish()
pair('f001',lambda exe,root:fatal_storage(exe,root,'journal-bound'))
pair('f002',lambda exe,root:fatal_storage(exe,root,'parent-inaccessible'))
for index,replacement in enumerate(('owned','socket','regular','directory','symlink','absent','same-inode-other-mode'),3):
 pair('f'+str(index).zfill(3),lambda exe,root,replacement=replacement:fatal_storage(exe,root,'anchor-directory',replacement))
report={'schema':'trnm.hia.peer-unix-daemon-fault-development.v1','status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL',
 'passed':sum(r['status']=='PASS' for r in rows),'total':len(rows),'rows':rows,
 'claims':{'actual_original_and_native_processes':True,'actual_owned_filesystem_faults':True,'full_peer_owner_retirement':False,'cross_uid_qualification':False,'production_shared_budget_qualification':False}}
(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'passed':report['passed'],'total':report['total'],'failures':[r for r in rows if r['status']!='PASS'],'report':digest_file(out/'report.json')},sort_keys=True))
raise SystemExit(0 if report['status']=='PASS' else 1)
