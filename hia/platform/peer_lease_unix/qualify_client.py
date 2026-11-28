"""Actual public-client differential with independent adversarial socket peers."""
import argparse,hashlib,json,os,pathlib,signal,socket,struct,subprocess,threading,time,traceback
p=argparse.ArgumentParser();p.add_argument('--native',type=pathlib.Path,required=True);p.add_argument('--original',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
out=a.output;out.mkdir(mode=0o700);fs=out/'fs';fs.mkdir(mode=0o700);rows=[]
def identity(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def word(b,at=0):return struct.unpack_from('<Q',b,at)[0]
scope=bytes([1])*32+bytes([2])*32+b'\1'+struct.pack('<Q',9)+bytes([3])*32
token=scope+bytes([4])*32+struct.pack('<QQ',1,123)+bytes([5])*32
def request(method=1):return struct.pack('<Q',method)+scope+bytes([4])*32+struct.pack('<QQQ',1,123,1000)+bytes([5])*32
def frame(body):return b'TPLS'+struct.pack('<I',len(body))+body
valid=frame(b'\1\0'+token)
def config(path,op=3,req=None,timeout_ns=500_000_000,absolute=None):
 path=os.fsencode(path);req=request() if req is None and op==3 else (req or b'');sec,ns=divmod(timeout_ns,1_000_000_000)
 return b'PLUC0001'+struct.pack('<9Q',op,len(path),sec,ns,int(absolute is not None),*(absolute or (0,0)),len(req),0)+path+req
def observe(exe,payload,d):
 d.mkdir(mode=0o700);(d/'stdin.raw').write_bytes(payload);start=time.monotonic_ns()
 argv=['strace','-f','-qq','-yy','-s','4096','-o',str(d/'syscalls.raw'),str(exe)]
 child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:stdout,stderr=child.communicate(payload,timeout=4);timeout=False
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGKILL);stdout,stderr=child.communicate(timeout=3);timeout=True
 for name,b in [('stdout',stdout),('stderr',stderr)]: (d/(name+'.raw')).write_bytes(b)
 r={'exit_code':child.returncode,'timed_out':timeout,'elapsed_ns':time.monotonic_ns()-start,'wall_limit_seconds':4,'cleanup_limit_seconds':3,'input':identity(payload),'stdout':identity(stdout),'stderr':identity(stderr),'trace':identity((d/'syscalls.raw').read_bytes()),'executable':identity(exe.read_bytes())}
 if stdout[:8]==b'PLUR0001' and len(stdout)>=32:r['decoded']={'category':word(stdout,8),'code':word(stdout,16),'payload_bytes':word(stdout,24),'well_framed':len(stdout)==32+word(stdout,24)}
 (d/'receipt.json').write_text(json.dumps(r,sort_keys=True)+'\n');return r,stdout,stderr
class Server:
 def __init__(self,listener,reply,chunk=None,delay=0):self.listener=listener;self.reply=reply;self.chunk=chunk;self.delay=delay;self.stop=threading.Event();self.request=b'';self.sent=0;self.error=None;self.thread=threading.Thread(target=self.run)
 def run(self):
  conn=None
  try:
   self.listener.settimeout(0.05)
   while not self.stop.is_set():
    try:conn,_=self.listener.accept();break
    except TimeoutError:pass
   if conn is None:return
   conn.settimeout(1)
   while len(self.request)<203:
    b=conn.recv(203-len(self.request))
    if not b:return
    self.request+=b
   step=self.chunk or max(1,len(self.reply))
   for at in range(0,len(self.reply),step):
    if self.stop.wait(self.delay):break
    conn.sendall(self.reply[at:at+step]);self.sent+=len(self.reply[at:at+step])
  except (BrokenPipeError,ConnectionResetError) as e:self.error=type(e).__name__
  except BaseException as e:self.error=repr(e)
  finally:
   if conn is not None:conn.close()
 def finish(self):
  self.stop.set();self.thread.join(2);assert not self.thread.is_alive()
  return {'request':identity(self.request),'request_hex':self.request.hex(),'sent':self.sent,'error':self.error}
path=fs/'lease.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));listener.listen(8);path.chmod(0o600)
def case(name,payload,reply=None,chunk=None,delay=0,expect_call=False,exact_reply=None):
 d=out/name;d.mkdir(mode=0o700);entry={'name':name};pairs=[]
 try:
  before=sorted(str(p.relative_to(fs)) for p in fs.rglob('*'))
  for kind,exe in [('r',a.original),('n',a.native)]:
   server=Server(listener,reply,chunk,delay) if reply is not None else None
   if server:server.thread.start()
   try:r,stdout,stderr=observe(exe,payload,d/kind)
   finally:peer=server.finish() if server else None
   if peer:(d/(kind+'-peer.json')).write_text(json.dumps(peer,sort_keys=True)+'\n')
   pairs.append((r,stdout,stderr,peer))
  x,y=pairs;checks={'process':x[0]['exit_code']==y[0]['exit_code']==0 and not x[0]['timed_out'] and not y[0]['timed_out'],'reply':x[1]==y[1],'stderr':x[2]==y[2]==b'','framed':x[0].get('decoded',{}).get('well_framed') is True and y[0].get('decoded',{}).get('well_framed') is True}
  checks['no_client_filesystem_mutation']=before==sorted(str(p.relative_to(fs)) for p in fs.rglob('*'))
  if reply is not None:
   checks['request_bytes']=x[3]['request_hex']==y[3]['request_hex']
   if expect_call:checks['complete_request']=x[3]['request']['bytes']==y[3]['request']['bytes']==203
  if exact_reply is not None:checks['expected_result']=tuple(x[0].get('decoded',{}).get(k) for k in ['category','code'])==exact_reply
  entry.update(status='PASS' if all(checks.values()) else 'FAIL',checks=checks,original=x[0],native=y[0])
  if entry['status']!='PASS':entry.update(original_stdout=x[1].hex(),native_stdout=y[1].hex(),original_stderr=x[2].decode(errors='replace'),native_stderr=y[2].decode(errors='replace'))
 except BaseException as e:entry.update(status='FAIL',failure=repr(e),traceback=traceback.format_exc())
 rows.append(entry);(out/'progress.json').write_text(json.dumps(rows,sort_keys=True)+'\n')

case('preflight',config(path,op=1),exact_reply=(0,0));case('binding',config(path,op=2),exact_reply=(0,0))
for name,pth in [('relative',b'relative'),('empty',b''),('root',b'/'),('dotdot',b'/tmp/../lease'),('embedded-nul',os.fsencode(path)+b'\0x'),('long',b'/'+b'x'*103),('very-long',b'/'+b'x'*65536),('missing-parent',fs/'absent/sock'),('missing-socket',fs/'absent.sock'),('trailing-slash',str(path)+'/')]:
 for op in [1,2,3]:case('path-'+name+'-'+str(op),config(pth,op=op))
for mode in [0o000,0o400,0o644,0o777,0o1600]:
 path.chmod(mode);case('socket-mode-'+oct(mode),config(path,op=1));path.chmod(0o600)
regular=fs/'regular';regular.write_bytes(b'not a socket');regular.chmod(0o600);case('regular-file',config(regular,op=1))
alias=fs/'alias';alias.symlink_to(path);case('socket-symlink',config(alias,op=1))
aliasdir=out/'alias';aliasdir.symlink_to(fs);case('parent-symlink',config(aliasdir/'lease.sock',op=1))
fs.chmod(0o755);case('broad-parent',config(path,op=1));fs.chmod(0o700)
for name,pth in [('embedded-dot',str(fs)+'/./lease.sock'),('double-slash',str(fs)+'//lease.sock')]:
 for op in [1,2]:case(name+'-'+str(op),config(pth,op=op))
for method in [1,2,3,4]:case('method-'+str(method),config(path,req=request(method)),valid,expect_call=True,exact_reply=(0,0))
for code in range(1,13):case('rejected-'+str(code),config(path),frame(bytes([1,1,code])),expect_call=True,exact_reply=(4,code))
case('bad-magic',config(path),b'NOPE'+struct.pack('<I',0),expect_call=True,exact_reply=(3,20))
case('excessive-length',config(path),b'TPLS'+struct.pack('<I',16385),expect_call=True,exact_reply=(3,21))
for n in [0,1,2,3,7,8,9,10,100,194]:case('eof-'+str(n),config(path),valid[:n],expect_call=True,exact_reply=(2,4099))
for n in range(187):case('complete-short-body-'+str(n),config(path),frame(valid[8:8+n]),expect_call=True)
for n in [188,189,256,1024,4096,16384]:case('trailing-body-'+str(n),config(path),frame(valid[8:]+bytes(n-187)),expect_call=True,exact_reply=(3,6))
for at,values in [(0,[0,2,255]),(1,[2,255]),(66,[0,3,255])]:
 for value in values:
  body=bytearray(valid[8:]);body[at]=value;case('field-'+str(at)+'-'+str(value),config(path),frame(body),expect_call=True)
for name,at,n in [('local',2,32),('remote',34,32),('scope',75,32),('session',107,32),('generation',139,8),('hash',155,32)]:
 body=bytearray(valid[8:]);body[at:at+n]=bytes(n);case('zero-'+name,config(path),frame(body),expect_call=True)
body=bytearray(valid[8:]);body[34:66]=body[2:34];case('self-peer',config(path),frame(body),expect_call=True)
for code in [0,13,255]:case('bad-reject-'+str(code),config(path),frame(bytes([1,1,code])),expect_call=True,exact_reply=(3,14))
for n in [1,2,7,64,193]:case('fragment-'+str(n),config(path,timeout_ns=1_000_000_000),valid,chunk=n,delay=0.0002,expect_call=True,exact_reply=(0,0))
case('one-shared-read-deadline',config(path,timeout_ns=150_000_000),valid,chunk=1,delay=0.02,expect_call=True,exact_reply=(2,4098))
case('zero-timeout',config(path,timeout_ns=0),exact_reply=(2,4098))
case('already-expired',config(path,absolute=(0,0)),exact_reply=(2,4098))
case('huge-timeout',config(path,timeout_ns=((1<<64)-1)*1_000_000_000),exact_reply=(2,4098))
for name,at,n in [('local',8,32),('direction',72,1),('session-renew',113,32),('generation-renew',145,8),('hash-renew',169,32)]:
 r=bytearray(request(2));r[at:at+n]=bytes(n);case('typed-'+name,config(path,req=bytes(r)),exact_reply=(100,100))
listener.close()
case('connection-refused',config(path),exact_reply=(2,111))
report={'status':'PASS' if all(x['status']=='PASS' for x in rows) else 'FAIL','total':len(rows),'passed':sum(x['status']=='PASS' for x in rows),'cases':rows,'actual_socket_peer':True,'runtime_fallback':False,'absolute_deadline_reference_conversion':'original Instant adjusted by one direct CLOCK_MONOTONIC sample; no bit-exact Instant-layout claim'}
(out/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'total':report['total'],'passed':report['passed'],'failures':[x for x in rows if x['status']!='PASS']},sort_keys=True));raise SystemExit(report['status']!='PASS')
