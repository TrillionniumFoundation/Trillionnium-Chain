"""Actual daemon CLI differential observations; no runtime implementation."""
import argparse,hashlib,json,os,pathlib,signal,socket,stat,subprocess,time,traceback
p=argparse.ArgumentParser();p.add_argument('--native',type=pathlib.Path,required=True);p.add_argument('--original',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
out=a.output;out.mkdir(mode=0o700);rows=[]
def identity(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def observe(exe,args,d):
 d.mkdir(mode=0o700);started=time.monotonic_ns()
 argv=['strace','-f','-qq','-yy','-s','4096','-o',str(d/'syscalls.raw'),str(exe),*args]
 child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:stdout,stderr=child.communicate(timeout=4);timeout=False
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGKILL);stdout,stderr=child.communicate(timeout=3);timeout=True
 (d/'stdout.raw').write_bytes(stdout);(d/'stderr.raw').write_bytes(stderr)
 result={'argv':argv,'exit_code':child.returncode,'timed_out':timeout,'wall_limit_seconds':4,'cleanup_limit_seconds':3,'elapsed_ns':time.monotonic_ns()-started,'stdout':identity(stdout),'stderr':identity(stderr),'executable':identity(exe.read_bytes()),'trace':identity((d/'syscalls.raw').read_bytes())}
 (d/'receipt.json').write_text(json.dumps(result,sort_keys=True)+'\n');return result,stdout,stderr
def snapshot(root):
 result={}
 for q in sorted(root.rglob('*')):
  s=q.lstat();row={'mode':s.st_mode&0o177777,'uid':s.st_uid,'gid':s.st_gid}
  if stat.S_ISREG(s.st_mode):row.update(identity(q.read_bytes()))
  if stat.S_ISLNK(s.st_mode):row['target']=os.readlink(q).replace(str(root),'<case>')
  result[q.relative_to(root).as_posix()]=row
 return result
cases=[]
for label,args in [('empty',[]),('help',['--help']),('short-help',['-h']),('unknown',['--wrong']),('missing-socket-value',['--socket']),('missing-journal-value',['--journal']),('ready-only',['--ready-file','x']),('socket-only',['--socket','/x']),('journal-only',['--journal','/j']),('unknown-after-pair',['--socket','/x','--journal','/j','bad']),('many-unknown',['--bad']*128)]:
 cases.append((label,lambda r,args=args:args))
def standard(r,socket_path=None,journal_path=None):return ['--socket',str(r/'lease.sock') if socket_path is None else socket_path,'--journal',str(r/'journal') if journal_path is None else journal_path]
for label,value in [('relative','relative'),('empty',''),('root','/'),('dot','/.'),('dotdot','/tmp/../x'),('root-dotdot','/../x'),('long','/'+('s'*103))]:
 cases.append(('socket-'+label,lambda r,value=value:standard(r,socket_path=value)))
for label,value in [('relative','relative'),('empty',''),('root','/'),('dot','/.'),('dotdot','/tmp/../j')]:
 cases.append(('journal-'+label,lambda r,value=value:standard(r,journal_path=value)))
for label,name in [('same','journal'),('lock','journal.lease-lock'),('anchor','.journal.head-v1')]:
 cases.append(('collision-'+label,lambda r,name=name:standard(r,socket_path=str(r/name))))
cases.append(('journal-is-lock',lambda r:standard(r,journal_path=str(r/'journal.lease-lock'))))
def occupied(r,kind):
 q=r/'lease.sock'
 if kind=='file':q.write_bytes(b'keep')
 elif kind=='directory':q.mkdir(mode=0o700)
 elif kind=='dangling':q.symlink_to(r/'absent')
 elif kind=='socket':s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(q));s.close()
 return standard(r)
for kind in ['file','directory','dangling','socket']:cases.append(('occupied-'+kind,lambda r,kind=kind:occupied(r,kind)))
def parent_case(r,kind):
 q=r/'boundary'
 if kind=='file':q.write_bytes(b'keep')
 elif kind=='alias':
  target=r/'actual';target.mkdir(mode=0o700);q.symlink_to(target)
 else:
  requested=int(kind,8);q.mkdir(mode=requested);q.chmod(requested)
  if stat.S_IMODE(q.stat().st_mode)!=requested:raise ValueError('requested parent permission fixture was not established')
 return standard(r,socket_path=str(q/'sock'))
for kind in ['file','alias','0755','0777','0701']:cases.append(('parent-'+kind,lambda r,kind=kind:parent_case(r,kind)))
def ancestry(r):
 q=r/'broad';q.mkdir(mode=0o777);q.chmod(0o777);(q/'private').mkdir(mode=0o700)
 return standard(r,socket_path=str(q/'private/sock'))
cases.append(('broad-ancestry',ancestry))
for label,prepare in cases:
 d=out/label;d.mkdir(mode=0o700);entry={'name':label}
 try:
  pairs=[]
  for kind,exe in [('r',a.original),('n',a.native)]:
   fs=d/kind;fs.mkdir(mode=0o700);args=prepare(fs);before=snapshot(fs);r,stdout,stderr=observe(exe,args,d/(kind+'-process'));after=snapshot(fs)
   (d/(kind+'-filesystem.json')).write_text(json.dumps({'before':before,'after':after},sort_keys=True)+'\n')
   pairs.append((r,stdout,stderr,before,after))
  x,y=pairs
  checks={'exit':x[0]['exit_code']==y[0]['exit_code'],'both_terminal_failures':x[0]['exit_code'] in [1,2] and y[0]['exit_code'] in [1,2] and not x[0]['timed_out'] and not y[0]['timed_out'],'stdout':x[1]==y[1],'stderr':x[2]==y[2],'before':x[3]==y[3],'after':x[4]==y[4]}
  entry.update(status='PASS' if all(checks.values()) else 'FAIL',checks=checks,original=x[0],native=y[0])
  if not all(checks.values()):entry.update(original_stderr=x[2].decode(errors='replace'),native_stderr=y[2].decode(errors='replace'))
 except BaseException as e:entry.update(status='FAIL',failure=repr(e),traceback=traceback.format_exc())
 rows.append(entry);(out/'progress.json').write_text(json.dumps(rows,sort_keys=True)+'\n')
report={'status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','cases':rows,'passed':sum(r['status']=='PASS' for r in rows),'total':len(rows),'source_of_original':'unaltered complete Cargo graph build','runtime_fallback':False}
(out/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'passed':report['passed'],'total':report['total'],'failures':[r for r in rows if r['status']!='PASS']},sort_keys=True));raise SystemExit(report['status']!='PASS')
