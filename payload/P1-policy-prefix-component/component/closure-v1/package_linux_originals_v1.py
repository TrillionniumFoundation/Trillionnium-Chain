#!/usr/bin/env python3
"""Archive only already-closed policy-prefix validation originals; execute no tests."""
import hashlib,json,os,stat,sys,time,traceback,zipfile
from pathlib import Path,PurePosixPath
E=Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1')
L=E/'linux-closed-originals-v1'
C=E/'closure-v1'
CAP=16*1024*1024
DF=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
RF=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def parentfd(p):
 p=Path(p)
 if not p.is_absolute() or str(p)!=os.path.normpath(str(p)):raise ValueError('noncanonical spelling')
 fd=os.open('/',DF)
 try:
  for part in p.parts[1:-1]:
   n=os.open(part,DF,dir_fd=fd);os.close(fd);fd=n
  return fd,p.name
 except BaseException:os.close(fd);raise
def read(p,limit=CAP):
 fd,name=parentfd(p);leaf=None
 try:
  leaf=os.open(name,RF,dir_fd=fd);a=os.fstat(leaf)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise ValueError('regular/size fence '+str(p))
  chunks=[];left=a.st_size
  while left:
   b=os.read(leaf,min(left,262144))
   if not b:raise ValueError('short read')
   chunks.append(b);left-=len(b)
  if os.read(leaf,1):raise ValueError('grew')
  b=b''.join(chunks)
  if ident(a)!=ident(os.fstat(leaf)) or ident(a)!=ident(os.stat(name,dir_fd=fd,follow_symlinks=False)):raise ValueError('unstable read '+str(p))
  return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'identity':list(ident(a))}
 finally:
  if leaf is not None:os.close(leaf)
  os.close(fd)
def put(p,b):
 p=Path(p);fd,name=parentfd(p);leaf=None
 try:
  leaf=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=fd)
  view=memoryview(b)
  while view:
   n=os.write(leaf,view);view=view[n:]
  os.fsync(leaf)
 finally:
  if leaf is not None:os.close(leaf)
  os.close(fd)
 rb,meta=read(p)
 if rb!=b:raise ValueError('write readback')
 return {k:meta[k]for k in ('path','bytes','sha256')}
def safe_rel(s):
 q=PurePosixPath(s)
 if not isinstance(s,str) or str(q)!=s or q.is_absolute() or any(p in ('','.','..')for p in q.parts):raise ValueError('relative path')
 return q
data=json.loads(sys.argv[1])
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE') not in (None,'','0'):raise ValueError('optimized assertions forbidden')
if E.resolve()!=E or L.resolve()!=L or os.path.lexists(C):raise ValueError('fixed roots/create-only closure')
C.mkdir(mode=0o700)
put(C/'package_linux_originals_v1.py',sys.argv[2].encode())
put(C/'packager-pre-dispatch-error.json',js({'schema':'trnm-evidence-orchestration-error-v1','layer':'functions.exec JavaScript parse','error':"SyntaxError: Unexpected identifier 'originals'",'cause':'unescaped Markdown backtick within JavaScript template literal','operator_tool_called':False,'files_written':False,'source_or_tests_accessed':False,'subsequent_change':'removed Markdown backticks from packaging README only; first operator launch retains original stable idempotency key'}))
state={'schema':'trnm-policy-prefix-closed-originals-package-v1','status':'HOLD','started_unix':time.time(),'errors':[],'tests_or_source_or_git_access':False,'original_root_M8_checks_are_historical':True,'hosted_qualification':False}
try:
 roster_raw,roster_meta=read(L/'source-roster.json')
 roster=json.loads(roster_raw)
 if roster['files']!=data['roster']:raise ValueError('fixed original roster mismatch')
 if len(roster['files'])!=115 or sum(x['bytes']for x in roster['files'])!=398878:raise ValueError('115 original files/bytes')
 files=[];contents={};source_ids={}
 for row in roster['files']:
  if set(row)!= {'path','bytes','sha256','origin','source_version'}:raise ValueError('raw roster schema')
  rel=safe_rel(row['path']);path=L/'payloads'/rel
  b,meta=read(path)
  if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('original byte identity')
  member='originals/'+str(rel)
  if member in contents:raise ValueError('duplicate member')
  contents[member]=b;source_ids[str(path)]=meta['identity']
  files.append({'zip_member':member,'path':str(rel),'bytes':len(b),'sha256':sha(b),'origin':row['origin'],'source_version':row['source_version'],'mac_source_path':str(path)})
 if sum(map(len,contents.values()))>CAP:raise ValueError('package bound')
 prov=put(L/'official-transfer-provenance.json',js(data['provenance']))
 programs=[]
 for name in ['rog_prepare_isolated_validation.py','rog_serial_and_clippy_validation.py','rog_default_harness_followup.py']:
  raw,meta=read(E/'executed-producers-v1'/name)
  programs.append({k:meta[k]for k in ('path','bytes','sha256')})
 zpath=L/'originals.zip';fd,name=parentfd(zpath)
 zfd=None
 try:
  zfd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=fd)
  with os.fdopen(zfd,'w+b',closefd=True) as out:
   zfd=None
   with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for member,b in sorted(contents.items()):
     zi=zipfile.ZipInfo(member,date_time=(1980,1,1,0,0,0));zi.compress_type=zipfile.ZIP_DEFLATED;zi.external_attr=(stat.S_IFREG|0o600)<<16
     z.writestr(zi,b,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
   out.flush();os.fsync(out.fileno())
 finally:
  if zfd is not None:os.close(zfd)
  os.close(fd)
 zraw,zmeta=read(zpath)
 import io
 with zipfile.ZipFile(io.BytesIO(zraw),'r')as z:
  if sorted(z.namelist())!=sorted(contents) or len(z.infolist())!=115 or z.testzip() is not None:raise ValueError('ZIP member/CRC fence')
  for row in files:
   b=z.read(row['zip_member'])
   if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('ZIP member hash')
 for row in files:
  b,meta=read(row['mac_source_path'])
  if meta['identity']!=source_ids[row['mac_source_path']] or len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('postarchive original fence')
 index={'schema':'trnm-policy-prefix-closed-originals-zip-index-v1','archive':{k:zmeta[k]for k in ('path','bytes','sha256')},'file_count':115,'total_uncompressed_bytes':398878,'files':files,'source_roster':{k:roster_meta[k]for k in ('path','bytes','sha256')},'official_transfer_provenance':prov,'actual_executed_ROG_programs_saved_separately':programs,'all_member_crc_and_sha256_verified':True,'source_files_stable_before_after':True,'original_ROG_source_checks_are_historical':True,'stage_or_source_or_git_written':False}
 im=put(L/'originals.zip.index.json',js(index))
 readme="""# Closed Linux component validation originals

This newly assembled ZIP contains exactly 115 original files (398,878 uncompressed bytes): 112 files from the two completed validation directories and three complete actual terminal transcripts. Member names have the fixed originals/ prefix. The index records each exact zip_member, original ROG origin, immutable-read version, size, and SHA256. Every member's CRC and SHA256 was verified after ZIP creation.

The first validation used RUST_TEST_THREADS=1: three prefix controls, one original golden control, and strict all-target/all-feature Clippy passed. It is a serial harness record. A separate follow-up removed inherited RUST_TEST_* variables and repeated only the same three plus one tests with the default harness; all four passed with zero ignored. Clippy was not repeated. The original compiler-path warning and both original environment records remain unchanged.

These results describe M8 plus the exact one-file uncommitted proposal at that time. They do not claim that the proposal was a clean M8 checkout, that the current root worktree is still M8, or that hosted 4-second performance or SQLite native qualification passed. This packaging operation reads only closed evidence; it runs no tests, Git, source reads, or network operations.

The official transfer provenance retains the source versions, pinned chunks, upload acknowledgements and final destination checks. Provider bookkeeping files are explicitly excluded, not validation outputs. Executed programs are preserved separately as exact code strings from the actual terminal invocations, clearly saved after execution. The original Mac compilation failure and all other component failures remain elsewhere in the component evidence.
"""
 put(L/'README.md',readme.encode())
 state.update(status='CLOSED_ORIGINALS_PACKAGED_AND_VERIFIED',file_count=115,raw_bytes=398878,archive=index['archive'],index=im,source_roster=index['source_roster'],transfer_provenance=prov,source_files_stable_before_after=True,zip_crc_and_member_hashes_verified=True)
except BaseException as exc:
 state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
finally:
 state['completed_unix']=time.time()
 summary=put(L/'packager-summary.json',js(state))
 print(json.dumps({'status':state['status'],'summary':summary,'file_count':state.get('file_count'),'raw_bytes':state.get('raw_bytes'),'archive':state.get('archive'),'index':state.get('index'),'errors':state['errors']}),flush=True)
sys.exit(0 if state['status']=='CLOSED_ORIGINALS_PACKAGED_AND_VERIFIED' else 1)
