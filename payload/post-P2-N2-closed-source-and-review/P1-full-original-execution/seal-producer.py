import datetime,difflib,hashlib,json,os,pathlib,stat,sys
D=json.loads(sys.argv[1]);SELF=sys.argv[2];C=pathlib.Path(D['destination']);assert C.resolve(strict=True)==C
def sig(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(f);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=4*1024*1024
  with os.fdopen(f,'rb',closefd=False) as z:b=z.read(s.st_size+1)
  assert len(b)==s.st_size and sig(os.fstat(f))==sig(s) and sig(p.lstat())==sig(s)
  return b
 finally:os.close(f)
def js(v):return(json.dumps(v,indent=2)+'\n').encode()
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert read(p)==b
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
origins={}
for row in json.loads(read(C/'copy-files.json'))['files']:origins[row['path']]=row['origin']
for row in D['copied_aux']:
 b=row['text'].encode();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
 p=C/row['target'];save(p,b);origins[str(p)]={'host':row['source_host'],'path':row['source_path']}
for n,v in D['tool_receipts'].items():save(C/n,js(v))
save(C/'auxiliary-copy-provenance.json',js({'schema':'trnm-P1-full-v2-auxiliary-copy-v1','method':'official h_read_multiple_files exact UTF-8 bytes with independent SHA and version','files':[{k:v for k,v in r.items() if k!='text'} for r in D['copied_aux']]}))
patch=''.join(difflib.unified_diff(D['verifier_old_source'].splitlines(True),D['verifier_new_source'].splitlines(True),fromfile='approved-M8-copy-verifier.py',tofile='P1-full-v2-copy-verifier.py'))
save(C/'copy-verifier-M8-to-P1-v2.patch',patch.encode())
save(C/'seal-producer.py',SELF.encode())
notes=('# P1 original full-v2 execution preservation\n\n'
'This directory preserves the original completed P1 repository-truth execution, exact HEAD 6a8cd55573065ceb50cdb65a7834615f79b521ae and tree cbd6b4552c87af27c72c0189806baeb33ecb8bf5. The original 18 steps all exited 0; the original lane took 546.056 seconds under its unchanged 2,700-second limit. Source-before and source-after are byte-identical to the independent 423-byte source identity.\n\n'
'All 51 execution originals (39 required flat files and 12 nested ci-observations logs) are present under flat/original/. The unchanged original driver, packaging producer and pinned closed-log manifest are also expanded. The complete 55-member ZIP has been verified by CRC, bytes and SHA256 on both hosts; official version-pinned transfer and actual PTY provenance are retained.\n\n'
'P1 full-v1 was a distinct source-identity failure before the lane started; this package does not rewrite that result. P1 external was not run. This is local P1 evidence, not hosted qualification, not a P2/N2 execution, and not a publication. No test, source/Git action or stage materialization was performed by this preservation.\n')
save(C/'README.md',notes.encode())
vf=json.loads(read(C/'copy-verification.json'))
summary={'schema':'trnm-P1-full-v2-original-copy-seal-v1','sealed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'verified','head':'6a8cd55573065ceb50cdb65a7834615f79b521ae','tree':'cbd6b4552c87af27c72c0189806baeb33ecb8bf5','original_status':'passed','original_lane_exit':0,'original_lane_seconds':vf['original_lane_elapsed_seconds'],'original_summary_sha256':'a61aca5c4745c4a4e6f89c8cdc18b489679662b135061bee1357ca4072ca0f3b','original_files':51,'required_flat_originals':39,'nested_originals':12,'original_bytes':886983,'zip_members':55,'all_originals_and_driver_expanded':True,'source_identity_sha256':'cca39d3cb68ec4f56128201fcad953c875c60c6117c5dbf7604e359f7faf1fa5','tests_rerun':False,'stage_written':False,'hosted_qualification':False,'future_revision_qualification':False,'remote_publication_claim':False}
save(C/'preservation-summary.json',js(summary))
files=[]
for base,ds,fs in os.walk(C,followlinks=False):
 for n in ds:
  p=pathlib.Path(base)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
 for n in fs:
  p=pathlib.Path(base)/n;b=read(p)
  files.append({'relative_path':str(p.relative_to(C)),'source_path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':origins.get(str(p),{'host':'mac','path':str(p)})})
files.sort(key=lambda r:r['relative_path'])
assert len(files)==len({r['relative_path'] for r in files})
manifest={'schema':'trnm-P1-full-v2-preserved-files-v1','root':str(C),'file_count':len(files),'total_bytes':sum(r['bytes'] for r in files),'files':files,'manifest_excludes_itself':True,'stage_written':False}
mi=save(C/'preserved-files.json',js(manifest))
summaryinfo={'path':str(C/'preservation-summary.json'),'bytes':(C/'preservation-summary.json').stat().st_size,'sha256':hashlib.sha256(read(C/'preservation-summary.json')).hexdigest()}
print(json.dumps({'directory':str(C),'manifest':mi,'summary':summaryinfo,'file_count_excluding_manifest':len(files),'bytes_excluding_manifest':manifest['total_bytes'],'stage_written':False}))
