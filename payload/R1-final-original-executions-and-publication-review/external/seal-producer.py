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
save(C/'auxiliary-copy-provenance.json',js({'schema':'trnm-R1-external-auxiliary-copy-v1','method':'official h_read_multiple_files exact UTF-8 bytes with independent SHA and version','files':[{k:v for k,v in r.items() if k!='text'} for r in D['copied_aux']]}))
patch=''.join(difflib.unified_diff(D['verifier_old_source'].splitlines(True),D['verifier_new_source'].splitlines(True),fromfile='R1-full-copy-verifier.py',tofile='R1-external-copy-verifier.py'))
save(C/'copy-verifier-R1-full-to-external-v1.patch',patch.encode())
save(C/'seal-producer.py',SELF.encode())
notes="# R1 original external-evidence execution preservation\n\nThis directory preserves the original completed R1 external-evidence-contract execution, exact HEAD 2a86462a1ab20c68151719ba4635e3c294391e64 and tree 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4. All 12 original stages exited 0; the lane took 213.820 seconds under its unchanged 2,700-second limit. The original readiness suite reported 78 methods / 34.516 seconds / OK. Four source records are byte-identical to the independently pinned 423-byte source identity. The original 14-object map was verified and fetched remained empty.\n\nAll 27 original files are present under flat/original/. The complete closed-directory inventory contained no nested log files; none were omitted. The unchanged original driver, approved packaging producer and pinned closed-log manifest are also expanded. The complete 31-member ZIP has been verified by CRC, bytes and SHA256 on both hosts, and official version-pinned transfer and actual PTY provenance are retained.\n\nThis is separate local R1 external evidence. It does not substitute for the original repository-truth lane or separate W1 control suite, and it confers no hosted or later-revision qualification. Historical failed and UNKNOWN records are unchanged. No tests, source/Git actions, publication or stage materialization were performed by this preservation.\n"
save(C/'README.md',notes.encode())
vf=json.loads(read(C/'copy-verification.json'))
summary={'schema':'trnm-R1-external-original-copy-seal-v1','sealed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'verified','head':'2a86462a1ab20c68151719ba4635e3c294391e64','tree':'5c26776f96f15fd131e85a5c2d7c5e895ad7fab4','original_status':'passed','original_lane_exit':0,'original_lane_seconds':vf['original_lane_elapsed_seconds'],'original_summary_sha256':'e261ab55ca4eb6104c3087d3e5d2a82fde3009d6cb848a782255cc1e35a83360','original_files':27,'required_flat_originals':27,'nested_originals':0,'original_bytes':112033,'zip_members':31,'all_originals_and_driver_expanded':True,'source_identity_sha256':'1b8638f7d5e3fb28abc25c06208df4e189ba3b86c7d0d3a12fb2a431607b7e03','tests_rerun':False,'stage_written':False,'hosted_qualification':False,'future_revision_qualification':False,'remote_publication_claim':False,'repository_truth_pass_claimed':False,'original_readiness_suite':vf['original_readiness_suite']}
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
manifest={'schema':'trnm-R1-external-preserved-files-v1','root':str(C),'file_count':len(files),'total_bytes':sum(r['bytes'] for r in files),'files':files,'manifest_excludes_itself':True,'stage_written':False}
mi=save(C/'preserved-files.json',js(manifest))
summaryinfo={'path':str(C/'preservation-summary.json'),'bytes':(C/'preservation-summary.json').stat().st_size,'sha256':hashlib.sha256(read(C/'preservation-summary.json')).hexdigest()}
print(json.dumps({'directory':str(C),'manifest':mi,'summary':summaryinfo,'file_count_excluding_manifest':len(files),'bytes_excluding_manifest':manifest['total_bytes'],'stage_written':False}))
