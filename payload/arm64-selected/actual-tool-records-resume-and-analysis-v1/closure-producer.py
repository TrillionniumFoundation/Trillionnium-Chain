import datetime,hashlib,json,os,stat,sys
from pathlib import Path
records,scripts=json.loads(sys.argv[1])
BASE=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
OUTER=Path('/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1')
OUT=BASE/'actual-tool-records-resume-and-analysis-v1';OUT.mkdir(mode=0o700)
def need(v,m):
 if not v:raise ValueError(m)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
 a=p.lstat();need(p.resolve(strict=True)==p and stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=32*1024*1024,'REGULAR_SOURCE')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')as f:
  need(fp(a)==fp(os.fstat(f.fileno())),'OPEN_IDENTITY');b=f.read(a.st_size+1);need(fp(a)==fp(os.fstat(f.fileno())),'FD_IDENTITY')
 need(len(b)==a.st_size and fp(a)==fp(p.lstat()),'PATH_IDENTITY');return b,fp(a)
def put(p,b):
 with p.open('xb')as f:f.write(b)
 r,_=read(p);need(r==b,'OUTPUT_READBACK');return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def putj(p,v):return put(p,(json.dumps(v,sort_keys=True,indent=2)+'\n').encode())
for name,v in records.items():putj(OUT/name,v)
for name,v in scripts.items():put(OUT/name,v.encode())
put(OUT/'closure-producer.py',sys.argv[2].encode())
selected_terminal=records['h5df-arm-selected-resume-terminal.json']
raw=bytes.fromhex(selected_terminal['bytes_hex'])
need(selected_terminal['status']['state']=='exited'and selected_terminal['status']['exit_code']==0 and selected_terminal['output_complete']is True and selected_terminal['status']['capture_error']is None and selected_terminal['offset']==0 and selected_terminal['next_offset']==len(raw)==2251 and hashlib.sha256(raw).hexdigest()=='d50e6c48771015e3a52a1cf9f3c1ea5fdb9e13cf7988a3a46cabb030e6bcdf66','ACTUAL_SELECTED_TERMINAL')
close=BASE/'final-review-v4'
targets=[close/'EVIDENCE_INDEX.json',close/'SEAL.json']
rows=[];identities={};dirs={}
def walk(root,prefix):
 pending=[root]
 while pending:
  d=pending.pop();st=d.lstat();need(stat.S_ISDIR(st.st_mode)and not d.is_symlink()and d.resolve(strict=True)==d,'DIRECTORY')
  dirs[str(d)]=(st.st_dev,st.st_ino,st.st_mode,st.st_nlink)
  for e in sorted(os.scandir(d),key=lambda x:x.name):
   p=Path(e.path);s=p.lstat()
   if stat.S_ISDIR(s.st_mode):pending.append(p)
   elif stat.S_ISREG(s.st_mode):
    need(p not in targets,'SEAL_ALREADY_EXISTS')
    b,f=read(p);rel=prefix+'/'+p.relative_to(root).as_posix()
    rows.append({'path':str(p),'archive_relative_path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':{'host':'mac','path':str(p)}});identities[str(p)]=f
   else:raise ValueError('SYMLINK_OR_SPECIAL')
walk(OUTER,'outer');walk(BASE,'selected')
rows.sort(key=lambda x:x['archive_relative_path'])
need(len(rows)<1000 and sum(x['bytes']for x in rows)<=64*1024*1024,'CLOSURE_BOUND')
for row in rows:
 b,f=read(Path(row['path']));need(f==identities[row['path']]and len(b)==row['bytes']and hashlib.sha256(b).hexdigest()==row['sha256'],'FINAL_SOURCE_FENCE')
for path,identity in dirs.items():
 s=Path(path).lstat();need((s.st_dev,s.st_ino,s.st_mode,s.st_nlink)==identity,'DIRECTORY_IDENTITY')
facts=close/'exact-confirmation-facts.json';fb,_=read(facts)
need(len(fb)==19677 and hashlib.sha256(fb).hexdigest()=='38005efb3f1dd717bac424109075ee56fdaba370c23b759f3ace6b16c02e9edb','FACTS_PIN')
index=putj(close/'EVIDENCE_INDEX.json',{'schema':'trnm-H5DF-arm64-bounded-original-evidence-index-v1','roots':[str(OUTER),str(BASE)],'files':rows,'file_count':len(rows),'total_bytes':sum(x['bytes']for x in rows),'index_and_seal_excluded':True,'all_sources_regular_singlelink_and_stable':True,'closure_scope':'Only two explicit task roots; no repository, global temporary tree, stage or active other task','selected_artifact_scope':'161 central-directory entries, 25 selected records independently CRC/SHA checked, not whole ZIP','original_attempts_preserved':True})
seal={'schema':'trnm-H5DF-arm64-bounded-original-evidence-seal-v1','status':'CLOSED','closed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'index':index,'indexed_files':len(rows),'indexed_bytes':sum(x['bytes']for x in rows),'facts':{'path':str(facts),'bytes':len(fb),'sha256':hashlib.sha256(fb).hexdigest()},'actual_selected_terminal':{'path':str(OUT/'h5df-arm-selected-resume-terminal.json'),'session_id':selected_terminal['session_id'],'exit_code':0,'output_complete':True,'original_output_bytes':2251,'original_output_sha256':hashlib.sha256(raw).hexdigest()},'no_active_GET_or_native_writer':True,'whole_ZIP_SHA_verified':False,'no_source_ref_stage_changes':True}
sp=putj(close/'SEAL.json',seal)
print(json.dumps({'status':'CLOSED','index':index,'seal':sp,'indexed_files':len(rows),'indexed_bytes':sum(x['bytes']for x in rows),'physical_files_in_two_roots':len(rows)+2,'physical_bytes_in_two_roots':sum(x['bytes']for x in rows)+index['bytes']+sp['bytes'],'facts_sha256':hashlib.sha256(fb).hexdigest()},sort_keys=True))
