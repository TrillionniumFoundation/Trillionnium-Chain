import os,json,pathlib,hashlib,time,shutil
ROOT=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
OUT=ROOT/'publication-materialization-v5'
JOBS=[
 ('initial-readonly-inventory','1a1b6b17808-12894-5f1'),
 ('sized-official-inventory','1a1b6b3c0ca-12894-606'),
 ('first-archive-raw','1a1b6b58336-12894-611'),
 ('bounded-remaining-recovery','1a1b6b770e6-12894-61f'),
 ('complete-checkout-validation','1a1b6bf8b3c-12894-675'),
]
def save(path,value):
 with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def ident(path):
 h=hashlib.sha256();n=0
 with path.open('rb') as f:
  while True:
   b=f.read(1048576)
   if not b:break
   h.update(b);n+=len(b)
 return {'path':path.relative_to(ROOT).as_posix(),'bytes':n,'sha256':h.hexdigest()}
checkout=json.loads((OUT/'checkout-result.json').read_text())
assert checkout['result']=='COMPLETE_VERIFIED_CHECKOUT' and checkout['missing_unique_blobs']==0
assert checkout['preflight_exit_code']==0 and checkout['identity_after_preflight']['status']==''
records=[];missing_sources=[]
for label,job in JOBS:
 source=pathlib.Path('/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs')/job
 target=OUT/'runtime-jobs'/job;target.mkdir(parents=True,exist_ok=False)
 names=sorted(p.name for p in source.iterdir());matches=[]
 def inspect(value,location,depth=0):
  if depth>4 or not isinstance(value,dict):return
  for key in ('args','argv'):
   args=value.get(key)
   if isinstance(args,list) and len(args)>=2 and args[0]=='-c' and isinstance(args[1],str) and args[1].startswith('/usr/bin/python3 - '):
    matches.append((location+'.'+key,args[1]))
  command=value.get('command')
  if isinstance(command,str) and command.startswith('/usr/bin/python3 - '):matches.append((location+'.command',command))
  for key in ('job','request','execution','spec','launch'):
   if isinstance(value.get(key),dict):inspect(value[key],location+'.'+key,depth+1)
 for path in sorted(source.iterdir()):
  if path.is_file() and path.suffix=='.json' and path.stat().st_size<2097152:
   try:value=json.loads(path.read_bytes())
   except (ValueError,UnicodeDecodeError):continue
   inspect(value,path.name)
 unique=sorted(set(command for _,command in matches))
 rec={'job_id':job,'label':label,'runtime_job_dir':str(source),'observed_files':names,'source_candidates':[where for where,_ in matches],'source_retained':False,'logs_retained':[]}
 if len(unique)==1:
  path=target/'actual-shell-command.sh'
  with path.open('x') as f:f.write(unique[0])
  rec.update(source_retained=True,source=ident(path))
 else:missing_sources.append({'job_id':job,'candidates':len(unique),'files':names})
 for name in ('stdout.log','stderr.log','stdout','stderr','status.json','state.json','result.json','exit.json','completion.json'):
  path=source/name
  if path.is_file() and path.stat().st_size<2097152:
   dest=target/name
   with path.open('rb') as f,dest.open('xb') as g:shutil.copyfileobj(f,g)
   rec['logs_retained'].append(ident(dest))
 save(target/'retention.json',rec);records.append(rec)
save(OUT/'runtime-source-retention.json',{'jobs':records,'missing_sources':missing_sources})
if missing_sources:
 print(json.dumps({'result':'SOURCE_RETENTION_NEEDS_REVIEW','missing_sources':missing_sources}),flush=True)
 raise SystemExit(2)
included=[];excluded=[]
for path in sorted(OUT.rglob('*')):
 if not path.is_file() or path.name=='archival-files.json':continue
 row=ident(path)
 if path.parent.name=='raw-blobs' and path.suffix=='.raw':
  receipt=json.loads(path.with_suffix('.receipt.json').read_text())
  assert row['bytes']==receipt['actual_bytes'] and row['sha256']==receipt['raw_sha256']
  assert receipt['imported'] is True and receipt['actual_git_blob_sha1']==path.stem
  excluded.append({**row,'git_blob_sha1':path.stem,'reason':'exact historical Git blob payload retained locally; do not duplicate in evidence archive'})
 else:included.append(row)
assert len(excluded)==19 and sum(x['bytes'] for x in excluded)==101102868
manifest={'schema':'pon-publication-materialization-archive-files-v1','root':str(ROOT),'path_base':'ROOT','files':included,'included_file_count':len(included),'included_total_bytes':sum(x['bytes'] for x in included),'excluded_raw_payloads':{'count':len(excluded),'total_bytes':sum(x['bytes'] for x in excluded),'items':excluded},'source_commit':checkout['source_commit'],'source_tree':checkout['source_tree'],'tracked_paths':checkout['tracked_paths'],'unique_blobs':checkout['unique_blobs'],'checkout_bytes':checkout['checkout_bytes'],'missing_unique_blobs':0,'checkout_result_path':'publication-materialization-v5/checkout-result.json','refs_unchanged':checkout['refs_unchanged'],'original_failures_retained_in':['publication-materialization-v1','publication-materialization-v2','publication-materialization-v3','publication-materialization-v4'],'runtime_jobs':[job for _,job in JOBS],'manifest_excludes_itself':True,'generated_unix_seconds':time.time()}
save(OUT/'archival-files.json',manifest)
print(json.dumps({'result':'ARCHIVAL_MANIFEST_READY','manifest':ident(OUT/'archival-files.json'),'included_file_count':len(included),'included_total_bytes':sum(x['bytes'] for x in included),'excluded_raw_count':len(excluded),'excluded_raw_total_bytes':sum(x['bytes'] for x in excluded),'actual_commands_retained':len(records),'checkout_result':ident(OUT/'checkout-result.json')}),flush=True)
