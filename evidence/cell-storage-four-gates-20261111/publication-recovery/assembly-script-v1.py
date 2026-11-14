from pathlib import Path,PurePosixPath
import copy,hashlib,json,os,re,shutil,subprocess,sys,tarfile,time,traceback
REPO=Path('/home/qian-qi/work/chain-cell-storage-four-gates-20261111-2bfb-publish')
AUDIT=Path('/home/qian-qi/work/chain-cell-storage-four-gates-20261111-2bfb-publish-setup/final-publication')
SCRIPT=Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-final-assemble-v1.py')
C3='030de92be05bfd4f73e199098c12dfeaedf29b17'
BASE='30ce6e99c5d0d86e6563a49786e8b1e41b44c6c6'
BEFORE='6985aca3803debe2945eebbc55e6c495598ae609'
EVID=REPO/'evidence/cell-storage-four-gates-20261111'
AUTHOR=Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-final-authoring-20261112.json')
NL=chr(10); D=chr(36)
AUDIT.mkdir(exist_ok=False)
state={'schema':'cell-four-gate-final-publication-v1','runtime_head':C3,'base_head':BASE,'status':'assembling','assembly_completed':False,'completed':False,'commands':[],'archives':[],'native_rerun':False,'github_write':False}
def save():
 p=AUDIT/'summary.json';q=AUDIT/'summary.json.tmp';q.write_text(json.dumps(state,indent=2,sort_keys=True)+NL);os.replace(q,p)
def put(path,data):
 path.parent.mkdir(parents=True,exist_ok=True)
 if isinstance(data,str):data=data.encode()
 with path.open('xb') as f:f.write(data)
def sha(data):return hashlib.sha256(data).hexdigest()
def pinned(path,size,digest):
 before=path.stat();b=path.read_bytes();after=path.stat()
 key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert key(before)==key(after),(str(path),'changed during read')
 assert len(b)==size and sha(b)==digest,(str(path),'size/SHA mismatch')
 return b
def command(name,args,timeout=300,required=True):
 started=time.monotonic();timed=False
 try:
  r=subprocess.run(args,cwd=REPO,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
  code=r.returncode;out=r.stdout;err=r.stderr
 except subprocess.TimeoutExpired as e:
  code=124;timed=True;out=e.stdout or b'';err=e.stderr or b''
 put(AUDIT/(name+'.stdout'),out);put(AUDIT/(name+'.stderr'),err)
 item={'name':name,'args':args,'exit_code':code,'timed_out':timed,'elapsed_seconds':time.monotonic()-started,'stdout_bytes':len(out),'stdout_sha256':sha(out),'stderr_bytes':len(err),'stderr_sha256':sha(err)}
 state['commands'].append(item);save();print(json.dumps({'command':name,'exit_code':code,'timed_out':timed}),flush=True)
 if required:assert code==0 and not timed,(name,code)
 return out,err,item
def git(args):
 return subprocess.check_output(['git']+args,cwd=REPO).decode().strip()
def safe_members(t):
 ms=t.getmembers();names=[m.name for m in ms]
 assert len(names)==len(set(names))
 for m in ms:
  p=PurePosixPath(m.name)
  assert m.isfile() and not p.is_absolute() and '..' not in p.parts and m.name=='/'.join(p.parts),m.name
 return ms
def admit_archive(label,path,size,digest,count,manifest_name,external=None,prefix=''):
 pinned(path,size,digest)
 with tarfile.open(path,'r:gz') as t:
  ms=safe_members(t);assert len(ms)==count
  names={m.name for m in ms}
  if external:
   manifest_raw=pinned(*external);manifest=json.loads(manifest_raw)
  else:
   manifest_raw=t.extractfile(manifest_name).read();manifest=json.loads(manifest_raw)
  rows=manifest['files'];assert len({r['path'] for r in rows})==len(rows)
  checked=set();streams=0
  for row in rows:
   name=prefix+row['path'];assert name in names,name
   size_key='bytes' if 'bytes' in row else 'size'
   assert size_key in row and isinstance(row[size_key],int)
   h=hashlib.sha256();length=0
   with t.extractfile(name) as f:
    while b:=f.read(1024*1024):length+=len(b);h.update(b)
   assert length==row[size_key] and h.hexdigest()==row['sha256'],name
   checked.add(name)
   if name.endswith(('.stdout','.stderr','.log')):streams+=1
  extras=names-checked
  if label=='desktop':
   assert extras=={prefix+n for n in manifest['self_exclusions']}
   checks=t.extractfile(prefix+'SHA256SUMS').read()
   lines=checks.decode().splitlines();assert len(lines)==118
   for line in lines:
    digest2,name=line.split('  ',1);assert sha(t.extractfile(prefix+name).read())==digest2
  elif external:
   assert extras==({manifest_name} if manifest_name else set()),extras
  else:assert extras=={manifest_name},extras
  small={}
  for m in ms:
   if m.size<=2*1024*1024 and ('/' not in m.name or label in ('current','prior','desktop')):
    small[m.name]=t.extractfile(m).read()
  rec={'label':label,'source_path':str(path),'bytes':size,'sha256':digest,'members':len(ms),'manifest_files_verified':len(rows),'streams_verified':streams,'manifest_sha256':sha(manifest_raw),'prefix':prefix,'raw_bytes_preserved':True}
  state['archives'].append(rec);save()
  return {'path':path,'record':rec,'manifest':manifest,'manifest_raw':manifest_raw,'small':small,'prefix':prefix}
def extract_packet(packet,target,expected_invalid):
 invalid=[]
 with tarfile.open(packet['path'],'r:gz') as t:
  for m in safe_members(t):
   rel=m.name
   prefix=packet['prefix']
   if prefix:
    assert rel.startswith(prefix);rel=rel[len(prefix):]
   b=t.extractfile(m).read()
   dest=rel
   if rel.endswith('.json'):
    try:json.loads(b)
    except (ValueError,UnicodeError) as e:
     invalid.append({'original':rel,'expanded':rel+'.raw','sha256':sha(b),'bytes':len(b),'error':str(e)})
     dest=rel+'.raw'
   put(target/dest,b)
 assert {(r['original'],r['sha256']) for r in invalid}==set(expected_invalid),invalid
 return invalid
try:
 save()
 a_raw=pinned(AUTHOR,36216,'0cfb34f997b2a5e379d3597982c64e66ec754d8afe84eafda60d4ad02d849fbf');a=json.loads(a_raw)
 assert a['runtime_head']==C3 and a['base_head']==BASE and a['pr']==923
 assert git(['rev-parse','HEAD'])==C3
 assert git(['branch','--show-current'])=='fix/chain-cell-storage-four-gates-20261111-2bfb'
 assert not git(['status','--porcelain=v1'])
 command('preflight',['bash','scripts/project-preflight.sh','--audit'],60)
 state['start_head']=C3;state['start_tree']=git(['rev-parse','HEAD^{tree}']);save()
 current=admit_archive('current',Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-recovered-original-current.tar.gz'),286100,'38519564908a3bd7afbaed914c866f06331b4b421532dbce86b2ebef145b0954',206,'remote-current-records/manifest.json',prefix='remote-current-records/')
 prior=admit_archive('prior',Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-recovered-original-prior.tar.gz'),183220,'64c3d37283e682830f65cd9b9a90d39e806f3f029aa2af5e9c9f9457900b80cc',177,'SNAPSHOT_MANIFEST.json')
 desktop=admit_archive('desktop',Path('/home/qian-qi/work/desktop-publication-records-export-2bfb-v1/desktop-publication-records.tar.gz'),289899,'2fd62f02a7472f854dd851aa91d665b22f86bf6f5ad1a2e56141303df0270e4f',119,'desktop-publication-records/MANIFEST.json',prefix='desktop-publication-records/')
 nr=Path('/home/qian-qi/work/chain-cell-four-gates-native-codeql-recovery-2bfb')
 native=admit_archive('native-codeql',nr/'recovered-native-codeql-selected-raw.tar.gz',20705422,'e5cb5c7cffebf9c48ba0f414ac4b6e2c31af39ce403bdf2a99dbcaeffb459da0',534,None,external=(nr/'recovered-selected-manifest.json',240425,'9f9ff7aa40a48146a83e36ec3ca47fe2196286c849959197f29381566dff3375'))
 dr=Path('/home/qian-qi/work/chain-cell-four-gates-discovery-ci-recovery-2bfb')
 discovery_manifest=(dr/'MANIFEST.json').read_bytes();assert sha(discovery_manifest)=='ab87e5187eb73978a9f20dfe527720589e53f5946dadb242fc297117b1b4c6c4'
 discovery=admit_archive('next-work-qrom',dr/'recovered-ci-records.tar.gz',1530054,'7438a1a3b4206d305a93e2af9f23ad66e548e330f7d796ea04c9fa3f91f5a6d5',186,'MANIFEST.json',external=(dr/'MANIFEST.json',len(discovery_manifest),'ab87e5187eb73978a9f20dfe527720589e53f5946dadb242fc297117b1b4c6c4'))
 bundle=Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-recovered-before-source.bundle')
 bundle_bytes=pinned(bundle,3994,'36913620ab2d97421b42f4402cb62cae29a98de01c611c7a9a814f0945a63651')
 command('before-bundle-verify',['git','bundle','verify',str(bundle)],60)
 command('before-bundle-unbundle',['git','bundle','unbundle',str(bundle)],60)
 assert git(['rev-list','--parents','-n','1',BEFORE]).split()==[BEFORE,BASE]
 paths=git(['ls-tree','-r','--name-only',C3]).splitlines()
 testpaths=[p for p in paths if p.endswith('/auth_time_fairness_tests.rs')];assert len(testpaths)==1
 testpath=testpaths[0];before_blob=git(['rev-parse',BEFORE+':'+testpath]);current_blob=git(['rev-parse',C3+':'+testpath])
 assert before_blob==current_blob=='6244859ea896ff0c729121129660e9d065d429a6'
 state['before_source']={'head':BEFORE,'parent':BASE,'test_path':testpath,'test_blob':before_blob,'c3_same_test_blob':True,'changed_paths':git(['diff','--name-only',BASE,BEFORE]).splitlines()}
 assert not EVID.exists(),'evidence target exists; reconcile instead of overwriting'
 EVID.mkdir(parents=True)
 put(EVID/'raw/remote-current-records.tar.gz',current['path'].read_bytes())
 put(EVID/'raw/remote-prior-records.tar.gz',prior['path'].read_bytes())
 put(EVID/'raw/cell-four-before-source.bundle',bundle_bytes)
 extract_packet(current,EVID/'current',[])
 extract_packet(prior,EVID/'prior',[])
 put(EVID/'desktop-publication/desktop-publication-records.tar.gz',desktop['path'].read_bytes())
 renames=extract_packet(desktop,EVID/'desktop-publication/expanded',[('setup/summary.json','5679eb1e5aaf90c8de7d049f1e01549b3597441c45e4f1a6138f8d18df2a9784')])
 put(EVID/'desktop-publication/filename-map.json',json.dumps({'schema':'expanded-original-filename-map-v1','archive_unchanged':True,'removed_archive_prefix':desktop['prefix'],'renames':renames},indent=2,sort_keys=True)+NL)
 put(EVID/'desktop-publication/README.md','# Desktop publication records'+NL+NL+'The [original archive](desktop-publication-records.tar.gz) is unchanged. The [expanded manifest](expanded/MANIFEST.json) pins original bytes. The single invalid setup JSON is retained as [summary.json.raw](expanded/setup/summary.json.raw); [the filename map](filename-map.json) records its original identity. This is the prior C3 source/publication audit, not a new native execution.'+NL)
 for packet,source,dest,archive_name,manifest_name,receipt_name in (
  (native,nr,EVID/'hosted-ci/native-codeql','recovered-native-codeql-selected-raw.tar.gz','recovered-selected-manifest.json','recovery-result.json'),
  (discovery,dr,EVID/'hosted-ci/next-work-qrom','recovered-ci-records.tar.gz','MANIFEST.json','FINAL_RECEIPT.json')):
  put(dest/archive_name,packet['path'].read_bytes());put(dest/manifest_name,packet['manifest_raw'])
  rb=(source/receipt_name).read_bytes();json.loads(rb);put(dest/receipt_name,rb)
  for name in ('README.md','REVIEW.md','REVIEW.json','observations.json','local-interruption.json'):
   if name in packet['small']:
    put(dest/(name+'.raw' if name.endswith('.md') else name),packet['small'][name])
  extra=source/'readback-transport-observation.json'
  if extra.is_file():b=extra.read_bytes();json.loads(b);put(dest/extra.name,b)
  put(dest/'README.md','# Retained CI observations'+NL+NL+'The [original-byte archive]('+archive_name+') has its own recorded archive identity. The [member manifest]('+manifest_name+') and [recovery receipt]('+receipt_name+') describe verification and recovery limits. Original Markdown, when copied here, uses a .md.raw suffix; its unchanged bytes also remain in the archive.'+NL)
 recovery=EVID/'publication-recovery'
 put(recovery/'authoring.json',a_raw)
 receipt_path=Path('/home/qian-qi/work/chain-cell-four-gates-2bfb-original-recovery-receipt-20261112.json')
 put(recovery/'original-package-recovery.json',pinned(receipt_path,4833,'a494d2c22944f654725cfc109f72606c6391762ed3661cdfc9df3a355798663a'))
 put(recovery/'interrupted-local-review.json',json.dumps(a['interrupted_local_review'],indent=2,sort_keys=True)+NL)
 put(recovery/'c3-hosted-workflow-snapshot.json',json.dumps(a['c3_hosted_snapshot'],indent=2,sort_keys=True)+NL)
 put(recovery/'before-source-verification.json',json.dumps(state['before_source'],indent=2,sort_keys=True)+NL)
 put(recovery/'archive-admission.json',json.dumps({'archives':state['archives'],'regular_files_only':True,'all_listed_member_hashes_verified':True,'no_native_execution':True},indent=2,sort_keys=True)+NL)
 local_matches=list(Path('/home/qian-qi/work/chain-cell-storage-four-gates-20261111-2bfb-publish-setup').rglob('cell-four-local-records.tar.gz'))
 assert not local_matches,'unexpected local packet found; preserve and review before attribution'
 put(recovery/'local-records-recovery-scope.json',json.dumps({'searched_owned_setup':True,'exact_filename':'cell-four-local-records.tar.gz','found':False,'lost_local_raw_bytes_claimed_in_commit':False,'six_transfer_failure_receipts_original_local_files_recovered':False,'remote_desktop_original_archive_preserved':True},indent=2,sort_keys=True)+NL)
 put(EVID/'README.md',a['evidence_readme'])
 plan=REPO/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
 old=plan.read_text();lines=old.splitlines(keepends=True)
 assert lines[0].startswith('**Cell storage four-gate continuation, 2026-11-11') and lines[36]=='**Paged real-model research bridge — NOT_RUN; qualification HOLD:**'+NL
 tail=''.join(lines[36:])
 old_heading='**Paged real-model research bridge — NOT_RUN; qualification HOLD:**'
 new_heading='**Historical paged real-model research bridge — NOT_RUN at that checkpoint; superseded by executed observations above:**'
 assert tail.count(old_heading)==1;tail=tail.replace(old_heading,new_heading,1)
 plan.write_text(a['plan_prefix']+tail)
 spec=REPO/'docs/development/specs/pon/CELL_STORAGE_FOUR_GATE_CONTINUATION_V1.md'
 old=spec.read_text()
 status='Status: implementation candidate; native execution is recorded separately.'
 assert old.count(status)==1 and old.count('## Acceptance boundaries')==1
 old=old.replace(status,'Status: local native execution recorded on C3; production qualification HOLD.',1)
 spec.write_text(old.replace('## Acceptance boundaries',a['recorded_spec']+'## Acceptance boundaries',1))
 codeql=REPO/a['ci_changes']['codeql_workflow'];old=codeql.read_text()
 marker='  pull_request:'+NL+'    branches:'+NL+'      - main'+NL+'      - fix/chain-six-axis-performance-20261103'+NL
 assert old.count(marker)==1
 added='      - '+a['ci_changes']['add_exact_pull_request_base']+NL
 new=old.replace(marker,marker+added,1);assert new.replace(added,'',1)==old;codeql.write_text(new)
 patch_records=[]
 for rel in (a['ci_changes']['next_arch_workflow'],a['ci_changes']['contract']):
  path=REPO/rel;old=path.read_text();new=old
  loop='          for selector in "'+D+'{required[@]}"; do'+NL
  assert new.count(loop)==2,(rel,'two exact storage loops required')
  stem='            stem="'+D+'{selector//:/-}"'+NL
  new=new.replace(loop,loop+stem)
  expected=(2,2) if rel.endswith('.yml') else (3,4)
  for (prefix,n) in zip(('native-storage-component-','native-storage-'),expected):
   token=prefix+D+'selector';assert new.count(token)==n,(rel,token,new.count(token),n)
   new=new.replace(token,prefix+D+'stem')
  assert new.count('--test "'+D+'selector"')==old.count('--test "'+D+'selector"')
  assert new.count('--lib "'+D+'selector"')==old.count('--lib "'+D+'selector"')
  path.write_text(new);patch_records.append({'path':rel,'old_sha256':sha(old.encode()),'new_sha256':sha(new.encode()),'storage_stems_added':2})
 put(recovery/'ci-scope.json',json.dumps({'codeql_added_pr_base':a['ci_changes']['add_exact_pull_request_base'],'patches':patch_records,'cargo_selectors_unchanged':True,'run_command_sh_unchanged':True},indent=2,sort_keys=True)+NL)
 corpus=REPO/'config/pon/pq-cross-branch-corpus-v1.json';raw=corpus.read_text();before=json.loads(raw);expected=copy.deepcopy(before)
 changed_paths=['docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md','docs/development/specs/pon/CELL_STORAGE_FOUR_GATE_CONTINUATION_V1.md',a['ci_changes']['codeql_workflow'],a['ci_changes']['next_arch_workflow'],a['ci_changes']['contract']]
 assert len(before['pinned_blobs'])==994 and len(before['required_paths'])==902
 bindings=[]
 for rel in changed_paths:
  prior_pin=before['pinned_blobs'][rel];assert git(['rev-parse',C3+':'+rel])==prior_pin
  after_pin=git(['hash-object',rel]);assert prior_pin!=after_pin
  needle=json.dumps(rel)+': '+json.dumps(prior_pin);replacement=json.dumps(rel)+': '+json.dumps(after_pin)
  assert raw.count(needle)==1;raw=raw.replace(needle,replacement,1)
  expected['pinned_blobs'][rel]=after_pin;bindings.append({'path':rel,'before':prior_pin,'after':after_pin})
 assert json.loads(raw)==expected
 corpus.write_text(raw)
 put(recovery/'source-binding-review.json',json.dumps({'changed':bindings,'preserved_pins':989,'total_pins':994,'required_paths':902,'all_other_fields_unchanged':True},indent=2,sort_keys=True)+NL)
 controls=[('storage-controls','scripts/ci/test_cell_storage_convergence_ci.py',19),('discovery-controls','scripts/ci/test_cell_discovery_v3_ci.py',5),('codeql-retention-controls','scripts/ci/test_codeql_retention.py',12)]
 for name,path,count in controls:
  out,err,item=command(name,[sys.executable,'-B',path],180)
  combined=(out+NL.encode()+err).decode()
  assert len(re.findall(r'^Ran '+str(count)+r' tests in [0-9.]+s$',combined,re.M))==1,(name,'wrong executed count')
  assert re.search(r'^OK$',combined,re.M),(name,'missing actual unittest OK')
  item['expected_tests']=count;item['executed_count_guard_passed']=True;save()
 command('inventory',[sys.executable,'-B','scripts/refresh_distributed_source_inventory.py','--check'],300)
 command('pq-bindings',[sys.executable,'-B','scripts/ci/check_pq_research_integration.py'],300)
 command('diff-check',['git','diff','--check'],60)
 tracked=set(git(['diff','--name-only',C3]).splitlines())
 allowed=set(changed_paths+['config/pon/pq-cross-branch-corpus-v1.json'])
 assert tracked==allowed,(tracked,allowed)
 assert not git(['diff',C3,'--','trillionnium'])
 assert not git(['diff',C3,'--','scripts/ci/run_cell_storage_four_gates_v1.py'])
 untracked=git(['ls-files','--others','--exclude-standard']).splitlines()
 assert all(p.startswith('evidence/cell-storage-four-gates-20261111/') for p in untracked),untracked
 state['tracked_source_scope']={'changed_paths':sorted(tracked),'rust_cargo_examples_unchanged_from_c3':True,'native_model_runner_unchanged_from_c3':True}
 state['assembly_completed']=True;state['status']='assembled-controls-passed-awaiting-final-index-and-repository-check';save()
 for name in ('storage-controls','discovery-controls','codeql-retention-controls','inventory','pq-bindings','diff-check','preflight'):
  for suffix in ('.stdout','.stderr'):put(recovery/'controls'/(name+suffix),(AUDIT/(name+suffix)).read_bytes())
 put(recovery/'controls/summary.json',json.dumps({'schema':'publication-precommit-controls-v1','commands':[x for x in state['commands'] if x['name'] in {v[0] for v in controls}|{'inventory','pq-bindings','diff-check','preflight'}],'no_native_execution':True,'runtime_attribution':C3},indent=2,sort_keys=True)+NL)
 print(json.dumps({'assembly_completed':True,'summary':str(AUDIT/'summary.json'),'status':state['status']}),flush=True)
except Exception as e:
 state['status']='assembly_failed';state['error']=repr(e);state['assembly_completed']=False;save()
 put(AUDIT/'assembly-error.txt',traceback.format_exc());print(json.dumps({'assembly_completed':False,'error':repr(e),'summary':str(AUDIT/'summary.json')}),flush=True);raise
