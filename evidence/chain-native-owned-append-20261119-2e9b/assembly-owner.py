from pathlib import Path
import subprocess,json,time,resource,sys,os,hashlib,traceback,tarfile,gzip,stat
s=Path('/home/qq/work/chain-native-first-graph-host-20261119-2e9b/source');base=s.parent;out=base/'candidate-freeze-14';out.mkdir(exist_ok=False);(out/'owner.py').write_text(sys.argv[1]);inp=json.loads(sys.argv[2])
prefix='evidence/chain-native-owned-append-20261119-2e9b';ev=s/prefix
res={'schema':'chain-native-owned-append-candidate-freeze-v1','complete':False,'source_parent':'f0a8364118df01113c14d6a81fbb6fdb6210e4ff','branch':'fix/chain-native-owned-append-20261119-2e9b','stages':[],'new_f0_run':None,'business_qualification':False,'full_physical_cost_closed':False}
def save():(out/'RESULT.json').write_text(json.dumps(res,indent=2)+'\n')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(name,args):
 t=time.monotonic();c=resource.getrusage(resource.RUSAGE_CHILDREN)
 with (out/(name+'.stdout')).open('xb') as a,(out/(name+'.stderr')).open('xb') as b:rc=subprocess.call(args,cwd=s,stdout=a,stderr=b)
 d=resource.getrusage(resource.RUSAGE_CHILDREN);row={'name':name,'command':args,'exit_code':rc,'wall_seconds':time.monotonic()-t,'child_user_cpu_seconds':d.ru_utime-c.ru_utime,'child_system_cpu_seconds':d.ru_stime-c.ru_stime};res['stages'].append(row);save();print(json.dumps(row),flush=True);return rc
try:
 assert run('preflight',['bash','scripts/project-preflight.sh'])==0
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=s,text=True).strip()==res['source_parent']
 audit=json.loads((base/'source-freeze-audit-12/RESULT.json').read_text());assert audit['complete'] is True
 for p,row in audit['source_files'].items():assert sha((s/p).read_bytes())==row['sha256'],p
 changed=subprocess.check_output(['git','diff','HEAD','--name-only'],cwd=s,text=True).splitlines()
 untracked=subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=s,text=True).splitlines()
 assert not subprocess.check_output(['git','diff','--name-only'],cwd=s).strip()
 prior_evidence=[str(p.relative_to(s)) for p in sorted(ev.iterdir()) if p.is_file()]
 staged=set(subprocess.check_output(['git','diff','--cached','--name-only','HEAD'],cwd=s,text=True).splitlines())
 assert staged==set(audit['changed']+audit['untracked']+prior_evidence)
 retained=base/'candidate-freeze-13'/'pre-packaging-evidence';retained.mkdir(exist_ok=False)
 for p in sorted(ev.iterdir()):
  if p.is_file():(retained/p.name).write_bytes(p.read_bytes())
 assert (retained/'candidate-source.patch').read_bytes()==(ev/'candidate-source.patch').read_bytes()
 assert run('retain-lossless-patch-container',['git','rm','--cached','--sparse','--',str((ev/'candidate-source.patch').relative_to(s))])==0
 (ev/'candidate-source.patch').unlink()
 (ev/'raw-observations.tar.gz').unlink()
 assert json.loads((base/'repository-truth-6/RESULT.json').read_text())['complete'] is True
 original_paths=sorted(audit['changed']+audit['untracked'])
 assert run('stage-reviewed-candidate',['git','add','--sparse','--']+original_paths)==0
 patch=subprocess.check_output(['git','diff','--binary','--cached','HEAD','--']+original_paths,cwd=s)
 (ev/'candidate-source.patch.gz').write_bytes(gzip.compress(patch,mtime=0))
 (ev/'source-audit.json').write_bytes((base/'source-freeze-audit-12/RESULT.json').read_bytes())
 raw_paths=[]
 for parent in sorted(base.iterdir()):
  if parent.name in ('source','target',out.name):continue
  if parent.is_dir():raw_paths.extend(p for p in parent.rglob('*') if p.is_file())
  elif parent.is_file():raw_paths.append(parent)
 raw_paths=sorted(raw_paths);manifest=[]
 for p in raw_paths:
  st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink() and st.st_nlink==1,str(p)
  raw=p.read_bytes();manifest.append({'path':str(p.relative_to(base)),'bytes':len(raw),'sha256':sha(raw)})
 archive=ev/'raw-observations.tar.gz'
 with archive.open('xb') as rawstream,gzip.GzipFile(filename='',mode='wb',fileobj=rawstream,mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w|') as tar:
  for p,row in zip(raw_paths,manifest):
   assert sha(p.read_bytes())==row['sha256'];tar.add(p,arcname=row['path'],recursive=False)
 verified={}
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar.getmembers():
   assert member.isfile();raw=tar.extractfile(member).read();verified[member.name]=(len(raw),sha(raw))
 assert len(verified)==len(manifest) and all(verified[x['path']]==(x['bytes'],x['sha256']) for x in manifest)
 archive_manifest={'schema':'chain-owned-append-lossless-raw-retention-v1','archive_bytes':archive.stat().st_size,'archive_sha256':sha(archive.read_bytes()),'file_count':len(manifest),'all_regular_files_in_completed_local_stage_directories_retained':True,'excluded_directories':['source (Git-backed candidate and parent)','target (rebuildable binaries)',out.name+' (this evidence assembly, separately retained owner/result)'],'files':manifest}
 (ev/'raw-files.json').write_text(json.dumps(archive_manifest,indent=2)+'\n')
 observations=[];command_rows=[];unknown_cpu=[]
 for path in sorted(base.glob('*/RESULT.json')):
  if path.parent==out:continue
  raw=path.read_bytes();value=json.loads(raw);entry={'path':str(path.relative_to(base)),'bytes':len(raw),'sha256':sha(raw),'reported_complete':value.get('complete'),'reported_exit_code':value.get('exit_code',value.get('native_exit_code')),'error':value.get('error')};observations.append(entry)
  stages=value.get('stages')
  if stages:selected=[(str(path.relative_to(base))+'#stages['+str(i)+']',row) for i,row in enumerate(stages)]
  else:selected=[(str(path.relative_to(base)),value)] if 'wall_seconds' in value else []
  if isinstance(value.get('preflight'),dict):selected.append((str(path.relative_to(base))+'#preflight',value['preflight']))
  for key,row in selected:
   command_rows.append({'id':key,**{k:row.get(k) for k in ('name','command','exit_code','wall_seconds','child_user_cpu_seconds','child_system_cpu_seconds')}})
   if row.get('child_user_cpu_seconds') is None or row.get('child_system_cpu_seconds') is None:unknown_cpu.append(key)
 for i,row in enumerate(res['stages']):command_rows.append({'id':out.name+'/RESULT.json#stages['+str(i)+']',**row})
 cost={'schema':'chain-owned-append-recorded-local-command-cost-v1','scope':'Actual retained local child process observations only; a sum of recorded non-overlapping command intervals, not full task time, full Chain cost or monetary bill. Build CPU is included in native command CPU. Unknown observations are never converted to zero.','source_parent':res['source_parent'],'command_rows':command_rows,'result_records':observations,'recorded_command_count':len(command_rows),'known_wall_seconds_sum':sum(x['wall_seconds'] for x in command_rows if x.get('wall_seconds') is not None),'known_child_user_cpu_seconds_sum':sum(x['child_user_cpu_seconds'] for x in command_rows if x.get('child_user_cpu_seconds') is not None),'known_child_system_cpu_seconds_sum':sum(x['child_system_cpu_seconds'] for x in command_rows if x.get('child_system_cpu_seconds') is not None),'missing_cpu_command_ids':unknown_cpu,'known_nonzero_command_exits':[{'id':x['id'],'exit_code':x['exit_code']} for x in command_rows if x.get('exit_code') not in (None,0)],'unmetered_or_unclosed':['controller and assistant orchestration outside recorded subprocess intervals','earlier read-only probes with no process CPU/wall measurement','remote automatic CI and future F0 are separate observations','monetary price, GitHub charge and provider invoice are unknown','historical ROOT connection 393 in F0 44451798839 remains incompletely observed'],'money':None,'full_physical_cost_closed':False}
 (ev/'cost-observations.json').write_text(json.dumps(cost,indent=2)+'\n')
 summary={'schema':'chain-owned-append-validation-summary-v1','complete_candidate_is_green':False,'authenticated':{'passed':133,'failed':0,'ignored':0,'raw':'authenticated-original-include-ignored-8/native-authenticated.log','sha256':'83ca708525ff68f8bfa67db329b769507f109f78ca5db832e8580e9c692dc371'},'post_write':{'passed':55,'failed':0,'ignored':0},'observer':{'passed':39,'failed':0,'ignored':0},'native_store':{'passed':37,'failed':0,'ignored':5},'detached':{'passed':25,'failed':0,'ignored':1},'history':{'passed':56,'failed':0,'ignored':1},'public_v3':{'passed':294,'failed':1,'ignored':2,'failed_test':'ingress::public_v3::scalar_cpu::metered_fact_tests::continuously_distinct_bad_products_exhaust_one_original_prepaid_domain','initial_credit_ns':400000000,'actual_paid_cpu_ns':298399949,'remaining_credit_ns':101600051,'minimum_start_reserve_ns':100000000,'fixed_attempts':512,'native_exit_code':101,'raw_stderr_sha256':'66e81978e52bb80618511a5f965ac41daae2b20b6d443066d61e0719496390e8'},'current_roster_reader':{'passed':20,'failed':0},'cross_branch_controls':{'passed':115,'failed':0},'authority_controls':{'passed':18,'failed':0},'hash_use_controls':{'passed':34,'failed':0},'strict_all_target_release_clippy_exit':0,'format_exit':0,'actual_node_linux_locked_graph_exit':0,'complete_workspace_locked_linux_metadata_exit':0,'complete_workspace_native_execution_qualified':False,'repository_truth_last':json.loads((base/'repository-truth-6/RESULT.json').read_text()),'repository_truth_remaining_input':'evidence/pon-work-native-certificates-20261107/mandatory_units/run-02-final/dense-repeat-u2.pmh1 missing from local sparse checkout; restore exact parent Git bytes, never repin or fabricate input','prior_f0':{'run_id':44451798839,'head':'3db79eb2682ba3bcbbf33557c5eee3b67731028f','phase_30s_goals':1,'four_second_goals':0,'denominator':6,'timely_ack':17,'packet_denominator':42,'qualification':False,'root_observation_393_complete':False},'new_f0':{'planned_invocations':1,'run_id':None,'qualification':False}}
 (ev/'validation-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 (ev/'READOUT.md').write_text(inp['readout'])
 (ev/'assembly-owner.py').write_bytes((out/'owner.py').read_bytes())
 (ev/'assembly-preparation-errors.json').write_text(json.dumps(inp['preparation_errors'],indent=2)+'\n')
 new_evidence=[str(p.relative_to(s)) for p in sorted(ev.iterdir()) if p.is_file()]
 assert run('stage-complete-evidence',['git','add','--sparse','--']+new_evidence)==0
 assert run('staged-diff-check',['git','diff','--cached','--check'])==0
 tree=subprocess.check_output(['git','write-tree'],cwd=s,text=True).strip();items=[]
 for rel in subprocess.check_output(['git','diff','--cached','--name-only','HEAD'],cwd=s,text=True).splitlines():
  metadata=subprocess.check_output(['git','ls-files','-s','--',rel],cwd=s,text=True).strip();left,right=metadata.split('\t',1);mode,oid,stage=left.split();assert right==rel and stage=='0'
  raw=(s/rel).read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==oid
  items.append({'path':rel,'absolute_path':str(s/rel),'mode':mode,'type':'blob','sha':oid,'bytes':len(raw),'sha256':sha(raw)})
 assert not subprocess.check_output(['git','diff','--name-only'],cwd=s).strip()
 manifest_pub={'schema':'chain-native-owned-append-exact-tree-publication-v1','source_parent':res['source_parent'],'parent_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=s,text=True).strip(),'tree':tree,'branch':res['branch'],'items':items}
 (out/'publication-manifest.json').write_text(json.dumps(manifest_pub,indent=2)+'\n')
 res.update(complete=True,tree=tree,file_count=len(items),archive_bytes=archive.stat().st_size,archive_sha256=sha(archive.read_bytes()),raw_file_count=len(manifest),readout_sha256=sha((ev/'READOUT.md').read_bytes()),cost_sha256=sha((ev/'cost-observations.json').read_bytes()),publication_manifest=str(out/'publication-manifest.json'));save();print(json.dumps(res,indent=2))
except BaseException as e:res['error']=repr(e);save();traceback.print_exc();raise
