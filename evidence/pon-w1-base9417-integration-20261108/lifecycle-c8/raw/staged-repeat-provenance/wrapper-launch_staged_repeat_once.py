#!/usr/bin/env python3
import pathlib,json,hashlib,subprocess,os,sys,time,argparse,re
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=pathlib.Path);ap.add_argument('--input-sha256',required=True);a=ap.parse_args()
ib=a.input.read_bytes();assert re.fullmatch('[0-9a-f]{64}',a.input_sha256) and hashlib.sha256(ib).hexdigest()==a.input_sha256
inp=json.loads(ib)
repo=pathlib.Path('/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b')
tool=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
head='4e007a87ceecbec8d265f6a70cfd71d512a514b5';tree='19a4f1a6e1cec5c27e595fa555b97cddc4717a3c'
assert inp['source_commit']==head and inp['source_tree']==tree

declaration_path=tool/'staged-one-repeat-declaration.json'
declaration_bytes=declaration_path.read_bytes()
assert hashlib.sha256(declaration_bytes).hexdigest()=='7b51a7dee784b9375eb1c1dcc9b8f54869538810c763ee1514208ba42912ce95'
declaration=json.loads(declaration_bytes)
assert declaration['source_commit']==head and declaration['source_tree']==tree
assert declaration['maximum_additional_attempts']==1 and declaration['stop_after_second_failure'] is True
assert declaration['test_parameters_changed'] is False and declaration['test_argv_changed'] is False
original=declaration['original'];original_path=pathlib.Path(original['manifest'])
original_bytes=original_path.read_bytes();assert hashlib.sha256(original_bytes).hexdigest()==original['manifest_sha256']=='a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25'
original_manifest=json.loads(original_bytes)
assert original_manifest['source_commit']==head and original_manifest['source_tree']==tree
assert original_manifest['qualification_complete'] is False
assert len(original_manifest['commands'])==4 and [x['exit'] for x in original_manifest['commands']]==[0,0,1,0]
for command in original_manifest['commands']:
 for stream in ('stdout','stderr'):
  record=command[stream];raw=pathlib.Path(record['path']).read_bytes()
  assert len(raw)==record['bytes'] and hashlib.sha256(raw).hexdigest()==record['sha256']
failed_row=original_manifest['commands'][2];assert failed_row['label']=='02-w1-retained-staged-tests'
failed_stderr=pathlib.Path(failed_row['stderr']['path']).read_bytes()
assert len(failed_stderr)==6501 and hashlib.sha256(failed_stderr).hexdigest()=='6523776cafbcfcb998f508af0a9a890ef1714adfc5a06aadd59a952baf4bca4c'
failed_text=failed_stderr.decode()
assert len(re.findall(r'^test_.* \.\.\. ok$',failed_text,re.M))==31
assert len(re.findall(r'^test_.* \.\.\. FAIL$',failed_text,re.M))==1
assert 'Ran 32 tests in ' in failed_text and 'FAILED (failures=1)' in failed_text
assert "['DEADLINE_EXHAUSTED_BEFORE_SPAWN']" in failed_text
original_terminal=original['terminal']
assert original_terminal['job_id']==original['job_id']=='1a1ba8f182e-12894-1b97'
assert original_terminal['state']=='failed' and original_terminal['exit_code']==1 and original_terminal['output_complete'] is True and original_terminal['output_durable'] is True
assert original_terminal['timed_out'] is False
specs={
 'core':('1a1ba6feff0-12894-1aad',v/'exact-ci-core-01/manifest.json',20),
 'owner':('1a1ba7cdd03-12894-1b0d',v/'exact-owner-02/manifest.json',19),
 'receiver':('1a1ba77dd3e-12894-1ae4',v/'exact-receiver-01/manifest.json',4),
 'backend':('1a1ba69e477-12894-1a74',pathlib.Path('/home/qian-qi/work/chain-w1-c8-backend-qualification-20261108-ec265b-01/manifest.json'),7),
 'native':('1a1ba6bcd14-12894-1a85',pathlib.Path('/home/qian-qi/work/chain-w1-c8-native-qualification-20261108-ec265b-01/manifest.json'),10),
 'historical-regressions':(None,v/'exact-historical-regressions-01/manifest.json',4),
 'history-local':(None,v/'exact-history-local-01/manifest.json',5)}
assert set(inp['components'])==set(specs)
checked=[];methods=0;ignored=0;nonzero=0
env=os.environ.copy();env['XDG_RUNTIME_DIR']='/run/user/'+str(os.getuid())

failed_unit='hepta-runtime-job-'+original['job_id']+'.service'
failed_query=subprocess.run(['systemctl','--user','show',failed_unit,'--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'],env=env,capture_output=True,text=True)
failed_fields=dict(x.split('=',1) for x in failed_query.stdout.splitlines() if '=' in x)
assert failed_fields.get('ActiveState') in ('inactive','failed') and failed_fields.get('MainPID')=='0',failed_fields
failed_group=failed_fields.get('ControlGroup');failed_cgroup=None
if failed_group:
 group=pathlib.Path('/sys/fs/cgroup')/failed_group.lstrip('/');failed_cgroup={'path':str(group),'exists':group.exists(),'observations':[]}
 if group.exists():
  for phase in ('before','after'):
   raw=(group/'cgroup.events').read_text();pairs=[line.split() for line in raw.splitlines()];assert len({k for k,v in pairs})==len(pairs)
   assert dict(pairs).get('populated')=='0'
   failed_cgroup['observations'].append({'phase':phase,'events':raw})
   if phase=='before':
    found=sorted(group.rglob('cgroup.procs'));assert group/'cgroup.procs' in found
    for p in found:
     data=p.read_text();assert not data.strip()
     failed_cgroup['observations'].append({'procs_path':str(p),'raw':data})
original_failed_unit={'fields':failed_fields,'query_exit':failed_query.returncode,'query_stderr':failed_query.stderr,'cgroup':failed_cgroup}
for name,(fixed_job,p,count) in specs.items():
 entry=inp['components'][name];job=entry['job_id']
 assert fixed_job is None or fixed_job==job,(name,job)
 assert re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',job)
 terminal=entry['authoritative_terminal']
 assert terminal['job_id']==job and terminal['state']=='succeeded' and terminal['exit_code']==0 and terminal['output_complete'] is True and terminal['output_durable'] is True and terminal['timed_out'] is False
 b=p.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha==entry['manifest_sha256'],(name,sha)
 m=json.loads(b);assert m['qualification_complete'] is True and len(m['commands'])==count
 src=m.get('source',{'commit':m.get('source_commit'),'tree':m.get('source_tree')});assert src=={'commit':head,'tree':tree},(name,src)
 assert all(c['exit']==c.get('expected_exit',0) for c in m['commands'])
 nonzero+=sum(int(c.get('expected_exit',0)!=0) for c in m['commands'])
 methods+=m.get('python_test_methods_reported',0)
 rust=m.get('rust_test_outcomes',{});assert rust.get('failed',0)==0;methods+=rust.get('passed',0);ignored+=rust.get('ignored',0)
 if name=='native':methods+=m['test_counts']['native_example']+m['test_counts']['verifier']
 unit='hepta-runtime-job-'+job+'.service'
 pctl=subprocess.run(['systemctl','--user','show',unit,'--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'],env=env,capture_output=True,text=True)
 fields=dict(x.split('=',1) for x in pctl.stdout.splitlines() if '=' in x)
 assert fields.get('ActiveState') in ('inactive','failed') and fields.get('MainPID')=='0',(name,pctl.returncode,pctl.stdout,pctl.stderr)
 cg=fields.get('ControlGroup');cgobs=None
 if cg:
  cgp=pathlib.Path('/sys/fs/cgroup')/cg.lstrip('/');exists=cgp.exists()
  cgobs={'path':str(cgp),'exists':exists,'subtree_procs':[],'events_before':None,'events_after':None}
  if exists:
   ev=cgp/'cgroup.events'
   before=ev.read_text();cgobs['events_before']=before
   evfields={}
   for line in before.splitlines():
    key,value=line.split();assert key not in evfields;evfields[key]=value
   assert evfields.get('populated')=='0',(name,cgobs)
   procs_paths=sorted(cgp.rglob('cgroup.procs'))
   assert cgp/'cgroup.procs' in procs_paths,(name,str(cgp))
   for procs in procs_paths:
    raw=procs.read_text()
    cgobs['subtree_procs'].append({'path':str(procs),'raw':raw})
    assert not raw.strip(),(name,str(procs),raw)
   after=ev.read_text();cgobs['events_after']=after
   evfields={}
   for line in after.splitlines():
    key,value=line.split();assert key not in evfields;evfields[key]=value
   assert evfields.get('populated')=='0',(name,cgobs)
 checked.append({'component':name,'job_id':job,'manifest':str(p),'manifest_sha256':sha,'command_count':count,'authoritative_terminal':terminal,'current_unit':fields,'unit_query_exit':pctl.returncode,'unit_query_stderr':pctl.stderr,'current_cgroup':cgobs})
assert (methods,ignored,nonzero)==(633,4,1),(methods,ignored,nonzero)
h=json.loads((v/'exact-history-local-01/history-artifact-and-list.json').read_text())
assert h['full_history_executed'] is False and h['listed_test_count']==1 and h['test_passes_claimed']==0
plan=tool/'staged-plan.json';assert hashlib.sha256(plan.read_bytes()).hexdigest()=='af2a4739fed7e449f80cffb44b237b3a36015b674174a990c40f017e7b812512'
driver=tool/'qualify_source.py';assert hashlib.sha256(driver.read_bytes()).hexdigest()=='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'
argv=[sys.executable,str(driver),'--repo',str(repo),'--head',head,'--out',str(v/'exact-staged-02'),'--plan',str(plan)]
binding={'schema':'TRNM-W1-C8-STAGED-DECLARED-REPEAT-LAUNCH1','source_commit':head,'source_tree':tree,'input_sha256':a.input_sha256,'repeat_declaration_sha256':'7b51a7dee784b9375eb1c1dcc9b8f54869538810c763ee1514208ba42912ce95','original_failed_attempt':original,'original_failed_unit':original_failed_unit,'all_first_attempts_passed':False,'repeat_is_causal_explanation':False,'known_current_components':checked,'scope':'Current seven known C8 qualification jobs only; bounded cgroup-v2 observations assert no live processes in each present owned subtree. This does not establish zombie reaping, absence of other host workloads, or reaping/accounting for every historical process','unchanged_original_test_parameters':True,'declared_test_methods':32,'new_operation_not_created':True,'new_operation_deadline_not_selected':True,'argv':argv,'observed_monotonic_ns':time.monotonic_ns()}
with (v/'staged-repeat-launch-binding.json').open('x') as f:f.write(json.dumps(binding,indent=2)+'\n')
print(json.dumps({'schema':binding['schema'],'known_components_terminal_and_currently_inactive':len(checked),'pre_staged_methods':methods,'new_operation_not_created':True}),flush=True)
os.execv(sys.executable,argv)
