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
  cgp=pathlib.Path('/sys/fs/cgroup')/cg.lstrip('/');procs=cgp/'cgroup.procs';ev=cgp/'cgroup.events'
  cgobs={'path':str(cgp),'exists':cgp.exists(),'procs':procs.read_text() if procs.exists() else None,'events':ev.read_text() if ev.exists() else None}
  assert not cgobs['procs'] or not cgobs['procs'].strip(),(name,cgobs)
 checked.append({'component':name,'job_id':job,'manifest':str(p),'manifest_sha256':sha,'command_count':count,'authoritative_terminal':terminal,'current_unit':fields,'unit_query_exit':pctl.returncode,'unit_query_stderr':pctl.stderr,'current_cgroup':cgobs})
assert (methods,ignored,nonzero)==(633,4,1),(methods,ignored,nonzero)
h=json.loads((v/'exact-history-local-01/history-artifact-and-list.json').read_text())
assert h['full_history_executed'] is False and h['listed_test_count']==1 and h['test_passes_claimed']==0
plan=tool/'staged-plan.json';assert hashlib.sha256(plan.read_bytes()).hexdigest()=='af2a4739fed7e449f80cffb44b237b3a36015b674174a990c40f017e7b812512'
driver=tool/'qualify_source.py';assert hashlib.sha256(driver.read_bytes()).hexdigest()=='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'
argv=[sys.executable,str(driver),'--repo',str(repo),'--head',head,'--out',str(v/'exact-staged-01'),'--plan',str(plan)]
binding={'schema':'TRNM-W1-C8-STAGED-LAUNCH-BINDING1','source_commit':head,'source_tree':tree,'input_sha256':a.input_sha256,'known_current_components':checked,'scope':'Current seven known C8 qualification jobs only; no assertion that the host has no other workloads or that every historical process was reaped','unchanged_original_test_parameters':True,'declared_test_methods':32,'new_operation_not_created':True,'new_operation_deadline_not_selected':True,'argv':argv,'observed_monotonic_ns':time.monotonic_ns()}
with (v/'staged-launch-binding.json').open('x') as f:f.write(json.dumps(binding,indent=2)+'\n')
print(json.dumps({'schema':binding['schema'],'known_components_terminal_and_currently_inactive':len(checked),'pre_staged_methods':methods,'new_operation_not_created':True}),flush=True)
os.execv(sys.executable,argv)
