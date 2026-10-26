#!/usr/bin/env python3
"""Check executed current inputs/results; no independent or production authority."""
from __future__ import annotations
import hashlib,json,re,subprocess,sys
from pathlib import Path
from check_invariant_evidence import ROOT,load,require,safe,source_bytes

PARAMETERS={'config/pon/devnet-v1.json','config/pon/ledger-v1.json','config/pon/model-family-v1.json','config/pon/work-profile-v1.json','config/pon/evaluation-round-v1.json'}
FALSE_FLAGS=['ordinary_hepta_entry','independent_accepted','three_improving_generations',
             'physical_power_loss','public_network_ready','production_activation']
REQUIRED_RUNS={'preflight','source-contract','source-rejections','invariant-registry','native-build',
 'native-suite','native-doctests','native-ignored-helper','native-lints','native-format',
 'test_reference','test_contracts','test_invariants','test_evaluation','test_evaluation_bundle',
 'test_artifacts','test_model_contract','test_inference_receipt','test_bounded_process',
 'test_work_backend','test_strict_signature','test_native_execution','test_interop',
 'accepted-block','native-ledger','historical-v1-rejections','historical-v4','historical-v4-rejections','model-learning',
 'model-settlement','learning-cycles','physical-evaluation','whitespace'}

def runtime(path):
 return(path.startswith(('formal/pon-nakamoto-v1/','trillionnium/'))and not path.endswith('.md'))or path in PARAMETERS

def json_bytes(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def validate(root=ROOT,evidence=None,*,exact_inventory=True):
 root=Path(root).resolve();folder=Path(evidence or root/'evidence/pon-evaluation-bundle-v1').resolve()
 manifest=load(folder/'manifest.json');require(manifest['schema']=='pon-evaluation-evidence-v1','schema')
 for flag in FALSE_FLAGS:require(manifest[flag]is False,'unsupported acceptance '+flag)
 require(manifest['source_clean']is True and manifest['all_commands_passed']is True,'incomplete evidence')
 require({'qualification.json','model/report.json','model/evaluation-bundle.json','cycles/report.json',
          'settlement/report.json','hosts/report.json','hosts/source-manifest.json'}<=set(manifest['files']),'missing mandatory artifact')
 for relative,digest in manifest['files'].items():
  require(hashlib.sha256(safe(folder,relative).read_bytes()).hexdigest()==digest,'changed evidence '+relative)
 require(hashlib.sha256(safe(root,'evidence/pon-v4/manifest.json').read_bytes()).hexdigest()==manifest['historical_v4_sha256'],'old evidence replaced')
 q=load(folder/'qualification.json');commit=q['source_commit']
 require({'pon_execute','pon_work_io'}<=set(q['native_binary_sha256']) and all(re.fullmatch('[0-9a-f]{64}',v)for v in q['native_binary_sha256'].values()),'missing native binary identity')
 require(commit==manifest['implementation_commit']and q['source_tree']==manifest['implementation_tree'],'source identity')
 require(subprocess.check_output(['git','rev-parse',commit+'^{tree}'],cwd=root,text=True).strip()==q['source_tree'],'source tree')
 require(q['source_clean']is True and q['source_clean_after']is True and q['all_commands_passed']is True,'dirty or failed run')
 for flag in ['ordinary_hepta_entry','independent_accepted','future_window_accepted','production_activation']:
  require(q[flag]is False,'qualification overclaim '+flag)
 # Historical component mode may admit NEW current files, never omit files that
 # existed in the measured tree. Derive that original inventory from Git, not the
 # mutable receipt; otherwise deleting a source binding can hide it as 'unmeasured'.
 measured_paths=subprocess.check_output(['git','ls-tree','-r','--name-only',commit],cwd=root,text=True).splitlines()
 measured_runtime={p for p in measured_paths if runtime(p)}
 require({p for p in q['source_files_sha256'] if runtime(p)}==measured_runtime,'measured runtime inventory mismatch')
 original=source_bytes(root,commit,list(q['source_files_sha256']))
 for relative,raw in original.items():
  require(hashlib.sha256(raw).hexdigest()==q['source_files_sha256'][relative],'source fingerprint '+relative)
  require(safe(root,relative).read_bytes()==raw,'runtime/invariant differs from measured source '+relative)
 tracked=set(subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines())
 untracked=set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=root,text=True).splitlines())
 current_runtime={p for p in tracked|untracked if runtime(p)}
 recorded_runtime={p for p in original if runtime(p)}
 require(recorded_runtime<=current_runtime,'recorded runtime inventory missing')
 inventory_matches=current_runtime==recorded_runtime
 if exact_inventory:require(inventory_matches,'runtime inventory mismatch')
 require('config/pon/invariants-v2.json'in original,'missing invariant source')
 require(subprocess.check_output(['git','rev-parse',q['input_source_commit']+'^{tree}'],cwd=root,text=True).strip()==q['input_source_tree'],'corpus source')
 records=list(q['results'])
 if 'qualification-supplement.json' in manifest['files']:
  extra=load(folder/'qualification-supplement.json')
  require(extra['schema']=='pon-evaluation-qualification-supplement-v1'and extra['source_commit']==commit and extra['source_tree']==q['source_tree']and extra['source_clean']is True,'supplement source')
  require(extra['production_activation']is False and extra['independent_accepted']is False,'supplement overclaim')
  for path,raw in source_bytes(root,commit,list(extra['source_files_sha256'])).items():
   require(hashlib.sha256(raw).hexdigest()==extra['source_files_sha256'][path]and safe(root,path).read_bytes()==raw,'supplement source changed')
  records+=extra['results']
 names=[r['name']for r in records];require(set(names)==REQUIRED_RUNS and len(names)==len(set(names)),'incomplete execution matrix')
 logs=[];native=0;doc=0;python_count=0
 for row in records:
  require(row['returncode']==0 and row['timed_out']is False,'failed command '+row['name'])
  require(row['vram_bytes']is None and row['included_transactions']is None and row['client_confirmed_transactions']is None,'unmeasured metric claimed')
  log=safe(folder,row['log']).read_text();logs.append(log)
  if 'python_tests'in row:
   require(re.search(r'Ran '+str(row['python_tests'])+r' tests?\b',log) and re.search(r'(?m)^OK\s*$',log),'Python log outcome')
   python_count+=row['python_tests']
  elif row['command'][0].endswith('python3'):
   observed=re.search(r'Ran (\d+) tests?\b',log)
   if observed:
    require(re.search(r'(?m)^OK\s*$',log),'supplemental Python outcome')
    python_count+=int(observed[1])
  if row['name']in {'native-suite','native-doctests','native-ignored-helper'}:
   counts=[]
   for section in re.split(r'(?m)^\s*(?:Running (?:unittests|tests/)|Doc-tests )',log):
    found=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored',section)
    if found:counts.append(found[-1])
   require(counts and sum(int(v[1])for v in counts)==row['native_passed'] and sum(int(v[2])for v in counts)==row['native_failed']==0,'native result counts')
   if row['name']=='native-suite':native=row['native_passed']
   if row['name']=='native-doctests':doc=row['native_passed']
  if row['name']=='native-ledger':
   require(row['command']==['python3','formal/pon-nakamoto-v1/test_contracts.py'],'native ledger entry')
   require(row['environment_overrides'].get('TRNM_EXECUTION_WORKERS')=='8' and row['environment_overrides'].get('TRNM_NATIVE_EXECUTOR','').endswith('/release/examples/pon_execute'),'native backend not selected')
 require(q['environment']['cargo_locked']is True and q['environment']['cargo_offline']is True and q['environment']['physical_power_loss']is False,'environment scope')
 joined='\n'.join(logs);selectors=set()
 for item in json.loads(original['config/pon/invariants-v2.json'])['invariants']:
  for selector in item['tests']:
   path,symbol=selector.split('::',1);name=symbol.split('.')[-1]
   if path.endswith('.py'):
    eligible=[r for r in records if path in r['command']]
    require(eligible,'missing exact test-file invocation '+selector)
    exact='\n'.join(safe(folder,r['log']).read_text()for r in eligible)
    require(re.search(r'\b'+re.escape(name)+r' \([^)]*'+re.escape(symbol)+r'\)[^\n]*\bok\b',exact),'unobserved exact class/method '+selector)
   require(re.search(r'\b'+re.escape(name)+r'(?:\s|\))[^\n]*\bok\b',joined),'unexecuted invariant '+selector)
   selectors.add(selector)
 sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
 from evaluation_bundle import verify_bundle,evaluate_bundle,artifact_id,read_bounded,MAX_TASK_BYTES
 from experiments.settle_model import verify_observation
 observed,model=verify_observation(folder/'model',q['evaluation_bundle'])
 require(observed['source']==q['input_source_commit'],'model corpus')
 bundle=verify_bundle((folder/'model/evaluation-bundle.json').read_bytes(),q['evaluation_bundle'])
 settlement=load(folder/'settlement/report.json')
 require(settlement['evaluation_bundle']==q['evaluation_bundle']and settlement['observed_evaluation_recomputed']is True,'unverified settlement')
 require(settlement['outcome']=='not_adopted'and settlement['model_reward']==0,'this measured outcome must not be rewritten as adoption')
 for flag in ['ordinary_hepta_entry','independent_evaluators','future_window_accepted','production_activation']:
  require(settlement[flag]is False,'settlement authority '+flag)
 cycles=load(folder/'cycles/report.json');require(cycles['source']==q['input_source_commit']and len(cycles['cycles'])==3,'learning cycle source/coverage')
 require(cycles['real_optimization']is True and cycles['public_pointer_unchanged']is True and cycles['total_model_reward']==0,'actual cycle outcome')
 for flag in ['new_future_window','ordinary_hepta_entry','independent_evaluators','three_improving_public_generations','production_activation']:
  require(cycles[flag]is False,'learning overclaim '+flag)
 used_groups=set(cycles['bootstrap_source_groups'])
 for i,row in enumerate(cycles['cycles'],1):
  directory=folder/'cycles'/('cycle-'+str(i));raw=(directory/'evaluation-bundle.json').read_bytes()
  parsed=verify_bundle(raw,row['evaluation_bundle'],expected_parent=cycles['bootstrap'])
  require(parsed['source_commit']==q['input_source_commit']and parsed['round']==i,'cycle context')
  data=load_list(directory/'evaluation.json');calibration=load_list(directory/'calibration.json')
  evaluated=evaluate_bundle(raw,row['evaluation_bundle'],data,'evaluation',calibration_rows=calibration,expected_parent=cycles['bootstrap'])
  require(evaluated==load(directory/'bound-evaluation.json')and row['evaluation']==evaluated['primary'],'cycle evaluated result')
  require(row['parent_actually_admitted_artifact']==cycles['bootstrap']==row['public_artifact_after']and row['reward']==0 and row['outcome']=='no_public_update','cycle public outcome')
  groups={g for partition in parsed['partitions'].values()for g in partition['groups']}
  require(not used_groups&groups,'reused source group across cycles');used_groups|=groups
 host=load(folder/'hosts/report.json');hm=load(folder/'hosts/source-manifest.json')
 require(host['source_commit']==commit==hm['source_commit']and host['source_clean']is True,'host source')
 require(host['bundle_hash']==hm['bundle_hash']==q['evaluation_bundle']and host['all_hosts_passed']is True,'host bundle/outcome')
 for flag in ['independent_operators','ordinary_hepta_entry','native_consensus_host','future_window_accepted','physical_power_loss','production_activation']:
  require(host[flag]is False,'host scope '+flag)
 require(len(host['results'])==len({r['host']for r in host['results']})==3,'physical host coverage')
 expected=load(folder/'hosts/expected.json')
 require(hashlib.sha256((folder/'hosts/remote-driver.py').read_bytes()).hexdigest()==hm['files']['run.py'],'host driver bytes')
 host_sources=[p for p in hm['files'] if p.startswith(('formal/','config/'))]
 for path,raw in source_bytes(root,commit,host_sources).items():
  require(hashlib.sha256(raw).hexdigest()==hm['files'][path],'host source bytes '+path)
 for name in ['evaluation-bundle.json','calibration.json','evaluation_a.json','evaluation_b.json','consumer.json']:
  require(hashlib.sha256((folder/'model'/name).read_bytes()).hexdigest()==hm['files']['inputs/'+name],'host input bytes '+name)
 for item in host['results']:
  require(item['returncode']==0 and item['parity_passed']is True and item['owned_temporary_directory_removed']is True,'host execution/cleanup')
  require(item['source_manifest']==hm and item['independent_operator']is False and item['production_activation']is False,'host manifest/scope')
  require({r['partition']for r in item['samples']}=={'evaluation_a','evaluation_b','consumer'}and len(item['samples'])==3,'host sample coverage')
  for sample in item['samples']:
   require(sample['result_sha256']==expected[sample['partition']]and sample['public_reward_eligible']is False,'host parity')
 calibration=load_list(folder/'model/calibration.json')
 for part in expected:
  result=evaluate_bundle((folder/'model/evaluation-bundle.json').read_bytes(),q['evaluation_bundle'],load_list(folder/'model'/(part+'.json')),part,calibration_rows=calibration)
  require(hashlib.sha256(json_bytes(result)).hexdigest()==expected[part],'remote expected outcome')
 return {'measured_commit':commit,'runtime_matches':inventory_matches,'recorded_runtime_matches':True,
         'unmeasured_added_runtime':sorted(current_runtime-recorded_runtime),'executed_invariant_selectors':len(selectors),
         'native_tests':native,'doc_tests':doc,'python_test_executions':python_count,'physical_hosts':3,
         'model_reward':0,'three_improving_generations':False,'ordinary_hepta_entry':False,'independent_accepted':False,'production_activation':False}

def load_list(path):
 from check_invariant_evidence import unique
 value=json.loads(path.read_text(),object_pairs_hook=unique);require(isinstance(value,list),'expected array');return value

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--component-scope',action='store_true',help='Check all original runtime bytes; report additional runtime as unmeasured, never as covered')
 parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--evidence',type=Path)
 parser.add_argument('--historical',action='store_true')
 args=parser.parse_args()
 folder=args.evidence or args.root/'evidence/pon-evaluation-bundle-v1'
 if args.historical:
  from historical_evidence import validate_historical_cli
  result=validate_historical_cli(__file__,args.root,folder)
 else:result=validate(root=args.root,evidence=folder,exact_inventory=not args.component_scope)
 if args.evidence is None:
  manifest=load(folder/'manifest.json')
  tracked=set(subprocess.check_output(['git','ls-files'],cwd=args.root,text=True).splitlines())
  require({'evidence/pon-evaluation-bundle-v1/'+p for p in manifest['files']}<=tracked,'untracked evidence')
 print(json.dumps(result,sort_keys=True))
