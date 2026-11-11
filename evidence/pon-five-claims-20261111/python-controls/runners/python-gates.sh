python3 - <<'PY'
from pathlib import Path
import subprocess,json,os,time,hashlib,re,sys
T='297bb40798ca1b4e4a987ef00582067282cda4e9'
S='f2375a08f4458f842b96d30215adcd5380270f1d'
OUT=Path('.git/pon-five-claims-bindings-d6cb-'+T[:12])
OUT.mkdir(exist_ok=False)
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',GIT_NO_LAZY_FETCH='1')
def git(*args):return subprocess.check_output(['git',*args],text=True,env=env).strip()
assert git('rev-parse','HEAD')==T and not git('status','--porcelain=v1')
def json_file(name,data):(OUT/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
json_file('source-before.json',{'head':T,'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1'),'implementation_source':S,'python':sys.version})
roster='ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f'
new='evidence/pon-w1-lifetime-five-claims-20261111'
commands=[
 ('preflight',['bash','scripts/project-preflight.sh','--audit']),
 ('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check']),
 ('ci-contract',['python3','scripts/ci/check_ci_contract.py']),
 ('repository-links',['python3','scripts/ci/check_repository.py']),
 ('ci-contract-negatives',['python3','scripts/ci/test_ci_contract.py']),
 ('ci-source-integrity-negatives',['python3','scripts/ci/test_ci_source_integrity.py']),
 ('authority-reader',['python3','scripts/ci/pq_authority_effect_register.py']),
 ('authority-negatives',['python3','scripts/ci/test_pq_authority_effect_register.py']),
 ('pq128-reader',['python3','scripts/ci/pq_lifetime_budget.py']),
 ('pq128-negatives',['python3','scripts/ci/test_pq_lifetime_budget.py']),
 ('lifetime-reader',['python3','scripts/w1_lifetime_ledger.py','--input',new+'/project-input.json']),
 ('lifetime-fixture',['cmp',new+'/project-report.json',str(OUT/'lifetime-reader.stdout.log')]),
 ('corpus-reader',['python3','scripts/ci/check_pq_research_integration.py']),
 ('corpus-negatives',['python3','scripts/ci/test_pq_research_integration.py']),
 ('current-qrom-reader',['python3','scripts/w1_qrom_current_implementation_audit.py','--output',str(OUT/'current-qrom-report.json')]),
 ('current-qrom-negatives',['python3','scripts/ci/test_w1_qrom_current_implementation_audit.py']),
 ('proof-profile-reader',['python3','scripts/ci/pq_proof_profile_binding.py']),
 ('proof-profile-negatives',['python3','scripts/ci/test_pq_proof_profile_binding.py']),
 ('qrom-closure-roster',['python3','scripts/ci/w1_qrom_closure_controls.py','run','--roster-sha256',roster,'--output',str(OUT/'qrom-closure')]),
 ('qrom-closure-completion',['python3','scripts/ci/w1_qrom_closure_controls.py','check','--roster-sha256',roster,'--output',str(OUT/'qrom-closure')]),
 ('qrom-semantics-reader',['python3','scripts/w1_qrom_semantics_audit.py','--out',str(OUT/'semantics.json')]),
 ('qrom-semantics-fixture',['cmp','evidence/pon-w1-qrom-semantics-current-20261109/report.json',str(OUT/'semantics.json')]),
 ('composition-unknown',['python3','scripts/w1_qrom_composition_budget.py']),
 ('composition-example',['python3','scripts/w1_qrom_composition_budget.py','--example']),
 ('joint-oracle-unknown',['python3','scripts/w1_qrom_joint_oracle_diagnostic.py']),
 ('joint-oracle-alias',['python3','scripts/w1_qrom_joint_oracle_diagnostic.py','--example','alias']),
 ('joint-oracle-separated',['python3','scripts/w1_qrom_joint_oracle_diagnostic.py','--example','separated']),
 ('four-propositions-v1',['python3','formal/pon-nakamoto-v1/test_four_propositions_v1.py','-v']),
 ('four-propositions-w1-v2',['python3','formal/pon-nakamoto-v1/test_four_propositions_w1_v2.py','-v']),
 ('demand-evidence',['python3','formal/pon-nakamoto-v1/test_demand_evidence.py']),
 ('work-utility',['python3','formal/pon-nakamoto-v1/test_work_utility.py']),
 ('upgrade-policy',['python3','formal/pon-nakamoto-v1/test_upgrade_policy.py']),
 ('cell-learning-scope',['python3','scripts/test_cell_learning_scope_join.py']),
]
for name in ('composition-unknown','composition-example','joint-oracle-unknown','joint-oracle-alias','joint-oracle-separated'):
 commands.append((name+'-fixture',['cmp','evidence/pon-w1-qrom-formal-bridge-20261107/'+name+'.json',str(OUT/(name+'.stdout.log'))]))
results=[]
for name,args in commands:
 print(json.dumps({'started':name,'command':args}),flush=True)
 started=time.time();timed_out=False;failure=None
 with (OUT/(name+'.stdout.log')).open('wb') as stdout,(OUT/(name+'.stderr.log')).open('wb') as stderr:
  try:
   p=subprocess.run(args,env=env,stdout=stdout,stderr=stderr,timeout=900)
   code=p.returncode
  except subprocess.TimeoutExpired:
   code=None;timed_out=True
  except Exception as exc:
   code=None;failure=repr(exc)
 stdout=(OUT/(name+'.stdout.log')).read_bytes()
 stderr=(OUT/(name+'.stderr.log')).read_bytes()
 text=(stdout+b'\n'+stderr).decode(errors='replace')
 counts=[int(x) for x in re.findall(r'Ran ([0-9]+) tests? in ',text)]
 record={'name':name,'command':args,'exit':code,'timed_out':timed_out,'exception':failure,'seconds':time.time()-started,'reported_test_counts':counts,'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),'stdout_bytes':len(stdout),'stderr_bytes':len(stderr)}
 if code!=0:record['failure_tail']=text[-6000:]
 results.append(record);json_file('results-partial.json',{'source':T,'results':results})
 print(json.dumps(record),flush=True)
source_after={'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1')}
json_file('source-after.json',source_after)
complete={'source':T,'implementation_source':S,'commands':len(results),'all_commands_exit_zero':all(r['exit']==0 for r in results),'source_after':source_after,'source_remained_clean':source_after['head']==T and not source_after['status'],'results':results,'output_directory':str(OUT.resolve()),'qualification_promoted':False}
json_file('results.json',complete)
print(json.dumps({'result':'PYTHON_GATES_COMPLETE','source':T,'commands':len(results),'all_exit_zero':complete['all_commands_exit_zero'],'failed':[r['name'] for r in results if r['exit']!=0],'source_remained_clean':complete['source_remained_clean'],'output_directory':str(OUT.resolve())}),flush=True)
PY
