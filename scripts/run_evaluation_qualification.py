#!/usr/bin/env python3
"""Execute source-bound current regressions and real controlled learning; no deployment."""
from __future__ import annotations
import argparse,hashlib,json,os,platform,re,signal,subprocess,sys,time
from pathlib import Path
from qualification_runtime import bind_python_runtime

ROOT=Path(__file__).resolve().parents[1]
PYTHON_TESTS=['test_reference','test_contracts','test_invariants','test_evaluation',
 'test_evaluation_bundle','test_artifacts','test_model_contract','test_inference_receipt',
 'test_bounded_process','test_work_backend','test_strict_signature','test_native_execution','test_interop']

def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def runtime(path):
 return (path.startswith(('formal/pon-nakamoto-v1/','trillionnium/'))and not path.endswith('.md'))or path in {
 'config/pon/devnet-v1.json','config/pon/ledger-v1.json','config/pon/model-family-v1.json','config/pon/work-profile-v1.json','config/pon/evaluation-round-v1.json'}

def run(output,source,target,cargo_home,hosts,client_only=False,session_only=False,native_node=False):
 session_only=session_only or native_node
 client_only=client_only or session_only
 out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
 if git('status','--porcelain'):raise ValueError('DIRTY_SOURCE')
 commit=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
 if not re.fullmatch('[0-9a-f]{40}',source):raise ValueError('SOURCE_COMMIT')
 source_tree=git('rev-parse',source+'^{tree}')
 files=git('ls-files').splitlines();source_files={p:sha(ROOT/p)for p in files if runtime(p)or p in {'config/pon/invariants-v2.json','scripts/run_evaluation_qualification.py','scripts/qualification_runtime.py'}}
 env=os.environ.copy()
 for name in list(env):
  if name.startswith('TRNM_'):env.pop(name)
 env.update(CARGO_HOME=str(Path(cargo_home).resolve()),CARGO_TARGET_DIR=str(Path(target).resolve()),
  CARGO_BUILD_JOBS='2',CARGO_NET_OFFLINE='true',RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1',
  OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',TRNM_NATIVE_MODE='release',TMPDIR='/tmp')
 env,child_python3=bind_python_runtime(env)
 (out/'logs').mkdir();records=[]
 def execute(name,command,timeout=1200,extra=None):
  log=out/'logs'/(name+'.log');usage=out/'logs'/(name+'.usage')
  actual=['/usr/bin/time','-f','%M %U %S','-o',str(usage),*command]
  child_env=dict(env);child_env.update(extra or {})
  started=time.monotonic_ns();timed_out=False
  with log.open('w')as stream:
   child=subprocess.Popen(actual,cwd=ROOT,env=child_env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=child.wait(timeout=timeout)
   except subprocess.TimeoutExpired:
    timed_out=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait()
  row={'name':name,'command':command,'returncode':code,'timed_out':timed_out,
       'elapsed_ns':time.monotonic_ns()-started,'log':str(log.relative_to(out)),
       'environment_overrides':extra or {},
       'peak_rss_kib':None,'vram_bytes':None,'included_transactions':None,'client_confirmed_transactions':None}
  if usage.exists():
   values=usage.read_text().splitlines()[-1].split()
   if len(values)==3 and values[0].isdigit():row['peak_rss_kib']=int(values[0])
  text=log.read_text(errors='replace')
  match=re.search(r'Ran (\d+) tests?\b',text)
  if match:row['python_tests']=int(match[1])
  if command[:2]==['cargo','test']:
   counts=[]
   for section in re.split(r'(?m)^\s*(?:Running (?:unittests|tests/)|Doc-tests )',text):
    values=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored',section)
    if values:counts.append(values[-1])
   row.update(native_passed=sum(int(v[1])for v in counts),native_failed=sum(int(v[2])for v in counts),native_ignored=sum(int(v[3])for v in counts))
  records.append(row);print(json.dumps(row),flush=True)
  if code or timed_out:raise RuntimeError('QUALIFICATION_FAILED '+name)
  if git('rev-parse','HEAD')!=commit or git('status','--porcelain'):raise ValueError('SOURCE_CHANGED')
  return text
 report={'schema':'pon-evaluation-qualification-v1','source_commit':commit,'source_tree':tree,
         'source_clean':True,'source_files_sha256':source_files,'input_source_commit':source,'input_source_tree':source_tree,
         'environment':{'platform':platform.platform(),'python':platform.python_version(),
          'child_python3':child_python3,
          'numpy':__import__('numpy').__version__,'cryptography':__import__('cryptography').__version__,
          'rust':subprocess.check_output(['rustc','--version'],text=True).strip(),
          'temporary_filesystem':subprocess.check_output(['findmnt','-T','/tmp','-n','-o','FSTYPE,TARGET'],text=True).strip(),
          'test_threads':1,'cargo_jobs':2,'cargo_offline':True,'cargo_locked':True,'physical_power_loss':False},
         'results':records,'all_commands_passed':False,'ordinary_hepta_entry':False,
         'independent_accepted':False,'future_window_accepted':False,'production_activation':False,
         'historical_evidence_sha256':{str(Path('evidence')/name/'manifest.json'):sha(ROOT/'evidence'/name/'manifest.json') for name in ['pon-v1','pon-v3','pon-v4','pon-evaluation-bundle-v1','pon-contract-authority-v1']},
         'workstream':'native-node' if native_node else ('native-session' if session_only else ('client-confirmation' if client_only else 'model-evaluation')),
         'model_experiments_rerun':not client_only}
 if session_only:
  report['historical_evidence_sha256']['evidence/pon-client-confirmation-v1/manifest.json']=sha(ROOT/'evidence/pon-client-confirmation-v1/manifest.json')
 error=None
 try:
  execute('preflight',['bash','scripts/project-preflight.sh','--audit'])
  execute('source-contract',['python3','scripts/ci/check_repository.py'])
  execute('source-rejections',['python3','scripts/ci/test_repository.py'])
  execute('invariant-registry',['python3','scripts/ci/test_invariants_registry.py'])
  manifest=['--manifest-path','trillionnium/Cargo.toml']
  execute('native-build',['cargo','build','--offline','--locked','--release',*manifest,'-p','trnm-protocol','-p','trnm-crypto-primitives','-p','trnm-mvcc-fee','-p','trnm-transport','--examples'])
  report['native_binary_sha256']={p.name:sha(p)for p in (Path(target).resolve()/'release/examples').iterdir()if p.is_file() and '.'not in p.name and os.access(p,os.X_OK)}
  if native_node:
   execute('native-node-build',['cargo','build','--offline','--locked','--release',*manifest,'-p','trnm-pon-node','--bins'])
   report['native_binary_sha256']['trnm-pon-node']=sha(Path(target).resolve()/'release/trnm-pon-node')
   raw=execute('native-prepared-cost',[str(Path(target).resolve()/'release/examples/pon_prepared_cost')],timeout=120)
   (out/'prepared-cost.json').write_text(raw)
   execute('native-node-contracts',['cargo','test','--offline','--locked',*manifest,'-p','trnm-pon-node','--test','native_node','--','--nocapture'])
  execute('native-suite',['cargo','test','--offline','--locked',*manifest,'--workspace','--all-targets','--all-features'])
  execute('native-doctests',['cargo','test','--offline','--locked',*manifest,'--workspace','--doc','--all-features'])
  execute('native-ignored-helper',['cargo','test','--offline','--locked',*manifest,'-p','trnm-research-protocol','--all-targets','--all-features','--','--ignored'])
  execute('native-lints',['cargo','clippy','--offline','--locked',*manifest,'--workspace','--all-targets','--all-features','--','-D','warnings'])
  execute('native-format',['cargo','fmt',*manifest,'--all','--','--check'])
  for test in PYTHON_TESTS+(['test_client_confirmation'] if client_only else [])+(['test_native_session','test_work_precheck'] if session_only else [])+(['test_evaluation_round'] if native_node else []):execute(test,['python3','formal/pon-nakamoto-v1/'+test+'.py'])
  execute('accepted-block',['python3','scripts/ci/test_pon_accepted_block.py'])
  execute('native-ledger',['python3','formal/pon-nakamoto-v1/test_contracts.py'],extra={'TRNM_NATIVE_EXECUTOR':str(Path(target).resolve()/'release/examples/pon_execute'),'TRNM_EXECUTION_WORKERS':'8'})
  execute('historical-v1-rejections',['python3','scripts/ci/test_pon_evidence.py'])
  execute('historical-v4',['python3','scripts/ci/check_completion_evidence.py','--historical'])
  execute('historical-v4-rejections',['python3','scripts/ci/test_completion_evidence.py'])
  if client_only:
   execute('native-client-confirmation',['python3','formal/pon-nakamoto-v1/test_client_confirmation.py'],extra={
    'TRNM_NATIVE_WORK':str(Path(target).resolve()/'release/examples/pon_work_io'),
    'TRNM_NATIVE_EXECUTOR':str(Path(target).resolve()/'release/examples/pon_execute'),'TRNM_EXECUTION_WORKERS':'8'})
   execute('historical-evaluation-components',['python3','scripts/ci/check_evaluation_bundle_evidence.py','--historical' if session_only else '--component-scope'])
   execute('historical-evaluation-rejections',['python3','scripts/ci/test_evaluation_bundle_evidence.py'])
   execute('responsibility-evidence',['python3','scripts/ci/test_responsibility_evidence.py'])
   execute('work-cost-rejections',['python3','scripts/ci/test_work_cost_report.py'])
   if session_only:
    selected={'TRNM_NATIVE_WORK':str(Path(target).resolve()/'release/examples/pon_work_io'),
              'TRNM_NATIVE_SESSION':str(Path(target).resolve()/'release/examples/pon_execute_session'),
              'TRNM_EXECUTION_WORKERS':'8'}
    execute('session-ledger',['python3','formal/pon-nakamoto-v1/test_contracts.py'],extra=selected)
    execute('session-invariants',['python3','formal/pon-nakamoto-v1/test_invariants.py'],extra=selected)
    execute('session-client-confirmation',['python3','formal/pon-nakamoto-v1/test_client_confirmation.py'],extra=selected)
    execute('historical-client',['python3','scripts/ci/check_client_confirmation_evidence.py','--historical'])
    execute('historical-client-rejections',['python3','scripts/ci/test_client_confirmation_evidence.py'])
    execute('session-comparison',['python3','formal/pon-nakamoto-v1/experiments/session_cost.py','--out',str(out/'comparison'),
            '--single',str(Path(target).resolve()/'release/examples/pon_execute'),
            '--session',str(Path(target).resolve()/'release/examples/pon_execute_session'),'--samples','3'])
    execute('session-pipeline',['python3','formal/pon-nakamoto-v1/experiments/session_pipeline.py','--out',str(out/'pipeline'),
            '--samples','3','--width','16'],extra=selected)

  else:
   produced=execute('model-learning',['python3','formal/pon-nakamoto-v1/experiments/model_loop.py','--source',source,'--out',str(out/'model')])
   bundle=json.loads(produced.splitlines()[-1])['evaluation_bundle'];report['evaluation_bundle']=bundle
   execute('model-settlement',['python3','formal/pon-nakamoto-v1/experiments/settle_model.py','--input',str(out/'model'),'--out',str(out/'settlement'),'--bundle-hash',bundle])
   execute('learning-cycles',['python3','formal/pon-nakamoto-v1/experiments/learning_cycles.py','--source',source,'--out',str(out/'cycles')])
   if hosts:
    execute('physical-evaluation',['python3','formal/pon-nakamoto-v1/experiments/evaluation_host_parity.py','--input',str(out/'model'),'--out',str(out/'hosts'),'--bundle-hash',bundle,'--hosts',*hosts],timeout=600)
  execute('whitespace',['git','diff','--check'])
  report['all_commands_passed']=True
 except (ValueError,RuntimeError,OSError,subprocess.SubprocessError)as failure:
  error=str(failure);report['error']=error
 finally:
  report['source_clean_after']=git('rev-parse','HEAD')==commit and not git('status','--porcelain')
  (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
  (out/'manifest.json').write_text(json.dumps({'schema':'pon-native-node-evidence-v1' if native_node else ('pon-native-session-evidence-v1' if session_only else ('pon-client-confirmation-evidence-v1' if client_only else 'pon-evaluation-evidence-v1')),'implementation_commit':commit,
    'implementation_tree':tree,'source_clean':report['source_clean_after'],'all_commands_passed':report['all_commands_passed'],
    'files':{str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p.name!='manifest.json'},
    'historical_v4_sha256':sha(ROOT/'evidence/pon-v4/manifest.json'),'ordinary_hepta_entry':False,
    'independent_accepted':False,'three_improving_generations':False,'physical_power_loss':False,
    'public_network_ready':False,'production_activation':False},indent=2)+'\n')
 if error:raise RuntimeError(error)
 print('QUALIFIED_CURRENT_SCOPE',out,flush=True)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--source',required=True)
 parser.add_argument('--native-node',action='store_true',help='Also qualify the native development node with its ordinary CLI and actual process/socket regressions')
 parser.add_argument('--session-only',action='store_true',help='Qualify native cache, incremental root, precheck and controlled receiver pipeline without rerunning model experiments')
 parser.add_argument('--client-only',action='store_true',help='Run common regression plus both client backends, preserving prior model evidence rather than rerunning unrelated experiments')
 parser.add_argument('--target',required=True);parser.add_argument('--cargo-home',required=True);parser.add_argument('--hosts',nargs='*',default=[])
 args=parser.parse_args();run(args.out,args.source,args.target,args.cargo_home,args.hosts,args.client_only,args.session_only,args.native_node)
