"""One corrected owned launcher, original Nice10 guard and total180 retained."""
from pathlib import Path
import datetime,hashlib,importlib.util,json,math,os,re,secrets,sys,threading,time
sys.dont_write_bytecode=True
START=time.monotonic()
D=Path(__file__).resolve().parent;R=Path('/home/qian-qi/Documents/Codex/2026-10-25/github-trillionnium-chain-https-github-com');P=D.parent
identity_helper=P/'unit_identity.py'
assert not identity_helper.is_symlink() and hashlib.sha256(identity_helper.read_bytes()).hexdigest()=='71b27371e7e84fd7f7e992f1f1b867be25762cb7e3577f03065b5270e5dfa845'
sys.path.insert(0,str(P))
from unit_identity import unit_identity,owns
OLDROOT=Path('/home/qian-qi/Documents/Codex/2026-10-25/github-trillionnium-chain-https-github-com/work/ci-follow/pn1-V19-new-clean-source-prepare-owner-preparation-20261026-001')
FIRST=OLDROOT/'execution-first-guard-terminal-original.json'
CONTROL=OLDROOT/'nice-control-terminal-original.json'
FIXED=OLDROOT/'execution-fixed-launcher-001/durable-terminal-original.json'
assert hashlib.sha256(FIRST.read_bytes()).hexdigest()=='ce7432e4be324ea52b709e311db875a82b7b65ea5a8d9845372f3002c72b8846'
assert hashlib.sha256(CONTROL.read_bytes()).hexdigest()=='c4c94eac511ce8d37d857b40f19e593a69901b801af7942c26a452a0b7c0d7bd'
assert hashlib.sha256(FIXED.read_bytes()).hexdigest()=='560ecd299f3190d5eb235653a9d3c64c4b25a8253c2ed83b5837fbcfabdca973'
def status(p):return json.loads(json.loads(p.read_text())['content'][0]['text'])
a,b,c=status(FIRST),status(CONTROL),status(FIXED)
assert a['state']=='failed' and a['exit_code']==1 and a['output_complete'] is True
assert b['state']=='succeeded' and b['exit_code']==0 and b['output_complete'] is True
assert c['state']=='failed' and c['exit_code']==1 and c['output_complete'] is True
observed_supervisor_ms=(a['at_unix_ms']-1793015411313)+(b['at_unix_ms']-1793015703756)+(c['at_unix_ms']-1793016218342)
assert observed_supervisor_ms==7036
FOURTH=R/'work/ci-follow/pn1-v3-clean-source-public-qualification-20261026-001/execution-owned-001/durable-terminal-original.json'
assert hashlib.sha256(FOURTH.read_bytes()).hexdigest()=='7561230b5f1d971d5c2cc25e8c1a1f484309c7697e28c6de23381505b404aefe'
fourth=status(FOURTH)
assert fourth['state']=='failed' and fourth['exit_code']==1 and fourth['output_complete'] is True and fourth['timed_out'] is False
observed_fourth_ms=fourth['at_unix_ms']-1793021224702
assert observed_fourth_ms==10592 and observed_supervisor_ms+observed_fourth_ms==17628
spent=35
TOTAL_NEW=140
assert spent>=(observed_supervisor_ms+observed_fourth_ms)/1000 and spent+TOTAL_NEW==175 and spent+TOTAL_NEW<180
# Old failures and control conservatively charged35s. Fresh140s owner includes
# cleanup/final publication; old consumed claims are preserved and never reused.
DEADLINE=START+TOTAL_NEW-60
admission=json.loads((D/'admission.json').read_text())
H,T=admission['head'],admission['tree'];S=Path(admission['source']).resolve()
assert re.fullmatch('[0-9a-f]{40}',H) and re.fullmatch('[0-9a-f]{40}',T)
assert H!='ec0acdff5717b8f584b26f30f1162bd9bf1cc888'
assert S.is_relative_to(R/'work/ci-follow') and S.is_dir()
NONCE=secrets.token_hex(16)
UNIT='pn1-checkpoint64-component-execute-'+NONCE+'.service'
DESCRIPTION='PN1 checkpoint64 actual fresh component execution '+NONCE
helper=R/'work/chain/formal/pon-nakamoto-v1/bounded_process.py'
assert hashlib.sha256(helper.read_bytes()).hexdigest()=='da175430a6b669d3e7d40fe7ec0e7bc00fe6e992cc2d4d443af07209b4013815'
spec=importlib.util.spec_from_file_location('new_source_remaining_budget_owner',helper)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
steps=[];error=None;code=None;launched=False;stdout=stderr=b'';cleanup=None
captured=None;observer_error=None;observer_thread=None;observer_stop=threading.Event()
cleanup_terminal_known=None
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',PYTHONDONTWRITEBYTECODE='1')
def bounded(name,argv,seconds,*,check=True,remaining=True):
 limit=min(seconds,max(.1,DEADLINE-time.monotonic())) if remaining else seconds
 start=time.monotonic();failure=None
 try:q=m.run_bounded(argv,b'',timeout=limit,stdout_limit=1048576,stderr_limit=1048576,cwd=S,env=env);rc,out,err=q.returncode,q.stdout,q.stderr
 except m.ProcessFailure as e:rc,out,err,failure=e.returncode,e.stdout,e.stderr,str(e)
 (D/(name+'.stdout.log')).write_bytes(out);(D/(name+'.stderr.log')).write_bytes(err)
 steps.append(dict(name=name,argv=argv,timeout_seconds=limit,elapsed_seconds=time.monotonic()-start,returncode=rc,error=failure,stdout_sha256=hashlib.sha256(out).hexdigest(),stderr_sha256=hashlib.sha256(err).hexdigest()))
 if check and (rc!=0 or failure is not None):raise RuntimeError(name+': '+str(failure or rc))
 return rc,out,err,failure
def git(name,*args):return bounded(name,['git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',*args],10)[1].decode().strip()
def state(name):
 return bounded(name,['systemctl','--user','show',UNIT,'--property=LoadState','--property=ActiveState','--property=InvocationID','--property=ExecStart'],5,check=False,remaining=False)
def parsed_state(observed):
 rc,out,err,failure=observed
 if failure is not None:return None
 values=dict(line.split('=',1) for line in out.decode().splitlines() if '=' in line)
 if rc==1 and values.get('LoadState')=='not-found' and values.get('ActiveState')=='inactive':return 'not-found'
 if rc!=0:return None
 if values.get('LoadState')=='not-found' and values.get('ActiveState')=='inactive':return 'not-found'
 return values.get('ActiveState')
def observe_own_invocation(argv):
 global captured,observer_error
 attempt=0
 while not observer_stop.is_set() and time.monotonic()<DEADLINE:
  attempt+=1
  try:
   candidate=unit_identity(UNIT,'invocation-observer-'+str(attempt),bounded)
   if not owns(candidate,UNIT,DESCRIPTION,argv):
    observer_error='OWNED_UNIT_EXACT_IDENTITY_MISMATCH';return
   captured=candidate;return
  except (OSError,ValueError,KeyError,TypeError) as e:
   observer_error=str(e)
   observer_stop.wait(.1)
try:
 assert git('head-before','rev-parse','HEAD')==H
 assert git('tree-before','rev-parse','HEAD^{tree}')==T
 assert git('status-before','status','--porcelain=v1','--untracked-files=all')==''
 assert git('branch-before','branch','--show-current')=='docs/chain-audit-remediation-20261022'
 assert git('origin-before','remote','get-url','origin')=='https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
 for relative,expected in [('scripts/run_pon_native_io_component.py','c5e8d582d2b53411b15114c6c7fd03b618f5ce3c79ee25bc198dd372857bbc65'),('scripts/ci/test_pon_native_io_build_monitor.py','96e8bf043e1c9b3fb813f4b026248806b3f7e3e1f79b10f52800774191ad4703'),('scripts/ci/check_pon_identity_churn.py','7000380737367657292f2e7cc6f779dde8ce64eaaebf5c196de733caf9ffbe71')]:
  p=S/relative;assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==expected
 assert not (P/'execution').exists() and not list(P.glob('component-execution-claim-v1-*'))
 for name,expected in [('prepared.json','a0f60210d0c46d9832c130b6e7ceb9582c0c8d1a81c89d239e5f871964054537'),('artifact-files.json','3b58039700f333224f0c62c9870d6c92d0b689e18b74cbe9b8c5dd3ca2e4d056')]:assert hashlib.sha256((P/'prepared'/name).read_bytes()).hexdigest()==expected
 bounded('preflight',['bash','scripts/project-preflight.sh','--dev'],30)
 previous=state('unit-before')
 assert parsed_state(previous)=='not-found'
 remaining=DEADLINE-time.monotonic();runtime=math.floor(remaining-40)
 assert runtime>0
 native=['/usr/bin/python3',str(S/'scripts/run_pon_native_io_component.py'),'execute','--profile','pn1-native-io-three-fd-component-v1','--out',str(P/'execution'),'--prepared',str(P/'prepared/prepared.json'),'--prepared-sha256','a0f60210d0c46d9832c130b6e7ceb9582c0c8d1a81c89d239e5f871964054537','--prepared-inventory-sha256','3b58039700f333224f0c62c9870d6c92d0b689e18b74cbe9b8c5dd3ca2e4d056','--expected-head',H,'--expected-tree',T]
 command=['systemd-run','--user','--wait','--pipe','--collect','--unit='+UNIT,'--description='+DESCRIPTION,'--service-type=exec','--property=CPUQuota=400%','--property=CPUQuotaPeriodSec=100ms','--property=MemoryMax=17179869184','--property=Nice=10','--property=RuntimeMaxSec='+str(runtime),'--property=TimeoutStopSec=10s','--property=KillMode=control-group','--setenv=PATH=/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin','--setenv=PYTHONDONTWRITEBYTECODE=1',*native]
 intent=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),head=H,tree=T,source=str(S),command=command,previous_failed_launch_plus_control_seconds_spent=spent,maximum_new_owner_seconds=TOTAL_NEW,conservative_recorded_attempts_seconds_bound=spent+TOTAL_NEW,internal_deadline_seconds=TOTAL_NEW-60,inner_unit_runtime_seconds=runtime,original_execute_seconds=180,old_failure_preserved=True,caps_profile_assertions_unchanged=True,task_complete=False,merge_ready=False)
 with (D/'execute-start-intent.json').open('x') as f:f.write(json.dumps(intent,indent=2)+'\n')
 observer_thread=threading.Thread(target=observe_own_invocation,args=(native,),daemon=True)
 observer_thread.start()
 launched=True
 code,stdout,stderr,error=bounded('execute-owner',command,remaining-20,check=False)
 if code!=0 or error is not None:raise RuntimeError('corrected-launcher-public-execute-failed')
 assert (P/'execution/results.json').is_file() and (P/'execution/artifact-files.json').is_file()
except BaseException as e:
 error=str(e) if error is None else error
finally:
 if observer_thread is not None:
  observer_stop.set();observer_thread.join(timeout=10)
  if observer_thread.is_alive():error=error or 'OWNED_UNIT_OBSERVER_TERMINAL_UNKNOWN'
  if captured is None:error=error or 'OWNED_UNIT_INVOCATION_NOT_CAPTURED'
 if launched:
  observed=state('unit-after')
  actual_state=parsed_state(observed)
  if actual_state in ('active','activating','deactivating','reloading'):
   error=error or 'OWNED_UNIT_UNEXPECTEDLY_ACTIVE_AFTER_CLIENT_TERMINAL'
   # Only the exact captured invocation of this nonce unit may be stopped.
   # Changed, unavailable or unobserved ownership remains UNKNOWN.
   try:
    before_stop=unit_identity(UNIT,'identity-before-stop',bounded)
    ours=captured is not None and owns(before_stop,UNIT,DESCRIPTION,native,captured)
   except (OSError,ValueError,KeyError,TypeError):ours=False
   if ours:
    cleanup=bounded('owned-unit-stop',['systemctl','--user','stop',UNIT],20,check=False,remaining=False)
    stopped=state('unit-after-stop')
    cleanup_terminal_known=parsed_state(stopped) in ('not-found','inactive','failed')
    if cleanup[0]!=0 or cleanup[3] is not None or not cleanup_terminal_known:
     error=error or 'OWNED_UNIT_STOP_OR_TERMINAL_UNKNOWN'
   else:
    cleanup='UNKNOWN_UNIT_OWNERSHIP_NO_STOP';error=error or str(cleanup)
  elif actual_state=='failed':
   error=error or 'OWNED_UNIT_FAILED_AFTER_CLIENT_TERMINAL'
  elif actual_state not in ('not-found','inactive'):
   error=error or 'OWNED_UNIT_TERMINAL_STATE_UNKNOWN'
 try:
  final=dict(head=git('head-after','rev-parse','HEAD'),tree=git('tree-after','rev-parse','HEAD^{tree}'),status=git('status-after','status','--porcelain=v1','--untracked-files=all'))
  assert final==dict(head=H,tree=T,status='')
 except BaseException as e:final=dict(error=str(e));error=error or str(e)
 elapsed=time.monotonic()-START
 if elapsed>TOTAL_NEW or spent+elapsed>180:error=error or 'ACTUAL_CUMULATIVE_EXECUTION_BUDGET_EXCEEDED'
 result=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),head=H,tree=T,returncode=code,error=error,elapsed_seconds_before_final_result_publication=elapsed,previous_failed_owner_seconds_spent=spent,actual_recorded_attempts_seconds=spent+elapsed,maximum_new_owner_seconds=TOTAL_NEW,maximum_recorded_attempts_seconds=spent+TOTAL_NEW,source_after=final,unit=UNIT,captured_actual_unit_identity=captured,unit_observer_error=observer_error if captured is None else None,cleanup_terminal_known=cleanup_terminal_known,execution_json_exists=(P/'execution/results.json').is_file(),inventory_exists=(P/'execution/artifact-files.json').is_file(),steps=steps,cleanup_stop_requested=isinstance(cleanup,tuple),cleanup_unknown=cleanup if isinstance(cleanup,str) else None,public_execute_attempted=launched,independent_reader_run=False,current_PR_or_fullscope_qualified=False,task_complete=False,merge_ready=False)
 with (D/'execute-owner-result.json').open('x') as f:f.write(json.dumps(result,indent=2)+'\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({k:v for k,v in result.items()if k!='steps'}),flush=True)
# Actual result-file close and final stdout flush are included before this last
# check. The durable owner terminal, not the pre-publication JSON snapshot,
# remains mandatory and authoritative for whole-job elapsed/exit acceptance.
final_elapsed=time.monotonic()-START
if final_elapsed>TOTAL_NEW or spent+final_elapsed>180:sys.exit(1)
sys.exit(0 if code==0 and error is None else 1)
