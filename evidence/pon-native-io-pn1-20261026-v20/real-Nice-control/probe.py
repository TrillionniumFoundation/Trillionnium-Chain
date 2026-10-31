from pathlib import Path
import datetime,json,os,secrets,subprocess,sys,time
sys.dont_write_bytecode=True
R=Path('/home/qian-qi/Documents/Codex/2026-10-25/github-trillionnium-chain-https-github-com')
S=R/'work/ci-follow/pn1-V19-new-clean-source-qualification-source-20261026-001/ownedsource'
sys.path.insert(0,str(S/'scripts'));sys.path.insert(0,str(S/'formal/pon-nakamoto-v1'))
from run_pon_w1_native_campaign import resource_observation,validate_resources
start=time.monotonic();obs=resource_observation();error=None
try:validate_resources(obs,10)
except (ValueError,KeyError,TypeError)as e:error=str(e)
direct=dict(actual=obs,guard_error=error,not_profile_execution=True)
unit='pn1-nice-launcher-control-'+secrets.token_hex(16)+'.service'
code="import sys,json;sys.dont_write_bytecode=True;sys.path.insert(0,"+repr(str(S/'scripts'))+");sys.path.insert(0,"+repr(str(S/'formal/pon-nakamoto-v1'))+");from run_pon_w1_native_campaign import resource_observation,validate_resources;o=resource_observation();validate_resources(o,10);print(json.dumps(o,sort_keys=True))"
args=['systemd-run','--user','--wait','--pipe','--collect','--service-type=exec','--unit='+unit,'--property=Nice=10','--property=CPUQuota=400%','--property=CPUQuotaPeriodSec=100ms','--property=MemoryMax=17179869184','--property=RuntimeMaxSec=5','--property=TimeoutStopSec=1s','--property=KillMode=control-group','/usr/bin/python3','-B','-c',code]
p=subprocess.run(args,capture_output=True,timeout=8)
D=Path(__file__).resolve().parent;(D/'inner.stdout.log').write_bytes(p.stdout);(D/'inner.stderr.log').write_bytes(p.stderr)
fixed=json.loads(p.stdout) if p.returncode==0 else None
v=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-start,direct=direct,exact_fixed_launcher=args,fixed_returncode=p.returncode,fixed=fixed,original_profile_NOT_RUN=True,old_failed_execution_actual_nice='UNKNOWN',historical_cause_proven=False,assertions_or_Nice10_requirement_changed=False)
(D/'receipt.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
assert error=='ACTUAL_EXPECTED_NICE_REQUIRED' and fixed is not None and fixed['nice']==10
