import sys,os,json,time,pathlib,subprocess,signal,hashlib
BASE=pathlib.Path('/home/qian-qi/Documents/Codex/2026-10-25/github-trillionnium-chain-https-github-com')
ROOT=BASE/'work/root-chain-integration-20261026'
D=BASE/'work/ci-follow/Chain-worker-owned-proc-fd-ESRCH-control-20261026-001'
mode=sys.argv[1]
clock=D/'local-worker-validation-clock.json'
if mode=='red':
 with clock.open('x') as f:json.dump({'started_monotonic_ns':time.monotonic_ns(),'started_utc_ns':time.time_ns(),'whole_seconds':600,'not_PN1_prepared_or_W1_qualification':True},f)
else:assert mode in ['red2','green']
c=json.loads(clock.read_text());deadline=c['started_monotonic_ns']/1e9+600
out=D/mode;out.mkdir(exist_ok=False)
source=ROOT/'trillionnium/crates/trnm-worker-agent/src/command_runtime_exec.rs'
sourcehash=hashlib.sha256(source.read_bytes()).hexdigest()
env={**os.environ,'CARGO_INCREMENTAL':'0','CARGO_BUILD_JOBS':'2','RUST_TEST_THREADS':'1','CARGO_TARGET_DIR':str(D/'target')}
if mode in ['red','red2']:commands=[['cargo','test','--locked','-p','trnm-worker-agent','--bin','trnm-worker-agent','vanished_owned_proc_fd_requires_a_fresh_complete_scan','--','--nocapture','--test-threads=1']]
else:commands=[['cargo','test','--locked','-p','trnm-worker-agent','--bin','trnm-worker-agent','--','--test-threads=1'],['cargo','clippy','--locked','-p','trnm-worker-agent','--bin','trnm-worker-agent','--tests','--','-D','warnings']]
rows=[];code=1
for i,cmd in enumerate(commands):
 remaining=deadline-time.monotonic()-25
 if remaining<=0:raise RuntimeError('local worker validation window exhausted; no restart')
 stdout=out/f'{i}.stdout.log';stderr=out/f'{i}.stderr.log';t=time.monotonic()
 with stdout.open('xb',buffering=0) as o,stderr.open('xb',buffering=0) as e:
  p=subprocess.Popen(cmd,cwd=ROOT/'trillionnium',env=env,stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
  (out/f'{i}.started.json').write_text(json.dumps({'command':cmd,'pid':p.pid,'source_sha256':sourcehash,'remaining_local_seconds':remaining,'not_native_prepared':True})+'\n')
  timed=False;violation=None
  while p.poll() is None:
   if time.monotonic()-t>=remaining:violation='local validation deadline';timed=True
   if stdout.stat().st_size+stderr.stat().st_size>4*1024*1024:violation='local raw limit'
   if violation:
    os.killpg(p.pid,signal.SIGKILL);break
   time.sleep(.1)
  code=p.wait()
 row={'command':cmd,'exit_code':code,'timed_out':timed,'violation':violation,'seconds':time.monotonic()-t,'actual_child_reaped':True,'source_sha256':sourcehash,'files':[]}
 for f in [stdout,stderr]:
  b=f.read_bytes();row['files'].append({'name':f.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
 rows.append(row);(out/f'{i}.result.json').write_text(json.dumps(row,indent=2)+'\n')
 if code!=0 or violation:break
assert hashlib.sha256(source.read_bytes()).hexdigest()==sourcehash
v={'mode':mode,'results':rows,'source_sha256':sourcehash,'elapsed_local_seconds':time.monotonic()-c['started_monotonic_ns']/1e9,'whole_limit_seconds':600,'native_W1_or_PN1_prepared_qualification':False,'merge_ready':False,'partial_failure_not_refunded':True}
(out/'result.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v),flush=True)
sys.exit(code if not any(r['violation'] for r in rows) else 1)
