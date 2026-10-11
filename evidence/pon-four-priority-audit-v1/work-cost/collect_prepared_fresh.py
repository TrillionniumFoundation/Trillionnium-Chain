import datetime, hashlib, json, os, platform, subprocess, sys, time
from pathlib import Path
ROOT=Path('/workspace/scratch/aebafee84981/Trillionnium-Chain')
sys.path.insert(0,str(ROOT/'scripts'))
import pon_work_cost_report as cost
os.chdir(ROOT)
out=Path('/workspace/scratch/aebafee84981/work-security-fresh-3c63c836/paired')
out.mkdir(exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
def write(name,value):
    cost.write_new(out/name,cost.encoded(value) if not isinstance(value,bytes) else value)
files=cost.current_inputs()
files['config/pon/work-security-acceptance-v1.json']=sha(cost.ACCEPTANCE_PROFILE.read_bytes())
cost.clean()
head=cost.git('rev-parse','HEAD');tree=cost.git('rev-parse','HEAD^{tree}')
record={'schema':'pon-paired-cost-execution-observation-v1','source_commit':head,'source_tree':tree,'source_files_sha256':files,'source_clean_before':True,'source_clean_after':None,'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.platform(),'python':platform.python_version(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'cargo':subprocess.check_output(['cargo','--version'],text=True).strip(),'environment':{k:os.environ.get(k) for k in ['CARGO_HOME','RUSTUP_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS','OPENBLAS_NUM_THREADS','OMP_NUM_THREADS','PYTHONDONTWRITEBYTECODE']},'logical_cpus':os.cpu_count(),'affinity_cpus':sorted(os.sched_getaffinity(0)),'cpu_description':Path('/proc/cpuinfo').read_text().split('\n\n')[0],'filesystem':subprocess.check_output(['stat','-f','-c','%T',str(ROOT)],text=True).strip(),'concurrency':'serial example; no other local measurement intentionally run concurrently','independent_accepted':False,'public_network_tested':False,'work_hardness_accepted':False,'production_activation':False}
command=['cargo','build','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-crypto-primitives','--example','pon_prepared_cost']
record['build_command']=command
build=cost.run_bounded(command,b'',timeout=900,stdout_limit=2*1024*1024,stderr_limit=2*1024*1024)
write('build.log',build.stdout+build.stderr);record['build_returncode']=build.returncode
if build.returncode==0:
    binary=Path(os.environ['CARGO_TARGET_DIR'])/'release/examples/pon_prepared_cost'
    record['binary_sha256']=sha(binary.read_bytes());record['command']=[str(binary)]
    start=time.monotonic_ns();execution=cost.run_bounded([str(binary)],b'',timeout=120,stdout_limit=2*1024*1024,stderr_limit=65536)
    record['process_wall_ns']=time.monotonic_ns()-start;record['returncode']=execution.returncode
    write('prepared-cost.json',execution.stdout);write('stderr.log',execution.stderr)
    record['binary_unchanged_after']=sha(binary.read_bytes())==record['binary_sha256']
    if execution.returncode==0:
        parsed=json.loads(execution.stdout)
        cost.prepared_samples(parsed)
        record['sample_validation_passed']=True
current=cost.current_inputs();current['config/pon/work-security-acceptance-v1.json']=sha(cost.ACCEPTANCE_PROFILE.read_bytes())
record['source_clean_after']=not cost.git('status','--porcelain')
record['source_inputs_unchanged_after']=current==files
record['source_head_unchanged_after']=cost.git('rev-parse','HEAD')==head
record['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
write('execution.json',record)
write('manifest.json',{'schema':'pon-paired-cost-artifacts-v1','files':{p.name:sha(p.read_bytes()) for p in out.iterdir() if p.is_file()},'independent_accepted':False,'production_activation':False})
print(json.dumps({k:v for k,v in record.items() if k not in ['source_files_sha256','cpu_description','affinity_cpus']},indent=2))
assert record.get('sample_validation_passed') and record['source_clean_after'] and record['source_inputs_unchanged_after'] and record['source_head_unchanged_after'] and record['binary_unchanged_after']
