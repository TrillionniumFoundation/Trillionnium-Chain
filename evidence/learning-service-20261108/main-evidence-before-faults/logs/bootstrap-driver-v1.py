import os,json,hashlib,subprocess,time,platform,shutil
from pathlib import Path
work=Path('/home/qq/chain-real-iteration-20261108-8b4f0eedf006')
source=work/'source'
for p in [Path('/home/qq/.cargo/bin/cargo'),Path('/home/qq/.rustup/toolchains'),Path('/home/qq/.cargo/registry/src'),Path('/home/qq/.cargo/registry/cache'),Path('/home/qq/hepta-p1-cargo-tools-20261105-ba4b')]:
 value={'toolchain_probe_path':str(p),'exists':p.exists()}
 if p.is_dir(): value['entries']=[q.name for q in p.iterdir()][:20]
 print(json.dumps(value),flush=True)
cargo=Path('/home/qq/.cargo/bin/cargo')
if cargo.exists():
 r=subprocess.run([str(cargo),'--version'],capture_output=True,text=True,timeout=15)
 print(json.dumps({'cargo_returncode':r.returncode,'cargo_version':r.stdout.strip()}),flush=True)
python=Path('/home/qq/hepta-smollm2-weight-research-20261103/ci-env/bin/python')
training=work/'inputs/training-input.json'
command=[str(python),str(source/'scripts/llm_inherited_runtime.py'),'train','--bootstrap','--operation-id','dev-bootstrap-8b4f-v1','--steps','1','--threads','2','--materials','/home/qq/hepta-smollm2-weight-research-20261103/pinned-base','--input',str(training),'--input-sha256',hashlib.sha256(training.read_bytes()).hexdigest(),'--output',str(work/'artifacts/bootstrap-v1')]
env=os.environ.copy()
explicit_env={'PYTHONDONTWRITEBYTECODE':'1','OMP_NUM_THREADS':'2','MKL_NUM_THREADS':'2','OPENBLAS_NUM_THREADS':'2'}
env.update(explicit_env)
started={'schema':'chain-development-bootstrap-start-v1','operation_id':'dev-bootstrap-8b4f-v1','command':command,'cwd':str(source),'explicit_environment':explicit_env,'source_archive_sha256':'e6666a3f8aa324620d6e3b952b098d83be988ae3687c409d7fad233b6f78075a','source_manifest_sha256':hashlib.sha256((source/'runtime-source-manifest.json').read_bytes()).hexdigest(),'scope':'explicit-development-bootstrap-not-original-owner-installation','profile':'strict-v1','platform':platform.platform(),'libc':platform.libc_ver(),'disk_free_bytes':shutil.disk_usage(work).free,'installation_authorized':False}
with (work/'logs/bootstrap-started-v1.json').open('x') as f: json.dump(started,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'bootstrap_started':started}),flush=True)
begin=time.monotonic_ns()
with (work/'logs/bootstrap-v1.stdout.log').open('xb') as out,(work/'logs/bootstrap-v1.stderr.log').open('xb') as err:
 r=subprocess.run(command,cwd=source,env=env,stdout=out,stderr=err,timeout=2100)
ended={'schema':'chain-development-bootstrap-exit-v1','operation_id':'dev-bootstrap-8b4f-v1','returncode':r.returncode,'wall_ns':time.monotonic_ns()-begin,'scope':started['scope'],'stdout_sha256':hashlib.sha256((work/'logs/bootstrap-v1.stdout.log').read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((work/'logs/bootstrap-v1.stderr.log').read_bytes()).hexdigest()}
descriptor=work/'artifacts/bootstrap-v1/worker/parent-material.json'
if descriptor.is_file(): ended['parent_material']={'path':str(descriptor),'sha256':hashlib.sha256(descriptor.read_bytes()).hexdigest(),'value':json.loads(descriptor.read_text())}
with (work/'logs/bootstrap-exit-v1.json').open('x') as f:json.dump(ended,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'bootstrap_exit':ended,'stdout_tail':(work/'logs/bootstrap-v1.stdout.log').read_text()[-3000:],'stderr_tail':(work/'logs/bootstrap-v1.stderr.log').read_text()[-3000:]}),flush=True)
