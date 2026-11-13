import os,json,hashlib,tarfile,subprocess,time
from pathlib import Path,PurePosixPath
work=Path('/home/qq/chain-real-iteration-20261108-8b4f0eedf006')
source=work/'source'
archive=work/'incoming/runtime-source-supplement-v2.tar.gz'
assert archive.stat().st_size==28744
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='629227c687b4297f39a33efbcb0b7c8b426170c8398eefa7a23bee63d9ed970d'
with tarfile.open(archive,'r:gz') as t:
 members=t.getmembers()
 for m in members:
  p=PurePosixPath(m.name)
  assert not p.is_absolute() and '..' not in p.parts and not m.issym() and not m.islnk()
  assert m.isfile() or m.isdir()
  if m.isfile(): assert not (source/m.name).exists() and not (source/m.name).is_symlink()
 t.extractall(source,filter='data')
supplement_path=source/'runtime-supplement-manifest-v2.json'
assert hashlib.sha256(supplement_path.read_bytes()).hexdigest()=='d3c30cd0ace4cecd7a2f87e476f3bd4d4c2876447855f41a4a4a2514804d5514'
supplement=json.loads(supplement_path.read_text())
original=json.loads((source/'runtime-source-manifest.json').read_text())
assert hashlib.sha256((source/'runtime-source-manifest.json').read_bytes()).hexdigest()=='2708306ae88f3ddec5bbe8d63c40375ef8826c50aa99d3b223ab448a60563cac'
old={x['path']:x for x in original['files']}
assert len(old)==87 and len(supplement['files'])==5 and not (set(old)&set(supplement['files']))
for name,meta in dict(old,**supplement['files']).items():
 b=(source/name).read_bytes()
 assert len(b)==meta['bytes'] and hashlib.sha256(b).hexdigest()==meta['sha256'],name
 assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==meta['git_blob_sha1'],name
driver=source/'scripts/run_learning_service_development.py'
assert hashlib.sha256(driver.read_bytes()).hexdigest()=='2f0e75426c6369174e07fd780d45643b67a4efc334a82bee62b989b158cee30f'
binary=work/'bin/learning_service_round-fc406bad'
native_sha='fc406badb161bd9847b9aa3b7f5863018baae62b172467e2ae3a44317a76808a'
assert binary.stat().st_size==20546720 and hashlib.sha256(binary.read_bytes()).hexdigest()==native_sha
python=Path('/home/qq/hepta-smollm2-weight-research-20261103/ci-env/bin/python')
parent=work/'artifacts/bootstrap-v1/worker/parent-material.json'
train=work/'inputs/training-input.json';heldout=work/'inputs/heldout-input.json';next_input=work/'inputs/next-task-input.json'
pins={str(parent):'3dc662136885ef85c77b16e6abf951169d94b29d274a3fc59021d98997eb5868',str(train):'1d4a4469a44bc142bc093b9de70eaca6e4cfa5a2f7a0329be1014bacb4818964',str(heldout):'079b5c91c0d607ed20abadcae0d7240cf9afd2f5e0fd4993894e340d1b350c41',str(next_input):'39c8b0db87b9d737c6fdde2ea30cd1780123f92ec7c570a9276cd7830ae0c886'}
for p,sha in pins.items():assert hashlib.sha256(Path(p).read_bytes()).hexdigest()==sha
output=work/'artifacts/development-iteration-v1'
assert not output.exists()
command=[str(python),str(driver),'run','--materials','/home/qq/hepta-smollm2-weight-research-20261103/pinned-base','--parent',str(parent),'--parent-sha256',pins[str(parent)],'--training-input',str(train),'--training-input-sha256',pins[str(train)],'--evaluation-input',str(heldout),'--evaluation-input-sha256',pins[str(heldout)],'--next-input',str(next_input),'--next-input-sha256',pins[str(next_input)],'--next-expected-output-sha256','8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d','--native-bin',str(binary),'--native-bin-sha256',native_sha,'--output',str(output),'--operation-id','dev-learning-service-8b4f-v1','--steps','10','--threads','2','--min-correct-gain','1','--base-fee','2000']
env=os.environ.copy()
explicit_env={'PYTHONDONTWRITEBYTECODE':'1','OMP_NUM_THREADS':'2','MKL_NUM_THREADS':'2','OPENBLAS_NUM_THREADS':'2'}
env.update(explicit_env)
start={'schema':'chain-integrated-development-launch-v1','operation_id':'dev-learning-service-8b4f-v1','command':command,'cwd':str(source),'explicit_environment':explicit_env,'native_sha256':native_sha,'driver_sha256':'2f0e75426c6369174e07fd780d45643b67a4efc334a82bee62b989b158cee30f','original_source_manifest_sha256':'2708306ae88f3ddec5bbe8d63c40375ef8826c50aa99d3b223ab448a60563cac','supplement_manifest_sha256':'d3c30cd0ace4cecd7a2f87e476f3bd4d4c2876447855f41a4a4a2514804d5514','verified_source_files':92,'whole_repository_source_verified':False,'expected_next_output':'yes','scope':'public-smoke-development-contract-no-original-owner-installation','single_main_trial':True}
with (work/'logs/integrated-started-v1.json').open('x') as f:json.dump(start,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'integrated_started':True,'operation_id':start['operation_id'],'verified_source_files':92,'output':str(output),'steps':10,'threads':2}),flush=True)
def execute(label,argv):
 begin=time.monotonic_ns()
 out=work/'logs'/(label+'.stdout.log');err=work/'logs'/(label+'.stderr.log')
 with out.open('xb') as f,err.open('xb') as e:
  result=subprocess.run(argv,cwd=source,env=env,stdout=f,stderr=e)
 record={'schema':'chain-integrated-process-exit-v1','label':label,'argv':argv,'returncode':result.returncode,'wall_ns':time.monotonic_ns()-begin,'stdout_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256(err.read_bytes()).hexdigest(),'stdout_bytes':out.stat().st_size,'stderr_bytes':err.stat().st_size}
 with (work/'logs'/(label+'-exit.json')).open('x') as f:json.dump(record,f,sort_keys=True,indent=2);f.write('\n')
 try:
  decoded=json.loads(out.read_text())
  record['observed_status']=decoded.get('status')
  record['next_input']=decoded.get('next_input')
 except Exception:pass
 print(json.dumps({'process_exit':record,'stderr_tail':err.read_text(errors='replace')[-2000:]}),flush=True)
 return record
main=execute('integrated-main-v1',command)
query_command=[str(python),str(driver),'query','--output',str(output),'--native-bin',str(binary),'--native-bin-sha256',native_sha]
cold=execute('integrated-cold-query-v1',query_command)
print(json.dumps({'main_and_cold_query_finished':True,'main_returncode':main['returncode'],'query_returncode':cold['returncode'],'main_status':main.get('observed_status'),'query_status':cold.get('observed_status'),'output':str(output),'no_retry_performed':True}),flush=True)
