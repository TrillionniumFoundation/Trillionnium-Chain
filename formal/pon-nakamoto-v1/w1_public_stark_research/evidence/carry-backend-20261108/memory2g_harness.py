import sys,pathlib,os,json,hashlib,importlib.util,subprocess
root=pathlib.Path('/home/qian-qi/work/chain-w1-carry-backend-20261108-f16ac')
crate=root/'formal/pon-nakamoto-v1/w1_public_stark_research'
out=root.parent/'chain-w1-packed-carry-memory2g-20261108-f16ac'
out.mkdir(exist_ok=False)
spec=importlib.util.spec_from_file_location('harness',crate/'run_carry_comparison.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
cpus=sorted(os.sched_getaffinity(0))[:8]
if len(cpus)!=8: raise ValueError('need eight CPUs')
os.sched_setaffinity(0,cpus)
env=dict(os.environ,RAYON_NUM_THREADS='8')
start=h.cgroup_snapshot()
data={'schema':'w1-packed-carry-single-fixture-memory-cap-v1','qualification':'HOLD_NO_GO','production_resources_qualified':False,'input_tasks':1,'fresh_complete_proof_attempts':1,'cpu_affinity':cpus,'observed_cgroup_start':start,'stages':{}}
(out/'result.json').write_text(json.dumps(data,indent=2))
print(json.dumps({'observed_cgroup_start':start}),flush=True)
if start.get('memory.max')!='2147483648': raise RuntimeError('requested 2 GiB MemoryMax not observed')
binary=crate/'target/release/examples/packed_carry_backend'
data['binary_sha256']=h.digest(binary)
fixtures=crate/'fixtures'
header,artifacts=fixtures/'retained.expected-header.bin',fixtures/'retained.artifacts.bin'
pub,proof=out/'prepared',out/'proof'
for stage,args in [('prepare',[binary,'prepare',fixtures/'retained.input.bin',fixtures/'retained.prefix.bin',header,artifacts,pub]),('prove',[binary,'prove',pub/'statement.bin',header,artifacts,proof]),('verify',[binary,'verify',pub/'statement.bin',header,artifacts,proof])]:
 result=h.run_stage(args,out/(stage+'_stage'),crate,env)
 data['stages'][stage]=result
 data['observed_cgroup_end']=h.cgroup_snapshot()
 (out/'result.json').write_text(json.dumps(data,indent=2))
 print(json.dumps({'stage':stage,'exit_code':result['exit_code'],'outer_wall_s':result['outer_wall_s'],'peak_rss_kib':result['peak_rss_kib'],'memory.peak':data['observed_cgroup_end'].get('memory.peak')}),flush=True)
 if result['exit_code']: break
data['fresh_complete_proof_verified']=len(data['stages'])==3 and all(x['exit_code']==0 for x in data['stages'].values())
data['observed_cgroup_end']=h.cgroup_snapshot()
(out/'result.json').write_text(json.dumps(data,indent=2))
sys.exit(0 if data['fresh_complete_proof_verified'] else 1)
