
from pathlib import Path
import os,subprocess,hashlib,json,time,shutil,sys
repo=Path('/home/qian-qi/work/chain-p3-shared-profile-20261108-3acf89')
crate=repo/'formal/pon-nakamoto-v1/w1_public_stark_research'
previous=Path('/home/qian-qi/work/p3-shared-profile-observations-3acf89')
obs=Path('/home/qian-qi/work/p3-shared-profile-observations-3acf89-base-sync')
target=Path('/home/qian-qi/work/p3-shared-profile-target-3acf89')
cargo='/home/qian-qi/.cargo/bin/cargo'
rustc='/home/qian-qi/.cargo/bin/rustc'
assert not obs.exists(),'refuse overwriting campaign'
obs.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(name,obj):(obs/name).write_text(json.dumps(obj,indent=2)+'\n')
def git(*args):return subprocess.check_output(['git',*args],cwd=repo,text=True).strip()
def source_identity():
 paths=sorted(p for directory in ['src','examples','tests'] for p in (crate/directory).rglob('*') if p.is_file() and p.suffix in ['.rs','.json'])
 paths+=[crate/'Cargo.toml',crate/'Cargo.lock']
 return {'head':git('rev-parse','HEAD'),'merge_head':git('rev-parse','MERGE_HEAD'),'index_tree':git('write-tree'),
 'unmerged_entries':git('ls-files','-u'),'source_files':{str(p.relative_to(crate)):sha(p) for p in paths},
 'tracked_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--binary'],cwd=repo)).hexdigest()}
preflight=subprocess.run(['bash','scripts/project-preflight.sh'],cwd=repo,capture_output=True,text=True)
(obs/'00-preflight.stdout.log').write_text(preflight.stdout)
(obs/'00-preflight.stderr.log').write_text(preflight.stderr)
assert preflight.returncode==0,preflight.stderr
before=source_identity()
write('merge-source-before.json',before)
assert before['head']=='cfef87ff6e09f998cb8fc5d3165fce8ac9eb2da1'
assert before['merge_head']=='09fbc0f45151a68a1bf205641171840fbf309882'
assert before['index_tree']=='26785a22b3118c718f71c1774dc1c1961db410e9'
assert not before['unmerged_entries']
os.sched_setaffinity(0,list(range(8)))
env=dict(os.environ,RAYON_NUM_THREADS='8',CARGO_TARGET_DIR=str(target))
flag_names=['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','CARGO_BUILD_TARGET']
assert all(env.get(n) is None for n in flag_names),{n:env.get(n) for n in flag_names}
version=subprocess.check_output([rustc,'--version','--verbose'],text=True)
assert version.startswith('rustc 1.95.0 ')
environment={'rustc':version,'cargo':subprocess.check_output([cargo,'--version','--verbose'],text=True),'cpu_affinity':sorted(os.sched_getaffinity(0)),'rayon_threads':8,'cpu_model':next(x for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),'build_environment':{n:env.get(n) for n in flag_names},'target_directory':str(target)}
write('build-environment.json',environment)
v1_index=json.loads((repo/'formal/pon-nakamoto-v1/p3_shared_primitive_qualification/evidence/native-v1/file-index.json').read_text())
v1_expected={x['path']:x for x in v1_index['files']}
fixtures=obs/'input-fixtures';fixtures.mkdir()
for p in sorted((previous/'input-fixtures').glob('*.bin')):
 expected=v1_expected['input-fixtures/'+p.name]
 assert sha(p)==expected['sha256'] and p.stat().st_size==expected['bytes']
 shutil.copyfile(p,fixtures/p.name)
shutil.copyfile(previous/'fixture-provenance.json',obs/'fixture-provenance.json')
original_driver=(previous/'run_tagged_sha3_abba.py').read_text()
assert hashlib.sha256(original_driver.encode()).hexdigest()=='cda4fd1cbe74407630c774c9f23a8dc7923171e653fe01f31983ad4bdfc887b1'
needle="        'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),"
assert original_driver.count(needle)==1
driver=original_driver.replace(needle,needle+"\n        'merge_head':subprocess.check_output(['git','rev-parse','MERGE_HEAD'],cwd=repo,text=True).strip(),\n        'index_tree':subprocess.check_output(['git','write-tree'],cwd=repo,text=True).strip(),")
(obs/'run_tagged_sha3_abba.py').write_text(driver)
receive=(previous/'run_tagged_sha3_receive_controls.py').read_bytes()
assert hashlib.sha256(receive).hexdigest()=='cba2cf5579e14b8faf2fbb54333ff4b761b05b0ff435f1c8849d3a6ad4ff6ab0'
(obs/'run_tagged_sha3_receive_controls.py').write_bytes(receive)
write('driver-provenance.json',{'abba_source_sha256':hashlib.sha256(original_driver.encode()).hexdigest(),'abba_campaign_sha256':sha(obs/'run_tagged_sha3_abba.py'),'changes':['source_snapshot additionally records MERGE_HEAD and git write-tree'],'receive_source_and_campaign_sha256':sha(obs/'run_tagged_sha3_receive_controls.py'),'fixture_source':'native-v1 self-contained inputs, verified against committed file-index.json','profile_or_air_changes_in_campaign':False})
print(json.dumps({'phase':'prepared','source':{k:v for k,v in before.items() if k!='source_files'},'environment':environment}),flush=True)
commands=[
 ('01-build',[cargo,'build','--offline','--locked','--release','--example','packed_carry_backend','--example','tagged_sha3_backend','--example','tagged_sha3_wire_controls']),
 ('02-tests',[cargo,'test','--offline','--locked','--release','--all-features']),
 ('03-clippy',[cargo,'clippy','--offline','--locked','--release','--all-targets','--all-features','--','-D','warnings'])]
results=[]
for label,argv in commands:
 start=time.monotonic()
 with (obs/(label+'.stdout.log')).open('wb') as out,(obs/(label+'.stderr.log')).open('wb') as err:
  p=subprocess.run(argv,cwd=crate,env=env,stdout=out,stderr=err,timeout=1800)
 row={'label':label,'argv':argv,'exit_code':p.returncode,'wall_s':time.monotonic()-start}
 results.append(row);write('build-test-results.json',results)
 print(json.dumps(row),flush=True)
 if p.returncode:raise SystemExit(p.returncode)
binaries={v:{'path':str(target/'release/examples'/n),'sha256':sha(target/'release/examples'/n)} for v,n in [('A','packed_carry_backend'),('B','tagged_sha3_backend'),('wire','tagged_sha3_wire_controls')]}
write('campaign-binaries.json',binaries)
print(json.dumps({'phase':'benchmark_start','binaries':binaries}),flush=True)
argv=['/usr/bin/python3',str(obs/'run_tagged_sha3_abba.py'),'--repo',str(repo),'--target',str(target),'--fixtures',str(fixtures),'--output',str(obs/'abba-v2'),'--timeout','1800']
with (obs/'04-abba.stdout.log').open('wb') as out,(obs/'04-abba.stderr.log').open('wb') as err:
 p=subprocess.run(argv,cwd=crate,env=env,stdout=out,stderr=err,timeout=1800)
print(json.dumps({'phase':'benchmark_end','exit_code':p.returncode,'stdout':(obs/'04-abba.stdout.log').read_text(),'stderr':(obs/'04-abba.stderr.log').read_text()}),flush=True)
if p.returncode:raise SystemExit(p.returncode)
argv=['/usr/bin/python3',str(obs/'run_tagged_sha3_receive_controls.py'),'--repo',str(repo),'--target',str(target),'--fixtures',str(fixtures),'--benchmark',str(obs/'abba-v2'),'--output',str(obs/'receive-controls-v2')]
with (obs/'05-receive.stdout.log').open('wb') as out,(obs/'05-receive.stderr.log').open('wb') as err:
 p=subprocess.run(argv,cwd=crate,env=env,stdout=out,stderr=err,timeout=600)
print(json.dumps({'phase':'receive_end','exit_code':p.returncode,'stdout':(obs/'05-receive.stdout.log').read_text(),'stderr':(obs/'05-receive.stderr.log').read_text()}),flush=True)
if p.returncode:raise SystemExit(p.returncode)
after=source_identity();write('merge-source-after.json',after)
assert before==after,'frozen merged source changed'
for v,n in [('A','packed_carry_backend'),('B','tagged_sha3_backend'),('wire','tagged_sha3_wire_controls')]:
 assert sha(target/'release/examples'/n)==binaries[v]['sha256'],'binary changed'
abba=json.loads((obs/'abba-v2/summary.json').read_text())
control=json.loads((obs/'receive-controls-v2/summary.json').read_text())
tests=(obs/'02-tests.stdout.log').read_text()
import re
test_counts=[int(v) for v in re.findall(r'test result: ok\. ([0-9]+) passed;',tests)]
summary={'schema':'p3-base-sync-merged-integration-campaign-v1','result':'PASS','qualification':'HOLD_NO_GO','source_identity':before,'source_frozen_unchanged':True,'build_test_commands':results,'test_counts':test_counts,'test_total':sum(test_counts),'wire_controls':control['wire_control_count'],'full_verifier_controls':control['full_verifier_control_count'],'full_verifier_controls_passed':control['full_verifier_controls_passed'],'abba':abba,'binaries':binaries,'new_profile_changes':False,'pruned_model_extension':False,'new_security_qualification':False}
write('campaign-summary.json',summary)
print(json.dumps({'phase':'FROZEN_CAMPAIGN_COMPLETE','result':'PASS','test_total':sum(test_counts),'wire_controls':control['wire_control_count'],'full_verifier_controls':control['full_verifier_control_count'],'source_frozen_unchanged':True,'observation_path':str(obs),'medians':abba['observed_medians']}),flush=True)
