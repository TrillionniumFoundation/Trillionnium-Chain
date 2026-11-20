from pathlib import Path
import hashlib,json,lzma,os,sys,time,traceback
import argparse
from hia.platform.service_settlement.contract import ROOT as REPO,HERE,output_directory
from hia.platform.service_settlement.process import run
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--original',type=Path,required=True);p.add_argument('--rust-bin',type=Path,required=True);p.add_argument('--head',required=True);p.add_argument('--tree',required=True);a=p.parse_args()
ROOT=output_directory(a.output);ROOT.mkdir(mode=0o700);SOURCE=a.original.resolve(strict=True)
(ROOT/'capture_exec.py').write_bytes((HERE/'qualification/capture_exec.py').read_bytes())
OUT=ROOT/'qualification';OUT.mkdir(mode=0o700)
ENV={'PATH':str(a.rust_bin.resolve(strict=True))+':/usr/bin:/bin','HOME':os.environ['HOME'],'PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(ROOT)}
REPORT={'status':'INCOMPLETE','target':os.uname().nodename,'execution_seconds':120,'cleanup_seconds':3,'fresh_original_invocation':True,'fresh_native_reexecution_claimed':False,'stages':[]}
def ident(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def identity(p):
 assert p.is_file() and not p.is_symlink()
 with p.open('rb') as f:return {'bytes':p.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def save(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
def stage(name,argv,cwd=ROOT,seconds=30):
 row=run(OUT/name,list(map(str,argv)),cwd=cwd,environment=ENV,seconds=seconds)
 REPORT['stages'].append({'name':name,**row});save(OUT/'report.json',REPORT)
 print(json.dumps({'stage':name,'status':row['status'],'elapsed_ns':row['elapsed_ns']}),file=sys.stderr,flush=True)
 assert row['status']=='PASS',(name,row.get('exception'))
 return (OUT/name/'stdout.raw').read_bytes()
try:
 (OUT/'executed-runner.py').write_bytes(Path(__file__).read_bytes())
 raw=(SOURCE/'qualification/report.json').read_bytes();r=json.loads(raw)
 assert r['status']=='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING'
 assert r['source_head']==a.head and r['source_tree']==a.tree
 assert r['original_outer_tests_passed']==136 and r['original_nested_fixture_types']==1 and r['original_nested_phases']==2 and r['compile_fail_doctests']==2
 exe=Path(r['original_adapter_binary']['path']);wanted={k:r['original_adapter_binary'][k] for k in ['bytes','sha256']}
 assert identity(exe)==wanted and exe==SOURCE/'cargo-target/debug/settlement-reference'
 assert r['original_adapter_binary']['cargo_event']['profile']=={'opt_level':'0','debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':False}
 (OUT/'original-build-report.json').write_bytes(raw)
 orig=json.loads((SOURCE/'qualification/original-source-before.json').read_bytes())
 deps=json.loads((SOURCE/'qualification/dependency-source-before.json').read_bytes())
 original={str(REPO/n):{k:v[k] for k in ['bytes','sha256']} for n,v in orig.items()}
 all_inputs=original|deps|{str(exe):wanted}|r['adapter_inputs']|{str(SOURCE/'qualification/report.json'):ident(raw),str(ROOT/'capture_exec.py'):identity(ROOT/'capture_exec.py'),str(Path(__file__)):identity(Path(__file__))}
 for p in [Path(sys.executable).resolve(),HERE/'process.py',REPO/'scripts/w1_owned_process_collector_v1.py']:
  all_inputs[str(p)]=identity(p)
 for value in json.loads((SOURCE/'qualification/actual-toolchains.json').read_bytes()).values():
  all_inputs[value['path']]={k:value[k] for k in ['bytes','sha256']}
 def fence():
  for name,v in all_inputs.items():assert identity(Path(name))==v,name
  for graph in r['feature_graphs']:
   for directory,names in graph['registry_source_sets'].items():
    assert sorted(str(x.relative_to(Path(directory))) for x in Path(directory).rglob('*') if x.is_file() or x.is_symlink())==names,directory
 fence();save(OUT/'source-before.json',all_inputs)
 stage('preflight',['bash','scripts/project-preflight.sh','--audit'],cwd=REPO)
 stage('elf-dynamic',['/usr/bin/readelf','-d',exe])
 all_inputs['/usr/bin/ldd']=identity(Path('/usr/bin/ldd'))
 deps_raw=stage('elf-loader',['/usr/bin/bash','/usr/bin/ldd',exe]);assert b'not found' not in deps_raw
 loader_inputs={}
 import re
 for line in deps_raw.decode().splitlines():
  matches=re.findall(r'(/[A-Za-z0-9_./+:-]+)',line)
  for value in matches:
   p=Path(value).resolve()
   if p.is_file():loader_inputs[str(p)]=identity(p)
 assert loader_inputs
 all_inputs.update(loader_inputs);save(OUT/'source-before.json',all_inputs)
 data=ROOT/'original-output';data.mkdir(mode=0o700)
 request={'output':str(data),'argv':[str(exe),'generate'],'executable':wanted,'source_report_status':r['status']}
 save(ROOT/'exec-request.json',request)
 all_inputs[str(ROOT/'exec-request.json')]=identity(ROOT/'exec-request.json');save(OUT/'source-before.json',all_inputs);fence()
 stage('fresh-original-generate',['/usr/bin/python3','-B',ROOT/'capture_exec.py',ROOT/'exec-request.json'],cwd=SOURCE/'adapter',seconds=120)
 actual=(data/'original.stdout.raw').read_bytes();errors=(data/'original.stderr.raw').read_bytes()
 assert not errors,errors
 fresh=json.loads(actual);packed=(HERE/'qualification/fixtures.json.xz').read_bytes()
 assert ident(packed)['sha256']=='bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26'
 retained_raw=lzma.decompress(packed);retained=json.loads(retained_raw)
 assert fresh==retained,'fresh original JSON differs from exact native fixture input'
 fixtures=fresh['fixtures'];assert len(fixtures)==320 and sum(x['operation_count'] for x in fixtures)==2636
 names=[x['name'] for x in fixtures];assert len(names)==len(set(names))
 rows=[]
 for f,g in zip(fixtures,retained['fixtures'],strict=True):
  for key in ['input','expected']:assert bytes.fromhex(f[key])==bytes.fromhex(g[key])
  rows.append({'name':f['name'],'operations':f['operation_count'],'input':ident(bytes.fromhex(f['input'])),'expected':ident(bytes.fromhex(f['expected']))})
 save(OUT/'fresh-fixture-byte-identities.json',rows)
 (OUT/'fresh-generated-fixtures.json.xz').write_bytes(lzma.compress(actual,preset=6))
 fence()
 REPORT.update(status='FRESH_ORIGINAL_320_FIXTURES_2636_OPERATIONS_EXACT_RETAINED_BYTES_PASS',source_report=ident(raw),source_unchanged=True,original_executable=wanted,original_stdout=ident(actual),original_stderr=ident(errors),fixture_count=320,operations=2636,retained_decompressed_identity=ident(retained_raw),exact_json_bytes_equal=actual==retained_raw,full_fixture_bytes_equal=True,fixture_identity_manifest=identity(OUT/'fresh-fixture-byte-identities.json'))
except BaseException:REPORT.update(status='FAIL',exception=traceback.format_exc())
finally:
 try:
  if 'fence' in globals():fence();REPORT['final_fence']='PASS'
 except BaseException:REPORT['status']='FAIL';REPORT['final_fence_exception']=traceback.format_exc()
 save(OUT/'report.json',REPORT);print(json.dumps({k:REPORT.get(k) for k in ['status','fixture_count','operations','original_stdout','exact_json_bytes_equal','final_fence','exception','final_fence_exception']}),flush=True)
raise SystemExit(0 if REPORT['status']=='FRESH_ORIGINAL_320_FIXTURES_2636_OPERATIONS_EXACT_RETAINED_BYTES_PASS' else 1)
