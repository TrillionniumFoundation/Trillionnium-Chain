#!/usr/bin/env python3
import argparse, datetime, hashlib, json, pathlib, subprocess, sys, re
REPO = pathlib.Path('/workspace/scratch/7318d5f890d1/chain-throughput')
WRAPPER = pathlib.Path('/workspace/scratch/7318d5f890d1/run-throughput.sh')
SELECTORS = [
 'ingress::public_v3::tests::completed_input_boundary_rejects_tail_without_consuming_pending_frame',
 'ingress::public_v3::tests::early_complete_body_waiting_for_ready_preserves_signed_native_submission',
 'ingress::public_v3::tests::trailing_input_after_complete_body_cancels_without_starting_work',
 'ingress::public_v3::tests::write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work',
 'ingress::public_v3::tests::disconnecting_paid_requests_waiting_for_queue_cancels_without_starting_work',
]
def sha(path):
 return hashlib.sha256(path.read_bytes()).hexdigest()
def now():
 return datetime.datetime.now(datetime.timezone.utc).isoformat()
def source():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=REPO).decode().split('\0')
 rows={}
 for name in sorted(set(paths)):
  if not name: continue
  if name.startswith('trillionnium/'):
   path=REPO/name
   if path.is_file(): rows[name]=sha(path)
 # Include external literal source fixtures used by crate src/build files.
 for name in list(rows):
  if not name.endswith('.rs') or ('/src/' not in name and not name.endswith('/build.rs')): continue
  src=REPO/name; content=src.read_text(errors='replace')
  included=[]
  for literal in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"\n]+)"',content):
   included.append((src.parent/literal).resolve())
  for suffix in re.findall(r'include_(?:str|bytes)!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"([^"\n]+)"',content):
   crate=src.parent
   while not (crate/'Cargo.toml').exists() and crate!=REPO: crate=crate.parent
   included.append(pathlib.Path(str(crate)+suffix).resolve())
  for item in included:
   if item.is_file(): rows[str(item.relative_to(REPO))]=sha(item)
 raw=json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
 return {'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'native_input_files':rows,'scope':'Dirty candidate: all repository workspace files (Rust, C, headers, build scripts, Cargo/lock and fixtures), plus external literal src/build includes; workflows excluded unless literally included by src; no full-repository immutability claim','manifest_sha256':hashlib.sha256(raw).hexdigest()}
def save(out,name,value):
 (out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def run(command,out,stem,timeout):
 start=now()
 with (out/(stem+'.stdout')).open('wb') as stdout, (out/(stem+'.stderr')).open('wb') as stderr:
  try: code=subprocess.run(command,cwd=REPO,stdout=stdout,stderr=stderr,timeout=timeout).returncode
  except subprocess.TimeoutExpired: code=124
 return {'command':command,'started_at':start,'finished_at':now(),'exit_code':code,'stdout_sha256':sha(out/(stem+'.stdout')),'stderr_sha256':sha(out/(stem+'.stderr'))}
def main():
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['build','test']);parser.add_argument('out',type=pathlib.Path);a=parser.parse_args();out=a.out
 if a.mode=='build':
  out.mkdir(parents=True,exist_ok=False)
  before=source();save(out,'source-before.json',before)
  pre=run(['bash','scripts/project-preflight.sh'],out,'preflight',60);save(out,'preflight-result.json',pre)
  if pre['exit_code']: print(json.dumps(pre),flush=True);return pre['exit_code']
  env_code="import os,json,subprocess; keys=['RUSTUP_TOOLCHAIN','RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTDOC','CC','CXX','AR','CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS','OPENSSL_DIR','OPENSSL_LIB_DIR','OPENSSL_INCLUDE_DIR','OPENSSL_STATIC','OPENSSL_NO_VENDOR','OPENSSL_CONF','OPENSSL_MODULES','PKG_CONFIG_PATH','PKG_CONFIG_LIBDIR','LIBRARY_PATH','LD_LIBRARY_PATH','RUST_TEST_THREADS']; print(json.dumps({'environment':{k:os.environ.get(k) for k in keys},'compiler':subprocess.check_output(['rustc','-vV'],text=True),'cargo':subprocess.check_output(['cargo','--version'],text=True),'cc':subprocess.check_output(['cc','--version'],text=True),'features':'--all-features','profile':'unchanged Cargo test profile'}))"
  env_result=run(['bash',str(WRAPPER),'python3','-c',env_code],out,'compiler-environment',60);save(out,'compiler-environment-result.json',env_result)
  if env_result['exit_code']: print(json.dumps(env_result));return env_result['exit_code']
  command=['bash',str(WRAPPER),'cargo','test','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib','--all-features','--no-run','--message-format=json']
  result=run(command,out,'build',900)
  after=source();save(out,'source-after-build.json',after)
  result['source_unchanged']=before==after
  result['source_manifest_sha256']=before['manifest_sha256'];result['base_head']=before['head']
  artifacts=[]
  for line in (out/'build.stdout').read_text(errors='replace').splitlines():
   try: row=json.loads(line)
   except json.JSONDecodeError: continue
   if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='trnm_pon_node' and row.get('profile',{}).get('test') and row.get('executable'):
    artifacts.append(row)
  if result['exit_code']==0 and len(artifacts)==1:
   result['artifact']=artifacts[0];result['executable_sha256']=sha(pathlib.Path(artifacts[0]['executable']))
  else:
   result['artifact_count']=len(artifacts)
  save(out,'build-result.json',result)
  print(json.dumps({k:v for k,v in result.items() if k!='artifact'},sort_keys=True),flush=True)
  if result['exit_code']:
   print((out/'build.stderr').read_text(errors='replace')[-7000:],flush=True)
  return 0 if result['exit_code']==0 and result['source_unchanged'] and 'artifact' in result else 1
 build=json.loads((out/'build-result.json').read_text())
 if build['exit_code'] or not build['source_unchanged'] or 'artifact' not in build: raise SystemExit('No successful exact-source Node build')
 before=source();expected=json.loads((out/'source-before.json').read_text())
 if before!=expected: raise SystemExit('Rust source drift since Node build')
 executable=pathlib.Path(build['artifact']['executable'])
 if sha(executable)!=build['executable_sha256']: raise SystemExit('Node ELF changed since build')
 results=[]
 for index,selector in enumerate(SELECTORS):
  stem='test-'+str(index+1)
  result=run([str(executable),selector,'--exact','--nocapture','--format','pretty','--test-threads=1'],out,stem,120)
  result['selector']=selector
  validation=run(['python3','scripts/ci/check_required_native_test.py',str(out/(stem+'.stdout')),'--test',selector],out,stem+'-required',30)
  result['required_selector_check']=validation
  results.append(result);save(out,'test-results.json',results)
  print(json.dumps({'selector':selector,'exit_code':result['exit_code'],'required_check':validation['exit_code'],'finished_at':result['finished_at']}),flush=True)
  if result['exit_code'] or validation['exit_code']:
   print((out/(stem+'.stdout')).read_text(errors='replace')[-4500:],flush=True)
   print((out/(stem+'.stderr')).read_text(errors='replace')[-2500:],flush=True)
 after=source();save(out,'source-after-tests.json',after)
 receipt={'scope':'Complete Node all-features lib test ELF compiled; only five named transport controls executed, no complete Node suite or hosted service rerun','base_head':before['head'],'source_manifest_sha256':before['manifest_sha256'],'source_unchanged':before==after,'executable_sha256':sha(executable),'executable_unchanged':sha(executable)==build['executable_sha256'],'finished_at':now(),'tests':len(results),'passed':sum(r['exit_code']==0 and r['required_selector_check']['exit_code']==0 for r in results)}
 save(out,'receipt.json',receipt);print(json.dumps(receipt),flush=True)
 return 0 if receipt['passed']==len(results) and receipt['source_unchanged'] and receipt['executable_unchanged'] else 1
if __name__=='__main__': sys.exit(main())
