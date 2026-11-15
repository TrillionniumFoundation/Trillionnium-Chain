import hashlib,json,os,subprocess,time,traceback
from pathlib import Path
repo=Path('/home/qian-qi/work/chain-pon-five-claims-20261111-d6cb')
artifacts=Path('/home/qian-qi/work/pon-five-claims-w1-artifacts-d6cb')
out=artifacts/'fixed-cache-recovery-297bb40798ca'
out.mkdir(exist_ok=False)
expected_head='297bb40798ca1b4e4a987ef00582067282cda4e9'
expected_tree='129267332b2ef87d3d66d014fddeb894faa9379f'
toolbin='/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'
env=os.environ.copy()
env['PATH']=toolbin+':'+env.get('PATH','')
env['RUSTUP_TOOLCHAIN']='1.95.0'
env['RUSTC']=toolbin+'/rustc'
target='/home/qian-qi/work/chain-pon-submit-target-d6cb'
env['CARGO_TARGET_DIR']=target
env['CARGO_BUILD_JOBS']='2'
env['RUST_TEST_THREADS']='1'
env['CARGO_TERM_COLOR']='never'
records=[]
def capture(args):
 return subprocess.run(args,cwd=repo,env=env,check=True,capture_output=True,text=True).stdout.strip()
def digest_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def run(label,args):
 started=time.time()
 with (out/(label+'.stdout.log')).open('wb') as stdout,(out/(label+'.stderr.log')).open('wb') as stderr:
  p=subprocess.run(args,cwd=repo,env=env,stdout=stdout,stderr=stderr,timeout=300)
 record={'label':label,'argv':args,'started_unix':started,'finished_unix':time.time(),'exit_code':p.returncode}
 for name in ['stdout','stderr']:
  q=out/(label+'.'+name+'.log')
  record[name]={'bytes':q.stat().st_size,'sha256':digest_file(q)}
 records.append(record);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps(record),flush=True)
 assert p.returncode==0,label
def full_source(label):
    head=capture(['git','rev-parse','HEAD'])
    tree=capture(['git','rev-parse','HEAD^{tree}'])
    entries=subprocess.run(['git','ls-tree','-r','--full-tree','-z','HEAD'],cwd=repo,check=True,capture_output=True).stdout.split(b'\0')
    count=total=0
    for entry in entries:
        if not entry: continue
        info,path=entry.split(b'\t',1)
        mode,kind,expected=info.split()
        assert kind==b'blob', 'unexpected nonblob source '+repr(path)
        item=repo/os.fsdecode(path)
        if mode==b'120000':
            raw=os.fsencode(os.readlink(item))
            actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            size=len(raw)
        else:
            before=item.stat()
            size=before.st_size
            digest=hashlib.sha1(b'blob '+str(size).encode()+b'\0')
            with item.open('rb') as stream:
                while True:
                    chunk=stream.read(1048576)
                    if not chunk: break
                    digest.update(chunk)
            after=item.stat()
            assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'source changed during read '+str(item)
            actual=digest.hexdigest()
        assert actual==expected.decode(), 'tracked source mismatch '+str(item)
        count+=1;total+=size
    assert capture(['git','status','--porcelain'])=='', 'dirty subject'
    result={'head':head,'tree':tree,'tracked_entries_verified':count,'tracked_bytes_verified':total,'full_git_blob_equality':True}
    (out/(label+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result

try:
 assert capture(['git','rev-parse','HEAD'])==expected_head
 assert capture(['git','rev-parse','HEAD^{tree}'])==expected_tree
 run('preflight-before-clean',['bash','scripts/project-preflight.sh'])
 before=full_source('source-before')
 qualified=json.loads((artifacts/'before-native-rustup-qualified'/'summary.json').read_text())
 assert qualified['expected_original_failure_observed'] is True
 binary=Path(qualified['binary']['path'])
 original_hash=qualified['binary']['sha256_after']
 assert original_hash=='f9f39f1e2b76c624810ff6e1c863541049db82f9442675865e635bb5cb584f56'
 assert digest_file(binary)==original_hash
 binaries=artifacts/'native-binaries'
 binaries.mkdir(exist_ok=True)
 kept=binaries/'before-e63427560885-f9f39f1e2b76.elf'
 if not kept.exists():
  run('preserve-before-elf',['cp','--reflink=auto','--sparse=always',str(binary),str(kept)])
 assert digest_file(binary)==original_hash and digest_file(kept)==original_hash
 binary_receipt={'scope':'qualified-before','source_head':qualified['source']['head'],'original_path':str(binary),'retained_path':str(kept),'bytes':kept.stat().st_size,'sha256':original_hash,'live_proc_image_observation':False,'include_elf_in_git':False}
 (out/'before-elf-retention.json').write_text(json.dumps(binary_receipt,indent=2)+'\n')
 run('metadata',[toolbin+'/cargo','metadata','--manifest-path','trillionnium/Cargo.toml','--locked','--offline','--format-version','1'])
 metadata=json.loads((out/'metadata.stdout.log').read_text())
 local=[item for item in metadata['packages'] if item['source'] is None]
 assert local and all(Path(item['manifest_path']).is_relative_to(repo) for item in local)
 local_ids={item['id'] for item in local}
 packages=[{key:item[key] for key in ['id','name','version','manifest_path']} for item in local]
 (out/'local-packages.json').write_text(json.dumps(packages,indent=2)+'\n')
 previous=[]
 for line in (artifacts/'fixed-native-297bb40798ca'/'build.stdout.log').read_text().splitlines():
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  if item.get('reason')=='compiler-artifact' and item.get('package_id') in local_ids:previous.append(item)
 (out/'failed-attempt-local-artifacts.json').write_text(json.dumps(previous,indent=2)+'\n')
 observed_sources=[]
 relative='trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs'
 for worktree in [repo,Path('/home/qian-qi/work/chain-pon-submit-probe-20261111-d6cb')]:
  path=worktree/relative;raw=path.read_bytes()
  found=[{'line':i+1,'text':line} for i,line in enumerate(raw.decode().splitlines()) if 'fn check_account_profile' in line]
  observed_sources.append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'mtime_ns':path.stat().st_mtime_ns,'declarations':found})
 cause={'schema':'trnm-node-cross-worktree-cache-observation-v1','subject':expected_head,'observed_sources':observed_sources,'failed_build_exit_code':101,'native_tests_invoked':False,'inference':'Cargo reused a fresh=true local mvcc artifact whose private-method diagnostic matches the before source instead of the public method in T. All local path package outputs will be invalidated, not only mvcc.'}
 (out/'cache-cause.json').write_text(json.dumps(cause,indent=2)+'\n')
 args=[toolbin+'/cargo','clean','--manifest-path','trillionnium/Cargo.toml','--release','--locked','--offline']
 for item in packages:args.extend(['-p',item['id']])
 run('clean-all-local-packages',args)
 survivors=sorted({path for item in previous for path in item['filenames'] if Path(path).exists()})
 (out/'local-artifact-survivors.json').write_text(json.dumps(survivors,indent=2)+'\n')
 assert not survivors,survivors
 assert not binary.exists()
 after=full_source('source-after')
 assert before==after
 summary={'schema':'trnm-node-local-cache-recovery-v1','subject':expected_head,'source_before':before,'source_after':after,'target_dir':target,'local_package_count':len(packages),'all_requested_packages_local':True,'third_party_packages_requested':False,'observed_stale_local_outputs_removed':True,'remaining_prior_local_artifacts':survivors,'before_binary':binary_receipt,'source_changed':False}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps(summary,indent=2),flush=True)
except BaseException:
 (out/'failure.txt').write_text(traceback.format_exc())
 raise
