from pathlib import Path,PurePosixPath
import hashlib,json,os,re,shutil,sys,time,tomllib,traceback,tarfile,stat,tempfile
import argparse
from hia.platform.service_settlement.contract import ROOT as PROJECT,HERE,output_directory
from hia.platform.service_settlement.process import run
parser=argparse.ArgumentParser()
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--rust-bin',type=Path,required=True)
parser.add_argument('--head',required=True)
parser.add_argument('--tree',required=True)
parser.add_argument('--deadline-monotonic-ns',type=int,required=True)
ARGS=parser.parse_args()
ROOT=output_directory(ARGS.output);ROOT.mkdir(mode=0o700)
HEAD=ARGS.head;TREE=ARGS.tree
REPO=PROJECT;OUT=ROOT/'qualification';OUT.mkdir(mode=0o700)
BIN=ARGS.rust_bin.resolve(strict=True)
assert BIN.is_dir() and ARGS.rust_bin.is_absolute()
HOME=Path(os.environ.get('HOME','')).resolve(strict=True);CARGO_HOME=Path(os.environ.get('CARGO_HOME',str(HOME/'.cargo'))).resolve(strict=True)
# Original tests bind pathname Unix sockets. Their temporary parent must not
# inherit the arbitrary depth of the caller's evidence output directory.
TEMP=Path(tempfile.mkdtemp(prefix='se-',dir='/tmp'))
def temporary_identity():
 s=TEMP.lstat();assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.geteuid() and TEMP.resolve(strict=True)==TEMP
 return {'path':str(TEMP),'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}
TEMP_BEFORE=temporary_identity();assert not list(TEMP.iterdir())
ENV={'PATH':str(BIN)+':/usr/bin:/bin','HOME':str(HOME),'CARGO_HOME':str(CARGO_HOME),'CARGO_NET_OFFLINE':'true','RUSTUP_TOOLCHAIN':'1.95.0-x86_64-unknown-linux-gnu','RUSTC':str(BIN/'rustc'),'CARGO':str(BIN/'cargo'),'RUSTDOC':str(BIN/'rustdoc'),'CARGO_BUILD_JOBS':'4','PYTHONDONTWRITEBYTECODE':'1','GIT_TERMINAL_PROMPT':'0','GIT_NO_LAZY_FETCH':'1','TMPDIR':str(TEMP)}
START=time.monotonic();DEADLINE=ARGS.deadline_monotonic_ns/1e9
assert START<DEADLINE<=START+1200
REPORT={'schema':'trnm.hia.service-settlement-engine.original.v1','status':'INCOMPLETE','target':os.uname().nodename,'source_head':HEAD,'source_tree':TREE,'stages':[],'fresh_original_generator_pending':True,'native_gate_claimed':False,'empty_cargo_target':True,'original_steps_capped_to_existing_240_second_owned_runner':True,'whole_settlement_closed':False}
GRAPH_DIRECTORIES={}
def ident(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def identity(p):
 assert p.is_file() and not p.is_symlink(),str(p)
 with p.open('rb') as f:return {'bytes':p.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def stage(name,argv,cwd=ROOT,seconds=30,env=None,stdin=b''):
 remain=DEADLINE-time.monotonic();assert remain>=1,'original qualification deadline exhausted before dispatch'
 row=run(OUT/name,list(map(str,argv)),cwd=cwd,environment=ENV if env is None else env,seconds=min(seconds,240,int(remain)),data=stdin)
 REPORT['stages'].append({'name':name,**row});save(OUT/'report.json',REPORT)
 print(json.dumps({'name':name,'status':row['status'],'elapsed_ns':row['elapsed_ns'],'exit_code':row['exit_code']}),file=sys.stderr,flush=True)
 assert row['status']=='PASS',(name,row.get('exception'),row.get('exit_code'))
 return (OUT/name/'stdout.raw').read_bytes()
def graph_fence(meta,start):
 packages={p['id']:p for p in meta['packages']};nodes={n['id']:n for n in meta['resolve']['nodes']}
 todo=[start];seen=set();captured={}
 while todo:
  pid=todo.pop()
  if pid in seen:continue
  seen.add(pid);todo.extend(nodes[pid]['dependencies'])
 for pid in sorted(seen):
  p=packages[pid]
  if p['source'] is None:continue
  assert p['source'].startswith('registry+'),p['source']
  directory=Path(p['manifest_path']).parent
  archive=directory.parents[2]/'cache'/directory.parent.name/(p['name']+'-'+p['version']+'.crate')
  expected=next(x for x in lock_packages if x[0]==p['name'] and x[1]==p['version'] and x[2]==p['source'])
  archive_identity=identity(archive);assert archive_identity['sha256']==expected[3],pid
  captured[str(archive)]=archive_identity
  prefix=p['name']+'-'+p['version'];archived={}
  with tarfile.open(archive,'r:gz') as tf:
   for entry in tf:
    parts=PurePosixPath(entry.name).parts
    assert parts and parts[0]==prefix and '..' not in parts and not PurePosixPath(entry.name).is_absolute(),entry.name
    if entry.isdir():continue
    assert entry.isfile() and len(parts)>1,entry.name
    rel=PurePosixPath(*parts[1:]).as_posix();assert rel not in archived,rel
    with tf.extractfile(entry) as f:
     raw=f.read()
    wanted=ident(raw);actual_path=directory/rel
    assert identity(actual_path)==wanted,str(actual_path)
    archived[rel]=wanted;captured[str(actual_path)]=wanted
  actual_files={str(x.relative_to(directory)) for x in directory.rglob('*') if x.is_file() or x.is_symlink()}
  metadata=actual_files & {'.cargo-ok','.cargo-checksum.json'}
  assert actual_files==set(archived)|metadata,{'crate':pid,'extra':sorted(actual_files-set(archived)-metadata),'missing':sorted(set(archived)-actual_files)}
  for name in metadata:captured[str(directory/name)]=identity(directory/name)
  if '.cargo-checksum.json' in metadata:
   checksum=json.loads((directory/'.cargo-checksum.json').read_bytes())
   assert checksum['package']==expected[3],pid
   for rel,digest in checksum.get('files',{}).items():assert rel in archived and archived[rel]['sha256']==digest,(pid,rel)
  GRAPH_DIRECTORIES[str(directory)]=sorted(actual_files)
 REPORT.setdefault('feature_graphs',[]).append({'root':start,'nodes':[{'id':x,'features':nodes[x]['features']} for x in sorted(seen)],'registry_inputs':len(captured),'source_proof':'exact Cargo.lock crate SHA256 and every archive member compared to actual Cargo metadata source tree','registry_source_sets':dict(GRAPH_DIRECTORIES)})
 return captured

try:
 (OUT/'executed-runner.py').write_bytes(Path(__file__).read_bytes())
 expected_raw=(HERE/'qualification/original_sources.json').read_bytes()
 (ROOT/'original-source-map.json').write_bytes(expected_raw)
 assert ident(expected_raw)=={'bytes':419290,'sha256':'5a9956bb08fdc4f14d5090a3e020a3a3e4a328796faab6512d4163a222d7b3bc'}
 expected=json.loads(expected_raw);assert len(expected)==1700
 assert stage('head',['/usr/bin/git','rev-parse','HEAD'],cwd=REPO).decode().strip()==HEAD
 assert stage('tree',['/usr/bin/git','rev-parse','HEAD^{tree}'],cwd=REPO).decode().strip()==TREE
 stage('preflight',['bash','scripts/project-preflight.sh','--audit'],cwd=REPO)
 listed=stage('original-tree',['/usr/bin/git','ls-tree','-rz','--full-tree',HEAD,'trillionnium'],cwd=REPO)
 actual={}
 for entry in listed.split(b'\0'):
  if not entry:continue
  meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split();rel=name.decode()
  assert mode in ('100644','100755') and kind=='blob'
  p=REPO/rel;raw=p.read_bytes();assert not p.is_symlink() and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob
  actual[rel]={'git_blob':blob,**ident(raw)}
 assert actual==expected
 save(OUT/'original-source-before.json',actual)
 def original_fence():
  for rel,v in actual.items():assert identity(REPO/rel)=={k:v[k] for k in ('bytes','sha256')},rel
 original_fence()
 configs=set()
 for p in [REPO/'trillionnium',REPO,*REPO.parents]:
  configs.update([p/'.cargo/config',p/'.cargo/config.toml'])
 configs.update([CARGO_HOME/'config',CARGO_HOME/'config.toml'])
 present=[str(p) for p in configs if p.exists()]
 save(OUT/'cargo-config-inventory.json',{'checked':sorted(map(str,configs)),'present':present});assert not present,present
 tools={}
 for name in ['rustc','cargo','rustdoc','cargo-clippy','clippy-driver','cargo-fmt','rustfmt']:
  p=BIN/name;tools[name]={'path':str(p),**identity(p)}
 save(OUT/'actual-toolchains.json',tools)
 rust=stage('rustc-version',[BIN/'rustc','-Vv']).decode();assert 'release: 1.95.0\n' in rust and 'host: x86_64-unknown-linux-gnu\n' in rust
 clippy=stage('clippy-version',[BIN/'cargo-clippy','--version']).decode();assert clippy.startswith('clippy 0.1.95 ')
 workspace=REPO/'trillionnium/Cargo.toml';cargo=BIN/'cargo';target=ROOT/'cargo-target'
 assert not target.exists()
 lock_raw=(REPO/'trillionnium/Cargo.lock').read_bytes()
 key=lambda p:(p['name'],p['version'],p.get('source',''),p.get('checksum',''))
 lock_packages={key(p) for p in tomllib.loads(lock_raw.decode())['package']}
 meta_raw=stage('locked-cargo-graph',[cargo,'metadata','--offline','--locked','--all-features','--format-version','1','--manifest-path',workspace],cwd=REPO,seconds=90)
 meta=json.loads(meta_raw);pkg=[p for p in meta['packages'] if p['name']=='trnm-service-settlement'];assert len(pkg)==1
 dependency_fence=graph_fence(meta,pkg[0]['id']);save(OUT/'dependency-source-before.json',dependency_fence)
 stdout=stage('original-all',[cargo,'test','--offline','--locked','--no-fail-fast','--manifest-path',workspace,'-p','trnm-service-settlement','--all-features','--target-dir',target,'--message-format=json','--','--test-threads=1'],cwd=REPO,seconds=900)
 events=[json.loads(x) for x in stdout.splitlines() if x.startswith(b'{')]
 tests=[x for x in events if x.get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']=='trnm_service_settlement' and x['profile']['test']]
 assert len(tests)==1
 test_exe=Path(tests[0]['executable']);REPORT['original_test_binary']={'path':str(test_exe),**identity(test_exe),'cargo_event':tests[0]}
 roster=stage('original-roster',[test_exe,'--list'],cwd=REPO,seconds=60).decode()
 names=[x[:-6] for x in roster.splitlines() if x.endswith(': test')];assert len(names)==137,len(names)
 summaries=[dict(zip(('passed','failed','ignored','measured','filtered'),map(int,m))) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',stdout.decode())]
 child='store::snapshot_tests::process_death_child_fixture'
 parent='store::snapshot_tests::process_death_preserves_fail_closed_and_exact_retry'
 assert len(set(names))==137 and child in names and parent in names
 ignored=re.findall(r'^test (.+?) \.\.\. ignored, (.+)$',stdout.decode(),re.MULTILINE)
 assert ignored==[(child,'child fixture explicitly executed by process_death_preserves_fail_closed_and_exact_retry')],ignored
 assert summaries==[{'passed':136,'failed':0,'ignored':1,'measured':0,'filtered':0},{'passed':2,'failed':0,'ignored':0,'measured':0,'filtered':0}],summaries
 nested=stage('nested-process-death',[test_exe,'--exact',parent,'--nocapture','--test-threads=1'],cwd=REPO,seconds=60)
 nested_errors=(OUT/'nested-process-death/stderr.raw').read_bytes()
 for phase in ['before-commit','after-commit']:
  marker=('process-death stage '+phase+': supported contract verified').encode()
  assert (nested+nested_errors).count(marker)==1,(phase,nested,nested_errors)
 assert b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 136 filtered out' in nested
 REPORT.update(original_outer_tests_passed=136,original_nested_fixture_types=1,original_nested_phases=2,original_nested_parent=parent)
 save(OUT/'retained-test-summary.json',{'names':names,'summaries':summaries,'compile_fail_doctests':2,'only_ignored_entry_is_parent_invoked_child':child,'explicit_nested_parent':parent,'explicit_nested_phases':['before-commit','after-commit'],'original_source_changed':False})
 stage('strict-clippy',[BIN/'cargo-clippy','clippy','--offline','--locked','--manifest-path',workspace,'-p','trnm-service-settlement','--all-targets','--all-features','--target-dir',target,'--','-D','warnings'],cwd=REPO,seconds=900)
 stage('formatting',[cargo,'fmt','--manifest-path',workspace,'-p','trnm-service-settlement','--','--check'],cwd=REPO,seconds=60)
 adapter=ROOT/'adapter';adapter.mkdir(mode=0o700)
 reference=(HERE/'qualification/reference.rs').read_bytes();assert ident(reference)['sha256']=='3ca09c00c6f061a09417e44a33ad68748322f6bc75301c460deb64938cab7182'
 (adapter/'reference.rs').write_bytes(reference)
 raw=(HERE/'qualification/reference.Cargo.toml').read_bytes();old=b'"@TASK_KERNEL@"'
 assert raw.count(old)==1;manifest=raw.replace(old,json.dumps(str(REPO/'trillionnium/crates/trnm-task-kernel')).encode());(adapter/'Cargo.toml').write_bytes(manifest)
 lock=(HERE/'qualification/reference.Cargo.lock').read_bytes();assert ident(lock)=={'bytes':17927,'sha256':'15c3bf160ed3c1932b3efab2b02500826facfcb5f7e8d9ea4c8fc3f2f9f940cd'}
 adapted={key(p) for p in tomllib.loads(lock.decode())['package']};assert adapted-lock_packages=={('trnm-settlement-hia-reference','0.1.0','','')}
 (adapter/'Cargo.lock').write_bytes(lock);(adapter/'errors.json').write_bytes((HERE/'qualification/errors.json').read_bytes())
 aenv=dict(ENV,TRNM_SETTLEMENT_ORIGINAL=str(REPO/'trillionnium/crates/trnm-service-settlement/src'),TRNM_SETTLEMENT_ERROR_TABLE=str(adapter/'errors.json'))
 graph_raw=stage('adapter-locked-graph',[cargo,'metadata','--offline','--locked','--format-version','1','--manifest-path',adapter/'Cargo.toml'],cwd=adapter,seconds=90,env=aenv)
 ameta=json.loads(graph_raw);apkg=[x for x in ameta['packages'] if x['name']=='trnm-settlement-hia-reference'];assert len(apkg)==1
 dependency_fence.update(graph_fence(ameta,apkg[0]['id']));save(OUT/'dependency-source-before.json',dependency_fence)
 generated=stage('adapter-locked-build',[cargo,'build','--offline','--locked','--manifest-path',adapter/'Cargo.toml','--target-dir',target,'--message-format=json'],cwd=adapter,seconds=300,env=aenv)
 rows=[json.loads(x) for x in generated.splitlines() if x.startswith(b'{')]
 adapters=[x for x in rows if x.get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']=='settlement-reference']
 assert len(adapters)==1 and not adapters[0]['profile']['test']
 binary=Path(adapters[0]['executable']);REPORT['original_adapter_binary']={'path':str(binary),**identity(binary),'cargo_event':adapters[0]}
 REPORT['adapter_inputs']={str(p):identity(p) for p in adapter.iterdir() if p.is_file()}
 assert (adapter/'Cargo.lock').read_bytes()==lock and (REPO/'trillionnium/Cargo.lock').read_bytes()==lock_raw
 for name,wanted in dependency_fence.items():assert identity(Path(name))==wanted,name
 for directory,names in GRAPH_DIRECTORIES.items():
  assert sorted(str(x.relative_to(Path(directory))) for x in Path(directory).rglob('*') if x.is_file() or x.is_symlink())==names,directory
 original_fence()
 for name,row in tools.items():assert identity(Path(row['path']))=={k:row[k] for k in ('bytes','sha256')}
 REPORT.update(status='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING',original_tests=137,compile_fail_doctests=2,source_unchanged=True,registry_source_unchanged=True,elapsed_seconds=time.monotonic()-START)
except BaseException:REPORT.update(status='FAIL',exception=traceback.format_exc())
finally:
 try:
  if 'original_fence' in globals():original_fence();REPORT['final_original_source_fence']='PASS'
 except BaseException:REPORT['final_fence_exception']=traceback.format_exc();REPORT['status']='FAIL'
 temporary={'before':TEMP_BEFORE,'removed':False}
 try:
  temporary['after']=temporary_identity();assert temporary['after']==TEMP_BEFORE
  temporary['entries_after']=sorted(p.name for p in TEMP.iterdir())
  if REPORT['status']=='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING':
   assert not temporary['entries_after'],'Original temporary directory retained unexpected entries'
   TEMP.rmdir();temporary['removed']=True
 except BaseException:REPORT['temporary_directory_exception']=traceback.format_exc();REPORT['status']='FAIL'
 save(OUT/'temporary-directory.json',temporary)
 REPORT['temporary_directory']=temporary
 save(OUT/'report.json',REPORT)
 print(json.dumps({k:REPORT.get(k) for k in ('status','original_tests','compile_fail_doctests','elapsed_seconds','original_adapter_binary','exception','final_fence_exception')},sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['status']=='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING' else 1)
