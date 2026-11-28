"""Bind the actual fresh original executable, compile profile, owned process and stdout."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,re,tarfile,math
from .observations import ident,document,file_id,basic_process,exact_int,save
from .process_readback import owned_process
from ..contract import FIXTURES_SHA256
import io,lzma,tomllib
BUILD_STATUS='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING'
GEN_STATUS='FRESH_ORIGINAL_320_FIXTURES_2636_OPERATIONS_EXACT_RETAINED_BYTES_PASS'
SOURCE_MAP={'bytes':419290,'sha256':'5a9956bb08fdc4f14d5090a3e020a3a3e4a328796faab6512d4163a222d7b3bc'}
STDOUT_ID={'bytes':37267073,'sha256':'d0a7700ed2b6a25a2ef41a3894de4ce4139a53547c1eec0ac9a0f925042b2550'}
# This reader receives the hash of the reviewed capture program as a source pin,
# alongside the immutable archive pin; the archive itself cannot choose this pin.
EXPECTED_WRAPPER_SHA256='9cf66393b9ec5b94d2b5b1b3a73eaa8a9ce04c49e4fed1e6310bf2317070eda8'
def validate_generator_binding(store,build,gen,expected_root,expected_generator_root):
 """This predicate rejects any otherwise-successful foreign owned-process receipt."""
 root=expected_root;groot=expected_generator_root;exe=root+'/cargo-target/debug/settlement-reference'
 expected_argv=['/usr/bin/python3','-B',groot+'/capture_exec.py',groot+'/exec-request.json']
 session=store.session;ADAPTER_ID={k:build['original_adapter_binary'][k] for k in ['bytes','sha256']}
 env={'PATH':session['rust_bin']+':/usr/bin:/bin','HOME':session['home'],'PYTHONDONTWRITEBYTECODE':'1','TMPDIR':groot}
 r,command=owned_process(store,'generator/qualification/fresh-original-generate',120,expected_argv,root+'/adapter',env)
 assert store.actual(exe)==ADAPTER_ID==gen['original_executable']
 assert {k:build['original_adapter_binary'][k] for k in ['bytes','sha256']}==ADAPTER_ID
 assert store.identity('generator/capture_exec.py')['sha256']==EXPECTED_WRAPPER_SHA256
 source=store.read('generator/capture_exec.py')
 assert b'os.execve(fd,request[\'argv\'],dict(os.environ))' in source
 request=store.doc('generator/exec-request.json')
 assert request=={'argv':[exe,'generate'],'executable':ADAPTER_ID,'output':groot+'/original-output','source_report_status':BUILD_STATUS}
 intent=store.doc('generator/original-output/actual-exec-intent.json')
 assert intent=={'argv':[exe,'generate'],'cwd':root+'/adapter','actual_executable':ADAPTER_ID,'exec_by_open_verified_fd':True,'stdout':groot+'/original-output/original.stdout.raw','stderr':groot+'/original-output/original.stderr.raw','stdout_max_bytes':67108864,'stdin_sha256':ident(b'')['sha256']}
 assert store.identity('generator/original-output/original.stdout.raw')==STDOUT_ID==gen['original_stdout']
 assert store.read('generator/original-output/original.stderr.raw')==b''
 assert store.read('generator/qualification/fresh-original-generate/stdout.raw')==store.read('generator/qualification/fresh-original-generate/stderr.raw')==b''
 inputs=store.doc('generator/qualification/source-before.json')
 for path,wanted in inputs.items():assert store.actual(path)==wanted,path
 for path in [exe,groot+'/capture_exec.py',groot+'/exec-request.json']:
  assert path in inputs
 assert inputs[groot+'/capture_exec.py']['sha256']==EXPECTED_WRAPPER_SHA256
 assert gen['source_report']==store.identity('original/qualification/report.json')
 assert gen['final_fence']=='PASS' and gen['source_unchanged'] is True and gen['full_fixture_bytes_equal'] is True
 return {'receipt':store.identity('generator/qualification/fresh-original-generate/receipt.json'),'argv':expected_argv,'actual_original_argv':[exe,'generate'],'executable':ADAPTER_ID,'stdout':STDOUT_ID,'output_is_full_fd_redirected_file':True,'collector_logs_are_separate':True,'actual_elapsed_ns':r['elapsed_ns']}

def verify_registry(store,build,wanted):
 lock=tomllib.loads(store.read('source/trillionnium/Cargo.lock').decode())
 pins={(p['name'],p['version'],p.get('source','')):p.get('checksum') for p in lock['package']}
 captured={};graphs=[];directories={}
 for stage,package_name in [('locked-cargo-graph','trnm-service-settlement'),('adapter-locked-graph','trnm-settlement-hia-reference')]:
  graph=store.doc('original/qualification/'+stage+'/stdout.raw');packages={p['id']:p for p in graph['packages']};nodes={p['id']:p for p in graph['resolve']['nodes']}
  matches=[p for p in packages.values() if p['name']==package_name];assert len(matches)==1
  start=matches[0]['id'];todo=[start];seen=set();counted={}
  while todo:
   item=todo.pop()
   if item in seen:continue
   seen.add(item);todo.extend(nodes[item]['dependencies'])
  for item in sorted(seen):
   p=packages[item]
   if p['source'] is None:continue
   assert p['source'].startswith('registry+')
   directory=PurePosixPath(p['manifest_path']).parent;prefix=p['name']+'-'+p['version']
   archive=directory.parents[2]/'cache'/directory.parent.name/(prefix+'.crate')
   raw=store.actual_bytes(str(archive));assert ident(raw)['sha256']==pins[(p['name'],p['version'],p['source'])]
   captured[str(archive)]=ident(raw);counted[str(archive)]=ident(raw);members={}
   with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tf:
    for member in tf:
     parts=PurePosixPath(member.name).parts
     assert parts and parts[0]==prefix and '..' not in parts and not PurePosixPath(member.name).is_absolute()
     if member.isdir():continue
     assert member.isfile() and len(parts)>1
     name=PurePosixPath(*parts[1:]).as_posix();assert name not in members
     data=tf.extractfile(member).read();assert store.actual_bytes(str(directory/name))==data
     members[name]=ident(data);captured[str(directory/name)]=ident(data);counted[str(directory/name)]=ident(data)
   declared=[x for x in build['feature_graphs'] if x['root']==start];assert len(declared)==1
   names=declared[0]['registry_source_sets'][str(directory)]
   assert len(names)==len(set(names)) and set(names)-set(members)<={'.cargo-ok','.cargo-checksum.json'} and set(members)<=set(names)
   for name in sorted(set(names)-set(members)):
    data=store.actual_bytes(str(directory/name));captured[str(directory/name)]=ident(data);counted[str(directory/name)]=ident(data)
    if name=='.cargo-checksum.json':
     checksum=document(data);assert checksum['package']==pins[(p['name'],p['version'],p['source'])]
     for k,h in checksum.get('files',{}).items():assert members[k]['sha256']==h
   directories[str(directory)]=sorted(names)
  graphs.append({'root':start,'nodes':[{'id':x,'features':nodes[x]['features']} for x in sorted(seen)],'registry_inputs':len(counted),'source_proof':'exact Cargo.lock crate SHA256 and every archive member compared to actual Cargo metadata source tree','registry_source_sets':dict(directories)})
 assert graphs==build['feature_graphs'] and captured==wanted

def readback(store):
 view=store.view
 root=view['roots']['original'];groot=view['roots']['generator'];repo=store.session['source_root']
 build=store.doc('original/qualification/report.json');gen=store.doc('generator/qualification/report.json')
 assert build['status']==BUILD_STATUS and gen['status']==GEN_STATUS
 assert build['source_head']==store.session['repository']['head'] and build['source_tree']==store.session['repository']['tree']
 assert build['source_unchanged'] is True and build['registry_source_unchanged'] is True and build['final_original_source_fence']=='PASS'
 assert build['empty_cargo_target'] is True
 for k,n in [('original_tests',137),('original_outer_tests_passed',136),('original_nested_fixture_types',1),('original_nested_phases',2),('compile_fail_doctests',2)]:
  assert exact_int(build[k])==n
 assert math.isfinite(build['elapsed_seconds']) and 0<build['elapsed_seconds']<1200
 expected=store.doc('original/original-source-map.json');assert store.identity('original/original-source-map.json')==SOURCE_MAP
 actual=store.doc('original/qualification/original-source-before.json');assert actual==expected and len(actual)==1700
 for name,wanted in actual.items():
  raw=store.read('source/'+name)
  assert ident(raw)=={k:wanted[k] for k in ['bytes','sha256']} and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==wanted['git_blob'],name
 listing=store.read('original/qualification/original-tree/stdout.raw');tracked={}
 for entry in listing.split(b'\0'):
  if not entry:continue
  meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split();assert mode in ['100644','100755'] and kind=='blob'
  tracked[name.decode()]=blob
 assert tracked=={n:v['git_blob'] for n,v in actual.items()}
 registry=store.doc('original/qualification/dependency-source-before.json')
 for name,wanted in registry.items():assert store.actual(name)==wanted,name
 toolchains=store.doc('original/qualification/actual-toolchains.json')
 for v in toolchains.values():assert store.actual(v['path'])=={k:v[k] for k in ['bytes','sha256']}
 config=store.doc('original/qualification/cargo-config-inventory.json')
 repo_path=PurePosixPath(repo);cargo_home=PurePosixPath(store.session['cargo_home']);checked=set()
 for p in [repo_path/'trillionnium',repo_path,*repo_path.parents]:
  checked.update([str(p/'.cargo/config'),str(p/'.cargo/config.toml')])
 checked.update([str(cargo_home/'config'),str(cargo_home/'config.toml')])
 assert config=={'checked':sorted(checked),'present':[]}
 assert 'release: 1.95.0\n' in store.read('original/qualification/rustc-version/stdout.raw').decode()
 assert store.read('original/qualification/clippy-version/stdout.raw').startswith(b'clippy 0.1.95 ')
 assert set(toolchains)=={'rustc','cargo','rustdoc','cargo-clippy','clippy-driver','cargo-fmt','rustfmt'}
 temporary=store.doc('original/qualification/temporary-directory.json')
 assert temporary==build['temporary_directory'] and set(temporary)=={'before','after','entries_after','removed'}
 assert temporary['before']==temporary['after'] and temporary['entries_after']==[] and temporary['removed'] is True
 td=temporary['before'];assert set(td)=={'path','device','inode','uid','mode'} and re.fullmatch(r'/tmp/se-[a-z0-9_]{8}',td['path'])
 assert exact_int(td['mode'])==0o700 and exact_int(td['uid'])>=0 and exact_int(td['device'])>=0 and exact_int(td['inode'])>0
 b=store.session['rust_bin'];cargo=b+'/cargo';manifest=repo+'/trillionnium/Cargo.toml';target=root+'/cargo-target'
 env={'PATH':b+':/usr/bin:/bin','HOME':store.session['home'],'CARGO_HOME':store.session['cargo_home'],'CARGO_NET_OFFLINE':'true','RUSTUP_TOOLCHAIN':'1.95.0-x86_64-unknown-linux-gnu','RUSTC':b+'/rustc','CARGO':cargo,'RUSTDOC':b+'/rustdoc','CARGO_BUILD_JOBS':'4','PYTHONDONTWRITEBYTECODE':'1','GIT_TERMINAL_PROMPT':'0','GIT_NO_LAZY_FETCH':'1','TMPDIR':td['path']}
 aenv=env|{'TRNM_SETTLEMENT_ORIGINAL':repo+'/trillionnium/crates/trnm-service-settlement/src','TRNM_SETTLEMENT_ERROR_TABLE':root+'/adapter/errors.json'}
 a=build['original_adapter_binary'];test=build['original_test_binary']
 for row,is_test in [(a,False),(test,True)]:
  event=row['cargo_event'];p=event['profile'];assert p=={'opt_level':'0','debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':is_test}
  assert event['fresh'] is False and event['executable']==row['path']
  assert store.actual(row['path'])=={k:row[k] for k in ['bytes','sha256']}
  assert store.actual_bytes(row['path'])[:4]==b'\x7fELF'
 assert a['path']==target+'/debug/settlement-reference'
 assert store.identity('original/adapter/reference.rs')['sha256']=='3ca09c00c6f061a09417e44a33ad68748322f6bc75301c460deb64938cab7182'
 for name,v in build['adapter_inputs'].items():assert store.actual(name)==v,name
 assert set(build['adapter_inputs'])=={root+'/adapter/'+x for x in ['Cargo.toml','Cargo.lock','reference.rs','errors.json']}
 assert store.read('original/adapter/reference.rs')==store.read('source/hia/platform/service_settlement/qualification/reference.rs')
 assert store.read('original/adapter/Cargo.lock')==store.read('source/hia/platform/service_settlement/qualification/reference.Cargo.lock')
 assert store.read('original/adapter/errors.json')==store.read('source/hia/platform/service_settlement/qualification/errors.json')
 expected_manifest=store.read('source/hia/platform/service_settlement/qualification/reference.Cargo.toml').replace(b'"@TASK_KERNEL@"',json.dumps(repo+'/trillionnium/crates/trnm-task-kernel').encode())
 assert store.read('original/adapter/Cargo.toml')==expected_manifest
 child='store::snapshot_tests::process_death_child_fixture';parent='store::snapshot_tests::process_death_preserves_fail_closed_and_exact_retry'
 specs={
 'head':(30,['/usr/bin/git','rev-parse','HEAD'],repo,env),
 'tree':(30,['/usr/bin/git','rev-parse','HEAD^{tree}'],repo,env),
 'preflight':(30,['bash','scripts/project-preflight.sh','--audit'],repo,env),
 'original-tree':(30,['/usr/bin/git','ls-tree','-rz','--full-tree',build['source_head'],'trillionnium'],repo,env),
 'rustc-version':(30,[b+'/rustc','-Vv'],root,env),
 'clippy-version':(30,[b+'/cargo-clippy','--version'],root,env),
 'locked-cargo-graph':(90,[cargo,'metadata','--offline','--locked','--all-features','--format-version','1','--manifest-path',manifest],repo,env),
 'original-all':(240,[cargo,'test','--offline','--locked','--no-fail-fast','--manifest-path',manifest,'-p','trnm-service-settlement','--all-features','--target-dir',target,'--message-format=json','--','--test-threads=1'],repo,env),
 'original-roster':(60,[test['path'],'--list'],repo,env),
 'nested-process-death':(60,[test['path'],'--exact',parent,'--nocapture','--test-threads=1'],repo,env),
 'strict-clippy':(240,[b+'/cargo-clippy','clippy','--offline','--locked','--manifest-path',manifest,'-p','trnm-service-settlement','--all-targets','--all-features','--target-dir',target,'--','-D','warnings'],repo,env),
 'formatting':(60,[cargo,'fmt','--manifest-path',manifest,'-p','trnm-service-settlement','--','--check'],repo,env),
 'adapter-locked-graph':(90,[cargo,'metadata','--offline','--locked','--format-version','1','--manifest-path',root+'/adapter/Cargo.toml'],root+'/adapter',aenv),
 'adapter-locked-build':(240,[cargo,'build','--offline','--locked','--manifest-path',root+'/adapter/Cargo.toml','--target-dir',target,'--message-format=json'],root+'/adapter',aenv)}
 assert [x['name'] for x in build['stages']]==list(specs)
 for name,(seconds,argv,cwd,e) in specs.items():
  r,_=owned_process(store,'original/qualification/'+name,seconds,argv,cwd,e)
  matches=[x for x in build['stages'] if x['name']==name];assert len(matches)==1 and {k:v for k,v in matches[0].items() if k!='name'}==r
 raw=store.read('original/qualification/original-all/stdout.raw').decode()
 summaries=[tuple(map(int,x)) for x in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',raw)]
 assert summaries==[(136,0,1,0,0),(2,0,0,0,0)]
 ignored=re.findall(r'^test (.+?) \.\.\. ignored, (.+)$',raw,re.MULTILINE)
 assert ignored==[(child,'child fixture explicitly executed by process_death_preserves_fail_closed_and_exact_retry')]
 roster=store.read('original/qualification/original-roster/stdout.raw').decode()
 names=[x[:-6] for x in roster.splitlines() if x.endswith(': test')]
 assert len(names)==len(set(names))==137 and child in names and parent in names
 summary=store.doc('original/qualification/retained-test-summary.json')
 assert summary['names']==names and summary['only_ignored_entry_is_parent_invoked_child']==child
 nested=store.read('original/qualification/nested-process-death/stdout.raw')+store.read('original/qualification/nested-process-death/stderr.raw')
 for phase in ['before-commit','after-commit']:assert nested.count(('process-death stage '+phase+': supported contract verified').encode())==1
 assert b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 136 filtered out' in nested
 for name,row in [('original-all',test),('adapter-locked-build',a)]:
  events=[document(l) for l in store.read('original/qualification/'+name+'/stdout.raw').splitlines() if l.startswith(b'{')]
  assert events.count(row['cargo_event'])==1
 generator=validate_generator_binding(store,build,gen,root,groot)
 assert gen['fixture_count']==320 and gen['operations']==2636 and gen['exact_json_bytes_equal'] is True
 verify_registry(store,build,registry)
 return {'status':'INDEPENDENT_FULL_FRESH_ORIGINAL_PROVENANCE_PASS','fresh_current_execution':True,'original_source_map':SOURCE_MAP,'source_files':1700,'registry_inputs':len(registry),'original_outer_tests':136,'nested_fixture_types':1,'nested_actual_phases':2,'compile_fail_doctests':2,'generator':generator,'fresh_report_identity':store.identity('generator/qualification/report.json'),'fresh_build_report_identity':store.identity('original/qualification/report.json'),'fresh_fixture_raw':STDOUT_ID},store
