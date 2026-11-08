#!/usr/bin/env python3
"""Prepare public evidence archives outside the frozen repository; no publication."""
from datetime import datetime,timezone
import hashlib,importlib.util,json,lzma,os,re,shutil,stat,subprocess,tarfile,time,traceback
from pathlib import Path
ROOT=Path('/home/qian-qi/work/trnm-quantum-four-gates-20261107-c9b4')
REPO=ROOT/'repo'; RUN=ROOT/'validation-competing-a56889a'
OUT=ROOT/'prepared-competing-evidence'
HEAD='a56889a54aac5f14141bb45fb602141dd6a37645'
EXPECTED={'head':HEAD,'tree':'b4e64c82d2646b9f32124feb510edc3349a375d0','tracked_files':11030,'inventory_sha256':'a1f7fa55fccc079391b874a86b2bdd5ae667615777aa305ad355d55b66c99424'}
DRIVER=ROOT/'run_competing_gates_validation.py'
DRIVER_SHA='48a259891b7da79f845cf578f71c035679c73844d6c3ddc3610352f22e2f9f39'
ENVFILE=ROOT/'build-environment-normal-loader-fresh-target.json'
ENV_SHA='e997245b8004f49da3cf8f1805934a0ddcdb910a205034f9382a2c4e3adeb4a4'
FUZZ=ROOT/'fuzz-validation-a56889a-20261107'
NODE=ROOT/'supplemental-validation/whole-node-a56889a-20261107'
READBACK=ROOT/'readback-competing-a56889a-v2'
MAX_PART=8*1024*1024
EXPECTED_ENV_KEYS=set('CARGO_BUILD_JOBS CARGO_HOME CARGO_INCREMENTAL CARGO_NET_OFFLINE CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG CARGO_TARGET_DIR GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_TERMINAL_PROMPT HOME LANG LC_ALL LD_LIBRARY_PATH OPENSSL_CONF OPENSSL_DIR OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR OPENSSL_MODULES OPENSSL_STATIC PATH PYTHONDONTWRITEBYTECODE PYTHONUNBUFFERED RUSTC RUSTDOC RUST_TEST_THREADS TRNM_PQ_OPENSSL TRNM_PQ_OPENSSL_SHA256 TRNM_PQ_OPENSSL_VERSION TRNM_RESEARCH_PYTHON'.split())
NATIVE_TESTS={
 'native-base-export':'quantum_native_bridge_tests::export_source_bound_native_dag_fixture',
 'native-base-replay':'quantum_native_bridge_tests::replay_source_bound_native_search_samples',
 'native-competition-export':'quantum_native_bridge_tests::competition::export_source_bound_native_competition_fixture',
 'native-competition-replay':'quantum_native_bridge_tests::competition::replay_source_bound_native_competition_samples'}
def need(x,m):
 if not x: raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  while block:=f.read(1024*1024): h.update(block)
 return h.hexdigest()
def utc(): return datetime.now(timezone.utc).isoformat()
def load(p):
 def pairs(rows):
  d={}
  for k,v in rows: need(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
  return d
 return json.loads(Path(p).read_bytes(),object_pairs_hook=pairs)
def write(p,v):
 with p.open('x') as f:
  json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def public_member(p):
 status=p.lstat()
 need(stat.S_ISREG(status.st_mode) and not p.is_symlink() and status.st_nlink==1,'NONREGULAR_OR_LINKED_INPUT:'+str(p))
 rel=p.relative_to(ROOT).as_posix()
 need(all(v not in ('','..','.','.git','registry','target','cargo-home') for v in rel.split('/')),'FORBIDDEN_INPUT_PATH:'+rel)
 need(p.name not in ('.env','credentials','credentials.json','credentials.toml','id_rsa','id_ed25519'),'CREDENTIAL_FILENAME:'+rel)
 with p.open('rb') as f: first=f.read(4)
 need(first!=b'\x7fELF','ELF_BINARY_FORBIDDEN:'+rel)
 return {'path':rel,'size_bytes':status.st_size,'sha256':sha(p),'source_mode':oct(stat.S_IMODE(status.st_mode))}
def files_under(directory):
 need(directory.is_dir() and not directory.is_symlink(),'INPUT_DIRECTORY_REQUIRED:'+str(directory))
 values=[]
 for p in directory.rglob('*'):
  need(not p.is_symlink(),'INPUT_SYMLINK:'+str(p))
  if p.is_file(): values.append(p)
  else: need(p.is_dir(),'SPECIAL_INPUT:'+str(p))
 return sorted(values,key=lambda p:p.relative_to(ROOT).as_posix())
def verify_declared_inventory(directory):
 value=load(directory/'artifact-inventory.json')
 rows=value['artifacts'] if isinstance(value,dict) else value
 for row in rows:
  path=directory/row['path']
  need(path.resolve().is_relative_to(directory.resolve()),'INVENTORY_ESCAPE')
  expected=row.get('size_bytes',row.get('bytes'))
  need(path.is_file() and path.stat().st_size==expected and sha(path)==row['sha256'],'DECLARED_ARTIFACT_CHANGED:'+str(path))
 return {'path':str((directory/'artifact-inventory.json').relative_to(ROOT)),
         'sha256':sha(directory/'artifact-inventory.json'),'members_verified':len(rows)}
def archive(name,paths):
 need(len(paths)==len(set(paths)),'DUPLICATE_ARCHIVE_INPUT')
 members=[public_member(p) for p in sorted(paths,key=lambda p:p.relative_to(ROOT).as_posix())]
 path=OUT/name
 with path.open('xb') as raw:
  with lzma.LZMAFile(raw,'w',preset=3) as compressed:
   with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as tar:
    for row in members:
     src=ROOT/row['path'];need(sha(src)==row['sha256'] and src.stat().st_size==row['size_bytes'],'INPUT_CHANGED_BEFORE_ARCHIVE')
     info=tarfile.TarInfo(row['path']);info.size=row['size_bytes'];info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
     with src.open('rb') as f: tar.addfile(info,f)
  raw.flush();os.fsync(raw.fileno())
 # Read every member back; do not trust merely successful compression.
 with tarfile.open(path,'r:xz') as tar:
  observed=[]
  for member in tar:
   need(member.isfile() and member.mode==0o644,'UNEXPECTED_ARCHIVE_MEMBER')
   stream=tar.extractfile(member);h=hashlib.sha256();size=0
   while block:=stream.read(1024*1024):h.update(block);size+=len(block)
   observed.append({'path':member.name,'size_bytes':size,'sha256':h.hexdigest()})
 need(observed==[{k:r[k] for k in ('path','size_bytes','sha256')} for r in members],'ARCHIVE_READBACK_MISMATCH')
 for row in members:need(sha(ROOT/row['path'])==row['sha256'],'INPUT_CHANGED_AFTER_ARCHIVE')
 full_hash=sha(path);full_size=path.stat().st_size;parts=[]
 if full_size>MAX_PART:
  whole=hashlib.sha256()
  with path.open('rb') as f:
   index=1
   while block:=f.read(MAX_PART):
    part=OUT/(name+'.part'+str(index).zfill(4))
    with part.open('xb') as p:p.write(block);p.flush();os.fsync(p.fileno())
    parts.append({'file':part.name,'size_bytes':len(block),'sha256':sha(part)})
    whole.update(part.read_bytes());index+=1
  need(whole.hexdigest()==full_hash and sum(r['size_bytes'] for r in parts)==full_size,'PART_REASSEMBLY')
  path.unlink()
 else:parts=[{'file':path.name,'size_bytes':full_size,'sha256':full_hash}]
 record={'schema':'trnm-public-evidence-archive-index-v1','archive':name,'archive_sha256':full_hash,
         'archive_size_bytes':full_size,'compression':'xz preset 3','tar_mode_and_timestamps_normalized':True,
         'member_count':len(members),'uncompressed_file_bytes':sum(r['size_bytes'] for r in members),'members':members,
         'single_file':full_size<=MAX_PART,'maximum_distribution_part_bytes':MAX_PART,'parts':parts,
         'reassembly':'concatenate parts in listed order; resulting bytes must equal archive_sha256',
         'every_member_read_back_and_hashed':True,'source_inputs_unchanged_after_archive':True}
 write(OUT/(name+'.index.json'),record)
 return {'index_file':name+'.index.json','index_sha256':sha(OUT/(name+'.index.json')),
         **{k:record[k] for k in ('archive','archive_sha256','archive_size_bytes','member_count','uncompressed_file_bytes','single_file','parts')}}
def main():
 need(sha(DRIVER)==DRIVER_SHA and sha(ENVFILE)==ENV_SHA,'FROZEN_DRIVER_OR_ENV')
 spec=importlib.util.spec_from_file_location('frozen_guard',DRIVER);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 before=mod.source(REPO,HEAD);need(before==EXPECTED,'SOURCE_BEFORE')
 need(not subprocess.check_output(['git','ls-files','--others','-z'],cwd=REPO),'EXTRA_SOURCE_BEFORE')
 failed_stage=ROOT/'prepared-competing-evidence-attempt1-failed'
 if OUT.exists():
  need(set(p.name for p in OUT.iterdir())=={'preparation-script.py','preparation-failure.json'},'UNEXPECTED_EXISTING_STAGE')
  need(sha(OUT/'preparation-failure.json')=='4ce774b173c4c9fb1adef2fd549b060b1b3f205d3448b912e1e98b2fa4095a58','FAILED_STAGE_IDENTITY')
  need(not failed_stage.exists(),'FAILED_STAGE_DESTINATION_EXISTS')
  OUT.rename(failed_stage)
 OUT.mkdir(exist_ok=False)
 started=time.monotonic()
 try:
  shutil.copyfile(__file__,OUT/'preparation-script.py')
  result=load(RUN/'result.json');commands=load(RUN/'commands.json')
  declaration=load(RUN/'declaration.json')
  need(set(declaration['effective_environment'])==EXPECTED_ENV_KEYS,'UNREVIEWED_ENVIRONMENT_KEYS')
  need(declaration['effective_environment']['TRNM_PQ_OPENSSL_SHA256'] and sha(ENVFILE)==ENV_SHA,'ENVIRONMENT_BINDING')
  need(result['status']=='FAIL' and result['commands']==47 and len(commands)==47,'ORIGINAL_RESULT_EXPECTATION')
  need(result['failed_required_commands']==['whole-node-lib'] and result['incomplete_optional_commands']==['fuzz-offline-full-metadata'],'UNRECONCILED_FAILURES')
  need(result['source_before']==result['source_after']==EXPECTED and result['abort'] is None and result['skipped']==[],'ORIGINAL_COMPLETION_SOURCE')
  byname={r['name']:r for r in commands};need(len(byname)==47,'DUPLICATE_COMMAND_NAME')
  python_groups=[{'name':r['name'],'count':r['python_ran_tests'][0],'exit_code':r['exit_code'],'pass':r['pass']} for r in commands if r.get('python_ran_tests')]
  need(all(len(byname[r['name']]['python_ran_tests'])==1 and r['pass'] is True and r['exit_code']==0 for r in python_groups),'PYTHON_SUITE_FAILURE')
  need(sum(r['count'] for r in python_groups)==696,'PYTHON_COUNT')
  native=[]
  for name,test in NATIVE_TESTS.items():
   r=byname[name];need(r['pass'] is True and r['exit_code']==0 and '--exact' in r['argv'] and '--ignored' in r['argv'],'NAMED_NATIVE_FAILURE')
   need(r['rust_summaries']==[{'outcome':'ok','passed':1,'failed':0,'ignored':0,'measured':0,'filtered_out':1286}],'NAMED_NATIVE_COUNTS')
   need(any(c['kind']=='exact-rust-test-inventory' and c['expected']==c['actual']==[test] and c['pass'] is True for c in r['checks']),'NAMED_NATIVE_IDENTITY')
   native.append({'command':name,'test':test,'passed':1,'failed':0,'explicit_ignored_selection':True,'log_sha256':r['log_sha256']})
  fuzz=load(FUZZ/'result.json');node=load(NODE/'result.json');readback=load(READBACK/'result.json')
  need(fuzz['status']=='PASS' and fuzz['head']==HEAD and fuzz['source_final']==EXPECTED and fuzz['online_offline_full_metadata_equal'] is True,'FUZZ_SUPPLEMENT')
  need(fuzz['all_resolved_archives_match_lockfile_checksums'] is True and fuzz['packages']==149 and fuzz['registry_packages']==136,'FUZZ_GRAPH')
  need(node['status']=='PASS' and node['source']==EXPECTED and node['outer_passed']==1250 and node['outer_failed']==0 and node['outer_ignored']==37 and node['outer_total']==1287,'NODE_SUPPLEMENT')
  need(node['original_driver_pass'] is False and node['whole_test_suite_rerun'] is False and node['raw_inputs_unchanged'] is True,'NODE_ORIGINAL_PRESERVATION')
  need(type(readback) is list and [r['name'] for r in readback]==['native-competition-summary','machine-cache-summary'],'READBACK_COMMAND_INVENTORY')
  for rb in readback:
   need(rb['exit_code']==0,'READBACK_COMMAND_FAILURE')
   need(sha(READBACK/(rb['name']+'.json'))==rb['stdout_sha256'],'READBACK_STDOUT_BINDING')
   need(sha(READBACK/(rb['name']+'.stderr'))==rb['stderr_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','READBACK_STDERR_BINDING')
  checks=[verify_declared_inventory(p) for p in (RUN,FUZZ,NODE)]
  copies={
   'original-driver-result.json':RUN/'result.json',
   'fuzz-graph-result.json':FUZZ/'result.json',
   'whole-node-inventory-result.json':NODE/'result.json',
   'native-test-elf.json':RUN/'native-test-elf.json',
   'full-source-identity.json':RUN/'sources/final-retained.json',
   'native-competition-summary.json':READBACK/'native-competition-summary.json',
   'machine-cache-summary.json':READBACK/'machine-cache-summary.json'}
  copied=[]
  for name,src in copies.items():
   pub=public_member(src);dest=OUT/name;shutil.copyfile(src,dest)
   need(sha(dest)==pub['sha256'],'DIRECT_COPY_HASH')
   copied.append({'file':name,'source':pub['path'],'size_bytes':dest.stat().st_size,'sha256':sha(dest)})
  frozen=archive('frozen-validation.tar.xz',files_under(RUN))
  supplemental_paths=[]
  for p in (FUZZ,NODE,READBACK,ROOT/'continuation-review-materials'):supplemental_paths.extend(files_under(p))
  supplemental_paths.extend([DRIVER,ROOT/'fuzz_cache_supplement_a56889a.py'])
  supplemental_paths.extend(files_under(failed_stage))
  supplemental=archive('supplemental-validation.tar.xz',supplemental_paths)
  after=mod.source(REPO,HEAD)
  need(after==before==EXPECTED and not subprocess.check_output(['git','ls-files','--others','-z'],cwd=REPO),'SOURCE_AFTER')
  for row in copied:need(sha(ROOT/row['source'])==row['sha256'],'DIRECT_SOURCE_CHANGED')
  need(sha(DRIVER)==DRIVER_SHA and sha(ENVFILE)==ENV_SHA,'ENV_OR_DRIVER_CHANGED')
  combined={'schema':'trnm-competing-gates-combined-validation-v1','status':'PASS_WITH_RETAINED_ORIGINAL_FAILURES',
   'validation_scope':'Frozen-source execution receipts plus independently checked supplemental resolution; not general quantum security',
   'source':EXPECTED,'source_guard_before':before,'source_guard_after':after,
   'original_driver':{'status':'FAIL','result_sha256':sha(RUN/'result.json'),'commands':47,
      'failed_required_commands':result['failed_required_commands'],'incomplete_optional_commands':result['incomplete_optional_commands'],
      'original_results_logs_and_failure_flags_preserved':True},
   'python':{'executed_test_count':696,'all_selected_suites_passed':True,'counts_are_execution_totals_not_unique_test_definitions':True,'groups':python_groups},
   'whole_node_outer':{k:node[k] for k in ('outer_passed','outer_failed','outer_ignored','outer_total','outer_filtered_out','outer_measured','nested_invocations','nested_success_summaries','original_log_sha256','original_row_sha256','elf_identity')},
   'explicit_ignored_native_tests':{'executed':4,'passed':4,'failed':0,'tests':native},
   'targeted_release_owner':{name:byname[name]['rust_summaries'] for name in ('release-owner-root-six','release-owner-sealed-seven')},
   'resolved_original_failures':[
    {'command':'whole-node-lib','original_process_exit_code':0,'original_driver_pass':False,
     'cause':'Wrapper demanded exactly one Rust summary although successful nested subprocesses produced three additional summaries.',
     'resolution':'Same-ELF --list and --ignored --list, full original outer inventory and exact source-aware nested-output recognition passed; full suite was not rerun.',
     'supplement_file':'whole-node-inventory-result.json','supplement_sha256':sha(NODE/'result.json')},
    {'command':'fuzz-offline-full-metadata','original_process_exit_code':101,
     'cause':'Original Cargo cache lacked locked arbitrary 1.4.2, jobserver 0.1.35 and libfuzzer-sys 0.4.10 dependencies.',
     'resolution':'Copied checksum-verified existing public archives into a separate Cargo home; locked online metadata and then offline full metadata returned identical bytes, all 136 registry checksums verified.',
     'supplement_file':'fuzz-graph-result.json','supplement_sha256':sha(FUZZ/'result.json'),
     'full_metadata_raw_sha256':fuzz['commands'][0]['stdout_sha256'],'full_metadata_canonical_sha256':fuzz['graph_canonical_sha256'],
     'packages':149,'registry_packages':136,'resolve_nodes':149}],
   'native_and_machine_readback':{'status':'READBACK_COMMANDS_PASSED','readback_result_sha256':sha(READBACK/'result.json'),'commands':readback,
      'native_summary_file':'native-competition-summary.json','machine_summary_file':'machine-cache-summary.json',
      'model_clock_and_actual_CPU_receipts_remain_distinct':True},
   'archives':[frozen,supplemental],'direct_copies':copied,
   'all_general_quantum_gates':'HOLD',
   'general_quantum_gates':{
    'complete_machine_cost_and_error_accounting':{'status':'HOLD','remaining':'Real hardware calibration, compiled physical layout and service measurements, energy and capital costs are missing.'},
    'minimum_legal_implementation_and_amortization':{'status':'HOLD','remaining':'Finite constructed implementations and cache observations do not prove a minimum over all legal algorithms or equal complete resources.'},
    'native_quantum_adversarial_execution':{'status':'HOLD','remaining':'Actual Node/CPU admission is observed; quantum execution clocks remain modeled and no QPU execution is present.'},
    'mixed_quantum_classical_consensus_security':{'status':'HOLD','remaining':'Finite conditional actions and fixed public arrival schedules do not establish arbitrary-algorithm or long-term settlement security.'}},
   'quantum_hardware_executed':False,'physical_hardware_calibrated':False,'quantum_mining_qualified':False,'production_activation':False,
   'repository_source_modified_by_preparation':False,'original_evidence_modified_by_preparation':False,
   'git_commit_created_by_preparation':False,'github_publication_performed_by_preparation':False,
   'target_ELF_cache_or_credentials_included':False}
  write(OUT/'combined-validation.json',combined)
  write(OUT/'preparation-receipt.json',{'schema':'trnm-competing-evidence-preparation-v1','status':'PREPARED_NOT_COMMITTED_OR_PUBLISHED',
    'created_utc':utc(),'elapsed_seconds':time.monotonic()-started,'source_before':before,'source_after':after,
    'preparation_script_sha256':sha(__file__),'source_helper_sha256':DRIVER_SHA,'input_artifact_inventories_verified':checks,
    'archive_member_readback_verified':True,'direct_copy_bytes_verified':True,'original_inputs_unchanged':True,
    'credential_environment_keys_checked_against_explicit_build_only_inventory':True,
    'retained_preparation_failure':{'path':str(failed_stage.relative_to(ROOT)),'reason':'Initial preparer expected status object, but observed readback result is a two-command receipt list; fixed only external preparer','sha256':sha(failed_stage/'preparation-failure.json')},
    'quantum_hardware_executed':False,'quantum_mining_qualified':False})
  rows=[{'file':p.name,'size_bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.iterdir()) if p.is_file()]
  write(OUT/'prepared-file-index.json',{'schema':'trnm-prepared-public-evidence-files-v1','source_head':HEAD,'files':rows,
     'index_excludes_itself':True,'maximum_archive_part_bytes':MAX_PART})
  print(json.dumps({'status':'PREPARED_NOT_COMMITTED_OR_PUBLISHED','directory':str(OUT),'files':rows,
    'prepared_file_index_sha256':sha(OUT/'prepared-file-index.json'),'archives':[frozen,supplemental]},sort_keys=True),flush=True)
  return 0
 except BaseException as e:
  write(OUT/'preparation-failure.json',{'status':'FAILED_NOT_COMMITTED_OR_PUBLISHED','error':repr(e),'traceback':traceback.format_exc(),'original_inputs_modified':False})
  raise
if __name__=='__main__':raise SystemExit(main())
