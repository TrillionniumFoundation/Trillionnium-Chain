import hashlib,json,subprocess,time
from pathlib import Path
root=Path('/home/qian-qi/work/pon-five-claims-w1-artifacts-d6cb')
fixed_dir=root/'fixed-native-rebuilt-297bb40798ca'
fixed=json.loads((fixed_dir/'summary.json').read_text())
before=json.loads((root/'before-native-rustup-qualified'/'summary.json').read_text())
assert fixed['source']['head']=='297bb40798ca1b4e4a987ef00582067282cda4e9'
assert fixed['source']['tree']=='129267332b2ef87d3d66d014fddeb894faa9379f'
assert fixed['native_tests_passed'] is True and fixed['executed_native_count']==fixed['requested_native_count']==14
assert len(fixed['native_results'])==14 and all(item['exactly_one_named_native_test_passed'] for item in fixed['native_results'])
assert before['expected_original_failure_observed'] is True and before['native_exit_code']==101
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
source=Path(fixed['binary']['path'])
expected=fixed['binary']['sha256_after']
assert expected==fixed['binary']['sha256_before'] and digest(source)==expected
retained=root/'native-binaries'/('fixed-297bb40798ca-'+expected[:12]+'.elf')
copy_started=time.time()
if not retained.exists():
 subprocess.run(['cp','--reflink=auto','--sparse=always',str(source),str(retained)],check=True,timeout=300)
assert digest(source)==expected and digest(retained)==expected
before_binary=json.loads((root/'fixed-cache-recovery-297bb40798ca'/'before-elf-retention.json').read_text())
assert digest(before_binary['retained_path'])==before_binary['sha256']
retention={'schema':'trnm-node-native-binary-retention-v1','source_subject':fixed['source'],'before_binary':before_binary,'fixed_binary':{'source_path':str(source),'retained_path':str(retained),'bytes':retained.stat().st_size,'sha256':expected,'copy_started_unix':copy_started,'copy_verified_unix':time.time(),'include_elf_in_git':False},'live_proc_image_observation':False,'binary_binding':'Direct subprocess argv plus file SHA256 before/after. No /proc executable-image observation was collected.'}
(root/'native-binary-retention.json').write_text(json.dumps(retention,indent=2)+'\n')
attempts=[
 {'directory':'before-native','outcome':'diagnostic expected native failure; non-absolute RUSTC made SQLite build UNQUALIFIED','native_exit_code':101,'native_functions_executed':1,'case_scope':'first Legacy/public_order=false case only'},
 {'directory':'before-native-qualified','outcome':'cancelled known-UNQUALIFIED loader environment before native','runtime_exit_code':-15,'native_exit_code':None,'native_functions_executed':0},
 {'directory':'before-native-rustup-qualified','outcome':'qualified expected native failure','native_exit_code':101,'native_functions_executed':1,'case_scope':'first Legacy/public_order=false case only'},
 {'directory':'fixed-native-297bb40798ca','outcome':'build refused stale cached local mvcc artifact; source T unchanged','build_exit_code':101,'native_exit_code':None,'native_functions_executed':0},
 {'directory':'fixed-native-rebuilt-297bb40798ca','outcome':'all 14 exact native controls passed after normal local-package cache invalidation','native_functions_executed':14,'local_compilation_origin_verified':True},
]
result={'schema':'trnm-submit-ancestry-artifact-index-v1','root':str(root),'fixed_source':fixed['source'],'before_source':before['source'],'native_process_image_observation':False,'binary_retention':retention,'attempts':attempts,'git_files':[],'local_only_files':[],'index_excludes_itself':True}
index_path=root/'artifact-index.json'
for path in sorted(root.rglob('*')):
 if not path.is_file() or path==index_path:continue
 relative=path.relative_to(root)
 entry={'relative_path':str(relative),'path':str(path),'bytes':path.stat().st_size,'sha256':digest(path)}
 if relative.parts[0]=='native-binaries':
  entry['exclude_from_git']=True
  result['local_only_files'].append(entry)
 else:result['git_files'].append(entry)
result['git_file_count']=len(result['git_files'])
result['git_total_bytes']=sum(item['bytes'] for item in result['git_files'])
result['local_only_file_count']=len(result['local_only_files'])
result['local_only_total_bytes']=sum(item['bytes'] for item in result['local_only_files'])
index_path.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'artifact_index':str(index_path),'bytes':index_path.stat().st_size,'sha256':digest(index_path),'git_files':result['git_file_count'],'git_bytes':result['git_total_bytes'],'local_only_files':result['local_only_files'],'fixed_native_count':14,'native_process_image_observation':False},indent=2),flush=True)
