import pathlib,subprocess,json,hashlib,re
p=pathlib.Path('/home/qq/work/chain-cell-capacity-dc0357-20261109')
g=lambda *a:subprocess.check_output(['git',*a],cwd=p)
source='6ea3bf3fe13d66333bba3a8c7b97e14b4319b39f'
head='06233be630f8eff6cea59cd5111e5941135a4aa5'
base='evidence/cell-capacity-release-dc0357-20261109/'
read=lambda path:g('show',head+':'+base+path)
mf=json.loads(read('file-manifest.json'))
assert mf['runtime_source_commit']==source
paths=[x['path'] for x in mf['files']]
assert len(paths)==len(set(paths))
tracked=g('ls-tree','-r','--name-only',head,'--',base).decode().splitlines()
assert {base+x for x in paths}|{base+'file-manifest.json'}==set(tracked)
for x in mf['files']:
 b=read(x['path'])
 assert len(b)==x['bytes'] and hashlib.sha256(b).hexdigest()==x['sha256'],x['path']
subtrees={}
for path in ['trillionnium','scripts','config','.github','formal']:
 a=g('rev-parse',source+':'+path).decode().strip(); b=g('rev-parse',head+':'+path).decode().strip()
 assert a==b,path
 subtrees[path]=a
index=json.loads(read('model/index.json'))
assert index['measured_code']['head']==source
assert index['result']['passed'] and index['result']['native_passed']
assert index['result']['forward_observations']==2
assert index['recovery']['restored_chunks']==95 and not index['recovery']['native_erasure_shard_recovery']
assert index['recovery']['publisher_cache_removed'] and index['recovery']['bep52_received_cache_removed'] and index['recovery']['consumer_cache_removed_before_forward']
assert index['transport']['loopback_only'] and not index['transport']['independent_failure_domains']
assert not index['execution_scope']['hepta_final_use'] and not index['execution_scope']['production_activation']
assert index['transport']['consumer_usage']['completed_fetches']==30 and index['transport']['complete_readback']
assert index['durations']['native_original_operation_elapsed_ms']==270246
assert index['original_bounds']['wall_seconds']==300
assert index['inputs']['payload_bytes']==280269602 and index['inputs']['base_weight_bytes']==269060552
probes=index['probe_results']; assert len(probes)==2 and [x['correct'] for x in probes]==[True,False]
da=read('da/cargo/da-crate.log').decode()
summaries=re.findall(r'test result:.*',da)
assert any('762 passed; 0 failed; 0 ignored' in x for x in summaries),summaries
rows=[tuple(map(int,re.search(r'(\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered',x).groups())) for x in summaries]
assert len(rows)==13 and sum(x[0] for x in rows)==812 and all(x[1:]==(0,0,0) for x in rows),rows
assert rows[0][0]==762 and sum(x[0] for x in rows[1:-1])==34 and rows[-1][0]==16
print(json.dumps({'schema':'storage-independent-original-audit.v1','audit_kind':'original evidence and Git object readback, no project runtime rerun','published_head':head,'runtime_source':source,'manifest_records_verified':len(paths),'artifact_bytes_verified':sum(x['bytes'] for x in mf['files']),'subtrees_byte_identical':subtrees,'da_original_summaries':summaries,'model_index_sha256':hashlib.sha256(read('model/index.json')).hexdigest(),'native_receipt_sha256':hashlib.sha256(read('model/native-result.json')).hexdigest(),'model_scope':{'payload_bytes':index['inputs']['payload_bytes'],'native_elapsed_ms':index['durations']['native_original_operation_elapsed_ms'],'restore_profile':index['recovery']['profile'],'forwards':len(probes),'answers_correct':sum(x['correct'] for x in probes),'loopback_only':True,'hepta_final_use':False,'native_erasure_shard_recovery':False,'production_activation':False}},sort_keys=True))
