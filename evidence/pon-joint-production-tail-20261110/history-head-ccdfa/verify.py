"""Verify retained observations without running any archived workload."""
import gzip
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sha = lambda b: hashlib.sha256(b).hexdigest()
delivery = json.loads((ROOT / 'manifest.json').read_bytes())
archive = (ROOT / 'readback.zip').read_bytes()
assert len(archive) == delivery['readback_zip_bytes'] and sha(archive) == delivery['readback_zip_sha256']
Z = zipfile.ZipFile(ROOT / 'readback.zip')
assert len(Z.infolist()) <= 100 and len(set(Z.namelist())) == len(Z.namelist())
assert sum(i.file_size for i in Z.infolist()) <= 10_000_000
for i in Z.infolist():
    assert not Path(i.filename).is_absolute() and '..' not in Path(i.filename).parts and i.file_size <= 2_000_000
packet_index = json.loads(Z.read('PACKET-MANIFEST.json'))
assert set(Z.namelist()) == {r['path'] for r in packet_index} | {'PACKET-MANIFEST.json'}
for r in packet_index:
    b = Z.read(r['path'])
    assert len(b) == r['bytes'] and sha(b) == r['sha256']
manifest = json.loads(Z.read('manifest.json'))
records = json.loads(Z.read('archive-members.json'))
assert len(records) == manifest['archive_members'] == 4140
assert len({r['name'] for r in records}) == 4140
assert sum(r['bytes'] for r in records) == manifest['expanded_bytes'] == 609881087
assert sum(r['retained'] for r in records) == manifest['retained_members']
raw = {}
for r in records:
    if not r['retained']:
        continue
    assert '..' not in Path(r['stored']).parts
    stored = Z.read(r['stored'])
    assert len(stored) == r['stored_bytes'] and sha(stored) == r['stored_sha256']
    b = gzip.decompress(stored)
    assert len(b) == r['bytes'] and sha(b) == r['sha256']
    raw[r['name']] = b
load = lambda n: json.loads(raw[n])
native = load('history-native/manifest.json')
prep = load('history-native/preparation.json')
assert native['process']['started'] and native['process']['exit_code'] == 101
assert not native['passed'] and not native['native_execution_authenticated']
assert prep['completed'] and prep['process']['exit_code'] == 0
assert native['source_before'] == native['source_after']
assert prep['source_before'] == native['source_before']
assert native['source_before']['commit'] == manifest['source']
assert native['source_before']['tree'] == manifest['tree']
assert native['binary_before'] == native['binary_after'] == prep['binary']
assert native['binary_before']['sha256'] == 'fb83ef3a63a5c81dc507992a41791c257c260514f434caaef9b836642dadf7f0'
assert sha(raw['history-native/history.log']) == native['log']['sha256']
assert sha(raw['history-native/history-resources.txt']) == native['resources']['sha256']
assert sha(raw['history-native/preparation.json']) == native['preparation_sha256']
assert sha(raw['history-native/long-history/summary.json']) == native['summary_file']['sha256']
assert sha(raw['history-native/build.jsonl']) == prep['build_log']['sha256']
events = []
for line in raw['history-native/history.log'].decode().splitlines():
    if line.startswith('{'):
        events.append(json.loads(line))
server = next(e for e in events if e.get('schema') == 'native-ancestry-public-server-exit-evidence-v1')
sync = next(e for e in events if e.get('schema') == 'native-ancestry-independent-sync-exit-evidence-v1')
loc = sync['failure_location']
assert server['configured_lifetime_seconds'] == 1800
assert server['loop_exit_before_internal_shutdown']['reason'] == 'lifetime_expired'
assert server['server_exit_ok'] and server['server_exit_error'] is None
assert loc['stage'] == 'history-rpc' and loc['completed_import_calls'] == 3463
assert loc['durable_committed_blocks'] is None and loc['activation_cursor'] is None
assert sync['sync_error'] == native['summary']['error'] == 'IO: Connection refused (os error 111)'
for name in ('inside-before', 'inside-after'):
    host = load('history-native-host/' + name + '.json')
    assert host['read_errors'] == {}
    assert host['limits'] == {'cpu.max': '25000 100000', 'cpu.max.burst': '0', 'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'}
    assert host['parent']['uid'] == 0
assert manifest['actual_joint_obligations_open'] == 13
assert manifest['qualification'] == 'HOLD_NO_GO'
assert not manifest['native_execution_by_this_readback']
assert sha(gzip.decompress(Z.read('git-test-source.rs.gz'))) == native['source_before']['test_sha256']
print(json.dumps({'retained_members_verified': manifest['retained_members'], 'original_result': 'FAILED_EXIT_101', 'failure_stage': loc['stage'], 'completed_import_call_returns': loc['completed_import_calls'], 'durable_committed_blocks': None, 'server_exit_reason': 'lifetime_expired', 'unique_causal_attribution': None, 'qualification': 'HOLD_NO_GO'}))

api = json.loads(Z.read('priority-artifacts.json'))
artifact = next(a for a in api['artifacts'] if a['id'] == manifest['artifact_id'])
assert artifact['size_in_bytes'] == manifest['archive_bytes']
assert artifact['digest'] == 'sha256:' + manifest['archive_sha256']
assert artifact['workflow_run']['head_sha'] == manifest['source']
jobs = json.loads(Z.read('priority-jobs.json'))
job = next(j for j in jobs['jobs'] if j['id'] == manifest['job_id'])
assert job['conclusion'] == 'failure' and job['run_id'] == manifest['run_id']
primary = json.loads(gzip.decompress((ROOT / 'primary-publication-unknown.json.gz').read_bytes()))
assert primary['state'] == 'UNKNOWN' and primary['job_id'] is None
assert primary['first_start_response']['isError'] and primary['identical_recovery_response']['isError']
assert primary['request']['idempotency_key'] == 'joint-history-evidence-publish-20261110-2349-8e76-v1'
original_request_payload = json.loads(primary['request']['stdin'])
assert original_request_payload['parent'] == manifest['source']
assert len(original_request_payload['files']) == 5
print('Original API metadata and complete packet hashes verified; no native workload executed.')
