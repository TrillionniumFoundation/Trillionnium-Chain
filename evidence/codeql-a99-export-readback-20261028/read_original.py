import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
with urllib.request.urlopen(sys.argv[1], timeout=30) as response:
    raw = response.read(280065)
assert len(raw) == 280064 and hashlib.sha256(raw).hexdigest() == '6e6f9b6545f288dd90a5c83d1158a96d1342da0e593689e39cfb1de23c3c818f'
(ROOT/'original.zip').write_bytes(raw)
z = zipfile.ZipFile(io.BytesIO(raw))
names = z.namelist()
assert len(names) == len(set(names)) == 145
members = []
for name in names:
    path = PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts
    data = z.read(name)
    members.append(dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
indexed = {r['path']:r for r in members}
outer = json.loads(z.read('sha256.json'))
assert set(outer) == {n for n in names if PurePosixPath(n).name != 'sha256.json'}
for name, digest in outer.items():
    assert indexed[name]['sha256'] == digest
inner = json.loads(z.read('analysis/sha256.json'))
assert set(inner) == {n.removeprefix('analysis/') for n in names if n.startswith('analysis/') and n != 'analysis/sha256.json'}
for name, digest in inner.items():
    assert indexed['analysis/'+name]['sha256'] == digest
before = json.loads(z.read('exporter-source-before.json'))
assert before == json.loads(z.read('exporter-source-after.json'))
assert before['tested_commit'] == 'a99ef8e333b6f1b7486b33e820464cf824fec273' and before['tracked_worktree_verified'] is True
result = json.loads(z.read('analysis/result.json'))
polls = []
for name in names:
    if name.startswith('analysis/poll-') and name.endswith('/selection.json'):
        selected = json.loads(z.read(name))
        polls.append(dict(path=name, ready=selected['ready'],
            checks=[{k:r.get(k) for k in ('id','head_sha','status','conclusion','output')} for r in selected['checks']],
            analyses=[{k:r.get(k) for k in ('id','ref','commit_sha','category','created_at','results_count','rules_count','error')} for r in selected['analyses']]))
value = dict(schema='codeql-a99-complete-original-independent-readback-v1',
    artifact_id=12788613489, run_id=40623893027, archive_bytes=len(raw),
    archive_sha256=hashlib.sha256(raw).hexdigest(), all_145_members_read_and_hashed=True,
    outer_manifest_entries=len(outer), inner_manifest_entries=len(inner),
    both_exact_manifest_sets_and_hashes_verified=True, original_zip_saved=True,
    source_before_equals_after=before, result=result, poll_selections=sorted(polls,key=lambda p:p['path']), members=members)
(ROOT/'independent-readback.json').write_text(json.dumps(value,indent=2)+'\n')
(ROOT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:value[k] for k in ('artifact_id','archive_bytes','archive_sha256','outer_manifest_entries','inner_manifest_entries')}))
print(json.dumps(result,indent=2))
print(json.dumps({'polls':[{'path':p['path'],'ready':p['ready'],'checks':[(c['id'],c['status'],c['conclusion']) for c in p['checks']],'categories':[a['category'] for a in p['analyses']]} for p in value['poll_selections']]},indent=2))
