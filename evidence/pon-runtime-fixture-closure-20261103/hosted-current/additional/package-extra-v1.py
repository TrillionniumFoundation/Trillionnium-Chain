#!/usr/bin/env python3
"""Freeze additional existing records; executes no native or source gate."""
from pathlib import Path
import base64
import datetime
import gzip
import hashlib
import json
import shutil
import stat

BASE = Path('/workspace/scratch/b5a148b09b11')
OUT = BASE / 'next-validation/hosted-evidence-publication/extra-stage-v1'
COMMIT = 'b4bdf142f513081715ecc8d1f9674291e85302cc'
TREE = '3e141fb9bcec9bf2a49d55647f46f12bd3ca28bb'

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()

def stable_read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode)
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    return raw

OUT.mkdir(exist_ok=False)
records = []

def copy_original(path, relative, expected=None):
    raw = stable_read(path)
    if expected is not None:
        assert len(raw) == expected['bytes'] and digest(raw) == expected['sha256']
    target = OUT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    assert not target.exists()
    shutil.copy2(path, target)
    assert stable_read(target) == raw == stable_read(path)
    records.append({'source': str(path), 'path': relative, 'bytes': len(raw),
                    'sha256': digest(raw), 'original_bytes_unmodified': True})

proof = BASE / 'next-validation/c5dd-private-graph-proof-review'
proof_index_raw = stable_read(proof / 'artifact-index.json')
assert digest(proof_index_raw) == '4f88bd4c316c8b6d2a4b7a2ff6bc4d8040f44430ca33895372253c34dbc9f54e'
proof_files = [p for p in sorted(proof.rglob('*')) if p.is_file()]
assert len(proof_files) == 13
for path in proof_files:
    relative = str(path.relative_to(proof))
    copy_original(path, 'service-path/c5dd-private-graph-proof-review/' + relative)

handoff_path = BASE / 'next-hosted/b4bdf-review/pq-two-x64-terminal-handoff.json'
handoff_raw = stable_read(handoff_path)
assert digest(handoff_raw) == '34af53c75ed9a78bd7bfd7a32e47d6bc86e31d478067f3df1832825ed14a04c6'
handoff = json.loads(handoff_raw)
assert handoff['candidate'] == COMMIT and handoff['tree'] == TREE
copy_original(handoff_path, 'b4bdf/' + handoff_path.name)
for entry in handoff['records']:
    path = Path(entry['path'])
    copy_original(path, 'b4bdf/' + path.name, entry)

gates = BASE / ('next-validation/final-publication/committed-check-' + COMMIT)
gate_files = [p for p in sorted(gates.rglob('*')) if p.is_file()]
assert len(gate_files) == 98
gate_entries, gate_blobs = [], {}
for path in gate_files:
    raw = stable_read(path)
    h = digest(raw)
    gate_entries.append({'path': str(path.relative_to(gates)), 'bytes': len(raw), 'sha256': h, 'blob': h})
    gate_blobs.setdefault(h, {'bytes': len(raw), 'data': base64.b64encode(raw).decode()})
gate_summary = json.loads(stable_read(gates / 'summary.json'))
assert gate_summary['expected_commit'] == COMMIT and gate_summary['status'] == 'PASS'
assert gate_summary['source_before'] == gate_summary['source_after']
assert gate_summary['source_before']['tree'] == TREE and gate_summary['source_before']['status'] == ''
assert gate_summary['command_count'] == 28
assert not gate_summary['native_compilation_executed'] and not gate_summary['native_tests_executed']
archive = {'schema': 'trnm-original-exact-commit-gate-byte-records-v1',
           'commit': COMMIT, 'entries': gate_entries, 'blobs': gate_blobs}
archive_raw = gzip.compress(encode(archive), compresslevel=9, mtime=0)
archive_path = OUT / 'b4bdf/exact-commit-gates.json.gz'
archive_path.write_bytes(archive_raw)
roundtrip = json.loads(gzip.decompress(stable_read(archive_path)))
for entry in roundtrip['entries']:
    raw = base64.b64decode(roundtrip['blobs'][entry['blob']]['data'], validate=True)
    assert len(raw) == entry['bytes'] and digest(raw) == entry['sha256']
    assert raw == stable_read(gates / entry['path'])
wrapper = {'schema': 'trnm-exact-commit-gate-archive-summary-v1',
           'packaged_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'commit': COMMIT, 'tree': TREE, 'status': gate_summary['status'],
           'source': str(gates), 'original_summary': gate_summary,
           'records': len(gate_entries), 'unique_raw_blobs': len(gate_blobs),
           'archive': {'path': 'exact-commit-gates.json.gz', 'bytes': len(archive_raw), 'sha256': digest(archive_raw)},
           'native_compilation_or_execution': False,
           'all_original_file_bytes_verified_after_archive': True,
           'later_head_results_inherited': False}
(OUT / 'b4bdf/exact-commit-gates.json').write_bytes(encode(wrapper))
copy_original(Path(__file__), 'additional/package-extra-v1.py')

files = []
for path in sorted(OUT.rglob('*')):
    if path.is_file():
        raw = stable_read(path)
        files.append({'path': str(path.relative_to(OUT)), 'bytes': len(raw), 'sha256': digest(raw)})
manifest = {'schema': 'trnm-additional-hosted-evidence-package-v1',
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'candidate': COMMIT, 'original_file_copies': records, 'files': files,
            'file_count_before_this_manifest': len(files), 'bytes_before_this_manifest': sum(x['bytes'] for x in files),
            'gate_original_records': len(gate_entries), 'native_executed': False,
            'scope': 'Existing C2 two-x64 native observations, original C2 clean source gates and source-only dependency-proof review. Original 92-file snapshot is unchanged; no runtime or ARM outcome is invented.'}
manifest_path = OUT / 'additional/manifest-v1.json'
manifest_path.write_bytes(encode(manifest))
print(json.dumps({'output': str(OUT), 'files': len(files) + 1, 'bytes': sum(x['bytes'] for x in files) + manifest_path.stat().st_size,
                  'manifest_sha256': digest(stable_read(manifest_path)), 'gate_archive_sha256': digest(archive_raw),
                  'gate_records': len(gate_entries), 'gate_unique_blobs': len(gate_blobs), 'native_executed': False}))
