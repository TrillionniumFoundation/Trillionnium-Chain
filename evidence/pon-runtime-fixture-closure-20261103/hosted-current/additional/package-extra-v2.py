#!/usr/bin/env python3
"""Freeze only new C1 runtime/C2 ARM Node/C1-C2 CPU evidence; no native execution."""
from pathlib import Path, PurePosixPath
import collections
import datetime
import gzip
import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import zipfile

BASE = Path('/workspace/scratch/b5a148b09b11')
PUB = BASE / 'next-validation/hosted-evidence-publication'
OUT = PUB / 'extra-stage-v2'
REPO = BASE / 'chain-six-axis'
PREFIX = 'evidence/pon-runtime-fixture-closure-20261103/hosted-current/'
C1 = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
C2 = 'b4bdf142f513081715ecc8d1f9674291e85302cc'
HOSTED = {'c5dd': BASE / 'next-hosted/c5dd7c-review', 'b4bdf': BASE / 'next-hosted/b4bdf-review'}
PREP = BASE / 'next-hosted/new-candidate-preparation'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def stable_read(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), ('regular original required', str(path))
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), str(path)
    return raw


def fingerprint(path):
    raw = stable_read(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def check_expected(raw, expected):
    assert sha(raw) == expected['sha256'], ('SHA256 changed', expected)
    if 'bytes' in expected:
        assert len(raw) == expected['bytes'], ('bytes changed', expected)


def protected_snapshot():
    result = []
    for name, count in [('frozen-manifest.json', 92), ('additional-upload-v1/frozen-manifest.json', 22)]:
        path = PUB / name
        raw = stable_read(path)
        data = json.loads(raw)
        assert data['target_prefix'] == PREFIX and data['file_count'] == len(data['files']) == count
        for row in data['files']:
            original = stable_read(Path(row['source_path']))
            check_expected(original, row)
            assert git_blob(original) == row['git_blob']
        result.append({'manifest': fingerprint(path), 'file_count': count,
                       'total_bytes': sum(row['bytes'] for row in data['files']), 'files': data['files']})
    return result


assert not OUT.exists(), 'new stage must not overwrite an existing freeze'
protected_before = protected_snapshot()
old_by_relative = {}
old_by_hash = collections.defaultdict(list)
for batch in protected_before:
    for row in batch['files']:
        assert row['relative_path'] not in old_by_relative
        old_by_relative[row['relative_path']] = row
        old_by_hash[row['sha256']].append(row)
assert len(old_by_relative) == 114
plan = {}
source_to_relative = {}


def add(path, relative, group, expected=None):
    path = Path(path)
    parts = PurePosixPath(relative)
    assert not parts.is_absolute() and '..' not in parts.parts
    assert not path.name.lower().startswith('readme'), 'README belongs to root'
    assert path.suffix.lower() not in {'.zip', '.sqlite', '.db', '.elf', '.pnk'}, str(path)
    raw = stable_read(path)
    assert not raw.startswith(b'\x7fELF'), str(path)
    if expected is not None:
        check_expected(raw, expected)
    assert relative not in old_by_relative, ('cannot duplicate or rewrite initial114', relative)
    if relative in plan:
        assert plan[relative]['source'] == str(path) and plan[relative]['sha256'] == sha(raw)
        return
    assert str(path) not in source_to_relative, ('duplicate input copy', str(path))
    plan[relative] = {'source': str(path), 'path': relative, 'target_path': PREFIX + relative,
                      'bytes': len(raw), 'sha256': sha(raw), 'git_blob': git_blob(raw),
                      'group': group, 'original_bytes_unmodified': True}
    source_to_relative[str(path)] = relative


def load_handoff(path, expected_sha, cohort):
    raw = stable_read(path)
    assert sha(raw) == expected_sha
    data = json.loads(raw)
    actual = data.get('candidate', data.get('cohort', {}).get('head'))
    assert actual == cohort
    return data


cpu_counts = {}
for key, head, expected_sha, expected_count in [
    ('c5dd', C1, '60072e4859aa64fa888c8f5074c7e774e0ac48bb09b64309bbd0fb5c173c5ae3', 19),
    ('b4bdf', C2, 'c5876f5069fb8ae8858c711d3a68fb5b9de25646a0f39a45c4d57de8fa533b13', 14),
]:
    folder = BASE / ('next-validation/' + key + '-workspace-cpu-four-lane-readback')
    handoff = load_handoff(folder / 'handoff.json', expected_sha, head)
    names = {row['file'] for row in handoff['files']} | {'handoff.json'}
    assert len(names) == expected_count
    assert names == {path.name for path in folder.iterdir() if path.is_file()}
    add(folder / 'handoff.json', key + '/workspace-cpu/handoff.json', key + '-workspace-cpu')
    for row in handoff['files']:
        assert Path(row['file']).name == row['file']
        add(folder / row['file'], key + '/workspace-cpu/' + row['file'], key + '-workspace-cpu', row)
    cpu_counts[key] = expected_count
assert sum(cpu_counts.values()) == 33

pq_path = HOSTED['b4bdf'] / 'pq-original-node-four-lane-handoff.json'
pq = load_handoff(pq_path, '23ee7f6e447a06d1d1da5c8335285df0f6274c7f15184f0f5941400ac81188a5', C2)
assert len(pq['records']) == 4 and all('/pq-node-arm64-' in row['path'] for row in pq['records'])
add(pq_path, 'b4bdf/' + pq_path.name, 'b4bdf-node-arm')
for row in [pq['aggregate'], *pq['records'], pq['metadata']]:
    path = Path(row['path'])
    add(path, 'b4bdf/' + path.name, 'b4bdf-node-arm', row)
add(Path(pq['reader']['path']), 'readers/aggregate-pq-four-lane.py', 'bounded-readers', pq['reader'])
for name in ['read-pq-node-lane.py', 'collect_readback.py']:
    add(PREP / name, 'readers/' + name, 'bounded-readers')
add(HOSTED['b4bdf'] / '20261103T233756374Z-pq-final-artifacts.json',
    'b4bdf/20261103T233756374Z-pq-final-artifacts.json', 'b4bdf-node-arm')
for aid in [13279503756, 13279562975]:
    add(HOSTED['b4bdf'] / f'{aid}-download-receipt.json', f'b4bdf/{aid}-download-receipt.json', 'b4bdf-node-arm')

runtime_path = HOSTED['c5dd'] / 'runtime-two-lane-terminal-handoff.json'
runtime = load_handoff(runtime_path, '279e35677b852eee1c3ff8559930261b69840591d441e83025a67b1e3ed6b940', C1)
add(runtime_path, 'c5dd/' + runtime_path.name, 'c5dd-runtime')
for row in [runtime['aggregate'], *runtime['records'], runtime['metadata'], runtime['reader'], *runtime['reader_refusal_records']]:
    path = Path(row['path'])
    add(path, 'c5dd/' + path.name, 'c5dd-runtime', row)
for name in ['runtime-aggregate-reader-initial.py', 'runtime-aggregate-reader-initial-reconstruction.json']:
    add(HOSTED['c5dd'] / name, 'c5dd/' + name, 'c5dd-runtime')
for name in ['read-runtime-lane.py', 'collector-plan.json']:
    add(PREP / name, 'readers/' + name, 'bounded-readers')
for original, relative in [
    ('scripts/ci/run_public_fixture_native.py', 'run_public_fixture_native.py'),
    ('trillionnium/Cargo.toml', 'Cargo.toml'),
]:
    add(HOSTED['c5dd'] / 'source-c5dd7c' / original, 'c5dd/runtime-source/' + relative, 'c5dd-runtime-source')
add(HOSTED['c5dd'] / '20261103T233941745Z-baseline-runtime-artifacts.json',
    'c5dd/20261103T233941745Z-baseline-runtime-artifacts.json', 'c5dd-runtime')
for aid in [13280768301, 13280868776]:
    add(HOSTED['c5dd'] / f'{aid}-download-receipt.json', f'c5dd/{aid}-download-receipt.json', 'c5dd-runtime')
add(Path(__file__).resolve(), 'additional/package-extra-v2.py', 'packaging')

git_cache = {}
embedded_by_hash = collections.defaultdict(list)
original_artifacts = {}
gzip_checks = []


def original_metadata_file(key, name):
    folder = HOSTED[key]
    if name.startswith('source-binding-receipt-1-'):
        binding = json.loads(stable_read(folder / 'source-binding.json'))
        return Path(binding['candidate_remote_receipt']['file'] if key == 'c5dd' else binding['receipts'][0]['path'])
    if name.startswith('source-binding-receipt-2-'):
        binding = json.loads(stable_read(folder / 'source-binding.json'))
        return Path(binding['actual_merge_remote_receipt_from_root']['file'] if key == 'c5dd' else binding['receipts'][1]['path'])
    assert Path(name).name == name
    return folder / name


def original_git_bytes(commit, path):
    assert commit in {C1, C2} and '..' not in PurePosixPath(path).parts
    key = (commit, path)
    if key not in git_cache:
        git_cache[key] = subprocess.check_output(['git', '-C', str(REPO), 'show', commit + ':' + path])
    return git_cache[key]


for relative, row in sorted(plan.items()):
    if not relative.endswith('.json.gz'):
        continue
    compressed = stable_read(Path(row['source']))
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        decoded = stream.read(256 * 1024 * 1024 + 1)
    assert len(decoded) <= 256 * 1024 * 1024
    data = json.loads(decoded)
    schema = data['schema']
    records = data.get('records', data.get('selected_records'))
    assert isinstance(records, list) and records
    archive_path = None
    archive = None
    if schema == 'trnm-workspace-cpu-original-text-records-v1':
        key = relative.split('/')[0]
        archive_path = HOSTED[key] / data['zip_filename']
        archive_expected = {'bytes': data['zip_bytes'], 'sha256': data['zip_sha256']}
    elif schema == 'exact-candidate-artifact-selected-originals-v1':
        archive_path = Path(data['artifact_file'])
        archive_expected = {'bytes': data['artifact_bytes'], 'sha256': data['artifact_sha256']}
    elif schema == 'exact-candidate-runtime-lane-original-records-v1':
        lane = 'head' if data['source'] == C1 else 'merge'
        archive_path = HOSTED['c5dd'] / f"c5dd7c-runtime-{lane}-{data['artifact_id']}.zip"
        receipt = json.loads(stable_read(HOSTED['c5dd'] / f"{data['artifact_id']}-download-receipt.json"))
        archive_expected = {'bytes': receipt['actual_bytes'], 'sha256': data['artifact_sha256']}
    else:
        assert schema in {'trnm-workspace-cpu-source-and-metadata-text-records-v1', 'c1-runtime-two-lane-complete-original-job-logs-v1'}, schema
    if archive_path is not None:
        original_archive = stable_read(archive_path)
        check_expected(original_archive, archive_expected)
        archive = zipfile.ZipFile(io.BytesIO(original_archive))
        assert len(archive.namelist()) == len(set(archive.namelist()))
        original_artifacts[str(archive_path)] = {**fingerprint(archive_path), 'copied': False,
                                               'reason': 'Original ZIP retained outside stage; selected text bytes compared directly.'}
    original_bytes = 0
    for record in records:
        raw = record['text'].encode('utf-8')
        check_expected(raw, record)
        original_bytes += len(raw)
        name = record.get('member', record.get('path', record.get('file')))
        origin = None
        if archive is not None:
            assert '..' not in PurePosixPath(name).parts and not PurePosixPath(name).is_absolute()
            original = archive.read(name)
            origin = str(archive_path) + '!' + name
        elif schema == 'trnm-workspace-cpu-source-and-metadata-text-records-v1':
            key = relative.split('/')[0]
            if name.startswith('source/'):
                source_path = name.removeprefix('source/')
                original = original_git_bytes(data['exact_source_commit'], source_path)
                origin = 'git:' + data['exact_source_commit'] + ':' + source_path
            else:
                assert name.startswith('original-metadata/')
                original_path = original_metadata_file(key, name.removeprefix('original-metadata/'))
                original = stable_read(original_path)
                origin = str(original_path)
        else:
            original_path = HOSTED['c5dd'] / name
            original = stable_read(original_path)
            origin = str(original_path)
        assert raw == original, (relative, name)
        embedded_by_hash[sha(raw)].append({'bundle': relative, 'record': name, 'original': origin, 'bytes': len(raw)})
    if archive is not None:
        archive.close()
    gzip_checks.append({'path': relative, 'schema': schema, 'compressed_bytes': len(compressed),
                        'compressed_sha256': sha(compressed), 'decoded_bytes': len(decoded),
                        'decoded_sha256': sha(decoded), 'record_count': len(records),
                        'original_text_bytes': original_bytes,
                        'every_embedded_utf8_length_and_sha256_verified': True,
                        'every_embedded_text_compared_byte_for_byte_to_original': True})
assert len(gzip_checks) == 15
assert sum(row['record_count'] for row in gzip_checks) == 3246

planned_by_hash = collections.defaultdict(list)
for row in plan.values():
    planned_by_hash[row['sha256']].append(row)
references = {}


def inspect_references(value, origin, pointer=''):
    if isinstance(value, dict):
        path = value.get('path', value.get('file'))
        expected_sha = value.get('sha256')
        if isinstance(path, str) and path.startswith('/') and isinstance(expected_sha, str) and re.fullmatch('[0-9a-f]{64}', expected_sha):
            key = (path, expected_sha)
            if key not in references:
                item = {'original_path': path, 'sha256': expected_sha, 'references': []}
                if 'bytes' in value:
                    item['bytes'] = value['bytes']
                matching_plan = [row for row in planned_by_hash.get(expected_sha, []) if Path(row['source']).name == Path(path).name]
                matching_old = [row for row in old_by_hash.get(expected_sha, []) if Path(row['relative_path']).name == Path(path).name]
                if path in source_to_relative and plan[source_to_relative[path]]['sha256'] == expected_sha:
                    item.update(resolution='included_in_v2', target_path=PREFIX + source_to_relative[path])
                elif matching_plan:
                    item.update(resolution='included_identical_bytes_in_v2', target_path=matching_plan[0]['target_path'])
                elif matching_old:
                    item.update(resolution='existing_immutable_initial114', target_path=matching_old[0]['path'])
                elif embedded_by_hash.get(expected_sha):
                    item.update(resolution='embedded_original_in_v2_gzip', embedded=embedded_by_hash[expected_sha])
                elif path.startswith(str(BASE / 'next-hosted') + '/') or path.startswith(str(BASE / 'next-validation') + '/'):
                    original = Path(path)
                    if original.is_file():
                        check_expected(stable_read(original), value)
                        item.update(resolution='external_local_original_verified_not_copied', reason='Outside bounded new evidence scope.')
                    else:
                        item.update(resolution='external_original_path_unavailable', reason='Historical path is preserved; no fabricated bytes or qualification.')
                else:
                    item.update(resolution='external_hosted_or_committed_source_observation', reason='Original observation only; ELF/database/current-worktree bytes are not substituted or copied.')
                references[key] = item
            references[key]['references'].append({'file': origin, 'json_pointer': pointer})
        for key, child in value.items():
            if key not in {'text', 'content'}:
                inspect_references(child, origin, pointer + '/' + str(key).replace('~', '~0').replace('/', '~1'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            inspect_references(child, origin, pointer + '/' + str(index))


for relative, row in plan.items():
    if relative.endswith('.json'):
        inspect_references(json.loads(stable_read(Path(row['source']))), relative)

OUT.mkdir(exist_ok=False)
for relative, row in sorted(plan.items()):
    source = Path(row['source'])
    raw = stable_read(source)
    check_expected(raw, row)
    target = OUT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(raw)
    assert stable_read(target) == raw == stable_read(source)

protected_after = protected_snapshot()
assert protected_after == protected_before, 'initial92/additional22 changed during packaging'
group_counts = dict(collections.Counter(row['group'] for row in plan.values()))
public_dependencies = sorted(references.values(), key=lambda row: (row['original_path'], row['sha256']))
manifest = {
    'schema': 'trnm-additional-hosted-evidence-package-v2',
    'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'output': str(OUT), 'target_prefix': PREFIX,
    'cohorts': [{'head': C1, 'actual_merge': '7a3e125cb343bd85fb806aba87a21f99eac082de', 'tree': '30f59a8ec2abdc269bf91e228c58206b23add43d'},
                {'head': C2, 'actual_merge': 'd9efb0f3bc4dfdbfd8fcb609375dfeb852407bfb', 'tree': '3e141fb9bcec9bf2a49d55647f46f12bd3ca28bb'}],
    'original_file_copies': [plan[key] for key in sorted(plan)],
    'files': [{key: row[key] for key in ['path', 'bytes', 'sha256', 'git_blob']} for row in [plan[key] for key in sorted(plan)]],
    'file_count_before_manifest_and_verification': len(plan), 'bytes_before_manifest_and_verification': sum(row['bytes'] for row in plan.values()),
    'group_file_counts': group_counts, 'cpu_handoff_file_counts': cpu_counts,
    'gzip_verification': gzip_checks, 'gzip_records_compared_to_originals': sum(row['record_count'] for row in gzip_checks),
    'original_zip_external_dependencies': sorted(original_artifacts.values(), key=lambda row: row['path']),
    'strong_reference_resolutions_and_external_dependencies': public_dependencies,
    'protected_existing_batches': [{key: batch[key] for key in ['manifest', 'file_count', 'total_bytes']} for batch in protected_before],
    'initial114_unchanged': True, 'all_new_target_paths_disjoint_from_initial114': True,
    'readme_changes': False, 'native_compilation_or_execution': False, 'new_downloads': False,
    'repo_source_index_ref_or_PR_mutations': False, 'commit_tree_or_ref_created': False,
    'scope': 'Original C1 nine-Host success with later public_submit_recovery abort; independent C2 four-lane Node aggregate with only new ARM records; all33 frozen C1/C2 CPU files. Older x64 and initial114 remain immutable external dependencies. No workspace/service-performance/other-source success is invented.',
}
manifest_path = OUT / 'additional/manifest-v2.json'
with manifest_path.open('xb') as stream:
    stream.write(encode(manifest))
verified_files = []
for path in sorted(OUT.rglob('*')):
    if path.is_file():
        raw = stable_read(path)
        relative = str(path.relative_to(OUT))
        if relative in plan:
            check_expected(raw, plan[relative])
            assert raw == stable_read(Path(plan[relative]['source']))
        verified_files.append({'path': relative, 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': git_blob(raw)})
assert {row['path'] for row in verified_files} == set(plan) | {'additional/manifest-v2.json'}
verification = {
    'schema': 'trnm-additional-hosted-evidence-verification-v2', 'status': 'PASS',
    'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'manifest': fingerprint(manifest_path), 'files_before_this_verification': verified_files,
    'file_count_before_this_verification': len(verified_files),
    'bytes_before_this_verification': sum(row['bytes'] for row in verified_files),
    'all_original_copies_byte_exact': True, 'all_source_inputs_still_match': True,
    'gzip_count': len(gzip_checks), 'gzip_original_record_count': sum(row['record_count'] for row in gzip_checks),
    'gzip_original_text_bytes': sum(row['original_text_bytes'] for row in gzip_checks),
    'every_gzip_record_sha256_length_and_original_bytes_verified': True,
    'initial114_unchanged': True, 'new_paths_disjoint': True,
    'no_zip_elf_database_or_readme_copied': True, 'native_executed': False,
    'strong_reference_count': len(public_dependencies),
    'reference_resolution_counts': dict(collections.Counter(row['resolution'] for row in public_dependencies)),
}
verification_path = OUT / 'additional/verification-v2.json'
with verification_path.open('xb') as stream:
    stream.write(encode(verification))
all_files = []
for path in sorted(OUT.rglob('*')):
    if path.is_file():
        raw = stable_read(path)
        all_files.append({'path': str(path.relative_to(OUT)), 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': git_blob(raw)})
summary = {'schema': 'trnm-additional-hosted-evidence-v2-complete-summary', 'output': str(OUT),
           'file_count': len(all_files), 'total_bytes': sum(row['bytes'] for row in all_files),
           'manifest': fingerprint(manifest_path), 'verification': fingerprint(verification_path),
           'file_set_sha256': sha(encode(all_files)), 'files': all_files,
           'initial114_unchanged': True, 'gzip_record_count': 3246, 'native_executed': False}
summary_path = PUB / 'extra-stage-v2-summary.json'
with summary_path.open('xb') as stream:
    stream.write(encode(summary))
print(json.dumps({key: value for key, value in summary.items() if key != 'files'}, indent=2))
print(json.dumps({'summary': fingerprint(summary_path), 'groups': group_counts}))
