#!/usr/bin/env python3
"""Finalize only the evidence inventory; native outcomes come from retained records."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import stat
from urllib.parse import unquote, urlsplit

ROOT = Path('/workspace/scratch/1eed767ad985/validation')
PUB = ROOT / 'throughput-publication-evidence'
PREFIX = 'evidence/pon-throughput-20261106/'
HEAD = '7586d3e209b38246402e34cf73a27aa9b907bc9c'
TREE = 'fc0e51b1235470b972de41f2d677f6d5948f4868'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'non-regular input: ' + str(path))
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


target = ROOT / 'throughput-publication-final-readback.json'
require(not target.exists(), 'immutable final readback already exists')
frozen = {}
for suffix in ['', '-2', '-3', '-4']:
    path = ROOT / ('throughput-immutable-blob-upload-plan' + suffix + '.json')
    plan = json.loads(path.read_text())
    for row in plan['files']:
        require(row['repo_path'].startswith(PREFIX), 'unexpected published prefix')
        name = row['repo_path'][len(PREFIX):]
        require(name not in frozen, 'duplicate frozen input: ' + name)
        require(Path(row['local_path']) == PUB / name, 'unexpected input location: ' + name)
        actual = identity(PUB / name)
        require(all(actual[k] == row[k] for k in actual), 'frozen input changed: ' + name)
        frozen[name] = actual

for path in PUB.rglob('*'):
    mode = path.lstat().st_mode
    require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'symlink or special evidence: ' + str(path))
files = sorted(p for p in PUB.rglob('*') if p.is_file())
names = {p.relative_to(PUB).as_posix() for p in files}
require(names == set(frozen) | {'README.md', 'manifest.json', 'SHA256SUMS'},
        'unexpected or missing evidence input')
readme = (PUB / 'README.md').read_text()
require('ROOT_FILL' not in readme and 'PENDING' not in readme, 'unfinished coordinating text')

links = []
for path in files:
    if path.suffix != '.md':
        continue
    text = re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', path.read_text(), flags=re.M | re.S)
    for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', text):
        url = urlsplit(target.strip('<>'))
        if url.scheme or url.netloc or not url.path:
            continue
        resolved = (path.parent / unquote(url.path)).resolve()
        require(resolved.is_relative_to(PUB.resolve()) and resolved.exists(), 'broken evidence link: ' + target)
        links.append({'from': path.relative_to(PUB).as_posix(), 'target': target})

native = json.loads((PUB / 'reports/rog-composed-7586d3e2/summary.json').read_text())
sampler = json.loads((PUB / 'reports/rog-composed-7586d3e2/sampler-summary.json').read_text())
static = json.loads((PUB / 'reports/static-7586d3e2/final-summary.json').read_text())
for report in [native, sampler]:
    require(report['expected_head'] == HEAD and report['finished_utc'], 'wrong or unfinished native source')
    before, after = report['source_before']['receipt'], report['source_after']['receipt']
    require(before == after and before['tested_commit'] == HEAD and before['tested_tree'] == TREE,
            'native source receipts differ')
require(static['tested_commit'] == HEAD and static['tested_tree'] == TREE, 'wrong static source')
require(sampler['sqlite']['qualified_by_this_run'] is False, 'sampler qualification drift')

payload = [dict(path=p.relative_to(PUB).as_posix(), **identity(p))
           for p in files if p.relative_to(PUB).as_posix() not in {'manifest.json', 'SHA256SUMS'}]
manifest = {
    'schema': 'trnm-throughput-publication-evidence-v2',
    'created_utc': datetime.now(timezone.utc).isoformat(),
    'scope': 'Evidence publication only; original native, CI and cost outcomes keep their measured source and attempt. No execution is inferred from packaging.',
    'validated_implementation': {'head': HEAD, 'tree': TREE,
        'ordered_parents': ['285982d78a4f62a064841cb0f106d18c865e19c5', '56897f125df27994efa1dda935f2c62eceb36de9']},
    'latest_completed_original_ci': {'candidate': '285982d78a4f62a064841cb0f106d18c865e19c5',
        'snapshot_utc': '2026-11-06T09:28:59Z', 'actual_head_and_prospective_merge_identities_retained': True},
    'source_scope': 'A later evidence-only Git commit is not a new native or performance measurement. Its exact publication identity is supplied by Git.',
    'frozen_input_files_verified_unchanged': len(frozen),
    'all_historical_failures_ignored_controls_and_source_identities_preserved': True,
    'final_static_result_as_recorded': static['result'],
    'final_native_suite_passed_as_recorded': native['passed'],
    'final_sampler_passed_as_recorded': sampler['passed'],
    'sampler_sqlite_status_as_recorded': sampler['sqlite']['status'],
    'sqlite_qualification_granted_by_packaging': False,
    'production_tps_established': False, 'production_activation': False,
    'original_campaign_acceptance': 'FAIL', 'original_f0_slo': 'FAIL_0_OF_6',
    'local_markdown_links_verified': links,
    'manifest_excludes': ['manifest.json', 'SHA256SUMS'],
    'files': payload,
}
(PUB / 'manifest.json').write_bytes(encoded(manifest))
all_without_checksums = sorted(p for p in PUB.rglob('*') if p.is_file() and p != PUB / 'SHA256SUMS')
checksums = ''.join(identity(p)['sha256'] + '  ' + p.relative_to(PUB).as_posix() + '\n' for p in all_without_checksums)
(PUB / 'SHA256SUMS').write_text(checksums)
for row in payload:
    require(identity(PUB / row['path']) == {k: row[k] for k in ['bytes', 'sha256', 'git_blob_sha']}, 'final payload changed')
for line in (PUB / 'SHA256SUMS').read_text().splitlines():
    sha, name = line.split('  ', 1)
    require(identity(PUB / name)['sha256'] == sha, 'final checksum readback differs')
receipt = {'schema': 'trnm-throughput-publication-readback-v2',
    'finished_utc': datetime.now(timezone.utc).isoformat(),
    'result': 'PASS', 'payload_files': len(payload), 'total_files': len(payload) + 2,
    'frozen_inputs': len(frozen), 'verified_markdown_links': len(links),
    'manifest': identity(PUB / 'manifest.json'), 'checksums': identity(PUB / 'SHA256SUMS'),
    'native_execution_performed_by_this_script': False,
    'publication_scope': 'evidence files plus separately reviewed sole-plan addendum'}
with target.open('xb') as stream:
    stream.write(encoded(receipt))
print(json.dumps(receipt, sort_keys=True))
