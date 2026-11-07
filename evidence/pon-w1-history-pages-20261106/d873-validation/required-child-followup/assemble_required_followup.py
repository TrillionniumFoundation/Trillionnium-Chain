#!/usr/bin/env python3
"""Retain existing required-job child evidence without running any test."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path('/workspace/scratch/a66f84888260')
REPO = ROOT / 'chain-integration'
SRC = ROOT / 'hosted-d873'
FILES = ROOT / 'evidence-publication/followup-files'
PREFIX = 'evidence/pon-w1-history-pages-20261106/d873-validation/required-child-followup'
OUT = FILES / PREFIX
HEAD = 'd87357de197db5ff750d08c96d52432e5d22a0b4'
PARENT = '8f9d9d950d97487f56d692dfb16509034315ead3'
BASE_TREE = 'c0cb8751eb81d7a08818a49cf2172ff4d43b1980'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str, env=None) -> str:
    return subprocess.check_output(['git', *args], cwd=REPO, text=True, env=env).strip()


def main() -> None:
    assert git('rev-parse', 'HEAD') == HEAD and not git('status', '--porcelain')
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ['secondary-child-failure-audit.json', 'required-wrapper-scope-audit.json']:
        (OUT / name).write_bytes((SRC / name).read_bytes())
    audit = json.loads((OUT / 'secondary-child-failure-audit.json').read_text())
    assert audit['assessment']['exact_acceptance_error'] == 'CONFIRMATION_TARGET'
    assert audit['assessment']['native_invocations_returned_exit_zero'] == 20
    assert audit['assessment']['pressure_confirmed_jobs'] == 0
    assert audit['qualification'] is False
    buf = io.BytesIO()
    members = []
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as archive:
        def add(name: str, raw: bytes, source: str) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(raw))
            members.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw), 'source': source})

        for job in sorted(audit['jobs'], key=lambda row: row['artifact_id']):
            artifact_id = job['artifact_id']
            zpath = SRC / 'secondary-children' / f'artifact-{artifact_id}.zip'
            assert sha(zpath.read_bytes()) == job['zip_sha256']
            minimal = zpath.with_name(f'artifact-{artifact_id}-minimal')
            for path in sorted(minimal.rglob('*')):
                if path.is_file():
                    add(f'artifact-{artifact_id}/' + str(path.relative_to(minimal)), path.read_bytes(), str(path.relative_to(ROOT)))
            with zipfile.ZipFile(zpath) as z:
                reports = [n for n in z.namelist() if n.endswith('/report.json')]
                assert len(reports) == 3
                for name in sorted(reports):
                    raw = z.read(name)
                    json.loads(raw)
                    add(f'artifact-{artifact_id}/' + name, raw, str(zpath.relative_to(ROOT)) + '!' + name)
    packed = gzip.compress(buf.getvalue(), compresslevel=6, mtime=0)
    (OUT / 'original-child-reports-and-receipts.tar.gz').write_bytes(packed)
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as archive:
        assert len(archive.getmembers()) == len(members)
        for member in members:
            raw = archive.extractfile(member['path']).read()
            assert len(raw) == member['bytes'] and sha(raw) == member['sha256']
    (OUT / 'archive-members.json').write_text(json.dumps({
        'schema': 'required-child-original-members-v1', 'archive_sha256': sha(packed),
        'archive_bytes': len(packed), 'member_bytes': sum(x['bytes'] for x in members),
        'all_original_bytes_preserved': True, 'members': members,
    }, indent=2) + '\n')

    rows = []
    for job in sorted(audit['jobs'], key=lambda row: row['job_id']):
        normal, pressure = job['confirmation']['phases']
        assert normal['workers'] == 0 and pressure['workers'] == 16
        assert pressure['requested_window_ns'] == 4_000_000_000
        assert pressure['client_confirmed_transactions'] == 0
        assert pressure['verification_errors'] == ['PUBLIC_REQUEST_DEADLINE']
        rows.append(f"| [{job['job_name']}]({job['job_url']}) | [{job['artifact_id']}]({job['artifact_url']}) | {normal['client_confirmation_latency_ns']/1e9:.9f} s; 1 confirmed | 7 ACKs, 1 successful History; 0 confirmed |")
    prose = '''# Follow-up: four required-job failures resolved to CONFIRMATION_TARGET

The earlier 01:43:12 UTC CI snapshot retained only the Host wrapper's child-exit
failure. Reading the four original uploaded artifacts resolves that cause gap:
all four fail the unchanged finite-window business confirmation acceptance stage
with `CONFIRMATION_TARGET`. Their pressure reports record
`PUBLIC_REQUEST_DEADLINE` during independent replay. This is additional readback
of existing jobs; no tests, reruns, cancellations or new jobs were initiated.

## Actual child outcomes

| Job | Original artifact | No-attack control | Original four-second pressure |
| --- | --- | --- | --- |
''' + '\n'.join(rows) + '''

Every job's five named Rust invocations returned exit 0, with no subprocess
timeout. The original `service_report` and `sustained_report` acceptance stages
passed. The only failed report acceptance stage is `confirmation_report`.
All Host error lists are empty; source identities and retained binary hashes
match before/after and preparation receipts.

The last Rust test asserts protocol/accounting invariants and records the finite
business outcome separately. Cargo exit 0 therefore does not imply business
confirmation. The original runner correctly rejects the failed business outcome
after reading its report. The 90-second subprocess limit does not extend the
original four-second business window.

Head jobs test `d87357de197db5ff750d08c96d52432e5d22a0b4`; the prospective job
tests `6f03626963aa2145b53acce3f5f9254e7ff81410`, bound to base a3e9002 and
candidate d87357d. All four trees are `323d99df3155b2242aec70c1cc11215bbade2807`.
This is PR #753 into the #688 integration branch, not main qualification.

## Scope and retained originals

[secondary-child-failure-audit.json](secondary-child-failure-audit.json) records
each artifact's digest, source/binary receipts, Host result, five actual test
terminals and report acceptance results. All four original ZIPs were accessible
and matched their GitHub artifact digests.

[required-wrapper-scope-audit.json](required-wrapper-scope-audit.json) binds the
four workflow steps to the five exact tests and sequential report validators.
Ten complete relevant source files have identical Git blobs at 0ca272d,
a3e9002 and d87357d. The two actually imported reader functions also retain
their original text. Production code changes remain separately attributable.
For protocol-contract, this wrapper is the first command under `set -e`;
its failure does not imply later protocol/formal checks executed.

[original-child-reports-and-receipts.tar.gz](original-child-reports-and-receipts.tar.gz)
preserves all twelve complete raw service/sustained/confirmation reports and
the original minimal child/Host/source receipts without reserialization.
[archive-members.json](archive-members.json) records every member's exact
SHA-256 and byte count; decompression and member hashes were verified locally.
The original four artifact URLs above retain their full ZIPs, including binaries
and other outputs not copied into this archive.

This evidence supersedes only the earlier uncertainty about those four child
failures. It does not certify all native correctness suites, make a causal
cross-runner performance claim, or close the original availability gate.
The tested d873 source remains unchanged and the PR remains a draft.
'''
    (OUT / 'README.md').write_text(prose)
    (OUT / 'assemble_required_followup.py').write_bytes(Path(__file__).read_bytes())
    retained = []
    for path in sorted(OUT.iterdir()):
        if path.name == 'retention-manifest.json':
            continue
        raw = path.read_bytes()
        retained.append({'path': path.name, 'bytes': len(raw), 'sha256': sha(raw)})
    (OUT / 'retention-manifest.json').write_text(json.dumps({
        'schema': 'required-child-followup-retention-v1', 'tested_commit': HEAD,
        'prior_evidence_commit': PARENT, 'source_unchanged': True,
        'tests_executed_by_collection': False, 'qualification': False,
        'archive_members_verified': len(members), 'files': retained,
    }, indent=2) + '\n')
    env = dict(os.environ, GIT_INDEX_FILE=str(ROOT / 'evidence-publication/followup-index'))
    git('read-tree', BASE_TREE, env=env)
    entries = []
    for path in sorted(OUT.iterdir()):
        relative = str(path.relative_to(FILES))
        blob = git('hash-object', '-w', str(path))
        git('update-index', '--add', '--cacheinfo', f'100644,{blob},{relative}', env=env)
        raw = path.read_bytes()
        entries.append({'path': relative, 'mode': '100644', 'type': 'blob', 'sha': blob,
                        'bytes': len(raw), 'sha256': sha(raw), 'local_path': str(path)})
    git('diff', '--cached', '--check', BASE_TREE, env=env)
    changes = git('diff', '--cached', '--name-status', BASE_TREE, env=env).splitlines()
    assert len(changes) == len(entries) and all(x.startswith('A\t' + PREFIX + '/') for x in changes)
    tree = git('write-tree', env=env)
    assert git('rev-parse', 'HEAD') == HEAD and not git('status', '--porcelain')
    manifest = {'schema': 'required-child-evidence-publication-v1', 'parent': PARENT,
                'base_tree': BASE_TREE, 'tree': tree,
                'evidence_branch': 'docs/chain-w1-history-outcomes-20261107-a66f',
                'original_gate_passed': False, 'tested_worktree_unchanged': True,
                'entries': entries, 'archive_members': len(members)}
    (ROOT / 'evidence-publication/followup-publish-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'files': len(entries), 'bytes': sum(e['bytes'] for e in entries),
                      'tree': tree, 'parent': PARENT, 'archive_members': len(members),
                      'retained_original_report_bytes': sum(x['bytes'] for x in members),
                      'original_gate_passed': False}))


if __name__ == '__main__':
    main()
