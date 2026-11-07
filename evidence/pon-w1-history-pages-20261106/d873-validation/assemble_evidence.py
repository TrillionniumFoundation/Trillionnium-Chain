#!/usr/bin/env python3
"""Preserve existing observations; this script does not execute any test."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile


ROOT = Path('/workspace/scratch/a66f84888260')
OUT = ROOT / 'evidence-publication/files/evidence/pon-w1-history-pages-20261106/d873-validation'
HEAD = 'd87357de197db5ff750d08c96d52432e5d22a0b4'
TREE = '323d99df3155b2242aec70c1cc11215bbade2807'
MANIFEST = []


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(name: str, value: object) -> None:
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def retain(source: Path, name: str, compress: bool = False) -> None:
    raw = source.read_bytes()
    stored = gzip.compress(raw, compresslevel=6, mtime=0) if compress else raw
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(stored)
    if compress:
        assert gzip.decompress(path.read_bytes()) == raw
    MANIFEST.append({
        'stored_path': name,
        'stored_bytes': len(stored),
        'stored_sha256': digest(stored),
        'source_path': str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source),
        'source_bytes': len(raw),
        'source_sha256': digest(raw),
        'encoding': 'gzip; exact decompressed original bytes' if compress else 'original bytes',
    })


def archive(name: str, members: list[Path]) -> None:
    buf = io.BytesIO()
    inventory = []
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(set(members)):
            assert path.is_file() and not path.is_symlink()
            raw = path.read_bytes()
            relative = str(path.relative_to(ROOT))
            item = tarfile.TarInfo(relative)
            item.size = len(raw)
            item.mode = 0o644
            item.mtime = 0
            item.uid = item.gid = 0
            tar.addfile(item, io.BytesIO(raw))
            inventory.append({'path': relative, 'bytes': len(raw), 'sha256': digest(raw)})
    packed = gzip.compress(buf.getvalue(), compresslevel=6, mtime=0)
    (OUT / name).write_bytes(packed)
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as tar:
        for row in inventory:
            assert digest(tar.extractfile(row['path']).read()) == row['sha256']
    MANIFEST.append({
        'stored_path': name, 'stored_bytes': len(packed), 'stored_sha256': digest(packed),
        'encoding': 'deterministic tar.gz; member bytes unchanged', 'members': inventory,
    })


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for source, name in [
        ('hosted-d873/original-gates-d873-summary.json', 'original-gates-summary.json'),
        ('hosted-d873/pr-source-identity.json', 'prospective-source-identity.json'),
        ('integration-validation/d873-native-validation-summary.json', 'local-native-validation-summary.json'),
        ('integration-validation/committed-python-checks.json', 'local-source-validation-summary.json'),
        ('d873-local-network-evidence-audit.json', 'local-network-evidence-audit.json'),
        ('d873-host-fresh-read-options.json', 'host-fresh-read-options.json'),
        ('hosted-d873/latency-diagnosis/analyze_existing.py', 'analyze_existing.py'),
        ('hosted-d873/latency-diagnosis/analyze_server.py', 'analyze_server.py'),
    ]:
        retain(ROOT / source, name)
    for source, name in [
        ('hosted-d873/latency-diagnosis/retained-failure-latency.json', 'retained-failure-latency.json.gz'),
        ('hosted-d873/latency-diagnosis/retained-server-latency.json', 'retained-server-latency.json.gz'),
        ('integration-validation/d873-release-regressions-04-receipts/network-only-business/report.json', 'local-network-business-report.json.gz'),
    ]:
        retain(ROOT / source, name, compress=True)
    for lane, label in [('fresh-head-artifact', 'head'), ('fresh-prospective-artifact', 'prospective')]:
        for case in ['original', 'fresh']:
            retain(ROOT / f'hosted-d873/{lane}/fresh-service/{case}/report.json', f'four-second-{label}-{case}-report.json.gz', compress=True)
    old = Path('/workspace/scratch/ab286a535ac8/w1-current-0ca272/fresh-service')
    retain(old / 'manifest.json', 'original-0ca272d-manifest.json')
    for case in ['original', 'fresh']:
        retain(old / case / 'report.json', f'original-0ca272d-{case}-report.json.gz', compress=True)
    for number in [1, 2, 3]:
        retain(ROOT / f'hosted-d873/native-artifact/run-{number}-raw/report.json', f'native-run-{number}-report.json.gz', compress=True)

    local = ROOT / 'integration-validation'
    local_files = [p for p in local.iterdir() if p.is_file() and (
        p.name.startswith(('d873-', 'committed-')) or p.name in {'factorial-native-gate.log'}
    ) and p.name != 'd873-native-validation-summary.json']
    archive('local-validation-logs.tar.gz', local_files)

    hosted = ROOT / 'hosted-d873'
    hosted_files = list(hosted.glob('*-128244*.log')) + list(hosted.glob('secondary-*.log'))
    for lane in ['fresh-head-artifact', 'fresh-prospective-artifact']:
        for p in (hosted / lane).rglob('*'):
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(hosted / lane)
            if len(rel.parts) == 1 and p.suffix in {'.json', '.log'}:
                hosted_files.append(p)
            elif rel.parts[0] == 'fresh-service-host' and p.suffix in {'.json', '.log'}:
                hosted_files.append(p)
            elif rel.parts[0] == 'fresh-service' and len(rel.parts) == 2 and p.suffix in {'.json', '.log'}:
                hosted_files.append(p)
    native = hosted / 'native-artifact'
    hosted_files += [p for p in native.iterdir() if p.is_file() and p.suffix in {'.json', '.log', '.txt', '.py'}]
    hosted_files += list(native.glob('run-*-raw/campaign-failure.json'))
    archive('hosted-source-host-build-and-failure-receipts.tar.gz', hosted_files)

    artifact_rows = []
    expected = {
        'w1-fresh-service-head-d873-13553258857.zip': ('13553258857', '0da0bbe4f9192c9a3e29cbae799a33306c04eb98dcdf52a77661ed7ce3fb3ca2', '42320841942'),
        'w1-fresh-prospective-6f036269-13553858028.zip': ('13553858028', '30575cdb6d1ddbb784a9e4ee824a7e14f92edb77443f7bb768b00377b487c9f1', '42320841942'),
        'native-d873-13552933660.zip': ('13552933660', '4f1eed3889ce0815eca8d4085fe0b3d19059b066ca98c37229ed106d215ec00c', '42320841936'),
    }
    for name, (artifact_id, sha, run_id) in expected.items():
        path = hosted / name
        actual = digest(path.read_bytes())
        assert actual == sha
        members = []
        with zipfile.ZipFile(path) as z:
            for row in z.infolist():
                if row.is_dir():
                    continue
                raw = z.read(row)
                members.append({'path': row.filename, 'bytes': len(raw), 'sha256': digest(raw)})
        artifact_rows.append({
            'artifact_id': artifact_id,
            'url': f'https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run_id}/artifacts/{artifact_id}',
            'zip_filename': name, 'zip_bytes': path.stat().st_size, 'zip_sha256': actual,
            'members': members,
        })
    write_json('original-artifact-inventory.json', {
        'schema': 'w1-d873-original-artifact-inventory-v1',
        'tests_executed_by_inventory': False,
        'all_zip_and_member_bytes_read': True,
        'original_archives_retained_in_github_actions': True,
        'original_archives_copied_into_git': False,
        'artifacts': artifact_rows,
    })

    for filename, target in [
        ('d873-m06-reuse-options.json', 'm06-reuse-options.json'),
        ('hosted-d873/publication-audit.json', 'publication-audit.json'),
        ('hosted-d873/publication-audit.py', 'publication-audit.py'),
        ('hosted-d873/prospective-git-commit.json', 'prospective-git-commit.json'),
        ('hosted-d873/required-source-final-monitor.json', 'secondary-ci-observation.json'),
        ('d873-scheduling-options.json', 'scheduling-options.json'),
    ]:
        p = ROOT / filename
        if p.exists():
            retain(p, target)
    retain(Path(__file__), 'assemble_evidence.py')
    already = {row['stored_path'] for row in MANIFEST}
    for path in sorted(OUT.iterdir()):
        if path.name == 'retention-manifest.json' or path.name in already:
            continue
        raw = path.read_bytes()
        MANIFEST.append({
            'stored_path': path.name, 'stored_bytes': len(raw),
            'stored_sha256': digest(raw), 'encoding': 'locally generated documentation or audit',
        })
    write_json('retention-manifest.json', {
        'schema': 'w1-d873-evidence-retention-v1',
        'tested_commit': HEAD, 'tested_tree': TREE,
        'tests_executed_by_collection': False,
        'source_mutated_by_collection': False,
        'original_four_second_gate_passed': False,
        'original_native_campaign_passed': False,
        'compression_round_trips_verified': True,
        'archive_member_bytes_verified': True,
        'files': MANIFEST,
    })
    print(json.dumps({
        'output': str(OUT), 'files': len(list(OUT.iterdir())),
        'stored_bytes': sum(p.stat().st_size for p in OUT.iterdir() if p.is_file()),
        'retained_raw_report_bytes': sum(r.get('source_bytes', 0) for r in MANIFEST),
        'original_artifact_members': sum(len(row['members']) for row in artifact_rows),
        'original_gate_passed': False,
    }))


if __name__ == '__main__':
    main()
