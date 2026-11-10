#!/usr/bin/env python3
"""Verify retained bytes and original source identities; never grant PQ qualification."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import zipfile

IMPLEMENTATION = '81f89b01b1fe0bb23cb8b885a30bb8fcb11a8455'
IMPLEMENTATION_TREE = 'a3899186dc25721f3bc04d1e043b3ce979119de8'
CANDIDATE = '8079efb7bbc121688f15c4327b2bc286e26845c3'
MERGE = '8d57aa4add724ba8d70e4c96717911869aa4680c'
BASE = 'ac8501a85a770ba34f34e1bed507ca747e5c3f8d'
EVIDENCE = 'evidence/pq-cell-retained-key-20261110'
MAX_BYTES = 64 * 1024 * 1024
SHARDS = {
    '13735539478': ('runtime', 'prospective-merge'),
    '13736460191': ('runtime', 'head'),
    '13737136810': ('quality', 'head'),
    '13737676372': ('quality', 'prospective-merge'),
}
COMMANDS = {
    'runtime': 'c2369d386856e03a4e6566b4232ccdfb43f2672ca49d2a7070ebd2bfe7d0e9ae',
    'quality': '5f46e68f4d31ddd3b4a5ead0217bcad2faae3b7acd457ee3ed5f8e8b57968f7a',
}
HISTORICAL = {
    'tests/fixtures/ci/cell-current-api-readback-v2-66b7064.log':
        '43059fa21c3542eff4f0c4aeb3552207847a8b483d214ce1e1514f79a4c09553',
    'tests/fixtures/ci/cell-current-api-readback-v2-66b7064.json':
        'd4576c31378caf413a8aa6104697d9c5251d696f14475275447f0cd1241ca250',
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field: ' + key)
        result[key] = value
    return result


def parse(raw: bytes):
    return json.loads(raw, object_pairs_hook=unique)


def regular(path: Path, maximum: int = MAX_BYTES) -> bytes:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), 'not a regular file: ' + str(path))
    require(metadata.st_size <= maximum, 'oversize file: ' + str(path))
    raw = path.read_bytes()
    require(len(raw) == metadata.st_size, 'changed file size: ' + str(path))
    return raw


def relative(root: Path, name: str) -> Path:
    require(isinstance(name, str) and name != '', 'invalid relative path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'noncanonical relative path: ' + name)
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), 'escaping relative path: ' + name)
    for parent in target.parents:
        if parent == root:
            break
        require(not parent.is_symlink(), 'symlinked parent: ' + str(parent))
    return target


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=root)


def verify(root: Path, candidate: str, downloads: Path | None):
    evidence = relative(root, EVIDENCE)
    manifest = parse(regular(evidence / 'manifest.json'))
    require(manifest['self_excluded'] is True, 'manifest must explicitly exclude itself')
    require(len(manifest['files']) == 58, 'expected exactly 58 listed evidence files')
    names = set()
    for item in manifest['files']:
        name = item['path']
        require(name not in names and name != 'manifest.json', 'duplicate/self manifest entry')
        names.add(name)
        raw = regular(relative(evidence, name))
        require(len(raw) == item['bytes'] and sha(raw) == item['sha256'],
                'manifest byte/hash mismatch: ' + name)
    actual = {str(path.relative_to(evidence)) for path in evidence.rglob('*') if path.is_file()}
    require(actual == names | {'manifest.json'}, 'evidence files differ from complete manifest')

    index = parse(regular(evidence / 'archive-index.json'))
    selected = index['selected_retained_members']
    selected_names = set()
    gzip_count = 0
    for item in selected:
        name = item['path']
        require(name not in selected_names, 'duplicate retained archive path: ' + name)
        selected_names.add(name)
        require(name in names, 'retained archive path absent from manifest: ' + name)
        raw = regular(relative(evidence, name))
        if 'gzip_sha256' in item:
            require(len(raw) == item['gzip_bytes'] and sha(raw) == item['gzip_sha256'],
                    'gzip container mismatch: ' + name)
            require(0 <= item['original_bytes'] <= MAX_BYTES, 'oversize declared decompression')
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                original = stream.read(item['original_bytes'] + 1)
            require(len(original) == item['original_bytes']
                    and sha(original) == item['original_sha256'],
                    'gzip original-byte mismatch: ' + name)
            gzip_count += 1
        else:
            require(len(raw) == item['bytes'] and sha(raw) == item['sha256'],
                    'retained archive member mismatch: ' + name)

    archives = []
    if downloads is not None:
        for archive in index['archives']:
            raw = regular(relative(downloads, archive['download_name']))
            require(len(raw) == archive['bytes'] and sha(raw) == archive['sha256'],
                    'downloaded archive mismatch: ' + archive['download_name'])
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                infos = [info for info in z.infolist() if not info.is_dir()]
                require(len({info.filename for info in infos}) == len(infos),
                        'duplicate ZIP member')
                expected = {item['name']: item for item in archive['members']}
                require(len(expected) == len(archive['members'])
                        and set(expected) == {info.filename for info in infos},
                        'ZIP member set mismatch')
                for info in infos:
                    item = expected[info.filename]
                    require(info.file_size == item['bytes'] and info.file_size <= MAX_BYTES,
                            'ZIP member size mismatch')
                    member = z.read(info)
                    require(len(member) == item['bytes'] and sha(member) == item['sha256'],
                            'ZIP member hash mismatch: ' + info.filename)
            archives.append({'name': archive['download_name'], 'sha256': sha(raw),
                             'members_verified': len(infos)})

    shard_records = []
    for artifact, (shard, kind) in SHARDS.items():
        folder = evidence / 'hosted' / artifact
        receipt = parse(regular(folder / 'rust-shard.json'))
        command = regular(folder / 'rust-shard.sh')
        require(receipt['schema'] == 'trnm-rust-baseline-shard-v1', 'wrong shard schema')
        require(receipt['shard'] == shard and receipt['status'] == 'passed'
                and type(receipt['exit_code']) is int and receipt['exit_code'] == 0,
                'unconfirmed original shard result: ' + artifact)
        require(sha(command) == receipt['command_sha256'] == COMMANDS[shard],
                'original shard command mismatch: ' + artifact)
        require(receipt['before'] == receipt['after'], 'original shard source endpoints differ')
        source = receipt['before']
        require(source['kind'] == kind and source['candidate'] == IMPLEMENTATION
                and source['tested_tree'] == IMPLEMENTATION_TREE
                and source['tracked_worktree_verified'] is True
                and source['tracked_entries'] == 27655 and source['tracked_bytes'] == 2527824853,
                'original shard source mismatch: ' + artifact)
        require(source['tested_commit'] == (IMPLEMENTATION if kind == 'head' else MERGE),
                'original shard tested identity mismatch')
        require(source['base'] == (None if kind == 'head' else BASE)
                and source['prospective_merge'] == (None if kind == 'head' else MERGE),
                'original shard merge context mismatch')
        require(receipt['run'] == {'GITHUB_RUN_ID': '42744039935', 'GITHUB_RUN_ATTEMPT': '1'},
                'original shard run mismatch')
        shard_records.append({'artifact': artifact, 'shard': shard, 'source_kind': kind,
                              'tested_commit': source['tested_commit'],
                              'command_sha256': sha(command), 'status': 'passed', 'exit_code': 0,
                              'source_endpoints_equal': True})

    fixture = regular(root / 'tests/fixtures/ci/cell-current-api-readback-v3-81f89b0.log')
    doclog = gzip.decompress(regular(evidence / 'hosted/mldsa-head/cell-current-api.log.gz'))
    require(fixture == doclog and len(fixture) == 1159
            and sha(fixture) == 'e5e18bd4a6acc39700ca5d85b4e1ec60c9c424f97405fd71ecc9dfde7d388721',
            'current fixture differs from retained actual doctest log')
    docreceipt = parse(regular(evidence / 'hosted/mldsa-head/cell-current-api.json'))
    require(docreceipt['status'] == 'command_succeeded' and docreceipt['exit_code'] == 0
            and docreceipt['before'] == docreceipt['after']
            and docreceipt['before']['tested_commit'] == IMPLEMENTATION
            and docreceipt['log_sha256'] == sha(fixture) and docreceipt['log_bytes'] == len(fixture),
            'current fixture original command identity mismatch')
    historical = []
    for name, digest in HISTORICAL.items():
        raw = regular(relative(root, name))
        require(raw == git(root, 'show', IMPLEMENTATION + ':' + name) and sha(raw) == digest,
                'historical fixture changed: ' + name)
        historical.append({'path': name, 'sha256': digest, 'unchanged_from_implementation': True})

    actual_head = git(root, 'rev-parse', 'HEAD').decode().strip()
    require(actual_head == candidate, 'checkout HEAD is not the requested candidate')
    runtime_tree = git(root, 'rev-parse', candidate + ':trillionnium').decode().strip()
    original_tree = git(root, 'rev-parse', IMPLEMENTATION + ':trillionnium').decode().strip()
    require(runtime_tree == original_tree, 'runtime Git subtree changed')
    return {
        'schema': 'trnm-pq-cell-evidence-independent-verification-v1',
        'verified_utc': datetime.now(timezone.utc).isoformat(), 'result': 'PASS',
        'reviewed_candidate': candidate, 'original_executed_source': IMPLEMENTATION,
        'original_executed_tree': IMPLEMENTATION_TREE,
        'evidence_manifest_listed_files': len(names), 'self_excluded_manifest_files': 1,
        'evidence_total_files': len(actual), 'evidence_manifest_sha256': sha(regular(evidence/'manifest.json')),
        'archive_selected_members_verified': len(selected_names), 'gzip_originals_verified': gzip_count,
        'original_download_archives_verified': archives,
        'original_downloads_checked': downloads is not None,
        'rust_shards': shard_records,
        'current_fixture_matches_actual_retained_log': True,
        'historical_fixtures': historical,
        'runtime_git_subtree_unchanged': True, 'runtime_git_subtree': runtime_tree,
        'runtime_current_working_bytes_verified': False,
        'harness_summary_counts_aggregated': False, 'whole_workspace_test_total': None,
        'independent_execution_authentication': False,
        'scope': 'retained-byte integrity and recorded source consistency only',
        'actual_lifetime_failure_bound': None, 'composition_coverage_proved': False,
        'whole_chain_pq_qualified': False, 'production_activation': False,
        'qualification': 'HOLD_NO_GO',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--downloads', type=Path)
    parser.add_argument('--candidate', default=CANDIDATE)
    args = parser.parse_args()
    root = args.root.resolve()
    require(args.output.is_absolute() and not args.output.resolve().is_relative_to(root),
            'report must be outside the source repository')
    try:
        report = verify(root, args.candidate, args.downloads)
        code = 0
    except (ValueError, OSError, KeyError, json.JSONDecodeError,
            subprocess.SubprocessError, gzip.BadGzipFile, zipfile.BadZipFile) as error:
        report = {'schema': 'trnm-pq-cell-evidence-independent-verification-v1',
                  'result': 'FAIL', 'reason': str(error),
                  'whole_chain_pq_qualified': False, 'production_activation': False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'report': str(args.output),
                      'reason': report.get('reason')}, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
