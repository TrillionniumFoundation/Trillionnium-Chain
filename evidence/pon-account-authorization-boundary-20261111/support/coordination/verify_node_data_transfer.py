#!/usr/bin/env python3
"""Verify and recover the independent DATA queue archive after terminal export.

The hash/length pins must be copied from the actual remote exporter. This does
not launch validation, change any original receipt, or grant qualification.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import tarfile

BASE = Path('/workspace/scratch/a4188f5c86b5')
HEAD = 'cdd984808a088e6c2e13b1e1ae6630a94d500c89'
TREE = '1ed39b6ebe55cb00c238f26f6bfc9361ab93faec'
JOB = '1a1c8ba754b-135c4-1d3'
ROOT = BASE / 'desktop-evidence' / HEAD
ARCHIVE = ROOT / 'desktop-node-retained-data-evidence-v1.tar.gz'
EXTRACTED = ROOT / 'node-retained-data-evidence-v1'
REPORT = ROOT / 'node-retained-data-transfer-verification.json'
REMOTE_ARCHIVE = '/home/qian-qi/chain-pq-a418-final-ci-tools/desktop-node-retained-data-evidence-v1.tar.gz'
IDS = ['node-retained-data-preflight', 'node-retained-data-source-before',
       'node-retained-data-all-targets', 'node-retained-data-source-after']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--expected-bytes', type=int, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args()
    for value in (args.expected_sha256, args.expected_manifest_sha256):
        require(re.fullmatch(r'[a-f0-9]{64}', value) is not None, 'invalid external SHA pin')
    require(args.expected_bytes > 0, 'invalid external byte length')
    require(not any(p.exists() for p in (ARCHIVE, EXTRACTED, REPORT)), 'create-only destination already exists')
    chunk_root = ROOT / 'node-retained-data-transfer'
    chunk_files = sorted(chunk_root.glob('chunk-*.json'), key=lambda p: int(p.stem.split('-')[-1]))
    require(bool(chunk_files), 'no original binary read chunks')
    payload = bytearray()
    chunk_provenance = []
    version = None
    for index, path in enumerate(chunk_files):
        raw = path.read_bytes()
        chunk = json.loads(raw)
        data = base64.b64decode(chunk['data_base64'], validate=True)
        require(chunk['path'] == REMOTE_ARCHIVE, 'wrong remote archive path')
        require(chunk['offset'] == len(payload), 'noncontiguous original archive chunks')
        require(chunk['next_offset'] == len(payload) + len(data), 'wrong chunk next offset')
        require(chunk['size'] == args.expected_bytes, 'remote archive length differs')
        require(sha(data) == chunk['chunk_sha256'], 'chunk SHA differs')
        if version is None:
            version = chunk['version']
        require(chunk['version'] == version, 'remote archive version changed')
        require(chunk['eof'] == (index == len(chunk_files) - 1), 'missing or premature EOF')
        chunk_provenance.append({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                                 'offset': chunk['offset'], 'next_offset': chunk['next_offset'],
                                 'chunk_sha256': chunk['chunk_sha256']})
        payload.extend(data)
    payload = bytes(payload)
    require(len(payload) == args.expected_bytes and sha(payload) == args.expected_sha256,
            'full archive differs from actual exporter pins')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            require(member.isfile() and not member.issym() and not member.islnk(), 'special archive member')
            require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == member.name,
                    'unsafe archive path')
            require(member.name not in members, 'duplicate archive member')
            data = tar.extractfile(member).read()
            require(len(data) == member.size, 'archive member length differs')
            members[member.name] = data
    manifest_bytes = members['export-manifest.json']
    require(sha(manifest_bytes) == args.expected_manifest_sha256, 'manifest external pin differs')
    manifest = json.loads(manifest_bytes)
    require(manifest['schema'] == 'desktop-primary-evidence-export-v1', 'unexpected archive schema')
    require(manifest['host'] == 'desktop' and manifest['source_commit'] == HEAD, 'source or host differs')
    require(manifest['origin_job_id'] == JOB, 'wrong original DATA native job')
    require(manifest['complete_command_ids'] == IDS, 'wrong original DATA record IDs')
    require(manifest['acceptance_granted'] is False and manifest['terminal_failures_preserved'] is True,
            'qualification/failure flags differ')
    for name in ('source_identity_before_export', 'source_identity_after_export'):
        identity = manifest[name]
        require(identity == {'head': HEAD, 'tree': TREE, 'status_porcelain': ''}, 'source no longer exact and clean')
    entries = {entry['archive_member']: entry for entry in manifest['entries']}
    require(len(entries) == len(manifest['entries']), 'duplicate manifest member')
    require(set(members) == set(entries) | {'export-manifest.json'}, 'archive/manifest membership differs')
    for name, entry in entries.items():
        require(len(members[name]) == entry['bytes'] and sha(members[name]) == entry['sha256'],
                'original member hash/length differs: ' + name)
    results = {}
    actual_running = []
    summaries = []
    failures = []
    for record_id in IDS:
        prefix = 'primary/validation/' + HEAD + '/' + record_id + '/'
        result = json.loads(members[prefix + 'result.json'])
        context = json.loads(members[prefix + 'context.json'])
        require(context['argv'] == result['argv'], 'context/result command argv differs')
        require(result['id'] == record_id and bool(result['finished_utc']), 'missing terminal record')
        require(context['source_commit'] == result['source_head_before'] == result['source_head_after'] == HEAD,
                'record source differs')
        require(context['source_tree'] == TREE and result['source_status_after'] == '', 'record source identity differs')
        computed_pass = result['returncode'] == 0 and result['launch_error'] is None
        require(result['pass'] is computed_pass and result['qualification_granted'] is False,
                'terminal status contradicts original facts')
        require(sha(members[prefix + 'context.json']) == manifest['record_results'][record_id]['context_sha256'],
                'manifest context pin differs')
        require(sha(members[prefix + 'result.json']) == manifest['record_results'][record_id]['result_sha256'],
                'manifest result pin differs')
        for stream in ('stdout', 'stderr'):
            require(sha(members[prefix + stream + '.log']) == result[stream + '_sha256'], 'receipt/log SHA differs')
        results[record_id] = {'pass': result['pass'], 'returncode': result['returncode'],
                              'finished_utc': result['finished_utc'], 'elapsed_seconds': result['elapsed_seconds']}
        if record_id == 'node-retained-data-all-targets':
            stdout = members[prefix + 'stdout.log'].decode()
            stderr = members[prefix + 'stderr.log'].decode()
            actual_running = re.findall(r'^\s*Running .+$', stderr, re.M)
            summaries = re.findall(r'^test result:.*$', stdout, re.M)
            failures = [line for line in stdout.splitlines() if '... FAILED' in line]
    with ARCHIVE.open('xb') as output:
        output.write(payload)
    os.chmod(ARCHIVE, 0o444)
    EXTRACTED.mkdir()
    for name, data in members.items():
        path = EXTRACTED.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as output:
            output.write(data)
        os.chmod(path, 0o444)
        require(path.read_bytes() == data, 'extracted original bytes differ')
    require({p.relative_to(EXTRACTED).as_posix() for p in EXTRACTED.rglob('*') if p.is_file()} == set(members),
            'extracted member set differs')
    report = {
        'schema': 'desktop-node-data-transfer-verification-v1',
        'verified_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'host': 'desktop', 'source_commit': HEAD, 'source_tree': TREE, 'origin_job_id': JOB,
        'archive': str(ARCHIVE), 'archive_sha256': sha(payload), 'archive_bytes': len(payload),
        'remote_archive': REMOTE_ARCHIVE, 'remote_file_version': version,
        'local_extracted_directory': str(EXTRACTED), 'manifest_sha256': sha(manifest_bytes),
        'member_count': len(members), 'original_file_count': len(entries), 'chunks': chunk_provenance,
        'archive_to_manifest_to_extracted_members_verified': True,
        'complete_command_ids': IDS, 'record_results': results,
        'actual_cargo_running_headers': actual_running, 'actual_test_summary_lines': summaries,
        'actual_failed_test_lines': failures,
        'test_summary_lines_are_verbatim_including_nested_subprocesses': True,
        'nested_summaries_not_added_to_parent_totals': True,
        'compiled_targets_not_treated_as_executed': True,
        'original_incomplete_node_queue_not_replaced': True, 'original_full_rust_failure_not_replaced': True,
        'acceptance_granted': False,
    }
    with REPORT.open('x') as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'archive': str(ARCHIVE), 'archive_sha256': sha(payload), 'archive_bytes': len(payload),
                      'manifest_sha256': sha(manifest_bytes), 'report': str(REPORT),
                      'report_sha256': sha(REPORT.read_bytes()), 'record_results': results}, sort_keys=True))


if __name__ == '__main__':
    main()
