#!/usr/bin/env python3
"""Add reviewed data/docs and lossless archive parts as a child of the executed source.

This operator helper never pushes, merges, changes a policy/reader, or runs a
native campaign. All input mutations have explicit old/new identities. Its
terminal output and create-only receipts remain outside the checkout.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/work/chain-w1-baseline-20261111-9082')
WORK = ROOT.parent
HEAD = '165d286b687e0a73d7fe68148d2179274fc0c0b8'
TREE = '2eb4f5e888a7a02f573d72a2fdf4d5a7cfc352e0'
BRANCH = 'fix/chain-w1-baseline-20261111-9082'
OUT = WORK / 'w1-baseline-9082-evidence-publication'
ARCHIVE = WORK / 'w1-baseline-9082-evidence-165d.tar.xz'
ARCHIVE_RECEIPT = WORK / 'w1-baseline-9082-evidence-165d.archive-receipt.json'
EVIDENCE = Path('evidence/pon-w1-zero-paired-lazy-20261112')
CORPUS = Path('config/pon/pq-cross-branch-corpus-v1.json')
DOCS = {
    'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
    'docs/research/PON_W1_ZERO_PAIRED_LAZY_V1.md',
    'docs/protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md',
}
CAP = 4 * 1024 * 1024
PENDING_MARKER = re.compile(rb'@@PENDING|PENDING_[A-Z0-9_]+')


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def fp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read_regular(path):
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink input: ' + str(part))
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'nonregular input: ' + str(path))
        data = stream.read()
        after = os.fstat(stream.fileno())
    require(fp(before) == fp(after) == fp(path.stat(follow_symlinks=False)),
            'input changed during read: ' + str(path))
    require(len(data) == before.st_size, 'incomplete input read')
    return data


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def create(path, data):
    for part in path.parents:
        require(not part.is_symlink(), 'symlink destination ancestor: ' + str(part))
    require(not path.exists() and not path.is_symlink(), 'create-only destination exists: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    for part in path.parents:
        require(not part.is_symlink(), 'symlink destination ancestor: ' + str(part))
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    require(read_regular(path) == data, 'new file readback differs')


def replace_checked(path, expected_sha, data):
    before = read_regular(path)
    require(sha(before) == expected_sha, 'old document differs: ' + str(path))
    mode = stat.S_IMODE(path.stat().st_mode)
    temp = path.with_name(path.name + '.w1-evidence-pending')
    create(temp, data)
    temp.chmod(mode)
    require(read_regular(path) == before, 'old document changed before replacement')
    os.replace(temp, path)
    require(read_regular(path) == data, 'replacement readback differs')


def git_entries(arguments, expected, *, index):
    """Bind the exact selected index/tree entries, including executable modes."""
    raw = subprocess.check_output(['git', *arguments, '--', *sorted(expected)])
    observed = {}
    for row in raw.split(b'\0'):
        if not row:
            continue
        metadata, path = row.split(b'\t', 1)
        fields = metadata.decode('ascii').split()
        name = path.decode('utf-8')
        require(name not in observed, 'duplicate Git entry: ' + name)
        if index:
            require(len(fields) == 3 and fields[2] == '0', 'non-stage-zero index entry')
            mode, oid = fields[:2]
        else:
            require(len(fields) == 3 and fields[1] == 'blob', 'non-blob committed entry')
            mode, _, oid = fields
        observed[name] = {'mode': mode, 'git_blob': oid}
    require(observed == expected, 'Git mode/blob roster differs from reviewed bytes')
    return observed


def main():
    require(len(sys.argv) == 3 and re.fullmatch('[0-9a-f]{64}', sys.argv[2]),
            'usage: helper payload.json expected_payload_sha256')
    payload_path = Path(sys.argv[1]).absolute()
    require(not payload_path.is_relative_to(ROOT), 'payload must remain outside checkout')
    payload_bytes = read_regular(payload_path)
    require(sha(payload_bytes) == sys.argv[2], 'payload digest differs')
    payload = json.loads(payload_bytes)
    require(payload['source_commit'] == HEAD and payload['source_tree'] == TREE,
            'payload source mismatch')
    require(set(payload['documents']) == DOCS, 'unexpected document mutation')
    require(not OUT.exists() and not (ROOT / EVIDENCE).exists(), 'publication already has state')
    OUT.mkdir()
    os.chdir(ROOT)
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    from run_w1_rank_batch_v5 import capture

    records = []

    def run(command, stem, timeout=600):
        print(json.dumps({'command_started': stem, 'command': command}), flush=True)
        result = capture(command, OUT, stem, timeout=timeout)
        create(OUT / (stem + '.json'), json_bytes(result))
        records.append(result)
        print(json.dumps({'command_finished': stem, 'exit_code': result['exit_code'],
                          'timed_out': result['timed_out']}), flush=True)
        require(result['exit_code'] == 0 and not result['timed_out'], 'command failed: ' + stem)
        return result

    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == HEAD,
            'checkout is no longer the executed source')
    require(subprocess.check_output(['git', 'branch', '--show-current'], text=True).strip() == BRANCH,
            'wrong branch')
    run(['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
         '--expected-head', HEAD, '--output', str(OUT / 'source-before-identity.json')],
        'source-before')
    run(['bash', 'scripts/project-preflight.sh', '--dev'], 'preflight-before-edit', 120)
    run(['gh', 'api', 'user', '--jq', '.login'], 'github-identity', 60)
    require((OUT / 'github-identity.stdout').read_text().strip() == 'ProfHepta',
            'operator GitHub account is not ProfHepta')
    archive_receipt_bytes = read_regular(ARCHIVE_RECEIPT)
    archive_receipt = json.loads(archive_receipt_bytes)
    require(archive_receipt['head'] == HEAD
            and archive_receipt['result'] == 'COMPLETE_BYTE_VERIFIED_ARCHIVE'
            and archive_receipt['declared_input_snapshot_complete'] is True,
            'complete original archive readback is required')
    archive_bytes = read_regular(ARCHIVE)
    require(len(archive_bytes) == archive_receipt['archive_bytes']
            and sha(archive_bytes) == archive_receipt['archive_sha256'], 'archive identity changed')
    require(archive_receipt['campaign_phase_success'] is True
            and archive_receipt['checks_phase_success'] is False,
            'preserve the original successful campaign and failed first checks batch')

    staged = {}
    for relative, record in payload['new_evidence_files'].items():
        path = Path(relative)
        require(not path.is_absolute() and '..' not in path.parts and len(path.parts) == 1,
                'unsafe evidence filename')
        data = base64.b64decode(record['base64'], validate=True)
        require(len(data) == record['bytes'] and sha(data) == record['sha256'],
                'payload evidence bytes differ')
        require(len(data) <= CAP, 'reviewed evidence exceeds original source-reader cap')
        require(relative not in {'native-evidence.parts.json', 'archive-receipt.json',
                                 'evidence-artifact-manifest.json'}, 'reserved evidence filename')
        staged[relative] = data
    require({'README.md', 'cost-results.md', 'results.json', 'excerpt.json',
             'local-development.tar.xz'}.issubset(staged), 'required reviewed evidence is absent')
    parts = []
    for index, offset in enumerate(range(0, len(archive_bytes), CAP)):
        name = f'native-evidence.tar.xz.part-{index:03d}'
        require(name not in staged, 'archive part collides with reviewed evidence')
        data = archive_bytes[offset:offset + CAP]
        staged[name] = data
        parts.append({'path': name, 'offset': offset, 'bytes': len(data),
                      'sha256': sha(data), 'git_blob': blob(data)})
    require(b''.join(staged[part['path']] for part in parts) == archive_bytes,
            'ordered parts do not reconstruct the complete original archive')
    staged['native-evidence.parts.json'] = json_bytes({
        'schema': 'TRNM-W1-ZERO-PAIRED-LAZY-ARCHIVE-PARTS1', 'source_commit': HEAD,
        'source_tree': TREE, 'archive_bytes': len(archive_bytes),
        'archive_sha256': sha(archive_bytes), 'archive_format': 'single XZ-compressed tar',
        'parts': parts, 'part_reader_limit_bytes': CAP,
        'original_reader_limit_unchanged': True, 'ordered_reassembly_verified': True,
        'original_archive_preserved': str(ARCHIVE), 'production_activation': False,
        'security_qualified': False})
    staged['archive-receipt.json'] = archive_receipt_bytes
    staged['evidence-artifact-manifest.json'] = json_bytes({
        'schema': 'TRNM-W1-ZERO-PAIRED-LAZY-DELIVERY1', 'native_source_commit': HEAD,
        'native_source_tree': TREE, 'files': [
            {'path': name, 'bytes': len(data), 'sha256': sha(data), 'git_blob': blob(data)}
            for name, data in sorted(staged.items())],
        'manifest_excludes_itself_to_avoid_a_hash_cycle': True,
        'native_results_are_not_reassigned_to_evidence_child': True,
        'production_activation': False, 'security_qualified': False})

    document_bytes = {}
    for relative, record in payload['documents'].items():
        before = read_regular(ROOT / relative)
        require(sha(before) == record['before_sha256'], 'document preimage mismatch: ' + relative)
        data = base64.b64decode(record['base64'], validate=True)
        require(len(data) == record['bytes'] and sha(data) == record['sha256'],
                'document payload mismatch')
        require(PENDING_MARKER.search(data) is None and data != before,
                'unresolved or empty document change')
        document_bytes[relative] = data
    for name, data in staged.items():
        require(len(data) <= CAP, 'oversized evidence: ' + name)
        if name.endswith(('.md', '.json')):
            require(PENDING_MARKER.search(data) is None, 'unresolved evidence: ' + name)
    plan = {'source_commit': HEAD, 'payload_sha256': sys.argv[2],
            'new_files': {str(EVIDENCE / name): {'bytes': len(data), 'sha256': sha(data)}
                          for name, data in sorted(staged.items())},
            'document_changes': {name: {'before_sha256': payload['documents'][name]['before_sha256'],
                                        'after_sha256': sha(data)}
                                 for name, data in sorted(document_bytes.items())},
            'source_reader_limit_bytes': CAP, 'created_unix': time.time()}
    create(OUT / 'reviewed-publication-plan.json', json_bytes(plan))
    corpus_before = read_regular(ROOT / CORPUS)
    corpus = json.loads(corpus_before)
    old_pins = dict(corpus['pinned_blobs'])
    old_required = list(corpus['required_paths'])
    for name, data in staged.items():
        create(ROOT / EVIDENCE / name, data)
    for name, data in document_bytes.items():
        replace_checked(ROOT / name, payload['documents'][name]['before_sha256'], data)
    affected = {str(EVIDENCE / name): data for name, data in staged.items()}
    affected.update(document_bytes)
    for name, data in affected.items():
        corpus['pinned_blobs'][name] = blob(data)
    corpus['pinned_blobs'] = dict(sorted(corpus['pinned_blobs'].items()))
    corpus['required_paths'] += sorted(set(affected) - set(old_required))
    require(corpus['required_paths'][:len(old_required)] == old_required,
            'existing required-path order changed')
    require(all(corpus['pinned_blobs'][name] == value for name, value in old_pins.items()
                if name not in affected), 'unrelated existing pin changed')
    corpus_after = json_bytes(corpus)
    replace_checked(ROOT / CORPUS, sha(corpus_before), corpus_after)
    changed = sorted(set(affected) | {str(CORPUS)})
    reviewed_bytes = {**affected, str(CORPUS): corpus_after}
    reviewed_entries = {}
    for name, data in reviewed_bytes.items():
        require(read_regular(ROOT / name) == data, 'reviewed content changed: ' + name)
        require(not (ROOT / name).stat().st_mode & stat.S_IXUSR,
                'publication data unexpectedly executable: ' + name)
        reviewed_entries[name] = {'mode': '100644', 'git_blob': blob(data)}
    create(OUT / 'reviewed-git-entries.json', json_bytes(reviewed_entries))
    create(OUT / 'corpus-maintenance.json', json_bytes({
        'previous_pins': len(old_pins), 'current_pins': len(corpus['pinned_blobs']),
        'previous_required_paths': len(old_required), 'current_required_paths': len(corpus['required_paths']),
        'refreshed_existing_pins': sorted(set(old_pins) & set(affected)),
        'added_pins': sorted(set(corpus['pinned_blobs']) - set(old_pins)),
        'unrelated_existing_pins_unchanged': True, 'old_required_prefix_unchanged': True}))
    run(['git', 'diff', '--check'], 'diff-whitespace', 60)
    run(['/usr/bin/python3', '-B', 'scripts/ci/check_pq_research_integration.py'], 'corpus-applied', 600)
    run(['/usr/bin/python3', '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'],
        'inventory-applied', 300)
    run(['bash', 'scripts/project-preflight.sh', '--dev'], 'preflight-before-commit', 120)
    run(['git', 'add', '--', *changed], 'stage-reviewed-files', 120)
    actual = subprocess.check_output(['git', 'diff', '--cached', '--name-only', '-z']).split(b'\0')
    require(sorted(item.decode() for item in actual if item) == changed, 'staged roster differs')
    git_entries(['ls-files', '--stage', '-z'], reviewed_entries, index=True)
    run(['git', 'diff', '--cached', '--check'], 'staged-whitespace', 60)
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == HEAD,
            'execution-source HEAD changed before commit')
    require(subprocess.check_output(['git', 'branch', '--show-current'], text=True).strip() == BRANCH,
            'branch changed before commit')
    run(['git', 'commit', '--signoff', '-m', 'docs(pon): retain measured legal-strategy baseline and failures'],
        'evidence-commit', 300)
    child = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    parents = subprocess.check_output(['git', 'rev-list', '--parents', '-n', '1', child],
                                      text=True).split()
    require(parents == [child, HEAD], 'evidence commit is not the single-parent execution-source child')
    require(subprocess.check_output(['git', 'branch', '--show-current'], text=True).strip() == BRANCH,
            'branch changed during commit')
    committed = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', '-z',
                                         HEAD, child]).split(b'\0')
    require(sorted(item.decode() for item in committed if item) == changed,
            'committed roster differs from reviewed publication')
    git_entries(['ls-tree', '-r', '-z', child], reviewed_entries, index=False)
    require(subprocess.check_output(['git', 'diff', '--name-only', HEAD, child, '--',
                                    'trillionnium', 'scripts', 'formal'], text=True).strip() == '',
            'evidence publication changed an implementation or checker')
    run(['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
         '--expected-head', child, '--output', str(OUT / 'source-after-identity.json')], 'source-after')
    result = {'result': 'EVIDENCE_CHILD_COMMITTED_AND_SOURCE_VERIFIED',
              'native_execution_source': HEAD, 'evidence_child': child,
              'evidence_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
              'branch': BRANCH, 'changed_paths': changed, 'github_identity': 'ProfHepta',
              'native_results_reassigned': False, 'post_commit_checks_still_required': True,
              'pushed': False, 'production_activation': False, 'security_qualified': False}
    create(OUT / 'publication-result.json', json_bytes(result))
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
