#!/usr/bin/env python3
"""Read-only exact-tree static checks; receipts live outside the repository."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-publication'
IMPLEMENTATION = '690f710c1b6808787996e86aa4c36bd53e1f3939'
ARCHIVE = 'evidence/pon-native-demand-acceptance-20261107/'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def git(*args):
    return subprocess.check_output(['/usr/bin/git', *args], cwd=SOURCE)

def clean():
    value = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    if value:
        raise RuntimeError('Publication tree is not clean: ' + repr(value[:4000]))

def snapshot(expected):
    clean()
    head = git('rev-parse', 'HEAD').decode().strip()
    if head != expected:
        raise RuntimeError('Unexpected source HEAD')
    changed = git('diff', '--name-only', '-z', IMPLEMENTATION, head).split(b'\0')
    if any(p and p.decode() != PLAN and not p.decode().startswith(ARCHIVE) for p in changed):
        raise RuntimeError('Publication changed implementation paths')
    rows = []
    for line in git('ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
        if not line:
            continue
        meta, name = line.split(b'\t', 1)
        mode, kind, oid = meta.decode().split(' ')
        rel = name.decode('utf-8')
        path = SOURCE / rel
        st = path.lstat()
        if mode == '120000':
            if not stat.S_ISLNK(st.st_mode):
                raise RuntimeError('Symlink mode mismatch: ' + rel)
            raw = os.readlink(path).encode('utf-8')
        else:
            if mode not in ('100644', '100755') or kind != 'blob' or not stat.S_ISREG(st.st_mode):
                raise RuntimeError('Unsupported source object: ' + rel)
            if bool(st.st_mode & 0o111) != (mode == '100755'):
                raise RuntimeError('Executable mode mismatch: ' + rel)
            raw = path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if actual != oid:
            raise RuntimeError('Tracked bytes mismatch: ' + rel)
        rows.append({'path': rel, 'mode': mode, 'git_blob': oid, 'bytes': len(raw), 'sha256': sha(raw)})
    result = {'schema': 'pon-publication-full-materialized-source-v1', 'head': head, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(), 'tracked_files': len(rows), 'tracked_bytes': sum(r['bytes'] for r in rows), 'files': rows}
    canonical = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    return result, sha(canonical)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.label) or not re.fullmatch(r'[0-9a-f]{40}', args.expected_head):
        raise ValueError('Invalid receipt identity')
    out = ROOT / args.label
    out.mkdir()
    before, source_id = snapshot(args.expected_head)
    save(out / 'source-before.json', before)
    save(out / 'provenance.json', {'schema': 'pon-publication-static-provenance-v1', 'implementation_source': IMPLEMENTATION, 'checked_head': args.expected_head, 'source_canonical_sha256': source_id, 'recorder_sha256': sha(Path(__file__).read_bytes()), 'production_activation': False})
    commands = [
        ('preflight', ['bash', 'scripts/project-preflight.sh']),
        ('source-pins', ['python3', 'scripts/ci/check_pq_research_integration.py']),
        ('negative-source-integrity', ['python3', 'scripts/ci/test_ci_source_integrity.py']),
        ('negative-research-integration', ['python3', 'scripts/ci/test_pq_research_integration.py']),
        ('negative-repository', ['python3', 'scripts/ci/test_repository.py']),
        ('repository-links', ['python3', 'scripts/ci/check_repository.py']),
        ('diff-whitespace', ['/usr/bin/git', 'diff', '--check', IMPLEMENTATION, 'HEAD']),
    ]
    reports = []
    for label, command in commands:
        clean()
        directory = out / label
        directory.mkdir()
        started = time.time()
        save(directory / 'started.json', {'command': command, 'head': args.expected_head, 'started_unix_seconds': started})
        print(json.dumps({'started': label, 'head': args.expected_head}), flush=True)
        with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
            proc = subprocess.run(command, cwd=SOURCE, stdout=stdout, stderr=stderr, check=False)
        stdout = (directory / 'stdout.log').read_bytes()
        stderr = (directory / 'stderr.log').read_bytes()
        report = {'schema': 'pon-publication-static-gate-v1', 'label': label, 'command': command, 'head': args.expected_head, 'exit_code': proc.returncode, 'started_unix_seconds': started, 'elapsed_seconds': time.time() - started, 'stdout': {'bytes': len(stdout), 'sha256': sha(stdout)}, 'stderr': {'bytes': len(stderr), 'sha256': sha(stderr)}, 'independent_business_acceptance': False}
        report['unittest_summaries'] = re.findall(r'^Ran (\d+) tests? in ([^\r\n]+)$', stderr.decode('utf-8', errors='strict'), re.M)
        save(directory / 'receipt.json', report)
        reports.append(report)
        clean()
        print(json.dumps({'finished': label, 'exit_code': proc.returncode, 'elapsed_seconds': report['elapsed_seconds'], 'unittest_summaries': report['unittest_summaries']}), flush=True)
    after, after_id = snapshot(args.expected_head)
    save(out / 'source-after.json', after)
    passed = all(r['exit_code'] == 0 for r in reports) and source_id == after_id
    save(out / 'summary.json', {'schema': 'pon-publication-static-summary-v1', 'head': args.expected_head, 'source_before_sha256': source_id, 'source_after_sha256': after_id, 'source_unchanged': source_id == after_id, 'gates': reports, 'all_selected_gates_passed': passed, 'complete_node_qualification': False, 'production_activation': False})
    return 0 if passed else 1

if __name__ == '__main__':
    raise SystemExit(main())
