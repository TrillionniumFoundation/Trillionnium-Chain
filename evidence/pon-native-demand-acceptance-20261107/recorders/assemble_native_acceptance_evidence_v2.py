#!/usr/bin/env python3
"""Copy already completed, verified observations into the owned evidence path."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-publication'
IMPLEMENTATION = '690f710c1b6808787996e86aa4c36bd53e1f3939'
TREE = 'b9ff2e5c4ca6e465b86cb4b2bd466ad831147899'
ARCHIVE_REL = 'evidence/pon-native-demand-acceptance-20261107'
ARCHIVE = SOURCE / ARCHIVE_REL
PLAN_REL = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
HEPTA = Path('/home/qian-qi/workspace/pon-hepta-acceptance-525798-20261107-evidence/chain-interop')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def load(path):
    return json.loads(path.read_text(encoding='utf-8'))

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def git(*args):
    return subprocess.check_output(['/usr/bin/git', *args], cwd=SOURCE)

COPIED = []
EXCLUDED_GENERATED_CACHE = []
def copy(src, relative):
    if not stat.S_ISREG(src.lstat().st_mode) or src.is_symlink():
        raise RuntimeError('Expected a regular source file: ' + str(src))
    dest = ARCHIVE / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    before = src.stat()
    raw = src.read_bytes()
    after = src.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise RuntimeError('Source changed during copy: ' + str(src))
    with dest.open('xb') as stream:
        stream.write(raw)
    if dest.read_bytes() != raw:
        raise RuntimeError('Copy mismatch')
    COPIED.append({'source_path': str(src), 'archive_path': relative, 'bytes': len(raw), 'sha256': digest(raw)})

def copy_tree(src, prefix):
    if not src.is_dir():
        raise RuntimeError('Missing receipt directory: ' + str(src))
    for path in sorted(src.rglob('*')):
        if '__pycache__' in path.relative_to(src).parts:
            if path.is_file() and not path.is_symlink():
                raw = path.read_bytes()
                EXCLUDED_GENERATED_CACHE.append({'source_path': str(path), 'bytes': len(raw), 'sha256': digest(raw), 'reason': 'Generated Python import cache, not execution evidence'})
            continue
        if path.is_symlink():
            raise RuntimeError('Symlink in receipt tree')
        if path.is_file():
            copy(path, prefix + '/' + path.relative_to(src).as_posix())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--readme', required=True)
    parser.add_argument('--plan-increment', required=True)
    parser.add_argument('--acceptance-status', required=True)
    parser.add_argument('--materialization-list', required=True)
    parser.add_argument('--expected-union-sha256', required=True)
    args = parser.parse_args()
    if git('rev-parse', 'HEAD').decode().strip() != IMPLEMENTATION or git('rev-parse', 'HEAD^{tree}').decode().strip() != TREE:
        raise RuntimeError('Publication source changed')
    if git('status', '--porcelain=v1', '-z', '--untracked-files=all'):
        raise RuntimeError('Publication worktree is not clean')
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=SOURCE, check=True)
    if ARCHIVE.exists():
        raise RuntimeError('Archive already exists')
    core_path = ROOT / 'recovery-core-gates-690f-v1/summary.json'
    core_raw = core_path.read_bytes()
    core = json.loads(core_raw)
    if digest(core_raw) != '7ae138b863ab5c0469fb6a635d43e9ebd5b8f9109daa36e1de52363f719c23d9':
        raise RuntimeError('Core summary identity changed')
    if core['all_selected_gates_passed'] is not True or core['source_commit'] != IMPLEMENTATION:
        raise RuntimeError('Core source/result mismatch')
    if {row['label'] for row in core['gates']} != {'core-suites', 'workspace-clippy', 'formatting', 'metadata-root', 'metadata-fuzz'}:
        raise RuntimeError('Core gate set changed')
    for row in core['gates']:
        if row['source_commit'] != IMPLEMENTATION or row['source_tree'] != TREE or type(row['exit_code']) is not int or row['exit_code'] != 0 or row['source_unchanged'] is not True:
            raise RuntimeError('Core command/source did not pass unchanged')
    static_raw = (ROOT / 'publication-static-690f-v1/summary.json').read_bytes()
    if digest(static_raw) != 'f9ee0b54b47049a06a737cfade1f66c7e1a06860971d98c638d960bd9cbc40bd':
        raise RuntimeError('Frozen static summary identity changed')
    static = json.loads(static_raw)
    if static['all_selected_gates_passed'] is not True or static['head'] != IMPLEMENTATION:
        raise RuntimeError('Static source gate failure must be explicitly reviewed')
    original = load(ROOT / 'recovery-evidence-tools/original-node-terminal-status.json')
    remainder = load(ROOT / 'recovery-evidence-tools/remaining-node-terminal-status.json')
    for terminal in (original, remainder):
        if terminal.get('terminal_publication_confirmed') is not True or terminal.get('output_complete') is not True or terminal.get('output_durable') is not True:
            raise RuntimeError('Missing authoritative durable terminal status')
    if original['job_id'] != '1a1b6390138-12894-305' or original['exit_code'] != 124:
        raise RuntimeError('Original failed attempt identity changed')
    if remainder['job_id'] != '1a1b6b4fa87-12894-60d':
        raise RuntimeError('Remainder run identity changed')
    union = ROOT / 'recovery-evidence-tools/node-cross-run-coverage-v1.json'
    union_raw = union.read_bytes()
    if digest(union_raw) != args.expected_union_sha256:
        raise RuntimeError('Final coverage audit identity changed')
    union_data = json.loads(union_raw)
    if union_data.get('source_commit') != IMPLEMENTATION or union_data.get('source_tree') != TREE:
        raise RuntimeError('Cross-run source binding mismatch')
    if union_data.get('qualification') is not False or union_data.get('single_complete_cargo_gate') is not False:
        raise RuntimeError('Cross-run coverage upgraded into qualification')
    if union_data.get('errors') != [] or union_data.get('all_targets_have_unambiguous_complete_summary') is not True or union_data.get('completed_target_count') != 91:
        raise RuntimeError('Coverage incomplete or attribution ambiguous')
    if union_data['original_run']['provenance']['job_id'] != original['job_id'] or union_data['remainder_run']['provenance']['job_id'] != remainder['job_id']:
        raise RuntimeError('Cross-run job binding mismatch')
    for name in ('result.json', 'source-after.json'):
        if (ROOT / 'build-receipts/complete-node-690f710c-v1' / name).exists():
            raise RuntimeError('Original closing receipt unexpectedly exists; inspect provenance')
    readme = Path(args.readme).read_bytes()
    plan_increment = Path(args.plan_increment).read_text(encoding='utf-8')
    status = load(Path(args.acceptance_status))
    if b'{{' in readme or '{{' in plan_increment or status.get('production_activation') is not False:
        raise RuntimeError('Unresolved report placeholder or activation flag')
    ARCHIVE.mkdir(parents=True)
    for source, dest in [
        ('recovery-static-690f-v1', 'python'),
        ('recovery-core-gates-690f-v1', 'core'),
        ('build-receipts/complete-node-690f710c-v1', 'node/original'),
        ('build-receipts/remaining-node-690f710c-v1', 'node/remaining'),
        ('recovery-evidence-tools', 'node/audit'),
        ('publication-static-690f-v1', 'publication/static-implementation'),
        ('build-receipts/pq-provider', 'provider'),
    ]:
        copy_tree(ROOT / source, dest)
    for attempt in range(1, 5):
        copy_tree(ROOT / ('publication-materialization-v' + str(attempt)), 'recovery/materialization-v' + str(attempt))
    materialization_raw = Path(args.materialization_list).read_bytes()
    if digest(materialization_raw) != 'a3560d20649c6baaae0d065da377c13567bce46b5ee91a8190a1896d42b8d8f8':
        raise RuntimeError('Materialization inventory identity changed')
    materialization = json.loads(materialization_raw)
    for row in materialization['files']:
        path = ROOT / row['path']
        if not path.resolve().is_relative_to(ROOT):
            raise RuntimeError('Materialization path escaped scope')
        raw = path.read_bytes()
        if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
            raise RuntimeError('Materialization receipt changed: ' + row['path'])
        copy(path, 'recovery/' + row['path'])
    copy(Path(args.materialization_list), 'recovery/materialization-archive-list.json')
    for name in ['run_remote_node_gate.py', 'run_remote_core_gates_recovery_v1.py', 'run_publication_static_gates_v1.py', 'assemble_native_acceptance_evidence_v1.py', 'assemble_native_acceptance_evidence_v2.py', 'commit_native_acceptance_evidence_v1.py', 'commit_native_acceptance_evidence_v2.py', 'publish_native_acceptance_v1.py', 'publish_native_acceptance_v2.py']:
        copy(ROOT / name, 'recorders/' + name)
    for name in ['native-source-publication-690f710c.json', 'kernel-parent-prerequisite-readonly-v1.json', 'cloud-workspace-loss-observation.json', 'runtime-inventory-launch-observation.json']:
        copy(ROOT / name, 'recovery/' + name)
    hepta_pins = {
        'MANIFEST.json': 'e288f09e79b0b05a809b5addffe6d694dc7542c11cbaabe31200d67fedaff94c',
        'README.md': 'c0a5c09b4bcb8cd1dad4afd7ca06ff8a13c3844ded0eea6cd9897d1c019e9a4f',
        'PUBLICATION_RECEIPT.json': 'fc5df3c0c414d7c9ae2f6ffbc80a94986fd309087d4bbc607d9f77c477c95fe6',
    }
    for name, expected in hepta_pins.items():
        if digest((HEPTA / name).read_bytes()) != expected:
            raise RuntimeError('Hepta handoff identity changed')
        copy(HEPTA / name, 'interop/hepta/' + name)
    copy(Path(args.readme), 'README.md')
    save(ARCHIVE / 'ACCEPTANCE_STATUS.json', status)
    save(ARCHIVE / 'INPUT_BINDINGS.json', {'schema': 'pon-native-acceptance-sealed-inputs-v1', 'implementation_source': IMPLEMENTATION, 'implementation_tree': TREE, 'core_summary_sha256': digest(core_raw), 'frozen_static_summary_sha256': digest(static_raw), 'node_union_sha256': digest(union_raw), 'original_node_job': original['job_id'], 'remaining_node_job': remainder['job_id'], 'complete_node_qualification': False, 'production_activation': False, 'review_note': 'Assembler v1 was not executed. Read-only review required explicit source/job/coverage/hash binding; v2 adds those preconditions before any repository mutation.'})
    with (ARCHIVE / '.gitattributes').open('x') as stream:
        stream.write('* -text\n*.log whitespace=-blank-at-eof,-blank-at-eol\n')
    save(ARCHIVE / 'COPY_PROVENANCE.json', {'schema': 'pon-native-acceptance-copy-provenance-v1', 'copied_unix_seconds': time.time(), 'implementation_source': IMPLEMENTATION, 'files': COPIED, 'excluded_generated_cache_files': EXCLUDED_GENERATED_CACHE})
    plan = SOURCE / PLAN_REL
    plan_before = plan.read_bytes()
    marker = b'## 0. One authority and explicit retirement\n\n'
    if plan_before.count(marker) != 1:
        raise RuntimeError('Plan insertion boundary changed')
    plan_after = plan_before.replace(marker, marker + plan_increment.encode() + b'\n\n', 1)
    plan.write_bytes(plan_after)
    save(ARCHIVE / 'PLAN_CHANGE.json', {'path': PLAN_REL, 'before_sha256': digest(plan_before), 'after_sha256': digest(plan_after), 'change': 'One acceptance checkpoint in the sole existing development plan'})
    files = []
    for path in sorted(ARCHIVE.rglob('*')):
        if path.is_file():
            raw = path.read_bytes()
            files.append({'path': path.relative_to(ARCHIVE).as_posix(), 'bytes': len(raw), 'sha256': digest(raw)})
    save(ARCHIVE / 'ARTIFACT_INDEX.json', {'schema': 'pon-native-acceptance-artifact-index-v1', 'self_excluded': True, 'implementation_source': IMPLEMENTATION, 'files': files, 'file_count': len(files), 'total_bytes': sum(row['bytes'] for row in files)})
    changed = [p.decode() for p in git('diff', '--name-only', '-z').split(b'\0') if p]
    if changed != [PLAN_REL]:
        raise RuntimeError('Unexpected tracked modification')
    print(json.dumps({'result': 'ASSEMBLED_NOT_COMMITTED', 'archive': ARCHIVE_REL, 'indexed_files': len(files), 'bytes': sum(row['bytes'] for row in files), 'source': IMPLEMENTATION, 'production_activation': False}))

if __name__ == '__main__':
    main()
