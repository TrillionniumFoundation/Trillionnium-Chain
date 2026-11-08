#!/usr/bin/env python3
"""Stage and commit only the owned acceptance archive and existing sole plan."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-publication'
ARCHIVE_REL = 'evidence/pon-native-demand-acceptance-20261107'
ARCHIVE = SOURCE / ARCHIVE_REL
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
EXPECTED = '690f710c1b6808787996e86aa4c36bd53e1f3939'
BRANCH = 'fix/chain-native-demand-acceptance-20261107'
OUT = ROOT / 'publication-commit-v1'
OUT.mkdir()
COMMANDS = []

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write('\n')

def command(args, label):
    proc = subprocess.run(args, cwd=SOURCE, capture_output=True, check=False)
    (OUT / (label + '.stdout.log')).write_bytes(proc.stdout)
    (OUT / (label + '.stderr.log')).write_bytes(proc.stderr)
    row = {'command': args, 'exit_code': proc.returncode, 'stdout_sha256': sha(proc.stdout), 'stderr_sha256': sha(proc.stderr)}
    COMMANDS.append(row)
    save(OUT / (label + '.json'), row)
    if proc.returncode != 0:
        raise RuntimeError('Command failed: ' + label)
    return proc.stdout

def git(*args):
    return subprocess.check_output(['/usr/bin/git', *args], cwd=SOURCE)

if git('rev-parse', 'HEAD').decode().strip() != EXPECTED or git('branch', '--show-current').decode().strip() != BRANCH:
    raise RuntimeError('Publication branch/head mismatch')
if git('diff', '--cached', '--name-only', '-z'):
    raise RuntimeError('Unexpected prior staged changes')
command(['bash', 'scripts/project-preflight.sh'], 'preflight-dev')
index = json.loads((ARCHIVE / 'ARTIFACT_INDEX.json').read_text())
indexed = set()
for row in index['files']:
    relative = row['path']
    path = ARCHIVE / relative
    if not path.resolve().is_relative_to(ARCHIVE.resolve()) or path.is_symlink() or relative in indexed:
        raise RuntimeError('Invalid archive index path')
    raw = path.read_bytes()
    if len(raw) != row['bytes'] or sha(raw) != row['sha256']:
        raise RuntimeError('Archive bytes changed: ' + relative)
    indexed.add(relative)
actual = {p.relative_to(ARCHIVE).as_posix() for p in ARCHIVE.rglob('*') if p.is_file()}
if actual != indexed | {'ARTIFACT_INDEX.json'}:
    raise RuntimeError('Unindexed archive files')
status = json.loads((ARCHIVE / 'ACCEPTANCE_STATUS.json').read_text())
if status.get('production_activation') is not False or status.get('complete_node_qualification') is not False:
    raise RuntimeError('Acceptance authority changed')
command(['/usr/bin/git', 'add', '--', PLAN], 'stage-plan')
# The archive is exclusively owned by this task; force inclusion preserves raw *.log.
command(['/usr/bin/git', 'add', '-f', '--', ARCHIVE_REL], 'stage-owned-archive')
paths = [p.decode() for p in git('diff', '--cached', '--name-only', '-z').split(b'\0') if p]
if not paths or any(p != PLAN and not p.startswith(ARCHIVE_REL + '/') for p in paths):
    raise RuntimeError('Staged path scope changed')
command(['bash', 'scripts/project-preflight.sh', '--staged'], 'preflight-staged')
command(['/usr/bin/git', 'diff', '--cached', '--check'], 'staged-whitespace')
save(OUT / 'staged-inventory.json', {'paths': paths, 'implementation_source': EXPECTED, 'artifact_index_sha256': sha((ARCHIVE / 'ARTIFACT_INDEX.json').read_bytes())})
command(['/usr/bin/git', 'commit', '-m', 'docs: retain native acceptance execution and unresolved gates'], 'commit')
head = git('rev-parse', 'HEAD').decode().strip()
if git('rev-parse', 'HEAD^').decode().strip() != EXPECTED:
    raise RuntimeError('Unexpected publication parent')
if git('status', '--porcelain=v1', '-z', '--untracked-files=all'):
    raise RuntimeError('Publication tree not clean after commit')
for path in sorted(actual):
    if git('show', head + ':' + ARCHIVE_REL + '/' + path) != (ARCHIVE / path).read_bytes():
        raise RuntimeError('Committed archive blob differs: ' + path)
save(OUT / 'result.json', {'schema': 'pon-native-acceptance-evidence-commit-v1', 'result': 'COMMITTED_NOT_PUSHED', 'created_unix_seconds': time.time(), 'implementation_source': EXPECTED, 'publication_head': head, 'publication_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(), 'branch': BRANCH, 'archive_file_count': len(actual), 'archive_indexed_bytes': index['total_bytes'], 'committed_blob_bytes_verified': True, 'commands': COMMANDS, 'force_push': False, 'merge': False, 'production_activation': False})
print(json.dumps({'result': 'COMMITTED_NOT_PUSHED', 'head': head, 'archive_files': len(actual)}), flush=True)
