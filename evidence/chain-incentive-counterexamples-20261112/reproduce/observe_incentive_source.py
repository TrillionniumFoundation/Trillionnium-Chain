#!/usr/bin/env python3
"""Observe the explicitly declared incentive source slice against committed blobs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()

def git(*args_):
    return subprocess.check_output(['git', *args_], cwd=args.repo)

paths = ['trillionnium', 'config', 'formal', 'scripts', 'docs', '.github', 'AGENTS.md', 'PROJECT_BOUNDARY.json', 'PROJECT_ID']
entries = git('ls-tree', '-r', '-z', 'HEAD', '--', *paths).split(b'\0')
checks, missing, mismatches = [], [], []
for entry in entries:
    if not entry:
        continue
    declaration, raw_path = entry.split(b'\t', 1)
    mode, kind, blob = declaration.decode().split()
    name = raw_path.decode()
    if kind != 'blob':
        raise ValueError('unsupported source object: '+name)
    path = args.repo / name
    if not path.exists():
        missing.append(name)
        continue
    if path.is_symlink():
        raise ValueError('source symlink requires an explicit declared treatment: '+name)
    raw = path.read_bytes()
    actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if actual != blob:
        mismatches.append({'path': name, 'expected': blob, 'actual': actual})
    checks.append({'path': name, 'bytes': len(raw), 'git_blob': blob,
                   'sha256': hashlib.sha256(raw).hexdigest()})
report = {'schema': 'incentive-source-observation-v1',
          'scope': 'all-tracked-trillionnium-config-formal-scripts-docs-github-and-project-boundaries; excluded-evidence-and-other-roots-are-not-a-full-worktree-completeness-claim',
          'commit': git('rev-parse', 'HEAD').decode().strip(),
          'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
          'files': len(checks), 'bytes': sum(row['bytes'] for row in checks),
          'checks': checks, 'missing': missing, 'mismatches': mismatches}
args.output.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
print(json.dumps({key: value for key, value in report.items() if key != 'checks'}, sort_keys=True))
raise SystemExit(1 if missing or mismatches else 0)
