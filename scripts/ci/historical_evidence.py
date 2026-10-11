#!/usr/bin/env python3
"""Run historical semantic validation against its original Git tree, never today's runtime.

Temporary detached checkouts are owned by this call and removed on success or failure.
No branch is moved, measurement is rewritten, source test is rerun or acceptance granted.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def identity(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
        raise ValueError('HISTORICAL_SOURCE_IDENTITY')
    return value


@contextlib.contextmanager
def measured_checkout(root, folder):
    root, folder = Path(root).resolve(), Path(folder).resolve()
    manifest = json.loads((folder / 'manifest.json').read_text())
    commit = identity(manifest['implementation_commit'])
    tree = identity(manifest['implementation_tree'])
    actual = subprocess.check_output(['git', 'rev-parse', commit + '^{tree}'], cwd=root, text=True).strip()
    if actual != tree:
        raise ValueError('HISTORICAL_SOURCE_TREE')
    old_bytecode = sys.dont_write_bytecode
    with tempfile.TemporaryDirectory(prefix='pon-historical-source-') as owned:
        source = Path(owned) / 'source'
        added = False
        try:
            subprocess.run(['git', 'worktree', 'add', '--detach', str(source), commit],
                           cwd=root, check=True, capture_output=True, text=True, timeout=90)
            added = True
            sys.dont_write_bytecode = True
            yield source
        finally:
            sys.dont_write_bytecode = old_bytecode
            if added:
                # Only this freshly created detached checkout; never a caller's worktree.
                subprocess.run(['git', 'worktree', 'remove', '--force', str(source)],
                               cwd=root, check=True, capture_output=True, text=True, timeout=90)


def validate_historical_cli(script, root, folder):
    """Use a fresh interpreter so an imported current module cannot masquerade as history."""
    root, folder = Path(root).resolve(), Path(folder).resolve()
    with measured_checkout(root, folder) as source:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, str(Path(script).resolve()), '--root', str(source),
                                 '--evidence', str(folder)], cwd=root, env=env, check=True,
                                capture_output=True, text=True, timeout=300)
        original = json.loads(result.stdout.splitlines()[-1])
    return {'measured_commit': original['measured_commit'], 'historical_semantics_verified': True,
            'verification_checkout': 'original-measured-tree', 'runtime_matches': False,
            'current_source_qualified_by_this_check': False, 'tests_reexecuted': False,
            'independent_accepted': False, 'production_activation': False}
