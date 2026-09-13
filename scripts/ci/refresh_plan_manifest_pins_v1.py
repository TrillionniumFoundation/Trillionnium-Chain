#!/usr/bin/env python3
"""Refresh declared development-input pins, never protocol imports or acceptance.

Default --check is read-only. --write atomically updates only the existing plan
manifest's declared blob/SHA fields. Assessed source, historical provenance,
production flags and frozen normative import digests are never generated here.
Commit/review the diff and run the ordinary exact-source validators afterwards.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True
from check_plan_manifest_pins_v1 import PIN_PATH_FIELDS
from check_documentation_contracts_v1 import PIN_FIELDS

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'docs/development/plan-manifest-v1.toml'


def bounded_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise ValueError('invalid input path')
    if relative.startswith('/') or any(part in {'', '.', '..'} for part in relative.split('/')):
        raise ValueError('input path must be repository-relative')
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f'input missing or outside repository: {relative}')
    return path


def refresh(root: Path, text: str) -> str:
    data = tomllib.loads(text)
    paths = {}
    for field, path_field in PIN_PATH_FIELDS.items():
        if field not in data or path_field not in data:
            raise ValueError(f'missing declared pin: {field}')
        paths[field] = data[path_field]
    for field, relative in PIN_FIELDS.items():
        if field not in data:
            raise ValueError(f'missing declared pin: {field}')
        if field in paths and paths[field] != relative:
            raise ValueError(f'conflicting pin path: {field}')
        paths[field] = relative
    declared = {field for field in data if field.endswith('_git_blob')}
    if declared != set(paths):
        raise ValueError('unrecognized or omitted development pin')
    replacements = {}
    for field, relative in paths.items():
        content = bounded_path(root, relative).read_bytes()
        replacements[field] = hashlib.sha1(
            b'blob '+str(len(content)).encode('ascii')+b'\0'+content
        ).hexdigest()
    for digest, path_key in (('plan_sha256', 'plan_path'),
                             ('evidence_contract_sha256', 'evidence_contract_path')):
        replacements[digest] = hashlib.sha256(bounded_path(root, data[path_key]).read_bytes()).hexdigest()
    for field, value in replacements.items():
        text, count = re.subn(r'(?m)^'+re.escape(field)+r' = "[^"\n]*"$',
                              f'{field} = "{value}"', text)
        if count != 1:
            raise ValueError(f'ambiguous or unsupported pin assignment: {field}')
    revised = tomllib.loads(text)
    # This tool may not change provenance, review requirements, replay commands,
    # production status, protocol imports or any other non-derived field.
    for key in set(data) | set(revised):
        if key not in replacements and data.get(key) != revised.get(key):
            raise ValueError(f'non-derived field changed: {key}')
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = bounded_path(ROOT, MANIFEST)
    if path.is_symlink():
        raise ValueError('plan manifest must not be a symlink')
    original = path.read_text(encoding='utf-8')
    updated = refresh(ROOT, original)
    if original == updated:
        print('development_pins=unchanged acceptance=not-assessed')
        return 0
    if not args.write:
        print('development pins stale; review inputs then use --write', file=sys.stderr)
        return 1
    fd, name = tempfile.mkstemp(prefix='.plan-pins-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as handle:
            handle.write(updated)
        os.chmod(name, path.stat().st_mode & 0o777)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print('development_pins=updated acceptance=not-assessed; review and run exact-source gates')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f'pin refresh refused: {error}', file=sys.stderr)
        raise SystemExit(2)
