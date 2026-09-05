#!/usr/bin/env python3
"""Bind Cargo's active targets to a clean, exact Git source. Not test acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class InventoryError(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise InventoryError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise InventoryError(f'non-JSON numeric constant: {value}')


def git(root: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(root), *args], text=True, timeout=20).strip()


def bound_file(root: pathlib.Path, raw: Any) -> tuple[pathlib.Path, str]:
    require(isinstance(raw, str) and bool(raw), 'missing file path')
    path = pathlib.Path(raw)
    require(path.is_absolute() and '..' not in path.parts, f'noncanonical Cargo path: {raw}')
    path = path.resolve(strict=True)
    require(path.is_relative_to(root) and path.is_file(), f'Cargo source escapes Git root: {raw}')
    relative = path.relative_to(root).as_posix()
    expected = git(root, 'rev-parse', f'HEAD:{relative}')
    data = path.read_bytes()
    actual = hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest()
    require(actual == expected, f'source differs from HEAD: {relative}')
    return path, expected


def validate_metadata(
    root: pathlib.Path, workspace: pathlib.Path, metadata: Any, expected_commit: str,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    workspace = workspace.resolve(strict=True)
    require(workspace.is_relative_to(root), 'workspace escapes Git root')
    require(re.fullmatch(r'[0-9a-f]{40}', expected_commit) is not None, 'invalid expected commit')
    head = git(root, 'rev-parse', 'HEAD')
    require(head == expected_commit, 'Git source does not match expected commit')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'Git source is not clean')
    require(isinstance(metadata, dict) and type(metadata.get('version')) is int and metadata['version'] == 1, 'unsupported Cargo metadata')
    require(metadata.get('workspace_root') == str(workspace), 'Cargo workspace root mismatch')
    members = metadata.get('workspace_members')
    packages = metadata.get('packages')
    require(isinstance(members, list) and bool(members), 'empty workspace membership')
    require(all(isinstance(x, str) and x for x in members), 'invalid member IDs')
    require(len(set(members)) == len(members), 'duplicate workspace membership')
    require(isinstance(packages, list), 'Cargo packages must be an array')
    by_id: dict[str, dict[str, Any]] = {}
    for package in packages:
        require(isinstance(package, dict), 'Cargo package must be an object')
        identity = package.get('id')
        require(isinstance(identity, str) and bool(identity), 'invalid package ID')
        require(identity not in by_id, 'duplicate Cargo package ID')
        by_id[identity] = package
    require(set(members) <= set(by_id), 'workspace member lacks Cargo package metadata')
    _, workspace_blob = bound_file(root, str(workspace / 'Cargo.toml'))
    _, lock_blob = bound_file(root, str(workspace / 'Cargo.lock'))
    manifest = tomllib.loads((workspace / 'Cargo.toml').read_text())
    declared_members = manifest.get('workspace', {}).get('members')
    require(isinstance(declared_members, list) and declared_members and all(isinstance(x, str) and x for x in declared_members), 'workspace members missing in TOML')
    declared_manifests = {
        (workspace / member / 'Cargo.toml').resolve(strict=True) for member in declared_members
    }
    observed_manifests: set[pathlib.Path] = set()
    names: set[str] = set()
    reports = []
    for identity in sorted(members):
        package = by_id[identity]
        path, manifest_blob = bound_file(root, package.get('manifest_path'))
        require(path in declared_manifests, 'Cargo returned an undeclared workspace package')
        require(path not in observed_manifests, 'Cargo manifest appears more than once')
        observed_manifests.add(path)
        cargo_toml = tomllib.loads(path.read_text())
        name = package.get('name')
        require(isinstance(name, str) and name == cargo_toml.get('package', {}).get('name'), 'Cargo package name mismatch')
        require(name not in names, 'duplicate package name')
        names.add(name)
        targets = package.get('targets')
        require(isinstance(targets, list) and bool(targets), f'{name}: missing targets')
        seen = set()
        target_reports = []
        for target in targets:
            require(isinstance(target, dict), f'{name}: malformed target')
            target_name, kinds = target.get('name'), target.get('kind')
            require(isinstance(target_name, str) and bool(target_name), f'{name}: invalid target name')
            require(isinstance(kinds, list) and kinds and all(isinstance(x, str) and x for x in kinds), f'{name}: invalid target kind')
            source, source_blob = bound_file(root, target.get('src_path'))
            key = (target_name, tuple(kinds), str(source))
            require(key not in seen, f'{name}: duplicate target')
            seen.add(key)
            target_reports.append({
                'name': target_name, 'kind': kinds,
                'source': source.relative_to(root).as_posix(), 'source_git_blob': source_blob,
            })
        reports.append({
            'package': name, 'package_id': identity,
            'manifest': path.relative_to(root).as_posix(), 'manifest_git_blob': manifest_blob,
            'targets': sorted(target_reports, key=lambda row: (row['name'], row['source'])),
        })
    require(observed_manifests == declared_manifests, 'Cargo omitted a declared workspace manifest')
    return {
        'schema': 'trnm-cargo-source-inventory-v1',
        'source_commit': head, 'source_tree': git(root, 'rev-parse', 'HEAD^{tree}'),
        'workspace_manifest': (workspace / 'Cargo.toml').relative_to(root).as_posix(),
        'workspace_lock': (workspace / 'Cargo.lock').relative_to(root).as_posix(),
        'workspace_manifest_git_blob': workspace_blob, 'lock_git_blob': lock_blob,
        'package_count': len(reports), 'packages': reports,
        'scope': 'cargo-target-to-tracked-source-binding',
        'test_acceptance': 'not-assessed', 'production_authority': False, 'result': 'PASS',
    }


def select_workspace(root: pathlib.Path, name: str) -> pathlib.Path:
    require(name in {'trillionnium', 'contracts'}, 'unsupported workspace selection')
    return root / name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-commit', default=os.environ.get('TRNM_EXPECTED_SOURCE_SHA'))
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--workspace-root', choices=['trillionnium', 'contracts'], default='trillionnium')
    args = parser.parse_args()
    workspace = select_workspace(ROOT, args.workspace_root)
    expected = args.expected_commit or git(ROOT, 'rev-parse', 'HEAD')
    if args.output:
        require(not args.output.resolve().is_relative_to(ROOT), 'inventory output must be outside Git root')
    completed = subprocess.run(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--locked'],
        cwd=workspace, capture_output=True, text=True, check=True, timeout=60,
    )
    metadata = json.loads(completed.stdout, object_pairs_hook=strict_object, parse_constant=reject_constant)
    report = validate_metadata(ROOT, workspace, metadata, expected)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end='')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Cargo source inventory failed: {error}', file=sys.stderr)
        raise SystemExit(2) from error
