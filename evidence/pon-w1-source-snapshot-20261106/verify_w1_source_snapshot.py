#!/usr/bin/env python3
"""Independent, deterministic source-map read-race controls; no prover/network.

The baseline is loaded from a Git object and the candidate from a workspace file.
Only temporary fixtures are mutated.  Archive replacement occurs at tarfile.open,
after the input has been hashed/read and before parsing begins, for both versions.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
from unittest.mock import patch


BASE = 'd9fd07c473998bd236207c1b7db4233f0eafd7fe'
REPO = Path(__file__).resolve().parents[2]
SCRIPT = Path('scripts/w1_profile_source_map.py')
PACKAGE = 'risc0-core-3.0.2'
MEMBER = 'src/field/baby_bear.rs'
ORIGINAL = b'ORIGINAL LOCKED SOURCE\n'
ALTERED = b'ALTERED AFTER ARCHIVE HASH; LONGER SOURCE\n'
VCS = b'{"git":{"sha1":"0000000000000000000000000000000000000000"},"path_in_vcs":"fixture"}\n'
REAL_TAR_OPEN = tarfile.open
REAL_PATH_OPEN = Path.open


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_module(name: str, code: bytes, path: Path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(code, str(path), 'exec'), module.__dict__)
    return module


def archive_bytes(package: str, payloads: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with REAL_TAR_OPEN(fileobj=stream, mode='w') as archive:
        for relative, data in payloads.items():
            info = tarfile.TarInfo(f'{package}/{relative}')
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def fixture(root: Path, module):
    src, cache = root / 'src', root / 'cache'
    cache.mkdir()
    source = src / PACKAGE / MEMBER
    source.parent.mkdir(parents=True)
    source.write_bytes(ORIGINAL)
    (src / PACKAGE / '.cargo_vcs_info.json').write_bytes(VCS)
    archive = cache / f'{PACKAGE}.crate'
    original_archive = archive_bytes(PACKAGE, {MEMBER: ORIGINAL, '.cargo_vcs_info.json': VCS})
    archive.write_bytes(original_archive)
    locked = {
        'name': 'risc0-core', 'version': '3.0.2',
        'source': module.REGISTRY_SOURCE, 'checksum': sha(original_archive),
    }
    return src, cache, source, archive, locked


def inspect_result(module, src, cache, locked):
    try:
        record, files = module.inspect_package(src, cache, PACKAGE, locked)
    except module.SourceMapError as error:
        return {'status': 'REFUSED', 'error': str(error)}
    item = files[f'{PACKAGE}/{MEMBER}']
    return {
        'status': 'ACCEPTED',
        'archive_matches_lock': record['archive_matches_lock'],
        'reported_archive_sha256': record['observed_archive_sha256'],
        'reported_source_sha256': item['sha256'],
        'reported_source_bytes': item['bytes'],
    }


def archive_control(module, mutation: str):
    with tempfile.TemporaryDirectory(prefix='w1-map-archive-') as temp:
        src, cache, source, archive, locked = fixture(Path(temp), module)
        replacement = archive_bytes(PACKAGE, {MEMBER: ALTERED, '.cargo_vcs_info.json': VCS})
        swapped = False

        def replace_before_parse(*args, **kwargs):
            nonlocal swapped
            if not swapped and mutation != 'none':
                swapped = True
                archive.write_bytes(replacement)
                if mutation == 'archive_and_local':
                    source.write_bytes(ALTERED)
            return REAL_TAR_OPEN(*args, **kwargs)

        with patch.object(module.tarfile, 'open', replace_before_parse):
            result = inspect_result(module, src, cache, locked)
        result.update({
            'mutation': mutation,
            'mutation_performed': swapped,
            'locked_archive_sha256': locked['checksum'],
            'archive_path_sha256_after': sha(archive.read_bytes()),
            'original_source_sha256': sha(ORIGINAL),
            'altered_source_sha256': sha(ALTERED),
            'source_path_sha256_after': sha(source.read_bytes()),
        })
        if result['status'] == 'ACCEPTED':
            result['accepted_original_locked_source'] = result['reported_source_sha256'] == sha(ORIGINAL)
        return result


@contextmanager
def replace_after_read(target: Path, replacement: bytes):
    """Replace the path after its first binary read context closes."""
    state = {'replaced': False, 'read_contexts': 0}

    class ReadContext:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            result = self.stream.__exit__(exc_type, exc, tb)
            if exc_type is None and not state['replaced']:
                state['replaced'] = True
                target.write_bytes(replacement)
            return result

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def open_with_replacement(path, mode='r', *args, **kwargs):
        stream = REAL_PATH_OPEN(path, mode, *args, **kwargs)
        if path == target and mode == 'rb' and not state['replaced']:
            state['read_contexts'] += 1
            return ReadContext(stream)
        return stream

    with patch.object(Path, 'open', open_with_replacement):
        yield state


def local_size_control(module):
    with tempfile.TemporaryDirectory(prefix='w1-map-local-') as temp:
        src, cache, source, archive, locked = fixture(Path(temp), module)
        with replace_after_read(source, ALTERED) as state:
            result = inspect_result(module, src, cache, locked)
        result.update({
            'mutation_performed': state['replaced'],
            'original_source_bytes': len(ORIGINAL),
            'source_path_bytes_after': source.stat().st_size,
        })
        if result['status'] == 'ACCEPTED':
            result['digest_is_original_snapshot'] = result['reported_source_sha256'] == sha(ORIGINAL)
            result['size_is_original_snapshot'] = result['reported_source_bytes'] == len(ORIGINAL)
        return result


def json_snapshot_control(module, file_kind: str):
    original = json.dumps({'snapshot': 'original', 'kind': file_kind}, sort_keys=True).encode()
    replacement = json.dumps({'snapshot': 'replaced', 'kind': file_kind}, sort_keys=True).encode()
    with tempfile.TemporaryDirectory(prefix='w1-map-json-') as temp:
        path = Path(temp) / f'{file_kind}.json'
        path.write_bytes(original)
        with replace_after_read(path, replacement) as state:
            if hasattr(module, 'read_json_snapshot'):
                parsed, reported = module.read_json_snapshot(path)
            else:
                # Exact baseline build_profile flow: parse first; hash path later.
                parsed = module.read_json(path)
                reported = module.sha_file(path)
        return {
            'parsed_snapshot': parsed['snapshot'],
            'reported_sha256': reported,
            'original_sha256': sha(original),
            'replacement_sha256': sha(replacement),
            'digest_matches_parsed_snapshot': reported == sha(original),
            'mutation_performed': state['replaced'],
        }


def lock_bytes(module, checksum: str) -> bytes:
    rows = ['version = 4\n']
    for package in module.SELECTED:
        name, version = package.rsplit('-', 1)
        rows.append(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            f'source = "{module.REGISTRY_SOURCE}"\nchecksum = "{checksum}"\n'
        )
    return '\n'.join(rows).encode()


def lock_snapshot_control(module):
    original = lock_bytes(module, '1' * 64)
    replacement = lock_bytes(module, '2' * 64)
    with tempfile.TemporaryDirectory(prefix='w1-map-lock-') as temp:
        path = Path(temp) / 'Cargo.lock'
        path.write_bytes(original)
        with replace_after_read(path, replacement) as state:
            if hasattr(module, 'load_locked_packages_snapshot'):
                parsed, reported = module.load_locked_packages_snapshot(path)
            else:
                # Exact baseline build_profile flow: parse first; hash path later.
                parsed = module.load_locked_packages(path)
                reported = module.sha_file(path)
        return {
            'parsed_checksums': sorted({item['checksum'] for item in parsed.values()}),
            'reported_sha256': reported,
            'original_sha256': sha(original),
            'replacement_sha256': sha(replacement),
            'digest_matches_parsed_snapshot': reported == sha(original),
            'mutation_performed': state['replaced'],
        }


def source_reread_control(module):
    """Mutate first semantic input after package custody checks; fail before parsing."""
    with tempfile.TemporaryDirectory(prefix='w1-map-reread-') as temp:
        root = Path(temp)
        repo, cargo = root / 'repo', root / 'cargo'
        src = cargo / 'registry/src/index.crates.io-fixture'
        cache = cargo / 'registry/cache/index.crates.io-fixture'
        cache.mkdir(parents=True)
        rows = ['version = 4\n']
        for package, selected in module.SELECTED.items():
            payloads = {name: b'// synthetic source for custody-only control\n' for name in selected}
            payloads['.cargo_vcs_info.json'] = VCS
            for name, value in payloads.items():
                local = src / package / name
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(value)
            packed = archive_bytes(package, payloads)
            (cache / f'{package}.crate').write_bytes(packed)
            name, version = package.rsplit('-', 1)
            rows.append(
                f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                f'source = "{module.REGISTRY_SOURCE}"\nchecksum = "{sha(packed)}"\n'
            )
        lock_path = repo / 'formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.lock'
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text('\n'.join(rows))
        first_source = src / 'risc0-zkp-3.0.5/src/lib.rs'
        original_inspect = module.inspect_package
        checked = 0

        def inspect_then_replace(*args, **kwargs):
            nonlocal checked
            result = original_inspect(*args, **kwargs)
            checked += 1
            if checked == len(module.SELECTED):
                first_source.write_bytes(b'// replaced after custody check\n')
            return result

        with patch.object(module, 'inspect_package', inspect_then_replace):
            try:
                module.build_profile(repo, cargo)
            except module.SourceMapError as error:
                return {
                    'status': 'REFUSED', 'error': str(error),
                    'packages_checked_before_mutation': checked,
                    'refused_at_source_digest_recheck': 'source changed during inspection' in str(error),
                }
        raise AssertionError('tampered semantic source unexpectedly accepted')


def assert_results(results):
    old, new = results['baseline'], results['candidate']
    for version in (old, new):
        assert version['unchanged']['status'] == 'ACCEPTED'
        assert version['unchanged']['accepted_original_locked_source'] is True
        assert version['source_reread']['refused_at_source_digest_recheck'] is True
    assert old['archive_and_local_replacement']['status'] == 'ACCEPTED'
    assert old['archive_and_local_replacement']['accepted_original_locked_source'] is False
    assert new['archive_and_local_replacement']['status'] == 'REFUSED'
    assert 'local source differs from locked archive' in new['archive_and_local_replacement']['error']
    assert old['archive_only_replacement']['status'] == 'REFUSED'
    assert new['archive_only_replacement']['status'] == 'ACCEPTED'
    assert new['archive_only_replacement']['accepted_original_locked_source'] is True
    for version in (old, new):
        assert version['local_size']['status'] == 'ACCEPTED'
        assert version['local_size']['digest_is_original_snapshot'] is True
    assert old['local_size']['size_is_original_snapshot'] is False
    assert new['local_size']['size_is_original_snapshot'] is True
    for key in ('lock_snapshot', 'history_snapshot', 'manifest_snapshot'):
        assert old[key]['digest_matches_parsed_snapshot'] is False
        assert new[key]['digest_matches_parsed_snapshot'] is True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    old_code = subprocess.check_output(['git', '-C', str(args.repo), 'show', f'{BASE}:{SCRIPT}'])
    new_path = args.repo / SCRIPT
    new_code = new_path.read_bytes()
    modules = {
        'baseline': load_module('source_mapper_baseline', old_code, new_path),
        'candidate': load_module('source_mapper_candidate', new_code, new_path),
    }
    results = {
        'purpose': 'Independent source-evidence consistency controls; not a consensus, proof-soundness, or PQ qualification test.',
        'baseline_commit': BASE,
        'baseline_script_sha256': sha(old_code),
        'candidate_script_sha256': sha(new_code),
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Synthetic immutable-lock fixtures with deterministic path replacements. No source files, cached crates, or historical evidence are modified.',
    }
    for name, module in modules.items():
        results[name] = {
            'unchanged': archive_control(module, 'none'),
            'archive_and_local_replacement': archive_control(module, 'archive_and_local'),
            'archive_only_replacement': archive_control(module, 'archive_only'),
            'local_size': local_size_control(module),
            'lock_snapshot': lock_snapshot_control(module),
            'history_snapshot': json_snapshot_control(module, 'history'),
            'manifest_snapshot': json_snapshot_control(module, 'manifest'),
            'source_reread': source_reread_control(module),
        }
    assert_results(results)
    results['status'] = 'PASS'
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(json.dumps({
        'status': results['status'],
        'output': str(args.out),
        'candidate_script_sha256': results['candidate_script_sha256'],
        'baseline_archive_and_local': results['baseline']['archive_and_local_replacement']['status'],
        'candidate_archive_and_local': results['candidate']['archive_and_local_replacement']['status'],
        'baseline_metadata_consistent': False,
        'candidate_metadata_consistent': True,
        'source_reread_refused_in_both': True,
    }, indent=2))


if __name__ == '__main__':
    main()
