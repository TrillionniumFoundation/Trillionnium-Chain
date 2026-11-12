#!/usr/bin/env python3
"""Project one verified historical runtime snapshot into a new private namespace.

This is a new preparation tool. It preserves historical non-path metadata and
expected bytes; its receipt is not a fresh historical capture or model admission.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

ROOT = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
CONTROL = Path(str(ROOT) + '-control')
BASE = Path(str(ROOT) + '-validation')
OUT = BASE / 'private-runtime02-projection'
NEW = Path('/home/qq/work/chain-bt-4a0b-runtime02')
OLD_ENV = Path('/home/qq/hepta-smollm2-weight-research-20261103/ci-env')
OLD_PYTHON = Path('/home/qq/hepta-smollm2-weight-research-20261103/python/cpython-3.12.16-linux-x86_64-gnu')
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
SOURCE_SHA = 'fb6fe559317f7c3cd6ef504581b89e7d8229a7c700d3c71b61099a32d443cec9'
SNAPSHOT_SHA = 'e87a3658675836c130ba2a97a805bc6d86cc435135e72f4b6e40747e9271b9eb'
CONTRACT_SHA = 'b947b8eaee6dcf4f2f932c22df7e4d989f27171702314e59b03f391ceebe7bbc'
PROBE = CONTROL / 'private-runtime-probe-v1.py'
PROBE_SHA = 'b36333de24d3128eb619baa0cfb1417901d2b483f0e29b922cf5609d8b68bbef'
TOP_LEVEL = {'actual_model_execution', 'distributions', 'files', 'immutable_held_runtime_closure',
             'installation_report_sha256', 'managed_inventory', 'observed_environment_isolated',
             'platform', 'prefix', 'preflight_import_probe_mapped_files', 'production_qualification',
             'python', 'requirements_sha256', 'schema', 'stdlib_root', 'wheels'}
EXTRAS = {
    'ensurepip/__pycache__/__init__.cpython-312.pyc': '2ba42de6735d44c3dc740a47babdcee421d4ac570b5772e7cfbabaa0df249919',
    'ensurepip/__pycache__/__main__.cpython-312.pyc': 'ba0156566977eecf5383dd49ac997b58d5676e461654d3a048831d8fa64a52b7',
    'sqlite3/__pycache__/__init__.cpython-312.pyc': '7245844a4f9b2de3ff8e2cd98dbd7e461c02b4ca70faa5238297658d435f6ef5',
    'sqlite3/__pycache__/dbapi2.cpython-312.pyc': '08551a87583a305e44bc538a91e97b464d729040de758d336acbfcefebc2d0d3',
    'venv/__pycache__/__init__.cpython-312.pyc': '885e42502ef976777acb36ff7343c144d331faab6cc782d9ae754d86ae6eb78b',
    'venv/__pycache__/__main__.cpython-312.pyc': '54429c77331e3496d8745399849ca9f4cfa218e3241871eafa72c44dfc54f91a',
}
os.umask(0o077)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + chr(10)).encode()


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def identity():
    value = {key: subprocess.check_output(['/usr/bin/git', *args], cwd=ROOT, text=True).strip()
             for key, args in {'head': ['rev-parse', 'HEAD'], 'tree': ['rev-parse', 'HEAD^{tree}'],
                               'status': ['status', '--porcelain', '--untracked-files=all']}.items()}
    assert value == {'head': HEAD, 'tree': TREE, 'status': ''}, value
    return value


def mapped(path):
    path = Path(path)
    for old, new in ((OLD_ENV, NEW / 'env'), (OLD_PYTHON, NEW / 'python')):
        if path == old or path.is_relative_to(old):
            return str(new / path.relative_to(old))
    return str(path)


def projected(original):
    value = copy.deepcopy(original)
    value['prefix'] = mapped(original['prefix'])
    value['stdlib_root'] = mapped(original['stdlib_root'])
    value['python']['executable'] = mapped(original['python']['executable'])
    for field in ('files', 'preflight_import_probe_mapped_files'):
        value[field] = {mapped(path): checksum for path, checksum in original[field].items()}
        assert len(value[field]) == len(original[field]), ('projection collision', field)
    value['managed_inventory'] = sorted(mapped(path) for path in original['managed_inventory'])
    assert len(set(value['managed_inventory'])) == len(original['managed_inventory'])
    unchanged = TOP_LEVEL - {'prefix', 'stdlib_root', 'python', 'files', 'managed_inventory',
                             'preflight_import_probe_mapped_files'}
    assert all(value[key] == original[key] for key in unchanged)
    assert {k: v for k, v in value['python'].items() if k != 'executable'} == {
        k: v for k, v in original['python'].items() if k != 'executable'}
    inverse = {mapped(path): path for path in original['files']}
    assert {inverse[path]: checksum for path, checksum in value['files'].items()} == original['files']
    assert sorted(inverse[path] for path in value['managed_inventory']) == original['managed_inventory']
    assert {inverse[path]: checksum for path, checksum in value['preflight_import_probe_mapped_files'].items()} == original['preflight_import_probe_mapped_files']
    return value


def original_functions(path):
    raw = path.read_bytes(); assert hashlib.sha256(raw).hexdigest() == CONTRACT_SHA
    module = ast.parse(raw)
    selected = [node for node in module.body if isinstance(node, ast.FunctionDef) and
                node.name in ('require', 'managed_inventory', 'file_digest')]
    assert len(selected) == 3
    scope = {'Path': Path, 'os': os, 'stat': stat, 'hashlib': hashlib,
             'MAX_FILES': 100000, 'MAX_BYTES': 16 * 1024**3}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), scope)
    return scope


def verify_members(files, file_digest):
    rows = []; total = 0
    for path, expected in sorted(files.items()):
        actual, size = file_digest(path)
        assert actual == expected, ('committed bytes changed', path)
        total += size; assert total <= 16 * 1024**3
        rows.append({'path': path, 'sha256': expected, 'bytes': size})
    return rows, total


def copy_regular(source, target, expected):
    assert not source.is_symlink() and source.parent.resolve(strict=True) == source.parent
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(source, flags), 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 16 * 1024**3
        checksum = hashlib.sha256(); count = 0
        with target.open('xb') as outgoing:
            for block in iter(lambda: incoming.read(1048576), b''):
                count += len(block)
                assert count <= before.st_size, ('source grew during copy', str(source))
                outgoing.write(block); checksum.update(block)
            outgoing.flush(); os.fsync(outgoing.fileno())
        after = os.fstat(incoming.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    assert all(getattr(before, key) == getattr(after, key) for key in fields)
    assert count == before.st_size and checksum.hexdigest() == expected
    os.chmod(target, stat.S_IMODE(before.st_mode) & 0o777)
    return count


def main():
    started = time.monotonic()
    assert len(sys.argv) == 1
    source_path = CONTROL / 'source-inputs.native-v2.json'
    source_raw = source_path.read_bytes()
    probe_raw = PROBE.read_bytes()
    assert hashlib.sha256(source_raw).hexdigest() == SOURCE_SHA
    assert hashlib.sha256(probe_raw).hexdigest() == PROBE_SHA
    spec = json.loads(source_raw)
    old_snapshot_path = Path(spec['environment']['runtime/runtime-snapshot.json']['path'])
    original_raw = old_snapshot_path.read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == SNAPSHOT_SHA
    original = json.loads(original_raw)
    assert set(original) == TOP_LEVEL and original['schema'] == 'hepta-controlled-cold-runtime-snapshot-v2'
    assert set(original['python']) == {'abi', 'executable', 'implementation', 'version'}
    assert len(original['files']) == 22435 and len(original['managed_inventory']) == 22421
    assert original['prefix'] == str(OLD_ENV) and original['stdlib_root'] == str(OLD_PYTHON / 'lib/python3.12')
    assert all(original['files'].get(path) == checksum for path, checksum in original['preflight_import_probe_mapped_files'].items())
    assert Path(sys.executable).resolve(strict=True) == OLD_PYTHON / 'bin/python3.12'
    assert digest(sys.executable) == spec['python']['sha256']
    assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
    assert not OUT.exists() and not NEW.exists() and not NEW.is_symlink()
    assert NEW.parent.resolve(strict=True) == NEW.parent
    assert not Path(spec['output']).exists() and not Path(spec['output'] + '-wrapper').exists()
    before = identity()
    OUT.mkdir(mode=0o700)
    report = {'schema': 'trnm.bt-verified-private-runtime-projection.v1', 'source': HEAD,
              'before_identity': before, 'observer_sha256': digest(Path(__file__)),
              'probe_sha256': PROBE_SHA, 'original_snapshot_sha256': SNAPSHOT_SHA,
              'original_snapshot_path': str(old_snapshot_path), 'new_root': str(NEW),
              'path_field_allowlist': ['prefix', 'stdlib_root', 'python.executable', 'files.keys',
                                       'managed_inventory.items', 'preflight_import_probe_mapped_files.keys'],
              'historical_non_path_metadata_preserved': False,
              'historical_probe_map_is_projected_provenance_not_new_observation': True,
              'full_sealed_runtime_import_admission_performed': False,
              'model_loaded': False, 'model_executed': False, 'native_operation_started': False,
              'hepta_final_use': False, 'production_activation': False, 'passed': False,
              'started_unix_ns': time.time_ns()}
    try:
        contract = ROOT / 'scripts/llm_python_runtime_contract.py'
        functions = original_functions(contract)
        file_digest, inventory = functions['file_digest'], functions['managed_inventory']
        extra_files = {str(OLD_PYTHON / 'lib/python3.12' / path): value for path, value in EXTRAS.items()}
        old_inventory = inventory(original)
        assert set(old_inventory) - set(original['managed_inventory']) == set(extra_files)
        assert set(original['managed_inventory']) <= set(old_inventory)
        extra_before, _ = verify_members(extra_files, file_digest)
        original_before, original_total = verify_members(original['files'], file_digest)
        assert original_total == 1112520241
        unchanged_payload = []
        for category in ('model', 'environment'):
            for logical, item in sorted(spec[category].items()):
                if category == 'environment' and logical == 'runtime/runtime-snapshot.json':
                    continue
                actual, size = file_digest(item['path'])
                assert actual == item['sha256'], ('unchanged payload pin', category, logical)
                unchanged_payload.append({'category': category, 'logical': logical,
                                          'path': item['path'], 'sha256': actual, 'bytes': size})
        assert len(unchanged_payload) == 29
        unchanged_payload_bytes = sum(row['bytes'] for row in unchanged_payload)
        unchanged_payload_chunks = sum((row['bytes'] + 4194303) // 4194304 for row in unchanged_payload)
        assert unchanged_payload_bytes == 272530091
        write(OUT / 'unchanged-payload-members.json', encoded(unchanged_payload))
        write(OUT / 'original-members-before.json', encoded(original_before))
        projected_value = projected(original)
        report['historical_non_path_metadata_preserved'] = True
        expected_snapshot = encoded(projected_value)
        expected_sha = hashlib.sha256(expected_snapshot).hexdigest()
        expected_map = [{'old_path': path, 'selected_path': mapped(path), 'sha256': checksum,
                         'external_member': mapped(path) == path}
                        for path, checksum in sorted(original['files'].items())]
        assert len({row['selected_path'] for row in expected_map}) == 22435
        write(OUT / 'expected-byte-map.json', encoded(expected_map))
        write(OUT / 'expected-projection.json', expected_snapshot)
        report['expected_projection_sha256'] = expected_sha
        report['expected_snapshot_bytes'] = len(expected_snapshot)
        report['expected_byte_map_sha256'] = digest(OUT / 'expected-byte-map.json')
        report['original_snapshot_members'] = len(expected_map)
        report['original_snapshot_member_bytes'] = original_total
        links = []; regular = []; external = []
        for path, checksum in sorted(original['files'].items()):
            old, new = Path(path), Path(mapped(path))
            if old == new:
                external.append({'path': path, 'sha256': checksum}); continue
            assert old.parent.resolve(strict=True) == old.parent, ('unsupported parent alias', path)
            if old.is_symlink():
                resolved = old.resolve(strict=True)
                assert str(resolved) in original['files'] and original['files'][str(resolved)] == checksum
                target = Path(mapped(resolved))
                assert target != resolved or not (resolved.is_relative_to(OLD_ENV) or resolved.is_relative_to(OLD_PYTHON))
                links.append({'old_path': path, 'new_path': str(new), 'old_link_text': os.readlink(old),
                              'old_resolved_target': str(resolved), 'new_resolved_target': str(target),
                              'payload_sha256': checksum})
            else:
                regular.append((old, new, checksum))
        assert len(links) == 3 and len(external) == 13
        NEW.mkdir(mode=0o700); assert NEW.resolve(strict=True) == NEW
        copied_bytes = sum(copy_regular(old, new, checksum) for old, new, checksum in regular)
        for item in links:
            old, new = Path(item['old_path']), Path(item['new_path'])
            target, text = Path(item['new_resolved_target']), item['old_link_text']
            assert old.is_symlink() and os.readlink(old) == text
            assert str(old.resolve(strict=True)) == item['old_resolved_target']
            new.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if Path(text).is_absolute():
                selected_text = str(target)
            elif (new.parent / text).resolve(strict=False) == target:
                selected_text = text
            else:
                selected_text = os.path.relpath(target, new.parent)
            new.symlink_to(selected_text)
            assert new.resolve(strict=True) == target
            assert file_digest(new)[0] == item['payload_sha256']
            item['new_link_text'] = selected_text
        assert inventory(projected_value) == projected_value['managed_inventory']
        new_members, new_total = verify_members(projected_value['files'], file_digest)
        assert new_total == original_total
        write(OUT / 'projected-members-before-probe.json', encoded(new_members))
        snapshot_path = OUT / 'runtime-snapshot.projected.v2.json'
        write(snapshot_path, expected_snapshot)
        assert digest(snapshot_path) == expected_sha
        private_python = NEW / 'python/bin/python3.12'
        cache = OUT / 'unused-projection-probe-bytecode'
        assert not cache.exists()
        env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': str(BASE / 'tmp')}
        argv = [str(private_python), '-I', '-S', '-B', '-X', 'pycache_prefix=' + str(cache),
                '-c', probe_raw.decode(), str(snapshot_path), expected_sha]
        with (OUT / 'private-python-probe.stdout').open('xb') as stdout, (OUT / 'private-python-probe.stderr').open('xb') as stderr:
            process = subprocess.run(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, timeout=180)
        report['probe_exit_code'] = process.returncode
        assert process.returncode == 0
        probe = json.loads((OUT / 'private-python-probe.json').read_bytes())
        assert probe['passed'] is True and probe['snapshot_sha256'] == expected_sha
        new_after, total_after = verify_members(projected_value['files'], file_digest)
        assert new_after == new_members and total_after == original_total
        assert inventory(projected_value) == projected_value['managed_inventory']
        original_after, original_after_total = verify_members(original['files'], file_digest)
        assert original_after == original_before and original_after_total == original_total
        assert inventory(original) == old_inventory
        extra_after, _ = verify_members(extra_files, file_digest)
        assert extra_after == extra_before
        write(OUT / 'original-members-after.json', encoded(original_after))
        write(OUT / 'projected-members-after-probe.json', encoded(new_after))
        report.update(snapshot={'path': str(snapshot_path), 'bytes': len(expected_snapshot), 'sha256': expected_sha},
                      copied_regular_files=len(regular), copied_regular_bytes=copied_bytes,
                      symlinks=links, external_members=external, extras_unchanged=extra_after,
                      old_and_new_expected_bytes_verified=True, new_inventory_exact=True,
                      old_runtime_inventory_unchanged=True, probe_receipt_sha256=digest(OUT / 'private-python-probe.json'),
                      python={'path': str(private_python), 'sha256': digest(private_python)},
                      snapshot_chunks=(len(expected_snapshot) + 4194303) // 4194304,
                      prospective_payload_bytes=unchanged_payload_bytes + len(expected_snapshot),
                      prospective_total_chunks=unchanged_payload_chunks + (len(expected_snapshot) + 4194303) // 4194304,
                      passed=True)
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['traceback'] = traceback.format_exc()
        report['passed'] = False
    finally:
        try:
            report['after_identity'] = identity()
            assert report['after_identity'] == before
            assert digest(source_path) == SOURCE_SHA and digest(old_snapshot_path) == SNAPSHOT_SHA
            assert digest(PROBE) == PROBE_SHA
            assert not Path(spec['output']).exists() and not Path(spec['output'] + '-wrapper').exists()
            report['source_and_original_input_unchanged'] = True
        except BaseException as error:
            report['end_error'] = type(error).__name__ + ': ' + str(error)
            report['passed'] = False
        report['completed'] = True; report['elapsed_seconds'] = time.monotonic() - started
        write(OUT / 'summary.json', encoded(report))
        print(json.dumps({'completed': True, 'passed': report['passed'], 'output': str(OUT),
                          'snapshot': report.get('snapshot'), 'native_operation_started': False}, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
