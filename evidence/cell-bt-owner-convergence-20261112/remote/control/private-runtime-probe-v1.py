#!/usr/bin/env python3
"""Observe the projected interpreter and original inventory guard; no model/import admission."""
import hashlib
import json
import os
from pathlib import Path
import sys
import sysconfig
import time

ROOT = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
BASE = Path(str(ROOT) + '-validation')
OUT = BASE / 'private-runtime02-projection'
NEW = Path('/home/qq/work/chain-bt-4a0b-runtime02')
OLD_ENV = '/home/qq/hepta-smollm2-weight-research-20261103/ci-env'
OLD_PYTHON = '/home/qq/hepta-smollm2-weight-research-20261103/python/cpython-3.12.16-linux-x86_64-gnu'
CONTRACT_SHA = 'b947b8eaee6dcf4f2f932c22df7e4d989f27171702314e59b03f391ceebe7bbc'
PYTHON_SHA = '23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def configuration():
    return {'prefix': sys.prefix, 'exec_prefix': sys.exec_prefix,
            'base_prefix': sys.base_prefix, 'base_exec_prefix': sys.base_exec_prefix,
            'sys_path': list(sys.path), 'paths': sysconfig.get_paths(),
            'variables': {key: sysconfig.get_config_var(key) for key in
                          ('base', 'installed_base', 'prefix', 'exec_prefix', 'SOABI', 'LIBDIR', 'LDLIBRARY')}}


def old_path(path):
    return any(path == root or path.startswith(root + '/') for root in (OLD_ENV, OLD_PYTHON))


def main():
    started = time.monotonic()
    assert len(sys.argv) == 3
    snapshot_path, expected_sha = Path(sys.argv[1]), sys.argv[2]
    assert snapshot_path == OUT / 'runtime-snapshot.projected.v2.json'
    assert digest(snapshot_path) == expected_sha
    value = json.loads(snapshot_path.read_bytes())
    assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
    assert isinstance(sys.pycache_prefix, str) and Path(sys.pycache_prefix).is_absolute()
    assert not Path(sys.pycache_prefix).exists()
    assert set(os.environ) == {'LANG', 'LC_ALL', 'TMPDIR'}
    assert Path('/proc/self/exe').resolve(strict=True) == NEW / 'python/bin/python3.12'
    assert Path(sys.executable).resolve(strict=True) == NEW / 'python/bin/python3.12'
    assert digest(sys.executable) == PYTHON_SHA
    assert sys.version == value['python']['version']
    assert sys.implementation.name == 'cpython' and value['python']['implementation'] == 'CPython'
    assert sysconfig.get_config_var('SOABI') == value['python']['abi']
    before = configuration()
    assert Path(sys.base_prefix) == NEW / 'python'
    contract = ROOT / 'scripts/llm_python_runtime_contract.py'
    raw = contract.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CONTRACT_SHA
    scope = {'__name__': '_original_contract_projection_probe', '__file__': str(contract)}
    exec(compile(raw, str(contract), 'exec', dont_inherit=True), scope)
    loaded = scope['load_snapshot'](snapshot_path, expected_sha)
    assert loaded == value
    scope['configure'](value)
    scope['verify_files'](value)
    after = configuration()
    assert after['prefix'] == after['exec_prefix'] == str(NEW / 'env')
    assert all(not old_path(path) for path in after['sys_path'])
    assert Path(after['paths']['stdlib']) == NEW / 'python/lib/python3.12'
    assert Path(after['paths']['purelib']) == NEW / 'env/lib/python3.12/site-packages'
    origins = []
    for name, module in sorted(sys.modules.items()):
        origin = getattr(module, '__file__', None)
        if origin is None or origin.startswith('<'):
            continue
        path = str(Path(origin).resolve(strict=True))
        assert not old_path(path), ('old runtime module origin', name, path)
        assert value['files'].get(path) == digest(path), ('uncommitted module origin', name, path)
        origins.append({'module': name, 'origin': origin, 'resolved': path,
                        'sha256': value['files'][path]})
    maps = Path('/proc/self/maps').read_text()
    executable = set()
    for line in maps.splitlines():
        row = line.split(None, 5)
        if len(row) == 6 and 'x' in row[1] and row[5].startswith('/'):
            assert not row[5].endswith(' (deleted)'), row[5]
            path = str(Path(row[5]).resolve(strict=True))
            assert not old_path(path), ('old runtime executable mapping', path)
            assert value['files'].get(path) == digest(path), ('uncommitted executable mapping', path)
            executable.add(path)
    assert not Path(sys.pycache_prefix).exists()
    report = {'schema': 'trnm.bt-private-runtime-physical-probe.v1', 'passed': True,
              'snapshot_sha256': expected_sha, 'python_sha256': PYTHON_SHA,
              'python_executable': str(Path(sys.executable).resolve(strict=True)),
              'python_version': sys.version, 'original_contract_sha256': CONTRACT_SHA,
              'configuration_before': before, 'configuration_after': after,
              'module_origins': origins, 'executable_mappings': sorted(executable),
              'original_configure_and_verify_files_passed': True,
              'historical_probe_map_not_used_as_actual_mapping_evidence': True,
              'full_sealed_runtime_import_admission_performed': False,
              'model_loaded': False, 'model_executed': False, 'native_operation_started': False,
              'hepta_final_use': False, 'production_activation': False,
              'elapsed_seconds': time.monotonic() - started}
    with (OUT / 'private-python-probe.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write(chr(10)); stream.flush(); os.fsync(stream.fileno())
    with (OUT / 'private-python-probe.maps').open('x') as stream:
        stream.write(maps); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'passed': True, 'snapshot_sha256': expected_sha,
                      'original_configure_and_verify_files_passed': True,
                      'module_count': len(origins), 'executable_mapping_count': len(executable),
                      'native_operation_started': False}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
