"""Physical complete growth State/index/recipient capacity qualification.

Fixtures stream to ordinary files and native sealed captures. The controller
does not materialize a million-row Python map or provide membership answers.
This is a separate qualification scope from the actual original Rust corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import time

from hia.platform.build import new_output, write_json
from hia.platform.continuity_store.build import Build
from hia.platform.continuity_store.native_io import run
from hia.platform.continuity_store.reference import canonical, configuration
from hia.platform.typed_store.cases import delta
from hia.platform.typed_store.native_io import file_hash

ROOT = Path(__file__).resolve().parents[3]
NATIVE_SECONDS = 240

def need(condition, message):
    if not condition:
        raise ValueError(message)

def record(stream, key, value):
    stream.write(struct.pack('<QQ', len(key), len(value)))
    stream.write(key)
    stream.write(value)

def growth_file(path, accounts, working, variant):
    need(accounts >= 1 and working >= 21, 'Invalid complete capacity fixture')
    with path.open('xb') as stream:
        stream.write(b'TKVSTR01' + struct.pack('<Q', accounts + working))
        record(stream, b'account:' + b'0' * 64, b'null')
        for index in range(1, accounts - 1):
            record(stream, f'account:{index:07}'.encode(), b'null')
        if accounts > 1:
            record(stream, b'account:' + b'f' * 64, b'null')
        record(stream, b'consensus-maintenance-v1', canonical(configuration(variant)['record']))
        for index in range(20):
            record(stream, f'reward:{index:02}'.encode(), canonical(
                {'maturity': 40 - index, 'amount': index,
                 'owner': ('f' if index & 1 and accounts > 1 else '0') * 64}))
        for index in range(working - 21):
            record(stream, f'zz:{index:05}'.encode(), b'null')
        stream.flush()
        os.fsync(stream.fileno())
    return {'bytes': path.stat().st_size, 'sha256': file_hash(path), 'rows': accounts + working}

def recipients_file(path, count, variant):
    with path.open('xb') as stream:
        stream.write(b'TKVSTR01' + struct.pack('<Q', count + 1))
        record(stream, b'consensus-maintenance-v1', canonical(configuration(variant)['record']))
        for index in range(count):
            record(stream, f'quota:{index:05}'.encode(), canonical({'remaining': 1, 'owner': f'{index:064x}'}))
        stream.flush()
        os.fsync(stream.fileno())
    return {'bytes': path.stat().st_size, 'sha256': file_hash(path), 'rows': count + 1}

def archive_file(path, output):
    before = {'bytes': path.stat().st_size, 'sha256': file_hash(path)}
    destination = output / (path.name + '.xz')
    with path.open('rb') as source, lzma.open(destination, 'wb', preset=1) as sink:
        while block := source.read(1 << 20):
            sink.write(block)
    digest, count = hashlib.sha256(), 0
    with lzma.open(destination, 'rb') as source:
        while block := source.read(1 << 20):
            digest.update(block)
            count += len(block)
    need(count == before['bytes'] and digest.hexdigest() == before['sha256'], 'Lossless fixture archive differs')
    return {'raw': before, 'archive_bytes': destination.stat().st_size,
        'archive_sha256': file_hash(destination), 'archive_path': str(destination)}

def main():
    if not __debug__:
        raise RuntimeError('Optimized qualification is not supported')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    start = time.monotonic_ns()
    controls, archived = [], []
    scope = {'schema': 'trnm.hia.continuity-growth-capacity.v1', 'original_rust_large_extent': 'NOT_RUN',
        'maximum_rows': 1065536, 'maximum_permanent_accounts': 1000000, 'maximum_working_keys': 65536,
        'gsc2_root': False, 'complete_node': False, 'physical_power_loss': False,
        'host_state_membership_algorithm': False, 'fresh_process_is_not_cache_eviction': True,
        'successful_account_lookups': ['first account: zero identity', 'last account: full f identity']}
    build_receipt = None
    try:
        build = Build(output / 'build', ROOT)
        executable, build_receipt = build.build()
        def execute(name, source, *, variant, height, code, expected=None):
            source_identity = {'bytes': source.stat().st_size, 'sha256': file_hash(source)}
            actual = run(executable, output / name, source, delta(()), variant=variant, height=height,
                root=False, observe=False, retain_bytes=False, timeout=NATIVE_SECONDS)
            checks = {'process': not actual['timed_out'] and not actual['gate_errors'] and actual['inputs_unchanged'],
                'code': actual['exit'] == code, 'source_unchanged': source_identity == {
                    'bytes': source.stat().st_size, 'sha256': file_hash(source)}}
            if code == 0:
                receipt = actual.get('receipt', {})
                checks.update(output=actual['output_bytes'] == source_identity['bytes']
                    and actual['output_sha256'] == source_identity['sha256'],
                    capacity=receipt.get('continuity') == expected,
                    context=receipt.get('context') == configuration(variant)['context'],
                    no_stderr=not actual['stderr_hex'], no_root=receipt.get('root_hex') == '0' * 64,
                    callbacks=receipt.get('progresses') == 6 + (expected['actual_keys'] + 255) // 256)
            else:
                checks.update(no_receipt=not actual['stdout_hex'], discarded=actual['output_bytes'] == 0,
                    diagnostic=len(actual.get('diagnostic', [])) == 7 and actual['diagnostic'][0] == code
                        and actual['diagnostic'][6] == 0)
            control = {'name': name, 'status': 'PASS' if all(checks.values()) else 'FAIL',
                'checks': checks, 'source': source_identity, 'actual': actual}
            controls.append(control)
            write_json(output / 'running-controls.json', {'controls': controls})
            need(control['status'] == 'PASS', 'Physical growth capacity mismatch: ' + name + ' ' + json.dumps(checks))
            build.check_sources()
            return actual
        full = output / 'maximum-state.kv'
        full_identity = growth_file(full, 1000000, 65536, 3)
        expected = dict(variant=3, height=20, actual_keys=1065536, credit_account_reserve=0,
            archive_reserve=0, reward_queue_reserve=0, required_keys=1065536, accounts=1000000,
            working_keys=65536, reward_heights=20, maturity=20)
        produced = execute('complete-maximum', full, variant=3, height=20, code=0, expected=expected)
        cold_source = Path(produced['output_path'])
        execute('fresh-process-complete-cold', cold_source, variant=3, height=20, code=0, expected=expected)
        archived.append(archive_file(full, output))
        # Corrupt the actual final physical byte after successful complete cold
        # validation. No earlier valid parse, index or answer is reused.
        with full.open('r+b') as stream:
            stream.seek(-1, os.SEEK_END)
            need(stream.read(1) == b'l', 'Unexpected last fixture byte')
            stream.seek(-1, os.SEEK_END)
            stream.write(b'x')
            stream.flush()
            os.fsync(stream.fileno())
        execute('corrupt-last-byte', full, variant=3, height=20, code=83)
        with full.open('r+b') as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b'l')
            stream.seek(8)
            stream.write(struct.pack('<Q', 1065537))
            stream.seek(0, os.SEEK_END)
            record(stream, b'zz:99999', b'null')
            stream.flush()
            os.fsync(stream.fileno())
        execute('row-1065537', full, variant=3, height=20, code=84)
        for name, accounts, working, variant in [('account-1000001', 1000001, 21, 2),
                ('working-65537', 999999, 65537, 3)]:
            source = output / (name + '.kv')
            growth_file(source, accounts, working, variant)
            execute(name, source, variant=variant, height=20, code=95)
            archived.append(archive_file(source, output))
        recipients = output / 'exact-recipients.kv'
        recipients_file(recipients, 65515, 2)
        expected = dict(variant=2, height=0, actual_keys=65516, credit_account_reserve=65515,
            archive_reserve=0, reward_queue_reserve=20, required_keys=131051, accounts=0,
            working_keys=65516, reward_heights=0, maturity=20)
        execute('65515-exact-recipient-identities', recipients, variant=2, height=0, code=0, expected=expected)
        archived.append(archive_file(recipients, output))
        build.check_sources()
        report = dict(scope, status='PASS', controls=controls, control_count=len(controls), build=build_receipt,
            original_full_state=full_identity, archives=archived, wall_ns=time.monotonic_ns() - start,
            source_inputs_stable=True)
        write_json(output / 'report.json', report)
        print(json.dumps({'status': 'PASS', 'controls': len(controls), 'wall_seconds': report['wall_ns'] / 1e9,
            'report': str(output / 'report.json')}))
        return 0
    except BaseException as error:
        write_json(output / 'report.json', dict(scope, status='FAIL', error=repr(error),
            controls=controls, archives=archived, build=build_receipt, wall_ns=time.monotonic_ns() - start))
        raise

if __name__ == '__main__':
    raise SystemExit(main())
