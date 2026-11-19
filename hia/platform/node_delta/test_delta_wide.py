"""Caller-extent controls for the actual native Delta transaction fixture."""
from pathlib import Path
import hashlib
import json
import os
import struct
import time

from native_support import Module
from test_delta import fixture, kv

HERE = Path(__file__).resolve().parent


def main():
    output = Path(os.environ.get('TRNM_DELTA_WIDE_OUTPUT', HERE / 'qualification-official-wide'))
    output.mkdir(mode=0o700)
    sources = {path: path.read_bytes() for path in (Path(__file__), HERE / 'test_delta.py')}
    module = Module(HERE / 'delta_fixture.hepta', output / 'build')
    receipts = []
    for name, disjoint in (('65536-existing-values', False), ('131072-disjoint-union', True)):
        before = {f'a{i:06}'.encode(): b'0' for i in range(65536)}
        if disjoint:
            after = {f'z{i:06}'.encode(): b'1' for i in range(65536)}
            rows = [(key, value, None) for key, value in before.items()]
            rows += [(key, None, value) for key, value in after.items()]
        else:
            after = {key: b'1' for key in before}
            rows = [(key, before[key], value) for key, value in after.items()]
        raw, used = fixture(before, rows)
        arguments = [raw, b'\xa5' * (len(raw) + 256), bytes(used) + b'\x6b' * 37]
        started = time.monotonic_ns()
        answer = module.call_many([arguments], timeout=60)[0]
        elapsed = time.monotonic_ns() - started
        want = kv(after)
        count = len(rows)
        header = struct.unpack('<9Q', answer['arguments'][1][8:80])
        assert answer['value'] == 256
        assert answer['arguments'][1][:8] == b'NDFOUT01'
        assert header == (256, 0, 0, 0, 3 + count + count // 256, count, count, len(want), 0)
        assert answer['arguments'][1][80:80 + len(want)] == want
        assert answer['arguments'][2][used:] == arguments[2][used:]
        receipts.append({'name': name, 'status': 'PASS', 'delta_rows': count,
            'before_rows': len(before), 'after_rows': len(after),
            'input_bytes': len(raw), 'context_bytes_used': used,
            'input_sha256': hashlib.sha256(raw).hexdigest(),
            'canonical_result_sha256': hashlib.sha256(want).hexdigest(),
            'progress_callbacks': header[4], 'read_commands': header[5],
            'write_commands': header[6], 'development_elapsed_ns': elapsed,
            'native_worker_wall_limit_seconds': 60})
    module.check_pin()
    assert all(path.read_bytes() == data for path, data in sources.items())
    report = {'schema': 'trnm.hia.delta-caller-extent-controls.v1', 'status': 'PASS',
        'native_controls': len(receipts), 'controls': receipts, 'build': module.receipt,
        'test_sources': {str(path): {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                         for path, data in sources.items()},
        'source_inputs_stable': True, 'original_rust': 'NOT_RUN',
        'original_service_cpu_budget_qualified': False,
        'maximum_state_value_byte_extent_qualified': False,
        'durable_transaction_complete': False}
    (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'controls': receipts, 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()
