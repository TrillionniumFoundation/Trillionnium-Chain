"""Test-only physical descriptors for the composed native staging owner."""
from __future__ import annotations

from pathlib import Path
import struct

from hia.platform.typed_store.native_io import run as typed_run

def run(executable: bytes, directory: Path, base, delta, *, variant=0, height=0,
        bootstrap_mutator=None, **options):
    if not __debug__:
        raise RuntimeError('Optimized qualification is not supported')
    def prefix(raw):
        result = b'TCSTG001' + struct.pack('<3Q', variant, height, 0) + raw
        return result if bootstrap_mutator is None else bootstrap_mutator(result)
    if 'profile' not in options:
        options['profile'] = variant >> 1 if variant <= 3 else 0
    row = typed_run(executable, directory, base, delta, bootstrap_mutator=prefix, **options)
    raw = bytes.fromhex(row['stdout_hex'])
    stderr = bytes.fromhex(row['stderr_hex'])
    row.update(variant=variant, height=height)
    if len(stderr) == 120:
        row['diagnostic'] = list(struct.unpack_from('<7Q', stderr))
        row['continuity_diagnostic'] = dict(zip(('phase', 'last', 'index', 'scan_index',
            'key_bytes', 'value_bytes', 'position', 'count'), struct.unpack_from('<8Q', stderr, 56)))
    if len(raw) == 512 and raw[:8] == b'TCRESULT' and raw[128:136] == b'CCHECK01':
        values = struct.unpack_from('<5Q', raw, 8)
        capacity = struct.unpack_from('<11Q', raw, 136)
        row['receipt'] = {'kind': values[0], 'count': values[1], 'output_bytes': values[2],
            'delta_count': values[3], 'progresses': values[4], 'block_hex': raw[48:80].hex(),
            'slot': int.from_bytes(raw[80:88], 'little'), 'root_hex': raw[88:120].hex(),
            'reserved': int.from_bytes(raw[120:128], 'little'),
            'continuity': dict(zip(('variant', 'height', 'actual_keys', 'credit_account_reserve',
                'archive_reserve', 'reward_queue_reserve', 'required_keys', 'accounts', 'working_keys',
                'reward_heights', 'maturity'), capacity)),
            'context': {name: raw[start:start + 32].hex() for name, start in zip(
                ('network', 'parameters', 'policy', 'task', 'model', 'input', 'registry', 'growth', 'evaluation'),
                range(224, 512, 32))}}
    return row
