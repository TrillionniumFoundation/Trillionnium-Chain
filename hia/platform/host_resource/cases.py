"""Shared declarative real-file cases for native HIA and unchanged Rust methods."""
from __future__ import annotations

import itertools
import json

CPU_VALUES = (10, 20, 3, 40)
CPU_KEYS = ('usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec')
VALUES = (*CPU_VALUES, 64, 2)
COUNTERS = ('cpu.stat', 'memory.current', 'pids.current')
LIMITS = {'cpu.max': b'25000 100000\n', 'cpu.max.burst': b'0\n',
          'memory.max': b'2147483648\n', 'memory.swap.max': b'0\n', 'pids.max': b'256\n'}


def cpu(values=CPU_VALUES, keys=CPU_KEYS, *, separator=b'\n', plus=False) -> bytes:
    return separator.join(key.encode() + b' ' + (b'+' if plus else b'') + str(value).encode()
                          for key, value in zip(keys, values)) + separator


DEFAULT_COUNTERS = {'cpu.stat': cpu(), 'memory.current': b'64\n', 'pids.current': b'2\n'}


def write(target: str, raw: bytes, *, kind='write') -> dict:
    return {'kind': kind, 'target': target, 'hex': raw.hex()}


def step(*, before=(), gate=0, mutation=(), error=0, values=VALUES, delta=(0, 0, 0, 0),
         op=1, chunk=4096, checks=2, complete_reads=3, rewind_field=None) -> dict:
    expected = {'error': error, 'checks': checks, 'complete_reads': complete_reads,
                'values': list(values) if not error else [0] * 6,
                'delta': list(delta) if not error else [0] * 4}
    if rewind_field is not None:
        expected['rewind_field'] = rewind_field
    return {'operation': op, 'gate': gate, 'chunk': chunk,
            'before': list(before), 'mutation': list(mutation), 'expected': expected}


def cases() -> list[dict]:
    rows = []
    def add(name, *steps):
        rows.append({'name': name, 'steps': list(steps) or [step()]})
    add('ordinary')
    add('ordinary-one-byte-reads', step(chunk=1))
    add('ordinary-three-byte-reads', step(chunk=3))
    for index, order in enumerate(itertools.permutations(range(4))):
        raw = cpu(tuple(CPU_VALUES[i] for i in order), tuple(CPU_KEYS[i] for i in order))
        add(f'key-order-{index:02}', step(before=[write('cpu.stat', raw)]))
    for name, raw in [
        ('crlf', cpu(separator=b'\r\n')),
        ('no-trailing-newline', cpu().rstrip(b'\n')),
        ('leading-plus', cpu(plus=True)),
        ('ascii-whitespace', b'\tusage_usec\t10\r\n nr_periods\x0c20 \n\tnr_throttled 3\n throttled_usec 40\t\n'),
        ('future-keys', cpu() + b'user_usec 2\nsystem_usec 8\nnr_bursts 0\nburst_usec 0\n'),
        ('unicode-future-key', cpu() + '计数 42\n'.encode()),
        ('nul-future-key', cpu() + b'future\0field 1\n'),
        ('future-full-u64', cpu() + b'future 18446744073709551615\n'),
        ('cpu-exact-bound', cpu().rstrip(b'\n').ljust(2048, b' ')),
    ]:
        add(name, step(before=[write('cpu.stat', raw)], chunk=1 if name == 'cpu-exact-bound' else 4096))
    for number in (0, 1, 2**63, 2**64 - 1):
        add(f'all-counters-{number}', step(before=[write('cpu.stat', cpu((number,) * 4)),
            write('memory.current', str(number).encode()), write('pids.current', str(number).encode())],
            values=(number,) * 6))
    malformed = {
        'empty': b'', 'blank-line': cpu() + b'\n', 'leading-blank': b'\n' + cpu(),
        'missing-value': cpu() + b'future\n', 'extra-word': cpu() + b'future 1 x\n',
        'negative': cpu() + b'future -1\n', 'overflow': cpu() + b'future 18446744073709551616\n',
        'plus-only': cpu() + b'future +\n', 'double-plus': cpu() + b'future ++1\n',
        'unicode-digit': cpu() + 'future １\n'.encode(),
        'vertical-tab': cpu() + b'future\x0b1\n',
        'duplicate-unknown': cpu() + b'future 1\nfuture 2\n',
        'duplicate-unicode': cpu() + '未来 1\n未来 2\n'.encode(),
        'duplicate-nul': cpu() + b'future\0key 1\nfuture\0key 2\n',
        'nonascii-space': cpu() + 'future\u00a01\n'.encode(),
    }
    for key in CPU_KEYS:
        malformed['missing-' + key] = b'\n'.join(line for line in cpu().splitlines()
                                                if not line.startswith(key.encode() + b' ')) + b'\n'
        malformed['duplicate-' + key] = cpu() + key.encode() + b' 0\n'
    for name, raw in malformed.items():
        add('cpu-' + name, step(before=[write('cpu.stat', raw)], error=13, checks=1))
    for index, target in enumerate(COUNTERS):
        bound = 2048 if index == 0 else 64
        for label, raw in [('invalid-utf8', DEFAULT_COUNTERS[target] + b'\xff'),
                           ('overflow-one-byte', DEFAULT_COUNTERS[target].rstrip(b'\n').ljust(bound + 1, b' ')),
                           ('huge-overflow', b'x' * (bound * 4 + 1))]:
            add(target + '-' + label, step(before=[write(target, raw)], error=13, checks=1,
                                          complete_reads=index, chunk=1 if label == 'overflow-one-byte' else 4096))
        for kind in ('remove', 'symlink', 'directory', 'fifo', 'socket'):
            add(target + '-' + kind, step(before=[{'kind': kind, 'target': target}],
                                         error=13, checks=1, complete_reads=index))
    for index, target in enumerate(COUNTERS[1:], 4):
        for label, raw in [('empty', b''), ('two', b'1 2'), ('max', b'max'),
                           ('minus', b'-1'), ('overflow', b'18446744073709551616'),
                           ('plus', b'+'), ('vertical', b'1\x0b'), ('nul', b'1\0'),
                           ('unicode-space', '\u00a01'.encode())]:
            add(target + '-' + label, step(before=[write(target, raw)], error=13, checks=1))
        for label, raw in [('exact-bound', b'64'.ljust(64, b' ')),
                          ('zero', b'0'), ('plus-zero', b'+0'), ('plus-max', b'+18446744073709551615'),
                          ('split-ascii-whitespace', b' \t\n64\r\x0c')]:
            values = list(VALUES)
            values[index] = int(raw.strip())
            add(target + '-' + label, step(before=[write(target, raw)], values=values, chunk=1))
    for gate in (5, 6, 7, 8):
        add(f'gate-{gate}-ordinary', step(gate=gate))
        for mutation, expected in [({'kind': 'replace_parent'}, 4),
                                   ({'kind': 'rename_parent'}, 4),
                                   ({'kind': 'symlink_parent'}, 4),
                                   ({'kind': 'chmod_parent', 'mode': 0o777}, 4),
                                   (write('memory.max', b'1073741824'), 7),
                                   (write('cpu.max', b'invalid'), 6),
                                   (write('boot', b'different-boot\n'), 4),
                                   (write('membership', b'0::/wrong.slice\n'), 3)]:
            label = mutation.get('target', mutation['kind']).replace('.', '-')
            add(f'gate-{gate}-{label}', step(gate=gate, mutation=[mutation], error=expected, checks=1))
    for gate in (5, 6):
        for mutation in ({'kind': 'replace_parent'}, {'kind': 'chmod_parent', 'mode': 0o777},
                         write('memory.max', b'1073741824'), write('boot', b'changed')):
            label = mutation.get('target', mutation['kind']).replace('.', '-')
            add(f'parse-first-{gate}-{label}', step(before=[write('cpu.stat', b'invalid')],
                gate=gate, mutation=[mutation], error=13, checks=1))
    add('first-check-precedes-counters', step(before=[write('pids.max', b'128'),
        {'kind': 'remove', 'target': 'cpu.stat'}], error=7, checks=0, complete_reads=0))
    add('missing-counter-before-parse-and-final', step(before=[write('cpu.stat', b'invalid'),
        {'kind': 'remove', 'target': 'pids.current'}], gate=5,
        mutation=[write('memory.max', b'1073741824')], error=13, checks=1, complete_reads=2))
    add('fresh-counter-inode', step(gate=5, mutation=[write('memory.current', b'96', kind='replace_counter')],
                                   values=(*CPU_VALUES, 96, 2)))
    add('sample-survives-later-counter-change', step(gate=6, mutation=[write('memory.current', b'96')]))
    add('each-sample-reopens', step(), step(before=[write('memory.current', b'96')], values=(*CPU_VALUES, 96, 2)))
    add('unchanged-delta', step(), step(op=2))
    add('positive-delta', step(), step(op=2, before=[write('cpu.stat', cpu((15, 30, 4, 65))),
        write('memory.current', b'1'), write('pids.current', b'0')],
        values=(15, 30, 4, 65, 1, 0), delta=(5, 10, 1, 25)))
    add('u64-max-delta', step(before=[write('cpu.stat', cpu((0,) * 4))], values=(0, 0, 0, 0, 64, 2)),
        step(op=2, before=[write('cpu.stat', cpu((2**64 - 1,) * 4))],
             values=(2**64 - 1,) * 4 + (64, 2), delta=(2**64 - 1,) * 4))
    for first in range(4):
        values = list(CPU_VALUES)
        for index in range(first, 4):
            values[index] -= 1
        add(f'rewind-first-field-{first}', step(), step(op=2,
            before=[write('cpu.stat', cpu(values))], error=14, rewind_field=first))
    add('delta-requires-private-baseline', step(op=2, error=15, checks=0, complete_reads=0))
    names = [r['name'] for r in rows]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate resource case identity')
    return rows


def corpus_bytes() -> bytes:
    return b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n'
                    for row in cases())
