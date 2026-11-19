"""Actual native default Settings constructor, complete snapshot comparison.

The expected result is independently built from the exact original include_str
inputs. Hashlib, the existing independent Edwards arithmetic and the recursive
top-down sparse-tree oracle do not implement the product. Product results come
only from the locked selfhost compiler's machine artifact in private children.
The retained Rust public constructor is a separate required qualification gate.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import random
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_ed25519 import B, compress, multiply
from hia.tests.test_state_root import descriptor, domain, reference as root_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'hia/src/node/settings_development.hepta'
COMPACT_SOURCE = ROOT / 'hia/src/protocol/state_root_compact.hepta'
OUT_MIN = 16384
WORK_MIN = 300000
BAD_INPUT = 0xfffffff0
CAPACITY = 0xfffffff1
CONFIG = 0xfffffff2
GENESIS_TIME = 0xfffffff3
INPUT_PINS = {
    'devnet-v1.json': '4491b96ead11a020e8d71f27713368b65e663eef5cfc6fd0800a166b0c2a20d4',
    'ledger-v1.json': '6755e36aab0ab9f4743da331a8dcd3374d657ff80f027ecf28db922e6d5ea39a',
    'work-profile-v1.json': '03f7537b2fc3fa0c2f7036dd73d7088ba1ce50eafe6f2c907087d30385320880',
    'model-family-v1.json': '30b250db074e7fbb5776c1474371258a6110cc1742e0e9970232a799ab790ca1',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def pinned_input(name):
    raw = (ROOT / 'config/pon' / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != INPUT_PINS[name]:
        raise ValueError('Original Settings include_str source changed: ' + name)
    return json.loads(raw)


@lru_cache(maxsize=4)
def development_public(index):
    seed = domain(b'DEV-ONLY-KEY', struct.pack('<Q', index))
    expanded = hashlib.sha512(seed).digest()
    scalar = (int.from_bytes(expanded[:32], 'little') & ((1 << 254) - 8)) | (1 << 254)
    return compress(multiply(scalar, B))


@lru_cache(maxsize=1)
def initial_material():
    params = pinned_input('devnet-v1.json')
    count = params['genesis_accounts']
    funding = params['genesis_funding_units_per_account']
    a = b''.join(struct.pack('<I', i % 31) for i in range(4096))
    b = b''.join(struct.pack('<I', (i * 7) % 37) for i in range(4096))
    task = domain(b'task', a, b)
    state = {'meta:issued': count * funding, 'model:current': '0' * 64,
             'work:' + task.hex(): True}
    for i in range(count):
        state['account:' + development_public(i).hex()] = {'balance': funding, 'nonce': 0}
    rows = [(key.encode(), canonical(value)) for key, value in sorted(state.items())]
    code, root = root_reference(rows)
    assert code == 0
    return task, rows, root


def request(timestamp):
    return b'SDV1\0' if timestamp is None else b'SDV1\1' + struct.pack('<Q', timestamp)


def expected_snapshot(timestamp):
    params = pinned_input('devnet-v1.json')
    wire = pinned_input('ledger-v1.json')
    work = pinned_input('work-profile-v1.json')
    model = pinned_input('model-family-v1.json')
    if timestamp is not None:
        if not 0 < timestamp <= (1 << 63) - 1:
            raise ValueError('GENESIS_TIME')
        params['genesis_timestamp'] = timestamp
        params['chain_label'] = 'trnm-pon-native-wall-devnet-3-' + str(timestamp)
    timestamp = params['genesis_timestamp']
    raw_params, raw_model = canonical(params), canonical(model)
    network = domain(b'network', params['chain_label'].encode())
    parameters = domain(b'parameters', raw_params, canonical(wire), canonical(work), raw_model)
    family = domain(b'family', raw_model)
    plan = domain(b'plan', b'public-source-file-disjoint-v1')
    fees = [0] * 25
    tags = set()
    for command in wire['commands']:
        tag = command['tag']
        assert 1 <= tag <= 12 and tag not in tags
        tags.add(tag)
        fees[tag] = command['base_fee_units']
    assert len(tags) == 12
    fees[13] = 100
    fees[14:18] = [160] * 4
    fees[18:22] = [100] * 4
    fees[22:25] = [200, 200, 240]
    evaluators = sorted(development_public(i) for i in range(3))
    task, rows, root = initial_material()
    state = descriptor(rows)
    genesis = domain(b'genesis', network, parameters, root, struct.pack('<Q', timestamp))
    result = bytearray(576)
    result[:4] = b'SDO1'
    struct.pack_into('<Q', result, 16, timestamp)
    result[24:248] = network + parameters + family + plan + genesis + root + task
    struct.pack_into('<25Q', result, 248, *fees)
    struct.pack_into('<5I', result, 448, 3, len(rows), len(raw_params), len(raw_model), len(state))
    result[480:576] = b''.join(evaluators)
    result.extend(raw_params + raw_model + state)
    struct.pack_into('<I', result, 4, len(result))
    return bytes(result)


class NativeDefaultSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=('f0',))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def invoke(self, raw, *, out_size=OUT_MIN + 31, work_size=WORK_MIN + 29, seed=57):
        output = bytes((i * 73 + seed) & 255 for i in range(out_size))
        scratch = bytes((i * 113 + seed) & 255 for i in range(work_size))
        call = self.native.call('f0', [raw, output, scratch], timeout=60).require_returned()
        self.assertEqual(call.arguments[0], raw)
        self.assertEqual(call.arguments[2][WORK_MIN:], scratch[WORK_MIN:])
        if call.value >= BAD_INPUT:
            self.assertEqual(call.arguments[1], output)
        else:
            self.assertEqual(call.arguments[1][call.value:], output[call.value:])
            self.assertEqual(call.arguments[2][:141568], bytes(141568))
        return call, output, scratch

    def check_snapshot(self, timestamp, **options):
        expected = expected_snapshot(timestamp)
        call, _, _ = self.invoke(request(timestamp), **options)
        self.assertEqual(call.value, len(expected), timestamp)
        self.assertEqual(call.arguments[1][:call.value], expected, timestamp)
        return expected

    def test_complete_default_and_same_timestamp_override_differ(self):
        default = self.check_snapshot(None)
        override = self.check_snapshot(1800000000)
        self.assertNotEqual(default[24:88], override[24:88])
        self.assertNotEqual(default[152:184], override[152:184])
        self.assertEqual(default[88:152], override[88:152])
        self.assertEqual(default[184:456], override[184:456])

    def test_integer_decimal_boundaries_and_i64_maximum(self):
        for timestamp in (1, 9, 10, 99, 100, 999, 1000, 1799999999, 1800000001,
                          (1 << 32) - 1, 1 << 32, (1 << 53) - 1, 1 << 53,
                          (1 << 53) + 1, 10**18, (1 << 63) - 1):
            with self.subTest(timestamp=timestamp):
                self.check_snapshot(timestamp)

    def test_original_genesis_time_refusals_restore_output(self):
        for timestamp in (0, 1 << 63, (1 << 64) - 1):
            with self.subTest(timestamp=timestamp):
                call, _, _ = self.invoke(request(timestamp))
                self.assertEqual(call.value, GENESIS_TIME)
                self.assertEqual(call.arguments[2][:141568], bytes(141568))
                # Config really precedes invalid time: its derived public set
                # exists in this private construction workspace before refusal.
                self.assertEqual(call.arguments[2][180256:180352],
                                 b''.join(sorted(development_public(i) for i in range(3))))

    def test_descriptor_and_capacity_refusals_write_nothing(self):
        valid = request(1)
        invalid = [valid[:n] for n in range(len(valid))]
        invalid += [b'SDV2\0', b'SDV1\2', request(None) + b'\0', valid + b'\0']
        for raw in invalid:
            call, _, before = self.invoke(raw, out_size=17, work_size=71)
            self.assertEqual(call.value, BAD_INPUT)
            self.assertEqual(call.arguments[2], before)
        for output, scratch in ((0, WORK_MIN), (OUT_MIN - 1, WORK_MIN),
                                (OUT_MIN, 0), (OUT_MIN, WORK_MIN - 1)):
            call, _, before = self.invoke(valid, out_size=output, work_size=scratch)
            self.assertEqual(call.value, CAPACITY)
            self.assertEqual(call.arguments[2], before)
        self.check_snapshot(1, out_size=OUT_MIN, work_size=WORK_MIN)

    def test_all_original_fixed_sources_are_exact(self):
        for name in INPUT_PINS:
            value = pinned_input(name)
            self.assertIsInstance(value, dict)
        default = expected_snapshot(None)
        self.assertEqual(default[8:16], bytes(8))
        self.assertEqual(default[468:480], bytes(12))


class CompactStateRootContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(COMPACT_SOURCE, byte_exports=('f0',))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def invoke(self, raw, count, *, output_size=49, scratch_size=None):
        needed = 132288 + 64 * count + len(raw)
        if scratch_size is None:
            scratch_size = needed + 31
        before = b'\x71' * scratch_size
        output = b'\x39' * output_size
        call = self.native.call('f0', [raw, output, before], timeout=60).require_returned()
        self.assertEqual(call.arguments[0], raw)
        self.assertEqual(call.arguments[2][needed:], before[needed:])
        if call.value:
            self.assertEqual(call.arguments[1], output)
        else:
            self.assertEqual(call.arguments[1][32:], output[32:])
        return call, before

    def test_empty_absence_order_and_non_seven_row_counts(self):
        rng = random.Random(0x43535231)
        for count in (0, 1, 2, 3, 7, 8, 17, 33, 65):
            rows = [(i.to_bytes(4, 'little') + rng.randbytes(i % 9), rng.randbytes(i % 31))
                    for i in range(count)]
            rng.shuffle(rows)
            expected = root_reference(rows)
            call, _ = self.invoke(descriptor(rows), count)
            self.assertEqual(call.value, expected[0])
            self.assertEqual(call.arguments[1][:32], expected[1])
        for rows in ([(b'', b'')], [(b'a', bytes(4096))], [(bytes(160), b'')]):
            call, _ = self.invoke(descriptor(rows), len(rows))
            self.assertEqual(call.arguments[1][:32], root_reference(rows)[1])

    def test_complete_grammar_collision_limits_and_capacity(self):
        rows = [(b'key', b'value'), (b'other', b'')]
        raw = descriptor(rows)
        for length in range(len(raw)):
            call, before = self.invoke(raw[:length], 2)
            self.assertEqual(call.value, 1)
            self.assertEqual(call.arguments[2], before)
        cases = [(raw + b'\0', 1), (b'SRV2' + struct.pack('<I', 0), 2),
                 (b'SRV1' + struct.pack('<I', 65537), 4),
                 (b'SRV1' + struct.pack('<I', 65536), 1),
                 (b'SRV1' + struct.pack('<III', 1, 161, 0), 4),
                 (b'SRV1' + struct.pack('<III', 1, 0, 4097), 4)]
        for data, code in cases:
            call, before = self.invoke(data, 2)
            self.assertEqual(call.value, code)
            self.assertEqual(call.arguments[2], before)
        for duplicate in ([('x'.encode(), b'a'), (b'x', b'b')], [(b'', b''), (b'', b'')]):
            call, _ = self.invoke(descriptor(duplicate), len(duplicate))
            self.assertEqual(call.value, 5)
        needed = 132288 + 64 * len(rows) + len(raw)
        for out_size, scratch_size in ((31, needed), (32, needed - 1)):
            call, before = self.invoke(raw, len(rows), output_size=out_size, scratch_size=scratch_size)
            self.assertEqual(call.value, 100)
            self.assertEqual(call.arguments[2], before)


if __name__ == '__main__':
    unittest.main()
