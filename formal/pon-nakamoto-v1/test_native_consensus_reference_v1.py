"""Current native-domain checks; immutable historical arithmetic remains separate."""
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest

import native_consensus_reference_v1 as native


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VECTOR_SCHEMA = 'pon-native-consensus-domain-v2'


def native_domain_vectors():
    """Retain all 75 V1 rows, independently recheck them, then append refusals."""
    original = json.loads((HERE / 'vectors/consensus-arithmetic-v1.json').read_text())
    if original['schema'] != 'pon-native-consensus-integer-vectors-v1' or len(original['rows']) != 75:
        raise AssertionError('historical vector inventory changed')
    rows = original['rows']
    maximum = (1 << 512) - 1
    for row in rows:
        operation = row['operation']
        left = int(row.get('left', '0'), 16)
        right = int(row.get('right', '0'), 16)
        error = None
        if operation == 'divide' and right == 0:
            value, error = 0, 'DIVISION_BY_ZERO'
        elif operation == 'divide':
            value = left // right
        elif operation == 'add':
            value = left + right
        elif operation == 'subtract':
            value = left - right
        elif operation == 'multiply':
            value = left * row['factor']
        elif operation == 'required_work':
            try:
                value = native.work(int(row['target'], 16))
            except ValueError as caught:
                value, error = 0, str(caught)
        elif operation == 'retarget':
            value = native.retarget(int(row['target'], 16), row['first'], row['last'],
                                    row['interval'], row['spacing'], int(row['pow_limit'], 16))
        else:
            raise AssertionError('unknown historical operation')
        if value < 0:
            error = 'CHAINWORK_UNDERFLOW'
        elif value > maximum:
            error = 'CHAINWORK_OVERFLOW'
        expected = {'error': error} if error else {'expected': f'{value:0128x}'}
        if {key: row[key] for key in ('error', 'expected') if key in row} != expected:
            raise AssertionError('historical result disagrees with current independent arithmetic')
    for target, interval, spacing, limit in (
            (1, 16, native.U64_MAX // 15 + 1, native.U256_MAX),
            (1, 16, native.U64_MAX // 60 + 1, native.U256_MAX),
            (1, native.U64_MAX, 1, native.U256_MAX),
            (1, 15, 10, native.U256_MAX),
            (1, 16, 0, native.U256_MAX),
            (0, 16, 10, native.U256_MAX),
            (2, 16, 10, 1),
            (1, 16, 10, 0)):
        try:
            native.retarget(target, 0, native.U64_MAX, interval, spacing, limit)
        except ValueError as error:
            if str(error) != 'TARGET_PARAMETERS':
                raise
        else:
            raise AssertionError('native-domain oracle accepted invalid retarget parameters')
        rows.append(dict(operation='retarget', target=f'{target:064x}', first=0,
                         last=native.U64_MAX, interval=interval, spacing=spacing,
                         pow_limit=f'{limit:064x}', error='TARGET_PARAMETERS'))
    return {'schema': VECTOR_SCHEMA, 'rows': rows}


class NativeDomainTests(unittest.TestCase):
    def test_current_retained_readers_reject_native_invalid_domain(self):
        scripts = str(ROOT / 'scripts')
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        for name in ('pon_daa_schedule_reader', 'pon_joint_daa_reader'):
            reader = importlib.import_module(name)
            with self.subTest(reader=name):
                with self.assertRaisesRegex(ValueError, '^UNKNOWN_PARENT$'):
                    reader.reference.timestamp_state(1, [], 1, 0)
                with self.assertRaisesRegex(ValueError, '^TARGET_PARAMETERS$'):
                    reader.reference.retarget(1, 0, native.U64_MAX, 16,
                                              native.U64_MAX // 60 + 1, native.U256_MAX)

    def test_current_vectors_preserve_all_historical_results_and_add_negative_domain(self):
        actual = json.loads((HERE / 'vectors/consensus-domain-v2.json').read_text())
        self.assertEqual(actual, native_domain_vectors())
        self.assertEqual(len(actual['rows']), 83)

    def test_original_three_inputs_keep_immutable_work_cost_contract_bytes(self):
        contract = json.loads((HERE / 'contracts/work-cost-contract-v1.json').read_text())
        entries = {row['path']: row for row in contract['source_entries']}
        for name in ('reference.py', 'test_reference.py', 'vectors/consensus-arithmetic-v1.json'):
            path = 'formal/pon-nakamoto-v1/' + name
            data = (ROOT / path).read_bytes()
            with self.subTest(path=path):
                self.assertEqual(len(data), entries[path]['bytes'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entries[path]['sha256'])
                self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                                 entries[path]['git_blob'])

    def test_nonzero_u256_work_domain_and_exact_endpoints(self):
        for value in (0, -1, 1 << 256, True, 1.0):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^TARGET$'):
                native.work(value)
        self.assertEqual(native.work(1), 1 << 255)
        self.assertEqual(native.work(native.U256_MAX), 1)

    def test_retarget_rejects_each_non_u64_input(self):
        for position in (1, 2, 3, 4):
            for value in (-1, 1 << 64, True, 1.0):
                arguments = [1000, 0, 150, 16, 10, 10000]
                arguments[position] = value
                with self.subTest(position=position, value=value):
                    with self.assertRaisesRegex(ValueError, '^TARGET_PARAMETERS$'):
                        native.retarget(*arguments)

    def test_retarget_rejects_invalid_target_domain(self):
        for target, limit in ((0, 100), (2, 1), (1, 0), (1, 1 << 256),
                              (True, 100), (1, True), (1.0, 100), (1, 100.0)):
            with self.subTest(target=target, limit=limit):
                with self.assertRaisesRegex(ValueError, '^TARGET_PARAMETERS$'):
                    native.retarget(target, 0, 150, 16, 10, limit)

    def test_both_checked_time_products_refuse_overflow(self):
        for interval, spacing in ((16, native.U64_MAX // 15 + 1),
                                  (16, native.U64_MAX // 60 + 1), (native.U64_MAX, 1)):
            with self.subTest(interval=interval, spacing=spacing):
                with self.assertRaisesRegex(ValueError, '^TARGET_PARAMETERS$'):
                    native.retarget(1, 0, native.U64_MAX, interval, spacing, native.U256_MAX)

    def test_largest_valid_timespan_and_saturating_subtraction(self):
        self.assertEqual(native.retarget(1, 0, native.U64_MAX, 16, native.U64_MAX // 60, 100), 4)
        self.assertEqual(native.retarget(1000, native.U64_MAX, 0, 16, 10, 10000), 253)

    def test_timestamp_requires_known_parent(self):
        with self.assertRaisesRegex(ValueError, '^UNKNOWN_PARENT$'):
            native.timestamp_state(1, [], 1, 0)

    def test_timestamp_rejects_non_u64_candidate_clock_skew_and_ancestry(self):
        for position in range(4):
            for value in (-1, 1 << 64, True, 1.0):
                arguments = [1, [0], 1, 0]
                arguments[position] = [value] if position == 1 else value
                with self.subTest(position=position, value=value):
                    with self.assertRaisesRegex(ValueError, '^TIMESTAMP_DOMAIN$'):
                        native.timestamp_state(*arguments)

    def test_future_bound_uses_native_wide_addition(self):
        self.assertEqual(native.timestamp_state(native.U64_MAX, [native.U64_MAX - 1],
                                               native.U64_MAX - 1, 1), 'admissible')
        self.assertEqual(native.timestamp_state(native.U64_MAX, [0], native.U64_MAX,
                                               native.U64_MAX), 'admissible')
        self.assertEqual(native.timestamp_state(native.U64_MAX, [0], native.U64_MAX - 2,
                                               1), 'deferred-future')

    def test_short_even_window_uses_upper_median_before_future_refusal(self):
        self.assertEqual(native.timestamp_state(2, [1, 2], 0, 0), 'invalid-median')
        self.assertEqual(native.timestamp_state(3, [1, 2], 3, 0), 'admissible')
        self.assertEqual(native.timestamp_state(3, [1, 2], 0, 0), 'deferred-future')

    def test_last_eleven_chronological_ancestors(self):
        history = [0, 0, 0, 50, 5, 60, 4, 70, 3, 80, 2, 90, 1, 100]
        self.assertEqual(native.timestamp_state(50, history, 0, 0), 'invalid-median')
        self.assertEqual(native.timestamp_state(51, history, 50, 0), 'deferred-future')
        self.assertEqual(native.timestamp_state(51, history, 50, 1), 'admissible')


if __name__ == '__main__':
    unittest.main(verbosity=2)
