"""Independent arithmetic controls and fixed-seal algebra fault injection.

Mutated captured values intentionally bypass the already checked Merkle layer
to test the algebraic checks themselves. They are NOT claimed accepted receipts.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('w1_algebra_tests', ROOT / 'scripts/w1_fri_algebra_replay.py')
algebra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(algebra)
P, ZERO, ONE = algebra.P, algebra.ZERO, algebra.ONE


def change_ext(value):
    return ((value[0] + 1) % P, *value[1:])


class FieldAndInterpreterTests(unittest.TestCase):
    def test_extension_modulus(self):
        x = (0, 1, 0, 0)
        self.assertEqual(algebra.power(x, 4), (P-11, 0, 0, 0))

    def test_multiplication_against_polynomial_long_reduction(self):
        for i in range(24):
            a = tuple((i+3)**(j+2) % P for j in range(4))
            b = tuple(((i+7)**(j+3) + P-1) % P for j in range(4))
            product = [0]*7
            for j in range(4):
                for k in range(4):
                    product[j+k] += a[j]*b[k]
            for degree in range(6, 3, -1):
                product[degree-4] -= 11*product[degree]
            self.assertEqual(algebra.mul(a, b), tuple(x % P for x in product[:4]))

    def test_inverse_and_zero_rejection(self):
        for value in (ONE, (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1), (4, 5, 6, 7)):
            self.assertEqual(algebra.mul(value, algebra.inverse(value)), ONE)
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'zero DEEP denominator'):
            algebra.inverse(ZERO)

    def test_noncanonical_extension_rejected(self):
        for value in ((P, 0, 0, 0), (-1, 0, 0, 0), (True, 0, 0, 0), (0, 0, 0)):
            with self.subTest(value=value), self.assertRaises(algebra.AlgebraReplayError):
                algebra.canonical_ext(value)

    def test_negative_or_noninteger_power_rejected(self):
        for exponent in (-1, True, 1.5):
            with self.subTest(exponent=exponent), self.assertRaises(algebra.AlgebraReplayError):
                algebra.power(ONE, exponent)

    def test_air_two_register_banks_and_conditional_multiplier(self):
        # (2 + (3*5)*7) = 107, with multiplier 7^2; then +11*7^2.
        operations = [
            ('Const', (2,)), ('Const', (3,)), ('Const', (5,)), ('Const', (11,)),
            ('True', ()), ('AndEqz', (0, 0)), ('AndEqz', (0, 2)),
            ('AndCond', (1, 1, 2)), ('AndEqz', (3, 3)),
        ]
        (total, multiplier), record = algebra.execute_air((operations, 4), (7, 0, 0, 0), [], [])
        self.assertEqual(total, (646, 0, 0, 0))
        self.assertEqual(multiplier, (343, 0, 0, 0))
        self.assertEqual((record['field_registers'], record['mix_registers']), (4, 5))

    def test_air_constant_reduction_and_extension_basis(self):
        operations = [('Const', (P+2,)), ('ConstExt', (P+1, 2, 3, 4)),
                      ('Mul', (0, 1)), ('True', ()), ('AndEqz', (0, 2))]
        (total, _), _ = algebra.execute_air((operations, 1), ONE, [], [])
        self.assertEqual(total, (2, 4, 6, 8))

    def test_air_forward_or_wrong_bank_reference_rejected(self):
        cases = [([('Const', (2,)), ('AndEqz', (0, 0))], 0),
                 ([('True', ()), ('Add', (0, 0))], 0),
                 ([('True', ()), ('AndCond', (0, 0, 0))], 1)]
        for program in cases:
            with self.subTest(program=program), self.assertRaisesRegex(algebra.AlgebraReplayError, 'register'):
                algebra.execute_air(program, ONE, [], [])

    def test_air_out_of_bounds_globals_and_taps_rejected(self):
        for operation in [('Get', (0,)), ('GetGlobal', (0, 0)), ('GetGlobal', (1, 0))]:
            with self.subTest(operation=operation), self.assertRaises(algebra.AlgebraReplayError):
                algebra.execute_air(([operation, ('True', ())], 0), ONE, [], [[]])

    def test_air_unsupported_parser_forms_rejected(self):
        for operation in ('PolyExtStep::Inverse(0),', 'PolyExtStep::Const(-1),',
                          'PolyExtStep::Const(1,2),', 'PolyExtStep::Const(foo),'):
            text = 'pub const DEF: PolyExtStepDef = PolyExtStepDef { block: &[' + operation + '], ret: 0 };'
            with self.subTest(operation=operation), self.assertRaises(algebra.AlgebraReplayError):
                algebra.parse_air(text)


class FixedAlgebraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.replay = algebra.load_replayer(ROOT)
        cls.sources = cls.replay.load_snapshot(ROOT)
        cls.supplement = algebra.load_supplement(ROOT, cls.replay)
        cls.receipt = cls.replay.bounded_file(ROOT, cls.replay.RECEIPT_PATH, cls.replay.RECEIPT_BYTES)
        cls.base = cls.replay.ReplayEngine(cls.sources, ROOT).run(cls.receipt)
        cls.inputs = algebra.capture_inputs(cls.replay, cls.base, cls.receipt)
        cls.engine = algebra.AlgebraEngine(cls.sources, cls.supplement)
        cls.result = cls.engine.run(cls.inputs)

    def test_complete_fixed_equation_counts_and_independent_values(self):
        result = self.result
        self.assertEqual(result['mixed_air']['operations'], 12359)
        self.assertEqual(result['mixed_air']['returned_total'], (890055781, 1976276683, 312542502, 1945752035))
        self.assertEqual(result['deep']['query_values_checked_against_first_fri_leaf'], 50)
        self.assertEqual(result['deep']['divisor_inverse_count'], 300)
        self.assertEqual(result['fri']['incoming_goal_equalities'], 150)
        self.assertEqual(result['fri']['terminal_equalities'], 50)
        q0 = result['fri']['queries'][0]
        self.assertEqual(q0['initial_index'], 777360)
        self.assertEqual(q0['deep_goal'], (1295369850, 707014057, 1267614, 1981086267))
        self.assertEqual(q0['terminal_value'], (1380940943, 1121887964, 585620636, 205243834))
        for query in result['fri']['queries']:
            self.assertTrue(query['deep_denominators_nonzero'])
            self.assertEqual(query['terminal_value'], query['terminal_goal'])
            for row in query['rounds']:
                self.assertEqual(row['incoming_goal'], row['selected_opened_value'])

    def test_inverse_dft_matches_separate_reverse_butterfly(self):
        roots = self.engine.roots

        def interpolate(values):
            def butterfly(a):
                if len(a) == 1:
                    return a
                half, step = len(a)//2, roots['REV'][len(a).bit_length()-1]
                left, right = [], []
                for i in range(half):
                    left.append(algebra.add(a[i], a[i+half]))
                    right.append(algebra.scale(algebra.sub(a[i], a[i+half]), pow(step, i, P)))
                return butterfly(left) + butterfly(right)
            raw = butterfly(list(values))
            return tuple(algebra.scale(raw[int(f'{i:04b}'[::-1], 2)], pow(16, -1, P)) for i in range(16))

        examples = [tuple((i*i+1, 17*i+2, i**3+3, i+4) for i in range(16))]
        examples.extend(tuple((5, 7, 9, 11) if i == basis else ZERO for i in range(16)) for basis in range(16))
        for values in examples:
            coefficients = algebra.inverse_dft16(values, roots['REV'][4])
            self.assertEqual(coefficients, interpolate(values))
            self.assertEqual(tuple(algebra.evaluate(coefficients, (pow(roots['FWD'][4], i, P), 0, 0, 0))
                                   for i in range(16)), values)

    def test_tap_groups_are_registers_not_tap_count(self):
        self.assertEqual(len(self.engine.taps['registers']), 163)
        self.assertEqual(sum(r['size'] for r in self.engine.taps['registers']), 643)
        self.assertEqual(self.engine.taps['widths'], (12, 23, 128))

    def test_constraint_mix_mutation_rejected(self):
        value = deepcopy(self.inputs)
        value['constraint_mix'] = change_ext(value['constraint_mix'])
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'mixed AIR validity'):
            self.engine.run(value)

    def test_public_output_mutation_rejected(self):
        value = deepcopy(self.inputs)
        outputs = list(value['outputs'])
        outputs[0] = (outputs[0] + 1) % P
        value['outputs'] = outputs
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'mixed AIR validity'):
            self.engine.run(value)

    def test_u_coefficient_mutation_rejected(self):
        value = deepcopy(self.inputs)
        u = list(value['u'])
        u[0] = change_ext(u[0])
        value['u'] = u
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'mixed AIR validity'):
            self.engine.run(value)

    def test_deep_point_mutation_rejected(self):
        value = deepcopy(self.inputs)
        value['z'] = change_ext(value['z'])
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'mixed AIR validity'):
            self.engine.run(value)

    def test_batch_mix_mutation_rejected(self):
        value = deepcopy(self.inputs)
        value['batch_mix'] = change_ext(value['batch_mix'])
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'fri0: incoming fold'):
            self.engine.run(value)

    def test_each_deep_oracle_mutation_rejected(self):
        for oracle in ('accum', 'code', 'data', 'check'):
            value = deepcopy(self.inputs)
            leaf = list(value['queries'][0]['leaves'][oracle])
            leaf[0] = (leaf[0] + 1) % P
            value['queries'][0]['leaves'][oracle] = leaf
            with self.subTest(oracle=oracle), self.assertRaisesRegex(algebra.AlgebraReplayError, 'fri0: incoming fold'):
                self.engine.run(value)

    def test_selected_fri_leaf_component_mutation_rejected(self):
        for round_, domain in enumerate((1 << 16, 1 << 12, 1 << 8)):
            value = deepcopy(self.inputs)
            query = value['queries'][0]
            position = query['index'] % (16*domain)
            leaf = list(query['leaves'][f'fri{round_}'])
            leaf[position//domain] = (leaf[position//domain] + 1) % P
            query['leaves'][f'fri{round_}'] = leaf
            with self.subTest(round_=round_), self.assertRaisesRegex(algebra.AlgebraReplayError, f'fri{round_}: incoming fold'):
                self.engine.run(value)

    def test_unselected_fri_leaf_component_mutation_rejected_downstream(self):
        value = deepcopy(self.inputs)
        query = value['queries'][0]
        leaf = list(query['leaves']['fri0'])
        unselected = (query['index']//(1 << 16) + 1) % 16
        leaf[unselected] = (leaf[unselected] + 1) % P
        query['leaves']['fri0'] = leaf
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'fri1: incoming fold'):
            self.engine.run(value)

    def test_each_fold_challenge_mutation_rejected(self):
        for round_ in range(3):
            value = deepcopy(self.inputs)
            mixes = list(value['fold_mixes'])
            mixes[round_] = change_ext(mixes[round_])
            value['fold_mixes'] = mixes
            pattern = f'fri{round_+1}: incoming fold' if round_ < 2 else 'terminal polynomial'
            with self.subTest(round_=round_), self.assertRaisesRegex(algebra.AlgebraReplayError, pattern):
                self.engine.run(value)

    def test_terminal_coefficient_mutation_rejected(self):
        value = deepcopy(self.inputs)
        final = list(value['final'])
        final[0] = change_ext(final[0])
        value['final'] = final
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'terminal polynomial'):
            self.engine.run(value)

    def test_wrong_terminal_coordinate_layout_rejected(self):
        value = deepcopy(self.inputs)
        flat = [value['final'][i][j] for j in range(4) for i in range(64)]
        value['final'] = tuple(tuple(flat[i:i+4]) for i in range(0, len(flat), 4))
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'terminal polynomial'):
            self.engine.run(value)

    def test_wrong_fri_coordinate_layout_rejected(self):
        value = deepcopy(self.inputs)
        leaf = value['queries'][0]['leaves']['fri0']
        value['queries'][0]['leaves']['fri0'] = tuple(leaf[j*16+i] for i in range(16) for j in range(4))
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'fri0: incoming fold'):
            self.engine.run(value)

    def test_query_index_mutation_rejected(self):
        value = deepcopy(self.inputs)
        value['queries'][0]['index'] ^= 1
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'fri0: incoming fold'):
            self.engine.run(value)

    def test_missing_query_and_noncanonical_leaf_rejected(self):
        value = deepcopy(self.inputs)
        value['queries'].pop()
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'query count'):
            self.engine.run(value)
        value = deepcopy(self.inputs)
        leaf = list(value['queries'][0]['leaves']['fri0'])
        leaf[0] = P
        value['queries'][0]['leaves']['fri0'] = leaf
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'canonical leaf'):
            self.engine.run(value)

    def test_stale_receipt_cannot_feed_capture(self):
        receipt = bytearray(self.receipt)
        receipt[-1] ^= 1
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'capture receipt identity'):
            algebra.capture_inputs(self.replay, self.base, bytes(receipt))

    def test_leaf_range_identity_mismatch_rejected(self):
        base = deepcopy(self.base)
        base['queries'][0]['openings'][0]['leaf_raw_bytes_sha256'] = '0'*64
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'leaf capture identity'):
            algebra.capture_inputs(self.replay, base, self.receipt)

    def test_duplicate_transcript_event_rejected(self):
        base = deepcopy(self.base)
        base['ordered_transcript_events'][0]['id'] = base['ordered_transcript_events'][1]['id']
        with self.assertRaisesRegex(algebra.AlgebraReplayError, 'event roster'):
            algebra.capture_inputs(self.replay, base, self.receipt)

    def test_source_helper_mutation_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / algebra.REPLAY_PATH
            path.parent.mkdir()
            path.write_bytes((ROOT / algebra.REPLAY_PATH).read_bytes() + b'\n')
            with self.assertRaisesRegex(algebra.AlgebraReplayError, 'helper SHA-256'):
                algebra.load_replayer(root)

    def test_symlink_helper_directory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
            with self.assertRaisesRegex(algebra.AlgebraReplayError, 'symlink replay helper'):
                algebra.load_replayer(root)

    def test_source_supplement_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / algebra.SUPPLEMENT_PATH
            path.parent.mkdir(parents=True)
            data = bytearray((ROOT / algebra.SUPPLEMENT_PATH).read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaisesRegex(algebra.AlgebraReplayError, 'supplement identity'):
                algebra.load_supplement(root, self.replay)


if __name__ == '__main__':
    unittest.main()
