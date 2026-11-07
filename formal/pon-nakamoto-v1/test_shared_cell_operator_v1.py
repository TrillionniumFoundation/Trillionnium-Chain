"""Exact tiling and refusal tests; reference products here are not native evidence."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
import numpy as np
from contract_wire import canonical
from experiments import shared_cell_operator_v1 as cell


class SharedCellOperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.rows, cls.provenance = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE,
            'consumer', 0, 7)

    def reference_products(self, tiles):
        # Unit-test input only, with no path to a completed native-run report.
        result = {}
        for tile in tiles:
            values = np.asarray(struct.unpack('<' + 'I' * (2 * cell.CELLS), tile['material']), dtype=np.int64)
            signed = np.where(values > cell.Q // 2, values - cell.Q, values)
            a, b = signed[:cell.CELLS].reshape(64, 64), signed[cell.CELLS:].reshape(64, 64)
            result[tile['index']] = cell.pack_field(a @ b)
        return result

    def test_real_source_all_257_features_and_complete_routing(self):
        tiles, bounds = cell.build_tiles(self.model, self.rows)
        self.assertEqual([t['feature_count'] for t in tiles], [64, 64, 64, 64, 1])
        self.assertTrue(all(bound < cell.Q // 2 for bound in bounds))
        self.assertTrue(any(v for row in self.model['router'] for v in row))
        output = cell.consume_products(tiles, self.reference_products(tiles), len(self.rows))
        cell.validate_consumption(self.model, self.rows, output)
        self.assertEqual(output['products'].shape, (15, 7))
        self.assertEqual(output['logits'].shape, (7, 3))

    def test_bias_coordinate_cannot_be_truncated(self):
        original, _ = cell.build_tiles(self.model, self.rows)
        before_output = cell.consume_products(original, self.reference_products(original), len(self.rows))
        model = copy.deepcopy(self.model)
        before = model['base'][0][256]
        model['base'][0][256] = 32767 if before != 32767 else -32767
        changed, _ = cell.build_tiles(model, self.rows)
        self.assertEqual([t['material'] for t in original[:4]], [t['material'] for t in changed[:4]])
        self.assertNotEqual(original[4]['material'], changed[4]['material'])
        output = cell.consume_products(changed, self.reference_products(changed), len(self.rows))
        difference = 8 * (model['base'][0][256] - before)
        self.assertTrue(np.array_equal(output['products'][0] - before_output['products'][0],
                                       np.full(len(self.rows), difference)))
        cell.validate_consumption(model, self.rows, output)

    def test_missing_or_wrong_tile_is_refused(self):
        tiles, _ = cell.build_tiles(self.model, self.rows)
        values = self.reference_products(tiles)
        for bad in ({k: v for k, v in values.items() if k != 4}, dict(values, extra=b'')):
            with self.subTest(kind=len(bad)), self.assertRaises(ValueError):
                cell.consume_products(tiles, bad, len(self.rows))
        wrong = copy.deepcopy(tiles)
        wrong[4]['feature_start'] = 0
        with self.assertRaisesRegex(ValueError, 'TILE_COVERAGE'):
            cell.consume_products(wrong, values, len(self.rows))

    def test_noncanonical_padding_and_signed_range_are_refused(self):
        tiles, _ = cell.build_tiles(self.model, self.rows)
        original = self.reference_products(tiles)
        for offset, value, code in ((0, cell.Q, 'PRODUCT_FIELD'),
                                    (63 * 64 * 4, 1, 'PRODUCT_PADDING'),
                                    (7 * 4, 1, 'PRODUCT_PADDING'),
                                    (0, cell.Q // 2, 'PRODUCT_SIGNED_BOUND')):
            with self.subTest(code=code):
                products = dict(original)
                raw = bytearray(products[0])
                struct.pack_into('<I', raw, offset, value)
                products[0] = bytes(raw)
                with self.assertRaisesRegex(ValueError, code):
                    cell.consume_products(tiles, products, len(self.rows))

    def test_in_range_wrong_operator_output_is_detected(self):
        tiles, _ = cell.build_tiles(self.model, self.rows)
        products = self.reference_products(tiles)
        raw = bytearray(products[0])
        value = struct.unpack_from('<I', raw, 0)[0]
        struct.pack_into('<I', raw, 0, (value + 1) % cell.Q)
        products[0] = bytes(raw)
        output = cell.consume_products(tiles, products, len(self.rows))
        with self.assertRaisesRegex(ValueError, 'MISMATCH'):
            cell.validate_consumption(self.model, self.rows, output)

    def test_frozen_model_input_and_bundle_tampering_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, tasks = root / 'model.json', root / 'consumer.json'
            model.write_bytes(canonical(self.model))
            task_raw = (cell.DEFAULT_MATERIAL / 'consumer.json').read_bytes()
            tasks.write_bytes(task_raw)
            bundle = cell.DEFAULT_MATERIAL / 'evaluation-bundle.json'
            value = copy.deepcopy(self.model)
            value['base'][0][0] += 1
            model.write_bytes(canonical(value))
            with self.assertRaisesRegex(ValueError, 'ARTIFACT_IDENTITY'):
                cell.load_inputs(model, tasks, bundle, cell.DEFAULT_BUNDLE, 'consumer', 0, 7)
            model.write_bytes(canonical(self.model))
            rows = json.loads(task_raw)
            rows[0]['x'][0] = rows[0]['x'][0] - 1 if rows[0]['x'][0] > -8 else -7
            tasks.write_bytes(canonical(rows))
            with self.assertRaisesRegex(ValueError, 'FROZEN_TASKS'):
                cell.load_inputs(model, tasks, bundle, cell.DEFAULT_BUNDLE, 'consumer', 0, 7)
            with self.assertRaisesRegex(ValueError, 'BUNDLE_IDENTITY'):
                cell.load_inputs(model, tasks, bundle, '00' * 32, 'consumer', 0, 7)

    def native_evidence(self):
        """Parser unit fixture only; its transcript uses the independent oracle."""
        from work_oracle import prove
        from contract_wire import H
        tiles, _ = cell.build_tiles(self.model, self.rows)
        tile = tiles[0]
        values = list(struct.unpack('<' + 'I' * (2 * cell.CELLS), tile['material']))
        seed = '12' * 32
        target = bytes([127]) + bytes([255]) * 31
        attempts = []
        for nonce in range(64):
            challenge = H('pon-shared-material-challenge-v1', bytes.fromhex(tile['task']), target,
                          bytes.fromhex(seed), struct.pack('<Q', 0), struct.pack('<Q', nonce))
            proof = prove(challenge, values[:cell.CELLS], values[cell.CELLS:])
            trace = proof[-32:]
            ticket = H('ticket', challenge, trace)
            hit = ticket <= target
            attempts.append(dict(nonce=nonce, challenge=challenge.hex(), trace=trace.hex(),
                                 ticket=ticket.hex(), target_hit=hit, proof_materialized=hit, error=None))
            if hit:
                break
        self.assertTrue(hit)
        material = dict(kind='material', task=tile['task'], profile=cell.PROFILE,
                        input_hex=tile['material'].hex(), input_sha256=tile['material_sha256'],
                        matrix_a_sha256=tile['a_sha256'], matrix_b_sha256=tile['b_sha256'],
                        input_bytes=len(tile['material']), matrix_width=cell.N, field_modulus=cell.Q,
                        target_index=0, target=target.hex(), seed=seed,
                        challenge_domain='pon-shared-material-challenge-v1', arithmetic='full-limb',
                        cycles=1, max_attempts=64, attack_controls=False, materialization='target-hit')
        setup = dict(kind='setup', task=tile['task'], arithmetic='full-limb', calls=1,
                     reuse_searches=1, outcome='Prepared')
        search = dict(kind='search', cycle=0, task=tile['task'], target=target.hex(),
                      arithmetic='full-limb', setup_calls=0, status='target-hit-unverified',
                      error=None, attempts=attempts)
        product = proof[4 + 2 * cell.CELLS * 4:-32]
        candidate = dict(kind='candidate', cycle=0, task=tile['task'], challenge=challenge.hex(),
                         target=target.hex(), ticket=ticket.hex(), proof_hex=proof.hex(),
                         proof_sha256=cell.sha256(proof), verified=False)
        verification = dict(kind='verification', cycle=0, proof_sha256=cell.sha256(proof),
                            typed_products_equal=True, native={'outcome': 'Accepted'},
                            scalar_reference={'outcome': 'Accepted'})
        winner = dict(candidate, kind='winner', product_hex=product.hex(),
                      product_sha256=cell.sha256(product), product_source='VerifiedWork.product',
                      scalar_reference_equal=True)
        del winner['verified']
        summary = dict(kind='summary', status='complete', measurement_incomplete=[], requested_cycles=1, searches=1,
                       attempts=len(attempts), winners=1, exhausted=0, failed_searches=0,
                       control_failures=0, requested_control_campaigns=0, control_campaigns=0)
        timing = {'wall_ns': 1, 'cpu_ns': 1}
        material['input_timing'] = timing
        setup['timing'] = timing
        search['timing'] = timing
        for trial in attempts:
            trial['timing'] = timing
        verification['native']['timing'] = timing
        verification['scalar_reference']['timing'] = timing
        winner['typed_copy_timing'] = timing
        for field in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                      'typed_copy_subtotal', 'run_through_before_summary', 'record_build_subtotal',
                      'serialization_output_subtotal'):
            summary[field] = timing
        records = [dict(record, schema=cell.NATIVE_SCHEMA, record_build_timing=timing)
                   for record in (material, setup, search, candidate, verification, winner, summary)]
        # Synthetic clock envelopes must be internally consistent. These are
        # parser controls, never claimed as measured native performance.
        records[2]['timing'] = dict(cpu_ns=len(attempts), wall_ns=len(attempts))
        records[-1]['producer_subtotal'] = dict(cpu_ns=1 + len(attempts), wall_ns=1 + len(attempts))
        records[-1]['record_build_subtotal'] = dict(cpu_ns=6, wall_ns=6)
        records[-1]['run_through_before_summary'] = dict(cpu_ns=12 + len(attempts), wall_ns=12 + len(attempts))
        options = dict(seed=seed, target_index=0, max_attempts=64, arithmetic='full-limb')
        return tiles, records, options, product

    def evidence_bytes(self, records):
        rows = copy.deepcopy(records)
        prefix = b''.join(canonical(row) + b'\n' for row in rows[:-1])
        rows[-1]['rows_before_summary'] = len(rows) - 1
        rows[-1]['bytes_before_summary'] = len(prefix)
        return prefix + canonical(rows[-1]) + b'\n'

    def test_native_failure_missing_verifier_or_truncation_cannot_pass(self):
        tiles, records, options, _ = self.native_evidence()
        raw = self.evidence_bytes(records)
        for invalid in (b'', raw[:-1], raw[:len(raw) // 2],
                        raw.replace(b'"cpu_ns":1', b'"cpu_ns":NaN', 1),
                        raw.replace(b'"cpu_ns":1', b'"cpu_ns":Infinity', 1),
                        self.evidence_bytes([row for row in records if row['kind'] != 'verification']),
                        self.evidence_bytes([records[-2], records[-1]])):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                cell.native_products(invalid, tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[-1]['status'] = 'failed'
        with self.assertRaisesRegex(ValueError, 'NATIVE_INCOMPLETE'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)

    def test_native_proof_typed_product_and_request_binding(self):
        tiles, records, options, product = self.native_evidence()
        # Evidence shape/parser tests do not establish execution by a native owner.
        decoded, _ = cell.native_products(self.evidence_bytes(records), tiles, 0, 1, **options)
        self.assertEqual(decoded, [product])
        cases = [(0, 'target', 'ff' * 32, 'NATIVE_REQUEST_TARGET'),
                 (0, 'seed', '00' * 32, 'NATIVE_REQUEST_SEED'),
                 (0, 'arithmetic', 'transposed', 'NATIVE_REQUEST_OPTIONS'),
                 (3, 'proof_sha256', '00' * 32, 'NATIVE_CANDIDATE_BINDING'),
                 (4, 'native', {'outcome': 'Rejected'}, 'NATIVE_VERIFICATION'),
                 (5, 'product_source', 'proof_bytes', 'NATIVE_TYPED_PRODUCT'),
                 (5, 'task', '00' * 32, 'NATIVE_WINNER_CONTEXT'),
                 (6, 'attempts', 999, 'NATIVE_SUMMARY_ATTEMPTS'),
                 (6, 'measurement_incomplete', ['clock'], 'NATIVE_MEASUREMENT_INCOMPLETE'),
                 (0, 'cycles', True, 'NATIVE_HEADER_COUNT'),
                 (2, 'cycle', False, 'NATIVE_CYCLES'),
                 (4, 'record_build_timing', {'wall_ns': None, 'cpu_ns': 1}, 'NATIVE_TIMING')]
        for index, key, value, code in cases:
            with self.subTest(code=code):
                wrong = copy.deepcopy(records)
                wrong[index][key] = value
                with self.assertRaisesRegex(ValueError, code):
                    cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[2]['attempts'][0]['nonce'] = 1
        with self.assertRaisesRegex(ValueError, 'NATIVE_NONCE'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[2]['attempts'][0]['challenge'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'NATIVE_CHALLENGE_BINDING'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[5]['product_hex'] = '00' * len(product)
        wrong[5]['product_sha256'] = cell.sha256(bytes(len(product)))
        with self.assertRaisesRegex(ValueError, 'NATIVE_PRODUCT_BINDING'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)

    def test_material_only_is_not_a_completed_proof_run(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'run'
            args = cell.parser().parse_args(['--out', str(out), '--material-only',
                                             '--batch-size', '7', '--baseline-repetitions', '2'])
            report = cell.run(args)
            self.assertEqual(report['status'], 'materials_ready')
            self.assertFalse(report['proof_backend_executed'])
            self.assertFalse(report['claims']['complete_operator'])
            self.assertEqual(len(list(out.glob('tile-*/material.bin'))), 5)

    def test_cost_subtotals_and_search_envelopes_cannot_erase_real_work(self):
        tiles, records, options, _ = self.native_evidence()
        for field in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                      'typed_copy_subtotal', 'record_build_subtotal'):
            wrong = copy.deepcopy(records)
            wrong[-1][field] = {'cpu_ns': 0, 'wall_ns': 0}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'SUMMARY_TIMING'):
                cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[2]['timing'] = {'cpu_ns': 0, 'wall_ns': 0}
        with self.assertRaisesRegex(ValueError, 'SEARCH_TIMING_ENVELOPE'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)
        wrong = copy.deepcopy(records)
        wrong[-1]['run_through_before_summary'] = {'cpu_ns': 1, 'wall_ns': 1}
        with self.assertRaisesRegex(ValueError, 'RUN_TIMING_ENVELOPE'):
            cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)

    def test_v2_verifier_roster_is_complete_and_charged_exactly_once(self):
        tiles, records, options, product = self.native_evidence()
        for row in records:
            row['schema'] = cell.NATIVE_SCHEMA_V2
        for index in (0, 1, 2):
            records[index]['preparation'] = 'sparse'
        records[0]['verifiers'] = 3
        for index in (0, 4, 6):
            records[index]['native_verifier_scope'] = cell.VERIFIER_SCOPE
        records[4]['native_verifiers'] = [
            {'index': index, 'outcome': 'Accepted', 'timing': {'cpu_ns': 1, 'wall_ns': 1},
             'product_sha256': cell.sha256(product)} for index in range(3)]
        records[-1]['native_verifier_subtotal'] = {'cpu_ns': 3, 'wall_ns': 3}
        records[-1]['native_verifier_calls'] = 3
        records[-1].update(preparation='sparse', verifiers=3)
        records[-1]['run_through_before_summary'] = {'cpu_ns': 1000, 'wall_ns': 1000}
        options.update(preparation='sparse', verifiers=3)
        decoded, _ = cell.native_products(self.evidence_bytes(records), tiles, 0, 1, **options)
        self.assertEqual(decoded, [product])
        for mutation, code in (
                (lambda r: r[4]['native_verifiers'].pop(), 'VERIFIER_COVERAGE'),
                (lambda r: r[4]['native_verifiers'][1].update(index=0), 'VERIFIER_BINDING'),
                (lambda r: r[4]['native_verifiers'][2].update(product_sha256='00' * 32), 'VERIFIER_BINDING'),
                (lambda r: r[4]['native_verifiers'][2].update(outcome='Rejected'), 'VERIFIER_BINDING'),
                (lambda r: r[-1].update(native_verifier_calls=True), 'VERIFIER_CALLS'),
                (lambda r: r[-1].update(native_verifier_subtotal={'cpu_ns': 4, 'wall_ns': 4}), 'SUMMARY_TIMING'),
                (lambda r: r[4].update(native_verifier_scope='independent-network-nodes'), 'VERIFIER_SCOPE'),
                (lambda r: r[1].update(preparation='dense'), 'PREPARATION_BINDING')):
            wrong = copy.deepcopy(records)
            mutation(wrong)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                cell.native_products(self.evidence_bytes(wrong), tiles, 0, 1, **options)

    def test_v2_materials_keep_unknown_system_costs_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            args = cell.parser().parse_args(['--out', str(Path(directory) / 'run'), '--material-only',
                                             '--preparation', 'sparse', '--verifiers', '3',
                                             '--batch-size', '7', '--baseline-repetitions', '2'])
            report = cell.run(args)
            self.assertEqual(report['schema'], cell.SCHEMA_V2)
            self.assertEqual(len(report['baseline']['cpu']['warm_samples_ns']), 2)
            self.assertFalse(report['cost_coverage']['net_compute_benefit_qualified'])
            for key in ('wan_transport', 'stale_blocks', 'network_validator_population', 'device_model_load'):
                self.assertIsNone(report['cost_coverage'][key])


if __name__ == '__main__':
    unittest.main(verbosity=2)
