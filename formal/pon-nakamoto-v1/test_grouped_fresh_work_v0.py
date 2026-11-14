"""Independent encoding and adversarial controls for the added security work."""
import copy
import hashlib
import json
import unittest

import grouped_fresh_work_v0 as fresh


class FreshSealTests(unittest.TestCase):
    def setUp(self):
        self.c = '13' * 32
        self.statement = '27' * 32

    def independent_hash(self, tag, fields):
        wire = b'TRNM-GROUPED-FRESH-SEAL0\0'
        wire += len(tag).to_bytes(2, 'big') + tag
        for field in fields:
            wire += len(field).to_bytes(4, 'big') + field
        return hashlib.sha256(wire).digest()

    def test_independent_full_framing_and_all_64_steps(self):
        identity = self.independent_hash(b'profile', [
            b'pon-grouped-int257-sealed-research-v0',
            b'pon-routed-int257-grouped-research-v0',
            b'signed-i32-coeff-i64-accum-bias8-lowest-argmax',
            b'\0@', b'\0\x10'])
        state = self.independent_hash(b'seed', [identity, bytes.fromhex(self.c),
                                              bytes.fromhex(self.statement)])
        for index in range(1, 65):
            state = self.independent_hash(b'step', [identity, bytes.fromhex(self.c),
                                                  index.to_bytes(2, 'big'), state])
        expected = (b'PGSF\0\0' + identity + bytes.fromhex(self.c) +
                    bytes.fromhex(self.statement) + state)
        self.assertEqual(fresh.prove(self.c, self.statement), expected)
        result = fresh.verify(self.c, self.statement, 'ff' * 32, expected)
        self.assertTrue(result['target_hit'])
        self.assertEqual(result['replayed_steps'], 64)
        self.assertEqual(result['chainwork_awarded'], 0)

    def test_new_candidate_uses_disjoint_step_input_domains(self):
        transcripts = []
        for c in (self.c, '14' * 32):
            rows = []
            fresh.prove(c, self.statement, on_step=rows.append)
            self.assertEqual(len(rows), 64)
            transcripts.append({r['input_hex'] for r in rows})
        self.assertEqual(len(transcripts[0]), 64)
        self.assertFalse(transcripts[0] & transcripts[1])

    def test_repeated_candidate_is_not_a_new_oracle_input(self):
        rows_a, rows_b = [], []
        proof = fresh.prove(self.c, self.statement, on_step=rows_a.append)
        repeat = fresh.prove(self.c, self.statement, on_step=rows_b.append)
        self.assertEqual(proof, repeat)
        self.assertEqual(rows_a, rows_b)

    def test_cached_endpoint_cannot_be_relabelled(self):
        proof = bytearray(fresh.prove(self.c, self.statement))
        proof[38:70] = bytes.fromhex('14' * 32)
        with self.assertRaisesRegex(ValueError, 'ENDPOINT'):
            fresh.verify('14' * 32, self.statement, 'ff' * 32, bytes(proof))

    def test_claimed_low_endpoint_is_only_a_cheap_filter(self):
        proof = fresh.prove(self.c, self.statement)[:102] + bytes(32)
        self.assertTrue(fresh.precheck(self.c, self.statement, '01' * 32, proof)['target_hit'])
        with self.assertRaisesRegex(ValueError, 'ENDPOINT'):
            fresh.verify(self.c, self.statement, '01' * 32, proof)

    def test_fixed_profile_and_all_wire_fields_are_binding(self):
        proof = fresh.prove(self.c, self.statement)
        for position in (0, 6, 38, 70, 102):
            changed = bytearray(proof)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                fresh.verify(self.c, self.statement, 'ff' * 32, bytes(changed))
        for data in (proof[:-1], proof + b'\0'):
            with self.assertRaisesRegex(ValueError, 'LENGTH'):
                fresh.verify(self.c, self.statement, 'ff' * 32, data)

    def test_stop_preserves_completed_prefix_and_no_witness(self):
        rows = []
        def stop(row):
            rows.append(row)
            if row['index'] == 17:
                raise RuntimeError('cancelled after actual step')
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            fresh.prove(self.c, self.statement, on_step=stop)
        self.assertEqual([r['index'] for r in rows], list(range(1, 18)))

    def test_miss_has_no_implicit_winning_promotion(self):
        proof = fresh.prove(self.c, self.statement)
        target = '00' * 31 + '01'
        self.assertFalse(fresh.verify(self.c, self.statement, target, proof)['target_hit'])
        with self.assertRaisesRegex(ValueError, 'TARGET_MISS'):
            fresh.verify(self.c, self.statement, target, proof, require_hit=True)

    def test_boolean_nonce_and_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            fresh.parse_package(b'{"schema":1,"schema":2}')
        fake = {k: '' for k in fresh.PACKAGE_FIELDS}
        fake.update(schema=fresh.PACKAGE_SCHEMA, profile=fresh.PROFILE, nonce=True)
        with self.assertRaisesRegex(ValueError, 'NONCE'):
            fresh.parse_package(json.dumps(fake).encode())

    def test_clock_is_not_optional(self):
        with self.assertRaisesRegex(ValueError, 'CLOCK_REQUIRED'):
            fresh.verify_grouped_package(b'{}', init={}, requests=[],
                                         expected_context={}, now_ns=None)

    def test_full_cell_reference_and_numeric_alias_rejection(self):
        from test_grouped_fresh_admission_wire_v0 import fixture
        import grouped_work_lottery_v0 as old
        frozen, _, init, requests, _, _, _ = fixture()
        candidate = frozen['candidates'][0]
        context = {'chain': frozen['branch']['network'], 'parent': frozen['branch']['parent'],
                   'batch_id': '11' * 32, 'challenge': candidate['challenge']}
        product = old.reference_product(init, requests)
        statement = fresh.grouped_binding(init, requests, context, product)['statement_commitment']
        proof = fresh.prove(context['challenge'], statement)
        packet = fresh.package(init, requests, context, product, nonce=candidate['nonce'],
                               capsule_hex=frozen['capsule_hex'], proof=proof)
        checked = fresh.verify_grouped_package(packet, init=init, requests=requests,
                                               expected_context=context, now_ns=15)
        self.assertEqual(checked['reference_macs'], 37008)
        self.assertEqual(checked['reference_additions'], 48)
        self.assertTrue(checked['native_authority_not_checked_by_this_helper'])
        changed = json.loads(packet)
        changed['product']['padded_macs'] = False
        self.assertEqual(changed['product'], product)  # Python's bool/int alias is the risk.
        with self.assertRaisesRegex(ValueError, 'PRODUCT_COUNT'):
            fresh.verify_grouped_package(json.dumps(changed).encode(), init=init,
                requests=requests, expected_context=context, now_ns=15)
        changed = copy.deepcopy(json.loads(packet))
        changed['product']['logits'][0][0] += 1
        with self.assertRaisesRegex(ValueError, 'FULL_GROUPED_RELATION'):
            fresh.verify_grouped_package(json.dumps(changed).encode(), init=init,
                requests=requests, expected_context=context, now_ns=15)
        with self.assertRaises(ValueError):
            fresh.verify_grouped_package(packet, init=init, requests=requests,
                                         expected_context=context, now_ns=2000)


if __name__ == '__main__':
    unittest.main()
