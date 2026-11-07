"""Adversarial controlled-wire fixtures; no fake signature is authenticated."""
import copy
import hashlib
import json
import struct
import unittest

import grouped_fresh_admission_wire_v0 as wire
import grouped_work_lottery_v0 as old
from experiments.grouped_cell_operator_v0 import model_commitment

BH = ('network', 'parameters', 'genesis', 'parent', 'prior_state', 'target')
BI = ('height', 'generation')
IH = ('registry_id', 'registry_digest', 'previous_registry_digest', 'demand_id',
      'source_record', 'authorization_scope', 'withdrawal_head', 'model_commitment',
      'request_precommitment', 'batch_id', 'transactions_commitment', 'payee', 'operation_id')
II = ('registry_sequence', 'model_generation', 'timestamp_ms', 'not_before_ns',
      'expires_ns', 'available_until_ns', 'nonce_first', 'nonce_count')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def h(tag, *parts):
    tag = tag.encode()
    raw = b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
    for part in parts:
        raw += struct.pack('<I', len(part)) + part
    return hashlib.sha256(raw).digest()


def seal_profile():
    parts = (b'pon-grouped-int257-sealed-research-v0', b'pon-routed-int257-grouped-research-v0',
             b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', b'\0@', b'\0\x10')
    return hashlib.sha256(b'TRNM-GROUPED-FRESH-SEAL0\0\0\x07profile' +
                          b''.join(struct.pack('>I', len(p)) + p for p in parts)).digest()


def encode_body(branch, intent):
    raw = b'PGAB\0\0' + seal_profile() + b'\0@'
    raw += b''.join(bytes.fromhex(branch[k]) for k in BH)
    raw += struct.pack('>QQ', *(branch[k] for k in BI))
    raw += b''.join(bytes.fromhex(intent[k]) for k in IH)
    raw += struct.pack('>8Q', *(intent[k] for k in II))
    assert len(raw) == 728
    return raw


def refresh(result, body, *, signatures=b'r' * 64 + b's' * 64):
    """Re-encode all response self-hashes; outside request/pins remain unchanged."""
    capsule = b'PGAC\0\0' + body + signatures
    result.update(body_hex=body.hex(), capsule_hex=capsule.hex(), capsule_sha256=sha(capsule))
    policy = result['external_policy']
    policy.update(expected_body_hex=body.hex(), expected_capsule_sha256=sha(capsule))
    policy['policy_id'] = h('pon-grouped-fresh-external-policy-v0',
        bytes.fromhex(policy['requester_public_key']), bytes.fromhex(policy['source_public_key']),
        struct.pack('>Q', policy['latest_sequence']), bytes.fromhex(policy['latest_digest']),
        bytes.fromhex(sha(capsule)), body).hex()
    result['expected_policy_file_sha256'] = sha(json.dumps(
        policy, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
    for row in result['candidates']:
        raw = b'PGCE\0\0' + body + struct.pack('>Q', row['nonce'])
        row.update(candidate_hex=raw.hex(), challenge=h('pon-grouped-fresh-challenge-v0', raw).hex(),
                   work_id=h('pon-grouped-fresh-work-id-v0', raw).hex())


def pins_for(result):
    return {'expected_body_sha256': sha(bytes.fromhex(result['body_hex'])),
            'expected_capsule_sha256': result['capsule_sha256'],
            'expected_policy_file_sha256': result['expected_policy_file_sha256'],
            'branch': copy.deepcopy(result['branch'])}


def fixture():
    matrix = [[(row * 3 + col) % 11 - 5 for col in range(257)] for row in range(3)]
    model = dict(type='init', model_version='12' * 32, base=matrix,
                 router=copy.deepcopy(matrix), deltas=[copy.deepcopy(matrix) for _ in range(3)])
    scope = sha(b'authorized-scope')
    requests = [dict(id=sha(str(i).encode()), scope=scope, arrival_ns=0, deadline_ns=2000,
                     x=[(i + col) % 17 - 8 for col in range(256)] + [8]) for i in range(16)]
    f = dict(model_commitment=model_commitment(model), request_precommitment=old.request_precommitment(model, requests),
             batch_id=sha(b'batch'), authorization_scope=scope, demand_id=sha(b'demand'),
             source_record=sha(b'source-record'), withdrawal_head=sha(b'withdrawal'), payee=sha(b'payee'),
             model_generation=4, timestamp_ms=1700000001000, not_before_ns=10, expires_ns=1000,
             available_until_ns=1000, nonce_first=17, nonce_count=3, now_ns=15)
    branch = {key: sha(key.encode()) for key in BH}
    branch.update(height=3, generation=7, target='ff' * 32)
    registry = h('pon-grouped-fresh-controlled-registry-v0', seal_profile())
    request, batch = bytes.fromhex(f['request_precommitment']), bytes.fromhex(f['batch_id'])
    intent = {k: f[k] for k in (*wire.REQUEST_HASHES, *II[1:])}
    intent.update(registry_id=registry.hex(), registry_digest=h(
        'pon-grouped-fresh-controlled-registry-entry-v0', registry, request, batch).hex(),
        previous_registry_digest='00' * 32, transactions_commitment=h('transactions-empty').hex(),
        operation_id=h('pon-grouped-fresh-controlled-operation-v0', registry, request, batch,
                       struct.pack('>Q', f['nonce_first']), struct.pack('>Q', f['nonce_count'])).hex(),
        registry_sequence=1)
    result = dict(schema='pon-grouped-fresh-controlled-freeze-v0', profile=wire.PROFILE,
        profile_hash=seal_profile().hex(), steps=64, numeric=wire.NUMERIC, batch_size=16,
        branch=copy.deepcopy(branch), body_bytes=728, capsule_bytes=862,
        external_policy=dict(schema='pon-grouped-fresh-controlled-external-policy-v0',
            requester_public_key='31' * 32, source_public_key='47' * 32, latest_sequence=1,
            latest_digest=intent['registry_digest'], fixture_keys_public=True,
            external_demand_authenticated=False, independent_operators=False),
        candidates=[dict(nonce=i) for i in range(17, 20)], canonical_body_layout={
            'magic': '504741420000', 'profile_hash_bytes': 32, 'steps_u16_be': 64,
            'branch_hashes': list(BH), 'branch_u64_be': list(BI),
            'intent_hashes': list(IH), 'intent_u64_be': list(II)},
        challenge_formula='pon_wire.hash(pon-grouped-fresh-challenge-v0, [PGCE\\0\\0 || body || nonce_u64_be])',
        controlled_fixture_authority=True, native_parent_target_checked=True,
        fixture_signature_algorithm='native-strict-Ed25519', external_demand_authenticated=False,
        independent_operators=False, native_w1_admission=False, chainwork_awarded=0, production_activation=False)
    for key in wire.TIMINGS:
        result[key] = {'wall_ns': 1, 'thread_cpu_ns': None}
    refresh(result, encode_body(branch, intent))
    return result, f, model, requests, pins_for(result), branch, intent


class AdmissionWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.r, self.f, self.model, self.requests, self.pins, self.branch, self.intent = copy.deepcopy(self.original)

    def inspect(self, *, pins=True):
        return wire.inspect_freeze(self.r, self.f, self.model, self.requests,
                                   expected_native=self.pins if pins else None)

    def test_independent_framing_material_and_complete_nonce_mapping(self):
        got = self.inspect()
        self.assertTrue(got['pins_checked'])
        self.assertTrue(got['branch_pin_checked'])
        self.assertEqual(list(got['candidates_by_nonce']), [17, 18, 19])
        self.assertEqual(got['model_commitment'], model_commitment(self.model))
        self.assertEqual(got['request_precommitment'], old.request_precommitment(self.model, self.requests))
        self.assertEqual(got['body']['branch'], self.branch)
        self.assertEqual(got['body']['intent'], self.intent)
        self.assertEqual(len(bytes.fromhex(self.r['candidates'][0]['candidate_hex'])), 742)
        for key in ('signature_verified_by_this_parser', 'native_branch_authenticated_by_this_parser',
                    'external_demand_authenticated', 'production_activation'):
            self.assertIs(got[key], False)
        self.assertEqual(got['chainwork_awarded'], 0)
        self.f['op'] = 'freeze'
        self.assertTrue(self.inspect()['pins_checked'])

    def test_omitted_or_partial_external_pins_do_not_claim_full_pinning(self):
        self.assertFalse(self.inspect(pins=False)['pins_checked'])
        self.pins = {'expected_body_sha256': self.pins['expected_body_sha256']}
        result = self.inspect()
        self.assertFalse(result['pins_checked'])
        self.assertFalse(result['branch_pin_checked'])

    def test_each_intent_field_is_bound_even_after_all_self_hashes_recomputed(self):
        for key in (*IH, *II):
            with self.subTest(field=key):
                self.setUp()
                self.intent[key] = sha(('changed-' + key).encode()) if key in IH else self.intent[key] + 1
                self.assertNotEqual(self.intent[key], self.original[6][key])
                if key == 'previous_registry_digest':
                    self.intent['registry_sequence'] = 2
                refresh(self.r, encode_body(self.branch, self.intent))
                with self.assertRaises(ValueError):
                    self.inspect(pins=False)

    def test_each_branch_field_requires_exact_external_branch_snapshot(self):
        for key in (*BH, *BI):
            with self.subTest(field=key):
                self.setUp()
                self.branch[key] = sha(('changed-' + key).encode()) if key in BH else self.branch[key] + 1
                self.r['branch'] = copy.deepcopy(self.branch)
                refresh(self.r, encode_body(self.branch, self.intent))
                self.pins = {'branch': self.pins['branch']}
                with self.assertRaisesRegex(ValueError, 'EXTERNAL_BRANCH'):
                    self.inspect()

    def test_body_magic_profile_steps_trailing_and_capsule_trailing_rejected(self):
        original = bytes.fromhex(self.r['body_hex'])
        for offset in (0, 6, 38, 39):
            raw = bytearray(original)
            raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                wire.decode_body(bytes(raw))
        for raw in (original[:-1], original + b'\0'):
            with self.assertRaisesRegex(ValueError, 'BODY_LENGTH'):
                wire.decode_body(raw)
        for raw in (bytes.fromhex(self.r['capsule_hex'])[:-1], bytes.fromhex(self.r['capsule_hex']) + b'\0'):
            with self.assertRaisesRegex(ValueError, 'CAPSULE_LENGTH'):
                wire.decode_capsule(raw)

    def test_each_external_hash_pin_is_checked(self):
        for key in ('expected_body_sha256', 'expected_capsule_sha256', 'expected_policy_file_sha256'):
            with self.subTest(pin=key):
                self.setUp()
                self.pins[key] = '99' * 32
                with self.assertRaisesRegex(ValueError, 'EXTERNAL_PIN'):
                    self.inspect()

    def test_material_changes_cannot_hide_behind_supplied_commitment_strings(self):
        changes = (
            lambda: self.model['base'][0].__setitem__(0, self.model['base'][0][0] + 1),
            lambda: self.model['router'][0].__setitem__(1, self.model['router'][0][1] + 1),
            lambda: self.model['deltas'][2][1].__setitem__(2, self.model['deltas'][2][1][2] + 1),
            lambda: self.model.__setitem__('model_version', '99' * 32),
            lambda: self.requests[5]['x'].__setitem__(7, 0),
            lambda: self.requests.reverse(),
        )
        for change in changes:
            self.setUp()
            change()
            with self.assertRaisesRegex(ValueError, 'MATERIAL_'):
                self.inspect()

    def test_all_request_scopes_must_match_even_with_rebound_precommitment(self):
        self.requests[15]['scope'] = sha(b'another-authorized-scope')
        self.f['request_precommitment'] = old.request_precommitment(self.model, self.requests)
        with self.assertRaisesRegex(ValueError, 'AUTHORIZATION_SCOPE'):
            self.inspect()

    def test_request_and_body_time_windows_and_nonce_overflow(self):
        self.f['now_ns'] = self.f['expires_ns']
        with self.assertRaisesRegex(ValueError, 'ADMISSION_NOT_CURRENT'):
            self.inspect()
        self.setUp()
        self.requests[0]['deadline_ns'] = self.f['now_ns']
        with self.assertRaisesRegex(ValueError, 'REQUEST_NOT_CURRENT'):
            self.inspect()
        for changes in ({'nonce_first': (1 << 64) - 1, 'nonce_count': 2},
                        {'nonce_count': 4097}, {'nonce_first': 0}, {'expires_ns': 10},
                        {'available_until_ns': 999}, {'model_generation': 0}):
            self.setUp()
            self.intent.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                wire.decode_body(encode_body(self.branch, self.intent))

    def test_bool_float_uppercase_and_unknown_field_aliases_rejected(self):
        changes = (
            lambda: self.f.__setitem__('nonce_first', True),
            lambda: self.r.__setitem__('steps', 64.0),
            lambda: self.r.__setitem__('chainwork_awarded', False),
            lambda: self.r['branch'].__setitem__('generation', True),
            lambda: self.r['external_policy'].__setitem__('latest_sequence', True),
            lambda: self.r['candidates'][0].__setitem__('nonce', 17.0),
            lambda: self.r.__setitem__('capsule_hex', self.r['capsule_hex'].upper()),
            lambda: self.model['base'][0].__setitem__(0, True),
            lambda: self.requests[0]['x'].__setitem__(0, False),
            lambda: self.f.__setitem__('target', 'ff' * 32),
        )
        for change in changes:
            self.setUp()
            change()
            with self.assertRaises(ValueError):
                self.inspect()

    def test_candidates_have_exact_range_order_body_and_domain(self):
        changes = (
            lambda: self.r['candidates'].pop(),
            lambda: self.r['candidates'].reverse(),
            lambda: self.r['candidates'].__setitem__(1, copy.deepcopy(self.r['candidates'][0])),
            lambda: self.r['candidates'][0].__setitem__('candidate_hex', self.r['candidates'][0]['candidate_hex'] + '00'),
            lambda: self.r['candidates'][0].__setitem__('challenge', self.r['candidates'][0]['work_id']),
        )
        for change in changes:
            self.setUp()
            change()
            with self.assertRaises(ValueError):
                self.inspect()
        with self.assertRaisesRegex(ValueError, 'NONCE_RANGE'):
            wire.candidate_bytes(bytes.fromhex(self.r['body_hex']), 16)
        body = bytes.fromhex(self.r['body_hex'])
        raw = b'PGCE\0\0' + body + struct.pack('>Q', 17)
        tag = b'pon-grouped-fresh-challenge-v0'
        wrong = sha(b'TRNM-PON1\0' + struct.pack('>H', len(tag)) + tag + struct.pack('>I', len(raw)) + raw)
        self.setUp()
        self.r['candidates'][0]['challenge'] = wrong
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_HASH'):
            self.inspect()

    def test_signature_carrier_changes_no_candidate_and_does_not_bypass_external_pin(self):
        before = self.inspect()
        refresh(self.r, bytes.fromhex(self.r['body_hex']), signatures=b'R' * 64 + b'S' * 64)
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_PIN_EXPECTED_CAPSULE_SHA256'):
            self.inspect()
        # Re-pinning a fake fixture only checks consistency; never Ed25519 validity.
        self.pins = pins_for(self.r)
        after = self.inspect()
        self.assertEqual(before['candidates_by_nonce'], after['candidates_by_nonce'])
        self.assertNotEqual(before['capsule_sha256'], after['capsule_sha256'])
        self.assertFalse(after['signature_verified_by_this_parser'])
        self.assertEqual(after['chainwork_awarded'], 0)


if __name__ == '__main__':
    unittest.main()
