"""Independent attacks on the grouped research lottery's binding boundary.

Small-oracle counterexamples below deliberately violate stated assumptions.
They do not demonstrate an accepted attack on the unchanged native W1 profile.
"""
from __future__ import annotations

import copy
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import grouped_work_lottery_v0 as lottery
from experiments import grouped_work_lottery_audit_v0 as audit_runner
from experiments.grouped_cell_operator_v0 import make_commands
from test_grouped_cell_operator_v0 import fixture
from work_query_bound import expected_first_query_credit


def independent_domain_hash(domain, *parts):
    """Encode the published native framing without calling its implementation."""
    domain = domain.encode('ascii')
    value = b'trnm.domain.hash.v1' + struct.pack('>Q', len(domain)) + domain
    value += b''.join(struct.pack('>Q', len(part)) + part for part in parts)
    return hashlib.sha256(value).digest()


def independent_model_hash(init):
    raw = bytes.fromhex(init['model_version']) + struct.pack('>QQQ', 257, 3, 3)
    raw += b''.join(struct.pack('>q', value)
                    for matrix in [init['base'], init['router'], *init['deltas']]
                    for row in matrix for value in row)
    return independent_domain_hash(
        'pon-routed-int257-grouped-model-v0',
        b'pon-routed-int257-grouped-research-v0',
        b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', raw)


def independent_preinput_hash(init, requests):
    raw = struct.pack('>Q', 16)
    for request in requests:
        raw += bytes.fromhex(request['id']) + bytes.fromhex(request['scope'])
        raw += struct.pack('>QQ', request['arrival_ns'], request['deadline_ns'])
        raw += b''.join(struct.pack('>q', value) for value in request['x'])
    return independent_domain_hash(
        'pon-grouped-preinput-audit-v0', b'pon-grouped-int257-lottery-audit-v0',
        b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', independent_model_hash(init), raw)


def independent_header_bytes(header):
    profile = independent_domain_hash(
        'pon-grouped-audit-profile-v0', b'pon-grouped-int257-lottery-audit-v0',
        b'pon-routed-int257-grouped-research-v0',
        b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', struct.pack('>Q', 16))
    fields = ('network', 'parameters', 'parent', 'target', 'payee', 'task',
              'model_commitment', 'request_precommitment', 'batch_id',
              'transactions_commitment', 'prior_state_root')
    return (b'PGLA\x00\x00' + profile + b''.join(bytes.fromhex(header[key]) for key in fields)
            + struct.pack('>QQQ', header['height'], header['timestamp_ms'], header['nonce']))


class GroupedLotteryAdversarialTests(unittest.TestCase):
    def setUp(self):
        model, rows, provenance = fixture(16)
        self.init, commands = make_commands(model, rows, provenance, [16], 1, 0)
        self.requests = commands[0]['requests']
        hashes = ('network', 'parameters', 'parent', 'payee', 'task', 'batch_id',
                  'transactions_commitment', 'prior_state_root')
        self.envelope = {key: hashlib.sha256(key.encode()).hexdigest() for key in hashes}
        self.envelope.update(target=f'{(1 << 252) - 1:064x}', height=1, timestamp_ms=2, nonce=0)
        self.header = lottery.make_candidate(self.init, self.requests, self.envelope)
        self.product = lottery.reference_product(self.init, self.requests)
        self.claim = lottery.package_claim(self.init, self.requests, self.header, self.product)

    def verify(self, claim=None, *, expected=None, now=1, init=None, requests=None):
        return lottery.verify_package(
            self.claim if claim is None else claim,
            expected_header=self.header if expected is None else expected,
            init=self.init if init is None else init,
            requests=self.requests if requests is None else requests, now_ns=now)

    def test_independent_encoding_binds_raw_inputs_without_challenge_cycle(self):
        self.assertEqual(self.header['model_commitment'], independent_model_hash(self.init).hex())
        self.assertEqual(self.header['request_precommitment'],
                         independent_preinput_hash(self.init, self.requests).hex())
        raw = independent_header_bytes(self.header)
        self.assertEqual(len(raw), 414)
        self.assertEqual(lottery.encode_header(self.header), raw)
        self.assertEqual(lottery.decode_header(raw), self.header)
        self.assertEqual(lottery.derive_challenge(self.header),
                         independent_domain_hash('pon-grouped-challenge-audit-v0', raw).hex())
        self.assertEqual(lottery.context_for(self.header)['challenge'],
                         self.claim['context']['challenge'])
        checked = self.verify()
        self.assertTrue(checked['correct_relation'])
        for key in ('chainwork_awarded', 'business_credit', 'model_reward'):
            self.assertIs(type(checked[key]), int)
            self.assertEqual(checked[key], 0)
        for key in ('pow_qualified', 'production_activation', 'minimum_fresh_work_proved'):
            self.assertIs(checked[key], False)

    def test_every_candidate_field_changes_challenge_and_cannot_replace_expected_policy(self):
        for key in (*lottery.HEADER_HASH_FIELDS, *lottery.HEADER_INT_FIELDS):
            changed = copy.deepcopy(self.header)
            if key in lottery.HEADER_INT_FIELDS:
                changed[key] += 1
            else:
                first = '1' if changed[key][0] != '1' else '2'
                changed[key] = first + changed[key][1:]
            with self.subTest(key=key):
                self.assertNotEqual(lottery.derive_challenge(changed),
                                    self.claim['context']['challenge'])
                with self.assertRaisesRegex(ValueError, 'EXPECTED_HEADER_BINDING'):
                    self.verify(expected=changed)

    def test_output_proof_ticket_and_profile_cannot_enter_candidate_or_raw_requests(self):
        for key in ('challenge', 'ticket', 'proof', 'output', 'receipt_id',
                    'statement_commitment', 'resulting_state_root', 'profile',
                    'dtype', 'shape', 'partition', 'routing'):
            with self.subTest(envelope=key), self.assertRaisesRegex(ValueError, 'ENVELOPE_FIELDS'):
                lottery.make_candidate(self.init, self.requests, dict(self.envelope, **{key: 'a' * 64}))
            requests = copy.deepcopy(self.requests)
            requests[0][key] = 'a' * 64
            with self.subTest(request=key), self.assertRaisesRegex(ValueError, 'REQUEST_FIELDS'):
                lottery.make_candidate(self.init, requests, self.envelope)

    def test_header_wire_has_one_length_version_profile_and_endianness(self):
        raw = lottery.encode_header(self.header)
        malformed = [b'', raw[:-1], raw + b'\0', bytearray(raw), raw[:2] + b'xx' + raw[4:]]
        altered_profile = bytearray(raw)
        altered_profile[6] ^= 1
        malformed.append(bytes(altered_profile))
        for value in malformed:
            with self.subTest(value_type=type(value).__name__, length=len(value)), self.assertRaises(ValueError):
                lottery.decode_header(value)
        changed = dict(self.header, nonce=(1 << 64) - 1)
        self.assertEqual(lottery.decode_header(lottery.encode_header(changed)), changed)
        self.assertEqual(lottery.encode_header(changed)[-8:], b'\xff' * 8)

    def test_header_numbers_and_hashes_do_not_accept_aliases_or_extra_profiles(self):
        for key in lottery.HEADER_INT_FIELDS:
            for value in (True, False, 1.0, -1, 1 << 64, '1', None):
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    lottery.encode_header(dict(self.header, **{key: value}))
        for key in lottery.HEADER_HASH_FIELDS:
            for value in ('A' * 64, 'a' * 63, 'a' * 65, b'\xaa' * 32, None):
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    lottery.encode_header(dict(self.header, **{key: value}))
        for value in ('0' * 64, '0x' + '1' * 62):
            with self.subTest(target=value), self.assertRaises(ValueError):
                lottery.encode_header(dict(self.header, target=value))
        with self.assertRaisesRegex(ValueError, 'PROFILE'):
            lottery.encode_header(dict(self.header, profile='another-numerical-profile'))

    def test_missing_caller_clock_cannot_create_a_verified_research_receipt(self):
        for clock in (None, True, -1, 1.0, 1 << 64):
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                self.verify(now=clock)
        with self.assertRaisesRegex(ValueError, 'REQUEST_NOT_CURRENT'):
            self.verify(now=self.requests[0]['deadline_ns'])

    def test_request_order_identity_scope_and_original_deadline_are_precommitted(self):
        for key in ('id', 'scope', 'arrival_ns', 'deadline_ns', 'x', 'order'):
            requests = copy.deepcopy(self.requests)
            if key == 'order':
                requests.reverse()
            elif key in ('id', 'scope'):
                requests[0][key] = 'f' * 64
            elif key == 'x':
                requests[0][key][10] = 1
            else:
                requests[0][key] += 1
            changed = lottery.make_candidate(self.init, requests, self.envelope)
            with self.subTest(key=key):
                self.assertNotEqual(changed['request_precommitment'], self.header['request_precommitment'])
                self.assertNotEqual(lottery.derive_challenge(changed), self.claim['context']['challenge'])
                with self.assertRaises(ValueError):
                    self.verify(requests=requests)

    def test_invalid_inputs_cannot_be_normalized_into_an_allowed_work_unit(self):
        bad_requests = [self.requests[:-1], self.requests + [self.requests[0]]]
        for change in ('duplicate', 'zero_bias', 'outside_range', 'bool', 'float', 'interval'):
            requests = copy.deepcopy(self.requests)
            if change == 'duplicate':
                requests[1]['id'] = requests[0]['id']
            elif change == 'zero_bias':
                requests[0]['x'][-1] = 0
            elif change == 'outside_range':
                requests[0]['x'][0] = 9
            elif change == 'bool':
                requests[0]['x'][0] = True
            elif change == 'float':
                requests[0]['x'][0] = 8.0
            else:
                requests[0]['arrival_ns'] = requests[0]['deadline_ns']
            bad_requests.append(requests)
        for requests in bad_requests:
            with self.subTest(size=len(requests)), self.assertRaises(ValueError):
                lottery.make_candidate(self.init, requests, self.envelope)
        for key in ('base', 'router', 'deltas'):
            for value in (32768, -32768, True, 0.0):
                init = copy.deepcopy(self.init)
                matrix = init[key][0] if key == 'deltas' else init[key]
                matrix[0][0] = value
                with self.subTest(matrix=key, value=value), self.assertRaises(ValueError):
                    lottery.make_candidate(init, self.requests, self.envelope)

    def test_rehashed_wrong_products_are_rejected_by_full_reference_arithmetic(self):
        for key in sorted(lottery.PRODUCT_FIELDS):
            product = copy.deepcopy(self.product)
            if key in ('router_outputs', 'logits'):
                product[key][0][0] += 1
            elif key in ('routes', 'predictions'):
                product[key][0] = (product[key][0] + 1) % 3
            elif key == 'groups':
                product[key][0].reverse()
            else:
                product[key] += 1
            claim = lottery.package_claim(self.init, self.requests, self.header, product)
            with self.subTest(key=key):
                self.assertNotEqual(claim['statement_commitment'], self.claim['statement_commitment'])
                with self.assertRaisesRegex(ValueError, 'PRODUCT_RELATION'):
                    self.verify(claim)

    def test_product_boolean_float_and_unbounded_counts_refuse_before_equality(self):
        for key in sorted(lottery.PRODUCT_FIELDS):
            for value in (False, 0.0):
                product = copy.deepcopy(self.product)
                if key in ('router_outputs', 'logits', 'groups'):
                    product[key][0][0] = value
                elif key in ('routes', 'predictions'):
                    product[key][0] = value
                else:
                    product[key] = value
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    lottery.package_claim(self.init, self.requests, self.header, product)
        for value in (-1, 1 << 64):
            product = dict(self.product, useful_dense_macs=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                lottery.package_claim(self.init, self.requests, self.header, product)

    def test_transport_randomness_and_json_reordering_offer_only_one_ticket(self):
        identities = set()
        for nonce in range(64):
            claim = lottery.package_claim(self.init, self.requests, self.header, self.product,
                                           transport_aux_hex=nonce.to_bytes(2, 'big').hex())
            reordered = dict(reversed(list(claim.items())))
            raw = json.dumps(reordered, indent=nonce % 3).encode()
            parsed = lottery.decode_package(raw)
            checked = self.verify(parsed)
            self.assertEqual(checked['chainwork_awarded'], 0)
            identities.add((claim['context']['challenge'], claim['ticket'], claim['receipt_id']))
        self.assertEqual(len(identities), 1)
        self.assertEqual(next(iter(identities)),
                         (self.claim['context']['challenge'], self.claim['ticket'], self.claim['receipt_id']))

    def test_malformed_json_duplicate_fields_and_false_verification_flags_refuse(self):
        raw = json.dumps(self.claim).encode()
        for extra in (b'"ticket":"' + self.claim['ticket'].encode() + b'",',
                      b'"schema":"' + lottery.SCHEMA.encode() + b'",'):
            with self.assertRaises(ValueError):
                lottery.decode_package(b'{' + extra + raw[1:])
        for raw_bad in (b'{}', raw[:-1], b'[]', b'\xff', raw + b'{}',
                        b' ' * (lottery.MAX_PACKAGE_BYTES + 1)):
            with self.subTest(length=len(raw_bad)), self.assertRaises(ValueError):
                lottery.decode_package(raw_bad)
        for key in ('semantic_verified', 'pow_qualified', 'chainwork_awarded', 'proof'):
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'PACKAGE_FIELDS'):
                self.verify(dict(self.claim, **{key: True}))
        for auxiliary in ('0', 'AB', None, '00' * 4097):
            with self.subTest(auxiliary=auxiliary), self.assertRaisesRegex(ValueError, 'TRANSPORT_AUX'):
                self.verify(dict(self.claim, transport_aux_hex=auxiliary))

    def test_altered_receipt_or_commitment_is_not_proof_of_correct_work(self):
        for key in ('model_commitment', 'input_commitment', 'statement_commitment', 'ticket', 'receipt_id'):
            claim = dict(self.claim, **{key: '0' * 64})
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'PACKAGE_BINDING'):
                self.verify(claim)
        for key in ('chain', 'parent', 'challenge', 'batch_id'):
            claim = copy.deepcopy(self.claim)
            claim['context'][key] = '0' * 64
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'PACKAGE_BINDING'):
                self.verify(claim)

    def test_post_ticket_target_swap_requires_a_new_committed_query(self):
        late_target = max(int(self.claim['ticket'], 16), 1)
        changed = dict(self.header, target=f'{late_target:064x}')
        self.assertNotEqual(changed['target'], self.header['target'])
        claim = lottery.package_claim(self.init, self.requests, changed, self.product)
        self.assertNotEqual(claim['ticket'], self.claim['ticket'])
        with self.assertRaisesRegex(ValueError, 'EXPECTED_HEADER_BINDING'):
            self.verify(claim)

    def test_cached_product_can_make_new_nonce_and_parent_tickets_but_never_work_credit(self):
        parent_changed = dict(self.envelope, parent='f' * 64)
        header = lottery.make_candidate(self.init, self.requests, parent_changed)
        claim = lottery.package_claim(self.init, self.requests, header, self.product)
        self.assertEqual(claim['product'], self.claim['product'])
        self.assertNotEqual(claim['ticket'], self.claim['ticket'])
        self.assertEqual(self.verify(claim, expected=header)['chainwork_awarded'], 0)
        with patch.object(lottery, 'reference_product', wraps=lottery.reference_product) as reference:
            result = lottery.cached_reticket_audit(
                self.init, self.requests, self.envelope, nonces=[0, 1, 0, 2, 1], now_ns=1)
        # One producer preparation, then a complete reference recomputation per
        # attempt, even for duplicate tickets. Verifier cost is never erased.
        self.assertEqual(reference.call_count, 6)
        self.assertEqual(result['planned_attempts'], 5)
        self.assertEqual(len(result['attempts']), 5)
        self.assertEqual(result['distinct_ticket_inputs'], 3)
        self.assertEqual([row['first_ticket_input'] for row in result['attempts']],
                         [True, True, False, True, False])
        for row in result['attempts']:
            self.assertEqual(row['status'], 'verified_research')
            self.assertEqual(row['producer_new_matrix_contractions'], 0)
            self.assertEqual(row['chainwork_awarded'], 0)
            self.assertGreaterEqual(row['verifier_cpu_ns'], 0)
        self.assertIs(result['fresh_matrix_work_per_ticket_required'], False)

    def test_failed_verifier_attempts_keep_already_queried_ticket_identities_and_cost(self):
        result = lottery.cached_reticket_audit(
            self.init, self.requests, self.envelope, nonces=[0, 1, 0],
            now_ns=self.requests[0]['deadline_ns'])
        self.assertEqual(result['planned_attempts'], 3)
        self.assertEqual(len(result['attempts']), 3)
        self.assertEqual(result['distinct_ticket_inputs'], 2)
        self.assertEqual([row['first_ticket_input'] for row in result['attempts']], [True, True, False])
        for row in result['attempts']:
            self.assertEqual(row['status'], 'rejected')
            self.assertEqual(row['error'], 'REQUEST_NOT_CURRENT')
            self.assertEqual(len(row['challenge']), 64)
            self.assertEqual(len(row['statement']), 64)
            self.assertEqual(len(row['ticket']), 64)
            self.assertEqual(row['producer_new_matrix_contractions'], 0)
            self.assertGreaterEqual(row['producer_cpu_ns'], 0)
            self.assertGreaterEqual(row['verifier_cpu_ns'], 0)
            self.assertGreaterEqual(row['attempt_cpu_ns'], row['producer_cpu_ns'] + row['verifier_cpu_ns'])
            self.assertEqual(row['chainwork_awarded'], 0)

    def test_cached_encoded_producer_matches_original_builder_for_nonce_parent_and_carrier_variants(self):
        prepared = lottery.prepare_reticket(self.init, self.requests)
        for nonce, parent in itertools.product((0, 1, 63, (1 << 64) - 1),
                                               (self.header['parent'], 'f' * 64)):
            header = dict(self.header, nonce=nonce, parent=parent)
            with self.subTest(nonce=nonce, parent=parent):
                expected = lottery.package_claim(self.init, self.requests, header, self.product,
                                                  transport_aux_hex='cafe')
                actual = lottery.bind_cached(prepared, header, transport_aux_hex='cafe')
                self.assertEqual(actual, expected)
                self.assertEqual(self.verify(actual, expected=header)['chainwork_awarded'], 0)

    def test_cached_preparation_owns_bytes_and_cannot_claim_changed_caller_material(self):
        init, requests = copy.deepcopy(self.init), copy.deepcopy(self.requests)
        prepared = lottery.prepare_reticket(init, requests)
        original = lottery.bind_cached(prepared, self.header)
        init['base'][0][0] += 1
        requests[0]['x'][10] = 1
        self.assertEqual(lottery.bind_cached(prepared, self.header), original)
        # A caller may mutate its returned product; it must not mutate future
        # packages assembled from the immutable serialized preparation.
        returned = lottery.bind_cached(prepared, self.header)
        returned['product']['logits'][0][0] += 1
        self.assertEqual(lottery.bind_cached(prepared, self.header), original)
        changed = lottery.make_candidate(init, requests, self.envelope)
        with self.assertRaisesRegex(ValueError, 'PREPARED_MATERIAL_BINDING'):
            lottery.bind_cached(prepared, changed)
        with self.assertRaises(ValueError):
            self.verify(original, init=init, requests=requests)

    def test_callback_mutation_does_not_rewrite_retained_attempt_and_failure_stops_without_retry(self):
        callback_rows = []

        def mutate(row):
            callback_rows.append(copy.deepcopy(row))
            row['ticket'] = '0' * 64
            row['status'] = 'invented-success'

        result = lottery.cached_reticket_audit(self.init, self.requests, self.envelope,
            nonces=[0, 1], now_ns=1, on_attempt=mutate)
        self.assertEqual(result['attempts'], callback_rows)
        for exception in (OSError, ValueError):
            prefix = []

            def fail_on_second_write(row):
                prefix.append(copy.deepcopy(row))
                if len(prefix) == 2:
                    raise exception('injected evidence write failure')

            with self.subTest(exception=exception.__name__), self.assertRaisesRegex(
                    exception, 'injected evidence write failure'):
                lottery.cached_reticket_audit(self.init, self.requests, self.envelope,
                    nonces=[0, 1, 2], now_ns=1, on_attempt=fail_on_second_write)
            self.assertEqual([row['nonce'] for row in prefix], [0, 1])
            self.assertTrue(all(row['status'] == 'verified_research' for row in prefix))
        with self.assertRaisesRegex(ValueError, 'AUDIT_CALLBACK'):
            lottery.cached_reticket_audit(self.init, self.requests, self.envelope,
                                         nonces=[0], now_ns=1, on_attempt=123)


class AuditRunnerFailureBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE).decode().strip()

    def repository_fixture(self):
        self.git('init', '-q')
        (self.root / 'source.py').write_text('VALUE = 7\n')
        self.git('add', 'source.py')
        self.git('-c', 'user.name=Audit Fixture', '-c', 'user.email=audit-fixture@example.invalid',
                 'commit', '-qm', 'Source guard test fixture')
        runner = self.root / 'native-observed-bytes'
        runner.write_bytes(b'not executed; source identity test only')
        return self.git('rev-parse', 'HEAD'), runner

    def test_source_guard_allows_untracked_evidence_but_rejects_untracked_executing_code(self):
        source_sha, runner = self.repository_fixture()
        before = audit_runner.source_snapshot(source_sha, runner, root=self.root, source_files=['source.py'])
        (self.root / 'raw-evidence.json').write_text('{"status":"observed"}')
        after = audit_runner.source_snapshot(source_sha, runner, root=self.root, source_files=['source.py'])
        self.assertEqual(before, after)
        (self.root / 'new_module.py').write_text('VALUE = 8\n')
        with self.assertRaisesRegex(ValueError, 'SOURCE_PATH_UNTRACKED_OR_MISSING'):
            audit_runner.source_snapshot(source_sha, runner, root=self.root,
                                         source_files=['source.py', 'new_module.py'])

    def test_source_guard_rejects_modified_tracked_bytes_wrong_head_and_changed_binary(self):
        source_sha, runner = self.repository_fixture()
        before = audit_runner.source_snapshot(source_sha, runner, root=self.root, source_files=['source.py'])
        runner.write_bytes(b'different observed binary bytes')
        after = audit_runner.source_snapshot(source_sha, runner, root=self.root, source_files=['source.py'])
        self.assertNotEqual(before['native_runner_sha256'], after['native_runner_sha256'])
        (self.root / 'source.py').write_text('VALUE = 9\n')
        with self.assertRaisesRegex(ValueError, 'TRACKED_SOURCE_DIRTY'):
            audit_runner.source_snapshot(source_sha, runner, root=self.root, source_files=['source.py'])
        with self.assertRaisesRegex(ValueError, 'SOURCE_HEAD_MISMATCH'):
            audit_runner.source_snapshot('0' * 40, runner, root=self.root, source_files=['source.py'])

    def test_preregistered_population_is_fixed_and_output_directory_is_create_only(self):
        plan = audit_runner.preregistration('a' * 40, 30)
        self.assertEqual(plan['primary']['nonces'], list(range(64)) + [0])
        self.assertEqual(plan['expired']['nonces'], list(range(8)))
        self.assertEqual(int(plan['primary']['target'], 16), (1 << 252) - 1)
        self.assertIs(plan['primary']['stop_on_success'], False)
        self.assertIs(plan['fixed_material']['replay_source'], True)
        self.assertEqual(plan['fixed_material']['partition'], 'consumer')
        self.assertEqual((plan['fixed_material']['offset'], plan['fixed_material']['count']), (0, 16))
        sentinel = self.root / 'keep.txt'
        sentinel.write_text('original evidence')
        with self.assertRaises(FileExistsError):
            audit_runner.execute(SimpleNamespace(out=self.root, source_sha='a' * 40,
                                                runner=self.root / 'missing', native_timeout=30))
        self.assertEqual(sentinel.read_text(), 'original evidence')
        for value in (True, 0, -1, 61, float('nan'), float('inf')):
            with self.subTest(timeout=value), self.assertRaisesRegex(ValueError, 'NATIVE_TIMEOUT'):
                audit_runner.preregistration('a' * 40, value)

    def test_native_nonzero_exit_retains_raw_output_returncode_and_observed_process_cost(self):
        runner = self.root / 'fault-child'
        runner.write_text(f'#!{sys.executable}\nimport sys\nprint("fault stdout")\n'
                          'print("fault stderr", file=sys.stderr)\nraise SystemExit(9)\n')
        runner.chmod(0o755)
        out = self.root / 'nonzero'
        out.mkdir()
        recorder = audit_runner.Recorder(out)
        with self.assertRaisesRegex(ValueError, 'NATIVE_EXIT_9'):
            audit_runner.native_crosscheck(runner, 2, {}, {}, {}, [], '0' * 64, recorder)
        result = json.loads((out / 'native-process-result.json').read_text())
        self.assertEqual(result['returncode'], 9)
        self.assertEqual((out / 'native-stdout.ndjson').read_bytes(), b'fault stdout\n')
        self.assertEqual((out / 'native-stderr.txt').read_bytes(), b'fault stderr\n')
        self.assertGreaterEqual(recorder.stages['native_process']['wall_ns'], 0)
        self.assertGreaterEqual(recorder.stages['native_process']['child_cpu_ns'], 0)

    def test_native_timeout_keeps_prefix_and_failure_without_success_receipt(self):
        runner = self.root / 'timeout-child'
        runner.write_text(f'#!{sys.executable}\nimport time\nprint("started", flush=True)\ntime.sleep(5)\n')
        runner.chmod(0o755)
        out = self.root / 'timeout'
        out.mkdir()
        recorder = audit_runner.Recorder(out)
        with self.assertRaisesRegex(ValueError, 'NATIVE_EXECUTOR_TIMEOUT'):
            audit_runner.native_crosscheck(runner, .25, {}, {}, {}, [], '0' * 64, recorder)
        failure = json.loads((out / 'native-failure.json').read_text())
        self.assertEqual(failure['error'], 'NATIVE_EXECUTOR_TIMEOUT')
        self.assertEqual(failure['stdout_prefix_bytes'], len((out / 'native-stdout.ndjson').read_bytes()))
        self.assertIs(failure['stdout_truncated'], False)
        self.assertEqual(recorder.stages['native_process']['status'], 'failed')
        self.assertFalse((out / 'native-crosscheck.json').exists())

    def test_recorder_preserves_cross_group_duplicate_queries_and_writes_each_attempt(self):
        recorder = audit_runner.Recorder(self.root)
        first = recorder.observer('primary')
        second = recorder.observer('expired')
        row = {'index': 0, 'status': 'verified_research', 'challenge': 'a' * 64,
               'statement': 'b' * 64, 'ticket': 'c' * 64, 'chainwork_awarded': 0}
        first(row)
        second(dict(row, status='rejected', error='REQUEST_NOT_CURRENT'))
        self.assertIs(recorder.rows['primary'][0]['global_first_ticket_input'], True)
        self.assertIs(recorder.rows['expired'][0]['global_first_ticket_input'], False)
        self.assertIs(recorder.rows['expired'][0]['first_ticket_input'], True)
        self.assertEqual(len(recorder.seen), 1)
        self.assertEqual(json.loads((self.root / 'expired/attempt-000.json').read_text())['status'], 'rejected')
        self.assertNotIn('global_first_ticket_input', row)


class TicketAssumptionAdversarialTests(unittest.TestCase):
    def test_selecting_target_after_ticket_breaks_the_first_query_bound(self):
        # Enumerate the complete toy oracle, keeping the native target-zero
        # refusal. With target chosen after Y, every outcome wins and the
        # predictable-target hypothesis is false even though every ticket is
        # uniformly distributed before revelation.
        modulus = 256
        late_target_credit = Fraction(sum(
            modulus // (max(ticket, 1) + 1) for ticket in range(modulus)
        ), modulus)
        self.assertEqual(late_target_credit, Fraction(669, 128))
        self.assertGreater(late_target_credit, 1)
        for precommitted_target in range(1, modulus):
            self.assertLessEqual(
                expected_first_query_credit(precommitted_target, bits=8), 1)

    def test_independent_free_proof_variants_would_multiply_queries(self):
        # An exhaustive two-variant toy oracle checks the exact formula; the
        # larger example is arithmetic under independence, not a benchmark.
        modulus, target, variants = 16, 1, 2
        success = sum(any(ticket <= target for ticket in tickets)
                      for tickets in itertools.product(range(modulus), repeat=variants))
        p = Fraction(target + 1, modulus)
        self.assertEqual(Fraction(success, modulus ** variants), 1 - (1 - p) ** variants)
        low_p = Fraction(1, 1 << 20)
        hypothetical_ratio = (1 - (1 - low_p) ** 64) / low_p
        self.assertGreater(hypothetical_ratio, Fraction(63_998, 1000))
        self.assertLess(hypothetical_ratio, 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
