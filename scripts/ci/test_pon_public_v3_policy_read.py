#!/usr/bin/env python3
"""Independent exact-vector/schema controls, not a service execution receipt."""
import copy
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_policy_read as reader

EXPECTED = {
    'r10': ['099c63fdd9a5feedd83dea1e681bcf35fa4ce219338df81a46c621ee5f5c028a',
            'a589532b416e0d35273235ec692cf47040edf182df2121702c1b237c8cff52e7',
            'fbd012278826496785fbd166d2d920ffa70a3491e52ddf2c9211d782357f9c35'],
    'r11': ['0d262ab290e74fa827b89bf11b581053eff9c347d54f511899315d4362febadc',
            'dfdba7a8bfc98ff3019425222a7d66d1e7d75dd164fad5eda3d9a54d61e5e5ce',
            '1141ff9f730ab723f9499215ae7396ef3c26020973c8ab345179bd78b31da9e7'],
    'r12': ['98db0a0a3cf84367cc62b293ace125ecfed37798b45c74e1382c9e625d3955b0',
            '56f683ca9a56a872747f58899c2734763303ad547cabf88d24a18c3994517d15',
            '0b32dc1c5cb3cd32f127792c2437a7e06afdee24dfd145e6c147ae9effc93973'],
    'r13': ['c110c3ccb1e229c3a85f4819b1e087fa819c865b50f8bd3ab78d3b8f45206cb2', 'af74a97fd543741369cf58b5e58a16f33ea74d71bb4d4641ab4700827bac1607', 'e171d2942b8abfd95351036464b5451b4562f0854f4b43b2de59c4e486bda176'],
    'r14': ['6d04725d8e7a84560baf69440b1becd79f47c9f1fb5e63b85f1447400c85d43f',
            'ffdf6e0653a4c1cb89fd92414ddc75052a100c75423b51b4cf86fed6d9c39258',
            '82033cc655921f7217f7dba8f844aa5d06a455cceda851af530e91f7672f9ec8'],
    'r15': ['7407c22c85e06aecf4a80b36e0448fed09d36f1c3709b30d31602c399ac5ff73',
            'b2ee3da40ceb26af516e3b7f2a913abba5ca7311a5930c9d3fcd8f312aac8c3f',
            '465805ad4ba2703e39eaf3cb8ca64881f5fb5f200f56397121ec674608db2f7c'],
    'r16': ['9a266e6e8d87c882ac052ca94119227b27cf0a4be99ba081cd7a5597b9d20658', '7701ac72cd420c36edc8abc6d486c0936ceb12e300f4bd1c965d3f43117edbad', 'a94c58876e87c298436e02d2b18b338088080bffa8fa22920cfffda1b84c194f'],
    'r17': ["c25a91118266f63379927d0a9ee12ce038ea949b3e0e79d4347ce24397542a4b","fd49fd3db695e7c7d2d0a0fd1e461b1e545bf97d05c8c58c62ec867267b59f7f","2a2d9766026a70a9383165dc318e38a25abeb64c11f167d68101eeb016ac0385"],
}
ARITHMETIC_EXPECTED = [
    '14ada27ef062b1e510b7d7ab470e83157e58e7752b8f27a754f64dac614146e3',
    '05ace470c6c6d89dabe506e4fa96555847f34e72ae28255b8eb80c9f9c2dfe5b',
    '8af03f5efd2dc465f6180faddd36561c6f4d42f996ab0f901594c2b460c3d1bd',
]
R14_ARITHMETIC_EXPECTED = [
    'c6d64d3f924ddc6b621e6a7faec04b4a835add3a90c8e3835a7718f77cf95825',
    '0d462bce59800e8a2e4cfe348d0db06bf9771caa4f9a56df36a7d8b59fe3b507',
    '4b04f3da433221f69055cc4e78268e0a4f2393ae66b43a849fc58e3c14ca485f',
]
R15_ARITHMETIC_EXPECTED = [
    '76d4a3d770673b6c910f82151abb8cabeccf7addb18b80a3bb055af882d97355',
    '83fd5a4f0bebc84f7ba88db24d71c0829d23438a97bc9033f22ea621e50460cf',
    '710c40ba97e191a998f5340b379c8c2fd12e7b5684f004155889050703456dcc',
]
R16_ARITHMETIC_EXPECTED = ['3d2064a0eae79ead4658a17770eede1c4c11fe29554b934b9019f92bc8cf87a0', 'a194005269f69a7c8732ef6db689e63b0e6f95bed8ce8e9aa3536b774d0aac69', '51f2c7e2f74caea92ad6a2566d2463ed1ab0717257f3e8cb245f4d0865359997']
CURRENT_ARITHMETIC_EXPECTED = ["97d8078ea6b4648eff20608d6e38a453165da7eace04611e93a5fa861f03066f","9883d6a055ed3c005763139b29019622e1941647b379a5cebf9a6a477b427573","12c0e6b0feeac6dc41b6322aaafbadd83587c74ea413664bb38bfe85ebd3b23e"]


def observation(revision='r13'):
    return dict(schema=reader.OBSERVATION_SCHEMA,
                transport_profile='public-protected-development-v3',
                policy_id=EXPECTED[revision][0], ticket_bits=8, lifetime_ms=2000)


def arithmetic_observation(revision='r13'):
    expected = {'r13': ARITHMETIC_EXPECTED, 'r14': R14_ARITHMETIC_EXPECTED,
                'r15': R15_ARITHMETIC_EXPECTED, 'r16': R16_ARITHMETIC_EXPECTED,
                'r17': CURRENT_ARITHMETIC_EXPECTED}[revision]
    return {**observation(revision), 'policy_id': expected[0]}


class PolicyReaderTests(unittest.TestCase):
    def test_separate_arithmetic_vectors_bind_exact_source_contract_and_base(self):
        config = reader.load_profiles()
        entry = config['arithmetic_profile']
        self.assertEqual([reader.arithmetic_policy_id(config, bits, 2000)
                          for bits in (8, 12, 16)], CURRENT_ARITHMETIC_EXPECTED)
        for revision, expected in (('r13', ARITHMETIC_EXPECTED),
                                   ('r14', R14_ARITHMETIC_EXPECTED),
                                   ('r15', R15_ARITHMETIC_EXPECTED),
                                   ('r16', R16_ARITHMETIC_EXPECTED),
                                   ('r17', CURRENT_ARITHMETIC_EXPECTED)):
            self.assertEqual([reader.arithmetic_policy_id(config, bits, 2000,
                                                         base_revision=revision)
                              for bits in (8, 12, 16)], expected)
            value = reader.identify_observation(arithmetic_observation(revision))
            self.assertEqual((value['resource_revision'], value['base_resource_revision'],
                              value['work_profile']),
                             (revision + '-arithmetic-facts-v1', revision, 'arithmetic-facts-v1'))
            self.assertNotEqual(value['policy_id'], observation(revision)['policy_id'])
        source = (reader.CONFIG.parents[2] / entry['source']).read_text()
        self.assertIn('b"' + entry['hash_domain'] + '"', source)
        self.assertEqual(re.findall(r'b"(fresh-empty-server-local-owner/[^\"]+)"', source),
                         [entry['resource_contract']])
        self.assertIn('&self.id()', source)
        self.assertIn('&(MAX_ARITHMETIC_FACT_SLOTS as u64).to_le_bytes()', source)
        self.assertIn('&(MAX_ARITHMETIC_FACT_SOFTWARE_BYTES as u64).to_le_bytes()', source)
        crypto = reader.CONFIG.parents[2] / 'trillionnium/crates/trnm-crypto-primitives/src/pon_work/arithmetic_facts.rs'
        self.assertRegex(crypto.read_text(), r'MAX_ARITHMETIC_FACT_SLOTS: usize = 64;')
        self.assertRegex(crypto.read_text(), r'MAX_ARITHMETIC_FACT_SOFTWARE_BYTES: usize = 4 \* 1024 \* 1024;')
        for fields in ({'ticket_bits': 12}, {'lifetime_ms': 1999}, {'ticket_bits': True},
                       {'work_profile': 'arithmetic-facts-v1'}, {'resource_revision': 'r13'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                reader.identify_observation({**arithmetic_observation(), **fields})

    def test_arithmetic_metadata_or_vectors_cannot_be_repinned(self):
        config = reader.load_profiles()
        for field, changed in (('base_revision', 'r12'), ('slots', 65), ('slots', True),
                               ('maximum_software_bytes', 8388608), ('source', 'elsewhere.rs'),
                               ('work_profile', 'raw-r13'), ('hash_domain', 'public-protected-profile-v3')):
            with tempfile.TemporaryDirectory() as directory:
                value = copy.deepcopy(config)
                value['arithmetic_profile'][field] = changed
                path = Path(directory) / 'profiles.json'
                path.write_text(json.dumps(value))
                with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                    reader.load_profiles(path)
        for edit in (lambda entry: entry['vectors'][0].update(policy_id=EXPECTED['r13'][0]),
                     lambda entry: entry.update(resource_contract=entry['resource_contract'] + '/changed')):
            value = copy.deepcopy(config)
            edit(value['arithmetic_profile'])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'profiles.json'
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    reader.load_profiles(path)

    def test_independent_r10_through_r16_vectors_recompute_exactly(self):
        config = reader.load_profiles()
        for revision in ('r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16'):
            expected = EXPECTED[revision]
            self.assertEqual([reader.policy_id(config, revision, bits, 2000)
                              for bits in (8, 12, 16)], expected)
            self.assertEqual(reader.identify_observation(observation(revision))['resource_revision'],
                             revision)
        self.assertEqual([row['policy_id'] for row in config['revisions']['r16']['vectors']],
                         EXPECTED['r16'])


    def test_r17_admission_wait_vectors_keep_original_limits_and_full_r16_contract(self):
        config = reader.load_profiles()
        self.assertEqual(config['current_revision'], 'r17')
        self.assertEqual([reader.policy_id(config, 'r17', bits, 2000)
                          for bits in (8, 12, 16)], EXPECTED['r17'])
        self.assertEqual(reader.identify_observation(observation('r17'))['resource_revision'],
                         'r17')
        self.assertEqual([config[key] for key in ('burst_ns', 'refill_ns_per_second',
                                                  'start_reserve_ns', 'worker_limit')],
                         [2_000_000_000, 250_000_000, 100_000_000, 2])
        self.assertLessEqual(len(reader.CONFIG.read_bytes()), 64 * 1024)
        expected_prefix = (
            'resource-revision-r17/'
            'actual-thread-cpu-admission-wait-same-original-account-before-queue-registration/'
            'rolling-debits-for-success-refusal-cancel-deadline-retry-and-unwind/'
            'no-admission-reservation-worker-or-principal-return/'
            'locked-wait-debit-before-original-start-eligibility/'
            'exact-last-sample-move-to-owner-no-resample-or-overlap/'
            'typed-same-account-reserve-and-handoff/'
            'unknown-clock-poison-credit-overflow-fail-closed/'
            'diagnostic-flow-overflow-unknown-no-policy-change/'
            'original-burst-refill-reserve-workers-grants-and-deadlines/')
        self.assertEqual(config['revisions']['r17']['resource_contract'], expected_prefix
                         + config['revisions']['r16']['resource_contract'].removeprefix(
                             'resource-revision-r16/'))

    def test_r16_raw_and_arithmetic_cannot_claim_or_be_repinned_as_r17(self):
        config = reader.load_profiles()
        for value, revision in ((observation('r16'), 'r16'),
                                (arithmetic_observation('r16'), 'r16-arithmetic-facts-v1')):
            with self.subTest(revision=revision):
                self.assertEqual(reader.identify_observation(value)['resource_revision'], revision)
                with self.assertRaises(ValueError):
                    reader.identify_observation({**value, 'resource_revision': 'r17'})
        for field, predecessor in (('revisions', EXPECTED['r16'][0]),
                                   ('arithmetic_profile', R16_ARITHMETIC_EXPECTED[0])):
            changed = copy.deepcopy(config)
            entry = (changed['revisions']['r17'] if field == 'revisions'
                     else changed['arithmetic_profile'])
            entry['vectors'][0]['policy_id'] = predecessor
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'profiles.json'
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, 'vector hash mismatch'):
                    reader.load_profiles(path)
        self.assertTrue(set(EXPECTED['r16']).isdisjoint(EXPECTED['r17']))
        self.assertTrue(set(R16_ARITHMETIC_EXPECTED).isdisjoint(CURRENT_ARITHMETIC_EXPECTED))

    def test_current_rust_contract_and_independent_config_are_byte_identical(self):
        config = reader.load_profiles()
        source = reader.CONFIG.parents[2] / 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
        contracts = re.findall(r'b"(resource-revision-r17/[^\"]+)"', source.read_text())
        self.assertEqual(contracts, [config['revisions']['r17']['resource_contract']])

    def test_historical_arithmetic_cannot_be_omitted_or_relabelled(self):
        config = reader.load_profiles()
        for edit in (
            lambda c: c.update(historical_arithmetic_profiles={}),
            lambda c: c['historical_arithmetic_profiles'].pop('r14'),
            lambda c: c['historical_arithmetic_profiles'].pop('r15'),
            lambda c: c['historical_arithmetic_profiles'].pop('r16'),
            lambda c: c['historical_arithmetic_profiles'].update(r14=c['arithmetic_profile']),
            lambda c: c['historical_arithmetic_profiles'].update(r15=c['arithmetic_profile']),
            lambda c: c['historical_arithmetic_profiles'].update(r16=c['arithmetic_profile']),
            lambda c: c['historical_arithmetic_profiles']['r13'].update(base_revision='r14'),
            lambda c: c['historical_arithmetic_profiles']['r13'].update(resource_revision='r14-arithmetic-facts-v1'),
            lambda c: c['historical_arithmetic_profiles']['r13']['vectors'][0].update(policy_id=CURRENT_ARITHMETIC_EXPECTED[0]),
            lambda c: c['revisions'].pop('r13'),
        ):
            changed = copy.deepcopy(config)
            edit(changed)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'profiles.json'
                path.write_text(json.dumps(changed))
                with self.subTest(edit=edit), self.assertRaises(ValueError):
                    reader.load_profiles(path)
        with self.assertRaisesRegex(ValueError, 'unknown historical'):
            reader.arithmetic_policy_id(config, 8, 2000, base_revision='r12')

    def test_wrong_parameters_unknown_digest_and_claimed_revision_refuse(self):
        for fields in ({'ticket_bits': 12}, {'lifetime_ms': 1999}, {'ticket_bits': True},
                       {'ticket_bits': 7}, {'lifetime_ms': 2001}, {'policy_id': '0' * 64},
                       {'policy_id': EXPECTED['r12'][0].upper()}, {'resource_revision': 'r12'},
                       {'transport_profile': 'public-protected-development-v2'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                reader.identify_observation({**observation(), **fields})
        with self.assertRaises(ValueError):
            reader.identify_observation(None)
        missing = observation()
        del missing['policy_id']
        with self.assertRaises(ValueError):
            reader.identify_observation(missing)

    def test_changed_contract_vector_or_resource_limits_fail_closed(self):
        config = reader.load_profiles()
        for change in (
            lambda value: value.update(burst_ns=3_000_000_000),
            lambda value: value['revisions']['r12'].update(resource_contract='resource-revision-r13/changed'),
            lambda value: value['revisions']['r11']['vectors'][0].update(policy_id=EXPECTED['r12'][0]),
            lambda value: value.update(current_revision='r11'),
        ):
            with tempfile.TemporaryDirectory() as directory:
                changed = copy.deepcopy(config)
                change(changed)
                path = Path(directory) / 'profiles.json'
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    reader.load_profiles(path)


if __name__ == '__main__':
    unittest.main()
