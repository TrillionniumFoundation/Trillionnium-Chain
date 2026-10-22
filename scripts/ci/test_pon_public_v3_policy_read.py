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
}


def observation(revision='r12'):
    return dict(schema=reader.OBSERVATION_SCHEMA,
                transport_profile='public-protected-development-v3',
                policy_id=EXPECTED[revision][0], ticket_bits=8, lifetime_ms=2000)


class PolicyReaderTests(unittest.TestCase):
    def test_independent_r10_r11_r12_vectors_recompute_exactly(self):
        config = reader.load_profiles()
        for revision, expected in EXPECTED.items():
            self.assertEqual([reader.policy_id(config, revision, bits, 2000)
                              for bits in (8, 12, 16)], expected)
            self.assertEqual(reader.identify_observation(observation(revision))['resource_revision'],
                             revision)
        self.assertEqual(config['current_revision'], 'r12')

    def test_current_rust_contract_and_independent_config_are_byte_identical(self):
        config = reader.load_profiles()
        source = reader.CONFIG.parents[2] / 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
        contracts = re.findall(r'b"(resource-revision-r12/[^\"]+)"', source.read_text())
        self.assertEqual(contracts, [config['revisions']['r12']['resource_contract']])

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
            lambda value: value['revisions']['r12'].update(resource_contract='resource-revision-r12/changed'),
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
