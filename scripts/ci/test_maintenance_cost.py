#!/usr/bin/env python3
"""Parser contracts for fixed maintenance; manufactured rows never become measurements."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_cross_arch_cost import (CAMPAIGNS, FALSE_FLAGS, MODES, TARGETS, TIMING_SCOPE,
    compare_artifacts, deterministic_projection, suite_contract, validate_raw_report,
    winning_challenge as reused_challenge)
from check_maintenance_cost import (MATERIAL_CLASS, MATERIAL_SOURCE, MATERIAL_TASK, TASK_PROFILE,
    METHODS, STRATEGIES, validate_maintenance_report, winning_challenge)
from check_one_zero_locality_cost import (validate_one_zero_report,
                                        winning_challenge as one_zero_challenge)
from check_zero_locality_cost import validate_zero_report, winning_challenge as zero_challenge
from test_cross_arch_cost import parser_fixture as reused_fixture, slow_clocks
from test_one_zero_locality_cost import one_zero_fixture
from test_zero_locality_cost import artifact_fixture, write_manifest, zero_fixture


def maintenance_fixture(configuration: dict) -> dict:
    """Synthetic parser data only, with no proof generation or executable evidence."""
    data = {'schema': 'pon-w1-maintenance-paired-v1', 'genesis_maintenance_material_only': True,
            'task_profile': TASK_PROFILE, 'targets': TARGETS, 'seed': configuration['seed'],
            'samples_per_case_target': configuration['samples'],
            'searches_per_cohort': configuration['searches'], 'attempt_budget': configuration['attempt_budget'],
            'timing': 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'timing_scope': dict(TIMING_SCOPE), 'observations': [], **{key: False for key in FALSE_FLAGS}}
    for target in TARGETS:
        for sample in range(configuration['samples']):
            for order in range(8):
                direction_offset = order if sample % 2 == 0 else 7 - order
                invocation = (sample // 2 + direction_offset) % 8
                strategy, mode = STRATEGIES[invocation // 2], MODES[invocation % 2]
                setups = [13] * (configuration['searches'] if mode == MODES[0] else 1)
                outcomes = []
                for index in range(configuration['searches']):
                    winner = index % 2 == 0
                    attempts = 1 if winner else configuration['attempt_budget']
                    outcomes.append({'search_index': index, 'status': 'winner' if winner else 'exhausted',
                        'attempts': attempts, 'search_elapsed_ns': 23,
                        'ticket_stream_commitment': '1' * 64, 'proof_stream_commitment': '2' * 64,
                        'winning_challenge': winning_challenge(MATERIAL_TASK, configuration['seed'], sample,
                            index, target, attempts - 1) if winner else None,
                        'winner_proof_commitment': '3' * 64 if winner else None,
                        'production_verifier_elapsed_ns': 29 if winner else None,
                        'reference_verifier_elapsed_ns': 31 if winner else None,
                        'reference_verifier_first': ((sample + index) % 2 == 0) if winner else None})
                setup, search = sum(setups), sum(outcome['search_elapsed_ns'] for outcome in outcomes)
                data['observations'].append({'class': MATERIAL_CLASS, 'input_source': MATERIAL_SOURCE,
                    'task': MATERIAL_TASK, 'rank_a': 56, 'rank_b': 32, 'target': target, 'sample': sample,
                    'invocation_order': order, 'strategy': strategy, 'method': METHODS[strategy],
                    'mode': mode, 'proof_bytes': 49188, 'setup_observations_ns': setups,
                    'setup_calls': len(setups), 'setup_elapsed_ns': setup, 'search_elapsed_ns': search,
                    'total_elapsed_ns': setup + search, 'outcomes': outcomes})
    return data


class MaintenanceRawContractTests(unittest.TestCase):
    def setUp(self):
        self.configuration = CAMPAIGNS[0]
        self.data = maintenance_fixture(self.configuration)

    def rejected(self, change):
        changed = copy.deepcopy(self.data)
        change(changed)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate_maintenance_report(changed, self.configuration)

    def test_complete_four_strategy_grid_keeps_winners_and_exhaustions(self):
        first = validate_maintenance_report(self.data, self.configuration)
        second = validate_maintenance_report(maintenance_fixture(CAMPAIGNS[1]), CAMPAIGNS[1])
        self.assertEqual((first['rows'], first['outcomes']), (64, 256))
        self.assertEqual((second['rows'], second['outcomes']), (32, 128))
        self.assertEqual(set(first['statuses']), {'winner', 'exhausted'})

    def test_fixed_genesis_material_bytes_and_ranks_are_independently_derived(self):
        # Derive the published finite matrices and task framing here, without the
        # native material generator. Gaussian elimination over F_(2^32-5) is a
        # field-rank check of these bytes, not a cost or provenance observation.
        matrices = [[(multiplier * index + offset) % modulus for index in range(4096)]
                    for multiplier, offset, modulus in [(13, 17, 257), (29, 31, 263)]]
        value = hashlib.sha256(b'TRNM-PON1\0\x04\x00task')
        for matrix in matrices:
            raw = b''.join(entry.to_bytes(4, 'little') for entry in matrix)
            value.update(len(raw).to_bytes(4, 'little') + raw)
        self.assertEqual(value.hexdigest(), MATERIAL_TASK)

        def rank(values):
            field = 2**32 - 5
            rows = [values[index:index + 64] for index in range(0, 4096, 64)]
            pivots = 0
            for column in range(64):
                pivot = next((index for index in range(pivots, 64) if rows[index][column]), None)
                if pivot is None:
                    continue
                rows[pivots], rows[pivot] = rows[pivot], rows[pivots]
                inverse = pow(rows[pivots][column], -1, field)
                rows[pivots] = [(entry * inverse) % field for entry in rows[pivots]]
                for index in range(pivots + 1, 64):
                    coefficient = rows[index][column]
                    rows[index] = [(left - coefficient * right) % field
                                   for left, right in zip(rows[index], rows[pivots])]
                pivots += 1
            return pivots

        self.assertEqual([rank(values) for values in matrices], [56, 32])

    def test_paired_forward_reverse_order_balances_every_strategy_mode_position(self):
        for configuration in CAMPAIGNS:
            rows = maintenance_fixture(configuration)['observations']
            for target in TARGETS:
                for even_sample in range(0, configuration['samples'], 2):
                    pair = [row for row in rows if row['target'] == target and
                            row['sample'] in (even_sample, even_sample + 1)]
                    for strategy in STRATEGIES:
                        for mode in MODES:
                            positions = [row['invocation_order'] for row in pair if
                                         row['strategy'] == strategy and row['mode'] == mode]
                            self.assertEqual(len(positions), 2)
                            self.assertEqual(sum(positions), 7)

    def test_all_four_native_schemas_reject_cross_substitution(self):
        cases = [(validate_raw_report, reused_fixture(self.configuration)),
                 (validate_zero_report, zero_fixture(self.configuration)),
                 (validate_one_zero_report, one_zero_fixture(self.configuration)),
                 (validate_maintenance_report, self.data)]
        for index, (validator, _) in enumerate(cases):
            for other, (_, data) in enumerate(cases):
                if index != other:
                    with self.subTest(validator=index, data=other), self.assertRaises(ValueError):
                        validator(data, self.configuration)

    def test_all_old_challenge_domains_are_rejected(self):
        for old in [reused_challenge, zero_challenge, one_zero_challenge]:
            with self.subTest(domain=old.__module__):
                self.rejected(lambda data: data['observations'][0]['outcomes'][0].update(
                    winning_challenge=old(MATERIAL_TASK, self.configuration['seed'], 0, 0, TARGETS[0], 0)))

    def test_task_profile_material_and_scope_cannot_be_relabelled(self):
        for change in [lambda data: data.update(genesis_maintenance_material_only=False),
                       lambda data: data.update(task_profile='leased-maintenance'),
                       lambda data: data.update(work_hardness_accepted=True),
                       lambda data: data['observations'][0].update(input_source='independently-qualified-work'),
                       lambda data: data['observations'][0].update(task='0' * 64),
                       lambda data: data['observations'][0].update(rank_a=0),
                       lambda data: data['observations'][0].update(rank_b=True)]:
            with self.subTest(change=change):
                self.rejected(change)

    def test_missing_repeated_or_reordered_native_rows_are_rejected(self):
        for change in [lambda data: data['observations'].pop(),
                       lambda data: data['observations'].reverse(),
                       lambda data: data['observations'].__setitem__(slice(32, None), copy.deepcopy(data['observations'][:32])),
                       lambda data: data['observations'][0]['outcomes'].pop(),
                       lambda data: data['observations'][0].update(invocation_order=False)]:
            with self.subTest(change=change):
                self.rejected(change)

    def test_all_required_producers_keep_full_trajectory_and_real_setup_cost(self):
        for change in [lambda data: data['observations'][6].update(method='product-only'),
                       lambda data: data['observations'][6].update(strategy='blocked-one-zero-rank-one'),
                       lambda data: data['observations'][6]['outcomes'][0].update(status='unsupported'),
                       lambda data: data['observations'][6].update(setup_calls=1),
                       lambda data: data['observations'][7]['setup_observations_ns'].append(1),
                       lambda data: data['observations'][6].update(total_elapsed_ns=92),
                       lambda data: data['observations'][6].update(proof_bytes=32)]:
            with self.subTest(change=change):
                self.rejected(change)

    def test_exhaustion_retains_attempts_and_streams_without_fabricated_verification(self):
        for fields in [{'attempts': 1}, {'proof_stream_commitment': None},
                       {'reference_verifier_elapsed_ns': 1}, {'reference_verifier_first': False},
                       {'winner_proof_commitment': '3' * 64}, {'attempts': True}]:
            with self.subTest(fields=fields):
                self.rejected(lambda data: data['observations'][6]['outcomes'][1].update(fields))

    def test_optimized_producer_keeps_identical_attempted_and_winning_streams(self):
        for key in ['ticket_stream_commitment', 'proof_stream_commitment', 'winner_proof_commitment']:
            with self.subTest(field=key):
                self.rejected(lambda data: data['observations'][6]['outcomes'][0].update({key: '9' * 64}))

    def test_wrong_campaign_cannot_be_substituted(self):
        with self.assertRaises(ValueError):
            validate_maintenance_report(maintenance_fixture(CAMPAIGNS[1]), CAMPAIGNS[0])

    def test_all_exhaustion_and_slower_clocks_remain_valid_finite_results(self):
        for row in self.data['observations']:
            for outcome in row['outcomes']:
                outcome.update(status='exhausted', attempts=self.configuration['attempt_budget'])
                for field in ['winning_challenge', 'winner_proof_commitment', 'production_verifier_elapsed_ns',
                              'reference_verifier_elapsed_ns', 'reference_verifier_first']:
                    outcome[field] = None
        slower = slow_clocks(self.data)
        self.assertEqual(validate_maintenance_report(slower, self.configuration)['statuses'], {'exhausted': 256})
        self.assertEqual(deterministic_projection(slower), deterministic_projection(self.data))


class MaintenanceArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-maintenance-parser-only-')
        self.root = Path(self.temporary.name)
        self.suite = 'maintenance-paired'
        self.records = {arch: artifact_fixture(self.root / arch, arch, suite=self.suite,
                        raw_fixture=maintenance_fixture) for arch in ['x64', 'arm64']}

    def tearDown(self):
        self.temporary.cleanup()

    def check(self):
        return compare_artifacts(self.root, 'a' * 40, suite=self.suite)

    def rejected(self, change):
        change(self.records['arm64'])
        write_manifest(self.root / 'arm64', self.records['arm64'], suite=self.suite)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check()

    def test_maintenance_has_separate_exact_commands_sources_schema_and_counts(self):
        report = self.check()
        self.assertEqual(report['schema'], 'trnm-cross-arch-maintenance-cost-comparison-v1')
        self.assertEqual([row['rows'] for row in report['campaigns']], [64, 32])
        self.assertFalse(report['speed_threshold_applied'])
        self.assertFalse(report['work_hardness_accepted'])

    def test_success_cannot_hide_failure_or_boolean_exit_alias(self):
        for change in [lambda report: report.update(error=None),
                       lambda report: report['observations'][4].update(launch_error='not executed'),
                       lambda report: report['observations'][4].update(exit_code=False)]:
            original = copy.deepcopy(self.records['arm64'])
            with self.subTest(change=change):
                self.rejected(change)
            self.records['arm64'] = original

    def test_binary_and_new_source_owner_are_required(self):
        self.rejected(lambda report: report['observations'][4]['command'].__setitem__(0, '/synthetic/pon_reused_cost'))
        # A fresh fixture ensures this source-owner rejection is independent of
        # the preceding deliberately invalid executable command.
        self.records['arm64']['observations'][4]['command'][0] = '/synthetic/parser-fixture/pon_maintenance_cost'
        self.rejected(lambda report: report['input_sha256'].pop(
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs'))

    def test_missing_campaign_or_stale_attempt_cannot_complete_pair(self):
        self.rejected(lambda report: report['runner_context'].update(GITHUB_RUN_ATTEMPT='2'))
        self.records['arm64']['runner_context']['GITHUB_RUN_ATTEMPT'] = '1'
        self.rejected(lambda report: report['campaigns'].pop())

    def test_original_stdout_and_empty_stderr_must_remain_hashed(self):
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        (base / 'campaign-0.stdout').write_text('{}')
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_empty_stderr_is_not_an_acceptable_smaller_inventory(self):
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        (base / 'campaign-0.stderr').unlink()
        write_manifest(self.root / 'arm64', self.records['arm64'], suite=self.suite)
        with self.assertRaises(ValueError):
            self.check()

    def test_other_suite_directory_cannot_supply_maintenance_evidence(self):
        (self.root / 'arm64' / suite_contract(self.suite)['directory']).rename(
            self.root / 'arm64' / 'cross-arch-one-zero-locality-cost')
        with self.assertRaises(ValueError):
            self.check()

    def test_full_stream_disagreement_between_architectures_is_rejected(self):
        report = self.records['arm64']
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        for index, configuration in enumerate(CAMPAIGNS):
            raw = maintenance_fixture(configuration)
            for row in raw['observations']:
                for outcome in row['outcomes']:
                    outcome['proof_stream_commitment'] = '8' * 64
            report['campaigns'][index]['validated'] = validate_maintenance_report(raw, configuration)
            (base / f'campaign-{index}.stdout').write_text(json.dumps(raw))
        write_manifest(self.root / 'arm64', report, suite=self.suite)
        with self.assertRaises(ValueError):
            self.check()


if __name__ == '__main__':
    unittest.main(verbosity=2)
