#!/usr/bin/env python3
"""Finite one-zero parser contracts; synthetic fixtures are never native evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_cross_arch_cost import (CAMPAIGNS, MODES, compare_artifacts,
    deterministic_projection, suite_contract, validate_raw_report,
    winning_challenge as reused_challenge)
from check_one_zero_locality_cost import (MATERIALS, METHODS, STRATEGIES,
    validate_one_zero_report, winning_challenge)
from check_zero_locality_cost import validate_zero_report, winning_challenge as zero_challenge
from test_cross_arch_cost import parser_fixture as reused_fixture, slow_clocks
from test_zero_locality_cost import artifact_fixture, write_manifest, zero_fixture


def one_zero_fixture(configuration: dict) -> dict:
    """Manufacture parser data only, without a proof or executable observation."""
    data = zero_fixture(configuration)
    data['schema'] = 'pon-w1-one-zero-locality-v1'
    del data['zero_structure_only']
    data['one_zero_rank_one_structure_only'] = True
    prototype = data['observations']
    data['observations'] = []
    for name, (rank_a, rank_b, task) in MATERIALS.items():
        for original in prototype:
            row = copy.deepcopy(original)
            invocation = (row['sample'] + row['invocation_order']) % 6
            strategy = STRATEGIES[invocation // 2]
            row.update({'class': name, 'rank_a': rank_a, 'rank_b': rank_b, 'task': task,
                        'strategy': strategy, 'method': METHODS[strategy], 'mode': MODES[invocation % 2]})
            for outcome in row['outcomes']:
                if outcome['status'] == 'winner':
                    outcome['winning_challenge'] = winning_challenge(task, configuration['seed'],
                        row['sample'], outcome['search_index'], row['target'], outcome['attempts'] - 1)
            data['observations'].append(row)
    return data


class OneZeroRawContractTests(unittest.TestCase):
    def setUp(self):
        self.configuration = CAMPAIGNS[0]
        self.data = one_zero_fixture(self.configuration)

    def rejected(self, change):
        change(self.data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate_one_zero_report(self.data, self.configuration)

    def test_two_materials_have_complete_target_strategy_mode_search_grid(self):
        result = validate_one_zero_report(self.data, self.configuration)
        self.assertEqual((result['rows'], result['outcomes']), (96, 384))
        self.assertEqual(set(result['statuses']), {'winner', 'exhausted'})
        second = validate_one_zero_report(one_zero_fixture(CAMPAIGNS[1]), CAMPAIGNS[1])
        self.assertEqual((second['rows'], second['outcomes']), (48, 192))

    def test_task_bytes_independently_bind_nonzero_outer_product_and_zero_side(self):
        # u and v are nonzero over the field, so u*v has rank one. This checks
        # fixed synthetic byte identities; it is not an actual work observation.
        matrix = b''.join(((i + 1) * (j + 3)).to_bytes(4, 'little')
                          for i in range(64) for j in range(64))
        zero = bytes(64 * 64 * 4)
        for name, a, b, ranks in [('left-zero-rank-one', zero, matrix, (0, 1)),
                                  ('right-zero-rank-one', matrix, zero, (1, 0))]:
            value = hashlib.sha256(b'TRNM-PON1\0\x04\x00task')
            for part in [a, b]:
                value.update(len(part).to_bytes(4, 'little'))
                value.update(part)
            self.assertEqual(MATERIALS[name], (*ranks, value.hexdigest()))

    def test_all_three_raw_schemas_refuse_cross_substitution(self):
        cases = [(validate_raw_report, reused_fixture(self.configuration)),
                 (validate_zero_report, zero_fixture(self.configuration)),
                 (validate_one_zero_report, self.data)]
        for index, (validator, _) in enumerate(cases):
            for other_index, (_, data) in enumerate(cases):
                if index != other_index:
                    with self.subTest(validator=index, data=other_index), self.assertRaises(ValueError):
                        validator(data, self.configuration)

    def test_both_old_challenge_domains_are_rejected(self):
        for old in [reused_challenge, zero_challenge]:
            data = copy.deepcopy(self.data)
            row = data['observations'][0]
            row['outcomes'][0]['winning_challenge'] = old(row['task'], self.configuration['seed'],
                row['sample'], 0, row['target'], 0)
            with self.subTest(domain=old.__module__), self.assertRaises(ValueError):
                validate_one_zero_report(data, self.configuration)

    def test_missing_zero_side_class_is_not_partial_success(self):
        self.rejected(lambda data: data['observations'].__delitem__(slice(48, None)))

    def test_one_class_cannot_duplicate_the_other(self):
        self.rejected(lambda data: data['observations'].__setitem__(slice(48, None),
            copy.deepcopy(data['observations'][:48])))

    def test_left_and_right_task_identities_cannot_be_swapped(self):
        self.rejected(lambda data: data['observations'][0].update(task=MATERIALS['right-zero-rank-one'][2]))

    def test_nonzero_side_rank_cannot_be_relabelled(self):
        self.rejected(lambda data: data['observations'][0].update(rank_b=0))

    def test_boolean_rank_cannot_alias_integer_one(self):
        self.rejected(lambda data: data['observations'][0].update(rank_b=True))

    def test_wrong_material_provenance_is_not_accepted(self):
        self.rejected(lambda data: data['observations'][0].update(input_source='verified-model-input'))

    def test_strategy_cannot_be_replaced_by_both_zero_kernel(self):
        self.rejected(lambda data: data['observations'][4].update(strategy='blocked-zero'))

    def test_wrong_product_only_method_cannot_claim_full_transcript(self):
        self.rejected(lambda data: data['observations'][4].update(method='zero-product-full-transcript'))

    def test_native_invocation_array_order_cannot_change(self):
        self.rejected(lambda data: data['observations'].reverse())

    def test_missing_search_remains_failure(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'].pop())

    def test_unsupported_cannot_replace_required_capable_constructor(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(status='unsupported'))

    def test_all_three_constructors_retain_real_cold_setup_count(self):
        self.rejected(lambda data: data['observations'][4].update(setup_calls=1))

    def test_reuse_cannot_hide_extra_setup(self):
        self.rejected(lambda data: data['observations'][5]['setup_observations_ns'].append(1))

    def test_setup_cannot_be_removed_from_total_cost(self):
        self.rejected(lambda data: data['observations'][0].update(total_elapsed_ns=92))

    def test_exhausted_search_requires_all_budget_attempts(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].update(attempts=1))

    def test_exhausted_search_keeps_proof_stream(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].update(proof_stream_commitment=None))

    def test_exhausted_search_cannot_invent_verification(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].update(production_verifier_elapsed_ns=1))

    def test_optimized_attempted_proof_stream_must_equal_generic(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(proof_stream_commitment='9' * 64))

    def test_optimized_attempted_ticket_stream_must_equal_generic(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(ticket_stream_commitment='9' * 64))

    def test_winner_proof_commitment_must_equal_other_producers(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(winner_proof_commitment='9' * 64))

    def test_scope_does_not_claim_all_qualified_materials(self):
        self.rejected(lambda data: data.update(one_zero_rank_one_structure_only=False))

    def test_no_work_hardness_promotion(self):
        self.rejected(lambda data: data.update(work_hardness_accepted=True))

    def test_wrong_seed_or_budget_cannot_substitute_a_campaign(self):
        with self.assertRaises(ValueError):
            validate_one_zero_report(one_zero_fixture(CAMPAIGNS[1]), CAMPAIGNS[0])

    def test_all_exhaustion_and_slower_clocks_remain_valid_observations(self):
        for row in self.data['observations']:
            for outcome in row['outcomes']:
                outcome.update(status='exhausted', attempts=self.configuration['attempt_budget'])
                for field in ['winning_challenge', 'winner_proof_commitment',
                              'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                              'reference_verifier_first']:
                    outcome[field] = None
        slower = slow_clocks(self.data)
        self.assertEqual(validate_one_zero_report(slower, self.configuration)['statuses'], {'exhausted': 384})
        self.assertEqual(deterministic_projection(slower), deterministic_projection(self.data))


class OneZeroArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-one-zero-parser-only-')
        self.root = Path(self.temporary.name)
        self.suite = 'one-zero-locality'
        self.records = {arch: artifact_fixture(self.root / arch, arch, suite=self.suite,
                         raw_fixture=one_zero_fixture) for arch in ['x64', 'arm64']}

    def tearDown(self):
        self.temporary.cleanup()

    def check(self):
        return compare_artifacts(self.root, 'a' * 40, suite=self.suite)

    def rejected(self, change):
        change(self.records['arm64'])
        write_manifest(self.root / 'arm64', self.records['arm64'], suite=self.suite)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check()

    def test_new_manifest_commands_and_pair_have_their_own_schema(self):
        report = self.check()
        self.assertEqual(report['schema'], 'trnm-cross-arch-one-zero-locality-cost-comparison-v1')
        self.assertEqual([row['rows'] for row in report['campaigns']], [96, 48])
        self.assertFalse(report['speed_threshold_applied'])
        self.assertFalse(report['work_hardness_accepted'])

    def test_null_manifest_error_cannot_be_hidden_beneath_pass(self):
        self.rejected(lambda report: report.update(error=None))

    def test_launch_error_cannot_be_hidden_beneath_pass(self):
        self.rejected(lambda report: report['observations'][4].update(launch_error='not executed'))

    def test_boolean_false_cannot_claim_zero_exit(self):
        self.rejected(lambda report: report['observations'][4].update(exit_code=False))

    def test_missing_campaign_is_not_a_success(self):
        self.rejected(lambda report: report['campaigns'].pop())

    def test_prior_suite_cannot_stand_in_for_new_native_binary(self):
        self.rejected(lambda report: report['observations'][4]['command'].__setitem__(0, '/synthetic/pon_zero_locality_cost'))

    def test_new_source_owner_hash_is_required(self):
        self.rejected(lambda report: report['input_sha256'].pop('scripts/ci/check_one_zero_locality_cost.py'))

    def test_source_mismatch_between_architectures_is_rejected(self):
        self.rejected(lambda report: report['input_sha256'].update({'scripts/ci/check_one_zero_locality_cost.py': '5' * 64}))

    def test_stale_attempt_cannot_complete_current_pair(self):
        self.rejected(lambda report: report['runner_context'].update(GITHUB_RUN_ATTEMPT='2'))

    def test_zero_receipt_directory_cannot_stand_in_for_one_zero(self):
        (self.root / 'arm64' / suite_contract(self.suite)['directory']).rename(
            self.root / 'arm64' / 'cross-arch-zero-locality-cost')
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_empty_stderr_is_rejected_even_with_new_inventory(self):
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        (base / 'campaign-0.stderr').unlink()
        write_manifest(self.root / 'arm64', self.records['arm64'], suite=self.suite)
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_original_output_is_rejected_by_its_hash(self):
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        (base / 'campaign-0.stdout').write_text('{}')
        with self.assertRaises(ValueError):
            self.check()

    def test_full_stream_disagreement_between_native_architectures_is_rejected(self):
        report = self.records['arm64']
        base = self.root / 'arm64' / suite_contract(self.suite)['directory']
        for index, configuration in enumerate(CAMPAIGNS):
            raw = one_zero_fixture(configuration)
            for row in raw['observations']:
                for outcome in row['outcomes']:
                    outcome['proof_stream_commitment'] = '8' * 64
            report['campaigns'][index]['validated'] = validate_one_zero_report(raw, configuration)
            (base / f'campaign-{index}.stdout').write_text(json.dumps(raw))
        write_manifest(self.root / 'arm64', report, suite=self.suite)
        with self.assertRaises(ValueError):
            self.check()


if __name__ == '__main__':
    unittest.main(verbosity=2)
