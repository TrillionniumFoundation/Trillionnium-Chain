#!/usr/bin/env python3
"""Zero-suite negative contracts; every manufactured fixture is parser data only."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from ci_observation import digest
from check_cross_arch_cost import (ARCHITECTURES, CAMPAIGNS, FALSE_FLAGS, MATERIALS, MODES,
    TARGETS, TIMING_SCOPE, benchmark_arguments, compare_artifacts, deterministic_projection,
    suite_contract, validate_artifact, validate_raw_report, winning_challenge as old_challenge)
from check_zero_locality_cost import (METHODS, STRATEGIES, STRATEGIES_V2, validate_zero_report,
    validate_zero_v1_report, validate_zero_v2_report, winning_challenge)
from run_cross_arch_cost import capture
from test_cross_arch_cost import parser_fixture as reused_fixture, slow_clocks


def zero_fixture(configuration: dict, *, version: int = 1) -> dict:
    """Synthetic shape exercise, never an actual proof, benchmark or CI receipt."""
    strategies = STRATEGIES if version == 1 else STRATEGIES_V2
    arms = len(strategies) * 2
    data = {'schema': f'pon-w1-zero-locality-v{version}', 'zero_structure_only': True,
            'targets': TARGETS, 'seed': configuration['seed'],
            'samples_per_case_target': configuration['samples'],
            'searches_per_cohort': configuration['searches'],
            'attempt_budget': configuration['attempt_budget'],
            'timing': 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'timing_scope': dict(TIMING_SCOPE), 'observations': [],
            **{key: False for key in FALSE_FLAGS}}
    task = MATERIALS['zero'][2]
    for target in TARGETS:
        for sample in range(configuration['samples']):
            for order in range(arms):
                invocation = ((sample + order) % arms if version == 1 else
                              (sample // 2 + (order if sample % 2 == 0 else arms - 1 - order)) % arms)
                strategy, mode = strategies[invocation // 2], MODES[invocation % 2]
                setups = [13] * (configuration['searches'] if mode == 'cold-per-search' else 1)
                outcomes = []
                for index in range(configuration['searches']):
                    winner = index % 2 == 0
                    attempts = 1 if winner else configuration['attempt_budget']
                    outcomes.append({'search_index': index, 'status': 'winner' if winner else 'exhausted',
                        'attempts': attempts, 'search_elapsed_ns': 23,
                        'ticket_stream_commitment': '1' * 64, 'proof_stream_commitment': '2' * 64,
                        'winning_challenge': winning_challenge(task, configuration['seed'], sample,
                            index, target, attempts - 1) if winner else None,
                        'winner_proof_commitment': '3' * 64 if winner else None,
                        'production_verifier_elapsed_ns': 29 if winner else None,
                        'reference_verifier_elapsed_ns': 31 if winner else None,
                        'reference_verifier_first': ((sample + index) % 2 == 0) if winner else None})
                setup, search = sum(setups), sum(row['search_elapsed_ns'] for row in outcomes)
                data['observations'].append({'class': 'zero', 'input_source': 'synthetic-fixture',
                    'task': task, 'rank_a': 0, 'rank_b': 0, 'target': target, 'sample': sample,
                    'invocation_order': order, 'strategy': strategy, 'method': METHODS[strategy],
                    'mode': mode, 'proof_bytes': 49188, 'setup_observations_ns': setups,
                    'setup_calls': len(setups), 'setup_elapsed_ns': setup,
                    'search_elapsed_ns': search, 'total_elapsed_ns': setup + search,
                    'outcomes': outcomes})
    return data


def artifact_fixture(directory: Path, arch: str, *, suite: str = 'zero-locality', raw_fixture=None,
                     zero_version: int = 2) -> dict:
    """Manufactured parser-only files with a header stub; nothing is executed."""
    contract = (suite_contract(suite, zero_version=zero_version)
                if suite == 'zero-locality' else suite_contract(suite))
    if raw_fixture is None:
        raw_fixture = ((lambda configuration: zero_fixture(configuration, version=zero_version))
                       if suite == 'zero-locality' else reused_fixture)
    spec = ARCHITECTURES[arch]
    base = directory / contract['directory']
    base.mkdir(parents=True)
    source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'source_state': 'committed-clean',
              'tracked_worktree_verified': True, 'tracked_entries': 1, 'tracked_bytes': 1}
    (directory / 'source.json').write_text(json.dumps({'tested_commit': source['commit'],
        'tested_tree': source['tree'], 'tracked_worktree_verified': True}))
    example = contract['example']
    (base / example).write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 +
        spec['elf_machine'].to_bytes(2, 'little') + b'SYNTHETIC PARSER FIXTURE; NEVER EXECUTED')
    (base / 'cpuinfo.txt').write_text('synthetic parser fixture; not hardware evidence\n')
    commands = [(['uname', '-a'], 'uname', 30), (['rustc', '+1.95.0', '-vV'], 'rustc', 30),
        (['cargo', '+1.95.0', '--version'], 'cargo', 30),
        (['cargo', '+1.95.0', 'build', '--locked', '--release', '--manifest-path',
          'trillionnium/Cargo.toml', '--target', spec['target'], '-p',
          'trnm-crypto-primitives', '--example', example], 'build', 900)]
    commands.extend(([f'/synthetic/parser-fixture/{example}', *benchmark_arguments(c)],
                     f'campaign-{index}', 300) for index, c in enumerate(CAMPAIGNS))
    observations = []
    for command, stem, timeout in commands:
        observations.append({'command': command, 'cwd': '/synthetic/parser-fixture',
            'exit_code': 0, 'timed_out': False, 'timeout_seconds': timeout,
            'elapsed_ns': 1, 'stdout': stem + '.stdout', 'stderr': stem + '.stderr'})
        (base / (stem + '.stdout')).write_text('synthetic parser fixture\n')
        (base / (stem + '.stderr')).write_bytes(b'')
    (base / 'uname.stdout').write_text('synthetic parser fixture ' + spec['machine'] + '\n')
    (base / 'rustc.stdout').write_text(f'synthetic parser fixture\nrelease: 1.95.0\nhost: {spec["target"]}\n')
    campaigns = []
    for index, configuration in enumerate(CAMPAIGNS):
        raw = raw_fixture(configuration)
        (base / f'campaign-{index}.stdout').write_text(json.dumps(raw))
        campaigns.append({'configuration': configuration, 'observation': observations[index + 4],
                          'result': 'PASS', 'validated': contract['validate_raw_report'](raw, configuration)})
    report = {'schema': contract['execution_schema'], 'result': 'PASS',
        'execution_context': 'github-hosted', 'architecture': arch,
        'runner_label': spec['runner'], 'target': spec['target'],
        'runner_context': {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                           'RUNNER_ARCH': spec['runner_arch']},
        'uname': {'system': 'Linux', 'machine': spec['machine']}, 'compiler_channel': '1.95.0',
        'build_profile': 'release', 'build_environment_overrides': {},
        'source_before': source, 'source_after': copy.deepcopy(source), 'source_changed': False,
        'input_sha256': {path: '4' * 64 for path in contract['inputs']},
        'binary_elf_machine': spec['elf_machine'], 'binary_sha256_before': digest(base / example),
        'binary_sha256_after': digest(base / example), 'observations': observations,
        'campaigns': campaigns, 'public_network_ready': False,
        'independent_hardware_qualified': False, 'resource_fairness_qualified': False,
        'work_profile_qualified': False, 'production_activation': False}
    write_manifest(directory, report, suite=suite, zero_version=zero_version)
    return report


def write_manifest(directory: Path, report: dict, *, suite: str = 'zero-locality', zero_version: int = 2) -> None:
    contract = (suite_contract(suite, zero_version=zero_version)
                if suite == 'zero-locality' else suite_contract(suite))
    base = directory / contract['directory']
    report['artifact_sha256'] = {path.name: digest(path) for path in base.iterdir()
                                if path.is_file() and path.name != 'manifest.json'}
    (base / 'manifest.json').write_text(json.dumps(report))


class ZeroRawContractTests(unittest.TestCase):
    def setUp(self):
        self.configuration = CAMPAIGNS[0]
        self.data = zero_fixture(self.configuration)

    def rejected(self, change):
        change(self.data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate_zero_report(self.data, self.configuration)

    def test_exact_three_strategy_grid_keeps_winners_and_exhaustions(self):
        report = validate_zero_report(self.data, self.configuration)
        self.assertEqual((report['rows'], report['outcomes']), (48, 192))
        self.assertEqual(set(report['statuses']), {'winner', 'exhausted'})

    def test_both_zero_and_old_seven_material_schemas_remain_separate(self):
        old = reused_fixture(self.configuration)
        self.assertEqual(validate_raw_report(old, self.configuration)['rows'], 560)
        for check, data in [(validate_raw_report, self.data), (validate_zero_report, old)]:
            with self.assertRaises(ValueError):
                check(data, self.configuration)

    def test_zero_success_cohorts_remain_valid_cost_observations(self):
        for row in self.data['observations']:
            for outcome in row['outcomes']:
                outcome.update(status='exhausted', attempts=self.configuration['attempt_budget'])
                for field in ['winning_challenge', 'winner_proof_commitment',
                              'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                              'reference_verifier_first']:
                    outcome[field] = None
        self.assertEqual(validate_zero_report(self.data, self.configuration)['statuses'], {'exhausted': 192})

    def test_slow_or_regressed_producer_and_verifier_clocks_are_not_rejected(self):
        slower = slow_clocks(self.data)
        self.assertEqual(validate_zero_report(slower, self.configuration),
                         validate_zero_report(self.data, self.configuration))
        self.assertEqual(deterministic_projection(slower), deterministic_projection(self.data))

    def test_missing_strategy_is_not_a_smaller_successful_campaign(self):
        self.rejected(lambda data: data['observations'].pop(4))

    def test_duplicate_strategy_cannot_stand_in_for_blocked_zero(self):
        self.rejected(lambda data: data['observations'][4].update(strategy='prepared-generic'))

    def test_reused_mode_cannot_stand_in_for_cold(self):
        self.rejected(lambda data: data['observations'][0].update(mode='reused-one-setup'))

    def test_zero_structure_scope_cannot_be_promoted(self):
        self.rejected(lambda data: data.update(zero_structure_only=False))

    def test_wrong_material_or_rank_is_not_zero_locality(self):
        self.rejected(lambda data: data['observations'][0].update(rank_a=1))

    def test_false_rank_must_not_use_boolean_integer_alias(self):
        self.rejected(lambda data: data['observations'][0].update(rank_a=False))

    def test_lost_setup_or_miss_hashing_scope_rejected(self):
        self.rejected(lambda data: data['timing_scope'].update(challenge_ticket_and_full_proof_stream_hashing_in_search=False))

    def test_generic_setup_cannot_use_old_scalar_zero_setup_rule(self):
        self.rejected(lambda data: data['observations'][0].update(setup_calls=0, setup_observations_ns=[]))

    def test_reuse_cannot_hide_extra_constructor_calls(self):
        self.rejected(lambda data: data['observations'][1].update(setup_calls=4))

    def test_failed_construction_cannot_be_unsupported_success(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(status='unsupported'))

    def test_missing_failed_search_rejected(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'].pop(1))

    def test_exhaustion_cannot_drop_last_attempt(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].update(attempts=63))

    def test_exhaustion_cannot_invent_a_verifier(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].update(production_verifier_elapsed_ns=1))

    def test_failed_search_clock_must_still_be_in_total(self):
        self.rejected(lambda data: data['observations'][0].update(search_elapsed_ns=46, total_elapsed_ns=98))

    def test_full_proof_stream_is_required_even_for_exhaustion(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][1].pop('proof_stream_commitment'))

    def test_wrong_complete_proof_stream_rejected(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][1].update(proof_stream_commitment='9' * 64))

    def test_wrong_ticket_stream_rejected(self):
        self.rejected(lambda data: data['observations'][1]['outcomes'][1].update(ticket_stream_commitment='9' * 64))

    def test_wrong_winner_proof_digest_rejected(self):
        self.rejected(lambda data: data['observations'][4]['outcomes'][0].update(winner_proof_commitment='9' * 64))

    def test_old_challenge_domain_cannot_be_relabelled(self):
        old = old_challenge(MATERIALS['zero'][2], 0, 0, 0, TARGETS[0], 0)
        self.rejected(lambda data: data['observations'][0]['outcomes'][0].update(winning_challenge=old))

    def test_rotation_or_native_row_order_cannot_be_relabelled(self):
        self.rejected(lambda data: data['observations'].reverse())

    def test_fake_verifier_order_rejected(self):
        self.rejected(lambda data: data['observations'][0]['outcomes'][0].update(reference_verifier_first=False))

    def test_wrong_campaign_arguments_rejected(self):
        with self.assertRaises(ValueError):
            validate_zero_report(zero_fixture(CAMPAIGNS[1]), CAMPAIGNS[0])

    def test_no_hardness_or_speed_acceptance(self):
        self.rejected(lambda data: data.update(work_hardness_accepted=True))


class ZeroV2RawContractTests(unittest.TestCase):
    def setUp(self):
        self.configuration = CAMPAIGNS[0]
        self.data = zero_fixture(self.configuration, version=2)

    def rejected(self, change):
        change(self.data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate_zero_v2_report(self.data, self.configuration)

    def test_all_five_complete_producers_and_modes_are_required(self):
        result = validate_zero_v2_report(self.data, self.configuration)
        self.assertEqual((result['rows'], result['outcomes']), (80, 320))
        self.assertEqual(set(result['statuses']), {'winner', 'exhausted'})
        for target in TARGETS:
            for pair in range(self.configuration['samples'] // 2):
                sums = {}
                for row in self.data['observations']:
                    if row['target'] == target and row['sample'] // 2 == pair:
                        key = row['strategy'], row['mode']
                        sums[key] = sums.get(key, 0) + row['invocation_order']
                self.assertEqual(len(sums), 10)
                self.assertEqual(set(sums.values()), {9})

    def test_odd_sample_count_retains_its_unmatched_valid_cohort(self):
        configuration = {**self.configuration, 'samples': 3}
        self.assertEqual(validate_zero_v2_report(zero_fixture(configuration, version=2), configuration)['rows'], 60)

    def test_historical_and_current_grids_cannot_be_relabelled(self):
        old = zero_fixture(self.configuration)
        self.assertEqual(validate_zero_report(old, self.configuration), validate_zero_v1_report(old, self.configuration))
        for checker, data in [(validate_zero_v1_report, self.data), (validate_zero_v2_report, old)]:
            with self.assertRaises(ValueError):
                checker(data, self.configuration)
        self.rejected(lambda data: data.update(schema='pon-w1-zero-locality-v1'))

    def test_v1_grid_cannot_become_current_by_changing_only_schema(self):
        data = zero_fixture(self.configuration)
        data['schema'] = 'pon-w1-zero-locality-v2'
        with self.assertRaises(ValueError):
            validate_zero_v2_report(data, self.configuration)

    def test_general_paired_and_previous_best_blocked_controls_cannot_be_removed(self):
        for strategy in ['paired-product', 'blocked-zero']:
            data = copy.deepcopy(self.data)
            data['observations'] = [row for row in data['observations'] if row['strategy'] != strategy]
            with self.assertRaises(ValueError):
                validate_zero_v2_report(data, self.configuration)

    def test_candidate_cannot_use_the_method_label_of_another_producer(self):
        self.rejected(lambda data: data['observations'][8].update(method=METHODS['blocked-zero']))

    def test_old_rotation_cannot_replace_adjacent_sample_balance(self):
        data = self.data
        for target in TARGETS:
            for sample in range(self.configuration['samples']):
                group = [row for row in data['observations'] if row['target'] == target and row['sample'] == sample]
                mapped = {(row['strategy'], row['mode']): row for row in group}
                for position in range(10):
                    arm = (sample + position) % 10
                    mapped[(STRATEGIES_V2[arm // 2], MODES[arm % 2])]['invocation_order'] = position
        data['observations'].sort(key=lambda row: (TARGETS.index(row['target']), row['sample'], row['invocation_order']))
        with self.assertRaises(ValueError):
            validate_zero_v2_report(data, self.configuration)

    def test_slow_candidate_remains_an_observation_with_no_speed_gate(self):
        self.assertEqual(validate_zero_v2_report(slow_clocks(self.data), self.configuration),
                         validate_zero_v2_report(self.data, self.configuration))

    def test_all_exhausted_candidate_costs_remain_defined_without_invented_winners(self):
        for row in self.data['observations']:
            for outcome in row['outcomes']:
                outcome.update(status='exhausted', attempts=self.configuration['attempt_budget'])
                for field in ['winning_challenge', 'winner_proof_commitment', 'production_verifier_elapsed_ns',
                              'reference_verifier_elapsed_ns', 'reference_verifier_first']:
                    outcome[field] = None
        self.assertEqual(validate_zero_v2_report(self.data, self.configuration)['statuses'], {'exhausted': 320})

    def test_candidate_failures_cannot_be_unsupported_success(self):
        self.rejected(lambda data: data['observations'][8]['outcomes'][0].update(status='unsupported'))

    def test_candidate_setup_and_failed_attempt_costs_cannot_be_dropped(self):
        for mutation in [lambda row: row.update(setup_calls=0, setup_observations_ns=[]),
                         lambda row: row['outcomes'].pop(),
                         lambda row: row['outcomes'][1].pop('proof_stream_commitment'),
                         lambda row: row['outcomes'][1].update(production_verifier_elapsed_ns=1)]:
            data = copy.deepcopy(self.data)
            mutation(data['observations'][8])
            with self.assertRaises((ValueError, KeyError)):
                validate_zero_v2_report(data, self.configuration)

    def test_candidate_complete_stream_disagreement_cannot_pass(self):
        self.rejected(lambda data: data['observations'][8]['outcomes'][1].update(proof_stream_commitment='9' * 64))

    def test_candidate_boolean_rank_does_not_alias_zero(self):
        self.rejected(lambda data: data['observations'][8].update(rank_a=False))


class ZeroArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-zero-parser-only-')
        self.root = Path(self.temporary.name)
        self.records = {arch: artifact_fixture(self.root / arch, arch) for arch in ARCHITECTURES}

    def tearDown(self):
        self.temporary.cleanup()

    def check(self):
        return compare_artifacts(self.root, 'a' * 40, suite='zero-locality')

    def rejected(self, change):
        change(self.records['arm64'])
        write_manifest(self.root / 'arm64', self.records['arm64'])
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check()

    def test_full_parser_fixture_exercises_source_binary_commands_and_both_campaigns(self):
        result = self.check()
        self.assertEqual(result['schema'], 'trnm-cross-arch-zero-locality-cost-comparison-v2')
        self.assertEqual([row['rows'] for row in result['campaigns']], [80, 40])
        self.assertFalse(result['speed_threshold_applied'])

    def test_failed_native_status_cannot_pass(self):
        self.rejected(lambda report: report.update(result='FAIL'))

    def test_failure_cannot_be_hidden_beneath_pass_label(self):
        self.rejected(lambda report: report.update(error='retained native constructor error'))

    def test_missing_campaign_is_not_completion(self):
        self.rejected(lambda report: report['campaigns'].pop())

    def test_failed_campaign_command_is_not_success(self):
        self.rejected(lambda report: report['observations'][4].update(exit_code=7))

    def test_campaign_failure_cannot_be_hidden_beneath_pass_label(self):
        self.rejected(lambda report: report['campaigns'][0].update(error='retained proof mismatch'))

    def test_false_cannot_be_used_as_zero_exit_code(self):
        self.rejected(lambda report: report['observations'][4].update(exit_code=False))

    def test_command_launch_error_cannot_be_hidden_beneath_success(self):
        self.rejected(lambda report: report['observations'][4].update(launch_error='not executed'))

    def test_prior_source_commit_cannot_replace_current(self):
        self.rejected(lambda report: report['source_before'].update(commit='c' * 40))

    def test_source_bytes_changed_around_native_execution_rejected(self):
        self.rejected(lambda report: report['source_after'].update(tree='c' * 40))

    def test_source_receipt_tree_must_match_native_execution(self):
        (self.root / 'arm64/source.json').write_text(json.dumps({'tested_commit': 'a' * 40,
            'tested_tree': 'c' * 40, 'tracked_worktree_verified': True}))
        with self.assertRaises(ValueError):
            self.check()

    def test_local_preflight_cannot_satisfy_hosted_comparison(self):
        self.rejected(lambda report: report.update(execution_context='local-native-preflight'))

    def test_missing_zero_checker_source_digest_rejected(self):
        self.rejected(lambda report: report['input_sha256'].pop('scripts/ci/check_zero_locality_cost.py'))

    def test_missing_new_candidate_source_or_scalar_bridge_rejected(self):
        for name in ['trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs',
                     'trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs',
                     'formal/pon-nakamoto-v1/test_zero_work.py']:
            report = copy.deepcopy(self.records['arm64'])
            report['input_sha256'].pop(name)
            write_manifest(self.root / 'arm64', report)
            with self.assertRaises(ValueError):
                self.check()
        write_manifest(self.root / 'arm64', self.records['arm64'])

    def test_exact_v1_artifacts_require_explicit_historical_selection(self):
        with tempfile.TemporaryDirectory(prefix='trnm-zero-history-parser-') as temporary:
            directory = Path(temporary)
            for arch in ARCHITECTURES:
                artifact_fixture(directory / arch, arch, zero_version=1)
            report = compare_artifacts(directory, 'a' * 40, suite='zero-locality', zero_version=1)
            self.assertEqual(report['schema'], 'trnm-cross-arch-zero-locality-cost-comparison-v1')
            self.assertEqual([row['rows'] for row in report['campaigns']], [48, 24])
            with self.assertRaises(ValueError):
                compare_artifacts(directory, 'a' * 40, suite='zero-locality')

    def test_historical_source_identity_cannot_include_new_candidate_even_when_resealed(self):
        with tempfile.TemporaryDirectory(prefix='trnm-zero-history-parser-') as temporary:
            directory = Path(temporary)
            report = artifact_fixture(directory, 'x64', zero_version=1)
            added = 'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs'
            self.assertNotIn(added, report['input_sha256'])
            report['input_sha256'][added] = '4' * 64
            write_manifest(directory, report, zero_version=1)
            with self.assertRaises(ValueError):
                validate_artifact(directory, 'a' * 40, suite='zero-locality', zero_version=1)

    def test_different_input_source_digest_across_architectures_rejected(self):
        self.rejected(lambda report: report['input_sha256'].update({'scripts/ci/check_zero_locality_cost.py': '5' * 64}))

    def test_old_binary_cannot_satisfy_zero_native_command(self):
        self.rejected(lambda report: report['observations'][4]['command'].__setitem__(0, '/synthetic/pon_reused_cost'))

    def test_two_x64_artifacts_cannot_satisfy_arm64(self):
        self.rejected(lambda report: report.update(architecture='x64'))

    def test_prior_run_attempt_cannot_satisfy_current_pair(self):
        self.rejected(lambda report: report['runner_context'].update(GITHUB_RUN_ATTEMPT='2'))

    def test_missing_raw_failure_stderr_rejected_even_when_inventory_refreshed(self):
        base = self.root / 'arm64' / suite_contract('zero-locality')['directory']
        (base / 'campaign-0.stderr').unlink()
        write_manifest(self.root / 'arm64', self.records['arm64'])
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_raw_output_rejected_by_retained_hash(self):
        base = self.root / 'arm64' / suite_contract('zero-locality')['directory']
        (base / 'campaign-0.stdout').write_text('{}')
        with self.assertRaises(ValueError):
            self.check()

    def test_consistent_but_different_cross_arch_proof_streams_rejected(self):
        report = self.records['arm64']
        base = self.root / 'arm64' / suite_contract('zero-locality')['directory']
        for index, configuration in enumerate(CAMPAIGNS):
            raw = zero_fixture(configuration, version=2)
            for row in raw['observations']:
                for outcome in row['outcomes']:
                    outcome['proof_stream_commitment'] = '8' * 64
            report['campaigns'][index]['validated'] = validate_zero_v2_report(raw, configuration)
            (base / f'campaign-{index}.stdout').write_text(json.dumps(raw))
        write_manifest(self.root / 'arm64', report)
        with self.assertRaises(ValueError):
            self.check()

    def test_reused_artifact_directory_cannot_stand_in_for_zero_suite(self):
        base = self.root / 'arm64'
        (base / suite_contract('zero-locality')['directory']).rename(base / 'cross-arch-cost')
        with self.assertRaises(ValueError):
            self.check()

    def test_real_failed_partial_json_keeps_stdout_and_stderr(self):
        output = self.root / 'real-capture-only'
        output.mkdir()
        observed = capture([sys.executable, '-c',
            'import sys; print(\'{"schema":"pon-w1-zero-locality-v1","observations":[\'); '
            'print("retained constructor error",file=sys.stderr); sys.exit(7)'],
            output, 'failed-zero-campaign', timeout=10)
        self.assertEqual(observed['exit_code'], 7)
        self.assertIn('"observations":[', (output / observed['stdout']).read_text())
        self.assertIn('retained constructor error', (output / observed['stderr']).read_text())
        with self.assertRaises(ValueError):
            json.loads((output / observed['stdout']).read_text())


class SharedExecutionReceiptContractTests(unittest.TestCase):
    """Original reused, historical zero v1 and current zero v2 keep explicit meanings."""

    def exercise(self, change=None):
        for suite, version in [('reused', 2), ('zero-locality', 1), ('zero-locality', 2)]:
            with self.subTest(suite=suite, zero_version=version), tempfile.TemporaryDirectory(
                    prefix='trnm-shared-cost-parser-only-') as temporary:
                directory = Path(temporary)
                report = artifact_fixture(directory, 'x64', suite=suite, zero_version=version)
                if change is None:
                    actual, _ = validate_artifact(directory, 'a' * 40, suite=suite, zero_version=version)
                    self.assertEqual(actual['schema'], suite_contract(suite, zero_version=version)['execution_schema'])
                    continue
                change(report)
                write_manifest(directory, report, suite=suite, zero_version=version)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    validate_artifact(directory, 'a' * 40, suite=suite, zero_version=version)

    def test_both_exact_historical_success_shapes_remain_valid(self):
        self.exercise()

    def test_manifest_failure_field_is_not_success_even_if_null_or_empty(self):
        for error in [None, '', 'retained native failure']:
            with self.subTest(error=error):
                self.exercise(lambda report: report.update(error=error))

    def test_campaign_failure_field_is_not_success_even_if_null_or_empty(self):
        for error in [None, '', 'retained campaign failure']:
            with self.subTest(error=error):
                self.exercise(lambda report: report['campaigns'][0].update(error=error))

    def test_launch_failure_field_is_not_success_even_if_null_or_empty(self):
        for error in [None, '', 'retained launch failure']:
            with self.subTest(error=error):
                self.exercise(lambda report: report['observations'][4].update(launch_error=error))

    def test_boolean_false_cannot_alias_integer_zero_exit(self):
        self.exercise(lambda report: report['observations'][4].update(exit_code=False))

    def test_integer_zero_cannot_alias_false_timeout(self):
        self.exercise(lambda report: report['observations'][4].update(timed_out=0))

    def test_negative_elapsed_clock_rejected(self):
        self.exercise(lambda report: report['observations'][4].update(elapsed_ns=-1))

    def test_boolean_elapsed_clock_rejected(self):
        self.exercise(lambda report: report['observations'][4].update(elapsed_ns=False))


if __name__ == '__main__':
    unittest.main(verbosity=2)
