#!/usr/bin/env python3
"""Negative parser/comparison tests; synthetic fixtures are never execution evidence."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from check_cross_arch_cost import (CAMPAIGNS, FALSE_FLAGS, MATERIALS, METHODS, MODES,
    STRATEGIES, STRUCTURED_METHODS, TARGETS, TIMING_SCOPE, compare_artifacts,
    deterministic_projection, read_json, suite_contract, validate_artifact, validate_files,
    validate_raw_report, winning_challenge)
from run_cross_arch_cost import capture, elf_machine


def parser_fixture(configuration: dict) -> dict:
    """An explicitly synthetic parser fixture, not a measured native run."""
    data = {'schema': 'pon-w1-reused-search-v1', 'targets': TARGETS, 'seed': configuration['seed'],
            'samples_per_case_target': configuration['samples'], 'searches_per_cohort': configuration['searches'],
            'attempt_budget': configuration['attempt_budget'],
            'timing': 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'timing_scope': dict(TIMING_SCOPE), 'observations': [], **{key: False for key in FALSE_FLAGS}}
    for name, (rank_a, rank_b, task) in MATERIALS.items():
        for target in TARGETS:
            for sample in range(configuration['samples']):
                for order in range(10):
                    invocation = (sample + order) % 10
                    strategy, mode = STRATEGIES[invocation // 2], MODES[invocation % 2]
                    method = STRUCTURED_METHODS.get(name, 'unsupported') if strategy == 'prepared-structured' else METHODS[strategy]
                    setups = [] if strategy == 'scalar-original' else [13] * (
                        configuration['searches'] if mode == 'cold-per-search' else 1)
                    outcomes = []
                    for index in range(configuration['searches']):
                        unsupported = method == 'unsupported'
                        winner = not unsupported and index % 2 == 0
                        attempts = 0 if unsupported else (1 if winner else configuration['attempt_budget'])
                        outcomes.append({'search_index': index, 'status': 'unsupported' if unsupported else (
                            'winner' if winner else 'exhausted'), 'attempts': attempts,
                            'search_elapsed_ns': 0 if unsupported else 23,
                            'ticket_stream_commitment': None if unsupported else '1' * 64,
                            'proof_stream_commitment': None if unsupported else '2' * 64,
                            'winning_challenge': winning_challenge(task, configuration['seed'], sample, index,
                                target, attempts - 1) if winner else None,
                            'winner_proof_commitment': '3' * 64 if winner else None,
                            'production_verifier_elapsed_ns': 29 if winner else None,
                            'reference_verifier_elapsed_ns': 31 if winner else None,
                            'reference_verifier_first': ((sample + index) % 2 == 0) if winner else None})
                    setup, search = sum(setups), sum(o['search_elapsed_ns'] for o in outcomes)
                    data['observations'].append({'class': name, 'input_source': 'hash-generated-rank-checked'
                        if name == 'full-rank-field' else 'synthetic-fixture', 'task': task,
                        'rank_a': rank_a, 'rank_b': rank_b, 'target': target, 'sample': sample,
                        'invocation_order': order, 'strategy': strategy, 'method': method, 'mode': mode,
                        'proof_bytes': 49188, 'setup_observations_ns': setups, 'setup_calls': len(setups),
                        'setup_elapsed_ns': setup, 'search_elapsed_ns': search,
                        'total_elapsed_ns': setup + search, 'outcomes': outcomes})
    return data


def slow_clocks(data: dict) -> dict:
    result = copy.deepcopy(data)
    for row in result['observations']:
        row['setup_observations_ns'] = [value * 10**6 for value in row['setup_observations_ns']]
        for key in ['setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns']:
            row[key] *= 10**6
        for outcome in row['outcomes']:
            for key in ['search_elapsed_ns', 'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns']:
                if outcome[key] is not None:
                    outcome[key] *= 10**6
    return result


class RawCostContractTests(unittest.TestCase):
    def setUp(self):
        self.configuration = CAMPAIGNS[0]
        self.data = parser_fixture(self.configuration)

    def rejected(self, change):
        change(self.data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate_raw_report(self.data, self.configuration)

    def test_fixture_shape_includes_winners_exhaustion_and_explicit_unsupported(self):
        result = validate_raw_report(self.data, self.configuration)
        self.assertEqual(result['rows'], 560)
        self.assertEqual(set(result['statuses']), {'winner', 'exhausted', 'unsupported'})

    def test_slower_measurements_and_reversed_speed_ratios_are_accepted(self):
        slower = slow_clocks(self.data)
        for row in slower['observations']:
            for outcome in row['outcomes']:
                if outcome['status'] == 'winner':
                    outcome['production_verifier_elapsed_ns'] *= 1000
        self.assertEqual(validate_raw_report(slower, self.configuration),
                         validate_raw_report(self.data, self.configuration))
        self.assertEqual(deterministic_projection(slower), deterministic_projection(self.data))

    def test_missing_material_strategy_or_mode_row_rejected(self):
        self.rejected(lambda d: d['observations'].pop())

    def test_missing_repeated_search_rejected(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'].pop())

    def test_reuse_cannot_hide_additional_actual_setup_calls(self):
        self.rejected(lambda d: d['observations'][3].update(setup_calls=4))

    def test_setup_clock_must_be_included_in_amortized_total(self):
        self.rejected(lambda d: d['observations'][2].update(total_elapsed_ns=92))

    def test_all_misses_must_be_counted_on_exhaustion(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][1].update(attempts=1))

    def test_exhaustion_cannot_invent_verifier_execution(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][1].update(production_verifier_elapsed_ns=1))

    def test_unsupported_cannot_claim_attempts(self):
        self.rejected(lambda d: d['observations'][4]['outcomes'][0].update(attempts=1))

    def test_unsupported_cannot_fabricate_a_proof_stream(self):
        self.rejected(lambda d: d['observations'][4]['outcomes'][0].update(proof_stream_commitment='1'*64))

    def test_complete_proof_stream_required_not_only_ticket_stream(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][0].pop('proof_stream_commitment'))

    def test_optimized_proof_stream_must_equal_scalar(self):
        self.rejected(lambda d: d['observations'][2]['outcomes'][0].update(proof_stream_commitment='9'*64))

    def test_reused_ticket_stream_must_equal_cold_search(self):
        self.rejected(lambda d: d['observations'][1]['outcomes'][0].update(ticket_stream_commitment='9'*64))

    def test_winner_challenge_must_bind_seed_search_index_and_nonce(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][0].update(winning_challenge='0'*64))

    def test_false_fixture_rank_or_task_rejected(self):
        self.rejected(lambda d: d['observations'][0].update(rank_a=64))

    def test_fixed_material_cannot_be_replaced(self):
        self.rejected(lambda d: d['observations'][0].update(task='0'*64))

    def test_timing_scope_cannot_drop_setup_or_hashing(self):
        self.rejected(lambda d: d['timing_scope'].update(actual_setup_per_mode=False))

    def test_invocation_rotation_is_retained(self):
        self.rejected(lambda d: d['observations'][0].update(invocation_order=2))

    def test_emitted_native_invocation_order_cannot_be_reordered(self):
        self.rejected(lambda d: d['observations'].__setitem__(slice(0, 10),
            list(reversed(d['observations'][:10]))))

    def test_material_target_sample_order_cannot_be_reordered(self):
        width = 2 * self.configuration['samples'] * 10
        self.rejected(lambda d: d['observations'].__setitem__(slice(0, width * 2),
            d['observations'][width:width * 2] + d['observations'][:width]))

    def test_verifier_order_is_actual_and_alternating(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][0].update(reference_verifier_first=False))

    def test_finite_result_cannot_promote_work_hardness(self):
        self.rejected(lambda d: d.update(work_hardness_accepted=True))

    def test_second_seed_and_budget_cannot_be_relabelled_as_first(self):
        with self.assertRaises(ValueError):
            validate_raw_report(parser_fixture(CAMPAIGNS[1]), CAMPAIGNS[0])


class ArtifactComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-cost-comparison-test-')
        self.root = Path(self.temporary.name)
        self.raw = [parser_fixture(c) for c in CAMPAIGNS]
        self.records = {}
        # These tiny metadata stubs exercise only pair selection. Native artifact
        # validation is explicitly mocked, never relabelled as actual execution.
        for arch in ['x64', 'arm64']:
            folder = self.root / arch / 'cross-arch-cost'
            folder.mkdir(parents=True)
            (folder / 'manifest.json').write_text('{}\n')
            self.records[arch] = ({'architecture': arch, 'source_before': {'tree': 'b'*40},
                'source_after': {'tree': 'b'*40}, 'input_sha256': {'fixture': '1'*64},
                'runner_context': {'GITHUB_RUN_ID': 'test-run', 'GITHUB_RUN_ATTEMPT': '1'}}, copy.deepcopy(self.raw))

    def tearDown(self):
        self.temporary.cleanup()

    def compare(self):
        with patch('check_cross_arch_cost.validate_artifact', side_effect=lambda p, _: self.records[p.name]):
            return compare_artifacts(self.root, 'a'*40)

    def test_two_architectures_with_different_speeds_preserve_same_streams(self):
        self.records['arm64'] = (self.records['arm64'][0], [slow_clocks(r) for r in self.raw])
        self.assertFalse(self.compare()['speed_threshold_applied'])

    def test_two_x64_runs_cannot_stand_in_for_arm64(self):
        self.records['arm64'][0]['architecture'] = 'x64'
        with self.assertRaises(ValueError):
            self.compare()

    def test_different_real_candidate_trees_rejected(self):
        self.records['arm64'][0]['source_before']['tree'] = 'c'*40
        with self.assertRaises(ValueError):
            self.compare()

    def test_prior_attempt_cannot_complete_new_comparison(self):
        self.records['arm64'][0]['runner_context']['GITHUB_RUN_ATTEMPT'] = '2'
        with self.assertRaises(ValueError):
            self.compare()

    def test_cross_architecture_stream_difference_rejected(self):
        self.records['arm64'][1][0]['observations'][0]['outcomes'][0]['proof_stream_commitment'] = '4'*64
        with self.assertRaises(ValueError):
            self.compare()

    def test_missing_actual_architecture_artifact_rejected(self):
        (self.root / 'arm64').rename(self.root / 'hidden')
        (self.root / 'third').mkdir()
        with self.assertRaises(ValueError):
            self.compare()


class ZeroVersionSelectionTests(unittest.TestCase):
    """Version selection never upgrades a historical report or erases its inputs."""

    def test_historical_v1_input_inventory_is_exactly_preserved(self):
        expected = [
            'rust-toolchain.toml', 'trillionnium/Cargo.lock',
            'scripts/ci/run_cross_arch_cost.py', 'scripts/ci/check_cross_arch_cost.py',
            'trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_locality_cost.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero.rs',
            'scripts/ci/check_zero_locality_cost.py',
        ]
        contract = suite_contract('zero-locality', zero_version=1)
        self.assertEqual(contract['inputs'], expected)
        self.assertEqual(contract['execution_schema'], 'trnm-cross-arch-zero-locality-cost-execution-v1')
        self.assertEqual(contract['comparison_schema'], 'trnm-cross-arch-zero-locality-cost-comparison-v1')

    def test_current_v2_requires_all_new_implementation_and_independent_reader_inputs(self):
        historical = suite_contract('zero-locality', zero_version=1)
        current = suite_contract('zero-locality')
        self.assertEqual(current, suite_contract('zero-locality', zero_version=2))
        self.assertEqual(current['directory'], historical['directory'])
        self.assertEqual(current['example'], historical['example'])
        self.assertEqual(current['inputs'], historical['inputs'] + [
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs',
            'trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs',
            'formal/pon-nakamoto-v1/test_zero_work.py',
            'formal/pon-nakamoto-v1/work_oracle.py',
            'formal/pon-nakamoto-v1/contract_wire.py',
            'trillionnium/crates/trnm-pon-node/tests/zero_task_preparation_lifecycle.rs',
        ])
        self.assertEqual(current['execution_schema'], 'trnm-cross-arch-zero-locality-cost-execution-v2')
        self.assertEqual(current['comparison_schema'], 'trnm-cross-arch-zero-locality-cost-comparison-v2')

    def test_raw_version_is_selected_explicitly_and_never_detected_from_input(self):
        from test_zero_locality_cost import zero_fixture
        for selected in (1, 2):
            parser = suite_contract('zero-locality', zero_version=selected)['validate_raw_report']
            for actual in (1, 2):
                with self.subTest(selected=selected, actual=actual):
                    raw = zero_fixture(CAMPAIGNS[0], version=actual)
                    if selected == actual:
                        self.assertEqual(parser(raw, CAMPAIGNS[0])['rows'], 48 if selected == 1 else 80)
                    else:
                        with self.assertRaises(ValueError):
                            parser(raw, CAMPAIGNS[0])

    def test_noninteger_and_unknown_zero_versions_are_refused(self):
        for version in (True, False, 0, 3, '1', 1.0, None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                suite_contract('zero-locality', zero_version=version)

    def test_comparison_cli_passes_exact_selection_through_full_artifact_validation(self):
        import check_cross_arch_cost
        from test_zero_locality_cost import artifact_fixture
        with tempfile.TemporaryDirectory(prefix='trnm-zero-version-cli-') as folder:
            root = Path(folder)
            for actual in (1, 2):
                artifacts = root / f'v{actual}'
                for arch in ('x64', 'arm64'):
                    artifact_fixture(artifacts / arch, arch, zero_version=actual)
                for selected in (None, 1, 2):
                    output = root / f'actual-{actual}-selected-{selected}.json'
                    arguments = ['check_cross_arch_cost.py', '--suite', 'zero-locality',
                                 '--artifacts', str(artifacts), '--expected-source', 'a' * 40,
                                 '--output', str(output)]
                    if selected is not None:
                        arguments += ['--zero-version', str(selected)]
                    expected_version = 2 if selected is None else selected
                    with self.subTest(actual=actual, selected=selected), \
                            patch.object(sys, 'argv', arguments), \
                            patch('check_cross_arch_cost.source', return_value={
                                'commit': 'a' * 40, 'tree': 'b' * 40, 'source_state': 'committed-clean'}), \
                            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        status = check_cross_arch_cost.main()
                    report = read_json(output)
                    self.assertEqual(report['schema'], f'trnm-cross-arch-zero-locality-cost-comparison-v{expected_version}')
                    self.assertEqual(status, 0 if actual == expected_version else 1)
                    self.assertEqual(report['result'], 'PASS' if actual == expected_version else 'FAIL')
                    if actual != expected_version:
                        self.assertIn('actual successful native execution required', report['error'])

    def test_runner_selects_schema_before_dirty_source_refusal_without_executing_commands(self):
        import run_cross_arch_cost
        with tempfile.TemporaryDirectory(prefix='trnm-zero-runner-selection-') as folder:
            for selected in (None, 1, 2):
                output = Path(folder) / f'selected-{selected}'
                output.mkdir()
                arguments = ['run_cross_arch_cost.py', '--arch', 'x64', '--suite', 'zero-locality', '--local']
                if selected is not None:
                    arguments += ['--zero-version', str(selected)]
                with self.subTest(selected=selected), patch.object(sys, 'argv', arguments), \
                        patch('run_cross_arch_cost.receipt_root', return_value=output), \
                        patch('run_cross_arch_cost.source', return_value={'source_state': 'dirty-fixture'}), \
                        patch('run_cross_arch_cost.capture') as execute, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(run_cross_arch_cost.main(), 1)
                    execute.assert_not_called()
                version = 2 if selected is None else selected
                report = read_json(output / 'manifest.json')
                self.assertEqual(report['schema'], f'trnm-cross-arch-zero-locality-cost-execution-v{version}')
                self.assertEqual(report['result'], 'FAIL')
                self.assertIn('committed source', report['error'])
                self.assertEqual(set(report['input_sha256']), set(suite_contract('zero-locality', zero_version=version)['inputs']))

    def test_both_clis_reject_unsupported_selectors_before_source_or_command_work(self):
        import check_cross_arch_cost
        import run_cross_arch_cost
        for module, required in [
            (check_cross_arch_cost, ['--artifacts', 'unused', '--expected-source', 'a' * 40, '--output', 'unused']),
            (run_cross_arch_cost, ['--arch', 'x64']),
        ]:
            for version in ('0', '3', 'true'):
                with self.subTest(module=module.__name__, version=version), \
                        patch.object(sys, 'argv', [module.__name__, '--suite', 'zero-locality',
                                                 '--zero-version', version, *required]), \
                        patch.object(module, 'source') as read_source, \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    module.main()
                self.assertEqual(caught.exception.code, 2)
                read_source.assert_not_called()


class NativeObservationTests(unittest.TestCase):
    def test_failed_observation_cannot_be_compared_as_success(self):
        with tempfile.TemporaryDirectory(prefix='trnm-failed-cost-') as folder:
            base = Path(folder)
            (base / 'cross-arch-cost').mkdir()
            (base / 'cross-arch-cost/manifest.json').write_text(json.dumps({
                'schema': 'trnm-cross-arch-cost-execution-v1', 'result': 'FAIL'}))
            with self.assertRaises(ValueError):
                validate_artifact(base, 'a'*40)

    def test_local_preflight_cannot_be_relabelled_as_hosted_artifact(self):
        with tempfile.TemporaryDirectory(prefix='trnm-local-cost-') as folder:
            base = Path(folder)
            (base / 'cross-arch-cost').mkdir()
            (base / 'cross-arch-cost/manifest.json').write_text(json.dumps({
                'schema': 'trnm-cross-arch-cost-execution-v1', 'result': 'PASS',
                'execution_context': 'local-native-preflight'}))
            with self.assertRaises(ValueError):
                validate_artifact(base, 'a'*40)

    def test_missing_manifest_is_not_execution(self):
        with tempfile.TemporaryDirectory(prefix='trnm-absent-cost-') as folder:
            with self.assertRaises(ValueError):
                validate_artifact(Path(folder), 'a'*40)

    def test_changed_raw_output_is_rejected_by_its_original_digest(self):
        with tempfile.TemporaryDirectory(prefix='trnm-output-integrity-') as folder:
            base = Path(folder)
            path = base / 'campaign-0.stderr'
            path.write_bytes(b'original failure')
            files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()}
            validate_files(base, files)
            path.write_bytes(b'replaced success')
            with self.assertRaises(ValueError):
                validate_files(base, files)

    def test_omitted_empty_stderr_is_still_missing_evidence(self):
        with tempfile.TemporaryDirectory(prefix='trnm-stderr-integrity-') as folder:
            base = Path(folder)
            path = base / 'campaign-0.stderr'
            path.write_bytes(b'')
            files = {path.name: hashlib.sha256(b'').hexdigest()}
            path.unlink()
            with self.assertRaises(ValueError):
                validate_files(base, files)

    def test_uninventoried_output_cannot_disappear_from_retained_scope(self):
        with tempfile.TemporaryDirectory(prefix='trnm-extra-output-') as folder:
            base = Path(folder)
            (base / 'unexpected.stderr').write_text('retained failure')
            with self.assertRaises(ValueError):
                validate_files(base, {})

    def test_real_failed_command_preserves_separate_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory(prefix='trnm-native-failure-') as folder:
            output = Path(folder)
            observed = capture([sys.executable, '-c',
                'import sys; print("retained output"); print("retained error",file=sys.stderr); sys.exit(7)'],
                output, 'failure', timeout=10)
            self.assertEqual(observed['exit_code'], 7)
            self.assertIn('retained output', (output / observed['stdout']).read_text())
            self.assertIn('retained error', (output / observed['stderr']).read_text())

    def test_elf_header_must_be_real_64_bit_little_endian_format(self):
        with tempfile.TemporaryDirectory(prefix='trnm-elf-header-test-') as folder:
            path = Path(folder) / 'header-only-fixture'
            path.write_bytes(b'not a native binary')
            with self.assertRaises(ValueError):
                elf_machine(path)
            path.write_bytes(b'\x7fELF\x02\x01' + b'\0'*12 + (183).to_bytes(2, 'little'))
            self.assertEqual(elf_machine(path), 183)

    def test_duplicate_json_keys_cannot_hide_an_earlier_failure(self):
        with tempfile.TemporaryDirectory(prefix='trnm-cost-json-test-') as folder:
            path = Path(folder) / 'ambiguous.json'
            path.write_text('{"result":"FAIL","result":"PASS"}')
            with self.assertRaises(ValueError):
                read_json(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
