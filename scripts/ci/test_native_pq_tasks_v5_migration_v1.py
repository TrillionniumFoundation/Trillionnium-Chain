#!/usr/bin/env python3
"""Synthetic reader/process-owner controls; never actual PQ/native evidence."""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import read_native_pq_tasks_v5_migration_v1 as reader
import run_native_pq_accounts_v2 as accounts
import run_native_pq_quota_v3 as quota
import run_native_pq_tasks_v4 as tasks4
import run_native_pq_tasks_v5 as retained
import run_native_pq_tasks_v5_migration_v1 as runner


def identity(value: str) -> str:
    return hashlib.sha256(('synthetic-reader-control:' + value).encode()).hexdigest()


def rust_log(outcomes: dict[str, str], filtered: int = 0) -> str:
    passed = sum(value == 'ok' for value in outcomes.values())
    failed = sum(value == 'FAILED' for value in outcomes.values())
    ignored = sum(value == 'ignored' for value in outcomes.values())
    status = 'FAILED' if failed else 'ok'
    return '\n'.join(f'test {name} ... {value}' for name, value in sorted(outcomes.items())) + (
        f'\ntest result: {status}. {passed} passed; {failed} failed; {ignored} ignored; '
        f'0 measured; {filtered} filtered out; finished in 0.001s\n')


def json_lines(rows: list[dict]) -> str:
    return '\n'.join(json.dumps(row, separators=(',', ':')) for row in rows) + '\n'


def native_records() -> list[dict]:
    rows = []
    roots = {case: identity(case + ':genesis') for case in reader.EXPECTED_PHASES}
    blocks = {(case, phase): identity(case + ':' + phase)
              for case, phases in reader.EXPECTED_PHASES.items() for phase in phases}
    for case, phases in reader.EXPECTED_PHASES.items():
        for phase in phases:
            source = phase in ('source-checkpoint', 'other-source-checkpoint')
            count = (57 if case == 'capacity' else 1) if source else {
                'claims': 2, 'lease': 1, 'registration': 1, 'replayed-claims': 2, 'fresh-lease': 1,
                'fresh-registration': 1, 'claims-capacity': 55, 'valid-claim-after-refusals': 1,
            }.get(phase, 0)
            if phase == 'other-source-checkpoint':
                count = 0
            raw_bytes = count * 200 if source else {'claims': 18864, 'lease': 4053, 'registration': 7894,
                'replayed-claims': 18864, 'fresh-lease': 4053, 'fresh-registration': 7894,
                'claims-capacity': 518760, 'valid-claim-after-refusals': 9432}.get(phase, 0)
            rows.append({'schema': 'native-pq5-migration-actual-phase-v1', 'case': case, 'phase': phase,
                         'profile': 'source-legacy' if source else reader.PROFILE,
                         'block': blocks[(case, phase)], 'parent': roots[case], 'state_root': identity(case + ':' + phase + ':state'),
                         'transactions': count, 'raw_bytes': raw_bytes, 'proof_bytes': 49188,
                         'packet_bytes': (0 if source else 8) + 318 + 2 + 2 * count + raw_bytes + 49188,
                         'activated': not phase.startswith('fork-'), 'wall_nanoseconds': 1, 'scope': reader.SCOPE})
    lookup = {(row['case'], row['phase']): row for row in rows}
    for chain in (['claims', 'lease', 'registration', 'material'],
                  ['fork-1', 'fork-2', 'fork-3', 'fork-4', 'fork-5', 'replayed-claims', 'fresh-lease', 'fresh-registration', 'fresh-material']):
        parent = roots['unified']
        for phase in chain:
            lookup[('unified', phase)]['parent'] = parent
            parent = blocks[('unified', phase)]
    lookup[('refusal', 'other-source-checkpoint')]['parent'] = blocks[('refusal', 'source-checkpoint')]
    for case, phases in reader.EXPECTED_PHASES.items():
        last = lookup[(case, phases[-1])]
        completion = {'schema': 'native-pq5-migration-completion-v1', 'case': case,
                      'source_checkpoint': blocks[(case, 'source-checkpoint')], 'cold_tip': last['block'],
                      'cold_state_root': last['state_root'], 'prior_pq_registry_external': True,
                      'source_retirement_finality_proved': False}
        if case == 'unified':
            completion.update(genesis=roots[case], reorg_claims_and_nonce_restored=True,
                              task_authority_restored=True, local_pool_ordinal_preserved=True, new_branch_signed_records=2)
        elif case == 'capacity':
            completion.update(claim_bytes=9432, accepted_claims=55, accepted_raw_bytes=518760, refused_claims=56,
                              refused_raw_bytes=528192, transaction_bytes_limit=524288, packet_bytes_limit=1048576, source_accounts=60)
        else:
            completion.update({key: True for key in ('wrong_checkpoint_refused', 'wrong_context_refused', 'wrong_anchor_refused',
                'wrong_prior_key_refused', 'old_pq2_refused', 'old_ed25519_refused', 'wrong_cold_context_refused')})
        rows.append(completion)
    rows.append({'schema': 'native-pq5-fresh-namespace-observation-v1', 'anchored_constructor_used': False,
                 **{key: identity('fresh:' + key) for key in ('network', 'parameters', 'genesis', 'state_root', 'state_json_sha256')}})
    return rows


def native_text(records: list[dict] | None = None) -> str:
    return rust_log({name: 'ok' for name in reader.CASES}) + json_lines(native_records() if records is None else records)


def retained_phases(version: int) -> list[dict]:
    module = retained if version == 5 else tasks4
    rows = [{'schema': module.PHASE_SCHEMA, 'phase': 'maintenance',
             'transactions': 32 if size in (129696, 252608, 264768) else int(size > 0),
             'raw_bytes': size, 'proof_bytes': 49188, 'wall_nanoseconds': 1,
             'block': identity(f'retained:{version}:{index}'), 'scope': module.PHASE_SCOPE}
            for index, size in enumerate(module.EXPECTED_RAW_BYTES)]
    for row in rows[-(8 if version == 5 else 6):]:
        row['phase'] = 'registered-material'
    if version == 5:
        next(row for row in rows if row['raw_bytes'] == 4121)['phase'] = 'registered-material'
        next(row for row in rows if row['raw_bytes'] == 8274)['phase'] = 'registered-material'
        for row in rows:
            row['packet_bytes'] = 8 + 318 + 2 + 2 * row['transactions'] + row['raw_bytes'] + row['proof_bytes']
    return rows


def make_baseline(directory: Path, root: Path) -> dict:
    root.mkdir()
    inputs = reader.baseline_inputs(reader.ROOT)
    for path in inputs:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((reader.ROOT / reader.BASE_RUNNER).read_bytes() if path == reader.BASE_RUNNER
                           else ('synthetic-input:' + path).encode())
    directory.mkdir()
    head, tree = 'a' * 40, 'b' * 40
    tests = {}
    for name, _, _, required in reader.BASE_TESTS:
        outcomes = retained.EXPECTED_OUTCOMES[name] if required is None else {case: 'ok' for case in required}
        text = rust_log(outcomes)
        if name == 'native-task':
            text += json_lines(retained_phases(5))
        elif name == 'retained-native-task':
            text += json_lines(retained_phases(4))
        elif name == 'retained-native-quota':
            sizes = [3821,7314,0,0,7314,3821,9272,7314,0,0,0,9432,3821,7314,0,0,0,0,9432,3821,519294]
            text += json_lines([{'schema': quota.PHASE_SCHEMA, 'phase': 'make-complete-w1-independent-reference-admit-sql',
                                 'transactions': 71 if size == 519294 else int(size > 0), 'raw_bytes': size,
                                 'wall_nanoseconds': 1, 'block': identity(f'quota:{index}'), 'scope': quota.PHASE_SCOPE}
                                for index, size in enumerate(sizes)])
        elif name == 'retained-pq2':
            phases = [{'schema': 'native-pq2-phase-observation-v1', 'phase': phase, 'details': {},
                       'result': outcome, 'wall_nanoseconds': 1, 'scope': accounts.PHASE_SCOPE}
                      for phase, outcome in accounts.PHASE_RESULTS.items() if phase != 'capacity_actual_pool_bundle']
            phases += [{'schema': 'native-pq2-phase-observation-v1', 'phase': 'capacity_actual_pool_bundle',
                        'details': {'transactions': count, 'raw_bytes': 4263 * count}, 'result': 'ok',
                        'wall_nanoseconds': 1, 'scope': accounts.PHASE_SCOPE} for count in [16] * 7 + [10]]
            text += json_lines(phases)
        (directory / (name + '.log')).write_text(text)
        tests[name] = retained.unit_result(text, name) if required is None else retained.test_result(text, required, exact=True)
    observations = []
    for log, command in reader.baseline_commands():
        if not (directory / log).exists():
            (directory / log).write_text('release: 1.95.0\n' if log == 'rustc.log' else 'synthetic reader input\n')
        observations.append({'command': command, 'log': log, 'cwd': str(root), 'exit_code': 0, 'process_exit_code': 0,
                             'executed': True, 'timed_out': False, 'expected_source': head, 'source_before_verified': True,
                             'source_after_verified': True, 'source_verified': True, 'elapsed_ns': 1})
    phase_files = {'native-task-phases.json': retained.task_phases((directory / 'native-task.log').read_text()),
                   'retained-task-phases.json': retained.v4_task_phases((directory / 'retained-native-task.log').read_text()),
                   'retained-quota-phases.json': retained.quota_phases((directory / 'retained-native-quota.log').read_text()),
                   'retained-pq2-phases.json': retained.phase_result((directory / 'retained-pq2.log').read_text())}
    for name, value in phase_files.items():
        (directory / name).write_text(json.dumps(value))
    binary = b'\x7fELFsynthetic parser fixture; never execute'
    (directory / 'native-task-test.bin.gz').write_bytes(gzip.compress(binary, mtime=0))
    report = {'schema': 'native-pq-tasks-v5-research-ci-v1', 'result': 'PASS', 'source_expected': head,
              'source_consistent': True, 'source': {'commit': head, 'tree': tree, 'source_state': 'committed-clean',
                  'tracked_worktree_verified': True, 'tracked_entries': 1, 'tracked_bytes': 1},
              'total_command_budget_seconds': 2400, 'renewal_19_22_qualified': True,
              'supported_new_commands': [18,19,20,21,22], 'production_activation': False,
              'whole_chain_post_quantum': False, 'p1_complete': False, 'migration_supported': False,
              'observations': observations, 'tests': tests, 'native_task_phase_count': 37,
              'input_sha256': {name: reader.digest(root / name) for name in inputs},
              'native_binary': {'bytes': len(binary), 'sha256': hashlib.sha256(binary).hexdigest(),
                  'retained_gzip': 'native-task-test.bin.gz', 'gzip_sha256': reader.digest(directory / 'native-task-test.bin.gz')}}
    report['artifact_sha256'] = {path.name: reader.digest(path) for path in directory.iterdir() if path.is_file()}
    (directory / 'manifest.json').write_text(json.dumps(report))
    return report


class MigrationReaderTests(unittest.TestCase):
    def test_complete_synthetic_control_is_only_parser_evidence(self):
        result = reader.native_result(native_text())
        self.assertEqual(result['tests']['passed'], 3)
        self.assertEqual(len(result['phases']), 19)
        self.assertFalse(result['synthetic_fixture_is_native_evidence'])

    def test_compiled_filtered_ignored_failed_and_renamed_tests_refuse(self):
        rows = {name: 'ok' for name in reader.CASES}
        first = sorted(rows)[0]
        for text in ('Finished compiling', rust_log(rows, filtered=1),
                     rust_log({**rows, first: 'ignored'}), rust_log({**rows, first: 'FAILED'}),
                     rust_log({name: value for name, value in rows.items() if name != first})):
            with self.subTest(text=text[:40]), self.assertRaises(ValueError):
                reader.native_result(text + json_lines(native_records()))

    def test_full_phase_roster_complete_proof_and_original_frame_sizes_required(self):
        mutations = [('proof_bytes', 0), ('proof_bytes', 49187), ('wall_nanoseconds', True),
                     ('packet_bytes', 1048577), ('raw_bytes', 2000), ('transactions', False), ('profile', 'legacy')]
        for field, value in mutations:
            rows = native_records()
            next(row for row in rows if row.get('phase') == 'claims')[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                reader.native_result(native_text(rows))
        for rows in (native_records()[1:], native_records() + [native_records()[0]]):
            with self.assertRaises(ValueError):
                reader.native_result(native_text(rows))

    def test_parent_chain_checkpoint_and_cold_state_are_cross_bound(self):
        for field, phase in [('parent', 'fresh-registration'), ('parent', 'fork-3'), ('state_root', 'fresh-material')]:
            rows = native_records()
            next(row for row in rows if row.get('phase') == phase)[field] = identity('substitution')
            with self.subTest(field=field, phase=phase), self.assertRaises(ValueError):
                reader.native_result(native_text(rows))
        rows = native_records()
        next(row for row in rows if row.get('schema') == 'native-pq5-migration-completion-v1')['source_checkpoint'] = identity('other')
        with self.assertRaises(ValueError):
            reader.native_result(native_text(rows))

    def test_capacity_scope_and_actual_refusal_flags_cannot_be_promoted(self):
        for case, field, value in [('capacity', 'accepted_claims', 54), ('capacity', 'transaction_bytes_limit', 1048576),
                                    ('capacity', 'claim_bytes', 9432.0), ('unified', 'new_branch_signed_records', 0),
                                    ('unified', 'prior_pq_registry_external', False), ('refusal', 'old_ed25519_refused', False),
                                    ('refusal', 'source_retirement_finality_proved', True)]:
            rows = native_records()
            next(row for row in rows if row.get('schema') == 'native-pq5-migration-completion-v1' and row['case'] == case)[field] = value
            with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                reader.native_result(native_text(rows))

    def test_complete_original_205_same_source_artifacts_and_eight_ignores_are_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            report = make_baseline(path / 'run', path / 'source')
            result = reader.baseline_result(path / 'run', 'a' * 40, 'b' * 40, path / 'source')
            self.assertEqual((result['passed'], result['integration_passed'], result['original_ignored']), (205,68,8))
            self.assertFalse(report['p1_complete'])
            self.assertFalse(report['migration_supported'])
            self.assertFalse(result['historical_report_flags_rewritten'])

    def test_same_source_requires_every_actual_original_command_and_execution_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            original = make_baseline(path / 'run', path / 'source')
            mutations = [lambda r: r.update(source_expected='c' * 40),
                         lambda r: r['source'].update(tree='c' * 40),
                         lambda r: r['observations'].pop(),
                         lambda r: r.update(total_command_budget_seconds=2401)]
            for field, value in [('executed', False), ('process_exit_code', None), ('source_before_verified', False),
                                 ('source_after_verified', False), ('source_verified', False), ('timed_out', True),
                                 ('expected_source', 'c' * 40), ('elapsed_ns', True)]:
                mutations.append(lambda r, k=field, v=value: r['observations'][0].update({k: v}))
            for mutate in mutations:
                report = copy.deepcopy(original)
                mutate(report)
                (path / 'run/manifest.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    reader.baseline_result(path / 'run', 'a' * 40, 'b' * 40, path / 'source')

    def test_raw_roster_input_and_executable_bytes_cannot_be_relabelled(self):
        for change in ('log', 'input', 'binary'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)
                report = make_baseline(path / 'run', path / 'source')
                if change == 'log':
                    log = path / 'run/task-renewal.log'
                    log.write_text(log.read_text().replace(sorted(retained.TASK_CASES)[0], 'substituted_case'))
                    report['artifact_sha256'][log.name] = reader.digest(log)
                elif change == 'input':
                    (path / 'source/trillionnium/Cargo.lock').write_text('changed source')
                else:
                    archive = path / 'run/native-task-test.bin.gz'
                    archive.write_bytes(gzip.compress(b'\x7fELFwrong executable', mtime=0))
                    report['artifact_sha256'][archive.name] = reader.digest(archive)
                    report['native_binary']['gzip_sha256'] = reader.digest(archive)
                (path / 'run/manifest.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    reader.baseline_result(path / 'run', 'a' * 40, 'b' * 40, path / 'source')

    def test_exhausted_new_budget_refuses_before_any_spawn(self):
        report = {'observations': []}
        with mock.patch.object(runner.time, 'monotonic', return_value=10), mock.patch.object(runner, 'checked') as checked:
            with self.assertRaises(TimeoutError):
                runner.run_bounded(['never-spawn'], Path('unused'), report, {}, 'a' * 40, 10)
            checked.assert_not_called()
        self.assertEqual(report['observations'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
