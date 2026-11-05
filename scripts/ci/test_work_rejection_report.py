#!/usr/bin/env python3
"""Negative accounting/identity tests; synthetic fixture durations are not observations."""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_work_rejection_report as cost


def attempt(class_name, target, sample, nonce, *, selected=True):
    """A synthetic trace fixture, explicitly substituted for the scalar oracle below."""
    challenge = cost.challenge_for(class_name, target, sample, nonce)
    counter = 0
    while True:
        trace = cost.h(b'synthetic-accounting-fixture-not-measurement', challenge, counter.to_bytes(8, 'little'))
        ticket = cost.h(b'ticket', challenge, trace)
        if (ticket.hex() <= target) is selected:
            break
        counter += 1
    prefix = cost.material(class_name)[2]
    return {'nonce': nonce, 'challenge': challenge.hex(), 'trace': trace.hex(), 'ticket': ticket.hex(),
        'proof_sha256': cost.digest(prefix + trace), 'selected': selected, 'challenge_ns': 3,
        'proof_construction_ns': 100, 'ticket_ns': 5}


def mutations(proof, challenge, target):
    fake_attempts = []
    for nonce in range(cost.LIMIT):
        trace = cost.h(b'rejection-cost-fake-trace-v1', challenge, nonce.to_bytes(8, 'little'))
        ticket = cost.h(b'ticket', challenge, trace)
        selected = ticket.hex() <= target and trace != proof[-32:]
        fake_attempts.append({'nonce': nonce, 'trace': trace.hex(), 'ticket': ticket.hex(), 'selected': selected,
                              'candidate_ns': 3, 'ticket_ns': 5})
        if selected: break
    changed = bytearray(proof)
    changed[-32:] = trace
    wall = len(fake_attempts) * 8 + 12
    transcript = {'id': 'transcript', 'outcome': 'ready', 'source_proof_sha256': cost.digest(proof),
        'proof_sha256': cost.digest(changed), 'trace': trace.hex(), 'ticket': ticket.hex(),
        'clone_ns': 7, 'mutation_ns': 2, 'ticket_search_wall_ns': wall, 'ticket_candidate_ns': 3 * len(fake_attempts),
        'ticket_hash_ns': 5 * len(fake_attempts), 'ticket_recording_overhead_ns': 12,
        'construction_ns': wall + 13, 'construction_overhead_ns': 4,
        'ticket_origin': 'new-fake-trace-search', 'ticket_attempts': fake_attempts, 'product_cell': None}
    changed = bytearray(proof)
    before = struct.unpack('<I', proof[-36:-32])[0]
    after = (before + 1) % cost.Q
    changed[-36:-32] = struct.pack('<I', after)
    product = {'id': 'product-last-cell', 'outcome': 'ready', 'source_proof_sha256': cost.digest(proof),
        'proof_sha256': cost.digest(changed), 'trace': proof[-32:].hex(),
        'ticket': cost.h(b'ticket', challenge, proof[-32:]).hex(),
        'clone_ns': 7, 'mutation_ns': 2, 'ticket_search_wall_ns': 0, 'ticket_candidate_ns': 0,
        'ticket_hash_ns': 0, 'ticket_recording_overhead_ns': 0, 'construction_ns': 13, 'construction_overhead_ns': 4,
        'ticket_origin': 'honest-winner', 'ticket_attempts': [],
        'product_cell': {'index': cost.CELLS - 1, 'before': before, 'after': after}}
    return [transcript, product]


def update_winner(row):
    winner = row['honest_search']['attempts'][-1]
    prefix = bytes.fromhex(row['proof_prefix_hex'])
    proof = prefix + bytes.fromhex(winner['trace'])
    challenge = bytes.fromhex(winner['challenge'])
    row['mutations'] = mutations(proof, challenge, row['target'])
    proof_hashes = {'legal': cost.digest(proof), **{m['id']: m['proof_sha256'] for m in row['mutations']}}
    measured = []
    for position in range(9):
        arm = (position + row['sample']) % 9
        variant, kernel = cost.VARIANTS[arm // 3], cost.KERNELS[arm % 3]
        durations = {'legal': (101, 303, 90), 'transcript': (80, 240, 72), 'product-last-cell': (100, 300, 90)}
        measured.append({'position': position, 'variant': variant, 'kernel': kernel, 'proof_sha256': proof_hashes[variant],
            'elapsed_ns': durations[variant][arm % 3], 'actual_result': cost.RESULTS[arm // 3],
            'returned_product_sha256': cost.digest(prefix[-cost.CELLS * 4:]) if variant == 'legal' else None,
            'probe': cost.expected_progress(challenge, variant)})
    row['measurements'] = measured


@lru_cache(maxsize=1)
def fixture_template():
    rows = []
    for class_name in cost.CLASSES:
        for target in cost.TARGETS:
            for sample in range(cost.SAMPLES):
                prefix, task = cost.material(class_name)[2:]
                row = {'class': class_name, 'target': target, 'sample': sample, 'task': task,
                    'proof_prefix_hex': prefix.hex(), 'setup': {'material_ns': 11, 'task_binding_ns': 13,
                        'reusable_preprocessing_ns': 17, 'total_ns': 41},
                    'honest_search': {'outcome': 'winner', 'attempt_limit': cost.LIMIT, 'wall_ns': 120,
                        'challenge_ns': 3, 'proof_construction_ns': 100, 'ticket_ns': 5, 'diagnostic_overhead_ns': 12,
                        'attempts': [attempt(class_name, target, sample, 0)]}, 'honest_acquisition_ns': 161,
                    'mutations': [], 'measurements': []}
                update_winner(row)
                rows.append(row)
    return {'schema': cost.SCHEMA, 'profile': cost.PROFILE, 'attempt_limit': cost.LIMIT,
        'samples_per_group': cost.SAMPLES, 'producer': 'prepared-task-full-transcript', 'kernels': list(cost.KERNELS),
        'samples': rows, **{flag: False for flag in cost.FALSE_FLAGS}}


def fixture():
    return copy.deepcopy(fixture_template())


def summarize_fixture(raw):
    # Only the expensive cryptographic scalar oracle is substituted. Fixtures
    # explicitly contain synthetic traces/clocks; all bytes, accounting, target
    # search, actual-result labels, progress and order validators still execute.
    winners = {(r['class'], r['honest_search']['attempts'][-1]['challenge']):
        (bytes.fromhex(r['proof_prefix_hex'])[-cost.CELLS * 4:], bytes.fromhex(r['honest_search']['attempts'][-1]['trace']))
        for r in raw['samples'] if r['honest_search']['outcome'] == 'winner'}
    with patch.object(cost, 'independent_winner', side_effect=lambda class_name, challenge: winners[(class_name, challenge)]):
        return cost.summarize(raw)


class RejectionAccountingTests(unittest.TestCase):
    def reject(self, mutate):
        raw = fixture()
        mutate(raw)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            summarize_fixture(raw)

    def test_complete_synthetic_accounting_counts_flows_once(self):
        value = summarize_fixture(fixture())
        self.assertEqual(value['cohorts'], 72)
        self.assertEqual(value['timed_verifications'], 648)
        self.assertEqual(value['independent_winning_transcript_replays'], 72)
        for group in value['groups']:
            self.assertEqual(group['honest_acquisition_ns'], 9 * 161)
            self.assertEqual(group['setup_ns'], 9 * 41)
            self.assertTrue(group['complete_balanced_group'])
            product = group['variants']['product-last-cell/production-transposed']
            self.assertEqual(product['construction_total_ns'], 9 * 13)
            self.assertEqual(product['first_construction_including_honest_acquisition_ns'], 9 * 174)
            self.assertEqual(product['rejection_to_first_construction_ratio']['numerator'], '50')
            self.assertEqual(product['rejection_to_existing_proof_mutation_ratio']['numerator'], '100')
            self.assertEqual(product['rejection_to_existing_proof_mutation_ratio']['denominator'], '13')
        self.assertFalse(value['worst_case_rejection_qualified'])

    def test_old_v3_cannot_be_relabelled_new_late_rejection(self):
        self.reject(lambda r: r.update(schema='pon-structured-cost-v3'))

    def test_missing_setup_rejects(self):
        self.reject(lambda r: r['samples'][0]['setup'].pop('reusable_preprocessing_ns'))

    def test_subtracted_setup_cannot_claim_reused_full_cost(self):
        self.reject(lambda r: r['samples'][0].update(honest_acquisition_ns=120))

    def test_actual_error_required_not_is_err_boolean(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6].update(actual_result=True))

    def test_product_error_cannot_be_inferred_from_transcript_label(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6].update(actual_result='Transcript'))

    def test_callback_probe_cannot_be_timed_verifier_cost(self):
        self.reject(lambda r: r['samples'][0]['measurements'][0]['probe'].update(timed=True))

    def test_probe_result_cannot_disagree_with_actual_timed_result(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6]['probe'].update(actual_result='Transcript'))

    def test_product_must_reach_full_correction_boundary(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6]['probe'].update(before_product=0))

    def test_transcript_must_skip_corrections(self):
        self.reject(lambda r: r['samples'][0]['measurements'][3]['probe'].update(before_product=1))

    def test_equal_counts_cannot_replace_exact_progress_order(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6]['probe'].update(sequence_sha256='0' * 64))

    def test_changed_timed_proof_binding_rejects(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6].update(proof_sha256='0' * 64))

    def test_product_cannot_search_another_ticket(self):
        self.reject(lambda r: r['samples'][0]['mutations'][1].update(ticket_origin='new-fake-trace-search'))

    def test_product_cannot_modify_trace(self):
        self.reject(lambda r: r['samples'][0]['mutations'][1].update(trace='0' * 64))

    def test_product_cannot_reuse_an_unchanged_claimed_cell(self):
        def mutate(r):
            cell = r['samples'][0]['mutations'][1]['product_cell']
            cell['after'] = cell['before']
        self.reject(mutate)

    def test_product_cannot_use_earlier_cell_and_claim_latest_logical_comparison(self):
        self.reject(lambda r: r['samples'][0]['mutations'][1]['product_cell'].update(index=0))

    def test_product_cannot_use_noncanonical_field(self):
        self.reject(lambda r: r['samples'][0]['mutations'][1]['product_cell'].update(after=cost.Q))

    def test_late_rejection_ticket_must_pass_same_target(self):
        self.reject(lambda r: r['samples'][0]['mutations'][0].update(ticket='f' * 64))

    def test_fake_search_cannot_drop_failed_attempt_cost(self):
        self.reject(lambda r: r['samples'][0]['mutations'][0].update(ticket_candidate_ns=0))

    def test_fake_search_cannot_swap_attempts(self):
        self.reject(lambda r: r['samples'][0]['mutations'][0]['ticket_attempts'][0].update(nonce=1))

    def test_selected_boolean_alias_rejects(self):
        self.reject(lambda r: r['samples'][0]['honest_search']['attempts'][0].update(selected=1))

    def test_duration_boolean_alias_rejects(self):
        self.reject(lambda r: r['samples'][0]['measurements'][0].update(elapsed_ns=True))

    def test_qualification_integer_alias_rejects(self):
        self.reject(lambda r: r.update(production_activation=0))

    def test_worst_case_claim_rejects(self):
        self.reject(lambda r: r.update(worst_case_rejection_qualified=True))

    def test_attempt_budget_boolean_alias_rejects(self):
        self.reject(lambda r: r.update(attempt_limit=True))

    def test_sample_boolean_alias_rejects(self):
        self.reject(lambda r: r['samples'][0].update(sample=False))

    def test_probe_integer_boolean_alias_rejects(self):
        self.reject(lambda r: r['samples'][0]['measurements'][0]['probe'].update(before_replay=True))

    def test_original_material_and_product_are_independently_checked(self):
        self.reject(lambda r: r['samples'][0].update(proof_prefix_hex='00' * (cost.PROOF_BYTES - 32)))

    def test_duplicate_cohort_cannot_increase_evidence(self):
        self.reject(lambda r: r['samples'].__setitem__(1, copy.deepcopy(r['samples'][0])))

    def test_missing_cohort_rejects(self):
        self.reject(lambda r: r['samples'].pop())

    def test_reordered_cohorts_reject(self):
        self.reject(lambda r: r['samples'].reverse())

    def test_duplicate_or_missing_kernel_arm_rejects(self):
        self.reject(lambda r: r['samples'][0]['measurements'].__setitem__(1, copy.deepcopy(r['samples'][0]['measurements'][0])))

    def test_pairwise_only_rotation_does_not_replace_nine_arm_order(self):
        self.reject(lambda r: r['samples'][1]['measurements'].reverse())

    def test_product_rejection_must_not_return_verified_product(self):
        self.reject(lambda r: r['samples'][0]['measurements'][6].update(returned_product_sha256='0' * 64))

    def test_changed_failed_attempt_proof_bytes_reject(self):
        self.reject(lambda r: r['samples'][0]['honest_search']['attempts'][0].update(proof_sha256='0' * 64))

    def test_exhaustion_cannot_be_asserted_early(self):
        self.reject(lambda r: r['samples'][0]['honest_search'].update(outcome='exhausted'))

    def test_fake_exhaustion_cannot_hide_a_passing_ticket(self):
        self.reject(lambda r: r['samples'][0]['mutations'][0].update(outcome='search-exhausted'))

    def test_search_wall_keeps_recording_overhead(self):
        self.reject(lambda r: r['samples'][0]['honest_search'].update(wall_ns=108))

    def test_search_retain_actual_failed_proof_before_winner(self):
        raw = fixture()
        row = raw['samples'][0]
        attempts = [attempt(row['class'], row['target'], row['sample'], 0, selected=False),
                    attempt(row['class'], row['target'], row['sample'], 1)]
        row['honest_search'].update(attempts=attempts, wall_ns=240, challenge_ns=6,
            proof_construction_ns=200, ticket_ns=10, diagnostic_overhead_ns=24)
        row['honest_acquisition_ns'] = 281
        update_winner(row)
        result = summarize_fixture(raw)
        self.assertEqual(result['groups'][0]['honest_attempts'], 10)
        self.assertEqual(result['groups'][0]['honest_acquisition_ns'], 9 * 161 + 120)
        row['honest_search']['attempts'].pop(0)
        with self.assertRaises(ValueError): summarize_fixture(raw)

    def test_independent_winner_failure_cannot_pass_raw_labels(self):
        raw = fixture()
        with patch.object(cost, 'independent_winner', return_value=(b'wrong product', b'wrong trace')):
            with self.assertRaises(ValueError): cost.summarize(raw)

    def test_exhausted_fake_search_cost_stays_in_complete_group_denominator(self):
        raw = fixture()
        row = raw['samples'][0]
        challenge = bytes.fromhex(row['honest_search']['attempts'][0]['challenge'])
        original_h = cost.h
        traces = [original_h(b'rejection-cost-fake-trace-v1', challenge, nonce.to_bytes(8, 'little'))
                  for nonce in range(cost.LIMIT)]
        trace_set = set(traces)
        fake = row['mutations'][0]
        fake['ticket_attempts'] = [{'nonce': nonce, 'trace': trace.hex(), 'ticket': 'f' * 64,
            'selected': False, 'candidate_ns': 3, 'ticket_ns': 5} for nonce, trace in enumerate(traces)]
        fake.update(outcome='search-exhausted', proof_sha256=None, trace=None, ticket=None,
            ticket_candidate_ns=3 * cost.LIMIT, ticket_hash_ns=5 * cost.LIMIT,
            ticket_search_wall_ns=8 * cost.LIMIT + 12, construction_ns=8 * cost.LIMIT + 25)
        row['measurements'] = [v for v in row['measurements'] if v['variant'] != 'transcript']
        def controlled_ticket(tag, *parts):
            if tag == b'ticket' and parts[0] == challenge and parts[1] in trace_set:
                return bytes([255]) * 32
            return original_h(tag, *parts)
        with patch.object(cost, 'h', side_effect=controlled_ticket):
            result = summarize_fixture(raw)
        group = result['groups'][0]
        expected = sum(r['mutations'][0]['construction_ns'] for r in raw['samples'][:9])
        entry = group['variants']['transcript/production-transposed']
        self.assertEqual(group['fake_exhausted'], 1)
        self.assertFalse(group['complete_balanced_group'])
        self.assertEqual(entry['verifications'], 8)
        self.assertEqual(entry['construction_total_ns'], expected)
        self.assertEqual(entry['matched_construction_total_ns'], expected - fake['construction_ns'])
        self.assertEqual(entry['first_construction_including_honest_acquisition_ns'], expected + group['honest_acquisition_ns'])

    def test_deterministic_projection_drops_clocks_only(self):
        left = fixture()
        right = copy.deepcopy(left)
        right['samples'][0]['measurements'][0]['elapsed_ns'] += 7
        self.assertEqual(cost.projection_sha256(left), cost.projection_sha256(right))
        right['samples'][0]['measurements'][0]['actual_result'] = 'Transcript'
        self.assertNotEqual(cost.projection_sha256(left), cost.projection_sha256(right))

    def test_summary_does_not_mutate_raw(self):
        raw = fixture()
        before = cost.encoded(raw)
        summarize_fixture(raw)
        self.assertEqual(cost.encoded(raw), before)

    def test_duplicate_json_keys_reject(self):
        with self.assertRaises(ValueError): json.loads('{"schema":1,"schema":2}', object_pairs_hook=cost.unique)

    def test_scalar_probe_counts_do_not_assume_constant_noise_work(self):
        result = cost.expected_progress(bytes([19]) * 32, 'product-last-cell')
        self.assertEqual(result['matrix_rows'], 328)
        self.assertEqual(result['transcript_tiles'], 512)
        self.assertEqual(result['before_product'], 1)
        self.assertEqual(result['before_verified_work'], 0)
        self.assertEqual(result['events'], 842 + sum(result['noise_counts']))


class RejectionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pon-rejection-receipt-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = {path: b'synthetic source input' for path in cost.SOURCE_PATHS}
        self.hashes = {path: cost.digest(raw) for path, raw in self.inputs.items()}
        self.summary = {'test_only': 'synthetic receipt validation fixture, not a cost observation'}
        self.arch = 'x64'
        spec = cost.ARCHITECTURES[self.arch]
        binary = b'\x7fELF\x02\x01' + bytes(12) + spec['elf_machine'].to_bytes(2, 'little')
        (self.root / cost.EXAMPLE).write_bytes(binary)
        (self.root / 'cpuinfo.txt').write_text('synthetic fixture\n')
        commands = [(['uname', '-a'], 'uname', cost.REJECTION_IDENTITY_TIMEOUT_SECONDS),
            (['rustc', '+1.95.0', '-vV'], 'rustc', cost.REJECTION_IDENTITY_TIMEOUT_SECONDS),
            (['cargo', '+1.95.0', '--version'], 'cargo', cost.REJECTION_IDENTITY_TIMEOUT_SECONDS),
            (cost.build_command(self.arch), 'build', cost.REJECTION_BUILD_TIMEOUT_SECONDS),
            (['/synthetic/' + spec['target'] + '/release/examples/' + cost.EXAMPLE], 'native', cost.REJECTION_CAMPAIGN_TIMEOUT_SECONDS)]
        observations = []
        for command, stem, timeout in commands:
            stdout = {'rustc': 'rustc fixture\nrelease: 1.95.0\nhost: ' + spec['target'] + '\n',
                      'cargo': 'cargo 1.95.0 (synthetic)\n', 'native': '{}\n'}.get(stem, 'synthetic\n')
            (self.root / (stem + '.stdout')).write_text(stdout)
            (self.root / (stem + '.stderr')).write_bytes(b'')
            observations.append({'command': command, 'cwd': '/synthetic-source', 'exit_code': 0,
                'timed_out': False, 'output_limit_exceeded': False, 'timeout_seconds': timeout,
                'stdout_limit_bytes': cost.RAW_LIMIT if stem == 'native' else 8 * 1024 * 1024,
                'stderr_limit_bytes': 8 * 1024 * 1024, 'stdout': stem + '.stdout', 'stderr': stem + '.stderr',
                'stdout_bytes': len(stdout.encode()), 'stderr_bytes': 0, 'elapsed_ns': 100})
        identity = {'commit': 'a' * 40, 'tree': 'b' * 40, 'source_state': 'committed-clean',
                    'tracked_worktree_verified': True, 'tracked_entries': 123, 'tracked_bytes': 1000}
        context = {key: None for key in cost.RUNNER_FIELDS}
        context.update(GITHUB_ACTIONS='true', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
            GITHUB_JOB='cross-arch-cost', GITHUB_REPOSITORY='TrillionniumFoundation/Trillionnium-Chain',
            RUNNER_ARCH='X64', RUNNER_OS='Linux', TRNM_COST_RUNNER_LABEL=spec['runner'])
        self.record = {'schema': 'pon-work-rejection-execution-v1', 'result': 'PASS', 'execution_context': 'github-hosted',
            'observed_at_utc': '2026-10-05T00:00:00+00:00',
            'runner_context': context, 'uname': {'system': 'Linux', 'machine': spec['machine']},
            'compiler_channel': '1.95.0', 'build_profile': 'release', 'observations': observations,
            'source_before': identity, 'source_after': copy.deepcopy(identity), 'input_sha256': self.hashes,
            'architecture': self.arch, 'target': spec['target'], 'build_environment_overrides': {},
            'binary_elf_machine': spec['elf_machine'], 'binary_sha256_before': cost.digest(binary),
            'binary_sha256_after': cost.digest(binary), **{flag: False for flag in cost.FALSE_FLAGS}}
        (self.root / 'summary.json').write_bytes(cost.encoded(self.summary))
        self.save()

    def save(self):
        self.record['artifact_sha256'] = {p.name: cost.file_digest(p) for p in self.root.iterdir()
                                          if p.is_file() and p.name != 'manifest.json'}
        (self.root / 'manifest.json').write_bytes(cost.encoded(self.record))

    def verify(self, *, current=None, historical=False):
        def git(*args):
            if args[0] == 'rev-parse': return 'b' * 40
            if args[0] == 'ls-tree': return '\n'.join(sorted(cost.SOURCE_PATHS))
            self.fail('unexpected git command')
        with patch.object(cost, 'git', git), patch.object(cost, 'source_bytes', return_value=self.inputs), \
             patch.object(cost, 'current_inputs', return_value=self.hashes if current is None else current), \
             patch.object(cost, 'summarize', return_value=self.summary):
            return cost.verify(self.root, require_current=not historical)

    def reject_record(self, mutate):
        mutate(self.record)
        self.save()
        with self.assertRaises((ValueError, KeyError, TypeError)): self.verify()

    def test_complete_synthetic_receipt_has_no_new_execution_claim(self):
        value = self.verify()
        self.assertFalse(value['experiment_reexecuted_by_verifier'])
        self.assertTrue(value['current_measured_inputs_match'])

    def test_wrong_native_architecture_rejects(self):
        self.reject_record(lambda r: r.update(architecture='arm64'))

    def test_hosted_env_cannot_override_uname(self):
        self.reject_record(lambda r: r['runner_context'].update(RUNNER_ARCH='ARM64'))

    def test_zero_run_attempt_rejects(self):
        self.reject_record(lambda r: r['runner_context'].update(GITHUB_RUN_ATTEMPT='0'))

    def test_boolean_exit_code_rejects(self):
        self.reject_record(lambda r: r['observations'][-1].update(exit_code=False))

    def test_success_cannot_hide_timeout(self):
        self.reject_record(lambda r: r['observations'][-1].update(timed_out=True))

    def test_success_cannot_hide_launch_failure(self):
        self.reject_record(lambda r: r['observations'][-1].update(launch_error='synthetic failure'))

    def test_success_cannot_hide_output_limit_failure(self):
        self.reject_record(lambda r: r['observations'][-1].update(output_limit_exceeded=True))

    def test_actual_build_cannot_be_replaced_by_successful_stub(self):
        self.reject_record(lambda r: r['observations'][3].update(command=['true']))

    def test_native_binary_command_must_name_native_target(self):
        self.reject_record(lambda r: r['observations'][-1].update(command=['/other/pon_rejection_cost']))

    def test_missing_source_hash_rejects(self):
        self.reject_record(lambda r: r['input_sha256'].pop('rust-toolchain.toml'))

    def test_source_before_after_must_match(self):
        self.reject_record(lambda r: r['source_after'].update(commit='c' * 40))

    def test_extra_success_claim_field_rejects(self):
        self.reject_record(lambda r: r.update(work_hardness_qualified=True))

    def test_command_cwd_cannot_switch_source(self):
        self.reject_record(lambda r: r['observations'][3].update(cwd='/different-source'))

    def test_actual_output_length_cannot_be_relabelled(self):
        self.reject_record(lambda r: r['observations'][-1].update(stdout_bytes=1))

    def test_binary_after_identity_cannot_change(self):
        self.reject_record(lambda r: r.update(binary_sha256_after='0' * 64))

    def test_changed_retained_raw_rejects_before_summarizing(self):
        (self.root / 'native.stdout').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.verify()

    def test_rehashed_wrong_summary_rejects(self):
        (self.root / 'summary.json').write_bytes(cost.encoded({'wrong': True}))
        self.save()
        with self.assertRaises(ValueError): self.verify()

    def test_historical_observation_is_not_current_after_source_change(self):
        changed = dict(self.hashes, **{'rust-toolchain.toml': '0' * 64})
        with self.assertRaises(ValueError): self.verify(current=changed)
        value = self.verify(current=changed, historical=True)
        self.assertFalse(value['current_measured_inputs_match'])

    def test_symlink_cannot_replace_original_artifact(self):
        original = self.root / 'native.stdout'
        raw = original.read_bytes()
        replacement = self.root.parent / (self.root.name + '-raw')
        replacement.write_bytes(raw)
        self.addCleanup(replacement.unlink)
        original.unlink()
        original.symlink_to(replacement)
        with self.assertRaises(ValueError): self.verify()


class RejectionCrossArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pon-rejection-comparison-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.values = [{'architecture': arch, 'source_commit': 'a' * 40, 'source_tree': 'b' * 40,
            'input_sha256': {'input': 'c' * 64}, 'execution_context': 'github-hosted',
            'runner_context': {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'cross-arch-cost',
                              'GITHUB_REPOSITORY': 'TrillionniumFoundation/Trillionnium-Chain'},
            'summary': {'projection_sha256': 'd' * 64}} for arch in ('x64', 'arm64')]

    def compare(self, **kwargs):
        with patch.object(cost, 'verify', side_effect=self.values):
            return cost.compare(self.root / 'x64', self.root / 'arm64', self.root / 'out',
                expected_source=kwargs.get('source', 'a' * 40), expected_run=kwargs.get('run', '123'),
                expected_attempt=kwargs.get('attempt', 1))

    def test_same_run_native_pair(self):
        self.assertEqual(self.compare()['result'], 'PASS')

    def test_two_x64_artifacts_do_not_make_cross_architecture(self):
        self.values[1]['architecture'] = 'x64'
        with self.assertRaises(ValueError): self.compare()

    def test_expected_source_is_required_and_exact(self):
        with self.assertRaises(ValueError): self.compare(source='c' * 40)

    def test_different_actual_run_rejects(self):
        self.values[1]['runner_context']['GITHUB_RUN_ID'] = '124'
        with self.assertRaises(ValueError): self.compare()

    def test_different_attempt_rejects(self):
        with self.assertRaises(ValueError): self.compare(attempt=2)

    def test_boolean_attempt_rejects(self):
        with self.assertRaises(ValueError): self.compare(attempt=True)

    def test_partial_expected_context_rejects(self):
        with self.assertRaises(ValueError): self.compare(run=None)

    def test_local_receipt_cannot_supply_hosted_comparison(self):
        self.values[0]['execution_context'] = 'local-native-preflight'
        with self.assertRaises(ValueError): self.compare()

    def test_different_raw_proof_or_rejection_stream_rejects(self):
        self.values[1]['summary']['projection_sha256'] = 'e' * 64
        with self.assertRaises(ValueError): self.compare()

    def test_five_capture_budget_keeps_every_grace(self):
        self.assertEqual(cost.rejection_job_budget_seconds(), 3 * 30 + 900 + 180 + 5 * 5)


if __name__ == '__main__':
    unittest.main()
