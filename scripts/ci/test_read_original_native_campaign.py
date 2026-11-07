#!/usr/bin/env python3
"""Reader counterexamples using an explicitly supplied real retained artifact.

Copied metadata/report mutations are parser tests, never new execution or
performance observations. Originals are read-only; temporary hard links are
replaced atomically before a mutation, never written through.
"""
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import read_original_native_campaign as reader

ARTIFACT = HEAD = TREE = MANIFEST = None
SUBSET = False


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()



class ActualCpuFlowSchemaTests(unittest.TestCase):
    """Synthetic accounting controls; no report, workload or native evidence."""

    @staticmethod
    def snapshot(*, wait=None, live=1_950_000_001, settled=None, owners=0, termination=0):
        paid = live + (0 if wait is None else wait)
        remaining = 2_000_000_000 - paid
        flow = dict(schema='public-v3-local-actual-cpu-flow-v1',
                    balance_identity_verified=True, initial_credit_ns=2_000_000_000,
                    credited_refill_ns=0, discarded_refill_ns=0,
                    live_debited_cpu_ns=live, settlement_residual_cpu_ns=0,
                    paid_cpu_debit_ns=paid, settlement_discard_ns=0,
                    settled_full_cpu_ns=live if settled is None else settled,
                    unsettled_known_live_cpu_ns=0 if settled is None else live-settled,
                    booked_reservation_ns=owners*100_000_000, live_owners=owners,
                    remaining_paid_credit_ns=remaining,
                    stored_credit_ns=remaining-owners*100_000_000-termination)
        if termination:
            flow.update(schema='public-v3-local-actual-cpu-flow-reorg-reserve-v2',
                        termination_reserved_ns=termination)
        if wait is not None:
            flow.update(schema='public-v3-local-actual-cpu-flow-admission-wait-v3',
                        admission_wait_cpu_ns=wait)
        return dict(depleted=remaining < 100_000_000 and paid > 1_900_000_000,
                    actual_flow=flow, clock_failures=0,
                    meter=dict(schema='public-v3-local-stored-cpu-budget-v1',
                               burst_ns=2_000_000_000, start_reserve_ns=100_000_000,
                               refill_ns_per_second=250_000_000, worker_limit=2,
                               accounting_unavailable=False))

    def test_legacy_flow_keeps_original_paid_depletion_formula(self):
        value = self.snapshot()
        self.assertTrue(reader.depletion(value))
        value['actual_flow']['termination_reserved_ns'] = 0
        self.assertTrue(reader.depletion(value))

    def test_admission_wait_depletion_does_not_invent_a_live_owner(self):
        value = self.snapshot(wait=1_950_000_001, live=0)
        self.assertTrue(reader.depletion(value))
        self.assertEqual(value['actual_flow']['unsettled_known_live_cpu_ns'], 0)
        self.assertEqual(value['actual_flow']['settled_full_cpu_ns'], 0)

    def test_unsettled_live_excludes_wait_even_while_an_owner_is_active(self):
        value = self.snapshot(wait=50_000_001, live=1_900_000_000,
                              settled=1_800_000_000, owners=1)
        self.assertTrue(reader.depletion(value))
        value['actual_flow']['unsettled_known_live_cpu_ns'] += 50_000_001
        with self.assertRaisesRegex(ValueError, 'unsettled live'):
            reader.depletion(value)

    def test_termination_reserve_cannot_substitute_for_actual_paid_depletion(self):
        for wait in (None, 5):
            value = self.snapshot(wait=wait, live=1_800_000_000, termination=200_000_000)
            self.assertFalse(reader.depletion(value))
            value['depleted'] = True
            with self.assertRaisesRegex(ValueError, 'depletion contradicts'):
                reader.depletion(value)

    def test_new_wait_field_is_required_and_has_exact_u64_type(self):
        for bad in (None, True, -1, 1.0, 2**64):
            value = self.snapshot(wait=7)
            value['actual_flow']['admission_wait_cpu_ns'] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                reader.depletion(value)
        value = self.snapshot(wait=0)
        del value['actual_flow']['admission_wait_cpu_ns']
        with self.assertRaisesRegex(ValueError, 'missing fields'):
            reader.depletion(value)

    def test_legacy_schemas_cannot_silently_acquire_new_wait_semantics(self):
        for termination in (0, 1):
            value = self.snapshot(termination=termination)
            value['actual_flow']['admission_wait_cpu_ns'] = 0
            with self.subTest(termination=termination), self.assertRaisesRegex(ValueError, 'another accounting generation'):
                reader.depletion(value)

    def test_missing_or_double_charged_wait_is_rejected_even_with_adjusted_credit(self):
        for factor in (0, 2):
            value = self.snapshot(wait=70, live=1_950_000_001)
            flow = value['actual_flow']
            flow['paid_cpu_debit_ns'] = flow['live_debited_cpu_ns'] + factor*70
            flow['remaining_paid_credit_ns'] = flow['stored_credit_ns'] = 2_000_000_000-flow['paid_cpu_debit_ns']
            with self.subTest(factor=factor), self.assertRaisesRegex(ValueError, 'paid debit'):
                reader.depletion(value)

    def test_null_flow_remains_unknown_and_cannot_prove_depletion(self):
        value = self.snapshot(wait=7)
        value['actual_flow'] = None
        value['depleted'] = False
        self.assertFalse(reader.depletion(value))
        value['depleted'] = True
        with self.assertRaisesRegex(ValueError, 'missing actual flow'):
            reader.depletion(value)

    def test_clock_failure_and_unavailable_meter_never_prove_depletion(self):
        for key, bad in (('clock_failures', 1), ('clock_failures', True)):
            value = self.snapshot(wait=7)
            value[key] = bad
            value['depleted'] = False
            self.assertFalse(reader.depletion(value))
        value = self.snapshot(wait=7)
        value['meter']['accounting_unavailable'] = True
        value['depleted'] = False
        self.assertFalse(reader.depletion(value))

    def test_missing_common_field_unknown_schema_and_boolean_counter_are_rejected(self):
        for key, bad in (('schema', 'unknown-flow-v99'), ('live_owners', True),
                         ('initial_credit_ns', 2**127), ('discarded_refill_ns', 2**64)):
            value = self.snapshot(wait=7)
            value['actual_flow'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                reader.depletion(value)
        value = self.snapshot(wait=7)
        del value['actual_flow']['discarded_refill_ns']
        with self.assertRaisesRegex(ValueError, 'missing fields'):
            reader.depletion(value)


class ActualArtifactReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes = (ARTIFACT / 'artifact-files.json').read_bytes()
        cls.manifest = reader.strict_json(cls.manifest_bytes)
        cls.valid = reader.read_campaign(ARTIFACT, MANIFEST, HEAD, TREE, retained_subset=SUBSET)
        cls.retention = (reader.strict_json((ARTIFACT / 'retention.json').read_bytes()) if SUBSET else None)
        bundle = (reader.SubsetBundle if SUBSET else reader.Bundle)(ARTIFACT, MANIFEST)
        try:
            cls.report = bundle.json('run-1-raw/report.json')
        finally:
            bundle.close()

    @classmethod
    def tearDownClass(cls):
        if (ARTIFACT / 'artifact-files.json').read_bytes() != cls.manifest_bytes:
            raise ValueError('original artifact manifest was modified')
        for name in ('results.json', *(() if SUBSET else ('run-1-raw/report.json', 'public_v3_multiprocess.bin'))):
            entry = next(row for row in cls.manifest['files'] if row['path'] == name)
            if hashlib.sha256((ARTIFACT / name).read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('original native input was modified: ' + name)

    def clone(self):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-native-reader-counterexample-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        paths = ([row['retained_path'] for row in self.retention['files']] if SUBSET else
                 [row['path'] for row in self.manifest['files']])
        for name in paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            os.link(ARTIFACT / name, path)
        (root / 'artifact-files.json').write_bytes(self.manifest_bytes)
        if SUBSET:
            (root / 'retention.json').write_bytes(encoded(self.retention))
        return root

    def set_manifest(self, root, manifest):
        raw = encoded(manifest)
        (root / 'artifact-files.json').write_bytes(raw)
        if SUBSET:
            retention = reader.strict_json((root / 'retention.json').read_bytes())
            retention['original_manifest'].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (root / 'retention.json').write_bytes(encoded(retention))

    def write(self, root, name, raw):
        retention = reader.strict_json((root / 'retention.json').read_bytes()) if SUBSET else None
        mapping = next(row for row in retention['files'] if row['original_path'] == name) if SUBSET else None
        path = root / (mapping['retained_path'] if SUBSET else name)
        wire = gzip.compress(raw, mtime=0) if SUBSET and mapping['encoding'] == 'gzip' else raw
        temporary = path.with_name(path.name + '.counterexample-new')
        temporary.write_bytes(wire)
        os.replace(temporary, path)
        manifest = reader.strict_json((root / 'artifact-files.json').read_bytes())
        row = next(item for item in manifest['files'] if item['path'] == name)
        row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if SUBSET:
            mapping.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           retained_bytes=len(wire), retained_sha256=hashlib.sha256(wire).hexdigest())
            (root / 'retention.json').write_bytes(encoded(retention))
        self.set_manifest(root, manifest)

    def change_json(self, root, name, change):
        value = reader.strict_json((root / name).read_bytes())
        change(value)
        self.write(root, name, encoded(value))

    def read(self, root):
        pin = hashlib.sha256((root / 'artifact-files.json').read_bytes()).hexdigest()
        return reader.read_campaign(root, pin, HEAD, TREE, retained_subset=SUBSET)

    def test_real_input_preserves_cohorts_and_explicit_unknowns(self):
        counts = self.valid['denominators']
        self.assertEqual(counts, {'complete_runs': 3, 'phases': 9,
            'submitted_block_observations': 189, 'confirmation_round_observations': 27,
            'hostile_round_observations': 18,
            'hostile_rounds_with_observed_depletion_overlap': 9,
            'all_hostile_rounds_depletion_overlapped': False,
            'unique_observed_transaction_ids': 3})
        self.assertFalse(self.valid['scope']['reader_executes_native_test'])
        self.assertFalse(self.valid['scope']['cryptographic_hardness_qualified'])
        self.assertFalse(self.valid['scope']['independent_operators_qualified'])
        self.assertFalse(self.valid['scope']['wan_qualified'])
        self.assertIsNone(self.valid['scope']['sustainable_business_tps'])

    def test_retained_derivation_version_and_all_old_score_fields_remain_exact(self):
        root = self.clone()
        self.change_json(root, 'run-1-phase-readback.json',
                         lambda value: value.update(schema='unknown-derivation'))
        with self.assertRaisesRegex(ValueError, 'unknown retained phase derivation'):
            self.read(root)
        for change in (
            lambda value: value['phases'][0].update(confirmed_rounds=2),
            lambda value: value.update(native_finite_experiment_criteria_met=False),
            lambda value: value['scope'].update(reader_runs_native_admission=True),
        ):
            root = self.clone()
            self.change_json(root, 'run-1-phase-readback.json', change)
            with self.assertRaisesRegex(ValueError, 'retained phase-reader derivation mismatch'):
                self.read(root)

    def test_manifest_pin_paths_duplicates_and_limits_cannot_be_repaired_by_self_report(self):
        with self.assertRaisesRegex(ValueError, 'file-list SHA256'):
            reader.read_campaign(ARTIFACT, '0' * 64, HEAD, TREE, retained_subset=SUBSET)
        controls = (
            lambda value: value['files'][0].update(path='../results.json'),
            lambda value: value['files'][0].update(path='/tmp/results.json'),
            lambda value: value['files'][0].update(path='run-1-raw/./report.json'),
            lambda value: value['files'].append(copy.deepcopy(value['files'][0])),
            lambda value: value['files'][0].update(bytes=reader.MAX_FILE_BYTES + 1),
            lambda value: value['files'][0].update(bytes=True),
        )
        for change in controls:
            with self.subTest(control=change):
                root = self.clone()
                manifest = copy.deepcopy(self.manifest)
                change(manifest)
                self.set_manifest(root, manifest)
                with self.assertRaises(ValueError):
                    self.read(root)

    def test_changed_file_symlink_and_nonregular_input_refuse(self):
        root = self.clone()
        (root / 'results.json').unlink()
        (root / 'results.json').symlink_to(ARTIFACT / 'results.json')
        with self.assertRaises(OSError):
            self.read(root)
        root = self.clone()
        raw = (root / 'results.json').read_bytes()
        temporary = root / 'replacement'
        temporary.write_bytes(raw.replace(b'release', b'debugXX', 1))
        os.replace(temporary, root / 'results.json')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.read(root)
        root = self.clone()
        (root / 'build.stderr.log').unlink()
        os.mkfifo(root / 'build.stderr.log')
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.read(root)

    def test_source_profile_resource_and_missing_binary_refuse(self):
        controls = (
            ('source-before-campaigns.json', lambda v: v.update(tested_tree='0' * 40)),
            ('run-3-resource-after.json', lambda v: v['limits'][0].update({'cpu.max': '800000 100000'})),
            ('results.json', lambda v: v['binary']['actual_compiler_artifact_profile'].update(opt_level='0')),
            ('results.json', lambda v: v.update(original_inputs={**v['original_inputs'], 'seed_transfers': 256})),
            ('results.json', lambda v: v.update(attempts=v['attempts'][:2])),
            ('run-1-phase-readback.json', lambda v: v['phases'][0].update(confirmed_rounds=2)),
        )
        for name, change in controls:
            with self.subTest(name=name):
                root = self.clone()
                self.change_json(root, name, change)
                with self.assertRaises(ValueError):
                    self.read(root)
        if not SUBSET:
            root = self.clone()
            (root / 'public_v3_multiprocess.bin').unlink()
            with self.assertRaises(OSError):
                self.read(root)

    def test_zero_test_output_cannot_pass_even_with_updated_metadata_hashes(self):
        root = self.clone()
        raw = (root / 'run-1.stdout.log').read_bytes().replace(b'1 passed', b'0 passed')
        self.write(root, 'run-1.stdout.log', raw)
        digest = hashlib.sha256(raw).hexdigest()
        def update_step(value):
            value.update(stdout_bytes=len(raw), stdout_sha256=digest)
        self.change_json(root, 'run-1.step.json', update_step)
        self.change_json(root, 'run-1-result.json', lambda v: update_step(v['step']))
        self.change_json(root, 'results.json', lambda v: update_step(v['attempts'][0]['step']))
        with self.assertRaisesRegex(ValueError, 'exactly one original native test'):
            self.read(root)

    def test_boolean_exit_status_is_not_integer_success(self):
        root = self.clone()
        self.change_json(root, 'run-1.step.json', lambda v: v.update(returncode=False))
        self.change_json(root, 'run-1-result.json', lambda v: v['step'].update(returncode=False))
        self.change_json(root, 'results.json', lambda v: v['attempts'][0]['step'].update(returncode=False))
        with self.assertRaisesRegex(ValueError, 'step did not complete'):
            self.read(root)

    def test_runtime_executable_cannot_differ_from_built_artifact(self):
        root = self.clone()
        raw = (root / 'run-1.stderr.log').read_bytes().replace(
            b'/release/deps/public_v3_multiprocess-', b'/debug/deps/public_v3_multiprocess-')
        self.write(root, 'run-1.stderr.log', raw)
        digest = hashlib.sha256(raw).hexdigest()
        def update_step(value):
            value.update(stderr_bytes=len(raw), stderr_sha256=digest)
        self.change_json(root, 'run-1.step.json', update_step)
        self.change_json(root, 'run-1-result.json', lambda v: update_step(v['step']))
        self.change_json(root, 'results.json', lambda v: update_step(v['attempts'][0]['step']))
        with self.assertRaisesRegex(ValueError, 'runtime executable'):
            self.read(root)

    def test_duplicate_json_and_nonfinite_numbers_refuse(self):
        for raw in (b'{"schema":"a","schema":"b"}', b'{"elapsed_seconds":NaN}'):
            root = self.clone()
            self.write(root, 'results.json', raw)
            with self.assertRaises(ValueError):
                self.read(root)

    def test_report_round_counters_and_authority_cannot_replace_observations(self):
        controls = (
            lambda p: p['confirmations'][0].update(paid_credit_depletion_observed_during_round=True),
            lambda p: p['confirmations'][0]['observation'].update(execution_authority=True),
            lambda p: p['confirmations'][0]['observation'].update(depth=7),
            lambda p: p['confirmations'][0]['receiver_hostile_after'].update(
                work_rejected=p['confirmations'][0]['receiver_hostile_before']['work_rejected']),
            lambda p: p['receiver_observation'].update(measurement_failures=1),
            lambda p: [row.update(public_request_body_digest=None) for child in p['children']
                       for row in child['report']['result']['calls']],
            lambda p: p['submissions'].pop(),
            lambda p: p['confirmations'].pop(),
        )
        for change in controls:
            with self.subTest(control=change):
                phase = copy.deepcopy(self.report['phases'][1])
                change(phase)
                with self.assertRaises(ValueError):
                    reader.phase(phase)

    def test_booked_principal_cannot_become_paid_cpu_depletion(self):
        original = self.report['phases'][1]['depletion_meter']
        self.assertTrue(reader.depletion(original))
        value = copy.deepcopy(original)
        flow = value['actual_flow']
        flow.update(paid_cpu_debit_ns=0, live_debited_cpu_ns=0,
                    settlement_residual_cpu_ns=0, settled_full_cpu_ns=0,
                    unsettled_known_live_cpu_ns=0, live_owners=20, booked_reservation_ns=2_000_000_000)
        flow['remaining_paid_credit_ns'] = flow['initial_credit_ns'] + flow['credited_refill_ns'] - flow['settlement_discard_ns']
        flow['stored_credit_ns'] = flow['remaining_paid_credit_ns'] - flow['booked_reservation_ns']
        with self.assertRaisesRegex(ValueError, 'live_owners: above allowed maximum'):
            reader.depletion(value)
        # Keep the original depletion counterexample inside the real two-owner
        # limit: booked principal can hide start credit, but it is not paid CPU.
        value = copy.deepcopy(original)
        flow = value['actual_flow']
        flow.update(initial_credit_ns=2_000_000_000, credited_refill_ns=0,
                    settlement_discard_ns=0, paid_cpu_debit_ns=1_850_000_000,
                    live_debited_cpu_ns=1_850_000_000, settlement_residual_cpu_ns=0,
                    settled_full_cpu_ns=0, unsettled_known_live_cpu_ns=1_850_000_000,
                    live_owners=2, booked_reservation_ns=200_000_000,
                    remaining_paid_credit_ns=150_000_000, stored_credit_ns=-50_000_000)
        with self.assertRaisesRegex(ValueError, 'reported depletion'):
            reader.depletion(value)
        value = copy.deepcopy(original)
        value['actual_flow']['paid_cpu_debit_ns'] += 1
        with self.assertRaisesRegex(ValueError, 'balance identity'):
            reader.depletion(value)

    def test_economics_requires_all_observed_samples_and_real_winners(self):
        for change in (
                lambda v: v['economics'].pop(),
                lambda v: v['economics'][0]['report']['result']['modes'][0]['samples'][0].update(errors=['retained failure']),
                lambda v: v.update(best_observed_cold_legal_method='prepared-generic')):
            value = copy.deepcopy(self.report)
            change(value)
            with self.assertRaises(ValueError):
                reader.economics(value)

    def cost_input(self):
        # Copy only the original cost observations and their actual business
        # packet context. Mutations are counterexamples, never measured costs.
        return copy.deepcopy({key: self.report[key] for key in (
            'economics', 'preparation', 'selection_candidates_cpu_ns',
            'best_observed_cold_legal_method', 'economics_complete')})

    def test_cost_derivation_keeps_actual_reuse_and_complete_denominators(self):
        value = reader.economics(self.report)
        self.assertEqual(value['schema'], 'pon-original-native-campaign-work-costs-v1')
        self.assertEqual(len(value['legal_cohorts']), 16)
        self.assertEqual(len(value['from_zero_cohorts']), 8)
        self.assertEqual(value['distinct_legal_winner_proofs'], 12)
        self.assertEqual(value['distinct_from_zero_proofs'], 12)
        for cohort in value['legal_cohorts']:
            actor = self.report['economics'][reader.METHODS.index(cohort['method'])]['report']['result']
            original = next(m for m in actor['modes']
                            if m['reuse_preparation'] is cohort['reuse_preparation'])
            total = sum(s['acquisition_cpu_ns'] for s in original['samples'])
            self.assertEqual(cohort['full_acquisition_process_cpu_ns']['sum_known_ns'], total)
            self.assertEqual(cohort['winning_searches'], 12)
            self.assertEqual(cohort['actual_setup_calls'], 3 if cohort['reuse_preparation'] else 12)
            ratio = cohort['full_acquisition_cpu_per_winner_ns']
            self.assertEqual(ratio['numerator'] * 12, total * ratio['denominator'])
        for cohort in value['from_zero_cohorts']:
            self.assertFalse(cohort['genuine_proof_acquisition_used'])
            self.assertEqual(cohort['valid_work_credit'], 0)
            self.assertEqual(cohort['false_candidates'], 12)
            ratio = cohort['rejection_to_full_construction_cpu_ratio']
            self.assertEqual(ratio['numerator'] * cohort['full_construction_process_cpu_ns']['sum_known_ns'],
                             ratio['denominator'] * cohort['separate_rejection_process_cpu_ns']['sum_known_ns'])
        self.assertFalse(value['scope']['nested_clocks_added_again_to_total'])
        self.assertFalse(value['scope']['modeled_64_winner_reuse'])
        self.assertFalse(value['scope']['w1_transcripts_independently_replayed'])
        self.assertFalse(value['scope']['cryptographic_hardness_qualified'])
        self.assertFalse(value['scope']['production_activation'])

    def test_cost_target_misses_packets_and_setup_counts_cannot_be_relabelled(self):
        def legal(value):
            return value['economics'][0]['report']['result']['modes'][0]['samples'][0]
        def false(value):
            return value['economics'][0]['report']['result']['same_task_target_from_zero_samples'][0]
        mutations = (
            lambda v: v['economics'][0]['report']['result']['modes'][0].update(setup_calls_per_sample=64),
            lambda v: legal(v).update(sample=True),
            lambda v: legal(v).update(initial_setup_cpu_ns=2**100),
            lambda v: legal(v)['verified_winners'][0].update(Err='Transcript'),
            lambda v: legal(v)['searches'][0].update(winning_header='00' * 318),
            lambda v: legal(v)['searches'][0].update(proof_digest='00' * 32),
            lambda v: legal(v)['searches'][0].update(packet_digest='00' * 32),
            lambda v: legal(v)['searches'][0]['attempts'][0].update(nonce=0),
            lambda v: legal(v)['searches'][0]['attempts'][0].update(ticket='00' * 32),
            lambda v: next(s for s in legal(v)['searches'] if len(s['attempts']) > 1)['attempts'].pop(0),
            lambda v: false(v)['searches'].pop(),
            lambda v: false(v)['searches'][0]['attempts'][0].update(trace='00' * 32),
            lambda v: false(v)['searches'][0].update(packet_bytes=1),
            lambda v: false(v)['searches'][0].update(packet_digest=legal(v)['searches'][0]['packet_digest']),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = self.cost_input()
                mutation(value)
                with self.assertRaises(ValueError):
                    reader.economics(value)

    def test_cost_unknown_subclocks_remain_unknown_not_free(self):
        value = self.cost_input()
        actor = value['economics'][0]['report']['result']
        actor['modes'][0]['samples'][0]['initial_setup_cpu_ns'] = None
        actor['same_task_target_from_zero_samples'][0]['diagnostic_cpu_ns'] = None
        costs = reader.economics(value)
        setup = costs['legal_cohorts'][0]['nested_initial_setup_cpu_ns']
        self.assertEqual(setup['unknown_count'], 1)
        rejection = costs['from_zero_cohorts'][0]
        self.assertEqual(rejection['separate_rejection_process_cpu_ns']['unknown_count'], 1)
        self.assertIsNone(rejection['rejection_to_full_construction_cpu_ratio'])
        actor['modes'][0]['samples'][0]['acquisition_cpu_ns'] = None
        with self.assertRaises(ValueError):
            reader.economics(value)

    def test_cost_known_disjoint_subclocks_bound_total_when_another_is_unknown(self):
        for axis in ('cpu_ns', 'wall_ns'):
            for unknown in ('initial_setup', 'search_setup', 'search'):
                with self.subTest(axis=axis, unknown=unknown):
                    value = self.cost_input()
                    sample = value['economics'][0]['report']['result']['modes'][0]['samples'][0]
                    total = sample['acquisition_' + axis]
                    if unknown == 'initial_setup':
                        sample['initial_setup_' + axis] = None
                    else:
                        phase = 'setup' if unknown == 'search_setup' else 'search'
                        sample['searches'][1][phase + '_' + axis] = None
                    # Both intervals fit individually, but their disjoint sum
                    # already exceeds the inclusive acquisition denominator.
                    sample['searches'][0]['setup_' + axis] = total
                    sample['searches'][0]['search_' + axis] = total
                    with self.assertRaisesRegex(ValueError, 'disjoint setup/search clocks exceed complete cost'):
                        reader.economics(value)

    def test_cost_known_subclock_sum_accepts_equality_and_slack_without_filling_unknown(self):
        for axis in ('cpu_ns', 'wall_ns'):
            for slack in (0, 1):
                with self.subTest(axis=axis, slack=slack):
                    value = self.cost_input()
                    sample = value['economics'][0]['report']['result']['modes'][0]['samples'][0]
                    sample['initial_setup_' + axis] = None
                    for search in sample['searches']:
                        search['setup_' + axis] = search['search_' + axis] = 0
                    sample['searches'][0]['search_' + axis] = sample['acquisition_' + axis] - slack
                    costs = reader.economics(value)
                    self.assertIsNone(sample['initial_setup_' + axis])
                    if axis == 'cpu_ns':
                        self.assertEqual(costs['legal_cohorts'][0]['nested_initial_setup_cpu_ns']['unknown_count'], 1)

    def test_cost_selection_uses_one_complete_method_not_each_fastest_sample(self):
        value = self.cost_input()
        candidates = []
        for index, actor in enumerate(value['economics']):
            for mode in actor['report']['result']['modes']:
                totals = ([100_000_000, 900_000_000, 100_000_000] if index == 0 else
                          [900_000_000, 100_000_000, 900_000_000] if index == 1 else
                          [2_000_000_000] * 3)
                for sample, total in zip(mode['samples'], totals):
                    sample['acquisition_cpu_ns'] = total
                if not mode['reuse_preparation']:
                    candidates.append([sorted(totals)[1], index])
        value['selection_candidates_cpu_ns'] = sorted(candidates)
        value['best_observed_cold_legal_method'] = 'prepared-generic'
        costs = reader.economics(value)
        for comparison in costs['fixed_method_comparisons']:
            self.assertEqual(comparison['selected_fixed_method'], 'prepared-generic')
            self.assertEqual(comparison['selected_total_cpu_ns'], 1_100_000_000)
            self.assertNotEqual(comparison['selected_total_cpu_ns'], 300_000_000)

    def test_effective_share_is_conditional_valid_work_not_fake_ticket_rate(self):
        value = reader.work_share_sensitivity(2, 1)
        rows = value['assumed_same_hardware_cpu_budget_shares']
        self.assertEqual(rows[1]['modeled_effective_valid_work_share'],
                         {'numerator': 2, 'denominator': 11, 'value': 2 / 11})
        self.assertEqual(rows[2]['modeled_effective_valid_work_share'],
                         {'numerator': 2, 'denominator': 5, 'value': 0.4})
        self.assertEqual(value['modeled_budget_share_at_half_valid_work']['value'], 1 / 3)
        self.assertFalse(value['invalid_from_zero_tickets_count_as_work'])
        self.assertIsNone(value['measured_network_adversary_share'])
        self.assertFalse(value['network_effective_work_share_qualified'])

    def test_subset_requires_explicit_mode_and_does_not_claim_omitted_binary(self):
        if SUBSET:
            self.assertEqual(self.valid['coverage'], 'retained-subset')
            self.assertFalse(self.valid['binary_payload_hash_verified'])
            self.assertLess(self.valid['verified_original_file_count'], self.valid['original_manifest_file_count'])
            with self.assertRaises(OSError):
                reader.read_campaign(ARTIFACT, MANIFEST, HEAD, TREE)
        else:
            self.assertEqual(self.valid['coverage'], 'full-artifact')
            self.assertTrue(self.valid['binary_payload_hash_verified'])
            self.assertEqual(self.valid['verified_original_file_count'], 910)

    def test_subset_mapping_and_gzip_decode_are_checked_against_original_hash(self):
        if not SUBSET:
            self.skipTest('gzip counterexamples require the explicit retained-subset invocation')
        root = self.clone()
        retention = reader.strict_json((root / 'retention.json').read_bytes())
        mapping = next(row for row in retention['files'] if row['encoding'] == 'gzip')
        path = root / mapping['retained_path']
        raw = gzip.decompress(path.read_bytes()) + b'counterexample-only extra decoded byte'
        wire = gzip.compress(raw, mtime=0)
        replacement = path.with_name(path.name + '.counterexample-new')
        replacement.write_bytes(wire)
        os.replace(replacement, path)
        mapping.update(retained_bytes=len(wire), retained_sha256=hashlib.sha256(wire).hexdigest())
        (root / 'retention.json').write_bytes(encoded(retention))
        with self.assertRaisesRegex(ValueError, 'decoded retention'):
            self.read(root)
        root = self.clone()
        retention = reader.strict_json((root / 'retention.json').read_bytes())
        retention['files'][0]['sha256'] = '0' * 64
        (root / 'retention.json').write_bytes(encoded(retention))
        with self.assertRaisesRegex(ValueError, 'contradicts original'):
            self.read(root)
        bundle = reader.SubsetBundle(ARTIFACT, MANIFEST)
        try:
            with self.assertRaisesRegex(ValueError, 'decoded retention exceeds'):
                bundle.raw('run-1-raw/report.json', 1024)
        finally:
            bundle.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--retained-subset', action='store_true')
    args, remaining = parser.parse_known_args()
    ARTIFACT, HEAD, TREE, MANIFEST = (args.artifact_dir, args.expected_head,
                                      args.expected_tree, args.expected_manifest_sha256)
    SUBSET = args.retained_subset
    unittest.main(argv=[sys.argv[0], *remaining])
