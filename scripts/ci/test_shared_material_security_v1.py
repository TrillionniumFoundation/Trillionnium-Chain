#!/usr/bin/env python3
"""Synthetic observer regressions, not native proof or performance evidence.

The false-transcript hash searches and their canonical bytes are real. Legal
verdicts and all clocks are invented solely to exercise evidence consistency;
these fixtures must never be presented as a completed native W1 experiment.
"""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_shared_material_security_v1 as security


def stamp(value):
    return {'cpu_ns': value, 'wall_ns': 2*value}


def record(kind, **fields):
    return dict(schema=security.NATIVE, kind=kind, record_build_timing=stamp(3), **fields)


def fixture(*, cycles=1, seed=bytes([7])*32):
    """One exact zero-material task with consecutive complete hash searches."""
    material = bytes(2*security.CELLS*4)
    task = security.H('task', material[:security.CELLS*4], material[security.CELLS*4:])
    target = bytes([127]) + bytes([255])*31
    limit = 4096
    tile = {'task': task.hex()}
    rows = [record('material', profile=security.PROFILE, input_hex=material.hex(),
                   input_sha256=security.sha(material),
                   matrix_a_sha256=security.sha(material[:security.CELLS*4]),
                   matrix_b_sha256=security.sha(material[security.CELLS*4:]),
                   task=task.hex(), target=target.hex(), target_index=0, seed=seed.hex(),
                   arithmetic='full-limb', materialization='target-hit',
                   challenge_domain='pon-shared-material-challenge-v1', cycles=cycles,
                   max_attempts=limit, input_bytes=len(material), matrix_width=64,
                   field_modulus=security.Q, max_line_bytes=4*1024*1024,
                   attack_controls=True, input_provenance_verified=False, input_timing=stamp(10)),
            record('setup', task=task.hex(), arithmetic='full-limb', calls=1,
                   reuse_searches=cycles, outcome='Prepared', timing=stamp(50))]
    legal_attempts = 0
    for cycle in range(cycles):
        trials = []
        for nonce in range(limit):
            context = security.H('pon-shared-material-challenge-v1', task, target, seed,
                                 struct.pack('<Q', cycle), struct.pack('<Q', nonce))
            # This is intentionally NOT a real W1 transcript; the parser is
            # not a cryptographic authority and the test claims no native run.
            trace = security.H('security-reader-unit-test-legal-trace', context)
            ticket = security.H('ticket', context, trace)
            hit = ticket <= target
            trials.append(dict(nonce=nonce, challenge=context.hex(), trace=trace.hex(),
                               ticket=ticket.hex(), target_hit=hit, proof_materialized=hit,
                               timing=stamp(5), error=None))
            if hit:
                break
        else:
            raise AssertionError('synthetic legal hash search exhausted')
        legal_attempts += len(trials)
        legal_proof = b'PNW1' + material + bytes(security.CELLS*4) + trace
        winner_fields = dict(cycle=cycle, task=task.hex(), challenge=context.hex(),
                             target=target.hex(), ticket=ticket.hex(), proof_hex=legal_proof.hex(),
                             proof_sha256=security.sha(legal_proof))
        rows.append(record('search', cycle=cycle, task=task.hex(), target=target.hex(),
                           arithmetic='full-limb', setup_calls=0, status='target-hit-unverified',
                           error=None, attempts=trials, timing=stamp(5*len(trials)+10)))
        rows.append(record('attack_setup', cycle=cycle, task=task.hex(), setup_calls=1,
                           reuse_searches=2, valid_proof_acquired=False, timing=stamp(11)))
        candidates = []
        for attack_index in range(2):
            context = security.H('pon-shared-material-challenge-v1', task, target, seed,
                                 struct.pack('<Q', cycle), struct.pack('<Q', attack_index))
            trials = []
            for nonce in range(limit):
                trace = security.H('pon-shared-material-false-trace-v1', context, struct.pack('<Q', nonce))
                ticket = security.H('ticket', context, trace)
                hit = ticket <= target
                trials.append(dict(nonce=nonce, challenge=context.hex(), trace=trace.hex(),
                                   ticket=ticket.hex(), target_hit=hit, proof_materialized=hit,
                                   timing=stamp(5), error=None))
                if hit:
                    break
            else:
                raise AssertionError('synthetic false-trace search exhausted')
            proof = b'PNW1' + material + bytes(security.CELLS*4) + trace
            candidate = dict(challenge=context.hex(), ticket=ticket.hex(),
                             proof_hex=proof.hex(), proof_sha256=security.sha(proof))
            candidates.append(candidate)
            rows.append(record('attack_search', cycle=cycle, attack_index=attack_index,
                               task=task.hex(), target=target.hex(), status='target-hit-unverified',
                               attempts=trials, candidate=candidate, timing=stamp(5*len(trials)+10)))
        for index, candidate in enumerate(candidates):
            for path, cost in (('native', 17), ('scalar-reference', 23)):
                rows.append(record('attack_native_verifier', cycle=cycle, attack_index=index,
                                   path=path, task=task.hex(), target=target.hex(),
                                   challenge=candidate['challenge'], proof_sha256=candidate['proof_sha256'],
                                   outcome='Transcript', expected_refusal_observed=True,
                                   unexpected_product_sha256=None, timing=stamp(cost)))
        rows.append(record('attack_cache_setup', cycle=cycle, capacity=1,
                           software_bytes=49308, timing=stamp(13)))
        for index, path in enumerate(security.PATHS):
            if path == 'after-owner-recreation':
                rows.append(record('attack_cache_reset', cycle=cycle, scope=security.RESET_SCOPE,
                                   timing=stamp(7)))
            candidate = candidates[1 if path == 'churn-other' else 0]
            warm = path == 'warm'
            observation = dict(exact_fact_found=warm, trace_reused=warm,
                               transcript_entered=not warm, transcript_completed=not warm,
                               lookup_contended=False, product_entered=False,
                               product_completed=False, product_reused=False, lookup_probes=1,
                               publication='None' if warm else 'Trace', publication_probes=0 if warm else 1)
            rows.append(record('attack_cache_verifier', cycle=cycle, path=path,
                               task=task.hex(), target=target.hex(),
                               challenge=candidate['challenge'], proof_sha256=candidate['proof_sha256'],
                               outcome='Transcript', expected_path_observed=True,
                               observation=observation, timing=stamp(19+index)))
        rows.extend([
            record('candidate', **winner_fields, verified=False),
            record('verification', cycle=cycle, proof_sha256=winner_fields['proof_sha256'],
                   native={'outcome': 'Accepted', 'timing': stamp(31)},
                   scalar_reference={'outcome': 'Accepted', 'timing': stamp(37)}, typed_products_equal=True),
            record('winner', **winner_fields, product_hex=bytes(security.CELLS*4).hex(),
                   product_sha256=security.sha(bytes(security.CELLS*4)), product_source='VerifiedWork.product',
                   scalar_reference_equal=True, typed_copy_timing=stamp(41)),
        ])
    producer = 50 + sum(row['timing']['cpu_ns'] for row in rows if row['kind'] == 'search')
    attack_cost = sum(row['timing']['cpu_ns'] for row in rows if row['kind'].startswith('attack_'))
    build = 3*len(rows)
    summary = record('summary', status='complete', measurement_incomplete=[],
                     requested_cycles=cycles, searches=cycles, attempts=legal_attempts, winners=cycles,
                     exhausted=0, failed_searches=0, control_failures=0,
                     requested_control_campaigns=cycles, control_campaigns=cycles,
                     producer_subtotal=stamp(producer), native_verifier_subtotal=stamp(31*cycles),
                     reference_verifier_subtotal=stamp(37*cycles), typed_copy_subtotal=stamp(41*cycles),
                     record_build_subtotal=stamp(build), serialization_output_subtotal=stamp(60),
                     run_through_before_summary=stamp(10+producer+(31+37+41)*cycles+build+60+attack_cost+100))
    rows.append(summary)
    return rows, (tile, material, seed, target, cycles, limit)


def encode(rows):
    """Recompute raw length to isolate semantic contradictions from truncation."""
    rows = copy.deepcopy(rows)
    prefix = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':'))+'\n').encode() for row in rows[:-1])
    rows[-1]['rows_before_summary'] = len(rows)-1
    rows[-1]['bytes_before_summary'] = len(prefix)
    return prefix + (json.dumps(rows[-1], sort_keys=True, separators=(',', ':'))+'\n').encode()


def first(rows, kind, **fields):
    return next(row for row in rows if row['kind'] == kind and all(row.get(key) == value for key, value in fields.items()))


def manifest_fixture(runner_hash, version=1):
    _, args = fixture()
    tile, material, seed, target, _, limit = args
    tiles = [dict(tile, index=index, feature_start=64*index, feature_count=min(64, 257-64*index),
                  material_bytes=len(material), material_sha256=security.sha(material),
                  a_sha256=security.sha(material[:security.CELLS*4]),
                  b_sha256=security.sha(material[security.CELLS*4:])) for index in range(5)]
    parameters = dict(seed=seed.hex(), target=target.hex(), target_index=0, arithmetic='full-limb',
                      tile_seed_derivation='H(shared-cell-seed-v1,seed,task)', attack_controls=False,
                      cycles=1, max_attempts=limit)
    if version == 2:
        parameters.update(preparation='sparse', verifiers=4)
    return dict(schema=security.MATERIAL_SCHEMAS[version-1], work_profile=security.PROFILE,
                field_modulus=security.Q, tiles=tiles, execution_source={'native_runner_sha256': runner_hash},
                execution_parameters=parameters, same_input_cycles=1, distinct_useful_batch_outputs=1,
                repeated_challenge_outputs_are_new_application_work=False)


class SharedMaterialSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.args = fixture()

    def fails(self, rows, message):
        with self.assertRaisesRegex(ValueError, message):
            security.inspect(encode(rows), *self.args)

    def test_complete_sequence_charges_parent_search_once_and_separates_verifiers(self):
        metrics = security.inspect(encode(self.original), *self.args)
        trials = sum(len(row['attempts']) for row in self.original if row['kind'] == 'attack_search')
        self.assertEqual(metrics['attacker_cpu_ns'], 11+2*10+5*trials)
        self.assertEqual(metrics['raw_native_rejection_cpu_ns'], 34)
        self.assertEqual(metrics['scalar_rejection_cpu_ns'], 46)
        self.assertEqual(metrics['candidates'], 2)
        self.assertEqual(metrics['cache_cpu_ns'], dict(zip(security.PATHS, range(19, 24))))

    def test_repeated_cycles_keep_all_attack_attempts_without_creating_useful_credit(self):
        rows, args = fixture(cycles=2)
        metrics = security.inspect(encode(rows), *args)
        self.assertEqual(metrics['candidates'], 4)
        self.assertEqual(metrics['setups'], 2)
        self.assertEqual(metrics['raw_native_rejection_cpu_ns'], 68)
        self.assertNotIn('distinct_application_batches', metrics)

    def test_rebuilt_subtotals_reject_zero_or_inflated_claims(self):
        for key in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                    'typed_copy_subtotal', 'record_build_subtotal'):
            for value in (stamp(0), stamp(2**32)):
                with self.subTest(key=key, value=value):
                    rows = copy.deepcopy(self.original)
                    rows[-1][key] = value
                    self.fails(rows, 'TIMING_SUBTOTAL_')

    def test_legal_and_attack_search_clocks_must_contain_every_attempt(self):
        for kind in ('search', 'attack_search'):
            for clock in security.CLOCKS:
                with self.subTest(kind=kind, clock=clock):
                    rows = copy.deepcopy(self.original)
                    first(rows, kind)['timing'][clock] = 0
                    self.fails(rows, 'SEARCH_TIMING_ENVELOPE')

    def test_run_envelope_contains_all_disjoint_paths_and_diagnostics(self):
        for field, value in (('run_through_before_summary', stamp(0)),
                             ('serialization_output_subtotal', stamp(2**40))):
            rows = copy.deepcopy(self.original)
            rows[-1][field] = value
            self.fails(rows, 'RUN_TIMING_ENVELOPE')

    def test_clock_unknown_boolean_negative_and_nonfinite_cannot_pass(self):
        for value in (None, False, -1, 2**64, float('nan'), float('inf')):
            with self.subTest(value=value):
                rows = copy.deepcopy(self.original)
                first(rows, 'attack_search')['timing']['cpu_ns'] = value
                self.fails(rows, 'TIMING_INCOMPLETE|NONINTEGER_JSON_NUMBER')

    def test_header_profile_domains_and_exact_counts_are_bound(self):
        for field, value in (('profile', 'another-profile'), ('field_modulus', security.Q-1),
                             ('matrix_width', 63), ('target_index', False), ('cycles', True),
                             ('input_bytes', len(self.args[1])-4), ('matrix_a_sha256', 'ff'*32),
                             ('challenge_domain', 'another-domain'), ('materialization', 'every-attempt'),
                             ('input_provenance_verified', True)):
            with self.subTest(field=field):
                rows = copy.deepcopy(self.original)
                rows[0][field] = value
                self.fails(rows, 'FROZEN_REQUEST_BINDING|FROZEN_HEADER_COUNT')

    def test_setup_task_arithmetic_and_counts_cannot_be_replaced(self):
        for field, value in (('task', 'ff'*32), ('arithmetic', 'transposed'), ('calls', True),
                             ('reuse_searches', False), ('outcome', 'Unobserved')):
            rows = copy.deepcopy(self.original)
            rows[1][field] = value
            self.fails(rows, 'ACTUAL_REUSE')
        rows = copy.deepcopy(self.original)
        first(rows, 'attack_setup')['task'] = 'ff'*32
        self.fails(rows, 'ATTACK_SETUP')

    def test_bool_attack_index_omitted_miss_and_repeated_context_are_refused(self):
        rows = copy.deepcopy(self.original)
        first(rows, 'attack_search')['attack_index'] = False
        self.fails(rows, 'ATTACK_CONTEXT')
        rows = copy.deepcopy(self.original)
        trial = first(rows, 'attack_search')['attempts'][0]
        trial['nonce'] += 1
        self.fails(rows, 'FALSE_TRACE_SEARCH')
        rows = copy.deepcopy(self.original)
        attack0 = first(rows, 'attack_search', attack_index=0)
        attack1 = first(rows, 'attack_search', attack_index=1)
        attack1['attempts'] = copy.deepcopy(attack0['attempts'])
        attack1['candidate'] = copy.deepcopy(attack0['candidate'])
        self.fails(rows, 'FALSE_TRACE_SEARCH')

    def test_false_candidate_cannot_credit_an_acquired_product(self):
        rows = copy.deepcopy(self.original)
        candidate = first(rows, 'attack_search')['candidate']
        proof = bytearray.fromhex(candidate['proof_hex'])
        proof[4+2*security.CELLS*4] = 1
        candidate['proof_hex'], candidate['proof_sha256'] = proof.hex(), security.sha(proof)
        self.fails(rows, 'FALSE_CANDIDATE')

    def test_cache_reset_remains_volatile_and_warm_path_cannot_claim_new_work(self):
        for key, value in (('scope', 'durable service recovery'), ('capacity', 999), ('path', 'cold')):
            rows = copy.deepcopy(self.original)
            first(rows, 'attack_cache_reset')[key] = value
            self.fails(rows, 'CACHE_RESET')
        for key in ('product_reused', 'product_entered', 'transcript_entered'):
            rows = copy.deepcopy(self.original)
            first(rows, 'attack_cache_verifier', path='warm')['observation'][key] = True
            self.fails(rows, 'CACHE_PATH')

    def test_native_rejection_cannot_also_claim_a_product_or_missing_verifier(self):
        rows = copy.deepcopy(self.original)
        first(rows, 'attack_native_verifier')['unexpected_product_sha256'] = 'ff'*32
        self.fails(rows, 'NATIVE_REJECTION')
        rows = copy.deepcopy(self.original)
        rows.remove(first(rows, 'attack_native_verifier'))
        self.fails(rows, 'INCOMPLETE_NATIVE_SEQUENCE')

    def test_incomplete_records_and_failed_campaigns_are_not_a_smaller_success(self):
        raw = encode(self.original)
        for broken in (b'', raw[:-1], raw[:len(raw)//2], raw + raw):
            with self.assertRaises(ValueError):
                security.inspect(broken, *self.args)
        for field, value in (('status', 'failed'), ('measurement_incomplete', ['missing clock']),
                             ('control_failures', 1), ('attempts', True)):
            rows = copy.deepcopy(self.original)
            rows[-1][field] = value
            self.fails(rows, 'NATIVE_NOT_COMPLETE|SUMMARY_COUNT_|LEGAL_ATTEMPT_DENOMINATOR')

    def test_v1_and_v2_material_manifest_bind_same_native_binary_target_and_single_output(self):
        digest = 'ab'*32
        for version in (1, 2):
            data = manifest_fixture(digest, version)
            checked, seed, target = security.material_manifest(json.dumps(data).encode(), digest, 0)
            self.assertEqual(checked, data)
            self.assertEqual(seed.hex(), data['execution_parameters']['seed'])
            self.assertEqual(target.hex(), data['execution_parameters']['target'])
            for field, value in (('distinct_useful_batch_outputs', 5), ('same_input_cycles', True),
                                 ('work_profile', 'replacement-work')):
                wrong = copy.deepcopy(data)
                wrong[field] = value
                with self.assertRaisesRegex(ValueError, 'MATERIAL_'):
                    security.material_manifest(json.dumps(wrong).encode(), digest, 0)
            with self.assertRaisesRegex(ValueError, 'SAME_FROZEN_NATIVE_BINARY'):
                security.material_manifest(json.dumps(data).encode(), '00'*32, 0)
            with self.assertRaisesRegex(ValueError, 'SAME_FROZEN_TARGET_AND_ARITHMETIC'):
                security.material_manifest(json.dumps(data).encode(), digest, 1)
        wrong = manifest_fixture(digest, 2)
        wrong['execution_parameters']['verifiers'] = True
        with self.assertRaisesRegex(ValueError, 'MATERIAL_V2_PARAMETERS'):
            security.material_manifest(json.dumps(wrong).encode(), digest, 0)

    def make_run(self, root):
        source = root/'materials'
        source.mkdir()
        runner = root/'synthetic-runner'
        runner.write_bytes(b'fixture only; subprocess execution is mocked')
        manifest = manifest_fixture(security.sha(runner.read_bytes()), 2)
        (source/'manifest.json').write_text(json.dumps(manifest))
        for index in range(5):
            directory = source/f'tile-{index}'
            directory.mkdir()
            (directory/'material.bin').write_bytes(self.args[1])
        args = SimpleNamespace(material_dir=str(source), runner=str(runner), out=str(root/'out'),
                               cycles=1, max_attempts=4096, target_index=0, timeout=1.0)
        return args, manifest

    def native_double(self, command, material, **_):
        self.assertNotIn('--preparation', command)
        self.assertNotIn('--verifiers', command)
        self.assertIn('--attack-controls', command)
        seed = bytes.fromhex(command[command.index('--seed')+1])
        rows, args = fixture(seed=seed)
        self.assertEqual(material, args[1])
        return SimpleNamespace(stdout=encode(rows), stderr=b'', returncode=0)

    def test_v2_consumer_material_executes_only_original_v1_security_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, manifest = self.make_run(Path(tmp))
            with mock.patch.object(security, 'run_bounded', side_effect=self.native_double) as child:
                self.assertEqual(security.run(args), 0)
            report = json.loads((Path(args.out)/'report.json').read_text())
            self.assertEqual(child.call_count, 5)
            self.assertEqual(report['source_parameters'], manifest['execution_parameters'])
            self.assertEqual(report['source_material_schema'], security.MATERIAL_SCHEMAS[1])
            self.assertEqual(report['execution_parameters']['native_schema'], security.NATIVE)
            self.assertEqual(report['execution_parameters']['preparation'], 'dense')
            self.assertEqual(report['execution_parameters']['verifiers'], 1)
            for flag in ('public_service_qualified', 'physical_recovery_qualified',
                         'cheapest_work_qualified', 'production_activation'):
                self.assertIs(report[flag], False)

    def test_timeout_retains_all_planned_tiles_costs_and_output_prefix_without_success_ratio(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, _ = self.make_run(Path(tmp))
            count = 0
            def execute(command, material, **kwargs):
                nonlocal count
                count += 1
                if count == 2:
                    raise security.ProcessFailure('NATIVE_EXECUTOR_TIMEOUT', returncode=-9,
                                                  stdout=b'partial\n', stderr=b'diagnostic\n', stdin_written=12,
                                                  stdout_truncated=False, stderr_truncated=False)
                return self.native_double(command, material, **kwargs)
            with mock.patch.object(security, 'run_bounded', side_effect=execute):
                self.assertEqual(security.run(args), 2)
            report = json.loads((Path(args.out)/'report.json').read_text())
            self.assertEqual(len(report['results']), 5)
            self.assertEqual(report['status'], 'incomplete')
            self.assertNotIn('raw_native_to_attacker_cpu_ratio', report)
            failure = report['results'][1]
            self.assertEqual(failure['returncode'], -9)
            self.assertEqual(failure['stdin_written'], 12)
            self.assertIn('child_user_cpu_ns', failure)
            self.assertIn('child_system_cpu_ns', failure)
            self.assertIn('supervisor_cpu_ns', failure)
            self.assertEqual((Path(args.out)/'tile-1/stdout.jsonl').read_bytes(), b'partial\n')
            self.assertEqual((Path(args.out)/'tile-1/stderr.txt').read_bytes(), b'diagnostic\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
