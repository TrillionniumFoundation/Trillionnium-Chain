#!/usr/bin/env python3
"""Arithmetic/schema negative controls, not native execution receipts."""
import copy
import json
import unittest
from work_from_zero import (CLASSES, TARGETS, MODES, case, h, load, projection,
                            validate_construction, validate_diagnosis, summarize)


def fixture(statement):
    challenge, task, target, matrices, limit = statement
    attempts = []
    chosen = None
    for nonce in range(limit):
        trace = h(b'from-zero-fake-trace-v1', challenge, nonce.to_bytes(8, 'little'))
        ticket = h(b'ticket', challenge, trace)
        selected = target != bytes(32) and ticket <= target
        attempts.append({'nonce': nonce, 'trace': trace.hex(), 'ticket': ticket.hex(), 'selected': selected})
        if selected:
            chosen = trace
            break
    return {'schema': 'pon-work-from-zero-construction-v1', 'challenge': challenge.hex(),
            'task': task.hex(), 'target': target.hex(), 'attempt_limit': limit,
            'setup_ns': 1, 'search_ns': 2, 'total_ns': 4, 'attempts': attempts,
            'proof_hex': None if chosen is None else (b'PNW1' + matrices + bytes(16384) + chosen).hex(),
            'outcome': 'exhausted' if chosen is None else 'prefilter-candidate',
            'honest_proof_acquired': False, 'acceptance_granted': False}


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.statement = case('dense', TARGETS[0], 0)
        self.data = fixture(self.statement)

    def test_complete_grid_and_bounded_exhaustion(self):
        candidates = exhausted = 0
        for name in CLASSES:
            for target in TARGETS:
                for sample in range(9):
                    statement = case(name, target, sample)
                    data = fixture(statement)
                    proof = validate_construction(data, statement)
                    if proof is None:
                        exhausted += 1
                        self.assertEqual(len(data['attempts']), statement[-1])
                    else:
                        candidates += 1
                        self.assertEqual(len(proof), 49188)
        self.assertEqual((candidates, exhausted), (72, 36))

    def test_exact_task_challenge_target_bindings(self):
        for key in ('task', 'target', 'challenge'):
            changed = copy.deepcopy(self.data)
            changed[key] = '11' * 32
            with self.assertRaises(ValueError):
                validate_construction(changed, self.statement)

    def test_no_promoted_flags(self):
        for key in ('honest_proof_acquired', 'acceptance_granted'):
            changed = copy.deepcopy(self.data)
            changed[key] = True
            with self.assertRaises(ValueError):
                validate_construction(changed, self.statement)

    def test_empty_attempt_stream_rejects(self):
        self.data['attempts'] = []
        with self.assertRaises(ValueError):
            validate_construction(self.data, self.statement)

    def test_changed_hashes_nonce_and_hit_reject(self):
        for key, value in [('nonce', True), ('trace', '00' * 32),
                           ('ticket', '00' * 32), ('selected', None)]:
            changed = copy.deepcopy(self.data)
            changed['attempts'][0][key] = value
            with self.assertRaises(ValueError):
                validate_construction(changed, self.statement)

    def test_attempts_after_first_hit_reject(self):
        self.data['attempts'].append(self.data['attempts'][-1])
        with self.assertRaises(ValueError):
            validate_construction(self.data, self.statement)

    def test_canonical_zero_claim_and_no_honest_prefix(self):
        proof = bytearray.fromhex(self.data['proof_hex'])
        for pos in (0, 4, 4 + 32768, len(proof) - 1):
            changed = copy.deepcopy(self.data)
            value = proof.copy()
            value[pos] ^= 1
            changed['proof_hex'] = value.hex()
            with self.assertRaises(ValueError):
                validate_construction(changed, self.statement)

    def test_full_cost_accounting_includes_setup(self):
        self.data['total_ns'] = 2
        with self.assertRaises(ValueError):
            validate_construction(self.data, self.statement)

    def test_noninteger_and_negative_clocks_reject(self):
        for value in (True, -1, 2.5, '3'):
            changed = copy.deepcopy(self.data)
            changed['search_ns'] = value
            with self.assertRaises(ValueError):
                validate_construction(changed, self.statement)

    def test_zero_success_has_no_invented_proof(self):
        statement = case('zero', TARGETS[2], 0)
        data = fixture(statement)
        self.assertIsNone(validate_construction(data, statement))
        data['proof_hex'] = '00'
        with self.assertRaises(ValueError):
            validate_construction(data, statement)

    def test_json_duplicate_nonfinite_and_size_reject(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b' ' * (4 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                load(raw)
        self.assertEqual(load(json.dumps(self.data).encode()), self.data)

    def test_exact_native_stage_and_kernel_required(self):
        for mode in MODES:
            data = {'schema': 'pon-work-verifier-diagnostic-v1', 'mode': mode,
                    'result': 'Transcript', 'elapsed_ns': 5}
            validate_diagnosis(data, mode)
            for wrong in ('Accepted', 'Target', 'Product', 'Cancelled'):
                changed = dict(data, result=wrong)
                with self.assertRaises(ValueError):
                    validate_diagnosis(changed, mode)
            with self.assertRaises(ValueError):
                validate_diagnosis(dict(data, mode='verify'), mode)

    def test_summary_retains_exhaustion_and_uses_only_executed_verifiers(self):
        samples = []
        for name in CLASSES:
            for target in TARGETS:
                for sample in range(9):
                    construction = fixture(case(name, target, sample))
                    candidate = construction['proof_hex'] is not None
                    samples.append({'class': name, 'target': target, 'sample': sample,
                        'construction': construction, 'caller_material_ns': 3,
                        'process_wall_ns': 9, 'verifications': [
                            {'mode': mode, 'elapsed_ns': 7} for mode in MODES] if candidate else []})
        groups = summarize(samples)
        self.assertEqual(len(groups), 12)
        for group in groups:
            self.assertEqual(group['native_construction_ns'], 36)
            self.assertEqual(group['caller_material_ns'], 27)
            for observed in group['verifiers'].values():
                if group['target'] == TARGETS[2]:
                    self.assertEqual(group['exhausted'], 9)
                    self.assertEqual(observed['calls'], 0)
                    self.assertIsNone(observed['verifier_to_native_construction_ratio'])
                else:
                    self.assertEqual(observed['verifier_to_native_construction_ratio'],
                                     {'numerator': 63, 'denominator': 36})
        with self.assertRaises(ValueError):
            summarize(samples[:-1])
        samples[0]['verifications'].pop()
        with self.assertRaises(ValueError):
            summarize(samples)

    def test_projection_drops_only_clocks(self):
        changed = copy.deepcopy(self.data)
        changed['total_ns'] += 900
        self.assertEqual(projection(changed), projection(self.data))
        changed['task'] = '22' * 32
        self.assertNotEqual(projection(changed), projection(self.data))


if __name__ == '__main__':
    unittest.main()
