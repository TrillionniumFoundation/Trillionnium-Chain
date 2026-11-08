#!/usr/bin/env python3
"""New independent CLI owners: commit, cancellation and cold native recovery.

This replays the supplied complete proof. It generates zero fresh proofs and is
not a production-resource or performance experiment. Every subprocess and raw
result is retained, including errors. New output directories are mandatory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--expected-binary-sha256', required=True)
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--proof', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.binary = a.binary.resolve(strict=True)
    a.fixture = a.fixture.resolve(strict=True)
    a.proof = a.proof.resolve(strict=True)
    a.output.mkdir(parents=True, exist_ok=False)
    assert sha(a.binary) == a.expected_binary_sha256
    inputs = [a.fixture / n for n in ('packet.bin', 'statement.bin', 'operator-plan.json')]
    inputs += [a.proof / n for n in ('sha.proof.bin', 'arith.proof.bin')]
    pins = {str(path): sha(path) for path in inputs}
    plan = {
        'schema': 'trnm-w1-node-independent-process-controls-v1',
        'cases': ['none', 'BeforeProof', 'BeforeNodeAdmission', 'NodeCommitted', 'BeforeActivation'],
        'cold_reopen_cases': ['none', 'BeforeNodeAdmission', 'NodeCommitted', 'BeforeActivation'],
        'new_complete_proofs': 0, 'production_resource_profile': False,
        'performance_claim': False, 'production_activation': False,
        'qualification': 'HOLD_NO_GO', 'binary': str(a.binary),
        'binary_sha256': sha(a.binary), 'input_sha256': pins,
        'harness_sha256': sha(Path(__file__)),
        'per_process_timeout_seconds': 60, 'rayon_num_threads': 8,
    }
    save(a.output / 'plan.json', plan)
    env = os.environ.copy()
    env['RAYON_NUM_THREADS'] = '8'
    results = []

    def execute(label, args):
        start = time.monotonic()
        try:
            run = subprocess.run([str(a.binary), *map(str, args)], env=env,
                                 capture_output=True, timeout=60)
            code, out, error = run.returncode, run.stdout, run.stderr
        except subprocess.TimeoutExpired as exception:
            code, out, error = None, exception.stdout or b'', exception.stderr or b''
        (a.output / (label + '.out')).write_bytes(out)
        (a.output / (label + '.err')).write_bytes(error)
        row = {'label': label, 'arguments': list(map(str, args)), 'exit_code': code,
               'wall_seconds': time.monotonic() - start,
               'stdout_sha256': hashlib.sha256(out).hexdigest(),
               'stderr_sha256': hashlib.sha256(error).hexdigest()}
        results.append(row)
        save(a.output / 'subprocesses.json', results)
        assert code == 0, row
        return json.loads(out.splitlines()[-1])['result']

    observations = []
    for case in plan['cases']:
        output = a.output / ('case-' + case)
        record = execute(case, ['exercise', a.fixture, a.proof, output, case])
        assert record == json.loads((output / 'exercise.json').read_text())
        assert record['work_starts_spent'] == 1 and record['next_work_start_refused'] is True
        assert record['production_activation'] is False and record['qualification'] == 'HOLD_NO_GO'
        if case == 'BeforeProof':
            assert record['outcome'] is None and record['error'] == 'REQUEST_CANCELLED:BeforeProof'
            assert record['node_opened'] is False and record['native_observation'] is None
            assert not (output / 'receiver-node').exists()
        elif case == 'BeforeNodeAdmission':
            assert record['outcome'] is None and record['error'] == 'REQUEST_CANCELLED:BeforeNodeAdmission'
            assert record['node_opened'] is True
            assert record['native_observation']['stored_exact'] is False
        else:
            outcome = record['outcome']
            assert record['error'] is None and outcome['native_admitted'] is True
            assert outcome['schema'] == 'trnm-w1-node-adapter-admission-v2'
            assert outcome['native_admission_path_invoked'] is True
            assert 'native_full_replay_required' not in outcome
            assert outcome['both_real_proofs_verified'] is True
            assert outcome['native_observation']['stored_exact'] is True
            assert outcome['native_observation']['active_chain_member'] is (case == 'none')
            if case == 'NodeCommitted':
                assert outcome['late_cancellation'] == 'REQUEST_CANCELLED:NodeCommitted'
                assert outcome['activation_error'] is None
            elif case == 'BeforeActivation':
                assert outcome['late_cancellation'] is None
                assert outcome['activation_error'] == 'REQUEST_CANCELLED:BeforeActivation'
            else:
                assert outcome['late_cancellation'] is None and outcome['activation_error'] is None
        observed = {'case': case, 'exercise': record}
        if case in plan['cold_reopen_cases']:
            cold = execute(case + '-cold', ['reopen', a.fixture, output, record['operation_directory']])
            assert cold['both_real_proofs_reverified'] is True and cold['admission_performed'] is False
            assert cold['production_activation'] is False
            expected_stored = case != 'BeforeNodeAdmission'
            assert cold['native_observation']['stored_exact'] is expected_stored
            # The original native owner recovers a committed best packet as active.
            assert cold['native_observation']['active_chain_member'] is expected_stored
            observed['cold_reopen'] = cold
        observations.append(observed)
        save(a.output / 'observations.json', observations)
    assert all(sha(Path(path)) == expected for path, expected in pins.items())
    assert sha(a.binary) == plan['binary_sha256']
    assert sha(Path(__file__)) == plan['harness_sha256']
    summary = {'schema': plan['schema'], 'result': 'PASS', 'subprocesses': len(results),
               'exercise_cases': 5, 'cold_reopen_cases': 4, 'new_complete_proofs': 0,
               'harness_input_binary_unchanged': True, 'production_resource_profile': False,
               'production_activation': False, 'qualification': 'HOLD_NO_GO',
               'plan_sha256': sha(a.output / 'plan.json'),
               'observations_sha256': sha(a.output / 'observations.json')}
    save(a.output / 'summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
