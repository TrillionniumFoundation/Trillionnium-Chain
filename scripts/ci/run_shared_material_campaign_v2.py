#!/usr/bin/env python3
"""Freeze and execute finite paired W1 observations on an existing model bundle.

This does not train or adopt a model. It retains all attempts, including one
declared exhaustion control. Local verifier replicas are not independent nodes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from bounded_process import ProcessFailure, run_bounded


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def write_new(path, value):
    with path.open('x') as output:
        json.dump(value, output, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')


def cases(repetitions):
    ordinary = [(target, arithmetic, preparation) for target in (0, 1)
                for arithmetic in ('full-limb', 'transposed') for preparation in ('dense', 'sparse')]
    result = []
    for repeat in range(repetitions):
        for target, arithmetic, preparation in ordinary[::1 if repeat % 2 == 0 else -1]:
            result.append(dict(name=f'paired-r{repeat}-t{target}-{arithmetic}-{preparation}',
                               target=target, arithmetic=arithmetic, preparation=preparation,
                               verifiers=1, cycles=1, max_attempts=4096, expected_exit=0))
    for target in (0, 1):
        for verifiers in (3, 8):
            result.append(dict(name=f'fanout-t{target}-v{verifiers}', target=target,
                               arithmetic='full-limb', preparation='sparse', verifiers=verifiers,
                               cycles=1, max_attempts=4096, expected_exit=0))
        result.append(dict(name=f'reuse-t{target}-cycles4', target=target, arithmetic='full-limb',
                           preparation='sparse', verifiers=1, cycles=4, max_attempts=4096, expected_exit=0))
    result.append(dict(name='bounded-search-exhaustion-control', target=1, arithmetic='full-limb',
                       preparation='sparse', verifiers=1, cycles=1, max_attempts=1, expected_exit=2))
    return result


def observed_outcome(directory, case, code, process_failure):
    """An arbitrary exit 2 must not masquerade as the planned exhaustion."""
    if process_failure is not None or code != case['expected_exit']:
        return 'unexpected_process_outcome'
    try:
        if code == 0:
            report = json.loads((directory / 'report.json').read_text())
            return ('complete' if report['status'] == 'complete' and
                    report['proof_backend_executed'] is True else 'unexpected_incomplete_report')
        failure = json.loads((directory / 'failure.json').read_text())
        if failure.get('error') != 'NATIVE_RUN_FAILED' or failure.get('status') != 'failed':
            return 'unexpected_failure_kind'
        states = failure['tile_states']
        failed = [row['index'] for row in states if row['state'] == 'process_finished_unaccepted']
        if len(failed) != 1:
            return 'unexpected_failed_tile_coverage'
        index = failed[0]
        if ([row['index'] for row in states] != list(range(5)) or
                any(row['state'] != ('completed' if row['index'] < index else
                                    'process_finished_unaccepted' if row['index'] == index else 'not_started')
                    for row in states)):
            return 'unexpected_failure_order'
        tile = directory / f'tile-{index}'
        process = json.loads((tile / 'process.json').read_text())
        records = [json.loads(line) for line in (tile / 'native.stdout.jsonl').read_bytes().splitlines()]
        if (process['returncode'] != 2 or [row['kind'] for row in records] !=
                ['material', 'setup', 'search', 'summary']):
            return 'unexpected_native_failure_sequence'
        header, _, search, summary = records
        if (header.get('max_attempts') != 1 or header.get('target_index') != case['target'] or
                search.get('status') != 'exhausted' or search.get('error') is not None or
                len(search['attempts']) != 1 or search['attempts'][0].get('nonce') != 0 or
                search['attempts'][0].get('target_hit') is not False or
                search['attempts'][0].get('proof_materialized') is not False or
                search['attempts'][0].get('error') is not None or
                summary.get('status') != 'failed' or summary.get('exhausted') != 1 or
                summary.get('winners') != 0 or summary.get('failed_searches') != 0 or
                summary.get('attempts') != 1 or summary.get('measurement_incomplete') != []):
            return 'unexpected_native_refusal'
        return 'expected_bounded_search_exhaustion'
    except (OSError, ValueError, KeyError, TypeError):
        return 'unreadable_outcome_evidence'


def run(args):
    if not 1 <= args.repetitions <= 10:
        raise ValueError('REPETITION_BOUND')
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('CLEAN_COMMITTED_SOURCE_REQUIRED')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runner = args.runner.resolve(strict=True)
    model = args.model_dir.resolve(strict=True)
    paths = [model / name for name in ('model.json', 'consumer.json', 'evaluation-bundle.json')]
    source = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
              'runner_sha256': digest(runner), 'inputs_sha256': {path.name: digest(path) for path in paths}}
    plan = {'schema': 'pon-shared-material-campaign-v2', 'source': source,
            'cases': cases(args.repetitions), 'bundle_hash': args.bundle_hash, 'seed': '8c' * 32,
            'baseline_repetitions': 100, 'replay_source_each_case': True,
            'consumer_timeout_seconds': 360, 'native_timeout_seconds_per_tile': 60,
            'negative_control_scope': 'one bounded-search exhaustion; not a relaxed service gate',
            'production_activation': False, 'model_training': False, 'model_adoption': False,
            'original_4s_16_hostile_gate_qualified': False,
            'hardware_scope': 'shared local host; no independent administrators or WAN'}
    write_new(out / 'plan.json', plan)
    observations = []
    with (out / 'journal.jsonl').open('x') as journal:
        def event(value):
            journal.write(json.dumps(value, sort_keys=True, allow_nan=False) + '\n')
            journal.flush()
            os.fsync(journal.fileno())

        for index, case in enumerate(plan['cases']):
            if (git('rev-parse', 'HEAD') != source['commit'] or
                    git('status', '--porcelain', '--untracked-files=normal') or
                    digest(runner) != source['runner_sha256'] or
                    any(digest(path) != source['inputs_sha256'][path.name] for path in paths)):
                event({'index': index, 'status': 'source_or_input_drift_refused'})
                raise ValueError('FROZEN_SOURCE_OR_INPUT_CHANGED')
            command = [sys.executable, str(ROOT / 'formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py'),
                       '--model', str(paths[0]), '--tasks', str(paths[1]),
                       '--evaluation-bundle', str(paths[2]), '--bundle-hash', args.bundle_hash,
                       '--replay-source', '--runner', str(runner), '--preparation', case['preparation'],
                       '--arithmetic', case['arithmetic'], '--verifiers', str(case['verifiers']),
                       '--target-index', str(case['target']), '--cycles', str(case['cycles']),
                       '--max-attempts', str(case['max_attempts']), '--seed', plan['seed'],
                       '--timeout', '60', '--baseline-repetitions', '100', '--out', str(out / case['name'])]
            event({'index': index, 'status': 'started', 'case': case, 'command': command})
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.perf_counter_ns()
            try:
                result = run_bounded(command, b'', timeout=360, stdout_limit=65536, stderr_limit=262144)
                stdout, stderr, code = result.stdout, result.stderr, result.returncode
                error = None
            except ProcessFailure as failure:
                stdout, stderr, code = failure.stdout, failure.stderr, failure.returncode
                error = str(failure)
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            observation = dict(index=index, name=case['name'], returncode=code,
                               expected_exit=case['expected_exit'], process_failure=error,
                               wall_ns=time.perf_counter_ns() - started,
                               child_user_cpu_ns=round((after.ru_utime - before.ru_utime) * 1e9),
                               child_system_cpu_ns=round((after.ru_stime - before.ru_stime) * 1e9),
                               cpu_scope='consumer process tree inclusive; overlaps per-tile and consumer clocks',
                               stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                               stderr_sha256=hashlib.sha256(stderr).hexdigest())
            observation['outcome_kind'] = observed_outcome(out / case['name'], case, code, error)
            (out / (case['name'] + '.stdout.txt')).write_bytes(stdout)
            (out / (case['name'] + '.stderr.txt')).write_bytes(stderr)
            observations.append(observation)
            write_new(out / (case['name'] + '.process.json'), observation)
            event({'index': index, 'status': 'finished', 'observation': observation})
    matched = all(row['outcome_kind'] == ('complete' if row['expected_exit'] == 0 else
                                         'expected_bounded_search_exhaustion') for row in observations)
    write_new(out / 'campaign.json', dict(schema=plan['schema'], source=source,
                                        planned_cases=len(plan['cases']), observations=observations,
                                        all_declared_outcomes_observed=matched,
                                        qualification=False, production_activation=False))
    return 0 if matched else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir', type=Path, required=True)
    parser.add_argument('--bundle-hash', required=True)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=3)
    raise SystemExit(run(parser.parse_args()))
