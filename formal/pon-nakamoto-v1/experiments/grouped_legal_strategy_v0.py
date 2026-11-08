"""Reproduce finite cheapest-known Cell strategy comparisons; never qualify PoW.

The retained real model/corpus is loaded through its existing bundle verifier.
Synthetic structured inputs and factorized models are separate, named controls.
All repeated rounds, rejected controls, preparation and independent verification
costs are retained. Output is create-only and records source identity and diff.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grouped_legal_strategy_v0 import (
    ARMS, CLASSES, DIM, EXPERTS, PROFILE, REPRESENTATION, canonical, observe, sha)
from contract_wire import ROOT
from experiments.shared_cell_operator_v1 import DEFAULT_MATERIAL, DEFAULT_BUNDLE, load_inputs

FORMAL = 'formal/pon-nakamoto-v1/'
OWNED_SOURCES = tuple(FORMAL + name for name in (
    'experiments/grouped_legal_strategy_v0.py', 'grouped_legal_strategy_v0.py',
    'test_grouped_legal_strategy_v0.py'))
# Include the lazy source-replay producer before load_inputs imports it, along
# with the local verification dependencies and configuration they load.
RELEVANT_SOURCES = OWNED_SOURCES + tuple(FORMAL + name for name in (
    'experiments/shared_cell_operator_v1.py', 'experiments/model_loop.py',
    'bounded_process.py', 'contract_wire.py', 'evaluation_bundle.py', 'evaluation.py',
    'model_contract.py', 'ledger.py', 'strict_signature.py', 'work_backend.py',
    'work_oracle.py')) + tuple('config/pon/' + name for name in (
        'ledger-v1.json', 'work-profile-v1.json', 'model-family-v1.json',
        'devnet-v1.json', 'evaluation-round-v1.json'))
CONTROL_RANKS = (1, 3, 8)
CONTROL_NAMES = ('dense_unique', 'bias_only', 'sparse_single_coordinate', 'repeated_input',
                 'rank_at_most_two_inputs', 'repeated_columns', 'extreme_inputs',
                 'repeated_input_separate_scopes')
NEGATIVE_CASES = (('invalid_zero_bias', 'INPUT_BIAS'), ('invalid_feature_range', 'INPUT_RANGE'))


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write('\n')


def source_identity(*, root=ROOT, sources=RELEVANT_SOURCES):
    root = Path(root)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    diff = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=root)
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True)
    tracked = subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root, text=True)
    manifest = {}
    for relative in sources:
        try:
            actual = (root / relative).read_bytes()
        except OSError:
            actual = None
        committed = subprocess.run(['git', 'show', head + ':' + relative], cwd=root,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        at_head = committed.returncode == 0
        manifest[relative] = {
            'actual_sha256': hashlib.sha256(actual).hexdigest() if actual is not None else None,
            'actual_bytes': len(actual) if actual is not None else None,
            'tracked_at_head': at_head,
            'head_sha256': hashlib.sha256(committed.stdout).hexdigest() if at_head else None,
            'matches_head_bytes': at_head and actual is not None and actual == committed.stdout}
    return {'commit': head, 'working_tree_status': status, 'tracked_diff_sha256': hashlib.sha256(diff).hexdigest(),
            'clean': status == '', 'tracked_tree_status': tracked, 'tracked_tree_clean': tracked == '',
            'relevant_sources': manifest,
            'relevant_sources_sha256': {path: item['actual_sha256'] for path, item in manifest.items()},
            'owned_sources_sha256': {path: manifest[path]['actual_sha256']
                                     for path in OWNED_SOURCES if path in manifest}}


def source_gate_failures(snapshot, expected_sha):
    if expected_sha is None:
        return []
    failures = []
    if re.fullmatch(r'[0-9a-f]{40}', expected_sha) is None:
        failures.append({'reason': 'EXPECTED_SOURCE_SHA_FORMAT'})
    if snapshot['commit'] != expected_sha:
        failures.append({'reason': 'SOURCE_SHA_MISMATCH'})
    if not snapshot['tracked_tree_clean']:
        failures.append({'reason': 'TRACKED_TREE_DIRTY'})
    for path, item in snapshot['relevant_sources'].items():
        if not item['tracked_at_head']:
            failures.append({'reason': 'RELEVANT_SOURCE_NOT_IN_HEAD', 'path': path})
        elif not item['matches_head_bytes']:
            failures.append({'reason': 'RELEVANT_SOURCE_BYTES_DIFFER', 'path': path})
    return failures


def campaign_plan(args):
    schedule = []

    def add(case, arm, *, rank=None, requests=None, expected='verified', error=None):
        schedule.append({'observation_id': f'observation-{len(schedule):03d}', 'case': case,
                         'rank': rank, 'arm': arm, 'requests_per_round': requests or args.batch_size,
                         'planned_rounds': args.rounds, 'round_indices': list(range(args.rounds)),
                         'expected_status': expected, 'expected_error': error})

    for arm in ARMS[:-1]:
        add('retained_consumer', arm)
    for rank in CONTROL_RANKS:
        for name in CONTROL_NAMES:
            for arm in ARMS:
                add(name, arm, rank=rank)
    for name, expected in NEGATIVE_CASES:
        add(name, 'direct_cached_merged', requests=1, expected='rejected', error=expected)
    return {'schema': 'pon-grouped-legal-strategy-plan-v0', 'profile': PROFILE,
            'observations': schedule, 'planned_observations': len(schedule),
            'planned_rounds': sum(row['planned_rounds'] for row in schedule),
            'selection': {'model': str(args.model), 'tasks': str(args.tasks),
                          'evaluation_bundle': str(args.evaluation_bundle), 'bundle_hash': args.bundle_hash,
                          'partition': args.partition, 'offset': args.offset, 'batch_size': args.batch_size,
                          'replay_source': args.replay_source},
            'rounds_are_fixed_request_replays': True, 'adaptive_selection': False,
            'chainwork_awarded': 0, 'pow_qualified': False}


def plan_row(plan, case, arm, rank=None):
    return next(row for row in plan['observations']
                if (row['case'], row['arm'], row['rank']) == (case, arm, rank))


def account_plan(plan, observations, not_started):
    expected = {row['observation_id']: row for row in plan['observations']}
    seen, errors = set(), []
    for record in observations + not_started:
        key = record['observation_id']
        if key not in expected or key in seen:
            errors.append({'reason': 'UNKNOWN_OR_DUPLICATE_OBSERVATION', 'observation_id': key})
            continue
        seen.add(key)
        spec = expected[key]
        if record.get('status') == 'not_started':
            indices = record['round_indices']
        else:
            indices = [a['round'] for a in record['attempts'] + record['not_started']]
        if record['planned_rounds'] != spec['planned_rounds'] or sorted(indices) != spec['round_indices']:
            errors.append({'reason': 'ROUND_DISPOSITION_MISMATCH', 'observation_id': key})
    for key in sorted(set(expected) - seen):
        errors.append({'reason': 'MISSING_OBSERVATION', 'observation_id': key})
    attempted = sum(len(o['attempts']) for o in observations)
    skipped = sum(len(o['not_started']) for o in observations) + sum(o['planned_rounds'] for o in not_started)
    if attempted + skipped != plan['planned_rounds']:
        errors.append({'reason': 'PLANNED_ROUND_DENOMINATOR_MISMATCH'})
    return {'planned_observations': plan['planned_observations'], 'planned_rounds': plan['planned_rounds'],
            'actual_attempts': attempted, 'not_started_rounds': skipped,
            'verified_attempts': sum(a['status'] == 'verified' for o in observations for a in o['attempts']),
            'rejected_attempts': sum(a['status'] == 'rejected' for o in observations for a in o['attempts']),
            'preparation_failures': sum(a['stage'] == 'preparation' for o in observations for a in o['attempts']),
            'round_accounting_complete': not errors, 'round_accounting_errors': errors,
            'instrumented_counts_complete': not not_started and
                all(o['instrumented_counts_complete'] for o in observations)}


def controlled_model(rank):
    model = {'fixture': 'controlled-factor-model-no-training-no-demand', 'numeric_profile': PROFILE,
             'base': [[((r * 7 + k * 11) % 13) - 6 for k in range(DIM)] for r in range(CLASSES)],
             'router': [[((e * 5 + k * 3) % 11) - 5 for k in range(DIM)] for e in range(EXPERTS)],
             'deltas': []}
    factors = []
    for e in range(EXPERTS):
        up = [[((r + j + e) % 5) - 2 for j in range(rank)] for r in range(CLASSES)]
        down = [[((k + j * 3 + e) % 5) - 2 for k in range(DIM)] for j in range(rank)]
        factors.append({'up': up, 'down': down})
        model['deltas'].append([[sum(up[r][j] * down[j][k] for j in range(rank))
                                 for k in range(DIM)] for r in range(CLASSES)])
    return model, factors


def controlled_vectors(name, count):
    dense = [[int(value) % 17 - 8 for value in hashlib.shake_256(
        f'pon-legal-input-fixture-v0/{i}'.encode()).digest(256)] + [8] for i in range(count)]
    if name == 'dense_unique':
        return dense
    if name == 'bias_only':
        return [[0] * 256 + [8] for _ in range(count)]
    if name == 'sparse_single_coordinate':
        result = []
        for i in range(count):
            row = [0] * 256 + [8]
            row[i % 256] = 8 if i % 2 else -8
            result.append(row)
        return result
    if name in ('repeated_input', 'repeated_input_separate_scopes'):
        return [list(dense[0]) for _ in range(count)]
    if name == 'rank_at_most_two_inputs':
        return [[((k % 3) - 1) + ((i % 5) - 2) * ((k % 2) * 2 - 1)
                 for k in range(256)] + [8] for i in range(count)]
    if name == 'repeated_columns':
        return [[((i % 5) - 2)] * 256 + [8] for i in range(count)]
    if name == 'extreme_inputs':
        return [[8 if ((k + i) % 3) else -8 for k in range(256)] + [8]
                for i in range(count)]
    raise ValueError('UNKNOWN_CONTROL')


def envelope(vectors, *, label, generation, scope):
    return [{'id': sha({'control': label, 'index': i}), 'scope': scope,
             'generation': generation, 'representation': REPRESENTATION, 'x': list(x)}
            for i, x in enumerate(vectors)]


def compact(observation):
    verified = [a for a in observation['attempts'] if a['status'] == 'verified']
    return {'arm': observation['arm'], 'verified_rounds': len(verified),
            'planned_rounds': observation['planned_rounds'],
            'attempted_rounds': observation['attempted_rounds'],
            'not_started_rounds': observation['not_started_rounds'],
            'round_accounting_complete': observation['round_accounting_complete'],
            'instrumented_counts_complete': observation['instrumented_counts_complete'],
            'preparation_cost': observation['preparation'].get('cost'),
            'first_round_cost': verified[0]['cost'] if verified else None,
            'warm_round_cost': verified[-1]['cost'] if len(verified) > 1 else None,
            'total_cost': observation['total_cost'],
            'known_completed_stage_cost': observation['known_completed_stage_cost'],
            'whole_observation_wall_ns': observation['whole_observation_wall_ns'],
            'whole_observation_cpu_ns': observation['whole_observation_cpu_ns'],
            'arithmetic_semantics_verified': observation['arithmetic_semantics_verified']}


def run_observations(args, out, plan):
    cases, failures, not_started = [], [], []
    real = {'status': 'started', 'kind': 'retained_trained_model_and_frozen_consumer_corpus'}
    observations = []
    # A failed real-source replay is preserved and cannot be replaced by controls.
    try:
        load_start = time.perf_counter_ns()
        model, original_rows, provenance = load_inputs(
            args.model, args.tasks, args.evaluation_bundle, args.bundle_hash,
            args.partition, args.offset, args.batch_size, replay_source=args.replay_source)
        real.update(status='loaded', provenance=provenance,
                    load_and_optional_source_replay_wall_ns=time.perf_counter_ns() - load_start)
        rows = envelope([r['x'] for r in original_rows], label='retained-consumer',
                        generation=provenance['model_artifact'], scope=provenance['scope'])
        for row, original in zip(rows, original_rows):
            row['id'] = original['id']
        arms = []
        for arm in ARMS[:-1]:
            record = observe(model, rows, arm=arm, rounds=args.rounds)
            record.update(case='retained_consumer', input_kind='retained_frozen_consumer_features',
                          observation_id=plan_row(plan, 'retained_consumer', arm)['observation_id'])
            observations.append(record)
            arms.append(compact(record))
        real.update(status='verified' if all(a['arithmetic_semantics_verified'] for a in arms) else 'failed',
                    arms=arms, source_manifest=provenance['selected_tasks'],
                    model_raw_file_sha256=hashlib.sha256(args.model.read_bytes()).hexdigest(),
                    model_raw_file_bytes=args.model.stat().st_size,
                    input_sha256=sha(rows), real_arrival_trace=None, authenticated_new_demand=False,
                    receipt_envelope_kind='declared arithmetic-only test scope/generation; not current owner authority')
        if real['status'] != 'verified':
            failures.append({'case': 'retained_consumer', 'reason': 'SEMANTIC_CHECK_FAILED'})
    except Exception as error:
        observed_ids = {record['observation_id'] for record in observations}
        not_started.extend(dict(spec, status='not_started', reason='REAL_SOURCE_LOAD_FAILED', cost=None)
                           for spec in plan['observations']
                           if spec['case'] == 'retained_consumer' and spec['observation_id'] not in observed_ids)
        real.update(status='failed', error_type=type(error).__name__, error=str(error))
        failures.append({'case': 'retained_consumer', 'reason': str(error)})
    write_json(out / 'retained-corpus.json', real)
    for rank in CONTROL_RANKS:
        model, factors = controlled_model(rank)
        write_json(out / f'controlled-model-rank-{rank}.json', {'model': model, 'factors': factors})
        for name in CONTROL_NAMES:
            rows = envelope(controlled_vectors(name, args.batch_size), label=name,
                            generation=sha(model), scope='controlled-public-fixture-no-demand')
            if name == 'repeated_input_separate_scopes':
                for i, row in enumerate(rows):
                    row['scope'] = f'controlled-fixture-owner-{i % 4}'
            case = {'name': name, 'rank': rank, 'input_kind': 'controlled_synthetic_not_corpus_or_demand',
                    'model_sha256': sha(model), 'input_sha256': sha(rows),
                    'requests': args.batch_size, 'unique_arithmetic_inputs': len({tuple(r['x']) for r in rows}),
                    'arms': []}
            for arm in ARMS:
                record = observe(model, rows, arm=arm, factors=factors, rounds=args.rounds)
                record.update(case=name, rank=rank, input_kind=case['input_kind'],
                              observation_id=plan_row(plan, name, arm, rank)['observation_id'])
                observations.append(record)
                case['arms'].append(compact(record))
                if not record['arithmetic_semantics_verified']:
                    failures.append({'case': name, 'rank': rank, 'arm': arm, 'reason': 'SEMANTIC_CHECK_FAILED'})
            cases.append(case)
    # Deliberate invalid controls: preserve every rejection in the same ledger.
    negatives = []
    model, factors = controlled_model(1)
    for name, expected in NEGATIVE_CASES:
        feature = [0] * DIM if name == 'invalid_zero_bias' else [9] + [0] * 255 + [8]
        rows = envelope([feature], label=name, generation=sha(model), scope='negative-control')
        record = observe(model, rows, arm='direct_cached_merged', rounds=args.rounds)
        record.update(case=name, input_kind='intentional_out_of_profile_negative',
                      observation_id=plan_row(plan, name, 'direct_cached_merged')['observation_id'])
        observations.append(record)
        matched = (len(record['attempts']) == args.rounds and not record['not_started'] and
                   all(a.get('error') == expected and a['status'] == 'rejected' for a in record['attempts']))
        negatives.append({'name': name, 'expected_error': expected, 'matched': matched,
                          'attempted_rounds': len(record['attempts'])})
        if not matched:
            failures.append({'case': name, 'reason': 'EXPECTED_REJECTION_MISSING'})
    return real, cases, negatives, observations, failures, not_started


def run(args):
    start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = source_identity()
    write_json(out / 'request.json', {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()})
    write_json(out / 'source-before.json', before)
    plan = campaign_plan(args)
    write_json(out / 'plan.json', plan)
    plan_sha256 = hashlib.sha256((out / 'plan.json').read_bytes()).hexdigest()
    before_gate = source_gate_failures(before, args.source_sha)
    if before_gate:
        failures = [dict(failure, case='source_identity', stage='before') for failure in before_gate]
        not_started = [dict(spec, status='not_started', reason='SOURCE_BEFORE_GATE_FAILED', cost=None)
                       for spec in plan['observations']]
        observations, cases, negatives = [], [], []
        real = {'status': 'not_started', 'reason': 'SOURCE_BEFORE_GATE_FAILED'}
        write_json(out / 'retained-corpus.json', real)
    else:
        real, cases, negatives, observations, failures, not_started = run_observations(args, out, plan)
    with (out / 'attempts.ndjson').open('x', encoding='utf-8') as handle:
        for record in observations:
            handle.write(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
    after = source_identity()
    write_json(out / 'source-after.json', after)
    after_gate = source_gate_failures(after, args.source_sha)
    failures.extend(dict(failure, case='source_identity', stage='after') for failure in after_gate)
    source_stable = (before['relevant_sources_sha256'] == after['relevant_sources_sha256'] and
                     before['commit'] == after['commit'])
    if not source_stable:
        failures.append({'case': 'source_identity', 'reason': 'SOURCE_CHANGED_DURING_RUN'})
    if hashlib.sha256((out / 'plan.json').read_bytes()).hexdigest() != plan_sha256:
        failures.append({'case': 'plan', 'reason': 'PREREGISTERED_PLAN_CHANGED'})
    accounting = account_plan(plan, observations, not_started)
    failures.extend(dict(error, case='round_accounting') for error in accounting['round_accounting_errors'])
    report = {'schema': 'pon-grouped-legal-strategy-campaign-v0', 'profile': PROFILE,
              'status': 'complete_research_hold' if not failures else 'failed_research_hold',
              'measurement_mode': 'final_exact_source' if args.source_sha else 'development_unqualified',
              'expected_source_sha': args.source_sha,
              'exact_committed_source_verified': bool(args.source_sha) and not before_gate and
                  not after_gate and source_stable,
              'source_before': before, 'source_after': after,
              'preregistered_plan_sha256': plan_sha256, 'preregistered_plan_file': 'plan.json',
              'environment': {'python': sys.version, 'platform': platform.platform(),
                              'machine': platform.machine(), 'numpy': importlib.metadata.version('numpy'),
                              'cryptography': importlib.metadata.version('cryptography'), 'gpu_used': False},
              'retained_corpus': real, 'controlled_cases': cases, 'negative_controls': negatives,
              'failures': failures, 'observations': len(observations),
              'not_started_observations': not_started,
              **accounting,
              'attempts_sha256': hashlib.sha256((out / 'attempts.ndjson').read_bytes()).hexdigest(),
              'wall_ns_before_final_report': time.perf_counter_ns() - start_wall,
              'cpu_ns_before_final_report': time.process_time_ns() - start_cpu,
              'interpretation': [
                  'Measured finite implemented algorithms; no minimum attacker-cost or hardware bound is proved.',
                  'Dense positions are a statement convention, not required operations or earned chainwork.',
                  'All arithmetic is exact integer with bias8; no float tolerance or reassociation profile is substituted.',
                  'Every factor arm verifies all BA coordinates equal the same delta before execution.',
                  'Factor cost includes router and base; cached merged weights remain a legitimate competitor.',
                  'Arithmetic cache misses bind exact model/input/scope/generation/representation; receipt/authority reuse is not granted.',
                  'All rounds reuse a fixed batch; repeated timings are neither independent demand nor new lottery queries.',
                  'Python full observations include preparation, validation, computation, reference and hashing; they are not GPU/native timing claims.',
                  'Failures retain wall/CPU observations; unknown counts are null, known completed-stage counters are separate.',
                  'A rejected preparation occupies round zero; remaining planned rounds are retained as not started.',
                  'The fixed case/arm/round plan is written before input loading and execution.',
                  'Without --source-sha this is explicitly unqualified development evidence, even if all arithmetic checks pass.'],
              'full_lottery_cost_measured': False, 'minimum_legal_cost_proved': False,
              'pow_qualified': False, 'production_activation': False, 'chainwork_awarded': 0}
    write_json(out / 'report.json', report)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--model', type=Path, default=DEFAULT_MATERIAL / 'model.json')
    p.add_argument('--tasks', type=Path, default=DEFAULT_MATERIAL / 'consumer.json')
    p.add_argument('--evaluation-bundle', type=Path, default=DEFAULT_MATERIAL / 'evaluation-bundle.json')
    p.add_argument('--bundle-hash', default=DEFAULT_BUNDLE)
    p.add_argument('--partition', default='consumer')
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--batch-size', type=int, default=16, choices=range(1, 65))
    p.add_argument('--rounds', type=int, default=3, choices=range(1, 65))
    p.add_argument('--replay-source', action='store_true')
    p.add_argument('--source-sha', help='Final mode: require this full HEAD and clean tracked source before and after.')
    return p


if __name__ == '__main__':
    result = run(parser().parse_args())
    print(json.dumps({key: result[key] for key in ('status', 'observations', 'actual_attempts',
                                                 'verified_attempts', 'rejected_attempts', 'failures')}))
    raise SystemExit(0 if not result['failures'] else 1)
