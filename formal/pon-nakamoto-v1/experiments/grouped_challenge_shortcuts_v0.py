"""Preregistered exact challenge-transform counterexamples; research HOLD only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grouped_challenge_shortcuts_v0 import BATCH, INTERNAL_INPUT_BOUNDS, PROFILE, PreparedProbe, verify
from grouped_legal_strategy_v0 import REPRESENTATION, canonical, sha
from experiments.grouped_legal_strategy_v0 import RELEVANT_SOURCES, source_gate_failures, source_identity, write_json
from experiments.shared_cell_operator_v1 import DEFAULT_BUNDLE, DEFAULT_MATERIAL, load_inputs

OWNED = tuple('formal/pon-nakamoto-v1/' + name for name in (
    'grouped_challenge_shortcuts_v0.py', 'test_grouped_challenge_shortcuts_v0.py',
    'experiments/grouped_challenge_shortcuts_v0.py'))
CASES = (('real_rank1', 'rank1_blinded', ('direct', 'cached')),
         ('real_mixing', 'batch_mix', ('direct', 'cached')),
         ('real_dropout', 'dropout', ('dense', 'sparse', 'lut')),
         ('controlled_dense_dropout', 'dropout', ('dense', 'sparse', 'lut')),
         ('controlled_zero_rank1', 'rank1_blinded', ('direct', 'cached', 'zero_skip')))


def plan_for(rounds):
    return [{'id': name + '/' + arm, 'case': name, 'kind': kind, 'producer': arm,
             'rounds': rounds, 'challenges': [hashlib.sha256(
                 f'{PROFILE}/{name}/{i}'.encode()).hexdigest() for i in range(rounds)]}
            for name, kind, arms in CASES for arm in arms]


def material(model, original, provenance, case):
    chosen = model
    rows = [{'id': row['id'], 'scope': provenance['scope'], 'generation': provenance['model_artifact'],
             'representation': REPRESENTATION, 'x': list(row['x'])} for row in original]
    if case == 'controlled_dense_dropout':
        for i, row in enumerate(rows):
            raw = hashlib.shake_256(f'controlled-dense-input/{i}'.encode()).digest(256)
            row.update(id=sha({'controlled_dense': i}), scope='controlled-no-authenticated-demand',
                       x=[(1 if b & 8 else -1) * (1 + b % 8) for b in raw] + [8])
    if case == 'controlled_zero_rank1':
        zero = [[0] * 257 for _ in range(3)]
        chosen = {'fixture': 'controlled-zero-not-retained-trained-model', 'base': zero,
                  'router': copy.deepcopy(zero), 'deltas': [copy.deepcopy(zero) for _ in range(3)]}
        for row in rows:
            row.update(scope='controlled-no-authenticated-demand', generation=sha(chosen))
    return chosen, rows


def observe(model, rows, spec):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    result = {'id': spec['id'], 'case': spec['case'], 'kind': spec['kind'], 'producer': spec['producer'],
              'model_sha256': sha(model), 'requests_sha256': sha(rows), 'planned_rounds': spec['rounds'],
              'preparation': {}, 'attempts': [], 'not_started': []}
    try:
        start = time.perf_counter_ns()
        prepared = PreparedProbe(model, rows, spec['kind'], spec['producer'])
        result['preparation'] = {'wall_ns': time.perf_counter_ns() - start, 'cost': prepared.preparation,
                                 'table_payload_bytes': prepared.preparation['table_entries'] * 8,
                                 'table_scope_keys': len(prepared.tables), 'paid_once': True}
    except Exception as error:
        result['attempts'].append({'round': 0, 'status': 'rejected', 'stage': 'preparation',
                                   'error': str(error), 'cost': None, 'wall_ns': time.perf_counter_ns() - wall})
        result['not_started'] = list(range(1, spec['rounds']))
        prepared = None
    if prepared is not None:
        for i, challenge_hex in enumerate(spec['challenges']):
            start, start_cpu = time.perf_counter_ns(), time.process_time_ns()
            row = {'round': i, 'challenge': challenge_hex, 'status': 'started', 'stage': 'producer',
                   'query_cost': None, 'reference_cost': None}
            try:
                challenge = bytes.fromhex(challenge_hex)
                claim, counts = prepared.produce(challenge)
                row.update(query_cost=counts, producer_wall_ns=time.perf_counter_ns() - start,
                           stage='independent_reference')
                reference_start = time.perf_counter_ns()
                reference, maximum = verify(model, rows, spec['kind'], challenge, claim)
                row.update(reference_cost=reference, maximum_internal_input_abs=maximum,
                           verification_wall_ns=time.perf_counter_ns() - reference_start,
                           stage='serialization_and_hash')
                row.update(numerical_statement_sha256=sha(claim), business_sha256=sha(claim['business']),
                           auxiliary_sha256=sha(claim['auxiliary']),
                           auxiliary_routes_sha256=sha(claim['auxiliary'].get('routes', claim['business']['routes'])),
                           canonical_bytes=len(canonical(claim)), status='verified', stage='complete')
                if 'first_claim' not in result:
                    result['first_claim'] = claim
            except Exception as error:
                row.update(status='rejected', error_type=type(error).__name__, error=str(error),
                           unknown_partial_counts=True)
            row.update(wall_ns=time.perf_counter_ns() - start, cpu_ns=time.process_time_ns() - start_cpu)
            result['attempts'].append(row)
    passed = [a for a in result['attempts'] if a['status'] == 'verified']
    result.update(whole_wall_ns=time.perf_counter_ns() - wall, whole_cpu_ns=time.process_time_ns() - cpu,
                  distinct_business_outputs=len({a['business_sha256'] for a in passed}),
                  distinct_auxiliary_outputs=len({a['auxiliary_sha256'] for a in passed}),
                  distinct_auxiliary_routes=len({a['auxiliary_routes_sha256'] for a in passed}),
                  all_verified=len(passed) == spec['rounds'])
    return result


def run(args):
    wall = time.perf_counter_ns()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = source_identity(sources=RELEVANT_SOURCES + OWNED)
    plan = plan_for(args.rounds)
    write_json(out / 'request.json', {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()})
    write_json(out / 'plan.json', {'schema': 'pon-challenge-shortcuts-plan-v0', 'profile': PROFILE,
                                 'observations': plan, 'internal_input_bounds': INTERNAL_INPUT_BOUNDS,
                                 'original_input_contract': 'fixed batch16, signed [-8,8], bias8 unchanged',
                                 'auxiliary_scope': 'separate exact research probes, not replacement user inputs',
                                 'rounds_are_replayed_requests': True})
    plan_hash = hashlib.sha256((out / 'plan.json').read_bytes()).hexdigest()
    failures = [dict(row, stage='source_before') for row in source_gate_failures(before, args.source_sha)]
    observations, not_started, provenance = [], [], None
    if not failures:
        try:
            model, original, provenance = load_inputs(args.model, args.tasks, args.evaluation_bundle,
                args.bundle_hash, 'consumer', 0, BATCH, replay_source=args.replay_source)
        except Exception as error:
            failures.append({'stage': 'input_load', 'error_type': type(error).__name__, 'reason': str(error)})
    if failures:
        not_started = [{'id': s['id'], 'rounds': s['rounds'], 'reason': 'PRECONDITION_FAILED', 'cost': None}
                       for s in plan]
    else:
        for spec in plan:
            chosen, rows = material(model, original, provenance, spec['case'])
            record = observe(chosen, rows, spec)
            observations.append(record)
            if not record['all_verified']:
                failures.append({'stage': 'observation', 'id': spec['id'], 'reason': 'REFERENCE_OR_PREPARATION_FAILED'})
    with (out / 'attempts.ndjson').open('x') as handle:
        for record in observations:
            handle.write(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
    after = source_identity(sources=RELEVANT_SOURCES + OWNED)
    failures.extend(dict(row, stage='source_after') for row in source_gate_failures(after, args.source_sha))
    stable = before['commit'] == after['commit'] and before['relevant_sources_sha256'] == after['relevant_sources_sha256']
    if not stable:
        failures.append({'stage': 'source', 'reason': 'SOURCE_CHANGED'})
    if hashlib.sha256((out / 'plan.json').read_bytes()).hexdigest() != plan_hash:
        failures.append({'stage': 'plan', 'reason': 'PLAN_CHANGED'})
    planned = sum(s['rounds'] for s in plan)
    attempted = sum(len(o['attempts']) for o in observations)
    skipped = sum(len(o['not_started']) for o in observations) + sum(o['rounds'] for o in not_started)
    complete = (planned == attempted + skipped and
                {o['id'] for o in observations + not_started} == {s['id'] for s in plan} and
                all(sorted([a['round'] for a in o['attempts']] + o['not_started']) ==
                    list(range(o['planned_rounds'])) for o in observations))
    if not complete:
        failures.append({'stage': 'accounting', 'reason': 'ROUND_DISPOSITION_MISMATCH'})
    report = {'schema': 'pon-challenge-shortcuts-campaign-v0', 'profile': PROFILE,
              'status': 'complete_research_hold' if not failures else 'failed_research_hold',
              'measurement_mode': 'final_exact_source' if args.source_sha else 'development_unqualified',
              'expected_source_sha': args.source_sha, 'source_before': before, 'source_after': after,
              'exact_committed_source_verified': bool(args.source_sha) and stable and
                  not source_gate_failures(before, args.source_sha) and not source_gate_failures(after, args.source_sha),
              'preregistered_plan_sha256': plan_hash, 'provenance': provenance,
              'observations': observations, 'not_started_observations': not_started,
              'planned_rounds': planned, 'actual_attempts': attempted, 'not_started_rounds': skipped,
              'verified_attempts': sum(a['status'] == 'verified' for o in observations for a in o['attempts']),
              'round_accounting_complete': complete, 'failures': failures,
              'wall_ns_before_final_report': time.perf_counter_ns() - wall,
              'attempts_sha256': hashlib.sha256((out / 'attempts.ndjson').read_bytes()).hexdigest(),
              'counter_scope': 'Explicit MAC/add/scan/LUT/expansion counters only; all other Python allocation, validation, hashing and copying remain in wall/CPU observations.',
              'interpretation': ['Original business output is independently checked every round and never changed by the auxiliary probe.',
                  'Rank-one blinding permits cached useful outputs plus challenge response vectors.',
                  'Full-rank batch mixing permits cached projections of every expert, including changed routing.',
                  'Finite dropout masks permit lawful scoped block lookup tables; preparation and table bytes remain charged.',
                  'Zero-operator control is a separate chosen model, not a replacement for the pinned real model.',
                  'These finite implementations give no lower bound or globally cheapest algorithm; no proof/ticket is implemented.'],
              'minimum_fresh_neural_cost_proved': False, 'full_lottery_cost_measured': False,
              'pow_qualified': False, 'production_activation': False, 'chainwork_awarded': 0}
    write_json(out / 'report.json', report)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--model', type=Path, default=DEFAULT_MATERIAL / 'model.json')
    p.add_argument('--tasks', type=Path, default=DEFAULT_MATERIAL / 'consumer.json')
    p.add_argument('--evaluation-bundle', type=Path, default=DEFAULT_MATERIAL / 'evaluation-bundle.json')
    p.add_argument('--bundle-hash', default=DEFAULT_BUNDLE)
    p.add_argument('--rounds', type=int, default=16, choices=range(1, 33))
    p.add_argument('--replay-source', action='store_true')
    p.add_argument('--source-sha')
    return p


if __name__ == '__main__':
    result = run(parser().parse_args())
    print(json.dumps({key: result[key] for key in ('status', 'planned_rounds', 'actual_attempts', 'verified_attempts', 'failures')}))
    raise SystemExit(0 if result['status'] == 'complete_research_hold' else 1)
