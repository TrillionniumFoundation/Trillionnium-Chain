#!/usr/bin/env python3
"""Strict all-attempt accounting for the opt-in native W1 cost experiment.

This checks recorded observations, not clock honesty or native execution. Its
fixed-budget prefixes concern named measured components, not a lower bound or
live-chain Gamma. Native admission, fork choice and reward are never inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from contract_wire import H, unique

SCHEMA = 'pon-work-expensive-native-v1'
ARMS = ['lazy-full-limb', 'prepared-generic', 'prepared-structured',
        'tiled-classical', 'tiled-strassen-one-level', 'paired-product',
        'blocked-zero', 'blocked-zero-integer-paired', 'blocked-one-zero-rank-one',
        'maintenance-periodic', 'maintenance-integer-paired', 'maintenance-prefix',
        'maintenance-limb', 'scalar-original']
CLASSES = ['periodic-dense-fixture', 'full-rank-field', 'zero', 'identity',
           'rank-one', 'sparse-diagonal', 'continuity-maintenance-v1',
           'left-zero-right-rank-one', 'right-zero-left-rank-one']
MAX_BYTES = 256 * 1024 * 1024
MAX_LINE = 256 * 1024
Q = 4294967291


def require(ok, code):
    if not ok:
        raise ValueError(code)


def integer(value, code, maximum=2**64-1):
    require(type(value) is int and 0 <= value <= maximum, code)
    return value


def hexbytes(value, length=32):
    require(type(value) is str and len(value) == 2 * length and
            all(c in '0123456789abcdef' for c in value), 'CANONICAL_HEX')
    return bytes.fromhex(value)


def timing(value):
    require(type(value) is dict and set(value) == {'cpu_ns', 'wall_ns'}, 'TIMING_KEYS')
    return {k: integer(value[k], 'TIMING_VALUE') for k in ('cpu_ns', 'wall_ns')}


def plus(a, b):
    return {k: integer(a[k] + b[k], 'TIMING_OVERFLOW') for k in a}


def zero():
    return dict(cpu_ns=0, wall_ns=0)


def reject_number(_):
    raise ValueError('NONINTEGER_JSON_NUMBER')


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES and raw.endswith(b'\n'),
            'TRUNCATED_OR_OVERSIZED_STREAM')
    lines = raw.splitlines()
    require(all(0 < len(line) <= MAX_LINE for line in lines), 'LINE_BOUND')
    rows = [json.loads(line, object_pairs_hook=unique, parse_float=reject_number,
                       parse_constant=reject_number) for line in lines]
    require(all(type(row) is dict and row.get('schema') == SCHEMA for row in rows), 'SCHEMA')
    return rows


def inspect(raw, budgets=(1_000_000, 5_000_000, 20_000_000), calibration_samples=2):
    """Replay the exact row schedule, phase sums, identities and every miss."""
    rows = decode(raw)
    cursor = 0

    def take(kind, context=None):
        nonlocal cursor
        require(cursor < len(rows), 'MISSING_' + kind.upper())
        row = rows[cursor]
        cursor += 1
        require(row.get('kind') == kind, 'ROW_ORDER_' + kind.upper())
        if context:
            require(all(type(row.get(k)) is type(v) and row[k] == v
                        for k, v in context.items()), 'ROW_CONTEXT')
        return row

    header = take('run')
    attempts = integer(header.get('attempts_per_arm'), 'ATTEMPT_LIMIT', 1024)
    samples = integer(header.get('samples'), 'SAMPLE_LIMIT', 16)
    reuse = integer(header.get('reuse_attempts'), 'REUSE_LIMIT', 1024)
    require(min(attempts, samples, reuse) >= 1, 'POSITIVE_COUNTS')
    require(header.get('profile') == 'pon-matmul-transcript-64-v1' and
            header.get('arms') == ARMS and header.get('production_activation') is False and
            header.get('challenge_domain') == 'pon-work-expensive-challenge-v1' and
            header.get('work_domain') == 'pon-work-expensive-work-v2' and
            integer(header.get('work_identity_revision'), 'WORK_REVISION') == 2 and
            header.get('work_identity_fields') == ['challenge', 'task', 'target'] and
            header.get('target_shared_challenge_stream') is True and
            header.get('challenge_is_native_header') is False, 'PROFILE_BINDING')
    target_index = integer(header.get('target_index'), 'TARGET_INDEX', 1)
    target = bytes([127 if target_index == 0 else 7]) + bytes([255]) * 31
    require(hexbytes(header.get('target')) == target, 'TARGET_BINDING')
    seed = hexbytes(header.get('seed'))
    class_count = integer(header.get('class_count'), 'CLASS_COUNT', 9)
    require(class_count in (1, 9), 'CLASS_COUNT')
    classes = ['supplied-material'] if class_count == 1 else CLASSES
    acquisition = timing(header.get('material_creation_timing'))
    require(type(calibration_samples) is int and 0 <= calibration_samples < samples,
            'CALIBRATION_SPLIT')
    budgets = list(budgets)
    require(budgets and len(budgets) <= 16 and len(set(budgets)) == len(budgets) and
            all(type(b) is int and 0 < b < 2**64 for b in budgets), 'BUDGETS')
    counters = dict(completed_cells=0, unsupported_cells=0, failed_cells=0,
                    attempts=0, hits=0, verified_hits=0)
    cells, material_rows = [], []
    reference_stream = {}
    unique_accepted = set()
    for name in classes:
        material = take('material', {'class': name})
        a, b = hexbytes(material.get('a_hex'), 16384), hexbytes(material.get('b_hex'), 16384)
        av, bv = struct.unpack('<4096I', a), struct.unpack('<4096I', b)
        require(max(av + bv) < Q, 'MATERIAL_FIELD')
        task = H('task', a, b)
        require(hexbytes(material.get('task')) == task and
                material.get('a_sha256') == hashlib.sha256(a).hexdigest() and
                material.get('b_sha256') == hashlib.sha256(b).hexdigest(), 'MATERIAL_HASH')
        require(integer(material.get('nonzero_a'), 'NONZERO_A', 4096) == sum(x != 0 for x in av)
                and integer(material.get('nonzero_b'), 'NONZERO_B', 4096) == sum(x != 0 for x in bv),
                'MATERIAL_NONZERO')
        material_rows.append({'class': name, 'task': task.hex(),
                              'a_sha256': material['a_sha256'], 'b_sha256': material['b_sha256'],
                              'identity_timing': timing(material.get('identity_timing'))})
        for sample in range(samples):
            for offset in range(len(ARMS)):
                arm = ARMS[(offset + sample) % len(ARMS)]
                context = {'class': name, 'sample': sample, 'arm': arm}
                phase = {key: zero() for key in ('setup', 'attempt', 'cleanup', 'teardown', 'verification')}
                index = setups = hits = verified = unsupported = errors = 0
                accepted_rows, lifetimes, trace_sequence, boundaries = [], [], [], []
                previous_observed = zero()

                def producer():
                    value = zero()
                    for key in ('setup', 'attempt', 'cleanup', 'teardown'):
                        value = plus(value, phase[key])
                    return value

                while index < attempts:
                    epoch = index // reuse
                    start = index
                    intended = min(attempts-index, reuse)
                    setup = take('setup', {**context, 'epoch': epoch, 'start_attempt': index})
                    require(integer(setup.get('setup_generation'), 'SETUP_GENERATION') == epoch and
                            setup.get('cache_key') == task.hex() and
                            integer(setup.get('intended_reuse_attempts'), 'INTENDED_REUSE') == intended,
                            'SETUP_BINDING')
                    setups += 1
                    phase['setup'] = plus(phase['setup'], timing(setup.get('timing')))
                    if setup.get('status') != 'prepared':
                        require(setup.get('status') in ('unsupported', 'error'), 'SETUP_STATUS')
                        if setup['status'] == 'unsupported':
                            require(setup.get('error') is None, 'UNSUPPORTED_ERROR')
                            unsupported += 1
                        else:
                            require(type(setup.get('error')) is str and setup['error'], 'SETUP_ERROR')
                            errors += 1
                        break
                    require(setup.get('error') is None, 'SETUP_ERROR')
                    epoch_hits = 0
                    for _ in range(intended):
                        row = take('attempt', {**context, 'epoch': epoch, 'index': index})
                        challenge = H('pon-work-expensive-challenge-v1', task, seed,
                                      struct.pack('<Q', sample), struct.pack('<Q', index))
                        require(hexbytes(row.get('challenge')) == challenge, 'CHALLENGE')
                        phase['attempt'] = plus(phase['attempt'], timing(row.get('timing')))
                        phase['cleanup'] = plus(phase['cleanup'], timing(row.get('cleanup_timing')))
                        paid = producer()
                        for clock in ('cpu_ns', 'wall_ns'):
                            require(integer(row.get('producer_cumulative_' + clock), 'CUMULATIVE') == paid[clock],
                                    'PRODUCER_CUMULATIVE')
                        observed = {clock: integer(row.get('observed_cell_cumulative_' + clock), 'OBSERVED_CUMULATIVE')
                                    for clock in ('cpu_ns', 'wall_ns')}
                        require(all(observed[k] >= previous_observed[k] and observed[k] >= paid[k]
                                    for k in observed), 'OBSERVED_CUMULATIVE_ORDER')
                        previous_observed = observed
                        if row.get('outcome') == 'error':
                            require(type(row.get('error')) is str and row['error'] and
                                    all(row.get(k) is None for k in ('trace', 'ticket', 'work_id', 'verification', 'proof_sha256', 'stream_equal')) and
                                    row.get('target_hit') is False and row.get('proof_materialized') is False,
                                    'FAILED_ATTEMPT')
                            errors += 1
                        else:
                            require(row.get('outcome') == 'complete' and row.get('error') is None, 'ATTEMPT_STATUS')
                            trace, ticket = hexbytes(row.get('trace')), hexbytes(row.get('ticket'))
                            require(H('ticket', challenge, trace) == ticket, 'TICKET_HASH')
                            hit = ticket <= target
                            require(row.get('target_hit') is hit and row.get('stream_equal') is True,
                                    'HIT_OR_STREAM')
                            key = (name, sample, index)
                            stream = (trace, ticket)
                            require(reference_stream.setdefault(key, stream) == stream, 'CROSS_ARM_STREAM')
                            trace_sequence.append(trace)
                            work = H('pon-work-expensive-work-v2', challenge, task, target)
                            require(hexbytes(row.get('work_id')) == work, 'WORK_ID')
                            materialized = hit if arm == 'lazy-full-limb' else True
                            require(row.get('proof_materialized') is materialized, 'MATERIALIZATION')
                            if materialized:
                                hexbytes(row.get('proof_sha256'))
                            else:
                                require(row.get('proof_sha256') is None, 'LAZY_MISS_DIGEST')
                            if hit:
                                hits += 1
                                epoch_hits += 1
                                verification = row.get('verification')
                                require(type(verification) is dict and verification.get('products_equal') is True,
                                        'VERIFIED_PRODUCT')
                                for backend in ('native', 'scalar'):
                                    observation = verification.get(backend, {})
                                    require(observation.get('outcome') == 'Accepted', 'NATIVE_VERDICT')
                                    phase['verification'] = plus(phase['verification'], timing(observation.get('timing')))
                                phase['verification'] = plus(phase['verification'], timing(verification.get('cleanup_timing')))
                                verified += 1
                                unique_accepted.add(work.hex())
                                accepted_rows.append({'work_id': work.hex(), 'producer': paid,
                                                      'observed': observed, 'index': index})
                            else:
                                require(row.get('verification') is None, 'LOSER_VERIFICATION')
                        index += 1
                    end = take('teardown', {**context, 'epoch': epoch})
                    require(integer(end.get('actual_attempts'), 'ACTUAL_REUSE') == index-start and
                            integer(end.get('actual_hits'), 'EPOCH_HITS') == epoch_hits and
                            end.get('lifetime_includes_audit_and_output') is True, 'CACHE_LIFETIME')
                    phase['teardown'] = plus(phase['teardown'], timing(end.get('timing')))
                    observed_end = {clock: integer(end.get('observed_cell_cumulative_' + clock), 'OBSERVED_TEARDOWN')
                                    for clock in ('cpu_ns', 'wall_ns')}
                    paid_end = producer()
                    require(all(observed_end[k] >= previous_observed[k] and observed_end[k] >= paid_end[k]
                                for k in observed_end), 'TEARDOWN_CLOCK_ORDER')
                    previous_observed = observed_end
                    boundaries.append({'producer_cpu_ns': paid_end['cpu_ns'],
                                       'observed_cpu_ns': observed_end['cpu_ns'],
                                       'completed_attempts': index,
                                       'verified_unique_hits': len({r['work_id'] for r in accepted_rows})})
                    lifetimes.append({'actual_attempts': index-start,
                                      'cached_lifetime': timing(end.get('cached_lifetime'))})
                summary = take('cell_summary', context)
                expected_status = 'failed' if errors else 'unsupported' if unsupported else 'complete'
                require(summary.get('status') == expected_status and
                        summary.get('sequence_complete') is (index == attempts) and
                        summary.get('native_branch_accepted_work') is None, 'CELL_STATUS')
                for field, value in {'attempts': index, 'hits': hits, 'verified_hits': verified,
                                     'setup_count': setups, 'unsupported_count': unsupported, 'error_count': errors,
                                     'distinct_application_results': int(verified > 0)}.items():
                    require(integer(summary.get(field), 'CELL_COUNT') == value, 'CELL_COUNT_' + field)
                for key in phase:
                    require(timing(summary.get(key + '_timing')) == phase[key], 'PHASE_SUM_' + key)
                paid = producer()
                require(timing(summary.get('producer_timing')) == paid, 'PRODUCER_SUM')
                observed_total = timing(summary.get('observed_cell_timing'))
                require(all(observed_total[k] >= previous_observed[k] and observed_total[k] >= paid[k]
                            for k in observed_total), 'OBSERVED_TOTAL')
                counters[expected_status.replace('complete', 'completed') + '_cells'] += 1
                counters['attempts'] += index
                counters['hits'] += hits
                counters['verified_hits'] += verified
                prefixes = []
                # Count only actual settled epoch boundaries. No destructor
                # measured after future attempts stands in for an early stop.
                for budget in budgets:
                    counts = {}
                    for scope in ('producer', 'observed'):
                        settled = [b for b in boundaries if b[scope + '_cpu_ns'] <= budget]
                        counts[scope + '_verified_unique_hits'] = settled[-1]['verified_unique_hits'] if settled else 0
                        counts[scope + '_settled_attempts'] = settled[-1]['completed_attempts'] if settled else 0
                    prefixes.append({'budget_cpu_ns': budget, **counts})
                cells.append({**context, 'status': expected_status, 'attempts': index, 'hits': hits,
                              'misses': index-hits-errors if expected_status == 'complete' else None,
                              'setup_count': setups, 'producer_timing': paid,
                              'observed_cell_timing': observed_total,
                              'verification_timing': phase['verification'], 'phase_timing': phase,
                              'actual_cache_lifetimes': lifetimes, 'prefixes': prefixes,
                              'settled_epoch_boundaries': boundaries,
                              'trace_sequence_sha256': hashlib.sha256(b''.join(trace_sequence)).hexdigest()})
    final = take('run_summary')
    require(cursor == len(rows), 'EXTRA_ROWS')
    require(final.get('status') == ('failed' if counters['failed_cells'] else 'complete') and
            final.get('all_attempts_retained') is True and final.get('qualification') is False and
            final.get('native_branch_accepted_work') is None and
            final.get('distinct_application_results_are_not_chain_weight') is True, 'RUN_STATUS')
    for key, count in counters.items():
        require(integer(final.get(key), 'RUN_COUNT') == count, 'RUN_COUNT_' + key)
    require(integer(final.get('requested_cells'), 'REQUESTED_CELLS') == samples*class_count*len(ARMS),
            'REQUESTED_CELLS')
    whole = timing(final.get('run_timing'))
    for clock in whole:
        require(whole[clock] >= sum(c['observed_cell_timing'][clock] for c in cells) + acquisition[clock],
                'WHOLE_RUN_CLOCK')
    # All constructors see the identical immutable operands in every sample.
    # A held-out support verdict cannot retroactively change calibration choice.
    for name in classes:
        for arm in ARMS:
            statuses = {c['status'] for c in cells if c['class'] == name and c['arm'] == arm}
            require(not {'complete', 'unsupported'} <= statuses, 'SUPPORT_CHANGED_WITH_SAMPLE')
            if arm in ('lazy-full-limb', 'prepared-generic', 'tiled-classical',
                       'tiled-strassen-one-level', 'paired-product', 'scalar-original'):
                require('unsupported' not in statuses, 'GENERIC_SUPPORT')
    selections = []
    if calibration_samples and not counters['failed_cells']:
        for name in classes:
            eligible = [arm for arm in ARMS if all(c['status'] == 'complete' for c in cells
                        if c['class'] == name and c['arm'] == arm and c['sample'] < calibration_samples)]
            require(bool(eligible), 'NO_COMPLETE_COMPARISON')
            scores = {arm: sum(c['producer_timing']['cpu_ns'] for c in cells
                              if c['class'] == name and c['arm'] == arm and c['sample'] < calibration_samples)
                      for arm in eligible}
            selected = min(eligible, key=lambda arm: (scores[arm], ARMS.index(arm)))
            evaluation = [c for c in cells if c['class'] == name and c['arm'] == selected and
                          c['sample'] >= calibration_samples]
            generic = [c for c in cells if c['class'] == name and c['arm'] == 'lazy-full-limb' and
                       c['sample'] >= calibration_samples]
            selected_ns = sum(c['producer_timing']['cpu_ns'] for c in evaluation)
            generic_ns = sum(c['producer_timing']['cpu_ns'] for c in generic)
            selections.append({'class': name, 'selected_arm': selected,
                               'selection_rule': 'minimum aggregate producer CPU on earlier calibration samples; fixed tie order',
                               'calibration_samples': list(range(calibration_samples)),
                               'evaluation_samples': list(range(calibration_samples, samples)),
                               'evaluation_producer_cpu_ns': selected_ns,
                               'generic_evaluation_producer_cpu_ns': generic_ns,
                               'generic_to_selected_cpu_ratio': None if not selected_ns else generic_ns/selected_ns,
                               'evaluation_budget_counts': [
                                   {'per_sample_budget_cpu_ns': budget,
                                    'evaluation_replicates': len(evaluation),
                                    'aggregate_budget_ceiling_cpu_ns': budget * len(evaluation),
                                    'selected_hits_across_replicates': sum(c['prefixes'][i]['producer_verified_unique_hits'] for c in evaluation),
                                    'generic_hits_across_replicates': sum(c['prefixes'][i]['producer_verified_unique_hits'] for c in generic),
                                    'selected_mean_hits_per_replicate': sum(c['prefixes'][i]['producer_verified_unique_hits'] for c in evaluation)/len(evaluation),
                                    'generic_mean_hits_per_replicate': sum(c['prefixes'][i]['producer_verified_unique_hits'] for c in generic)/len(generic)}
                                   for i, budget in enumerate(budgets)]})
    return {'schema': 'pon-work-expensive-reader-v1', 'status': final['status'],
            'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw),
            'seed': seed.hex(), 'target': target.hex(), 'attempts_per_arm': attempts,
            'samples': samples, 'reuse_attempts': reuse, 'counts': counters,
            'unique_relation_winners_across_repeated_arms': len(unique_accepted),
            'material_creation_timing': acquisition, 'run_timing': whole,
            'material_identity': material_rows, 'cells': cells, 'calibration_selection': selections,
            'budgets': {'cpu_ns': budgets, 'prefix_boundary': 'only actually completed and destroyed cache epochs',
                        'producer': 'setup + attempts + per-attempt cleanup + completed epoch teardown',
                        'observed': 'continuous cell clock includes instrumented verifiers, evidence and output',
                        'excluded': 'material acquisition and identity/rank preparation are separately reported; no network or native admission',
                        'actual_early_stop_executed': False},
            'gamma': None, 'gamma_upper_bound': None, 'native_branch_accepted_work': None,
            'scope': 'finite primitive observation; calibration selection is available to honest miners too',
            'cross_target_or_reuse_cohorts_are_additive_work': False,
            'production_activation': False, 'work_hardness_qualified': False,
            'limits': ['No claim about a globally cheapest algorithm or expectation over untested strategies.',
                       'A self-reported stream does not authenticate clocks, execution or hidden adversary attempts.',
                       'Repeated arms, reuse horizons and target cohorts do not create additive chain or application credit.',
                       'Prefix counts are measurements under explicit component budgets, not live fork-choice W_accepted.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--calibration-samples', type=int, default=2)
    parser.add_argument('--budgets-ns', type=int, nargs='+', default=[1_000_000, 5_000_000, 20_000_000])
    args = parser.parse_args()
    with args.raw.open('rb') as source:
        raw = source.read(MAX_BYTES+1)
    result = inspect(raw, args.budgets_ns, args.calibration_samples)
    with args.out.open('x') as target:
        json.dump(result, target, sort_keys=True, indent=2, allow_nan=False)
        target.write('\n')
    print(json.dumps({'status': result['status'], 'counts': result['counts'], 'gamma': None}))
    return int(result['status'] != 'complete')


if __name__ == '__main__':
    raise SystemExit(main())
