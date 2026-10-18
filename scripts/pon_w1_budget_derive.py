#!/usr/bin/env python3
"""Derive complete costs, unique proof counts and original-budget recovery.

Read-only: every raw JSONL input is checked by pon_w1_budget_reader before use;
raw bytes are rechecked against that exact validation. Results/hardware are
retained host observations, not authenticated by this reader. No native process,
network, input write, new service domain or production profile is created.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys

sys.dont_write_bytecode = True
import pon_w1_budget_reader as reader

require = reader.require


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def span(values):
    values = list(values)
    return {'n': len(values), 'sum': sum(values), 'min': min(values) if values else None,
            'median': statistics.median(values) if values else None,
            'max': max(values) if values else None}


def named_file(root, name):
    require(isinstance(name, str) and Path(name).name == name and name not in ('', '.', '..'),
            'a simple retained file name is required')
    return root / name


def load_json(raw):
    return json.loads(raw, object_pairs_hook=reader.unique_object,
                      parse_constant=reader.reject_constant, parse_float=reader.finite_float)


def derive(args):
    for label, value in (('head', args.expected_head), ('tree', args.expected_tree)):
        require(re.fullmatch(r'[0-9a-f]{40}', value) is not None, 'literal source ' + label + ' required')
    names = [*args.compare, args.exhausted, args.budget]
    require(len(names) == len(set(names)), 'duplicate retained input names cannot increase sample count')
    records, identities, validations = {}, {}, []
    for name in names:
        path = named_file(args.raw_dir, name)
        validated = reader.analyze(path)
        require(validated['record_consistency'] == 'PASS' and not validated['semantic_alerts'],
                name + ': malformed or unexpected native verification outcomes')
        raw = path.read_bytes()
        require(sha(raw) == validated['sha256'] and len(raw) == validated['bytes'],
                name + ': input changed after validation')
        records[name] = [load_json(line) for line in raw.splitlines()]
        for row in records[name]:
            for field in ('timing', 'setup', 'search', 'total'):
                if field in row:
                    require(row[field]['cpu_ns'] is not None,
                            name + ': numeric cost derivation requires known ' + field + ' CPU; the reader retains unknown samples')
            if row['kind'] == 'receiver' and row['status'] == 'started':
                require(row['settlement']['total_cpu_ns'] is not None,
                        name + ': numeric derivation requires known settled CPU')
        identities[name] = {'sha256': validated['sha256'], 'bytes': validated['bytes']}
        validations.append({'file': name, 'record_consistency': 'PASS',
                            'semantic_alerts': validated['semantic_alerts'],
                            'sha256': validated['sha256'], 'records': validated['records']})
    metadata = {}
    require(args.results != args.hardware, 'results and hardware must be distinct retained inputs')
    require(records[args.exhausted][0]['target'] == '00' * 32,
            'the designated forced-exhaustion campaign must retain the all-zero target')
    for name in (args.results, args.hardware):
        require(name not in names, 'metadata cannot replace raw campaign input')
        raw = named_file(args.raw_dir, name).read_bytes()
        identities[name] = {'sha256': sha(raw), 'bytes': len(raw)}
        metadata[name] = load_json(raw)
    results, hardware = metadata[args.results], metadata[args.hardware]
    require(results['head'] == args.expected_head and results['tree'] == args.expected_tree,
            'retained source head/tree differs from explicitly expected observation')
    require(results['native'] is True, 'retained run does not report native execution')
    reader.integer(results['operator_count'], 'recorded operator count', 1)
    require(results['independent_operator_qualification'] is False,
            'this local cost reader does not transfer independent-operator qualification')
    campaigns, paired, false_rows = [], defaultdict(list), defaultdict(list)
    kernel_rows = defaultdict(list)
    all_primary_producers = []
    selected = tuple(args.compare)
    for name, rows in records.items():
        producers = [row for row in rows if row['kind'] == 'producer']
        receivers = [row for row in rows if row['kind'] == 'receiver']
        diagnostics = [row for row in rows if row['kind'] == 'raw-verifier-diagnostic']
        p = {row['case']: row for row in producers}
        candidates = [row for row in producers if row['status'] == 'target-hit-unverified']
        legal = [row for row in candidates if row['valid_proof_acquisition_used']]
        false = [row for row in candidates if not row['valid_proof_acquisition_used']]
        campaigns.append({
            'file': name, 'campaign': rows[0], 'producer_cases_offered': len(producers),
            'producer_status_counts': dict(Counter(row['status'] for row in producers)),
            'producer_attempts_executed': sum(len(row['attempts']) for row in producers),
            'producer_full_total_cpu_ns_including_unsupported_setup': sum(row['total']['cpu_ns'] for row in producers),
            'public_material_construction_cpu_ns_separate': sum(row['timing']['cpu_ns'] for row in rows if row['kind'] == 'public-task-material'),
            'candidate_arm_cases': len(candidates),
            'legal_candidate_arm_cases': len(legal), 'false_candidate_arm_cases': len(false),
            'distinct_candidate_proof_digests': len({row['candidate_proof_digest'] for row in candidates}),
            'distinct_legal_candidate_proof_digests': len({row['candidate_proof_digest'] for row in legal}),
            'distinct_false_candidate_proof_digests': len({row['candidate_proof_digest'] for row in false}),
            'raw_verifier_records': len(diagnostics),
            'raw_verifier_outcomes': dict(Counter(row['outcome']['kind'] for row in diagnostics)),
            'receiver_requested_rows': len(receivers), 'receiver_summary': rows[-1],
        })
        if name not in selected:
            continue
        all_primary_producers.extend(candidates)
        for diagnostic in diagnostics:
            side = 'false' if diagnostic['case'].endswith('/from-zero-false-trace') else 'legal'
            kernel_rows[(side, diagnostic['kernel'])].append({
                'file': name, 'case': diagnostic['case'],
                'cpu_ns': diagnostic['timing']['cpu_ns'], 'outcome': diagnostic['outcome'],
            })
        d = {(row['case'], row['kernel']): row for row in diagnostics}
        r = {(row['case'], row['round']): row for row in receivers}
        for case, row in p.items():
            kind, sample, arm = case.split('/')
            if row['status'] != 'target-hit-unverified':
                continue
            if arm in ('structured', 'blocked-zero'):
                generic = p[f'{kind}/{sample}/generic']
                require(generic['candidate_proof_digest'] == row['candidate_proof_digest'], 'paired candidate bytes differ')
                paired[(kind, arm)].append({
                    'file': name, 'sample': int(sample), 'task': row['task'], 'target': row['target'],
                    'same_exact_candidate_proof_digest': row['candidate_proof_digest'],
                    'attempts': len(row['attempts']),
                    'generic_setup_cpu_ns': generic['setup']['cpu_ns'],
                    'alternative_setup_cpu_ns': row['setup']['cpu_ns'],
                    'generic_search_cpu_ns': generic['search']['cpu_ns'],
                    'alternative_search_cpu_ns': row['search']['cpu_ns'],
                    'generic_total_cpu_ns': generic['total']['cpu_ns'],
                    'alternative_total_cpu_ns': row['total']['cpu_ns'],
                    'generic_cpu_over_alternative_cpu': generic['total']['cpu_ns'] / row['total']['cpu_ns'],
                })
            if arm == 'from-zero-false-trace':
                diagnostic = d[(case, 'production')]
                receiver = r[(case, 0)]
                require(receiver['status'] == 'started', 'comparison receiver did not start; do not fabricate a complete-verification ratio')
                false_rows[kind].append({
                    'file': name, 'sample': int(sample), 'attempts': len(row['attempts']),
                    'task': row['task'], 'target': row['target'],
                    'producer_setup_cpu_ns': row['setup']['cpu_ns'],
                    'producer_search_cpu_ns': row['search']['cpu_ns'],
                    'producer_full_total_cpu_ns': row['total']['cpu_ns'],
                    'raw_production_verifier_cpu_ns': diagnostic['timing']['cpu_ns'],
                    'raw_production_verifier_cpu_over_full_producer_cpu': diagnostic['receiver_cpu_over_full_producer_search_cpu'],
                    'cooperative_receiver_settled_cpu_ns': receiver['settlement']['total_cpu_ns'],
                    'cooperative_receiver_cpu_over_full_producer_cpu': receiver['settlement']['total_cpu_ns'] / row['total']['cpu_ns'],
                    'raw_outcome': diagnostic['outcome'], 'cooperative_outcome': receiver['outcome'],
                })
    for key in ('work_profile', 'target', 'samples', 'attempt_budget_per_arm', 'receiver_replays', 'classes'):
        require(records[selected[0]][0][key] == records[selected[1]][0][key], 'comparison has different declared ' + key)
    comparisons = []
    for (kind, arm), pairs in paired.items():
        generic = sum(row['generic_total_cpu_ns'] for row in pairs)
        alternative = sum(row['alternative_total_cpu_ns'] for row in pairs)
        comparisons.append({
            'class': kind, 'alternative_arm': arm, 'pairs': pairs,
            'paired_candidate_count': len(pairs),
            'generic_full_cpu_ns': generic, 'alternative_full_cpu_ns': alternative,
            'generic_total_cpu_over_alternative_total_cpu': generic / alternative,
            'fraction_of_generic_full_cpu_saved': 1 - alternative / generic,
            'pairwise_speedup': span(row['generic_cpu_over_alternative_cpu'] for row in pairs),
            'alternative_slower_pair_count': sum(row['alternative_total_cpu_ns'] > row['generic_total_cpu_ns'] for row in pairs),
            'generic_setup_cpu_ns': span(row['generic_setup_cpu_ns'] for row in pairs),
            'alternative_setup_cpu_ns': span(row['alternative_setup_cpu_ns'] for row in pairs),
            'pairing_scope': 'same seed/class/sample/task/target/challenge stream and exact candidate proof; full setup plus all attempts; fixed arm execution order, no confidence or universal speedup claim',
        })
    false_costs = []
    for kind, values in false_rows.items():
        false_costs.append({
            'class': kind, 'cases': values,
            'producer_full_cpu_ns': span(row['producer_full_total_cpu_ns'] for row in values),
            'raw_production_verifier_cpu_ns': span(row['raw_production_verifier_cpu_ns'] for row in values),
            'cooperative_receiver_settled_cpu_ns': span(row['cooperative_receiver_settled_cpu_ns'] for row in values),
            'raw_verifier_over_full_producer_cpu': span(row['raw_production_verifier_cpu_over_full_producer_cpu'] for row in values),
            'cooperative_receiver_over_full_producer_cpu': span(row['cooperative_receiver_cpu_over_full_producer_cpu'] for row in values),
            'ratio_of_summed_raw_cpu_to_summed_full_producer_cpu': sum(row['raw_production_verifier_cpu_ns'] for row in values) / sum(row['producer_full_total_cpu_ns'] for row in values),
            'ratio_of_summed_cooperative_cpu_to_summed_full_producer_cpu': sum(row['cooperative_receiver_settled_cpu_ns'] for row in values) / sum(row['producer_full_total_cpu_ns'] for row in values),
        })
    kernel_comparisons = []
    for side in ('legal', 'false'):
        production = {(row['file'], row['case']): row['cpu_ns']
                      for row in kernel_rows[(side, 'production')]}
        for kernel in ('scalar-reference', 'limb'):
            pairs = [{'file': row['file'], 'case': row['case'],
                      'production_cpu_ns': production[(row['file'], row['case'])],
                      'alternative_cpu_ns': row['cpu_ns']}
                     for row in kernel_rows[(side, kernel)]]
            production_cpu = sum(row['production_cpu_ns'] for row in pairs)
            alternative_cpu = sum(row['alternative_cpu_ns'] for row in pairs)
            kernel_comparisons.append({
                'candidate_type': side, 'alternative_kernel': kernel, 'pairs': pairs,
                'production_cpu_ns': production_cpu, 'alternative_cpu_ns': alternative_cpu,
                'production_cpu_over_alternative_cpu': production_cpu / alternative_cpu if alternative_cpu else None,
                'fraction_production_cpu_saved': 1 - alternative_cpu / production_cpu if production_cpu else None,
                'alternative_slower_pairs': sum(row['alternative_cpu_ns'] > row['production_cpu_ns'] for row in pairs),
                'scope': 'same complete raw proof with fixed recorded kernel order; excludes original service dispatch and cooperative CPU accounting; repeated proof bytes are not independent samples',
            })
    budget_rows = [row for row in records[args.budget] if row['kind'] == 'receiver']
    first_refusal, streak, post_refusal_starts = None, 0, []
    for ordinal, row in enumerate(budget_rows, 1):
        if row['status'] == 'not-started':
            if first_refusal is None:
                first_refusal = ordinal
            streak += 1
        elif first_refusal is not None:
            post_refusal_starts.append({
                'request_ordinal': ordinal, 'round': row['round'], 'case': row['case'],
                'outcome': row['outcome'], 'preceding_refusal_streak': streak,
                'before_credit_ns': row['before']['stored_credit_ns'],
                'after_credit_ns': row['after']['stored_credit_ns'],
                'settled_cpu_ns': row['settlement']['total_cpu_ns'],
            })
            streak = 0
    recoveries = [row for row in post_refusal_starts if row['preceding_refusal_streak'] > 0]
    output = {
        'schema': 'pon-w1-derived-costs-v1', 'source_head': results['head'], 'source_tree': results['tree'],
        'input_identities': identities,
        'record_validation': validations,
        'strict_reader_sha256': sha(Path(reader.__file__).read_bytes()),
        'hardware': hardware, 'operator_count': results['operator_count'],
        'w1_command_results': [row for row in results['steps'] if row['name'].startswith('w1-')],
        'other_failed_steps_in_same_batch': [row for row in results['steps'] if row['returncode'] != 0],
        'campaigns': campaigns, 'paired_alternative_costs': comparisons, 'false_trace_costs': false_costs,
        'raw_verifier_kernel_comparisons': kernel_comparisons,
        'primary_two_seed_distinct_candidate_proof_digests': len({row['candidate_proof_digest'] for row in all_primary_producers}),
        'primary_two_seed_distinct_legal_proof_digests': len({row['candidate_proof_digest'] for row in all_primary_producers if row['valid_proof_acquisition_used']}),
        'budget_recovery': {
            'definition': 'an actual started request after a nonempty consecutive refusal streak, under the same row-chained original CPU domain; not process restart, independent admission entitlement or business confirmation',
            'first_refused_request_ordinal': first_refusal,
            'started_before_first_refusal': first_refusal - 1 if first_refusal is not None else len(budget_rows),
            'post_first_refusal_started_requests': len(post_refusal_starts),
            'recovery_events_after_refusal_streak': len(recoveries),
            'recovery_outcomes': dict(Counter(row['outcome']['kind'] for row in recoveries)),
            'trailing_refusals': streak, 'events': recoveries,
        },
        'scope': {
            'reader_ran_native_code': False, 'raw_inputs_modified': False,
            'native_execution_is_retained_input_not_reexecution': True,
            'same_host_other_builds_possible_as_reported': hardware.get('native_same_host_other_builds_possible'),
            'cost_denominator': 'per-arm full setup plus all attempted search trials once; nested setup/search/trials not double-added; common public-material construction separate',
            'excluded_from_raw_cpu_cost': ['final JSONL serialization', 'network admission ticket', 'socket transport', 'signed request verification', 'full packet/M06/SQLite admission'],
            'receiver_budget_wall_includes_jsonl_emission_and_actual_refill': True,
            'receiver_replay_cost_not_new_proof_production_per_request': True,
            'zero_target_exhaustion_is_forced_no_hit_boundary': True,
            'unique_business_confirmations': None, 'business_tps': None,
            'independent_operators': False, 'production_qualification': False,
        },
    }
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--compare', nargs=2, default=['w1-seed1.jsonl', 'w1-seed2.jsonl'])
    parser.add_argument('--exhausted', default='w1-exhausted.jsonl')
    parser.add_argument('--budget', default='w1-receiver-budget.jsonl')
    parser.add_argument('--results', default='results.json')
    parser.add_argument('--hardware', default='hardware.json')
    args = parser.parse_args()
    try:
        result = derive(args)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, ZeroDivisionError) as error:
        print(json.dumps({'schema': 'pon-w1-derived-costs-v1', 'result': 'FAIL',
                          'error': str(error), 'native_execution_performed_by_reader': False},
                         allow_nan=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
