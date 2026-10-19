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


def fixed_legal_arm_costs(records):
    """One actual fixed implementation per class; no hindsight arm switching."""
    groups, cohorts = defaultdict(list), defaultdict(set)
    for filename, rows in records.items():
        seed = rows[0]['seed']
        diagnostics = {(row['case'], row['kernel']): row for row in rows
                       if row['kind'] == 'raw-verifier-diagnostic'}
        for row in rows:
            if row['kind'] != 'producer':
                continue
            kind, sample, arm = row['case'].split('/')
            if arm not in ('generic', 'structured', 'blocked-zero'):
                continue
            key = (seed, int(sample))
            cohorts[kind].add(key)
            winner = row['status'] == 'target-hit-unverified'
            if winner:
                require(diagnostics[(row['case'], 'production')]['outcome']['kind'] == 'verified-work',
                        'fixed legal cost needs complete production verification')
            groups[(kind, arm)].append({
                'file': filename, 'seed': seed, 'sample': int(sample),
                'status': row['status'], 'task': row['task'], 'target': row['target'],
                'setup_cpu_ns': row['setup']['cpu_ns'],
                'search_cpu_ns': row.get('search', {}).get('cpu_ns'),
                'full_cpu_ns': row['total']['cpu_ns'],
                'attempts': len(row['attempts']), 'winner': winner,
                'production_verifier_cpu_ns': diagnostics[(row['case'], 'production')]['timing']['cpu_ns'] if winner else None,
            })
    aggregates, completed = [], defaultdict(list)
    for (kind, arm), cases in sorted(groups.items()):
        keys = {(case['seed'], case['sample']) for case in cases}
        require(len(keys) == len(cases) and keys == cohorts[kind],
                'fixed-arm cost requires every unique declared seed/sample, including unsupported and exhausted cases')
        require(len({case['target'] for case in cases}) == 1, 'fixed-arm targets cannot be pooled')
        full = sum(case['full_cpu_ns'] for case in cases)
        attempts = sum(case['attempts'] for case in cases)
        winners = sum(case['winner'] for case in cases)
        unsupported = sum(case['status'] == 'unsupported' for case in cases)
        aggregate = {
            'class': kind, 'arm': arm, 'target': cases[0]['target'], 'cases': cases,
            'case_count': len(cases), 'status_counts': dict(Counter(case['status'] for case in cases)),
            'full_setup_plus_all_search_cpu_ns': full,
            'setup_cpu_ns': sum(case['setup_cpu_ns'] for case in cases),
            'search_cpu_ns': sum(case['search_cpu_ns'] for case in cases if case['search_cpu_ns'] is not None),
            'attempts': attempts, 'winners': winners,
            'full_cpu_per_attempt': {'cpu_ns': full, 'attempts': attempts,
                                     'ratio_ns': full / attempts if attempts else None},
            'full_cpu_per_winner': {'cpu_ns': full, 'winners': winners,
                                    'ratio_ns': full / winners if winners else None},
            'eligible_for_fixed_arm_comparison': unsupported == 0 and winners > 0,
        }
        aggregates.append(aggregate)
        if aggregate['eligible_for_fixed_arm_comparison']:
            completed[kind].append(aggregate)
    minimum = []
    for kind, arms in sorted(completed.items()):
        require(len({(arm['winners'], arm['attempts'], arm['target']) for arm in arms}) == 1,
                'fixed implementations must retain the same winner and attempted stream cohort')
        best = min(arms, key=lambda arm: (arm['full_setup_plus_all_search_cpu_ns'], arm['arm']))
        minimum.append({
            'class': kind, 'arm': best['arm'], 'observed_complete_arms': [arm['arm'] for arm in arms],
            'case_count': best['case_count'], 'attempts': best['attempts'], 'winners': best['winners'],
            'full_setup_plus_all_search_cpu_ns': best['full_setup_plus_all_search_cpu_ns'],
            'setup_cpu_ns': best['setup_cpu_ns'], 'search_cpu_ns': best['search_cpu_ns'],
            'full_cpu_per_winner': best['full_cpu_per_winner'],
        })
    return {
        'aggregates': aggregates, 'minimum_observed_fixed_arm_per_class': minimum,
        'scope': 'each fixed arm retains all declared seeds/samples and all failed attempts; one implementation per class across the complete cohort; zero winners have a null per-winner ratio; unsupported cases prevent selection',
        'per_sample_hindsight_mixture_is_implemented_strategy': False,
        'setup_reused_across_attempts_within_each_search': True,
        'one_setup_reused_across_separate_searches_measured': False,
        'fastest_adversary_lower_bound': False,
    }


def legal_winner_costs(records):
    """Only after strict raw validation; preserve setup and every failed attempt."""
    samples, grouped = [], defaultdict(list)
    for filename, rows in records.items():
        campaign = rows[0]
        diagnostics = {(row['case'], row['kernel']): row for row in rows
                       if row['kind'] == 'raw-verifier-diagnostic'}
        for row in rows:
            if row['kind'] != 'producer' or row['status'] != 'target-hit-unverified' or not row['valid_proof_acquisition_used']:
                continue
            kind, sample, arm = row['case'].split('/')
            require(arm in ('generic', 'structured', 'blocked-zero'), 'false trace cannot enter legal winner minimum')
            verified = diagnostics[(row['case'], 'production')]
            require(verified['outcome']['kind'] == 'verified-work', 'legal cost needs actual complete production verification')
            trial_cpu = [attempt['timing']['cpu_ns'] for attempt in row['attempts']]
            case = {
                'file': filename, 'seed': campaign['seed'], 'class': kind,
                'sample': int(sample), 'arm': arm, 'method': row['method'],
                'task': row['task'], 'target': row['target'],
                'proof_digest': row['candidate_proof_digest'],
                'winning_challenge': row['attempts'][-1]['challenge'],
                'attempts': len(row['attempts']),
                'setup_cpu_ns': row['setup']['cpu_ns'],
                'search_cpu_ns': row['search']['cpu_ns'],
                'full_cpu_ns': row['total']['cpu_ns'],
                'full_wall_ns': row['total']['wall_ns'],
                'production_verifier_cpu_ns': verified['timing']['cpu_ns'],
                'per_attempt_cpu_ns': {
                    'known': span(value for value in trial_cpu if value is not None),
                    'unknown_count': sum(value is None for value in trial_cpu),
                },
            }
            require(case['full_cpu_ns'] is not None and case['full_cpu_ns'] > 0,
                    'legal minimum requires known positive full producer CPU')
            samples.append(case)
            grouped[(campaign['seed'], kind, int(sample))].append(case)
    minimum = []
    for (seed, kind, sample), cases in sorted(grouped.items()):
        require(len({case['arm'] for case in cases}) == len(cases), 'duplicate seed/case cannot increase legal sample count')
        require(len({(case['task'], case['target'], case['proof_digest'], case['winning_challenge'], case['attempts']) for case in cases}) == 1,
                'legal arms must retain the same complete winning proof and attempted stream')
        best = min(cases, key=lambda case: (case['full_cpu_ns'], case['arm']))
        minimum.append({
            'seed': seed, 'class': kind, 'sample': sample,
            'observed_complete_arms': [case['arm'] for case in cases],
            'minimum_full_cpu_arm': best['arm'],
            'minimum_full_cpu_ns': best['full_cpu_ns'],
            'setup_cpu_ns': best['setup_cpu_ns'], 'search_cpu_ns': best['search_cpu_ns'],
            'attempts': best['attempts'], 'proof_digest': best['proof_digest'],
        })
    return {
        'samples': samples, 'minimum_per_same_case': minimum,
        'minimum_scope': 'minimum observed full setup-plus-all-attempts CPU among completed implemented legal arms for the same seed/task/challenge stream; unsupported and exhausted arms stay in the original campaign counts',
        'public_material_construction_separate': True,
        'fastest_adversary_lower_bound': False,
        'independent_proof_count_is_not_arm_count': True,
        'per_sample_minimum_is_descriptive_not_an_implemented_strategy': True,
        'fixed_implementation_cohorts': fixed_legal_arm_costs(records),
    }


def compare_hosts(left, right, labels):
    require(len(labels) == 2 and all(isinstance(label, str) and label.strip() for label in labels)
            and labels[0] != labels[1], 'two distinct explicit host labels required')
    require((left['source_head'], left['source_tree']) == (right['source_head'], right['source_tree']),
            'hardware comparison requires the same exact source commit/tree')
    require(left['strict_reader_sha256'] == right['strict_reader_sha256'], 'same strict reader required')
    def campaign_grid(report):
        rows = report['campaigns']
        indexed = {row['file']: row['campaign'] for row in rows}
        require(len(indexed) == len(rows) and indexed, 'nonempty unique host campaign grid required')
        return indexed
    require(campaign_grid(left) == campaign_grid(right),
            'both hosts require the same complete seed/target/sample/attempt/receiver budget campaign grid')
    def indexed(report):
        rows = report['implemented_legal_winner_costs']['samples']
        result = {(row['seed'], row['class'], row['sample'], row['arm']): row for row in rows}
        require(len(result) == len(rows) and result, 'nonempty unique legal host cases required')
        return result
    a, b = indexed(left), indexed(right)
    require(a.keys() == b.keys(), 'host comparison cannot discard absent or exhausted legal cases')
    pairs = []
    for key, first in sorted(a.items()):
        second = b[key]
        require(all(first[field] == second[field] for field in
                    ('task', 'target', 'proof_digest', 'winning_challenge', 'attempts', 'method')),
                'host cases must use identical task/target/proof/challenge/attempts/implementation')
        ratio = first['full_cpu_ns'] / second['full_cpu_ns']
        pairs.append({
            'seed': key[0], 'class': key[1], 'sample': key[2], 'arm': key[3],
            'proof_digest': first['proof_digest'], 'attempts': first['attempts'],
            'left_full_cpu_ns': first['full_cpu_ns'], 'right_full_cpu_ns': second['full_cpu_ns'],
            'left_setup_cpu_ns': first['setup_cpu_ns'], 'right_setup_cpu_ns': second['setup_cpu_ns'],
            'left_search_cpu_ns': first['search_cpu_ns'], 'right_search_cpu_ns': second['search_cpu_ns'],
            'left_cpu_over_right_cpu': ratio,
        })
    def false_index(report):
        cases = [(group['class'], row) for group in report['false_trace_costs'] for row in group['cases']]
        indexed = {(row['seed'], kind, row['sample']): row for kind, row in cases}
        require(len(indexed) == len(cases), 'duplicate false-trace cases cannot increase host sample count')
        return indexed
    a_false, b_false = false_index(left), false_index(right)
    require(a_false.keys() == b_false.keys(), 'host comparison cannot discard false-trace cases')
    false_pairs = []
    for key, first in sorted(a_false.items()):
        second = b_false[key]
        require(all(first[field] == second[field] for field in
                    ('task', 'target', 'proof_digest', 'challenge', 'attempts', 'raw_outcome')),
                'false-trace host cases must retain the same exact fabricated proof and raw relation outcome')
        false_pairs.append({
            'seed': key[0], 'class': key[1], 'sample': key[2],
            'proof_digest': first['proof_digest'], 'attempts': first['attempts'],
            'left_full_producer_cpu_ns': first['producer_full_total_cpu_ns'],
            'right_full_producer_cpu_ns': second['producer_full_total_cpu_ns'],
            'left_raw_verifier_cpu_ns': first['raw_production_verifier_cpu_ns'],
            'right_raw_verifier_cpu_ns': second['raw_production_verifier_cpu_ns'],
            'left_raw_verifier_over_full_producer_cpu': first['raw_production_verifier_cpu_over_full_producer_cpu'],
            'right_raw_verifier_over_full_producer_cpu': second['raw_production_verifier_cpu_over_full_producer_cpu'],
            'left_producer_cpu_over_right_cpu': first['producer_full_total_cpu_ns'] / second['producer_full_total_cpu_ns'],
        })
    return {
        'schema': 'pon-w1-same-source-host-comparison-v1', 'host_labels': labels,
        'source_head': left['source_head'], 'source_tree': left['source_tree'],
        'left': left, 'right': right, 'paired_legal_costs': pairs,
        'paired_false_trace_costs': false_pairs,
        'scope': 'same source and exact mathematical cases on caller-labelled retained hosts; CPU clocks are per actual execution thread, not wall-time estimates; host provenance remains the external runner observation',
        'gpu_or_asic_lower_bound': False, 'independent_operators_qualified': False,
        'work_hardness_accepted': False, 'public_service_measured': False,
    }


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
                    'file': name, 'seed': rows[0]['seed'], 'sample': int(sample), 'attempts': len(row['attempts']),
                    'proof_digest': row['candidate_proof_digest'],
                    'challenge': row['attempts'][-1]['challenge'],
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
        'schema': 'pon-w1-derived-costs-v2', 'source_head': results['head'], 'source_tree': results['tree'],
        'input_identities': identities,
        'record_validation': validations,
        'strict_reader_sha256': sha(Path(reader.__file__).read_bytes()),
        'hardware': hardware, 'operator_count': results['operator_count'],
        'w1_command_results': [row for row in results['steps'] if row['name'].startswith('w1-')],
        'other_failed_steps_in_same_batch': [row for row in results['steps'] if row['returncode'] != 0],
        'campaigns': campaigns, 'paired_alternative_costs': comparisons, 'false_trace_costs': false_costs,
        'raw_verifier_kernel_comparisons': kernel_comparisons,
        'implemented_legal_winner_costs': legal_winner_costs({name: records[name] for name in selected}),
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
    parser.add_argument('--peer-raw-dir', type=Path,
                        help='independently validate a second retained host directory with the same source and file names')
    parser.add_argument('--host-labels', nargs=2,
                        help='explicit caller labels for --raw-dir and --peer-raw-dir; not independent operator proof')
    args = parser.parse_args()
    try:
        result = derive(args)
        require((args.peer_raw_dir is None) == (args.host_labels is None),
                '--peer-raw-dir and two --host-labels must be supplied together')
        if args.peer_raw_dir is not None:
            require(args.raw_dir.resolve() != args.peer_raw_dir.resolve(), 'same directory is not two host observations')
            peer_args = argparse.Namespace(**vars(args))
            peer_args.raw_dir = args.peer_raw_dir
            result = compare_hosts(result, derive(peer_args), args.host_labels)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, ZeroDivisionError) as error:
        print(json.dumps({'schema': 'pon-w1-derived-costs-v2', 'result': 'FAIL',
                          'error': str(error), 'native_execution_performed_by_reader': False},
                         allow_nan=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
