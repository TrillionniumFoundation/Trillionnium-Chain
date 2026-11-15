#!/usr/bin/env python3
"""Reproduce finite same-material cost statistics using only retained JSON.

No repository imports, native execution, model evaluation, or clock measurement.
--security-report is repeated once per target. All paths are caller supplied;
absolute run paths inside older records are used only for their case basename.
Output times remain integer nanoseconds. Ratios are exact rational numbers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from fractions import Fraction


SCHEMA = 'pon-shared-material-statistics-v2'
CORE = ('producer_subtotal', 'native_verifier_subtotal', 'typed_copy_subtotal')
PAIRED = re.compile(r'paired-r([0-2])-t([01])-(full-limb|transposed)-(dense|sparse)')
LEAVES = {
    'setup': 'setup', 'producer': 'producer_subtotal',
    'native_verifier': 'native_verifier_subtotal',
    'reference_verifier': 'reference_verifier_subtotal',
    'typed_copy': 'typed_copy_subtotal',
    'record_build': 'record_build_subtotal',
    'serialization_output': 'serialization_output_subtotal',
}
ARM_METRICS = tuple(name + '_' + clock for name in
                    ('setup', 'producer', 'native_verifier', 'core', 'child', 'ordinary_warm',
                     'product_consumption', 'consumer_run_tree', 'outer_consumer_tree')
                    for clock in ('cpu_ns', 'wall_ns'))
PAIR_METRICS = tuple(name + '_' + clock for name in ('setup', 'producer', 'core', 'child')
                     for clock in ('cpu_ns', 'wall_ns'))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def integer(value, code='INTEGER', positive=False):
    require(type(value) is int and value >= (1 if positive else 0), code)
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY:' + key)
        result[key] = value
    return result


def read(path):
    raw = path.read_bytes()
    require(len(raw) <= 16 * 1024 * 1024, 'INPUT_SIZE')
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
    return value, hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def fraction(value):
    return {'numerator': value.numerator, 'denominator': value.denominator}


def median(values):
    ordered = sorted(values)
    require(bool(ordered), 'EMPTY_STATISTIC')
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def ns_stats(values):
    require(len(values) == 3 and all(type(value) is int and value >= 0 for value in values),
            'THREE_INTEGER_REPETITIONS_REQUIRED')
    return {'min': min(values), 'median': median(values), 'max': max(values)}


def ratio_stats(values):
    require(len(values) == 3 and all(isinstance(value, Fraction) for value in values), 'THREE_RATIOS_REQUIRED')
    return {'min': fraction(min(values)), 'median': fraction(median(values)), 'max': fraction(max(values))}


def divide(numerator, denominator):
    return Fraction(integer(numerator), integer(denominator, 'POSITIVE_DENOMINATOR', positive=True))


def complete_metrics(run, outer):
    native = run['native_leaf_costs']
    values = {}
    for name, leaf in LEAVES.items():
        for clock in ('cpu_ns', 'wall_ns'):
            values[name + '_' + clock] = integer(native[leaf][clock])
    for clock in ('cpu_ns', 'wall_ns'):
        values['core_' + clock] = sum(integer(native[key][clock]) for key in CORE)
        values['ordinary_warm_' + clock] = integer(run['baseline'][clock]['warm_median'], positive=True)
        values['ordinary_cold_' + clock] = integer(run['baseline'][clock]['cold_preparation_plus_execution'], positive=True)
    values['child_cpu_ns'] = integer(run['process_observations']['child_cpu_ns'])
    values['child_wall_ns'] = integer(run['process_observations']['sequential_child_wall_ns'])
    values['supervisor_exchange_cpu_ns'] = integer(run['process_observations']['supervisor_exchange_cpu_ns'])
    for name, phase in (('product_consumption', 'direct_product_consumption'),
                        ('input_validation_and_optional_source_replay', 'input_validation_and_optional_source_replay'),
                        ('material_preparation', 'material_preparation')):
        values[name + '_cpu_ns'] = integer(run['phase_cpu_ns'][phase])
        values[name + '_wall_ns'] = integer(run['phase_wall_ns'][phase])
    values['consumer_run_tree_cpu_ns'] = integer(run['research_campaign_cost']['cpu_ns'])
    values['consumer_run_tree_wall_ns'] = integer(run['research_campaign_cost']['wall_ns'])
    values['outer_consumer_tree_cpu_ns'] = integer(outer['child_user_cpu_ns']) + integer(outer['child_system_cpu_ns'])
    values['outer_consumer_tree_wall_ns'] = integer(outer['wall_ns'])
    require(values['outer_consumer_tree_cpu_ns'] >= values['consumer_run_tree_cpu_ns'], 'OUTER_CPU_ENVELOPE')
    require(values['outer_consumer_tree_wall_ns'] >= values['consumer_run_tree_wall_ns'], 'OUTER_WALL_ENVELOPE')
    require(values['core_cpu_ns'] <= values['child_cpu_ns'] and values['core_wall_ns'] <= values['child_wall_ns'],
            'CORE_CHILD_ENVELOPE')
    return values


def baseline_ratios(values):
    return {scope + '_' + clock + '_to_ordinary_warm_' + clock:
            divide(values[scope + '_' + clock], values['ordinary_warm_' + clock])
            for scope in ('core', 'child') for clock in ('cpu_ns', 'wall_ns')}


def summarize_scenarios(cost, registry):
    collected = {}
    complete = {row['index'] for row in registry if row['status'] == 'complete_consistent_observation'}
    require({row['run_index'] for row in cost['scenarios']} == complete, 'SCENARIO_RUN_COVERAGE')
    for item in cost['scenarios']:
        index = item['run_index']
        run = cost['runs'][index]
        native = run['native_leaf_costs']
        names = set()
        for case in item['cases']:
            name = case['name']
            require(name not in names, 'DUPLICATE_SCENARIO')
            names.add(name)
            observers = integer(case['verifiers_assumed'], positive=True)
            stale = integer(case['stale_fraction_bps_assumed'])
            require(stale < 10000, 'NO_LIVE_SCENARIO')
            require(case['qualification'] is False and case['net_compute_benefit'] is None and
                    case['total_system_cpu_ns'] is None and case['wall_ns'] is None and
                    case['model_load_and_consumer_not_in_partial_work'] is True, 'SCENARIO_SCOPE')
            cpu = (native['producer_subtotal']['cpu_ns'] +
                   observers * native['native_first_verifier_subtotal']['cpu_ns'] +
                   native['typed_copy_subtotal']['cpu_ns'])
            cpu_ratio = {'numerator': cpu * 10000, 'denominator': 10000 - stale}
            proof_ratio = {'numerator': run['bytes']['proofs_all_cycles'] * observers * 10000,
                           'denominator': 10000 - stale}
            require(case['partial_work_cpu_ns_per_distinct_live_batch'] == cpu_ratio and
                    case['canonical_proof_fanout_bytes_per_distinct_live_batch'] == proof_ratio,
                    'SCENARIO_ARITHMETIC')
            settings = {'verifiers_assumed': observers, 'stale_fraction_bps_assumed': stale}
            if name not in collected:
                collected[name] = {'name': name, 'assumptions': settings, 'scope': case['scope'],
                                   'measured_global_population_or_stale_rate': False,
                                   'model_load_and_consumer_excluded': True,
                                   'columns': ['run_index', 'partial_cpu_ns_numerator', 'cpu_denominator',
                                               'proof_fanout_bytes_numerator', 'bytes_denominator'], 'rows': [],
                                   'total_system_cpu_ns': None, 'wall_ns': None, 'net_compute_benefit': None}
            entry = collected[name]
            require(entry['assumptions'] == settings and entry['scope'] == case['scope'], 'SCENARIO_IDENTITY')
            entry['rows'].append([index, cpu_ratio['numerator'], cpu_ratio['denominator'],
                                  proof_ratio['numerator'], proof_ratio['denominator']])
    for entry in collected.values():
        require({row[0] for row in entry['rows']} == complete, 'SCENARIO_CASE_COVERAGE')
    return list(collected.values())


def summarize_security(paths, material, source):
    entries, digests = [], {}
    for path in paths:
        report, sha = read(path)
        target = integer(report['execution_parameters']['target_index'])
        require(target in (0, 1) and str(target) not in digests, 'SECURITY_TARGET')
        digests[str(target)] = sha
        require(report['schema'] == 'pon-shared-material-security-v1' and report['status'] == 'complete', 'SECURITY_STATUS')
        require(report['source_execution'] == source, 'SECURITY_SOURCE')
        require(all(report[name] is False for name in ('cheapest_work_qualified', 'physical_recovery_qualified',
                                                      'public_service_qualified', 'production_activation')), 'SECURITY_CLAIMS')
        rows = report['results']
        require(len(rows) == 5 and [row['index'] for row in rows] == list(range(5)) and
                all(row['status'] == 'complete' for row in rows), 'SECURITY_TILE_COVERAGE')
        require([row['material_sha256'] for row in rows] == material['materials'], 'SECURITY_MATERIAL_BINDING')
        measured = [row['measurements'] for row in rows]
        require(all(set(row) == set(measured[0]) for row in measured), 'SECURITY_MEASUREMENT_FIELDS')
        totals = {key: sum(integer(row[key]) for row in measured) for key in measured[0] if key != 'cache_cpu_ns'}
        totals['cache_cpu_ns'] = {key: sum(integer(row['cache_cpu_ns'][key]) for row in measured)
                                  for key in measured[0]['cache_cpu_ns']}
        require(totals == report['totals'], 'SECURITY_TOTAL_ALIAS')
        ratio = divide(totals['raw_native_rejection_cpu_ns'], totals['attacker_cpu_ns'])
        require(float(ratio) == report['raw_native_to_attacker_cpu_ratio'], 'SECURITY_RATIO_ALIAS')
        child = sum(integer(row['child_user_cpu_ns']) + integer(row['child_system_cpu_ns']) for row in rows)
        supervisor = sum(integer(row['supervisor_cpu_ns']) for row in rows)
        entries.append({'target_index': target, 'cycles_per_tile': report['cycles'], 'planned_tiles': 5,
                        'totals': totals, 'raw_rejection_to_attacker_cpu_ratio': fraction(ratio),
                        'same_cpu_clock': True, 'attack_wall_cost_ns': None,
                        'cache_warm_to_cold_cpu_ratio': fraction(divide(totals['cache_cpu_ns']['warm'], totals['cache_cpu_ns']['cold'])),
                        'after_owner_recreation_to_cold_cpu_ratio': fraction(divide(totals['cache_cpu_ns']['after-owner-recreation'], totals['cache_cpu_ns']['cold'])),
                        'five_tile_workflow_cost': {'child_cpu_ns': child, 'supervisor_cpu_ns': supervisor,
                            'process_tree_cpu_ns': child + supervisor,
                            'sequential_whole_tile_wall_ns': sum(integer(row['wall_ns']) for row in rows),
                            'native_exchange_wall_ns_subset': sum(integer(row['native_exchange_wall_ns']) for row in rows)},
                        'scope': report['scope'], 'cache_scope': 'software exact-fact cache; owner recreation is not a physical power-loss recovery measurement',
                        'cost_scope': 'five tile workflows only; native subphases and exchange wall are contained, not extra additive costs',
                        'full_system_cost': None, 'qualification': False})
    require(set(digests) == {'0', '1'}, 'TWO_SECURITY_TARGETS_REQUIRED')
    return sorted(entries, key=lambda item: item['target_index']), digests


def summarize(args):
    cost, cost_sha = read(args.cost_readback)
    campaign, campaign_sha = read(args.campaign_dir / 'campaign.json')
    plan, plan_sha = read(args.campaign_dir / 'plan.json')
    require(cost['schema'] == 'pon-shared-material-total-cost-v2' and len(cost['runs']) == 31, 'COST_COHORT')
    require(cost['status'] == 'incomplete_local_observations', 'EXHAUSTION_MUST_REMAIN_INCOMPLETE')
    require(cost['qualification'] is False and cost['production_activation'] is False and
            cost['full_system_cost'] is None and cost['net_compute_benefit'] is None, 'COST_CLAIMS')
    require(bool(cost['coverage']) and all(value is None for value in cost['coverage'].values()), 'UNKNOWN_GLOBAL_MUST_STAY_NULL')
    require(campaign['schema'] == plan['schema'] == 'pon-shared-material-campaign-v2' and
            campaign['source'] == plan['source'] and campaign['all_declared_outcomes_observed'] is True, 'CAMPAIGN_BINDING')
    require(len(campaign['observations']) == len(plan['cases']) == 31, 'CAMPAIGN_COVERAGE')
    require(plan['model_training'] is False and plan['model_adoption'] is False and
            plan['original_4s_16_hostile_gate_qualified'] is False, 'CAMPAIGN_CLAIMS')
    source = cost['runs'][0]['source']
    require(source['git_head'] == campaign['source']['commit'] and source['git_head_tree'] == campaign['source']['tree'] and
            source['native_runner_sha256'] == campaign['source']['runner_sha256'] and source['dirty_porcelain'] == '', 'FROZEN_SOURCE')
    material = cost['runs'][0]['material_identity']
    require(material['selected_tasks']['rows'] == 64 and cost['distinct_material_cohorts_observed'] == 1 and
            cost['distinct_material_batches_across_all_arms'] == 1 and cost['additional_useful_output_credit_from_cycles_or_arms'] == 0,
            'USEFUL_OUTPUT_CREDIT')
    registry, arms, pair_members, outputs = [], {}, {}, set()
    process_digests, complete_indices, incomplete_indices = {}, [], []
    for index, (run, expected, observed) in enumerate(zip(cost['runs'], plan['cases'], campaign['observations'])):
        name = Path(run['directory']).name
        require(name == expected['name'] == observed['name'] and observed['index'] == index, 'CASE_INDEX_BINDING')
        outer, process_sha = read(args.campaign_dir / (name + '.process.json'))
        require(outer == observed, 'CAMPAIGN_PROCESS_ALIAS')
        process_digests[name] = process_sha
        require(run['source'] == source and run['material_identity'] == material, 'RUN_COHORT_BINDING')
        require(run['full_system_cost'] is None and run['net_compute_benefit'] is None and run['qualification'] is False,
                'RUN_CLAIMS')
        parameters = run['parameters']
        for field, planned in (('target_index', 'target'), ('arithmetic', 'arithmetic'), ('preparation', 'preparation'),
                               ('cycles', 'cycles'), ('verifiers', 'verifiers'), ('max_attempts', 'max_attempts')):
            require(parameters[field] == expected[planned], 'RUN_PLAN_BINDING:' + field)
        require(parameters['seed'] == plan['seed'] and parameters['baseline_repetitions'] == plan['baseline_repetitions'], 'RUN_SEED_BASELINE_BINDING')
        match = PAIRED.fullmatch(name)
        kind = 'paired' if match else 'fanout' if name.startswith('fanout-') else 'reuse' if name.startswith('reuse-') else 'exhaustion'
        row = {'index': index, 'name': name, 'kind': kind, 'round': int(match[1]) if match else None,
               'status': run['status'], 'target_index': parameters['target_index'],
               'arithmetic': parameters['arithmetic'], 'preparation': parameters['preparation'],
               'verifiers': parameters['verifiers'], 'cycles': parameters['cycles'],
               'max_attempts_per_search': parameters['max_attempts'],
               'returncode': outer['returncode'], 'outcome_kind': outer['outcome_kind'],
               'observation_fingerprint': run['record_fingerprint'],
               'outer_consumer_tree_cpu_ns': integer(outer['child_user_cpu_ns']) + integer(outer['child_system_cpu_ns']),
               'outer_consumer_tree_wall_ns': integer(outer['wall_ns'])}
        if run['status'] == 'complete_consistent_observation':
            require(expected['expected_exit'] == outer['returncode'] == 0 and outer['outcome_kind'] == 'complete', 'COMPLETE_OUTCOME')
            require(run['distinct_application_batches_credited'] == 1, 'COMPLETE_CREDIT')
            complete_indices.append(index)
            outputs.add(run['application_output_sha256'])
            values = complete_metrics(run, outer)
            ratios = baseline_ratios(values)
            row.update(attempts=run['attempts'], misses=run['misses'], winning_proofs=run['winning_proofs'],
                       full_native_verifier_calls=run['full_native_verifier_calls'],
                       distinct_output_from_this_replay=1, additional_distinct_output_across_campaign=0,
                       mathematical_stream_sha256=run['mathematical_stream_sha256'],
                       application_output_sha256=run['application_output_sha256'],
                       nanoseconds=values, bytes=run['bytes'],
                       ordinary_warm_ratios={key: fraction(value) for key, value in ratios.items()})
            require(run['winning_proofs'] == 5 * parameters['cycles'] and
                    run['full_native_verifier_calls'] == 5 * parameters['cycles'] * parameters['verifiers'], 'ACTUAL_REPLAY_CALLS')
            if match:
                require((int(match[2]), match[3], match[4]) ==
                        (row['target_index'], row['arithmetic'], row['preparation']), 'PAIRED_NAME')
                key = (row['target_index'], row['arithmetic'], row['preparation'])
                arms.setdefault(key, []).append(row)
                pair_key = (row['target_index'], row['arithmetic'], row['round'])
                require(row['preparation'] not in pair_members.setdefault(pair_key, {}), 'DUPLICATE_PAIR_ARM')
                pair_members[pair_key][row['preparation']] = row
        else:
            require(kind == 'exhaustion' and run['status'] == 'incomplete' and run['distinct_application_batches_credited'] == 0 and
                    outer['returncode'] == expected['expected_exit'] == 2 and
                    outer['outcome_kind'] == 'expected_bounded_search_exhaustion', 'EXHAUSTION_OUTCOME')
            incomplete_indices.append(index)
            row.update(distinct_output_from_this_replay=0, additional_distinct_output_across_campaign=0,
                       missing_tiles=run['not_observed_tiles'], partial_processes=run['partial_processes'],
                       partial_native_child_cpu_ns=run['observed_partial_child_cpu_ns'],
                       partial_sequential_native_child_wall_ns=run['observed_partial_sequential_child_wall_ns'],
                       observed_partial_supervisor_cpu_ns=run['observed_partial_supervisor_cpu_ns'],
                       observed_elapsed_wall_ns=run['observed_elapsed_wall_ns'],
                       full_internal_attempt_coverage='unknown', full_system_cost=None)
        registry.append(row)
    require(len(complete_indices) == 30 and len(incomplete_indices) == 1 and len(outputs) == 1, 'EXACT_CAMPAIGN_COUNTS')
    require(len(arms) == 8 and len(pair_members) == 12, 'EXACT_PAIRED_COVERAGE')
    arm_stats = []
    for (target, arithmetic, preparation), members in sorted(arms.items()):
        members.sort(key=lambda item: item['round'])
        require([row['round'] for row in members] == [0, 1, 2], 'THREE_DISTINCT_ROUNDS')
        keys = members[0]['ordinary_warm_ratios']
        arm_stats.append({'target_index': target, 'arithmetic': arithmetic, 'preparation': preparation,
                          'run_indices_in_round_order': [row['index'] for row in members],
                          'nanoseconds': {key: ns_stats([row['nanoseconds'][key] for row in members]) for key in ARM_METRICS},
                          'ordinary_warm_ratio_stats': {key: ratio_stats([Fraction(row['ordinary_warm_ratios'][key]['numerator'],
                                                                                 row['ordinary_warm_ratios'][key]['denominator'])
                                                                        for row in members]) for key in keys}})
    paired_ratios = []
    for target in (0, 1):
        for arithmetic in ('full-limb', 'transposed'):
            rounds, all_ratios = [], {key: [] for key in PAIR_METRICS}
            for repeat in range(3):
                pair = pair_members[(target, arithmetic, repeat)]
                require(set(pair) == {'dense', 'sparse'}, 'PAIR_COVERAGE')
                dense, sparse = pair['dense'], pair['sparse']
                require(dense['mathematical_stream_sha256'] == sparse['mathematical_stream_sha256'], 'PAIRED_LOTTERY_STREAM')
                ratios = {key: divide(sparse['nanoseconds'][key], dense['nanoseconds'][key]) for key in PAIR_METRICS}
                rounds.append({'round': repeat, 'dense_index': dense['index'], 'sparse_index': sparse['index'],
                               'sparse_over_dense': {key: fraction(value) for key, value in ratios.items()}})
                for key, value in ratios.items():
                    all_ratios[key].append(value)
            paired_ratios.append({'target_index': target, 'arithmetic': arithmetic, 'rounds': rounds,
                                  'paired_ratio_stats': {key: ratio_stats(values) for key, values in all_ratios.items()}})
    security, security_digests = summarize_security(args.security_report, material, source)
    audit, audit_sha = read(args.audit_controls)
    audit_log = args.audit_log.read_bytes()
    audit_log_sha = hashlib.sha256(audit_log).hexdigest()
    require(audit['returncode'] == 0 and audit['log_sha256'] == audit_log_sha and
            b'Ran 61 tests' in audit_log and b'\nOK\n' in audit_log and b'skipped' not in audit_log, 'AUDIT_CONTROL_BINDING')
    paired_indices = [row['index'] for row in registry if row['kind'] == 'paired']
    ranges = {}
    for key in registry[0]['ordinary_warm_ratios']:
        values = [Fraction(registry[index]['ordinary_warm_ratios'][key]['numerator'],
                           registry[index]['ordinary_warm_ratios'][key]['denominator']) for index in paired_indices]
        ranges[key] = {'min': fraction(min(values)), 'max': fraction(max(values))}
    return {
        'schema': SCHEMA, 'status': cost['status'],
        'input_sha256': {'cost_readback': cost_sha, 'campaign': campaign_sha, 'plan': plan_sha,
                         'campaign_case_processes': process_digests, 'security_reports_by_target': security_digests,
                         'audit_controls_metadata': audit_sha, 'audit_controls_log': audit_log_sha,
                         'summary_script': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'frozen_execution_source': source, 'frozen_input_file_sha256': campaign['source']['inputs_sha256'],
        'execution_context': {'seed': plan['seed'], 'baseline_repetitions': plan['baseline_repetitions'],
                              'target_hex_by_index': {str(row['parameters']['target_index']): row['parameters']['target']
                                                      for row in cost['runs']},
                              'verifier_scope': 'same_process_sequential_full_replay'},
        'material_identity': material, 'application_output_sha256': next(iter(outputs)),
        'paired_mathematical_streams': cost['paired_mathematical_streams'],
        'counts': {'runs': 31, 'complete': 30, 'incomplete_exhaustion': 1, 'paired': 24,
                   'fanout': 4, 'reuse': 2, 'unique_material_batches': 1, 'requests_in_unique_batch': 64,
                   'new_batches_of_demand_from_repetitions': 0},
        'statistics': {'time_unit': 'nanoseconds', 'ratios': 'exact numerator/denominator; CPU/CPU or wall/wall only',
                       'arm_summary': 'three separate observed repetitions: min, median, max',
                       'paired_summary': 'median of the three per-round sparse/dense ratios; never ratio of arm medians',
                       'uncertainty': 'finite shared-host observations; no confidence interval, independent replication, or qualification'},
        'cost_scopes': {
            'core': 'local producer (setup plus all attempts/searches) + all measured native verifier calls + typed product copy',
            'core_exclusions': 'scalar reference, diagnostic record build/serialization, Python consumer, input/model load, process overhead, WAN, other independent validators, real stales/competing miners, energy',
            'child': 'full native child observation including local diagnostics and process overhead',
            'consumer_run_tree': 'consumer.run() through before final report write; excludes Python startup/import/exit; parent plus all children once',
            'outer_consumer_tree': 'full observed consumer process tree including startup/import/exit; includes inner consumer and native work; never add those again',
            'subset_aliases': 'setup is inside producer; all native/diagnostic work is inside child; child is inside consumer/outer scope; these columns are not additive',
            'output_credit': 'one fixed 64-request material cohort and one output; 30 completed observations are research repetitions, not 30 new service batches'},
        'runs': registry, 'arm_statistics': arm_stats, 'paired_sparse_over_dense': paired_ratios,
        'paired_same_clock_ordinary_ratio_ranges': ranges,
        'fanout_run_indices': [row['index'] for row in registry if row['kind'] == 'fanout'],
        'fanout_scope': 'N=3/8 are actual sequential full replay calls in one process; independent-validator population remains unknown',
        'reuse_run_indices': [row['index'] for row in registry if row['kind'] == 'reuse'],
        'reuse_scope': 'four challenge cycles reexecute the same material output; 20 winning proofs do not create four useful business batches',
        'exhaustion_run_indices': incomplete_indices,
        'outer_research_case_cost': {
            'run_indices': list(range(31)), 'process_tree_cpu_ns': sum(row['outer_consumer_tree_cpu_ns'] for row in registry),
            'sequential_case_wall_ns': sum(row['outer_consumer_tree_wall_ns'] for row in registry),
            'scope': 'sum of 31 separately observed consumer case envelopes, including exhaustion; excludes campaign-driver overhead, intercase gaps, security experiment, builds and reader audits; not a single-inference cost'},
        'hypothetical_scenarios': summarize_scenarios(cost, registry), 'security': security,
        'measurement_limitations': {
            'host_scope': plan['hardware_scope'], 'shared_host_background_load_controlled': False,
            'audit_tests': 61, 'audit_skipped': 0, 'audit_started_utc': audit['started_utc'],
            'audit_finished_utc': audit['finished_utc'], 'audit_wall_ns': audit['wall_ns'],
            'audit_overlap_reported_during_campaign': True, 'affected_run_indices': None,
            'overlap_scope': 'recorded read-only audit window; per-case absolute intervals are not in the campaign records, so affected cases are not inferred',
            'noise_attribution': 'audit overlap is one recorded concurrent activity, not the sole known or inferred source of shared-host variability'},
        'unknown_global': cost['coverage'], 'model_training': False, 'model_adoption': False,
        'model_reward_recomputed': False, 'original_4s_16_hostile_gate_qualified': False,
        'full_system_cost': None, 'net_compute_benefit': None, 'qualification': False, 'production_activation': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cost-readback', type=Path, required=True)
    parser.add_argument('--campaign-dir', type=Path, required=True)
    parser.add_argument('--security-report', type=Path, action='append', required=True)
    parser.add_argument('--audit-controls', type=Path, required=True)
    parser.add_argument('--audit-log', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args)
    with args.out.open('x') as stream:
        json.dump(result, stream, sort_keys=True, separators=(',', ':'), allow_nan=False)
        stream.write('\n')
    print(json.dumps({'schema': SCHEMA, 'counts': result['counts'], 'qualification': False,
                      'output_sha256': hashlib.sha256(args.out.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
