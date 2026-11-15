#!/usr/bin/env python3
"""Predeclared actual-SHA nonce-bank experiment, with separately billed audit."""
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction as F
from hashlib import sha256
from pathlib import Path
from time import perf_counter_ns
import json
import sys
from research_core import (BASE, baseline, ref, PreparedBankTask, evaluate_gate,
                           bank_order, witness_bytes)
from bank_policy import optimal_batch, online_penalty_identity_search
from upstream.selector_policy_r3 import fraction_record, CacheModel, finite_penalty


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+'\n')


def assert_sources():
    manifest = json.loads((BASE/'SOURCE_PINS.json').read_text())
    for name, record in manifest['files'].items():
        if sha256((BASE/name).read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('PIN_MISMATCH:'+name)


def load_inputs():
    expected_bytes = (BASE/'upstream/reference/real_lottery_hit_p_1_64.expected.bin').read_bytes()
    ctx = ref.Expected(*(expected_bytes[i:i+32] for i in range(0,192,32)))
    a = baseline.decode_task((BASE/'upstream/reference/structured-a.bin').read_bytes())
    b = baseline.decode_task((BASE/'upstream/reference/structured-b.bin').read_bytes())
    return ctx, a, b


def combined(recorder, task):
    values = recorder.counts()
    values['scalar_multiplications'] += task.field.multiplications
    values['scalar_additions'] += task.field.additions
    values['field_equality_checks'] = task.field.comparisons
    values['recognition_words'] = task.field.recognition_words
    values['compiled_table_reads'] = task.field.table_field_reads
    values['useful_product_acquisitions'] = task.product_acquisitions
    return values


def difference(a, b):
    return {k: a[k]-b[k] for k in a}


def deep_size(value, seen=None):
    """Reachable CPython object size, not allocator/RSS/global resource bound."""
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    total = sys.getsizeof(value)
    if isinstance(value, dict):
        total += sum(deep_size(k, seen)+deep_size(v, seen) for k,v in value.items())
    elif isinstance(value, (list, tuple, set, frozenset)):
        total += sum(deep_size(x, seen) for x in value)
    elif hasattr(value, '__dict__'):
        total += deep_size(vars(value), seen)
    return total


def hash_prefix_replay(recorder):
    start = perf_counter_ns()
    prefix = baseline.BoundedPrefixSHA256()
    for message, tag in zip(recorder.messages, recorder.tags):
        if prefix.digest(message, tag) != sha256(message).digest():
            raise AssertionError('SHA_PREFIX_MISMATCH')
    return {'compressions': prefix.compressions,
            'digest_comparisons': len(recorder.messages), 'payload': prefix.payload(),
            'replay_ns': perf_counter_ns()-start,
            'part_of_measured_hashlib_producer': False,
            'interpretation': 'separate executable attainable compression schedule, never a SHA lower bound'}


def run_strategy(name, global_affine, bank, cache_mode, plan):
    directory = BASE/'results'/name
    directory.mkdir(parents=True, exist_ok=False)
    (directory/'witnesses').mkdir()
    recorder = baseline.Recorder()
    start = perf_counter_ns()
    with recorder.active():
        ctx, a, b = load_inputs()
        task = PreparedBankTask(a, b, global_affine=global_affine)
    setup_ns = perf_counter_ns()-start
    setup_counts = combined(recorder, task)
    setup_field = task.field.snapshot()
    setup_messages = len(recorder.messages)
    gate_start = perf_counter_ns()
    gates, gate_records, buckets, operations = [], [], {}, {}
    if bank:
        with recorder.active():
            gates = [evaluate_gate(ctx, n) for n in
                     range(plan['nonce_start_inclusive'], plan['nonce_end_exclusive'])]
        ordered, buckets = bank_order(gates, operations)
        bank_bytes = b''.join(g.encode() for g in gates)
        order_bytes = b''.join(g.nonce.to_bytes(8,'little') for g in ordered)
        (directory/'selector_bank.bin').write_bytes(bank_bytes)
        (directory/'selector_order.bin').write_bytes(order_bytes)
        seal = {'sealed_utc_before_any_ticket': datetime.now(timezone.utc).isoformat(),
                'plan_sha256': sha256((BASE/'EXPERIMENT_PLAN.json').read_bytes()).hexdigest(),
                'bank_sha256': sha256(bank_bytes).hexdigest(),
                'order_sha256': sha256(order_bytes).hexdigest(),
                'gates': len(gates), 'nonempty_coordinates': len(buckets),
                'bucket_counts': [{'coordinate': list(k), 'count': len(v)} for k,v in sorted(buckets.items())],
                'uses_ticket_information': False}
        write_json(directory/'selector_seal.json', seal)
        gate_records = [{'nonce':g.nonce, 'seed':g.seed.hex(), 'coordinate':list(g.coordinate)} for g in gates]
    else:
        ordered = range(plan['nonce_start_inclusive'], plan['nonce_end_exclusive'])
        seal = None
    prepaid_gate_ns = perf_counter_ns()-gate_start
    after_gate_counts = combined(recorder, task)
    after_gate_messages = len(recorder.messages)
    producer_reachable_size = deep_size((ctx, task, gates, ordered, buckets))
    cache_coordinate, cached_product = None, None
    cache_reads = cache_hits = cache_writes = cache_evictions = 0
    rows, attempted_bytes = [], {}
    winner = None
    continuation_start = perf_counter_ns()
    for item in ordered:
        before = combined(recorder, task)
        before_messages = len(recorder.messages)
        attempt_start = perf_counter_ns()
        with recorder.active():
            gate = item if bank else evaluate_gate(ctx, item)
            if not bank:
                gate_records.append({'nonce':gate.nonce, 'seed':gate.seed.hex(), 'coordinate':list(gate.coordinate)})
            hit = False
            if cache_mode != 'none':
                cache_reads += 1
                hit = gate.coordinate == cache_coordinate
            if hit:
                cache_hits += 1
                useful = cached_product
            else:
                useful = task.product(gate.coordinate)
                if cache_mode == 'replace' or (cache_mode == 'retain_first' and cached_product is None):
                    cache_evictions += int(cached_product is not None)
                    cached_product, cache_coordinate = useful, gate.coordinate
                    cache_writes += 1
            witness = task.continue_gate(ctx, gate, useful)
            event = ref.statement(ctx, witness)
            ticket = ref.H(b'ticket', event)
        attempt_ns = perf_counter_ns()-attempt_start
        raw = witness_bytes(witness)
        row = {'ordinal':len(rows), 'nonce':gate.nonce, 'coordinate':list(gate.coordinate),
               'cache_hit':hit, 'event':event.hex(), 'ticket':ticket.hex(),
               'target_passes':ticket<=ctx.target,
               'witness_sha256':sha256(raw).hexdigest(),
               'candidate_counts':difference(combined(recorder, task), before),
               'candidate_tag_counts':dict(Counter(recorder.tags[before_messages:])),
               'instrumented_producer_phase_ns':attempt_ns}
        rows.append(row)
        attempted_bytes[gate.nonce] = raw
        (directory/'witnesses'/f'nonce-{gate.nonce}.bin').write_bytes(raw)
        if row['target_passes']:
            winner = gate.nonce
            break
    continuation_ns = perf_counter_ns()-continuation_start
    whole_counts = combined(recorder, task)
    prefix = hash_prefix_replay(recorder)
    counter = Counter(recorder.tags)
    candidate_set = set(attempted_bytes)
    for row in gate_records:
        row['attempted'] = row['nonce'] in candidate_set
    write_json(directory/'gates.json', gate_records)
    write_json(directory/'attempts.json', rows)
    useful_cache_bytes = 256 if cached_product is not None else 0
    summary = {
        'name':name, 'global_affine':global_affine, 'bank':bank, 'cache_mode':cache_mode,
        'gates_paid':len(gate_records), 'attempts':len(rows),
        'failed_attempts':len(rows)-int(winner is not None), 'winner_nonce':winner,
        'paid_but_unattempted_selectors':len(gate_records)-len(rows),
        'useful_product_acquisitions':task.product_acquisitions,
        'setup_counts':setup_counts, 'setup_field_detail':setup_field,
        'prepaid_gate_counts':difference(after_gate_counts, setup_counts),
        'whole_campaign_counts':whole_counts,
        'sha_tag_counts':dict(counter), 'bounded_prefix_replay':prefix,
        'sampler_digest_calls':counter['noise-eight'],
        'all_observed_samplers_used_one_digest':counter['noise-eight']==32*len(rows),
        'bank_operations':operations,
        'cache_operations':{'lookups':cache_reads, 'hits':cache_hits, 'writes':cache_writes, 'evictions':cache_evictions},
        'payload':{'original_inputs':32768, 'expected_context':192, 'merkle_digests':8128,
                   'compiled_field_words':1316 if global_affine else 0,
                   'selector_records':43*len(gates), 'explicit_order_nonce_list':8*len(gates),
                   'cached_useful_result':useful_cache_bytes,
                   'coordinate_key':3 if useful_cache_bytes else 0,
                   'one_candidate_wire':1419,
                   'raw_input_parse_temporaries_and_compression_workspace_included':False,
                   'python_producer_reachable_size_after_bank':producer_reachable_size,
                   'python_size_is_not_RSS_or_total_allocator_usage':True,
                   'separate_evidence_recorders_and_saved_witness_files_not_producer_cache':True},
        'instrumented_phase_ns':{'input_load_and_setup':setup_ns,
                                  'bank_gates_and_sort_and_seal_logging':prepaid_gate_ns,
                                  'continuations_and_attempt_logging':continuation_ns},
        'wall_times_are_not_native_performance_or_lower_bounds':True,
        'setup_hash_messages':setup_messages,
        'prepaid_gate_hash_messages':after_gate_messages-setup_messages,
        'selection_sealed_before_ticket':seal is not None,
        'qualification':'RESEARCH_ONLY_HOLD_NO_GO'}
    write_json(directory/'result.json', summary)
    return summary, attempted_bytes


def validation_audit(strategy_results, attempted_by_strategy, plan):
    """Separate full-range audit; never free producer advice or lottery cost."""
    start = perf_counter_ns()
    ctx, a, b = load_inputs()
    all_rows, hits = [], []
    comparisons = 0
    out = BASE/'results/full_range_audit'
    out.mkdir(exist_ok=False)
    (out/'accepted_witnesses').mkdir()
    recorder = baseline.Recorder()
    with recorder.active():
        prepared = baseline.Prepared(a, b)
        for nonce in range(plan['nonce_start_inclusive'], plan['nonce_end_exclusive']):
            witness = prepared.produce(ctx, nonce)
            event = ref.statement(ctx, witness)
            ticket = ref.H(b'ticket', event)
            raw = witness_bytes(witness)
            for name, values in attempted_by_strategy.items():
                if nonce in values:
                    if raw != values[nonce]:
                        raise AssertionError('COMPLETE_WITNESS_MISMATCH:'+name+':'+str(nonce))
                    comparisons += 1
            row = {'nonce':nonce,'coordinate':[witness.bi,witness.bk,witness.bj],
                   'event':event.hex(),'ticket':ticket.hex(),'target_passes':ticket<=ctx.target,
                   'witness_sha256':sha256(raw).hexdigest()}
            all_rows.append(row)
            if row['target_passes']:
                hits.append(nonce)
                (out/'accepted_witnesses'/f'nonce-{nonce}.bin').write_bytes(raw)
    # Frozen original unprepared producer is a distinct check, with its tree
    # recomputation fully recorded as audit work, not billed to any strategy.
    reference_meter = baseline.Recorder()
    with reference_meter.active():
        for nonce in range(plan['nonce_start_inclusive'], plan['nonce_end_exclusive']):
            original = ref.produce(ctx, nonce, a, b)
            row = all_rows[nonce-plan['nonce_start_inclusive']]
            if sha256(witness_bytes(original)).hexdigest() != row['witness_sha256']:
                raise AssertionError('ORIGINAL_PRODUCER_MISMATCH')
            for name, values in attempted_by_strategy.items():
                if nonce in values and witness_bytes(original) != values[nonce]:
                    raise AssertionError('ORIGINAL_COMPLETE_BYTES_MISMATCH:'+name)
    assert comparisons == sum(s['attempts'] for s in strategy_results)
    write_json(out/'candidates.json', all_rows)
    result = {'nonce_start':plan['nonce_start_inclusive'], 'nonce_end':plan['nonce_end_exclusive'],
              'full_range_dense_candidates':len(all_rows), 'all_full_range_dense_against_frozen_producer':True,
              'strategy_complete_witness_byte_comparisons':comparisons,
              'accepted_nonces':hits,
              'prepared_dense_audit_counts':recorder.counts(),
              'original_unprepared_audit_counts':reference_meter.counts(),
              'instrumented_audit_ns':perf_counter_ns()-start,
              'audit_work_included_in_mining_costs':False,
              'audit_results_read_by_strategy':False}
    write_json(out/'result.json', result)
    return result


def policy_results():
    p, alpha, penalty = F(1,2), F(3,4), F(202)
    model = CacheModel(2,1,p,F(1),F(1),F(100))
    old = finite_penalty(model,3,penalty)[0]['value']
    identity = online_penalty_identity_search(2,3,p,1,1,100,1,penalty)
    assert old == identity == F(1281,8)
    return {'schema':'selected-bank-finite-iid-results-r4-v1',
            'concrete_SHA_independence_claim':False,
            'strict_old_online_counterexample':{
                'D':2,'capacity':1,'draw_cap':3,'p':fraction_record(p),
                'gate':1,'continuation':1,'uncached_useful':100,
                'required_success':fraction_record(alpha),'lambda':202,
                'old_class_penalized_optimum':fraction_record(old),
                'old_class_cost_lower_bound':fraction_record(old-penalty*(1-alpha)),
                'bank_policy_cost':fraction_record(F(209,2)),
                'bank_policy_success':fraction_record(alpha),
                'strict_gap':fraction_record(F(41,8)),
                'construction':'pay three selectors, pick most frequent coordinate (lexicographic tie), attempt its first two nonce records'},
            'illustrative_fixed_batch':{
                key:(list(value) if key=='order' else fraction_record(value))
                for key,value in optimal_batch((5,2,1),(512,512,512),F(1,64),1580).items()},
            'all_physical_strategy_lower_bound_claim':False}


def main():
    assert_sources()
    plan = json.loads((BASE/'EXPERIMENT_PLAN.json').read_text())
    source_pins = {str(p.relative_to(BASE)):sha256(p.read_bytes()).hexdigest()
                   for p in [BASE/'EXPERIMENT_PLAN.json',BASE/'SOURCE_PINS.json',BASE/'research_core.py',
                             BASE/'bank_policy.py',BASE/'run_campaign.py',BASE/'test_research.py']}
    write_json(BASE/'results/EXECUTED_SOURCE_PINS.json', source_pins)
    # Prepaid bank runs first. No full-range ticket trace exists at that point.
    specifications = [('dense_bank_cache1',False,True,'replace'),
                      ('global_affine_bank_cache1',True,True,'replace'),
                      ('dense_online_direct',False,False,'none'),
                      ('dense_online_cache1',False,False,'retain_first'),
                      ('global_affine_online',True,False,'none')]
    summaries, attempted = [], {}
    for args in specifications:
        summary, raw = run_strategy(*args, plan)
        summaries.append(summary)
        attempted[args[0]] = raw
        print(json.dumps({'strategy':args[0],'gates':summary['gates_paid'],
                          'attempts':summary['attempts'],'winner':summary['winner_nonce'],
                          'useful_products':summary['useful_product_acquisitions'],
                          'prefix_compressions':summary['bounded_prefix_replay']['compressions']}),flush=True)
    audit = validation_audit(summaries, attempted, plan)
    write_json(BASE/'results/policy_result.json', policy_results())
    write_json(BASE/'results/campaign_result.json', {
        'schema':'selected-nonce-bank-actual-SHA-observation-r4-v1',
        'generated_utc':datetime.now(timezone.utc).isoformat(),
        'source_pins':source_pins, 'plan':plan, 'strategies':summaries, 'audit':audit,
        'iid_theorem_applied_to_concrete_SHA':False,
        'whole_W1_or_STARK_or_production_acceptance_claim':False})
    print(json.dumps({'audit_accepted_nonces':audit['accepted_nonces'],
                      'full_byte_comparisons':audit['strategy_complete_witness_byte_comparisons']}),flush=True)


if __name__ == '__main__':
    main()
