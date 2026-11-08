#!/usr/bin/env python3
"""Fresh exact selected-event strategy experiment, all finite attempts retained."""
from datetime import datetime, timezone
from fractions import Fraction as F
from hashlib import sha256
from pathlib import Path
import json
import sys
sys.dont_write_bytecode = True
from frontier import BASE, baseline, ref, FrontierPrepared, witness_bytes
from selector_policy import (CacheModel, optimal_cache, finite_penalty, fraction_record,
                             lazy_expected_products, cache_until_first_hit_expected_products,
                             finite_success_lower_bound)


def combined(recorder, prepared):
    result = recorder.counts()
    result['scalar_multiplications'] += prepared.arithmetic.multiplications
    result['scalar_additions'] += prepared.arithmetic.additions
    result['field_equality_checks'] = prepared.arithmetic.comparisons
    result['recognition_words'] = prepared.arithmetic.recognition_words
    return result


def verify_upstream():
    manifest = json.loads((BASE/'UPSTREAM_SOURCE.json').read_text())
    for name, digest in manifest['files'].items():
        if sha256((BASE/'upstream'/name).read_bytes()).hexdigest() != digest:
            raise ValueError('UPSTREAM_CHANGED:'+name)
    return sha256((BASE/'UPSTREAM_SOURCE.json').read_bytes()).hexdigest()


def run_campaign(draws=512):
    expected, old_w = baseline.decode_fixture(
        (BASE/'upstream/reference/real_lottery_hit_p_1_64.expected.bin').read_bytes(),
        (BASE/'upstream/reference/real_lottery_hit_p_1_64.witness.bin').read_bytes())
    a = baseline.decode_task((BASE/'upstream/reference/structured-a.bin').read_bytes())
    b = baseline.decode_task((BASE/'upstream/reference/structured-b.bin').read_bytes())
    strategy_specs = [('dense_direct','dense','none',512),
                      ('dense_eager','dense','eager',512),
                      ('dense_lazy_full','dense','lazy',512),
                      ('dense_lazy_16','dense','lazy',16),
                      ('affine_direct','affine','none',512),
                      ('affine_lazy_full','affine','lazy',512),
                      ('affine_eager','affine','eager',512)]
    canonical_rows = []
    canonical_witnesses = []
    runs = []
    prefix = baseline.BoundedPrefixSHA256()
    prefix_horizons = {}
    for name, arithmetic, cache, cap in strategy_specs:
        prep_meter = baseline.Recorder()
        with prep_meter.active():
            prepared = FrontierPrepared(a,b,arithmetic=arithmetic,cache=cache,capacity=cap)
        preparation = combined(prep_meter, prepared)
        arithmetic_at_prep = prepared.arithmetic.snapshot()
        cached_at_prep = prepared.cache_record()
        run_meter = baseline.Recorder()
        horizons = {}
        verified_hits = 0
        if name == 'dense_direct':
            for message, tag in zip(prep_meter.messages, prep_meter.tags):
                assert prefix.digest(message,tag) == sha256(message).digest()
            prefix_horizons['preparation'] = prefix.compressions
        for nonce in range(draws):
            old_count = len(run_meter.messages)
            with run_meter.active():
                witness = prepared.produce(expected, nonce)
                event = ref.statement(expected, witness)
                ticket = ref.H(b'ticket',event)
            row = {'nonce':nonce, 'coordinate':[witness.bi,witness.bk,witness.bj],
                   'witness_sha256':sha256(witness_bytes(witness)).hexdigest(),
                   'event':event.hex(),'ticket':ticket.hex(),
                   'ticket_passes':ticket <= expected.target}
            if name == 'dense_direct':
                canonical_rows.append(row)
                canonical_witnesses.append(witness_bytes(witness))
                for message, tag in zip(run_meter.messages[old_count:],run_meter.tags[old_count:]):
                    assert prefix.digest(message,tag) == sha256(message).digest()
                if nonce+1 in (1,45,128,512):
                    prefix_horizons[str(nonce+1)] = prefix.compressions
            elif row != canonical_rows[nonce] or witness_bytes(witness) != canonical_witnesses[nonce]:
                raise AssertionError('STRATEGY_OUTPUT_MISMATCH:'+name+':'+str(nonce))
            if row['ticket_passes']:
                accepted = ref.verify(expected,witness)
                assert accepted.event_id == event and accepted.ticket == ticket
                verified_hits += 1
            if nonce == old_w.nonce:
                assert witness_bytes(witness) == witness_bytes(old_w)
            if nonce+1 in (1,45,128,512):
                totals = combined(run_meter,prepared)
                totals['scalar_multiplications'] += preparation['scalar_multiplications']-arithmetic_at_prep['multiplications']
                totals['scalar_additions'] += preparation['scalar_additions']-arithmetic_at_prep['additions_including_subtractions']
                for k in ('sha256_calls','sha256_input_bytes','sha256_compression_blocks'):
                    totals[k] += preparation[k]
                horizons[str(nonce+1)] = {'whole_campaign':totals,'cache':prepared.cache_record()}
        runs.append({'name':name,'preparation':preparation,'cache_after_preparation':cached_at_prep,
                     'horizons':horizons,'fresh_acceptance_replays':verified_hits,
                     'all_witnesses_match_dense_direct':True})
    first_hit = next((r['nonce'] for r in canonical_rows if r['ticket_passes']),None)
    out = BASE/'results'
    out.mkdir(exist_ok=True)
    (out/'candidate_rows.json').write_text(json.dumps(canonical_rows,indent=2)+'\n')
    return {'schema':'selected-legal-cost-frontier-observation-v1',
            'generated_utc':datetime.now(timezone.utc).isoformat(),
            'upstream_manifest_sha256':verify_upstream(),
            'draws_per_strategy':draws,'strategies':runs,
            'target_probability':fraction_record(F(int.from_bytes(expected.target,'big')+1,2**256)),
            'first_hit_nonce':first_hit,
            'accepted_nonces':[r['nonce'] for r in canonical_rows if r['ticket_passes']],
            'distinct_coordinates':len({tuple(r['coordinate']) for r in canonical_rows}),
            'sha256_bounded_prefix_whole_campaign_compressions':prefix_horizons,
            'sha256_bounded_prefix_digest_checks':len(prefix_horizons)>0,
            'native_timing_claim':False,'all_strategy_physical_lower_bound_claim':False,
            'same_old_accepted_witness_reproduced':True,
            'witness_comparison':'exact complete bytes for every nonce, not only digest comparison',
            'candidate_rows_sha256':sha256((out/'candidate_rows.json').read_bytes()).hexdigest()}


def run_policy():
    p=F(1,64)
    models=[]
    for cap in (0,1,4,8,16,64,512):
        model=CacheModel(512,cap,p,F(3),F(1580),F(512))
        states=optimal_cache(model)
        changes=[s for i,s in enumerate(states) if i==0 or (s['hit'],s['miss']) !=
                 (states[i-1]['hit'],states[i-1]['miss'])]
        models.append({'capacity':cap,'value_from_empty_cache':fraction_record(states[0]['value']),
                       'action_changes':[{'k':s['k'],'hit':s['hit'],'miss':s['miss'],
                                          'value':fraction_record(s['value'])} for s in changes]})
    finite=[]
    for rounds in (45,128,512):
        model=CacheModel(512,16,p,F(3),F(1580),F(512))
        state=finite_penalty(model,rounds,F(250000))[0]
        finite.append({'round_cap':rounds,'failure_penalty':250000,
                       'value':fraction_record(state['value']),
                       'expected_tariff':fraction_record(state['cost']),
                       'success_probability':fraction_record(1-state['failure']),
                       'initial_hit':state['hit'],'initial_miss':state['miss']})
    affine_models=[]
    for cap in (0,16,512):
        states=optimal_cache(CacheModel(512,cap,p,F(3),F(1580),F(5)))
        affine_models.append({'capacity':cap,
                              'post_setup_value':fraction_record(states[0]['value']),
                              'initial_preparation_tariff':1352,
                              'new_campaign_total':fraction_record(states[0]['value']+1352),
                              'initial_hit':states[0]['hit'],'initial_miss':states[0]['miss']})
    dual=[]
    for rounds,alpha in ((45,F(1,2)),(128,F(17,20)),(512,F(99,100))):
        model=CacheModel(512,16,p,F(3),F(1580),F(512))
        bound=finite_success_lower_bound(model,rounds,alpha,F(250000))
        dual.append({'round_cap':rounds, **{k:fraction_record(v) for k,v in bound.items()}})
    return {'schema':'selected-iid-cache-policy-research-v1',
            'model':'uniform independent coordinates and independent Bernoulli tickets; closed arithmetic/cache action set',
            'actual_concrete_SHA_security_claim':False,'universal_physical_lower_bound_claim':False,
            'nonce_eventual_success_on_finite_protocol_claim':False,
            'tariff':{'compression':1,'field_multiplication':1,'field_addition':0,
                      'lookup':0,'insertion':0,'retained_memory':0,
                      'gate':3,'common_continuation':1580,'uncached_useful':512},
            'schedule_mapping':'illustrative fixed J=32 continuation schedule; real sampler tails and physical lookup/storage prices are not modeled',
            'unbounded_auxiliary_first_success_models':models,
            'finite_nonce_attempt_penalty_models':finite,
            'finite_required_success_weak_dual_bounds':dual,
            'affine_useful_oracle_policy_comparison':affine_models,
            'common_preparation_tariff_excluded_from_policy_values':904,
            'preparation_tariff_basis':'894 task-tree compressions plus 10 first-nonce fixed context/prefix overhead; add once to every new-campaign value',
            'always_attempt_lazy_expected_distinct_products_before_first_hit':fraction_record(
                cache_until_first_hit_expected_products(512,p)),
            'expected_distinct_coordinates_in_fixed_draws':[
                {'draws':n,'expected_products':fraction_record(lazy_expected_products(n))} for n in (1,45,128,512)],
            'qualification':'HOLD_NO_GO'}


def main():
    verify_upstream()
    result=run_campaign()
    (BASE/'results/frontier_result.json').write_text(json.dumps(result,indent=2)+'\n')
    policy=run_policy()
    (BASE/'results/policy_result.json').write_text(json.dumps(policy,indent=2)+'\n')
    print(json.dumps({'strategy_count':len(result['strategies']),'draws_each':result['draws_per_strategy'],
                      'distinct_coordinates':result['distinct_coordinates'],
                      'accepted_nonces':result['accepted_nonces'],
                      'first_hit_nonce':result['first_hit_nonce'],
                      'qualification':'HOLD_NO_GO'}))

if __name__=='__main__':
    main()
