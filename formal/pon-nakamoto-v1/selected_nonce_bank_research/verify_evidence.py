#!/usr/bin/env python3
"""Read-only consistency checks over retained R4 evidence; no new mining run."""
from hashlib import sha256
from pathlib import Path
import json
import sys
from research_core import BASE, Gate, bank_order


def read(name):
    return json.loads((BASE/name).read_text())


def main():
    checks = 0

    def require(condition, reason):
        nonlocal checks
        if not condition:
            raise ValueError(reason)
        checks += 1

    for name, record in read('SOURCE_PINS.json')['files'].items():
        require(sha256((BASE/name).read_bytes()).hexdigest()==record['sha256'], 'SOURCE_PIN:'+name)
    execution_pins = read('results/EXECUTED_SOURCE_PINS.json')
    for name, digest in execution_pins.items():
        require(sha256((BASE/name).read_bytes()).hexdigest()==digest, 'EXECUTED_SOURCE_CHANGED:'+name)
    campaign = read('results/campaign_result.json')
    plan = read('EXPERIMENT_PLAN.json')
    require(campaign['plan']==plan, 'PLAN')
    require(campaign['source_pins']==execution_pins, 'CAMPAIGN_PINS')
    rows = read('results/full_range_audit/candidates.json')
    by_nonce = {r['nonce']:r for r in rows}
    require(list(by_nonce)==list(range(512,1024)), 'AUDIT_NONCE_RANGE')
    accepted = [r for r in rows if r['target_passes']]
    require(read('results/native_expected_rows.json')==accepted, 'NATIVE_EXPECTED_ROWS')
    require([r['nonce'] for r in accepted]==campaign['audit']['accepted_nonces'], 'AUDIT_HITS')
    attempts = 0
    for s in campaign['strategies']:
        path = 'results/'+s['name']+'/'
        require(read(path+'result.json')==s, 'SUMMARY:'+s['name'])
        gates = read(path+'gates.json')
        candidates = read(path+'attempts.json')
        G, T, U = s['gates_paid'], s['attempts'], s['useful_product_acquisitions']
        attempts += T
        require(len(gates)==G and len(candidates)==T, 'COUNTS:'+s['name'])
        require(sum(g['attempted'] for g in gates)==T, 'PAID_GATE_STATUS')
        require(G-T==s['paid_but_unattempted_selectors'], 'UNATTEMPTED_GATE_COST')
        require(candidates[-1]['target_passes'] and not any(c['target_passes'] for c in candidates[:-1]), 'FIRST_SUCCESS')
        require(candidates[-1]['nonce']==s['winner_nonce'], 'WINNER')
        counts = s['whole_campaign_counts']
        require(counts['sha256_calls']==254+4*G+36*T, 'RAW_HASH_CALLS')
        require(counts['sha256_compression_blocks']==1146+12*G+84*T, 'RAW_HASH_BLOCKS')
        require(s['sampler_digest_calls']==32*T, 'OBSERVED_SAMPLER')
        require(s['bounded_prefix_replay']['compressions']==904+3*G+44*T, 'PREFIX_BLOCKS')
        M = 1536*T+(26 if s['global_affine'] else 512*U)
        A = 1472*T+(8533+73*U if s['global_affine'] else 448*U)
        require(counts['scalar_multiplications']==M and counts['scalar_additions']==A, 'ARITHMETIC_ACCOUNT')
        for candidate in candidates:
            n = candidate['nonce']
            raw = (BASE/path/f'witnesses/nonce-{n}.bin').read_bytes()
            require(len(raw)==1419 and sha256(raw).hexdigest()==candidate['witness_sha256'], 'WITNESS_PIN')
            require(candidate['witness_sha256']==by_nonce[n]['witness_sha256'], 'AUDIT_WITNESS_PIN')
            require(candidate['event']==by_nonce[n]['event'] and candidate['ticket']==by_nonce[n]['ticket'], 'AUDIT_EVENT_TICKET')
        if s['bank']:
            bank_raw = (BASE/path/'selector_bank.bin').read_bytes()
            ordered_raw = (BASE/path/'selector_order.bin').read_bytes()
            bank_gates = [Gate(g['nonce'], bytes.fromhex(g['seed']), tuple(g['coordinate'])) for g in gates]
            order, buckets = bank_order(bank_gates)
            require(bank_raw==b''.join(g.encode() for g in bank_gates), 'BANK_BYTES')
            require(ordered_raw==b''.join(g.nonce.to_bytes(8,'little') for g in order), 'BANK_ORDER_BYTES')
            require([c['nonce'] for c in candidates]==[g.nonce for g in order[:T]], 'NO_TICKET_REORDER')
            seal = read(path+'selector_seal.json')
            require(seal['bank_sha256']==sha256(bank_raw).hexdigest() and
                    seal['order_sha256']==sha256(ordered_raw).hexdigest(), 'SEAL')
            require(seal['plan_sha256']==execution_pins['EXPERIMENT_PLAN.json'], 'SEALED_PLAN')
            require(seal['nonempty_coordinates']==len(buckets)==317, 'BANK_COORDINATES')
    require(attempts==campaign['audit']['strategy_complete_witness_byte_comparisons']==164, 'COMPLETE_BYTE_CHECK_COUNT')
    native = read('results/native_acceptance/result.json')
    require(native['accepted_invocations']==18 and native['unique_accepted_witnesses']==13 and
            native['negative_controls']==2, 'NATIVE_TOTALS')
    for record in native['results']:
        raw = (BASE/record['witness_file']).read_bytes()
        require(sha256(raw).hexdigest()==record['witness_sha256'], 'NATIVE_WITNESS_PIN')
        stdout = BASE/f"results/native_acceptance/{record['name']}.stdout.json"
        require(sha256(stdout.read_bytes()).hexdigest()==record['stdout_sha256'], 'NATIVE_STDOUT_PIN')
        value = json.loads(stdout.read_text())
        require(value['result']['status']==record['status'] and value['counts']==record['counts'], 'NATIVE_OBSERVATION')
        require(record['exit_code']==0, 'NATIVE_EXIT')
        if record['status']=='ACCEPT_SELECTED_EVENT_ONLY':
            require(value['counts']['scalar_multiplications']==2048, 'FULL_NATIVE_ARITHMETIC')
    print(json.dumps({'status':'PASS','read_only_artifact_consistency_checks':checks,
                      'new_nonce_or_pressure_experiment':False,
                      'universal_physical_lower_bound_claim':False}))


if __name__ == '__main__':
    main()
