#!/usr/bin/env python3
"""Run finite offline W1 attacks on the complete Cell consumer's same five tasks.

Raw failures remain evidence. Ratios describe this instrumented implementation,
not a cheapest attacker, a public Host budget, or service/durable recovery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import resource
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from bounded_process import ProcessFailure, run_bounded
from contract_wire import H, unique
from work_oracle import CELLS, N, PROOF_BYTES, Q, precheck

SCHEMA = 'pon-shared-material-security-v1'
NATIVE = 'pon-shared-material-v1'
PROFILE = 'pon-matmul-transcript-64-v1'
MATERIAL_SCHEMAS = ('pon-shared-cell-operator-v1', 'pon-shared-cell-operator-v2')
CLOCKS = ('cpu_ns', 'wall_ns')
RESET_SCOPE = 'in-process volatile owner destruction/recreation; no node or durable recovery'
PATHS = ('cold', 'warm', 'churn-other', 'after-churn', 'after-owner-recreation')
CYCLE = ['search', 'attack_setup', 'attack_search', 'attack_search',
         'attack_native_verifier', 'attack_native_verifier', 'attack_native_verifier', 'attack_native_verifier',
         'attack_cache_setup', 'attack_cache_verifier', 'attack_cache_verifier', 'attack_cache_verifier',
         'attack_cache_verifier', 'attack_cache_reset', 'attack_cache_verifier', 'candidate', 'verification', 'winner']


def require(value, code):
    if not value:
        raise ValueError(code)


def reject_number(_):
    raise ValueError('NONINTEGER_JSON_NUMBER')


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_float=reject_number, parse_constant=reject_number)


def finite_float(text):
    value = float(text)
    require(math.isfinite(value), 'NONFINITE_JSON_NUMBER')
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit):
    with Path(path).open('rb') as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit, 'INPUT_SIZE')
    return raw


def save(path, value):
    with Path(path).open('x') as output:
        json.dump(value, output, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')


def timing_value(row, key='timing'):
    require(type(row) is dict, 'TIMING_INCOMPLETE')
    value = row.get(key)
    require(type(value) is dict and set(value) == {'cpu_ns', 'wall_ns'} and
            all(type(n) is int and 0 <= n < 2**64 for n in value.values()), 'TIMING_INCOMPLETE')
    return value


def timing(row, key='timing'):
    return timing_value(row, key)['cpu_ns']


def time_sum(values):
    return {clock: sum(value[clock] for value in values) for clock in CLOCKS}


def time_contains(parent, children, code):
    subtotal = time_sum(children)
    require(all(parent[clock] >= subtotal[clock] for clock in CLOCKS), code)


def number(row, key, expected, code):
    require(type(row.get(key)) is int and row[key] == expected, code)


def hex_bytes(value, size, code):
    require(type(value) is str and len(value) == 2*size and
            all(c in '0123456789abcdef' for c in value), code)
    return bytes.fromhex(value)


def material_manifest(raw, runner_hash, target_index):
    """Bind either consumer evidence version to the unchanged v1 attack mode.

    This is a manifest consistency check, not a replay of the source model or
    proof that a prior consumer run completed. Each A/B pair is checked against
    its recorded task and hashes immediately before its actual native search.
    """
    manifest = json.loads(raw, object_pairs_hook=unique, parse_float=finite_float, parse_constant=reject_number)
    require(type(manifest) is dict and manifest.get('schema') in MATERIAL_SCHEMAS and
            type(manifest.get('tiles')) is list and len(manifest['tiles']) == 5, 'MATERIAL_MANIFEST')
    require(manifest.get('work_profile') == PROFILE, 'MATERIAL_PROFILE')
    number(manifest, 'field_modulus', Q, 'MATERIAL_PROFILE')
    source = manifest.get('execution_source')
    require(type(source) is dict and
            hex_bytes(source.get('native_runner_sha256'), 32, 'NATIVE_BINARY_IDENTITY').hex() == runner_hash,
            'SAME_FROZEN_NATIVE_BINARY')
    require(type(target_index) is int and target_index in (0, 1), 'TARGET_INDEX')
    target = bytes([127 if target_index == 0 else 7]) + bytes([255])*31
    original = manifest.get('execution_parameters')
    require(type(original) is dict, 'MATERIAL_PARAMETERS')
    number(original, 'target_index', target_index, 'SAME_FROZEN_TARGET_AND_ARITHMETIC')
    require(original.get('target') == target.hex() and original.get('arithmetic') == 'full-limb' and
            original.get('tile_seed_derivation') == 'H(shared-cell-seed-v1,seed,task)' and
            original.get('attack_controls') is False, 'SAME_FROZEN_TARGET_AND_ARITHMETIC')
    seed = hex_bytes(original.get('seed'), 32, 'SEED')
    for key, maximum in (('cycles', 64), ('max_attempts', 4096)):
        require(type(original.get(key)) is int and 1 <= original[key] <= maximum, 'MATERIAL_PARAMETERS')
    number(manifest, 'same_input_cycles', original['cycles'], 'MATERIAL_CYCLES')
    number(manifest, 'distinct_useful_batch_outputs', 1, 'MATERIAL_UNIQUE_OUTPUT')
    require(manifest.get('repeated_challenge_outputs_are_new_application_work') is False, 'MATERIAL_UNIQUE_OUTPUT')
    if manifest['schema'] == MATERIAL_SCHEMAS[1]:
        require(original.get('preparation') in ('dense', 'sparse') and type(original.get('verifiers')) is int and
                1 <= original['verifiers'] <= 64, 'MATERIAL_V2_PARAMETERS')
    for index, tile in enumerate(manifest['tiles']):
        require(type(tile) is dict, 'MATERIAL_TILE')
        for key, expected in (('index', index), ('feature_start', index*N),
                              ('feature_count', min(N, 257-index*N)), ('material_bytes', 2*CELLS*4)):
            number(tile, key, expected, 'MATERIAL_TILE')
        for key in ('task', 'material_sha256', 'a_sha256', 'b_sha256'):
            hex_bytes(tile.get(key), 32, 'MATERIAL_TILE_DIGEST')
    return manifest, seed, target


def inspect(raw, tile, material, seed, target, cycles, attempts):
    require(type(raw) is bytes and type(material) is bytes and len(material) == 2*CELLS*4 and
            type(seed) is bytes and len(seed) == 32 and type(target) is bytes and
            target in (bytes([127])+bytes([255])*31, bytes([7])+bytes([255])*31), 'FROZEN_REQUEST')
    require(type(cycles) is int and 1 <= cycles <= 64 and type(attempts) is int and
            1 <= attempts <= 4096, 'FROZEN_REQUEST')
    require(type(tile) is dict and tile.get('task') == H('task', material[:CELLS*4], material[CELLS*4:]).hex(),
            'FROZEN_TASK')
    require(raw.endswith(b'\n'), 'TRUNCATED_NATIVE_OUTPUT')
    lines = raw.splitlines(keepends=True)
    require(all(1 < len(line) <= 4 * 1024 * 1024 + 1 for line in lines), 'NATIVE_LINE_LIMIT')
    rows = [decode(line) for line in lines]
    require(all(type(row) is dict and row.get('schema') == NATIVE for row in rows), 'NATIVE_SCHEMA')
    require([row.get('kind') for row in rows] == ['material', 'setup'] + CYCLE * cycles + ['summary'], 'INCOMPLETE_NATIVE_SEQUENCE')
    header, setup, summary = rows[0], rows[1], rows[-1]
    for row in rows: timing(row, 'record_build_timing')
    timing(header, 'input_timing'); timing(setup)
    require(header.get('profile') == PROFILE and header.get('input_hex') == material.hex() and
            header.get('input_sha256') == sha(material) and
            header.get('matrix_a_sha256') == sha(material[:CELLS*4]) and
            header.get('matrix_b_sha256') == sha(material[CELLS*4:]) and
            header.get('task') == tile['task'] and header.get('target') == target.hex() and
            header.get('seed') == seed.hex() and header.get('arithmetic') == 'full-limb' and
            header.get('materialization') == 'target-hit' and
            header.get('challenge_domain') == 'pon-shared-material-challenge-v1' and
            header.get('attack_controls') is True and header.get('input_provenance_verified') is False,
            'FROZEN_REQUEST_BINDING')
    for key, expected in (('input_bytes', len(material)), ('matrix_width', N), ('field_modulus', Q),
                          ('target_index', 0 if target[0] == 127 else 1), ('cycles', cycles),
                          ('max_attempts', attempts), ('max_line_bytes', 4*1024*1024)):
        number(header, key, expected, 'FROZEN_HEADER_COUNT')
    require(setup.get('task') == tile['task'] and setup.get('arithmetic') == 'full-limb' and
            setup.get('outcome') == 'Prepared', 'ACTUAL_REUSE')
    number(setup, 'calls', 1, 'ACTUAL_REUSE')
    number(setup, 'reuse_searches', cycles, 'ACTUAL_REUSE')
    require(summary.get('status') == 'complete' and summary.get('measurement_incomplete') == [], 'NATIVE_NOT_COMPLETE')
    for key in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                'typed_copy_subtotal', 'run_through_before_summary', 'record_build_subtotal', 'serialization_output_subtotal'):
        timing(summary, key)
    for key, expected in {'requested_cycles': cycles, 'searches': cycles, 'winners': cycles,
                          'exhausted': 0, 'failed_searches': 0, 'control_failures': 0,
                          'requested_control_campaigns': cycles, 'control_campaigns': cycles,
                          'rows_before_summary': len(rows)-1, 'bytes_before_summary': sum(map(len, lines[:-1]))}.items():
        require(type(summary.get(key)) is int and summary[key] == expected, 'SUMMARY_COUNT_' + key)
    metrics = {'attacker_cpu_ns': 0, 'raw_native_rejection_cpu_ns': 0, 'scalar_rejection_cpu_ns': 0,
               'cache_setup_cpu_ns': 0, 'cache_reset_cpu_ns': 0,
               'setups': 0, 'searches': 0, 'attempts': 0, 'candidates': 0, 'cache_cpu_ns': dict.fromkeys(PATHS, 0)}
    task = bytes.fromhex(tile['task'])
    subtotals = {'producer_subtotal': [timing_value(setup)], 'native_verifier_subtotal': [],
                 'reference_verifier_subtotal': [], 'typed_copy_subtotal': [],
                 'record_build_subtotal': [timing_value(row, 'record_build_timing') for row in rows[:-1]]}
    attack_times = []
    legal_attempts = 0
    for cycle in range(cycles):
        group = rows[2 + 18*cycle:2 + 18*(cycle+1)]
        require(all(type(row.get('cycle')) is int and row['cycle'] == cycle for row in group), 'CYCLE_BINDING')
        search = group[0]; trials = search.get('attempts')
        require(search.get('task') == tile['task'] and search.get('target') == target.hex() and
                search.get('arithmetic') == 'full-limb' and
                search.get('status') == 'target-hit-unverified' and 'error' in search and search['error'] is None and
                type(trials) is list and 1 <= len(trials) <= attempts, 'LEGAL_SEARCH')
        number(search, 'setup_calls', 0, 'LEGAL_SEARCH')
        timing(search); legal_attempts += len(trials)
        subtotals['producer_subtotal'].append(timing_value(search))
        for nonce, trial in enumerate(trials):
            context = H('pon-shared-material-challenge-v1', task, target, seed, struct.pack('<Q', cycle), struct.pack('<Q', nonce))
            require(type(trial) is dict, 'LEGAL_ATTEMPTS')
            trace = hex_bytes(trial.get('trace'), 32, 'LEGAL_TRACE'); ticket = H('ticket', context, trace); hit = ticket <= target
            require(type(trial.get('nonce')) is int and trial['nonce'] == nonce and 'error' in trial and trial['error'] is None and
                    len(trace) == 32 and trial.get('challenge') == context.hex() and trial.get('ticket') == ticket.hex() and
                    trial.get('target_hit') is hit and trial.get('proof_materialized') is hit and hit == (nonce == len(trials)-1), 'LEGAL_ATTEMPTS')
            timing(trial)
        time_contains(timing_value(search), [timing_value(trial) for trial in trials], 'LEGAL_SEARCH_TIMING_ENVELOPE')
        require(group[17].get('challenge') == context.hex() and group[17].get('ticket') == ticket.hex(), 'LEGAL_WINNER_STREAM')
        legal_trace, legal_ticket = trace, ticket
        attack_setup = group[1]
        require(attack_setup.get('task') == tile['task'] and
                attack_setup.get('valid_proof_acquired') is False, 'ATTACK_SETUP')
        number(attack_setup, 'setup_calls', 1, 'ATTACK_SETUP')
        number(attack_setup, 'reuse_searches', 2, 'ATTACK_SETUP')
        metrics['attacker_cpu_ns'] += timing(attack_setup)
        attack_times.append(timing_value(attack_setup))
        metrics['setups'] += 1
        candidates = []
        for index, row in enumerate(group[2:4]):
            number(row, 'attack_index', index, 'ATTACK_CONTEXT')
            require(row.get('task') == tile['task'] and
                    row.get('target') == target.hex() and row.get('status') == 'target-hit-unverified', 'ATTACK_CONTEXT')
            context = H('pon-shared-material-challenge-v1', task, target, seed, struct.pack('<Q', cycle), struct.pack('<Q', index))
            trials = row.get('attempts')
            require(type(trials) is list and 1 <= len(trials) <= attempts, 'ATTEMPT_DENOMINATOR')
            for nonce, trial in enumerate(trials):
                require(type(trial) is dict, 'FALSE_TRACE_SEARCH')
                trace = H('pon-shared-material-false-trace-v1', context, struct.pack('<Q', nonce))
                ticket = H('ticket', context, trace)
                hit = ticket <= target
                require(type(trial.get('nonce')) is int and trial['nonce'] == nonce and 'error' in trial and trial['error'] is None and
                        trial.get('challenge') == context.hex() and trial.get('trace') == trace.hex() and
                        trial.get('ticket') == ticket.hex() and trial.get('target_hit') is hit and
                        trial.get('proof_materialized') is hit and hit == (nonce == len(trials)-1), 'FALSE_TRACE_SEARCH')
                timing(trial)
            time_contains(timing_value(row), [timing_value(trial) for trial in trials], 'ATTACK_SEARCH_TIMING_ENVELOPE')
            proof = b'PNW1' + material + bytes(CELLS*4) + trace
            candidate = row.get('candidate')
            require(type(candidate) is dict and candidate.get('proof_hex') == proof.hex() and
                    candidate.get('proof_sha256') == sha(proof) and candidate.get('challenge') == context.hex() and
                    candidate.get('ticket') == ticket.hex(), 'FALSE_CANDIDATE')
            candidates.append((context.hex(), sha(proof)))
            metrics['attacker_cpu_ns'] += timing(row)
            attack_times.append(timing_value(row))
            metrics['searches'] += 1; metrics['attempts'] += len(trials); metrics['candidates'] += 1
        for order, row in enumerate(group[4:8]):
            index, path = order//2, ('native', 'scalar-reference')[order % 2]
            number(row, 'attack_index', index, 'NATIVE_REJECTION')
            require(row.get('path') == path and
                    (row.get('challenge'), row.get('proof_sha256')) == candidates[index] and
                    row.get('task') == tile['task'] and row.get('target') == target.hex() and
                    row.get('outcome') == 'Transcript' and row.get('expected_refusal_observed') is True and
                    'unexpected_product_sha256' in row and row['unexpected_product_sha256'] is None,
                    'NATIVE_REJECTION')
            metrics['raw_native_rejection_cpu_ns' if path == 'native' else 'scalar_rejection_cpu_ns'] += timing(row)
            attack_times.append(timing_value(row))
        number(group[8], 'capacity', 1, 'CACHE_CAPACITY')
        require(type(group[8].get('software_bytes')) is int and 0 < group[8]['software_bytes'] < 2**64,
                'CACHE_CAPACITY')
        require(set(group[13]) == {'schema', 'kind', 'cycle', 'timing', 'record_build_timing', 'scope'} and
                group[13].get('scope') == RESET_SCOPE, 'CACHE_RESET')
        metrics['cache_setup_cpu_ns'] += timing(group[8]); metrics['cache_reset_cpu_ns'] += timing(group[13])
        attack_times.extend([timing_value(group[8]), timing_value(group[13])])
        for index, row in enumerate(group[9:13] + [group[14]]):
            warm = index == 1
            observation = row.get('observation', {})
            require(type(observation) is dict, 'CACHE_PATH')
            require(row.get('path') == PATHS[index] and row.get('outcome') == 'Transcript' and
                    row.get('expected_path_observed') is True and
                    row.get('task') == tile['task'] and row.get('target') == target.hex() and
                    (row.get('challenge'), row.get('proof_sha256')) == candidates[1 if index == 2 else 0] and
                    observation.get('exact_fact_found') is warm and observation.get('trace_reused') is warm and
                    observation.get('transcript_entered') is (not warm) and
                    observation.get('transcript_completed') is (not warm) and
                    all(observation.get(key) is False for key in ('lookup_contended', 'product_entered',
                                                                 'product_completed', 'product_reused')) and
                    observation.get('publication') == ('None' if warm else 'Trace'), 'CACHE_PATH')
            number(observation, 'lookup_probes', 1, 'CACHE_PATH')
            number(observation, 'publication_probes', 0 if warm else 1, 'CACHE_PATH')
            metrics['cache_cpu_ns'][PATHS[index]] += timing(row)
            attack_times.append(timing_value(row))
        winner, verification = group[17], group[16]
        timing(winner, 'typed_copy_timing')
        for backend in ('native', 'scalar_reference'): timing(verification.get(backend, {}))
        subtotals['native_verifier_subtotal'].append(timing_value(verification['native']))
        subtotals['reference_verifier_subtotal'].append(timing_value(verification['scalar_reference']))
        subtotals['typed_copy_subtotal'].append(timing_value(winner, 'typed_copy_timing'))
        require(all(group[15].get(key) == winner.get(key) for key in
                    ('challenge', 'task', 'target', 'ticket', 'proof_hex', 'proof_sha256')), 'LEGAL_CANDIDATE')
        proof = hex_bytes(winner.get('proof_hex'), PROOF_BYTES, 'LEGAL_PROOF')
        product = hex_bytes(winner.get('product_hex'), CELLS*4, 'LEGAL_PRODUCT')
        require(len(proof) == PROOF_BYTES and proof[4:4+len(material)] == material and
                winner.get('task') == tile['task'] and winner.get('target') == target.hex() and
                proof[-32:] == legal_trace and winner.get('ticket') == legal_ticket.hex() and
                winner.get('scalar_reference_equal') is True and group[15].get('verified') is False and
                sha(proof) == winner.get('proof_sha256') and sha(product) == winner.get('product_sha256') and
                product == proof[4+len(material):-32] and winner.get('product_source') == 'VerifiedWork.product' and
                verification.get('proof_sha256') == sha(proof) and verification.get('typed_products_equal') is True and
                all(verification.get(path, {}).get('outcome') == 'Accepted' for path in ('native', 'scalar_reference')), 'LEGAL_TYPED_HANDOFF')
        precheck(bytes.fromhex(winner['challenge']), task, target, proof)
    require(type(summary.get('attempts')) is int and summary['attempts'] == legal_attempts, 'LEGAL_ATTEMPT_DENOMINATOR')
    for key, values in subtotals.items():
        require(timing_value(summary, key) == time_sum(values), 'TIMING_SUBTOTAL_' + key)
    # Search clocks already contain their attempts. These outer phases are
    # disjoint; native/ref/cache and diagnostic paths are never added twice.
    # Serialization has only an aggregate native clock, not per-record clocks.
    # Its containment can be checked, but it cannot be independently summed.
    time_contains(timing_value(summary, 'run_through_before_summary'),
                  [timing_value(header, 'input_timing'),
                   timing_value(summary, 'serialization_output_subtotal')] +
                  [timing_value(summary, key) for key in subtotals] + attack_times,
                  'RUN_TIMING_ENVELOPE')
    return metrics


def run(args):
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    try:
        save(out/'request.json', vars(args))
        source = Path(args.material_dir).resolve(); runner = Path(args.runner).resolve()
        manifest_raw = read(source/'manifest.json', 4*1024*1024)
        require(type(args.cycles) is int and 1 <= args.cycles <= 64 and type(args.max_attempts) is int and
                1 <= args.max_attempts <= 4096 and type(args.timeout) in (int, float) and
                math.isfinite(args.timeout) and 0 < args.timeout <= 300, 'RUN_BOUND')
        runner_hash = sha(read(runner, 64*1024*1024))
        manifest, seed, target = material_manifest(manifest_raw, runner_hash, args.target_index)
        original = manifest['execution_parameters']
    except Exception as error:
        save(out/'failure.json', {'schema': SCHEMA, 'status': 'failed', 'phase': 'preflight', 'error': str(error)})
        raise
    report = {'schema': SCHEMA, 'status': 'incomplete', 'source_manifest_sha256': sha(manifest_raw),
              'source_execution': manifest['execution_source'], 'target': target.hex(), 'cycles': args.cycles,
              'source_parameters': original, 'source_material_schema': manifest['schema'],
              'execution_parameters': dict(vars(args), seed=seed.hex(), arithmetic='full-limb', attack_controls=True,
                                           native_schema=NATIVE, preparation='dense', verifiers=1),
              'planned_tiles': 5, 'results': [], 'scope': 'finite offline same-material experiment; caller-trusted native binary; clocks are not attestation',
              'public_service_qualified': False, 'physical_recovery_qualified': False, 'cheapest_work_qualified': False, 'production_activation': False}
    for index, tile in enumerate(manifest['tiles']):
        directory = out/f'tile-{index}'; directory.mkdir()
        item = {'index': index, 'status': 'not-completed'}; start = time.perf_counter_ns()
        own = time.process_time_ns(); before = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            material = read(source/f'tile-{index}/material.bin', 2*CELLS*4)
            require(tile['index'] == index and len(material) == 2*CELLS*4 and sha(material) == tile['material_sha256'] and
                    sha(material[:CELLS*4]) == tile['a_sha256'] and sha(material[CELLS*4:]) == tile['b_sha256'] and
                    H('task', material[:CELLS*4], material[CELLS*4:]).hex() == tile['task'], 'SAME_TASK_MATERIAL')
            tile_seed = H('shared-cell-seed-v1', seed, bytes.fromhex(tile['task']))
            command = [str(runner), '--shared-material-v1', '--target-index', str(args.target_index), '--seed', tile_seed.hex(),
                       '--cycles', str(args.cycles), '--max-attempts', str(args.max_attempts), '--attack-controls']
            item.update(command=command, task=tile['task'], material_sha256=sha(material), seed=tile_seed.hex(), runner_sha256=runner_hash)
            require(sha(read(runner, 64*1024*1024)) == runner_hash, 'NATIVE_BINARY_CHANGED')
            exchange_start = time.perf_counter_ns()
            result = run_bounded(command, material, timeout=args.timeout, stdout_limit=256*1024*1024, stderr_limit=65536)
            item['native_exchange_wall_ns'] = time.perf_counter_ns()-exchange_start
            (directory/'stdout.jsonl').write_bytes(result.stdout); (directory/'stderr.txt').write_bytes(result.stderr)
            item.update(returncode=result.returncode, stdin_bytes=len(material), stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr), stdout_sha256=sha(result.stdout))
            require(sha(read(runner, 64*1024*1024)) == runner_hash, 'NATIVE_BINARY_CHANGED')
            require(result.returncode == 0, 'NATIVE_EXECUTION_INCOMPLETE')
            item['measurements'] = inspect(result.stdout, tile, material, tile_seed, target, args.cycles, args.max_attempts)
            item['status'] = 'complete'
        except Exception as error:
            item.update(error_type=type(error).__name__, error=str(error))
            if isinstance(error, ProcessFailure):
                (directory/'stdout.jsonl').write_bytes(error.stdout); (directory/'stderr.txt').write_bytes(error.stderr)
                item.update(returncode=error.returncode, stdin_written=error.stdin_written,
                            stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
        finally:
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            item.update(wall_ns=time.perf_counter_ns()-start, supervisor_cpu_ns=time.process_time_ns()-own,
                        child_user_cpu_ns=round((after.ru_utime-before.ru_utime)*1e9), child_system_cpu_ns=round((after.ru_stime-before.ru_stime)*1e9),
                        cumulative_children_peak_rss_raw=after.ru_maxrss, peak_rss_scope='cumulative high-water, not additive per-child RSS')
            item['wall_scope'] = 'whole tile workflow, including material/binary checks, output retention and evidence validation'
            save(directory/'process.json', item); report['results'].append(item); save(out/f'progress-{index}.json', report)
    if all(row['status'] == 'complete' for row in report['results']):
        measures = [row['measurements'] for row in report['results']]
        totals = {key: sum(row[key] for row in measures) for key in measures[0] if key != 'cache_cpu_ns'}
        totals['cache_cpu_ns'] = {path: sum(row['cache_cpu_ns'][path] for row in measures) for path in PATHS}
        report.update(status='complete', totals=totals,
                      raw_native_to_attacker_cpu_ratio=totals['raw_native_rejection_cpu_ns']/totals['attacker_cpu_ns'] if totals['attacker_cpu_ns'] else None)
    save(out/'report.json', report)
    return 0 if report['status'] == 'complete' else 2


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('material-dir', 'runner', 'out'): p.add_argument('--'+name, required=True)
    p.add_argument('--target-index', type=int, choices=(0, 1), required=True)
    p.add_argument('--cycles', type=int, default=4); p.add_argument('--max-attempts', type=int, default=4096)
    p.add_argument('--timeout', type=float, default=60)
    args = p.parse_args()
    try: raise SystemExit(run(args))
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({'schema': SCHEMA, 'status': 'failed', 'error': str(error)}), file=sys.stderr)
        raise SystemExit(2)
