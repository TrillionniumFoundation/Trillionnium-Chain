"""Complete public-source integer routing through unchanged W1 64x64 products.

This research consumer packs the five existing 3x257 matrices into 15 rows and
splits all 257 feature coordinates into five W1 tasks. It consumes products
returned by pon_shared_material_v1 after native full verification. No training,
consensus relation, adoption authority, or application payment is implemented here.

Example with the existing tracked retrospective material:
  python formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py \
    --material-only --out /tmp/shared-cell-material
Add --runner /absolute/path/to/pon_shared_material_v1 for real native work.
For a newly frozen model_loop.py run pass --model, --tasks, --evaluation-bundle,
--bundle-hash (from that producer), and --replay-source. All output is new evidence;
the original model, corpus, and evaluation bundle remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import struct
import subprocess
import sys
import time

os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')
os.environ.setdefault('OMP_NUM_THREADS', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from bounded_process import ProcessFailure, run_bounded
from contract_wire import H, ROOT, canonical, unique
from evaluation_bundle import (MAX_BUNDLE_BYTES, MAX_TASK_BYTES, partition_manifest,
                               predict_rows, read_bounded, verify_bundle)
from model_contract import DIM, load_model, load_model_bytes
from work_oracle import CELLS, N, PROOF_BYTES, Q, precheck, task_id

SCHEMA = 'pon-shared-cell-operator-v1'
NATIVE_SCHEMA = 'pon-shared-material-v1'
PROFILE = 'pon-matmul-transcript-64-v1'
OPERATORS = ('base', 'router', 'delta-0', 'delta-1', 'delta-2')
OUTPUT_ROWS = 3 * len(OPERATORS)
DEFAULT_MATERIAL = ROOT / 'evidence/pon-native-node-v1/model-current/model'
DEFAULT_BUNDLE = '485d1ddac3f10b859599297ede15c5703517952d3f507cdc3efea7f14214429e'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def save_json(path, value, *, canonical_bytes=False):
    raw = canonical(value) if canonical_bytes else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with Path(path).open('xb') as output:
        output.write(raw)


def decode_hex(value, size, code):
    require(isinstance(value, str) and len(value) == 2 * size and
            all(c in '0123456789abcdef' for c in value), code)
    return bytes.fromhex(value)


def load_inputs(model_path, tasks_path, bundle_path, expected_bundle, partition,
                offset, batch_size, *, replay_source=False):
    raw = read_bounded(bundle_path, MAX_BUNDLE_BYTES)
    bundle = verify_bundle(raw, expected_bundle)
    require(partition in bundle['partitions'] and partition not in ('train', 'calibration'),
            'CONSUMPTION_PARTITION')
    model = load_model(model_path, bytes.fromhex(bundle['candidate_artifact']))
    require(model['source'] == bundle['source_commit'], 'MODEL_SOURCE')
    task_raw = read_bounded(tasks_path, MAX_TASK_BYTES)
    rows = json.loads(task_raw, object_pairs_hook=unique)
    manifest = partition_manifest(rows)
    require(manifest == bundle['partitions'][partition], 'FROZEN_TASKS')
    require(type(offset) is int and type(batch_size) is int and 0 <= offset and
            1 <= batch_size <= 64 and offset + batch_size <= len(rows), 'BATCH_WINDOW')
    if replay_source:
        # Reuse the existing source producer, including inventory labels, snippet
        # splitting, deduplication, feature hashing, and deterministic partitions.
        from experiments.model_loop import corpus
        reproduced = [row for row in corpus(bundle['source_commit']) if row['split'] == partition]
        require(reproduced == rows, 'SOURCE_REPLAY')
    selected = rows[offset:offset + batch_size]
    provenance = {
        'source_commit': bundle['source_commit'], 'source_replayed': replay_source,
        'model_artifact': bundle['candidate_artifact'], 'model_sha256': sha256(canonical(model)),
        'evaluation_bundle': expected_bundle, 'evaluation_bundle_sha256': sha256(raw),
        'partition': partition, 'whole_partition': manifest,
        'tasks_file_sha256': sha256(task_raw), 'selected_tasks': partition_manifest(selected),
        'batch_offset': offset, 'batch_size': batch_size,
        'scope': bundle['scope'], 'ordinary_hepta_product_entry': False,
        'independent_administration': False, 'prospective_evaluation': False,
        'production_activation': False, 'public_reward_eligible': False,
    }
    return model, selected, provenance


def model_arrays(model, rows):
    load_model_bytes(canonical(model))
    partition_manifest(rows)
    require(1 <= len(rows) <= N, 'INFERENCE_BATCH')
    weights = np.asarray(model['base'] + model['router'] +
                         [row for delta in model['deltas'] for row in delta], dtype=np.int64)
    inputs = np.asarray([row['x'] for row in rows], dtype=np.int64).T.copy()
    require(weights.shape == (OUTPUT_ROWS, DIM) and inputs.shape == (DIM, len(rows)), 'OPERATOR_SHAPE')
    return weights, inputs


def pack_field(matrix):
    values = (matrix % Q).ravel().tolist()
    return struct.pack('<' + 'I' * len(values), *values)


def build_tiles(model, rows):
    """Tile a COMPLETE model contraction; no feature or request is discarded."""
    weights, inputs = model_arrays(model, rows)
    batch = len(rows)
    tiles = []
    maxima = np.abs(inputs).max(axis=1)
    full_bounds = np.abs(weights) @ maxima
    # The source model contract itself establishes this conservative bound.
    require(DIM * 32767 * 8 < Q // 2 and int(full_bounds.max()) < Q // 2,
            'SIGNED_DECODE_RANGE')
    for index, start in enumerate(range(0, DIM, N)):
        stop = min(start + N, DIM)
        width = stop - start
        a = np.zeros((N, N), dtype=np.int64)
        b = np.zeros((N, N), dtype=np.int64)
        a[:OUTPUT_ROWS, :width] = weights[:, start:stop]
        b[:width, :batch] = inputs[start:stop]
        a_bytes, b_bytes = pack_field(a), pack_field(b)
        bounds = (np.abs(weights[:, start:stop]) @ maxima[start:stop]).tolist()
        require(max(bounds) < Q // 2, 'TILE_SIGNED_DECODE_RANGE')
        material = a_bytes + b_bytes
        av = list(struct.unpack('<' + 'I' * CELLS, a_bytes))
        bv = list(struct.unpack('<' + 'I' * CELLS, b_bytes))
        tiles.append({'index': index, 'feature_start': start, 'feature_count': width,
                      'active_output_rows': OUTPUT_ROWS, 'active_requests': batch,
                      'task': task_id(av, bv).hex(), 'a_sha256': sha256(a_bytes),
                      'b_sha256': sha256(b_bytes), 'material_sha256': sha256(material),
                      'material_bytes': len(material), 'signed_decode_bounds': bounds,
                      'nonzero_a_cells': int(np.count_nonzero(a)),
                      'nonzero_b_cells': int(np.count_nonzero(b)), 'material': material})
    require([tile['feature_count'] for tile in tiles] == [64, 64, 64, 64, 1], 'FEATURE_COVERAGE')
    return tiles, full_bounds.tolist()


def consume_products(tiles, products, batch):
    """Consume only supplied verified product bytes, without redoing matmul."""
    require(type(batch) is int and 1 <= batch <= N and len(tiles) == 5, 'CONSUMER_SHAPE')
    require(len(products) == len(tiles) and sorted(products) == list(range(len(tiles))), 'TILE_SET')
    totals = np.zeros((OUTPUT_ROWS, batch), dtype=np.int64)
    for index, tile in enumerate(tiles):
        require(tile['index'] == index and tile['feature_start'] == index * N and
                tile['feature_count'] == min(N, DIM - index * N), 'TILE_COVERAGE')
        raw = products[index]
        require(type(raw) is bytes and len(raw) == CELLS * 4, 'PRODUCT_BYTES')
        field = np.asarray(struct.unpack('<' + 'I' * CELLS, raw), dtype=np.int64).reshape(N, N)
        require(bool((field < Q).all()), 'PRODUCT_FIELD')
        require(not field[OUTPUT_ROWS:].any() and not field[:OUTPUT_ROWS, batch:].any(), 'PRODUCT_PADDING')
        signed = np.where(field > Q // 2, field - Q, field)[:OUTPUT_ROWS, :batch]
        bounds = np.asarray(tile['signed_decode_bounds'], dtype=np.int64)[:, None]
        require(bool((np.abs(signed) <= bounds).all()), 'PRODUCT_SIGNED_BOUND')
        totals += signed
    router = totals[3:6].T
    routes = np.argmax(router, axis=1)
    logits = totals[:3].T.copy()
    for request, expert in enumerate(routes):
        logits[request] += totals[6 + 3 * int(expert):9 + 3 * int(expert), request]
    return {'products': totals, 'routes': routes, 'logits': logits,
            'predictions': np.argmax(logits, axis=1)}


def prepare_numpy(model, rows):
    x = np.asarray([row['x'] for row in rows], dtype=np.int64)
    router = np.asarray(model['router'], dtype=np.int64)
    # Reusable legal ordinary preprocessing: a deployed model may cache these
    # three sums and evaluate just its selected expert for each request.
    merged = np.asarray(model['base'], dtype=np.int64)[None, :, :] + np.asarray(model['deltas'], dtype=np.int64)
    return x, router, merged


def numpy_operator(prepared):
    x, router, merged = prepared
    routes = np.argmax(x @ router.T, axis=1)
    logits = np.empty((len(x), 3), dtype=np.int64)
    for expert in range(3):
        indices = np.flatnonzero(routes == expert)
        if len(indices):
            logits[indices] = x[indices] @ merged[expert].T
    return {'routes': routes, 'logits': logits, 'predictions': np.argmax(logits, axis=1)}


def validate_consumption(model, rows, observed):
    prepared = prepare_numpy(model, rows)
    optimized = numpy_operator(prepared)
    scalar = predict_rows(model, rows)
    require(observed['predictions'].tolist() == scalar, 'SCALAR_PREDICTION_MISMATCH')
    for field in ('routes', 'logits', 'predictions'):
        require(np.array_equal(observed[field], optimized[field]), 'NUMPY_' + field.upper() + '_MISMATCH')
    # This diagnostic checks every operator output, including unselected experts;
    # it is counted separately and included in the total experiment cost.
    weights, inputs = model_arrays(model, rows)
    require(np.array_equal(observed['products'], weights @ inputs), 'COMPLETE_OPERATOR_MISMATCH')


def baseline(model, rows, repetitions):
    require(type(repetitions) is int and 1 <= repetitions <= 10000, 'BASELINE_REPETITIONS')
    start = time.perf_counter_ns()
    prepared = prepare_numpy(model, rows)
    preparation_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    first = numpy_operator(prepared)
    cold_ns = time.perf_counter_ns() - start
    for _ in range(8):
        numpy_operator(prepared)
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        numpy_operator(prepared)
        samples.append(time.perf_counter_ns() - start)
    start = time.perf_counter_ns()
    scalar = predict_rows(model, rows)
    scalar_ns = time.perf_counter_ns() - start
    require(first['predictions'].tolist() == scalar, 'BASELINE_REFERENCE')
    ordered = sorted(samples)
    return {'implementation': 'numpy-int64-cached-base-plus-delta-selected-expert',
            'numpy_version': np.__version__, 'repetitions': repetitions, 'warmup_runs': 8,
            'preparation_ns': preparation_ns, 'first_execution_ns': cold_ns,
            'cold_preparation_plus_execution_ns': preparation_ns + cold_ns,
            'warm_min_ns': min(samples), 'warm_median_ns': int(statistics.median(samples)),
            'warm_p95_ns': ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)],
            'warm_samples_ns': samples, 'scalar_predict_rows_ns': scalar_ns,
            'predictions': scalar, 'routes': first['routes'].tolist(),
            'logical_multiply_adds': len(rows) * 6 * DIM,
            'cost_scope': 'one complete batch; model/input decode excluded from warm runs; reusable model preprocessing reported'}


def native_timing(value):
    require(isinstance(value, dict) and set(value) == {'wall_ns', 'cpu_ns'} and
            all(type(number) is int and 0 <= number < 1 << 64 for number in value.values()),
            'NATIVE_TIMING')


def reject_json_number(value):
    raise ValueError('NATIVE_NONINTEGER_JSON_NUMBER')


def native_products(raw, tiles, index, cycles, *, seed, target_index, max_attempts, arithmetic):
    """Bind the trusted native runner's complete evidence to the frozen request.

    This parser is not a cryptographic verification authority. Actual complete
    transcript replay is owned by the hash-recorded native executable. Checking
    its sequencing, hashes and challenge identities detects evidence mixups.
    """
    require(type(raw) is bytes and raw.endswith(b'\n'), 'NATIVE_TRUNCATED_STDOUT')
    require(target_index in (0, 1) and type(target_index) is int, 'NATIVE_TARGET_INDEX')
    seed_bytes = decode_hex(seed, 32, 'NATIVE_REQUEST_SEED')
    target = bytes([127 if target_index == 0 else 7]) + bytes([255]) * 31
    target_hex = target.hex()
    lines = raw.splitlines(keepends=True)
    records = []
    for line in lines:
        require(line.endswith(b'\n') and 1 < len(line) <= 4 * 1024 * 1024 + 1, 'NATIVE_RECORD_LIMIT')
        record = json.loads(line, object_pairs_hook=unique,
                            parse_float=reject_json_number, parse_constant=reject_json_number)
        require(isinstance(record, dict) and record.get('schema') == NATIVE_SCHEMA, 'NATIVE_SCHEMA')
        native_timing(record.get('record_build_timing'))
        records.append(record)
    expected_order = ['material', 'setup'] + ['search', 'candidate', 'verification', 'winner'] * cycles + ['summary']
    require([row.get('kind') for row in records] == expected_order, 'NATIVE_SEQUENCE')
    tile = tiles[index]
    task = bytes.fromhex(tile['task'])
    material = records[0]
    for field, expected in {'input_bytes': len(tile['material']), 'matrix_width': N,
                            'field_modulus': Q, 'target_index': target_index, 'cycles': cycles,
                            'max_attempts': max_attempts}.items():
        require(type(material.get(field)) is int and material[field] == expected, 'NATIVE_HEADER_COUNT')
    native_timing(material.get('input_timing'))
    require(material.get('task') == tile['task'] and material.get('profile') == PROFILE and
            material.get('input_hex') == tile['material'].hex() and
            material.get('input_sha256') == tile['material_sha256'] and
            material.get('matrix_a_sha256') == tile['a_sha256'] and
            material.get('matrix_b_sha256') == tile['b_sha256'] and
            material.get('input_bytes') == len(tile['material']) and
            material.get('matrix_width') == N and material.get('field_modulus') == Q, 'NATIVE_MATERIAL')
    require(material.get('target_index') == target_index and material.get('target') == target_hex,
            'NATIVE_REQUEST_TARGET')
    require(material.get('seed') == seed and material.get('challenge_domain') == 'pon-shared-material-challenge-v1',
            'NATIVE_REQUEST_SEED')
    require(material.get('arithmetic') == arithmetic and material.get('cycles') == cycles and
            material.get('max_attempts') == max_attempts and material.get('attack_controls') is False and
            material.get('materialization') == 'target-hit', 'NATIVE_REQUEST_OPTIONS')
    setup = records[1]
    native_timing(setup.get('timing'))
    require(type(setup.get('calls')) is int and type(setup.get('reuse_searches')) is int, 'NATIVE_SETUP_COUNT')
    require(setup.get('task') == tile['task'] and setup.get('arithmetic') == arithmetic and
            setup.get('calls') == 1 and setup.get('reuse_searches') == cycles and
            setup.get('outcome') == 'Prepared', 'NATIVE_SETUP')
    products = []
    total_attempts = 0
    for cycle in range(cycles):
        search, candidate, verification, winner = records[2 + 4 * cycle:6 + 4 * cycle]
        require(all(type(row.get('cycle')) is int and row['cycle'] == cycle
                    for row in (search, candidate, verification, winner)), 'NATIVE_CYCLES')
        require(search.get('task') == tile['task'] and search.get('target') == target_hex and
                search.get('arithmetic') == arithmetic and search.get('setup_calls') == 0 and
                search.get('status') == 'target-hit-unverified' and search.get('error') is None,
                'NATIVE_SEARCH')
        native_timing(search.get('timing'))
        require(type(search.get('setup_calls')) is int, 'NATIVE_SETUP_COUNT')
        attempts = search.get('attempts')
        require(isinstance(attempts, list) and 1 <= len(attempts) <= max_attempts, 'NATIVE_ATTEMPTS')
        total_attempts += len(attempts)
        for nonce, attempt in enumerate(attempts):
            require(isinstance(attempt, dict) and type(attempt.get('nonce')) is int and
                    attempt['nonce'] == nonce and attempt.get('error') is None, 'NATIVE_NONCE')
            native_timing(attempt.get('timing'))
            challenge = H('pon-shared-material-challenge-v1', task, target, seed_bytes,
                          struct.pack('<Q', cycle), struct.pack('<Q', nonce))
            require(attempt.get('challenge') == challenge.hex(), 'NATIVE_CHALLENGE_BINDING')
            trace = decode_hex(attempt.get('trace'), 32, 'NATIVE_TRACE')
            ticket = H('ticket', challenge, trace)
            hit = ticket <= target
            require(attempt.get('ticket') == ticket.hex() and attempt.get('target_hit') is hit and
                    attempt.get('proof_materialized') is hit and hit == (nonce == len(attempts) - 1),
                    'NATIVE_ATTEMPT_TICKET')
        require(winner.get('task') == tile['task'] and winner.get('target') == target_hex,
                'NATIVE_WINNER_CONTEXT')
        require(winner.get('challenge') == challenge.hex() and winner.get('ticket') == ticket.hex(),
                'NATIVE_WINNER_CHALLENGE')
        proof = decode_hex(winner.get('proof_hex'), PROOF_BYTES, 'NATIVE_PROOF')
        product = decode_hex(winner.get('product_hex'), CELLS * 4, 'NATIVE_PRODUCT')
        require(sha256(proof) == winner.get('proof_sha256') and
                sha256(product) == winner.get('product_sha256'), 'NATIVE_DIGEST')
        require(proof[4:4 + 2 * CELLS * 4] == tile['material'], 'NATIVE_PROOF_MATERIAL')
        require(proof[-32:] == trace, 'NATIVE_PROOF_TRACE')
        require(proof[4 + 2 * CELLS * 4:-32] == product, 'NATIVE_PRODUCT_BINDING')
        native_timing(winner.get('typed_copy_timing'))
        require(winner.get('product_source') == 'VerifiedWork.product' and
                winner.get('scalar_reference_equal') is True, 'NATIVE_TYPED_PRODUCT')
        for field in ('task', 'challenge', 'target', 'ticket', 'proof_hex', 'proof_sha256'):
            require(candidate.get(field) == winner.get(field), 'NATIVE_CANDIDATE_BINDING')
        require(candidate.get('verified') is False and verification.get('proof_sha256') == sha256(proof) and
                verification.get('typed_products_equal') is True, 'NATIVE_VERIFICATION')
        for backend in ('native', 'scalar_reference'):
            value = verification.get(backend)
            require(isinstance(value, dict) and value.get('outcome') == 'Accepted', 'NATIVE_VERIFICATION')
            native_timing(value.get('timing'))
        # Additional wire/ticket check only; no fallback from failed native replay.
        precheck(challenge, task, target, proof)
        products.append(product)
    require(all(product == products[0] for product in products), 'REUSED_TASK_PRODUCT')
    summary = records[-1]
    require(summary.get('status') == 'complete', 'NATIVE_INCOMPLETE')
    require(summary.get('measurement_incomplete') == [], 'NATIVE_MEASUREMENT_INCOMPLETE')
    for field in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                  'typed_copy_subtotal', 'run_through_before_summary', 'record_build_subtotal',
                  'serialization_output_subtotal'):
        native_timing(summary.get(field))
    expected_counts = {'requested_cycles': cycles, 'searches': cycles, 'attempts': total_attempts,
                       'winners': cycles, 'exhausted': 0, 'failed_searches': 0, 'control_failures': 0,
                       'requested_control_campaigns': 0, 'control_campaigns': 0,
                       'rows_before_summary': len(records) - 1,
                       'bytes_before_summary': sum(len(line) for line in lines[:-1])}
    for field, expected in expected_counts.items():
        require(type(summary.get(field)) is int and summary[field] == expected, 'NATIVE_SUMMARY_' + field.upper())
    return products, records


def run_native(runner, tiles, out, seed, target_index, cycles, attempts, arithmetic, timeout):
    require(runner.is_file(), 'NATIVE_RUNNER_UNAVAILABLE')
    results = []
    products_by_cycle = [dict() for _ in range(cycles)]
    runner_hash = sha256(runner.read_bytes())
    for index, tile in enumerate(tiles):
        require(sha256(runner.read_bytes()) == runner_hash, 'NATIVE_RUNNER_CHANGED')
        directory = out / f'tile-{index}'
        tile_seed = H('shared-cell-seed-v1', bytes.fromhex(seed), bytes.fromhex(tile['task']))
        command = [str(runner.resolve()), '--shared-material-v1', '--target-index', str(target_index),
                   '--seed', tile_seed.hex(), '--max-attempts', str(attempts), '--cycles', str(cycles),
                   '--arithmetic', arithmetic]
        start = time.perf_counter_ns()
        own_cpu = time.process_time_ns()
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            result = run_bounded(command, tile['material'], timeout=timeout,
                                 stdout_limit=min(256 * 1024 * 1024, 128 * 1024 + cycles * (attempts * 2048 + 512 * 1024)),
                                 stderr_limit=65536)
        except ProcessFailure as error:
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            failure_wall_ns = time.perf_counter_ns() - start
            failure_own_cpu_ns = time.process_time_ns() - own_cpu
            (directory / 'native.stdout.jsonl').write_bytes(error.stdout)
            (directory / 'native.stderr.txt').write_bytes(error.stderr)
            save_json(directory / 'process-failure.json', {
                'error': str(error), 'returncode': error.returncode, 'stdin_written': error.stdin_written,
                'stdout_truncated': error.stdout_truncated, 'stderr_truncated': error.stderr_truncated,
                'wall_ns': failure_wall_ns, 'supervisor_cpu_ns': failure_own_cpu_ns,
                'command': command, 'runner_sha256': runner_hash,
                'child_user_cpu_ns': round((after.ru_utime - children.ru_utime) * 1e9),
                'child_system_cpu_ns': round((after.ru_stime - children.ru_stime) * 1e9),
                'children_peak_rss_before_raw': children.ru_maxrss,
                'children_peak_rss_after_raw': after.ru_maxrss,
                'stdout_retained_bytes': len(error.stdout), 'stderr_retained_bytes': len(error.stderr),
                'timeout_seconds_per_tile': timeout,
                'timing_scope': 'failure includes child group cleanup; retained I/O may be a bounded prefix'})
            raise
        wall_ns = time.perf_counter_ns() - start
        own_cpu_ns = time.process_time_ns() - own_cpu
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        (directory / 'native.stdout.jsonl').write_bytes(result.stdout)
        (directory / 'native.stderr.txt').write_bytes(result.stderr)
        process = {'index': index, 'command': command, 'runner_sha256': runner_hash,
                   'returncode': result.returncode, 'wall_ns': wall_ns, 'supervisor_cpu_ns': own_cpu_ns,
                   'runner_sha256_after': sha256(runner.read_bytes()),
                   'child_user_cpu_ns': round((after.ru_utime - children.ru_utime) * 1e9),
                   'child_system_cpu_ns': round((after.ru_stime - children.ru_stime) * 1e9),
                   'children_peak_rss_before_raw': children.ru_maxrss,
                   'children_peak_rss_after_raw': after.ru_maxrss,
                   'peak_rss_scope': 'cumulative children high-water; not an additive per-child measurement',
                   'stdin_bytes': len(tile['material']), 'stdout_bytes': len(result.stdout),
                   'stderr_bytes': len(result.stderr), 'stdout_sha256': sha256(result.stdout)}
        save_json(directory / 'process.json', process)
        require(process['runner_sha256_after'] == runner_hash, 'NATIVE_RUNNER_CHANGED')
        require(result.returncode == 0, 'NATIVE_RUN_FAILED')
        verified, records = native_products(result.stdout, tiles, index, cycles, seed=tile_seed.hex(),
                                           target_index=target_index, max_attempts=attempts, arithmetic=arithmetic)
        for cycle, product in enumerate(verified):
            products_by_cycle[cycle][index] = product
        # Full native timing/attempt rows remain in raw evidence; no timing is
        # inferred from skipped, missing, or fabricated success records.
        process['native_summary'] = records[-1]
        save_json(directory / 'accepted.json', {'tile': index, 'verified_cycles': cycles,
                  'task': tile['task'], 'runner_sha256': runner_hash, 'stdout_sha256': process['stdout_sha256']})
        results.append(process)
    return products_by_cycle, results


def execution_identity(runner):
    relative_paths = ['formal/pon-nakamoto-v1/' + name for name in
                      ('experiments/shared_cell_operator_v1.py', 'model_contract.py',
                       'evaluation_bundle.py', 'work_oracle.py', 'bounded_process.py',
                       'contract_wire.py', 'ledger.py', 'evaluation.py', 'experiments/model_loop.py')]
    identity = {'files_sha256': {name: sha256((ROOT / name).read_bytes()) for name in relative_paths},
                'native_runner_sha256': sha256(Path(runner).read_bytes()) if runner else None}
    for key, command in [('git_head', ['git', 'rev-parse', 'HEAD']),
                         ('git_head_tree', ['git', 'rev-parse', 'HEAD^{tree}']),
                         ('dirty_porcelain', ['git', 'status', '--porcelain', '--untracked-files=normal'])]:
        observed = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  check=True, timeout=10)
        require(len(observed.stdout) <= 128 * 1024, 'SOURCE_IDENTITY_LIMIT')
        identity[key] = observed.stdout.decode('utf-8').strip()
    return identity


def hardware_snapshot():
    observed = {'platform': platform.platform(), 'python': platform.python_version(),
                'processor': platform.processor(), 'cpu_count': os.cpu_count(),
                'numpy_version': np.__version__,
                'cpu_affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
                'thread_environment': {name: os.environ.get(name) for name in ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS')},
                'isolation': 'uncontrolled-shared-host; observations are not a performance qualification',
                'cgroup_observations': {}}
    cpuinfo = Path('/proc/cpuinfo')
    if cpuinfo.is_file():
        observed['cpu_model'] = next((line.split(':', 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                                      if line.startswith('model name')), None)
    for location in ('/proc/self/cgroup', '/sys/fs/cgroup/cpu.max', '/sys/fs/cgroup/cpu.stat',
                     '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current',
                     '/sys/fs/cgroup/cpuset.cpus.effective'):
        path = Path(location)
        if path.is_file():
            with path.open('rb') as source:
                raw = source.read(16385)
            require(len(raw) <= 16384, 'HARDWARE_OBSERVATION_LIMIT')
            observed['cgroup_observations'][location] = raw.decode('utf-8').strip()
    return observed


def run(args):
    started = time.perf_counter_ns()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    request = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    save_json(out / 'request.json', request)
    try:
        require(args.material_only != bool(args.runner), 'SELECT_MATERIAL_ONLY_OR_NATIVE_RUNNER')
        require(type(args.timeout) in (int, float) and math.isfinite(args.timeout) and
                0 < args.timeout <= 3600, 'TIMEOUT_PER_TILE')
        decode_hex(args.seed, 32, 'SEED')
        require(1 <= args.cycles <= 64 and 1 <= args.max_attempts <= 4096, 'RUN_LIMIT')
        phase = time.perf_counter_ns()
        model, rows, provenance = load_inputs(args.model, args.tasks, args.evaluation_bundle,
                                             args.bundle_hash, args.partition, args.batch_offset,
                                             args.batch_size, replay_source=args.replay_source)
        load_ns = time.perf_counter_ns() - phase
        phase = time.perf_counter_ns()
        tiles, full_bounds = build_tiles(model, rows)
        material_ns = time.perf_counter_ns() - phase
        identity = execution_identity(args.runner)
        hardware = hardware_snapshot()
        frozen_execution = {'target_index': args.target_index, 'target': (bytes([127 if args.target_index == 0 else 7]) + bytes([255]) * 31).hex(),
                            'seed': args.seed, 'tile_seed_derivation': 'H(shared-cell-seed-v1,seed,task)',
                            'arithmetic': args.arithmetic, 'cycles': args.cycles,
                            'max_attempts': args.max_attempts, 'timeout_seconds_per_tile': args.timeout,
                            'timeout_scope': 'per native child exchange, not an application batch deadline',
                            'baseline_repetitions': args.baseline_repetitions, 'attack_controls': False}
        manifest = {'schema': SCHEMA, 'work_profile': PROFILE, 'field_modulus': Q,
                    'execution_source': identity, 'execution_parameters': frozen_execution, 'host': hardware,
                    'provenance': provenance, 'operator_order': list(OPERATORS),
                    'operator_shape': [3, DIM], 'packed_weight_shape': [OUTPUT_ROWS, DIM],
                    'input_shape': [DIM, len(rows)], 'full_feature_coverage': DIM,
                    'tiles': [{k: v for k, v in tile.items() if k != 'material'} for tile in tiles],
                    'signed_decode': {'method': 'centered-field-then-integer-tile-sum',
                                      'whole_operator_absolute_bounds': full_bounds,
                                      'contract_bound': DIM * 32767 * 8, 'strict_half_modulus': Q // 2},
                    'geometry': {'w1_product_multiply_adds_per_batch': len(tiles) * N ** 3,
                                 'all_five_operator_multiply_adds': OUTPUT_ROWS * DIM * len(rows),
                                 'ordinary_cached_selected_expert_multiply_adds': 6 * DIM * len(rows),
                                 'unselected_expert_multiply_adds': 6 * DIM * len(rows),
                                 'unmerged_base_delta_extra_multiply_adds': 3 * DIM * len(rows),
                                 'structural_padding_multiply_adds': len(tiles) * N ** 3 - OUTPUT_ROWS * DIM * len(rows),
                                 'packed_operator_density_fraction': [OUTPUT_ROWS * DIM * len(rows), len(tiles) * N ** 3],
                                 'ordinary_required_density_fraction': [6 * DIM * len(rows), len(tiles) * N ** 3],
                                 'output_rows_zero_padded': N - OUTPUT_ROWS,
                                 'request_columns_zero_padded': N - len(rows),
                                 'inner_coordinates_zero_padded': len(tiles) * N - DIM},
                    'same_input_cycles': args.cycles,
                    'distinct_useful_batch_outputs': 1,
                    'repeated_challenge_outputs_are_new_application_work': False,
                    'scope': 'retrospective-public-source-integer-model; unchanged-W1; not-LLM-Hepta-adoption-or-payment'}
        # Timeout is a bounded finite JSON number; manifest is ordinary JSON because
        # the existing artifact canonicalizer deliberately excludes floats.
        save_json(out / 'manifest.json', manifest)
        save_json(out / 'model.json', model, canonical_bytes=True)
        save_json(out / 'tasks.json', rows, canonical_bytes=True)
        for tile in tiles:
            directory = out / f"tile-{tile['index']}"
            directory.mkdir()
            (directory / 'material.bin').write_bytes(tile['material'])
        phase = time.perf_counter_ns()
        normal = baseline(model, rows, args.baseline_repetitions)
        baseline_ns = time.perf_counter_ns() - phase
        save_json(out / 'baseline.json', normal)
        report = {'schema': SCHEMA, 'status': 'materials_ready', 'proof_backend_executed': False,
                  'provenance': provenance, 'geometry': manifest['geometry'],
                  'host': hardware, 'execution_source': identity, 'execution_parameters': frozen_execution,
                  'phases_ns': {'input_validation_and_optional_source_replay': load_ns,
                                'material_preparation': material_ns, 'all_baseline_diagnostics': baseline_ns},
                  'baseline': normal, 'native': [], 'outputs': [],
                  'claims': {'complete_operator': False, 'canonical_material_available_for_security_experiment': True,
                             'security_experiment_executed_here': False,
                             'production_activation': False, 'beneficial_model_update': False,
                             'independent_followup_evaluation': False, 'adoption': False, 'payment': False,
                             'wan_transmission_measured': False, 'energy_measured': False}}
        if args.runner:
            phase = time.perf_counter_ns()
            all_products, native = run_native(Path(args.runner), tiles, out, args.seed, args.target_index,
                                               args.cycles, args.max_attempts, args.arithmetic, args.timeout)
            report['phases_ns']['native_runs_and_evidence_checks'] = time.perf_counter_ns() - phase
            report['native'] = native
            phase = time.perf_counter_ns()
            observed = [consume_products(tiles, products, len(rows)) for products in all_products]
            report['phases_ns']['direct_product_consumption'] = time.perf_counter_ns() - phase
            phase = time.perf_counter_ns()
            for cycle, result in enumerate(observed):
                validate_consumption(model, rows, result)
                output = {'cycle': cycle, 'predictions': result['predictions'].tolist(),
                          'routes': result['routes'].tolist(), 'logits': result['logits'].tolist(),
                          'all_operator_outputs': result['products'].tolist()}
                save_json(out / f'output-{cycle}.json', output, canonical_bytes=True)
                report['outputs'].append({'cycle': cycle, 'sha256': sha256(canonical(output))})
            report['phases_ns']['independent_scalar_and_numpy_validation'] = time.perf_counter_ns() - phase
            report['proof_backend_executed'] = True
            report['status'] = 'complete'
            report['claims']['complete_operator'] = True
            child_wall = sum(item['wall_ns'] for item in native)
            report['costs'] = {
                'native_process_wall_ns': child_wall,
                'native_child_cpu_ns': sum(item['child_user_cpu_ns'] + item['child_system_cpu_ns'] for item in native),
                'all_local_pipe_bytes': sum(item['stdin_bytes'] + item['stdout_bytes'] + item['stderr_bytes'] for item in native),
                'canonical_matrices_bytes': len(tiles) * 2 * CELLS * 4,
                'proof_bytes': args.cycles * len(tiles) * PROOF_BYTES,
                'typed_product_bytes': args.cycles * len(tiles) * CELLS * 4,
                'native_wall_to_one_ordinary_warm_batch_ratio': child_wall / normal['warm_median_ns'],
                'native_wall_to_one_ordinary_cold_batch_ratio': child_wall / normal['cold_preparation_plus_execution_ns'],
                'transmission_scope': 'actual local stdin/stdout/stderr; proof and product bytes also itemized; no WAN latency/bandwidth assumption',
                'same_inputs_cycles': args.cycles, 'distinct_application_batches': 1,
                'cache_credit': 'repeated challenge cycles recompute the same output; no extra useful-output credit',
                'mining_and_proof_and_full_verification_included': True,
            }
        for name, expected_hash in identity['files_sha256'].items():
            require(sha256((ROOT / name).read_bytes()) == expected_hash, 'EXECUTION_SOURCE_CHANGED')
        report['phases_ns']['total_experiment_before_final_report_write'] = time.perf_counter_ns() - started
        save_json(out / 'report.json', report)
        return report
    except Exception as error:
        save_json(out / 'failure.json', {'schema': SCHEMA, 'status': 'failed',
                  'error_type': type(error).__name__, 'error': str(error),
                  'elapsed_ns': time.perf_counter_ns() - started,
                  'proof_backend_executed_successfully': False,
                  'partial_evidence_preserved': True,
                  'planned_tile_count': 5, 'tile_states': [
                      {'index': index, 'state': ('completed' if (out / f'tile-{index}/accepted.json').exists()
                       else 'process_failure' if (out / f'tile-{index}/process-failure.json').exists()
                       else 'process_finished_unaccepted' if (out / f'tile-{index}/process.json').exists()
                       else 'not_started')} for index in range(5)]})
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--model', type=Path, default=DEFAULT_MATERIAL / 'model.json')
    result.add_argument('--tasks', type=Path, default=DEFAULT_MATERIAL / 'consumer.json')
    result.add_argument('--evaluation-bundle', type=Path, default=DEFAULT_MATERIAL / 'evaluation-bundle.json')
    result.add_argument('--bundle-hash', default=DEFAULT_BUNDLE)
    result.add_argument('--partition', default='consumer')
    result.add_argument('--batch-offset', type=int, default=0)
    result.add_argument('--batch-size', type=int, default=64)
    result.add_argument('--replay-source', action='store_true')
    result.add_argument('--material-only', action='store_true')
    result.add_argument('--runner', type=Path)
    result.add_argument('--target-index', type=int, choices=(0, 1), default=0)
    result.add_argument('--arithmetic', choices=('full-limb', 'transposed'), default='full-limb')
    result.add_argument('--seed', default='8c' * 32)
    result.add_argument('--cycles', type=int, default=1)
    result.add_argument('--max-attempts', type=int, default=4096)
    result.add_argument('--timeout', type=float, default=60.0)
    result.add_argument('--baseline-repetitions', type=int, default=100)
    result.add_argument('--out', required=True)
    return result


if __name__ == '__main__':
    try:
        completed = run(parser().parse_args())
        print(json.dumps({'schema': SCHEMA, 'status': completed['status'],
                          'proof_backend_executed': completed['proof_backend_executed'],
                          'model_artifact': completed['provenance']['model_artifact']}))
    except (ValueError, OSError) as failure:
        print(json.dumps({'schema': SCHEMA, 'status': 'failed', 'error': str(failure)}), file=sys.stderr)
        raise SystemExit(2)
