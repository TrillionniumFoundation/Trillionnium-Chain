"""Finite lawful implementation comparison for the existing exact int257 Cell.

This module measures/counts implemented algorithms; it never infers a minimum
work bound, new demand, a lottery query, or a right to chainwork. Cached values
are pure arithmetic, keyed by exact model/input/representation/scope/generation.
Every fresh request still needs its own commitment, lifetime and owner checks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import time

PROFILE = 'pon-routed-int257-grouped-research-v0'
SCHEMA = 'pon-grouped-legal-strategy-observation-v0'
DIM, CLASSES, EXPERTS, MAX_BATCH = 257, 3, 3, 64
MAX_COEFFICIENT, MAX_INPUT, MAX_RANK = 32767, 8, 8
REPRESENTATION = 'exact-signed-i64-int257-bias8-v0'
ARMS = ('direct_original', 'direct_cached_merged', 'grouped_cached_merged',
        'sparse_cached_merged', 'repeated_cached_merged', 'factor_selected')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _matrix(value, rows, columns, bound, code):
    require(type(value) is list and len(value) == rows and
            all(type(row) is list and len(row) == columns for row in value), code + '_SHAPE')
    require(all(type(x) is int and -bound <= x <= bound for row in value for x in row),
            code + '_RANGE')
    return tuple(tuple(row) for row in value)


def validate_model(model):
    require(type(model) is dict and all(key in model for key in ('base', 'router', 'deltas')),
            'MODEL_FIELDS')
    base = _matrix(model['base'], CLASSES, DIM, MAX_COEFFICIENT, 'BASE')
    router = _matrix(model['router'], CLASSES, DIM, MAX_COEFFICIENT, 'ROUTER')
    require(type(model['deltas']) is list and len(model['deltas']) == EXPERTS, 'DELTAS_SHAPE')
    deltas = tuple(_matrix(delta, CLASSES, DIM, MAX_COEFFICIENT, 'DELTA')
                   for delta in model['deltas'])
    return base, router, deltas


def validate_requests(requests):
    require(type(requests) is list and 1 <= len(requests) <= MAX_BATCH, 'BATCH_SIZE')
    ids = set()
    for request in requests:
        require(type(request) is dict and
                {'id', 'scope', 'generation', 'representation', 'x'} <= set(request),
                'REQUEST_FIELDS')
        require(all(type(request[k]) is str and 1 <= len(request[k]) <= 128
                    for k in ('id', 'scope', 'generation')), 'REQUEST_IDENTITY')
        require(request['id'] not in ids, 'DUPLICATE_REQUEST_ID')
        ids.add(request['id'])
        require(request['representation'] == REPRESENTATION, 'REPRESENTATION')
        _matrix([request['x']], 1, DIM, MAX_INPUT, 'INPUT')
        require(request['x'][-1] == 8, 'INPUT_BIAS')


@dataclass
class Cost:
    """Implemented operation counters, never substituted for observed runtime.

    A MAC position counts one multiply and an accumulator update, including the
    first term. Pure copies, key construction, validation and additions are
    separate. Object allocation and interpreter overhead remain in wall/CPU.
    """
    model_elements_checked: int = 0
    input_elements_checked: int = 0
    preparation_macs: int = 0
    preparation_additions: int = 0
    execution_macs: int = 0
    execution_additions: int = 0
    input_scan_elements: int = 0
    cache_key_elements: int = 0
    cache_lookups: int = 0
    cache_hits: int = 0
    gather_elements: int = 0
    scatter_elements: int = 0
    reference_macs: int = 0
    reference_additions: int = 0
    hash_input_bytes: int = 0

    def add(self, other):
        for key, value in asdict(other).items():
            setattr(self, key, getattr(self, key) + value)
        return self


@dataclass(frozen=True)
class Prepared:
    model_sha256: str
    base: tuple
    router: tuple
    deltas: tuple
    merged: tuple | None
    factors: tuple | None
    arm: str
    preparation_cost: tuple


def prepare(model, arm, factors=None):
    require(arm in ARMS, 'STRATEGY')
    base, router, deltas = validate_model(model)
    model_bytes = canonical(model)
    cost = Cost(model_elements_checked=(2 + EXPERTS) * CLASSES * DIM,
                hash_input_bytes=len(model_bytes))
    merged = None
    if 'cached_merged' in arm:
        merged = tuple(tuple(tuple(base[r][k] + delta[r][k] for k in range(DIM))
                             for r in range(CLASSES)) for delta in deltas)
        cost.preparation_additions = EXPERTS * CLASSES * DIM
    admitted_factors = None
    if arm == 'factor_selected':
        require(type(factors) is list and len(factors) == EXPERTS, 'FACTORS_REQUIRED')
        admitted = []
        for e, factor in enumerate(factors):
            require(type(factor) is dict and set(factor) == {'up', 'down'}, 'FACTOR_FIELDS')
            require(type(factor['down']) is list and 1 <= len(factor['down']) <= MAX_RANK,
                    'FACTOR_RANK')
            rank = len(factor['down'])
            up = _matrix(factor['up'], CLASSES, rank, MAX_COEFFICIENT, 'UP')
            down = _matrix(factor['down'], rank, DIM, MAX_COEFFICIENT, 'DOWN')
            # Full exact comparison, including coordinates absent from test inputs.
            for r in range(CLASSES):
                for k in range(DIM):
                    actual = sum(up[r][j] * down[j][k] for j in range(rank))
                    require(actual == deltas[e][r][k], 'FACTOR_NOT_SAME_DELTA')
            cost.preparation_macs += CLASSES * rank * DIM
            cost.model_elements_checked += rank * (CLASSES + DIM)
            admitted.append((up, down))
        admitted_factors = tuple(admitted)
    return Prepared(hashlib.sha256(model_bytes).hexdigest(), base, router, deltas,
                    merged, admitted_factors, arm, tuple(asdict(cost).items()))


def _dot(weight, x, cost):
    cost.execution_macs += len(x)
    return sum(a * b for a, b in zip(weight, x))


def _argmax(values):
    return max(range(CLASSES), key=lambda index: values[index])


def _one(prepared, request, cost):
    x = request['x']
    if prepared.arm == 'sparse_cached_merged':
        positions = [(k, value) for k, value in enumerate(x) if value]
        cost.input_scan_elements += DIM
        scores = [sum(weight[k] * value for k, value in positions) for weight in prepared.router]
        route = _argmax(scores)
        logits = [sum(weight[k] * value for k, value in positions)
                  for weight in prepared.merged[route]]
        cost.execution_macs += 2 * CLASSES * len(positions)
    else:
        scores = [_dot(row, x, cost) for row in prepared.router]
        route = _argmax(scores)
        if prepared.arm == 'factor_selected':
            up, down = prepared.factors[route]
            hidden = [_dot(row, x, cost) for row in down]
            logits = [_dot(prepared.base[r], x, cost) + _dot(up[r], hidden, cost)
                      for r in range(CLASSES)]
            cost.execution_additions += CLASSES
        elif prepared.arm == 'direct_original':
            logits = [_dot(prepared.base[r], x, cost) +
                      _dot(prepared.deltas[route][r], x, cost) for r in range(CLASSES)]
            cost.execution_additions += CLASSES
        else:
            logits = [_dot(row, x, cost) for row in prepared.merged[route]]
    return tuple(scores), route, tuple(logits), _argmax(logits)


class ArithmeticCache:
    """Bounded local arithmetic memo; no request receipt or permission is cached."""
    def __init__(self, capacity=MAX_BATCH):
        require(type(capacity) is int and 1 <= capacity <= MAX_BATCH, 'CACHE_CAPACITY')
        self.capacity = capacity
        self._entries = {}

    def compute(self, prepared, request, cost):
        key = (prepared.model_sha256, request['scope'], request['generation'],
               request['representation'], tuple(request['x']))
        cost.cache_key_elements += DIM
        cost.cache_lookups += 1
        found = self._entries.get(key)
        if found is not None:
            cost.cache_hits += 1
            return found
        found = _one(prepared, request, cost)
        if len(self._entries) >= self.capacity:
            self._entries.pop(next(iter(self._entries)))
        self._entries[key] = found
        return found

    @property
    def entries(self):
        return len(self._entries)


def _product(results):
    routes = [result[1] for result in results]
    groups = [[i for i, route in enumerate(routes) if route == e] for e in range(EXPERTS)]
    return {'router_outputs': [list(r[0]) for r in results], 'routes': routes, 'groups': groups,
            'logits': [list(r[2]) for r in results], 'predictions': [r[3] for r in results],
            'useful_dense_macs': 2 * CLASSES * DIM * len(results), 'padded_macs': 0,
            'nonempty_expert_groups': sum(bool(group) for group in groups)}


def execute(prepared, requests, *, cache=None):
    require(type(prepared) is Prepared, 'PREPARED_MODEL')
    validate_requests(requests)
    cost = Cost(input_elements_checked=len(requests) * DIM)
    if prepared.arm == 'grouped_cached_merged':
        scores = [[_dot(row, request['x'], cost) for row in prepared.router] for request in requests]
        routes = [_argmax(score) for score in scores]
        results = [None] * len(requests)
        for e in range(EXPERTS):
            indices = [i for i, route in enumerate(routes) if route == e]
            gathered = [list(requests[i]['x']) for i in indices]
            cost.gather_elements += len(gathered) * DIM
            for i, x in zip(indices, gathered):
                logits = [_dot(row, x, cost) for row in prepared.merged[e]]
                results[i] = (tuple(scores[i]), e, tuple(logits), _argmax(logits))
                cost.scatter_elements += CLASSES
    elif prepared.arm == 'repeated_cached_merged':
        if cache is None:
            cache = ArithmeticCache()
        require(type(cache) is ArithmeticCache, 'ARITHMETIC_CACHE')
        results = [cache.compute(prepared, request, cost) for request in requests]
    else:
        require(cache is None, 'CACHE_WRONG_STRATEGY')
        results = [_one(prepared, request, cost) for request in requests]
    return _product(results), cost


def independent_reference(model, requests):
    """Original base+delta products; no merged or factor/cache strategy helper."""
    base, router, deltas = validate_model(model)
    validate_requests(requests)
    router_outputs, routes, logits, predictions = [], [], [], []
    groups = [[] for _ in range(EXPERTS)]
    for i, request in enumerate(requests):
        x = request['x']
        scores = [sum(weight[k] * x[k] for k in range(DIM)) for weight in router]
        route = 0
        for e in range(1, EXPERTS):
            if scores[e] > scores[route]:
                route = e
        output = [sum(base[r][k] * x[k] for k in range(DIM)) +
                  sum(deltas[route][r][k] * x[k] for k in range(DIM)) for r in range(CLASSES)]
        pred = 0
        for r in range(1, CLASSES):
            if output[r] > output[pred]:
                pred = r
        router_outputs.append(scores)
        routes.append(route)
        logits.append(output)
        predictions.append(pred)
        groups[route].append(i)
    return {'router_outputs': router_outputs, 'routes': routes, 'groups': groups, 'logits': logits,
            'predictions': predictions, 'useful_dense_macs': 2 * CLASSES * DIM * len(requests),
            'padded_macs': 0, 'nonempty_expert_groups': sum(bool(group) for group in groups)}, Cost(
                model_elements_checked=(2 + EXPERTS) * CLASSES * DIM,
                input_elements_checked=len(requests) * DIM,
                reference_macs=3 * CLASSES * DIM * len(requests),
                reference_additions=CLASSES * len(requests))


def observe(model, requests, *, arm, factors=None, rounds=1, cache_capacity=MAX_BATCH):
    """All attempted rounds and costs are retained, including exceptions.

    The first round pays actual model preparation. Later rounds are declared
    replays, not new demand, and may reuse arithmetic memo entries. Timings are
    Python implementation observations, never a native/GPU performance claim.
    """
    require(type(rounds) is int and 1 <= rounds <= 64, 'ROUNDS')
    start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
    attempts, not_started = [], []
    total = Cost()
    instrumented_counts_complete = True
    prepared = None
    preparation = {}
    preparation_start = time.perf_counter_ns()
    try:
        prepared = prepare(model, arm, factors)
        total.add(Cost(**dict(prepared.preparation_cost)))
        preparation = {'status': 'complete', 'wall_ns': time.perf_counter_ns() - preparation_start,
                       'cost': dict(prepared.preparation_cost), 'paid_once': True,
                       'instrumented_counts_complete': True}
    except Exception as error:
        elapsed = time.perf_counter_ns() - preparation_start
        instrumented_counts_complete = False
        preparation = {'status': 'rejected', 'wall_ns': elapsed, 'cost': None,
                       'paid_once': True, 'instrumented_counts_complete': False}
        # Preparation belongs to the first planned round. Later rounds cannot
        # start without it; retain those dispositions instead of losing them.
        attempts.append({'round': 0, 'status': 'rejected', 'stage': 'preparation',
                         'error': str(error), 'cost': None, 'wall_ns': elapsed,
                         'known_completed_stage_cost': asdict(total),
                         'instrumented_counts_complete': False,
                         'partial_operation_counts_available': False})
        not_started = [{'round': i, 'status': 'not_started', 'reason': 'PREPARATION_FAILED',
                        'cost': None} for i in range(1, rounds)]
    cache = ArithmeticCache(cache_capacity) if prepared is not None and arm == 'repeated_cached_merged' else None
    if prepared is not None:
        for round_index in range(rounds):
            start = time.perf_counter_ns()
            attempt_cost = Cost()
            record = {'round': round_index, 'status': 'started', 'stage': 'execution'}
            try:
                product, kernel_cost = execute(prepared, requests, cache=cache)
                attempt_cost.add(kernel_cost)
                record['kernel_including_input_validation_wall_ns'] = time.perf_counter_ns() - start
                reference_start = time.perf_counter_ns()
                record['stage'] = 'independent_reference'
                reference, reference_cost = independent_reference(model, requests)
                attempt_cost.add(reference_cost)
                require(product == reference, 'INDEPENDENT_REFERENCE_MISMATCH')
                record['reference_wall_ns'] = time.perf_counter_ns() - reference_start
                serialization_start = time.perf_counter_ns()
                record['stage'] = 'serialization_and_hash'
                raw = canonical({'profile': PROFILE, 'model_sha256': prepared.model_sha256,
                                 'requests': requests, 'product': product})
                record['arithmetic_observation_sha256'] = hashlib.sha256(raw).hexdigest()
                record['serialization_and_hash_wall_ns'] = time.perf_counter_ns() - serialization_start
                attempt_cost.hash_input_bytes += len(raw)
                record.update(status='verified', stage='complete', cache_entries=cache.entries if cache else 0,
                              instrumented_counts_complete=True)
            except Exception as error:
                instrumented_counts_complete = False
                record.update(status='rejected', error=str(error), partial_operation_counts_available=False,
                              instrumented_counts_complete=False,
                              known_completed_stage_cost=asdict(attempt_cost))
            record.update(wall_ns=time.perf_counter_ns() - start,
                          cost=asdict(attempt_cost) if record['instrumented_counts_complete'] else None)
            total.add(attempt_cost)
            attempts.append(record)
    return {'schema': SCHEMA, 'profile': PROFILE, 'arm': arm,
            'model_sha256': prepared.model_sha256 if prepared else sha(model),
            'request_manifest_sha256': sha(requests), 'requests_per_round': len(requests),
            'planned_rounds': rounds, 'attempted_rounds': len(attempts),
            'not_started_rounds': len(not_started), 'not_started': not_started,
            'round_accounting_complete': sorted(a['round'] for a in attempts + not_started) == list(range(rounds)),
            'attempts': attempts, 'preparation': preparation,
            'instrumented_counts_complete': instrumented_counts_complete,
            'total_cost': asdict(total) if instrumented_counts_complete else None,
            'known_completed_stage_cost': asdict(total),
            'whole_observation_wall_ns': time.perf_counter_ns() - start_wall,
            'whole_observation_cpu_ns': time.process_time_ns() - start_cpu,
            'arithmetic_semantics_verified': prepared is not None and len(attempts) == rounds and
                all(a['status'] == 'verified' for a in attempts),
            'measurement_scope': 'Python algorithms, validation, full reference, serialization/hash; no native/GPU throughput claim',
            'rounds_are_replayed_requests': rounds > 1,
            'all_attempts_retained': True, 'actual_new_demand': 0, 'chainwork_awarded': 0,
            'pow_qualified': False, 'minimum_legal_cost_proved': False, 'production_activation': False}
