"""Exact lawful shortcuts for separately named challenge-arithmetic probes.

Original business inputs, router and output retain int257/bias8 semantics.
Auxiliary values are NOT a replacement for the original user input/profile.
Counters describe these implementations, not physical cost or a lower bound.
"""
from array import array
import copy
import hashlib

from grouped_legal_strategy_v0 import (
    DIM, canonical, execute, independent_reference, prepare, require, sha,
    validate_requests)

BATCH = 16
PROFILE = 'pon-grouped-challenge-shortcuts-research-v0'
PRODUCERS = {'rank1_blinded': ('direct', 'cached'),
             'batch_mix': ('direct', 'cached'), 'dropout': ('dense', 'sparse', 'lut')}
INTERNAL_INPUT_BOUNDS = {'rank1_blinded': 16, 'batch_mix': 264, 'dropout': 8}


def cost():
    return dict(macs=0, additions=0, scanned_elements=0, table_entries=0,
                table_lookups=0, mask_bits_examined=0, expanded_bytes=0)


def dot(a, b, counts):
    counts['macs'] += len(a)
    return sum(x * y for x, y in zip(a, b))


def matvec(matrix, x, counts):
    return [dot(row, x, counts) for row in matrix]


def product(scores, logits):
    routes = [max(range(3), key=row.__getitem__) for row in scores]
    return {'router_outputs': scores, 'routes': routes,
            'groups': [[i for i, e in enumerate(routes) if e == j] for j in range(3)],
            'logits': logits, 'predictions': [max(range(3), key=row.__getitem__) for row in logits],
            'useful_dense_macs': 6 * DIM * len(scores), 'padded_macs': 0,
            'nonempty_expert_groups': len(set(routes))}


def cache_key(row):
    return row['scope'], row['generation'], row['representation'], tuple(row['x'])


class PreparedProbe:
    """One exact model/request batch. No receipt, authority or work credit is cached."""
    def __init__(self, model, requests, kind, producer):
        require(kind in PRODUCERS and (producer in PRODUCERS[kind] or
                (kind == 'rank1_blinded' and producer == 'zero_skip')), 'PRODUCER')
        validate_requests(requests)
        require(len(requests) == BATCH, 'FIXED_BATCH16')
        self.model, self.requests = copy.deepcopy(model), copy.deepcopy(requests)
        self.kind, self.producer = kind, producer
        self.weights = prepare(self.model, 'direct_cached_merged')
        self.operators = (self.weights.router, *self.weights.merged)
        self.preparation = cost()
        self.preparation['additions'] = dict(self.weights.preparation_cost)['preparation_additions']
        self.x = tuple(tuple(row['x']) for row in requests)
        self.seed_context = bytes.fromhex(sha(model)) + bytes.fromhex(sha(requests))
        self.projections, self.tables = None, {}
        if kind == 'batch_mix' and producer == 'cached':
            self.projections = [[matvec(op, x, self.preparation) for x in self.x]
                                for op in self.operators]
            scores = self.projections[0]
            routes = [max(range(3), key=row.__getitem__) for row in scores]
            self.business = product(scores, [self.projections[e + 1][i] for i, e in enumerate(routes)])
        else:
            self.business, counted = execute(self.weights, self.requests)
            self.preparation['macs'] += counted.execution_macs
        if producer == 'zero_skip':
            require(all(v == 0 for op in self.operators for row in op for v in row), 'ZERO_MODEL_REQUIRED')
        if producer == 'lut':
            self._prepare_tables()

    def _prepare_tables(self):
        for request in self.requests:
            key = cache_key(request)
            if key in self.tables:
                continue
            x = request['x']
            blocks = [tuple(k for k in range(start, start + 8) if x[k] != 0)
                      for start in range(0, 256, 8)]
            terms = [[[coefficient * value for coefficient, value in zip(row, x)]
                      for row in op] for op in self.operators]
            self.preparation['macs'] += 12 * DIM
            values = []
            for operator in terms:
                out = []
                for row in operator:
                    tables = []
                    for active in blocks:
                        if not active:
                            tables.append(None)
                            continue
                        table = array('q', [0]) * (1 << len(active))
                        for mask in range(1, len(table)):
                            bit = mask & -mask
                            table[mask] = table[mask ^ bit] + row[active[bit.bit_length() - 1]]
                        self.preparation['additions'] += len(table) - 1
                        self.preparation['table_entries'] += len(table)
                        tables.append(table)
                    out.append((row[-1], tables))
                values.append(out)
            self.tables[key] = blocks, values

    def randomness(self, challenge, counts):
        require(type(challenge) is bytes and len(challenge) == 32, 'CHALLENGE')
        size = {'rank1_blinded': 272, 'batch_mix': 256, 'dropout': 512}[self.kind]
        raw = hashlib.shake_256(PROFILE.encode() + b'\0' + self.kind.encode() + b'\0' +
                               challenge + self.seed_context).digest(size)
        counts['expanded_bytes'] += size
        if self.kind == 'rank1_blinded':
            return [1 if b & 1 else -1 for b in raw[:256]] + [0], [
                (1 if b & 8 else -1) * (1 + b % 8) for b in raw[256:]]
        if self.kind == 'batch_mix':
            # |diagonal| >= 16 > sum |off-diagonal| = 15: exact full rank.
            return [[(1 if raw[i * BATCH + j] & 1 else -1) + 17 * (i == j)
                     for j in range(BATCH)] for i in range(BATCH)]
        return [raw[i * 32:(i + 1) * 32] for i in range(BATCH)]

    def transformed(self, random, counts):
        if self.kind == 'rank1_blinded':
            u, v = random
            counts['macs'] += DIM * BATCH
            counts['additions'] += DIM * BATCH
            return [[a + b * v[i] for a, b in zip(x, u)] for i, x in enumerate(self.x)]
        if self.kind == 'batch_mix':
            return [[dot([x[k] for x in self.x], [row[j] for row in random], counts)
                     for k in range(DIM)] for j in range(BATCH)]
        counts['mask_bits_examined'] += 256 * BATCH
        return [[x[k] if random[i][k // 8] & (1 << (k % 8)) else 0
                 for k in range(256)] + [8] for i, x in enumerate(self.x)]

    def _rank1(self, random, counts):
        u, v = random
        routed = self.business['routes']
        response = {0: matvec(self.weights.router, u, counts)}
        for e in set(routed):
            response[e + 1] = matvec(self.weights.merged[e], u, counts)
        correction_r = [[a * v[i] for a in response[0]] for i in range(BATCH)]
        correction_y = [[a * v[i] for a in response[e + 1]] for i, e in enumerate(routed)]
        counts['macs'] += 6 * BATCH
        if self.producer == 'cached':
            noisy_r = [[a + b for a, b in zip(row, correction_r[i])]
                       for i, row in enumerate(self.business['router_outputs'])]
            noisy_y = [[a + b for a, b in zip(row, correction_y[i])]
                       for i, row in enumerate(self.business['logits'])]
            counts['additions'] += 6 * BATCH
        else:
            z = self.transformed(random, counts)
            noisy_r = [matvec(self.weights.router, x, counts) for x in z]
            recovered = [[a - b for a, b in zip(row, correction_r[i])] for i, row in enumerate(noisy_r)]
            counts['additions'] += 3 * BATCH
            require([max(range(3), key=row.__getitem__) for row in recovered] == routed, 'RECOVERED_ROUTER')
            noisy_y = self._selected(z, routed, counts)
        return {'router_noisy': noisy_r, 'router_correction': correction_r,
                'logits_noisy': noisy_y, 'logit_correction': correction_y}

    def _selected(self, x, routes, counts, sparse=False):
        outputs = []
        for row, e in zip(x, routes):
            if sparse:
                positions = [k for k, v in enumerate(row) if v]
                counts['scanned_elements'] += DIM
                outputs.append([dot([w[k] for k in positions], [row[k] for k in positions], counts)
                                for w in self.weights.merged[e]])
            else:
                outputs.append(matvec(self.weights.merged[e], row, counts))
        return outputs

    def _lut(self, masks, counts):
        scores, logits = [], []
        for request, mask in zip(self.requests, masks):
            blocks, operators = self.tables[cache_key(request)]
            selected = []
            for active in blocks:
                selected.append(sum(((mask[k // 8] >> (k % 8)) & 1) << j for j, k in enumerate(active)))
                counts['mask_bits_examined'] += len(active)
            def row_value(row):
                bias, tables = row
                value = bias
                for table, index in zip(tables, selected):
                    if table is not None:
                        value += table[index]
                        counts['additions'] += 1
                        counts['table_lookups'] += 1
                return value
            score = [row_value(row) for row in operators[0]]
            expert = max(range(3), key=score.__getitem__)
            scores.append(score)
            logits.append([row_value(row) for row in operators[expert + 1]])
        return product(scores, logits)

    def produce(self, challenge):
        counts = cost()
        if self.producer == 'zero_skip':
            require(type(challenge) is bytes and len(challenge) == 32, 'CHALLENGE')
            zero = [[0, 0, 0] for _ in range(BATCH)]
            auxiliary = {name: copy.deepcopy(zero) for name in (
                'router_noisy', 'router_correction', 'logits_noisy', 'logit_correction')}
        else:
            random = self.randomness(challenge, counts)
            if self.kind == 'rank1_blinded':
                auxiliary = self._rank1(random, counts)
            elif self.kind == 'batch_mix' and self.producer == 'cached':
                def projection(op, j):
                    return [dot([self.projections[op][i][r] for i in range(BATCH)],
                                [row[j] for row in random], counts) for r in range(3)]
                scores = [projection(0, j) for j in range(BATCH)]
                routes = [max(range(3), key=row.__getitem__) for row in scores]
                auxiliary = product(scores, [projection(e + 1, i) for i, e in enumerate(routes)])
            elif self.producer == 'lut':
                auxiliary = self._lut(random, counts)
            else:
                z = self.transformed(random, counts)
                sparse = self.producer == 'sparse'
                if sparse:
                    scores = []
                    for x in z:
                        positions = [k for k, v in enumerate(x) if v]
                        counts['scanned_elements'] += DIM
                        scores.append([dot([w[k] for k in positions], [x[k] for k in positions], counts)
                                       for w in self.weights.router])
                else:
                    scores = [matvec(self.weights.router, x, counts) for x in z]
                routes = [max(range(3), key=row.__getitem__) for row in scores]
                auxiliary = product(scores, self._selected(z, routes, counts, sparse=sparse))
        return {'business': copy.deepcopy(self.business), 'auxiliary': auxiliary}, counts


def verify(model, requests, kind, challenge, claim):
    """Fresh original-coefficient scalar check, without any producer cache."""
    require(kind in PRODUCERS and len(requests) == BATCH, 'PROBE')
    require(type(challenge) is bytes and len(challenge) == 32, 'CHALLENGE')
    require(type(claim) is dict and set(claim) == {'business', 'auxiliary'}, 'CLAIM_FIELDS')
    business, ordinary_cost = independent_reference(model, requests)
    require(canonical(claim['business']) == canonical(business), 'BUSINESS_OUTPUT')
    counts = cost()
    counts['macs'], counts['additions'] = ordinary_cost.reference_macs, ordinary_cost.reference_additions
    size = {'rank1_blinded': 272, 'batch_mix': 256, 'dropout': 512}[kind]
    raw = hashlib.shake_256(PROFILE.encode() + b'\0' + kind.encode() + b'\0' + challenge +
                           bytes.fromhex(sha(model)) + bytes.fromhex(sha(requests))).digest(size)
    counts['expanded_bytes'] += size
    original = [row['x'] for row in requests]
    if kind == 'rank1_blinded':
        u = [1 if b & 1 else -1 for b in raw[:256]] + [0]
        v = [(1 if b & 8 else -1) * (1 + b % 8) for b in raw[256:]]
        z = [[x[k] + u[k] * v[i] for k in range(DIM)] for i, x in enumerate(original)]
        counts['macs'] += DIM * BATCH
        counts['additions'] += DIM * BATCH
    elif kind == 'batch_mix':
        z = [[sum(original[i][k] * ((1 if raw[i * BATCH + j] & 1 else -1) + 17 * (i == j))
                  for i in range(BATCH)) for k in range(DIM)] for j in range(BATCH)]
        counts['macs'] += DIM * BATCH * BATCH
    else:
        z = [[x[k] if raw[i * 32 + k // 8] & (1 << (k % 8)) else 0 for k in range(256)] + [8]
             for i, x in enumerate(original)]
        counts['mask_bits_examined'] += 256 * BATCH

    def original_mv(matrix, x):
        counts['macs'] += 3 * DIM
        return [sum(matrix[r][k] * x[k] for k in range(DIM)) for r in range(3)]

    def selected_mv(expert, x):
        a, b = original_mv(model['base'], x), original_mv(model['deltas'][expert], x)
        counts['additions'] += 3
        return [a[r] + b[r] for r in range(3)]

    noisy_scores = [original_mv(model['router'], x) for x in z]
    if kind == 'rank1_blinded':
        response = original_mv(model['router'], u)
        correction_r = [[value * v[i] for value in response] for i in range(BATCH)]
        scores = [[value - correction_r[i][r] for r, value in enumerate(row)]
                  for i, row in enumerate(noisy_scores)]
        routes = [max(range(3), key=row.__getitem__) for row in scores]
        require(scores == business['router_outputs'] and routes == business['routes'], 'RECOVERED_ROUTER')
        correction = {e: selected_mv(e, u) for e in set(routes)}
        correction_y = [[value * v[i] for value in correction[e]] for i, e in enumerate(routes)]
        noisy_logits = [selected_mv(e, z[i]) for i, e in enumerate(routes)]
        require([[value - correction_y[i][r] for r, value in enumerate(row)]
                 for i, row in enumerate(noisy_logits)] == business['logits'], 'RECOVERED_OUTPUT')
        counts['macs'] += 6 * BATCH
        counts['additions'] += 6 * BATCH
        auxiliary = {'router_noisy': noisy_scores, 'router_correction': correction_r,
                     'logits_noisy': noisy_logits, 'logit_correction': correction_y}
    else:
        routes = [max(range(3), key=row.__getitem__) for row in noisy_scores]
        auxiliary = product(noisy_scores, [selected_mv(e, z[i]) for i, e in enumerate(routes)])
    maximum = max(abs(value) for row in z for value in row)
    require(maximum <= INTERNAL_INPUT_BOUNDS[kind], 'INTERNAL_BOUND')
    require(canonical(claim['auxiliary']) == canonical(auxiliary), 'AUXILIARY_OUTPUT')
    return counts, maximum
