"""Exact W1 zero-task algorithms and a declared compression-query model.

No CPU benchmark, actual-SHA hardness proof, native authority or production
activation. Counts are explicitly separated scalar products/additions/reductions.
The compression theorem is about an ideal random function, not SHA-256 rounds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import json
import struct
from typing import Iterable

Q = (1 << 32) - 5
N, R = 64, 8
TRACE_DOMAIN = b'TRNM-PON-TRACE1\0'
TRACE_BLOCKS = 2049
Matrix = tuple[tuple[int, ...], ...]


def nat(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(f'{name} must be a {"positive" if positive else "nonnegative"} integer')
    return value


def pon_message(tag: bytes, *parts: bytes) -> bytes:
    if type(tag) is not bytes or len(tag) >= 1 << 16:
        raise ValueError('tag must be u16-length bytes')
    message = b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
    for part in parts:
        if type(part) is not bytes or len(part) >= 1 << 32:
            raise ValueError('parts must be u32-length bytes')
        message += struct.pack('<I', len(part)) + part
    return message


def sha_blocks(message: bytes) -> tuple[bytes, ...]:
    if type(message) is not bytes or len(message) >= 1 << 61:
        raise ValueError('SHA-256 message must have fewer than 2^64 bits')
    padded = message + b'\x80'
    padded += bytes((56 - len(padded)) % 64) + struct.pack('>Q', 8 * len(message))
    return tuple(padded[i:i + 64] for i in range(0, len(padded), 64))


def noise_message(challenge: bytes, label: int, counter: int) -> bytes:
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError('challenge must be 32 bytes')
    if type(label) is not int or not 0 <= label < 4:
        raise ValueError('W1 noise label must lie in 0..3')
    if type(counter) is not int or not 0 <= counter < 128:
        raise ValueError('W1 noise counter must lie in 0..127')
    return pon_message(b'noise', challenge, bytes([label]), struct.pack('<I', counter))


def expand(challenge: bytes, label: int, length: int) -> tuple[int, ...]:
    nat(length, 'length', positive=True)
    if length > N * R:
        raise ValueError('bounded W1 noise control cannot exceed 512 words')
    result = []
    for counter in range(128):
        digest = hashlib.sha256(noise_message(challenge, label, counter)).digest()
        for (value,) in struct.iter_unpack('<I', digest):
            if value < Q:
                result.append(value)
                if len(result) == length:
                    return tuple(result)
    raise ValueError('NOISE_BUDGET')


def parse_ticket_blocks(first: bytes, last: bytes) -> tuple[bytes, bytes] | None:
    """Literal two-block PON1 ticket parser, without trusting a digest claim.

    A query observer must obtain `first` from an already queried (IV,first)
    response equal to the last compression's input CV, BEFORE its response.
    Parsing message bytes alone does not establish this ancestry or valid W1.
    """
    if type(first) is not bytes or type(last) is not bytes or len(first) != 64 or len(last) != 64:
        return None
    challenge, trace = first[22:54], first[58:64] + last[:26]
    if sha_blocks(pon_message(b'ticket', challenge, trace)) != (first, last):
        return None
    return challenge, trace


def actual_message_geometry() -> dict[str, int]:
    header = b'PNH1\x01\x00' + bytes(312)
    messages = {
        'challenge': pon_message(b'challenge', header),
        'noise': noise_message(bytes(32), 0, 0),
        'ticket': pon_message(b'ticket', bytes(32), bytes(32)),
        'trace': TRACE_DOMAIN + bytes(32) + bytes(4 * N * N * (N // R)),
    }
    return {key + suffix: value for key, message in messages.items()
            for suffix, value in (('_bytes', len(message)), ('_blocks', len(sha_blocks(message))))}


@dataclass
class Arithmetic:
    """Counts executed mathematical operations, not Python/runtime instructions."""
    phase: str = 'unspecified'
    counts: dict[str, dict[str, int]] = field(default_factory=dict)

    def tick(self, kind: str, amount: int = 1) -> None:
        bucket = self.counts.setdefault(self.phase, dict(products=0, additions=0, reductions=0))
        bucket[kind] += amount

    def factor(self, row: tuple[int, ...]) -> int:
        total = 0
        for j in range(0, len(row), 2):
            self.tick('products')
            self.tick('additions')
            total += row[j] * row[j + 1]
        return total

    def dot(self, left: tuple[int, ...], right: tuple[int, ...], lf: int, rf: int) -> int:
        total = 0
        for j in range(0, len(left), 2):
            self.tick('products')
            self.tick('additions', 3)
            total += (left[j] + right[j + 1]) * (left[j + 1] + right[j])
        self.tick('additions', 2)
        self.tick('reductions')
        total -= lf + rf
        assert total >= 0
        return total % Q

    def combine(self, a: Matrix, b: Matrix, sign: int = 1) -> Matrix:
        self.tick('additions', len(a) * len(a[0]))
        self.tick('reductions', len(a) * len(a[0]))
        return tuple(tuple((x + sign * y) % Q for x, y in zip(ar, br))
                     for ar, br in zip(a, b))


def matrix(values: Iterable[int], rows: int, columns: int) -> Matrix:
    values = tuple(values)
    if len(values) != rows * columns or any(type(v) is not int or not 0 <= v < Q for v in values):
        raise ValueError('invalid canonical matrix')
    return tuple(values[i * columns:(i + 1) * columns] for i in range(rows))


def transpose(a: Matrix) -> Matrix:
    return tuple(zip(*a))


def paired_product(a: Matrix, bt: Matrix, af: tuple[int, ...], bf: tuple[int, ...],
                   count: Arithmetic) -> Matrix:
    return tuple(tuple(count.dot(row, column, af[i], bf[j]) for j, column in enumerate(bt))
                 for i, row in enumerate(a))


def quadrants(a: Matrix) -> tuple[Matrix, Matrix, Matrix, Matrix]:
    half = len(a) // 2
    return tuple(tuple(row[start:start + half] for row in a[top:top + half])
                 for top, start in ((0, 0), (0, half), (half, 0), (half, half)))


@dataclass(frozen=True)
class Prepared:
    size: int
    side: str
    rows: Matrix = ()
    factors: tuple[int, ...] = ()
    children: tuple['Prepared', ...] = ()


def prepare(a: Matrix, depth: int, side: str, count: Arithmetic) -> Prepared:
    nat(depth, 'depth')
    size = len(a)
    if side not in ('left', 'right') or size < 2 or size & (size - 1):
        raise ValueError('side and power-of-two size must support even paired leaves')
    if any(len(row) != size or any(type(v) is not int or not 0 <= v < Q for v in row) for row in a):
        raise ValueError('prepare requires a canonical square matrix')
    if size >> depth < 2:
        raise ValueError('Strassen leaves must have even size at least two')
    if depth == 0:
        rows = a if side == 'left' else transpose(a)
        return Prepared(size, side, rows, tuple(count.factor(row) for row in rows))
    a11, a12, a21, a22 = quadrants(a)
    plus = count.combine
    if side == 'left':
        children = (plus(a11, a22), plus(a21, a22), a11, a22,
                    plus(a11, a12), plus(a21, a11, -1), plus(a12, a22, -1))
    else:
        children = (plus(a11, a22), a11, plus(a12, a22, -1), plus(a21, a11, -1),
                    a22, plus(a11, a12), plus(a21, a22))
    return Prepared(size, side, children=tuple(prepare(c, depth - 1, side, count) for c in children))


def prepared_product(a: Prepared, b: Prepared, count: Arithmetic) -> Matrix:
    if a.size != b.size or a.side != 'left' or b.side != 'right' or bool(a.children) != bool(b.children):
        raise ValueError('incompatible prepared products')
    if not a.children:
        return paired_product(a.rows, b.rows, a.factors, b.factors, count)
    p1, p2, p3, p4, p5, p6, p7 = (
        prepared_product(x, y, count) for x, y in zip(a.children, b.children))
    plus = count.combine
    c11 = plus(plus(plus(p1, p4), p5, -1), p7)
    c12 = plus(p3, p5)
    c21 = plus(p2, p4)
    c22 = plus(plus(plus(p1, p2, -1), p3), p6)
    return tuple(x + y for x, y in zip(c11, c12)) + tuple(x + y for x, y in zip(c21, c22))


def zero_prefixes(el: Matrix, er: Matrix, fl: Matrix, fr: Matrix, *, depth: int = 2
                  ) -> tuple[tuple[int, ...], dict[str, dict[str, int]]]:
    """Same W1 bi,bj,bk,i,j order; finite control retains words for comparison.

    n may be a small multiple of the rank/tile size; deployment is n=64,r=8.
    The separate native producer streams one tile to SHA, not a full transcript.
    """
    n, r = len(el), len(fr)
    if r < 2 or r & (r - 1) or n % r or len(fl) != n or len(er) != r:
        raise ValueError('invalid factor dimensions')
    for a, rows, columns in ((el, n, r), (er, r, n), (fl, n, r), (fr, r, n)):
        matrix((v for row in a for v in row), rows, columns)
        if any(len(row) != columns for row in a):
            raise ValueError('ragged factors')
    if type(depth) is not int or depth < 0 or r >> depth < 2:
        raise ValueError('invalid paired-leaf depth')
    blocks = n // r
    count = Arithmetic('middle')
    current = tuple((0,) * r for _ in range(r))
    middles = []
    for bk in range(blocks):
        left = tuple(row[bk * r:(bk + 1) * r] for row in er)
        right = transpose(fl[bk * r:(bk + 1) * r])
        af = tuple(count.factor(row) for row in left)
        bf = tuple(count.factor(row) for row in right)
        current = count.combine(current, paired_product(left, right, af, bf, count))
        middles.append(current)
    count.phase = 'left'
    el_factors = tuple(count.factor(row) for row in el)
    middle_transposes = tuple(transpose(a) for a in middles)
    middle_factors = tuple(tuple(count.factor(row) for row in a) for a in middle_transposes)
    count.phase = 'output-right-prepare'
    rights = tuple(prepare(tuple(row[bj * r:(bj + 1) * r] for row in fr), depth, 'right', count)
                   for bj in range(blocks))
    words = []
    for bi in range(blocks):
        lefts = []
        for bk in range(blocks):
            count.phase = 'left'
            lifted = paired_product(el[bi * r:(bi + 1) * r], middle_transposes[bk],
                                    el_factors[bi * r:(bi + 1) * r], middle_factors[bk], count)
            count.phase = 'output-left-prepare'
            lefts.append(prepare(lifted, depth, 'left', count))
        for right in rights:
            for left in lefts:
                count.phase = 'output-products'
                tile = prepared_product(left, right, count)
                words.extend(v for row in tile for v in row)
    return tuple(words), count.counts


def zero_proof(challenge: bytes, *, depth: int = 2) -> tuple[bytes, dict[str, dict[str, int]]]:
    factors = [expand(challenge, label, N * R) for label in range(4)]
    el, er, fl, fr = (matrix(values, rows, columns) for values, rows, columns in
                      zip(factors, (N, R, N, R), (R, N, R, N)))
    words, counts = zero_prefixes(el, er, fl, fr, depth=depth)
    encoded = struct.pack('<' + 'I' * len(words), *words)
    trace = hashlib.sha256(TRACE_DOMAIN + challenge + encoded).digest()
    return b'PNW1' + bytes(12 * N * N) + trace, counts


def multiplication_schedule(depth: int) -> dict[str, int]:
    if type(depth) is not int or not 0 <= depth <= 2:
        raise ValueError('actual W1 r=8 permits paired-leaf depths 0,1,2')
    leaf, leaves = R >> depth, 7 ** depth
    output_pairs = (N // R) ** 3
    left_preparations, right_preparations = (N // R) ** 2, N // R
    result = {
        'middle_products': 2560, 'left_products': 16896,
        'output_cross_products': output_pairs * leaves * leaf ** 3 // 2,
        'output_left_factor_products': left_preparations * leaves * leaf ** 2 // 2,
        'output_right_factor_products': right_preparations * leaves * leaf ** 2 // 2,
    }
    result['output_products'] = sum(v for k, v in result.items() if k.startswith('output_'))
    result['total_products'] = result['middle_products'] + result['left_products'] + result['output_products']
    return result


def compression_failure_bound(*, captured_queries: int, audit_queries: int,
                              digest_references: int, state_bits: int = 256,
                              opaque_advice_bits: int = 0) -> dict[str, int | Fraction]:
    """Before-preprocessing lazy-sampling bound; see the v2 theorem.

    At each fresh compression response exclude prior outputs, prior/current
    chaining-value query addresses, IV, and prior FULL digest references.
    Arbitrary s-bit oracle advice uses only a deliberately loose 2^s union bound.
    This is not conditioned on a selected favorable advice/transcript and is not
    a SHA-256 theorem. Audit queries count in failure only, never miner resources.
    """
    for value, name in ((captured_queries, 'captured queries'), (audit_queries, 'audit queries'),
                        (digest_references, 'digest references'), (opaque_advice_bits, 'advice bits')):
        nat(value, name)
    nat(state_bits, 'state bits', positive=True)
    total = captured_queries + audit_queries
    numerator = total * (total + 1 + digest_references)
    loss = 1 << opaque_advice_bits
    return dict(total_distinct_query_cap=total, numerator_without_advice=numerator,
                denominator=1 << state_bits, advice_loss=loss,
                union_bound=min(Fraction(1), Fraction(loss * numerator, 1 << state_bits)))


def compression_opportunity_cap(*, preprocessing_queries: int, online_queries: int,
                                previously_exposed_trace_paths: int = 0,
                                blocks_per_trace: int = TRACE_BLOCKS) -> int:
    """Good-event class only; all query units, with no seconds/FLOPs conversion.

    Exposed paths are distinct-challenge CANONICAL paths, including prepared
    winners AND prepared misses with a seen lottery answer. A queried invalid
    trace path is not retired here; it may share a prefix with a canonical path. They cannot be counted as new fresh opportunities again.
    Do not subtract paths absent from the captured preprocessing query budget.
    """
    for value, name in ((preprocessing_queries, 'preprocessing queries'),
                        (online_queries, 'online queries'),
                        (previously_exposed_trace_paths, 'exposed paths')):
        nat(value, name)
    nat(blocks_per_trace, 'blocks per trace', positive=True)
    retired = previously_exposed_trace_paths * blocks_per_trace
    if retired > preprocessing_queries:
        raise ValueError('retired paths exceed the captured preparation budget')
    return (preprocessing_queries - retired + online_queries) // blocks_per_trace


def prefix_bank_cap(prepaid_prefix_lengths: Iterable[int], online_queries: int,
                    *, blocks_per_trace: int = TRACE_BLOCKS) -> int:
    """Exact completion count for a disjoint exposed prefix bank plus new paths.

    No selected-ticket outcome or proof randomness enters this count. Existing
    completed/exposed lotteries must be retired before passing this bank.
    """
    nat(online_queries, 'online queries')
    nat(blocks_per_trace, 'blocks per trace', positive=True)
    lengths = tuple(prepaid_prefix_lengths)
    if any(type(length) is not int or not 0 <= length <= blocks_per_trace for length in lengths):
        raise ValueError('invalid prepaid path length')
    count = 0
    for remaining in sorted(blocks_per_trace - length for length in lengths):
        if remaining > online_queries:
            break
        online_queries -= remaining
        count += 1
    return count + online_queries // blocks_per_trace


@dataclass
class QueryGraph:
    """Transparent deterministic finite transcript for testing the graph lemma.

    Outputs are supplied by a test, not a cryptographic oracle implementation.
    Real probability is the separate random-compression model in the document.
    Duplicate queries cost no new query. Audits cannot be assigned miner credit.
    """
    iv: int = 0
    table: dict[tuple[int, bytes], int] = field(default_factory=dict)
    first_at: dict[tuple[int, bytes], int] = field(default_factory=dict)
    origins: dict[tuple[int, bytes], str] = field(default_factory=dict)
    references: list[tuple[int, int]] = field(default_factory=list)
    bad_events: list[str] = field(default_factory=list)

    def query(self, state: int, block: bytes, output: int, *, origin: str = 'online') -> int:
        if origin not in ('prep', 'online', 'audit') or type(block) is not bytes:
            raise ValueError('invalid query origin or block')
        key = (state, block)
        if key in self.table:
            if output != self.table[key]:
                raise ValueError('inconsistent oracle response')
            return output
        if output in self.table.values():
            self.bad_events.append('output-collision')
        if output == self.iv or output == state or any(output == key[0] for key in self.table):
            self.bad_events.append('prior-chaining-address-or-IV')
        if any(output == value for _, value in self.references):
            self.bad_events.append('prior-full-digest-reference')
        self.table[key] = output
        self.first_at[key] = len(self.table)
        self.origins[key] = origin
        return output

    def ticket_query(self, state: int, block: bytes, output: int, *, origin: str = 'online'
                     ) -> tuple[bytes, bytes] | None:
        """Record a structurally opened full t before a ticket-final response.

        At most one ancestry can exist outside output-collision Bad. A later
        first-block opening to an earlier guessed CV itself causes Bad. This
        parser does not assert canonical validity or a predictable lottery set.
        """
        candidates = [first for (iv, first), value in self.table.items()
                      if iv == self.iv and value == state]
        opened = parse_ticket_blocks(candidates[0], block) if len(candidates) == 1 else None
        if opened is not None:
            self.reference(int.from_bytes(opened[1], 'big'))
        self.query(state, block, output, origin=origin)
        return opened

    def reference(self, digest: int) -> int:
        moment = len(self.table)
        self.references.append((moment, digest))
        return moment

    def path(self, blocks: tuple[bytes, ...]) -> tuple[tuple[int, bytes], ...]:
        state = self.iv
        path = []
        for block in blocks:
            key = (state, block)
            if key not in self.table:
                raise ValueError('path not completely audited')
            path.append(key)
            state = self.table[key]
        return tuple(path)

    def canonical_coverage(self, openings: Iterable[tuple[tuple[bytes, ...], int, int]]) -> dict[str, int | bool]:
        paths = []
        first_blocks = set()
        for blocks, digest, at in openings:
            if (at, digest) not in self.references:
                raise ValueError('opening must cite an actual prior full-digest reference')
            if not blocks or blocks[0] in first_blocks:
                raise ValueError('the disjoint-trace lemma requires distinct first blocks')
            first_blocks.add(blocks[0])
            path = self.path(blocks)
            if self.table[path[-1]] != digest:
                raise ValueError('opening is not the claimed canonical digest')
            paths.append((path, at))
        edges = set().union(*(set(path) for path, _ in paths)) if paths else set()
        temporal = all(self.first_at[key] <= at and self.origins[key] != 'audit'
                       for path, at in paths for key in path)
        total_length = sum(len(path) for path, _ in paths)
        return dict(paths=len(paths), path_edges=total_length, distinct_edges=len(edges),
                    edge_disjoint=len(edges) == total_length, complete_before_reference=temporal,
                    bad_event=bool(self.bad_events), captured_distinct_queries=sum(
                        origin != 'audit' for origin in self.origins.values()))


def repeated_salt_control(*, paths: int, prefix_blocks: int, suffix_blocks: int) -> dict[str, int]:
    for value, name in ((paths, 'paths'), (prefix_blocks, 'prefix blocks'), (suffix_blocks, 'suffix blocks')):
        nat(value, name, positive=True)
    return dict(independent_count=paths * (prefix_blocks + suffix_blocks),
                reusable_prefix_count=prefix_blocks + paths * suffix_blocks)


def summary() -> dict:
    schedules = {str(depth): multiplication_schedule(depth) for depth in range(3)}
    return {
        'schema': 'w1-multi-instance-cost-v2',
        'actual_message_geometry': actual_message_geometry(),
        'zero_task_scalar_product_schedules': schedules,
        'depth2_product_saving_fraction': Fraction(152832 - 126864, 152832),
        'compression_query_model': {
            'query_units_per_distinct_trace': TRACE_BLOCKS,
            'failure_example_Q8_V4_R2': compression_failure_bound(
                captured_queries=8, audit_queries=4, digest_references=2),
            'partial_prefix_example': prefix_bank_cap((2048, 2047), 3),
            'same_salt_counterexample': repeated_salt_control(paths=2, prefix_blocks=3, suffix_blocks=1),
        },
        'qualifications': {
            'actual_sha256_lower_bound_proved': False,
            'universal_matrix_cost_lower_bound_proved': False,
            'physical_cost_floor_proved': False,
            'cpu_speedup_measured': False,
            'all_project_blockers_closed': False,
            'production_activation': False,
        },
    }


def json_exact(value):
    if isinstance(value, Fraction):
        return {'numerator': value.numerator, 'denominator': value.denominator}
    raise TypeError(type(value).__name__)


if __name__ == '__main__':
    print(json.dumps(summary(), default=json_exact, sort_keys=True, indent=2))
