"""Source-bound W1 ticket-composition controls, not a SHA security assumption.

The probability model uses independent per-message-block permutations. Actual
SHA is used only in framing/differential controls. ChronologyControl accepts
explicitly scripted permutation entries: its examples are exact countermodels,
not random samples or measured mining performance.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction
from itertools import permutations, product
from math import comb
from types import MappingProxyType
from typing import Iterable, Mapping
import hashlib
import json
import struct

import w1_multi_instance_cost_v2 as geometry

Q = (1 << 32) - 5
MATRIX_N, RANK, CELLS = 64, 8, 4096
TRACE_BLOCKS = 2049
STATE_SIZE = 1 << 256
Block = bytes


def integer(value: int, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def digest(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("digest must contain exactly 32 bytes")
    return value


@dataclass(frozen=True)
class BlockPattern:
    """A superset of legal blocks; None is an unconstrained byte."""
    values: tuple[int | None, ...]

    def __post_init__(self):
        if len(self.values) != 64 or any(
            value is not None and (type(value) is not int or not 0 <= value < 256)
            for value in self.values
        ):
            raise ValueError("a pattern must have 64 byte constraints")

    @classmethod
    def masked(cls, block: bytes, variable: Iterable[int]) -> "BlockPattern":
        if len(block) != 64:
            raise ValueError("block length")
        values = list(block)
        for position in variable:
            integer(position, "position")
            if position >= 64:
                raise ValueError("position")
            values[position] = None
        return cls(tuple(values))

    def conflicts(self, other: "BlockPattern") -> tuple[int, ...]:
        return tuple(i for i, (a, b) in enumerate(zip(self.values, other.values))
                     if a is not None and b is not None and a != b)

    def contains(self, block: bytes) -> bool:
        return len(block) == 64 and all(a is None or a == b
                                       for a, b in zip(self.values, block))


def key_patterns() -> dict[str, BlockPattern]:
    noise = geometry.sha_blocks(geometry.noise_message(bytes(32), 0, 0))
    ticket = geometry.sha_blocks(geometry.pon_message(b"ticket", bytes(32), bytes(32)))
    return {
        # This deliberately overapproximates labels/counter-low-byte ranges.
        "noise_first": BlockPattern.masked(noise[0], (*range(21, 53), 57, 62)),
        "noise_last": BlockPattern.masked(noise[1], ()),
        "ticket_last": BlockPattern.masked(ticket[1], range(26)),
    }


def key_separation() -> dict[str, tuple[int, ...]]:
    patterns = key_patterns()
    return {name: patterns[name].conflicts(patterns["ticket_last"])
            for name in ("noise_first", "noise_last")}


@dataclass(frozen=True)
class HeaderOpening:
    encoded: bytes
    target: int
    task: bytes


def parse_header_blocks(blocks: tuple[bytes, ...]) -> HeaderOpening | None:
    """Parse the exact six-block challenge message, including SHA padding."""
    if len(blocks) != 6 or any(len(block) != 64 for block in blocks):
        return None
    raw = b"".join(blocks)[25:343]
    if len(raw) != 318 or raw[:6] != b"PNH1\x01\x00":
        return None
    if geometry.sha_blocks(geometry.pon_message(b"challenge", raw)) != blocks:
        return None
    return HeaderOpening(raw, int.from_bytes(raw[118:150], "big"), raw[278:310])


def parse_task_blocks(blocks: tuple[bytes, ...]) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    if len(blocks) != 513 or any(len(block) != 64 for block in blocks):
        return None
    raw = b"".join(blocks)
    left, right = raw[20:16404], raw[16408:32792]
    if geometry.sha_blocks(geometry.pon_message(b"task", left, right)) != blocks:
        return None
    a = tuple(value for (value,) in struct.iter_unpack("<I", left))
    b = tuple(value for (value,) in struct.iter_unpack("<I", right))
    if len(a) != CELLS or len(b) != CELLS or any(value >= Q for value in a + b):
        return None
    return a, b


def parse_trace_blocks(blocks: tuple[bytes, ...]) -> tuple[bytes, tuple[int, ...]] | None:
    if len(blocks) != TRACE_BLOCKS or any(len(block) != 64 for block in blocks):
        return None
    raw = b"".join(blocks)[:131120]
    if raw[:16] != geometry.TRACE_DOMAIN or geometry.sha_blocks(raw) != blocks:
        return None
    words = tuple(value for (value,) in struct.iter_unpack("<I", raw[48:]))
    if len(words) != 32768 or any(value >= Q for value in words):
        return None
    return raw[16:48], words


def first_block_challenge(block: bytes) -> bytes | None:
    """A syntactic c reference, including requests at arbitrary CVs."""
    if len(block) != 64:
        return None
    if block[:16] == geometry.TRACE_DOMAIN:
        return block[16:48]
    c = block[22:54]
    t = block[58:64] + bytes(26)
    if geometry.sha_blocks(geometry.pon_message(b"ticket", c, t))[0] == block:
        return c
    return None


def field_bytes(values: Iterable[int]) -> bytes:
    words = tuple(values)
    if any(type(value) is not int or not 0 <= value < Q for value in words):
        raise ValueError("noncanonical field word")
    return struct.pack("<" + "I" * len(words), *words)


def matrix_product(a: tuple[int, ...], b: tuple[int, ...],
                   rows: int, inner: int, columns: int) -> tuple[int, ...]:
    if len(a) != rows * inner or len(b) != inner * columns:
        raise ValueError("matrix length")
    return tuple(sum(a[i * inner + k] * b[k * columns + j]
                     for k in range(inner)) % Q
                 for i in range(rows) for j in range(columns))


def expanded_noise(challenge: bytes) -> tuple[tuple[int, ...], ...]:
    return tuple(geometry.expand(digest(challenge), label, 512) for label in range(4))


def canonical_prefixes(a: tuple[int, ...], b: tuple[int, ...],
                       noise: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    """Literal arithmetic validity given already fixed expansion values.

    Supplying this array is an ANALYSIS interface, not an uncharged miner oracle.
    The ideal-model observer derives it from the hidden, disjoint noise subfamily.
    """
    if len(a) != CELLS or len(b) != CELLS or len(noise) != 4:
        raise ValueError("matrix/noise length")
    if any(len(factor) != 512 for factor in noise):
        raise ValueError("noise length")
    field_bytes(a + b + tuple(value for factor in noise for value in factor))
    el, er, fl, fr = noise
    e = matrix_product(el, er, 64, 8, 64)
    f = matrix_product(fl, fr, 64, 8, 64)
    aa = tuple((x + y) % Q for x, y in zip(a, e))
    bb = tuple((x + y) % Q for x, y in zip(b, f))
    accum = [0] * CELLS
    words = []
    for bi in range(0, 64, 8):
        for bj in range(0, 64, 8):
            for bk in range(0, 64, 8):
                for i in range(bi, bi + 8):
                    for j in range(bj, bj + 8):
                        index = i * 64 + j
                        accum[index] = (accum[index] + sum(
                            aa[i * 64 + k] * bb[k * 64 + j]
                            for k in range(bk, bk + 8))) % Q
                        words.append(accum[index])
    return tuple(words)


def trace_key_overlap(challenge: bytes) -> dict:
    """Construct a relation-level canonical trace containing a ticket-final key.

    This fixes c externally, chooses A'=I and B', then removes exact noise.
    It is not a header/task fixed point or a native admissible block attack.
    The overlapping ticket key is for trace=0, not asserted to be this trace's
    actual final digest.
    """
    c = digest(challenge)
    block = geometry.sha_blocks(geometry.pon_message(b"ticket", c, bytes(32)))[1]
    desired = tuple(value for (value,) in struct.iter_unpack("<I", block))
    field_bytes(desired)
    noise = expanded_noise(c)
    el, er, fl, fr = noise
    e = matrix_product(el, er, 64, 8, 64)
    f = matrix_product(fl, fr, 64, 8, 64)
    aa = tuple(int(i == j) for i in range(64) for j in range(64))
    bb = [0] * CELLS
    # Prefix word numbers 4..19 occupy the trace's second 64-byte block.
    for offset, value in enumerate(desired, 4):
        i, j = divmod(offset, 8)
        bb[i * 64 + j] = value
    a = tuple((x - y) % Q for x, y in zip(aa, e))
    b = tuple((x - y) % Q for x, y in zip(bb, f))
    prefixes = canonical_prefixes(a, b, noise)
    blocks = geometry.sha_blocks(geometry.TRACE_DOMAIN + c + field_bytes(prefixes))
    return {"challenge": c, "a": a, "b": b, "noise": noise,
            "prefixes": prefixes, "overlap_block": block,
            "trace_blocks": blocks,
            "trace_digest": hashlib.sha256(
                geometry.TRACE_DOMAIN + c + field_bytes(prefixes)).digest()}


@dataclass(frozen=True)
class Reference:
    query: int
    kind: str
    value: bytes


@dataclass(frozen=True)
class CapturedPaths:
    """Copied immutable rooted-path table at the single seal boundary."""
    root: int
    parents: Mapping[int, tuple[int, bytes]]
    calls: int
    entries: int
    joined: bool

    def __post_init__(self):
        object.__setattr__(self, "parents", MappingProxyType(dict(self.parents)))

    def path_to(self, state: int, maximum: int) -> tuple[bytes, ...] | None:
        if self.joined:
            return None
        path = []
        while state != self.root:
            if len(path) == maximum or state not in self.parents:
                return None
            state, block = self.parents[state]
            path.append(block)
        return tuple(reversed(path))


@dataclass
class ChronologyControl:
    """Exact scripted graph and pre-answer parser, over the toy group Z/(2^256).

    Arbitrary script responses are checked for permutation consistency. They are
    not sampled; this object proves no probability bound and does not implement
    SHA. Both query directions and unrooted components remain available.
    """
    root: int = 0
    table: dict[tuple[bytes, int], int] = field(default_factory=dict)
    reverse: dict[tuple[bytes, int], int] = field(default_factory=dict)
    vertices: set[int] = field(default_factory=set)
    parents: dict[int, tuple[int, bytes]] = field(default_factory=dict)
    references: list[Reference] = field(default_factory=list)
    protected: set[int] = field(default_factory=set)
    calls: int = 0
    joined: bool = False
    next_script_output: int = 100
    sealed_capture: CapturedPaths | None = None

    def __post_init__(self):
        if type(self.root) is not int or not 0 <= self.root < STATE_SIZE:
            raise ValueError("root")
        self.vertices.add(self.root)

    def path_to(self, state: int, maximum: int) -> tuple[bytes, ...] | None:
        if self.joined:
            return None
        path = []
        while state != self.root:
            if len(path) == maximum or state not in self.parents:
                return None
            state, block = self.parents[state]
            path.append(block)
        return tuple(reversed(path))

    def reference(self, kind: str, value: bytes) -> None:
        self.references.append(Reference(self.calls, kind, digest(value)))
        self.protected.add(int.from_bytes(value, "big"))

    def _before(self, block: bytes, h: int | None) -> None:
        if type(block) is not bytes or len(block) != 64:
            raise ValueError("block")
        self.calls += 1
        c = first_block_challenge(block)
        if c is not None:
            self.reference("challenge", c)
        path = None if h is None else self.path_to(h, 5)
        if path is not None and len(path) == 5:
            parsed = parse_header_blocks(path + (block,))
            if parsed is not None:
                self.reference("task", parsed.task)
        if path is not None and len(path) == 1:
            parsed_ticket = geometry.parse_ticket_blocks(path[0], block)
            if parsed_ticket is not None:
                self.reference("trace", parsed_ticket[1])

    def forward(self, block: bytes, h: int, y: int) -> int:
        if not 0 <= h < STATE_SIZE or not 0 <= y < STATE_SIZE:
            raise ValueError("state")
        self._before(block, h)
        key = (block, h)
        z = (h + y) % STATE_SIZE
        if key in self.table:
            if self.table[key] != y:
                raise ValueError("inconsistent repeated forward entry")
            return z
        if (block, y) in self.reverse:
            raise ValueError("not a permutation")
        old = self.vertices | self.protected
        self.joined = self.joined or z in old or z == h
        self.table[key] = y
        self.reverse[(block, y)] = h
        self.vertices.update((h, z))
        if not self.joined and (h == self.root or h in self.parents):
            self.parents[z] = (h, block)
        return z

    def inverse(self, block: bytes, y: int, h: int) -> int:
        if not 0 <= h < STATE_SIZE or not 0 <= y < STATE_SIZE:
            raise ValueError("state")
        self._before(block, None)
        key = (block, y)
        z = (h + y) % STATE_SIZE
        if key in self.reverse:
            if self.reverse[key] != h:
                raise ValueError("inconsistent repeated inverse entry")
            return h
        if (block, h) in self.table:
            raise ValueError("not a permutation")
        old = self.vertices | self.protected
        self.joined = self.joined or h in old or z in old
        self.table[(block, h)] = y
        self.reverse[key] = h
        self.vertices.update((h, z))
        return h

    def scripted_forward(self, block: bytes, h: int) -> int:
        if (block, h) in self.table:
            return self.forward(block, h, self.table[(block, h)])
        while True:
            y = self.next_script_output
            self.next_script_output += 1
            z = (h + y) % STATE_SIZE
            if ((block, y) not in self.reverse and z not in self.vertices
                    and z not in self.protected and z != h):
                return self.forward(block, h, y)

    def open_path(self, blocks: tuple[bytes, ...], final: int | None = None) -> int:
        h = self.root
        for index, block in enumerate(blocks):
            if index == len(blocks) - 1 and final is not None:
                h = self.forward(block, h, (final - h) % STATE_SIZE)
            else:
                h = self.scripted_forward(block, h)
        return h


def seal_openings(observer: ChronologyControl,
                  openings: Iterable[tuple[bytes, bytes]], *,
                  maximum_openings: int) -> CapturedPaths:
    """Register ALL t/d first, then seal once, before any auditor oracle call.

    The opened pairs contain literal (header bytes, full trace). Their relation
    may be wrong. Validation here is grammar only, and performs no hash query.
    A later auditor exposure cannot enlarge this copied captured path table.
    """
    integer(maximum_openings, "maximum_openings")
    if observer.sealed_capture is not None:
        raise ValueError("captured table already sealed")
    submitted = tuple(openings)
    if len(submitted) > maximum_openings:
        raise ValueError("sealed opening cap")
    parsed = []
    for raw_header, t in submitted:
        if type(raw_header) is not bytes:
            raise ValueError("header bytes")
        h = parse_header_blocks(geometry.sha_blocks(
            geometry.pon_message(b"challenge", raw_header)))
        if h is None:
            raise ValueError("header grammar")
        parsed.append((h, digest(t)))
    # This whole loop contains no primitive queries. Later per-opening audit is
    # deliberately outside the seal operation.
    for h, t in parsed:
        observer.reference("trace", t)
        observer.reference("task", h.task)
    capture = CapturedPaths(observer.root, observer.parents, observer.calls,
                            len(observer.table), observer.joined)
    observer.sealed_capture = capture
    return capture


@dataclass(frozen=True)
class BoundCandidate:
    header: HeaderOpening
    a: tuple[int, ...]
    b: tuple[int, ...]
    prefixes: tuple[int, ...]

    def canonical(self, noise: tuple[tuple[int, ...], ...]) -> bool:
        return self.header.target != 0 and self.prefixes == canonical_prefixes(self.a, self.b, noise)


def extract_candidate(observer: ChronologyControl, c: bytes, t: bytes) -> BoundCandidate | None:
    """Use current captured work online, and the immutable seal snapshot later.

    There is no caller flag claiming that a new auditor path was captured.
    After seal_openings, the guard automatically excludes all later exposures.
    """
    if observer.joined:
        return None
    paths = observer.sealed_capture if observer.sealed_capture is not None else observer
    header_path = paths.path_to(int.from_bytes(digest(c), "big"), 6)
    header = None if header_path is None else parse_header_blocks(header_path)
    if header is None:
        return None
    task_path = paths.path_to(int.from_bytes(header.task, "big"), 513)
    matrices = None if task_path is None else parse_task_blocks(task_path)
    trace_path = paths.path_to(int.from_bytes(digest(t), "big"), TRACE_BLOCKS)
    trace = None if trace_path is None else parse_trace_blocks(trace_path)
    if matrices is None or trace is None or trace[0] != c:
        return None
    return BoundCandidate(header, matrices[0], matrices[1], trace[1])


def fresh_probability_bounds(size: int, target: int, used: int) -> tuple[Fraction, Fraction]:
    integer(size, "size", 2)
    integer(target, "target")
    integer(used, "used")
    if target >= size or used >= size:
        raise ValueError("target/table outside state space")
    accepted = target + 1
    return (Fraction(max(0, accepted - used), size - used),
            min(Fraction(1), Fraction(accepted, size - used)))


def exact_fresh_probability(size: int, target: int, h: int,
                            used_outputs: Iterable[int]) -> Fraction:
    outputs = tuple(used_outputs)
    lower, upper = fresh_probability_bounds(size, target, len(outputs))
    if len(set(outputs)) != len(outputs) or any(
            type(y) is not int or not 0 <= y < size for y in outputs):
        raise ValueError("used outputs")
    if type(h) is not int or not 0 <= h < size:
        raise ValueError("state")
    remaining = set(range(size)) - set(outputs)
    result = Fraction(sum((h + y) % size <= target for y in remaining), len(remaining))
    if not lower <= result <= upper:
        raise AssertionError("conditional envelope")
    return result


def native_weight(size: int, target: int) -> int:
    integer(size, "size", 2)
    integer(target, "target", 1)
    if target >= size:
        raise ValueError("target")
    return size // (target + 1)


def binomial_tail(trials: int, probability: Fraction, at_least: int) -> Fraction:
    integer(trials, "trials")
    integer(at_least, "at_least")
    if not isinstance(probability, Fraction) or not 0 <= probability <= 1:
        raise ValueError("probability")
    return sum((Fraction(comb(trials, k)) * probability ** k
                * (1 - probability) ** (trials - k)
                for k in range(at_least, trials + 1)), Fraction(0))


def fresh_capacity(preprocessing: int, online: int, retired: int,
                   path_blocks: int = TRACE_BLOCKS) -> int:
    """Conditional arithmetic only: retired must be covered CANONICAL paths."""
    for name, value in (("preprocessing", preprocessing), ("online", online), ("retired", retired)):
        integer(value, name)
    integer(path_blocks, "path_blocks", 1)
    if path_blocks * retired > preprocessing:
        raise ValueError("retirement has no captured path allowance")
    return (preprocessing - path_blocks * retired + online) // path_blocks


def adaptive_marked_distribution(size: int = 5, target: int = 1,
                                 queries: int = 3, mark_cap: int = 2) -> dict[int, Fraction]:
    """Exhaustive finite conditional-process control; not a W1 cost experiment.

    Ticket queries adapt to earlier ticket outputs. The marker sees a disjoint
    hidden noise permutation, but the query scheduler does not. All ticket-key
    calls, marked or not, deplete the same permutation. Only pre-answer marks
    count; no conditioning on a future Join or future validity set is performed.
    """
    integer(size, "size", 2)
    if size > 6 or not 1 <= queries < size or not 0 <= target < size:
        raise ValueError("finite control range")
    integer(mark_cap, "mark_cap")
    all_permutations = tuple(permutations(range(size)))
    counts = Counter()
    for noise, ticket in product(all_permutations, repeat=2):
        available = list(range(size))
        previous = 0
        marked = 0
        wins = 0
        for index in range(queries):
            h = available.pop((previous + index) % len(available))
            mark = noise[h] % 2 == 0 and marked < mark_cap
            if mark:
                marked += 1
            answer = (h + ticket[h]) % size
            if mark and answer <= target:
                wins += 1
            previous = answer
        counts[wins] += 1
    denominator = len(all_permutations) ** 2
    return {wins: Fraction(count, denominator) for wins, count in sorted(counts.items())}


def selection_countermodels() -> dict[str, Fraction]:
    # Independent N,L: V=(N==0) is measurable after enlarging by N;
    # shared primitive: V=(L==0) leaks the lottery itself and is invalid.
    independent = [(noise == 0, lottery == 0)
                   for noise, lottery in product(range(2), repeat=2)]
    shared = [(lottery == 0, lottery == 0) for lottery in range(2)]
    def conditional(rows):
        selected = [win for valid, win in rows if valid]
        return Fraction(sum(selected), len(selected))
    # Stop after the first success: runs whose realized trial count is 1 all win.
    stopped = [(1 if first == 0 else 2, first == 0 or second == 0)
               for first, second in product(range(2), repeat=2)]
    return {
        "independent_noise_valid_subset_win_probability": conditional(independent),
        "overlapping_noise_valid_subset_win_probability": conditional(shared),
        "conditioned_on_one_realized_trial_win_probability":
            Fraction(sum(win for count, win in stopped if count == 1),
                     sum(count == 1 for count, _ in stopped)),
        "unconditioned_two_trial_any_win_probability": Fraction(3, 4),
    }


def summary() -> dict:
    distribution = adaptive_marked_distribution()
    upper = fresh_probability_bounds(5, 1, 2)[1]
    return {
        "scope": "source-byte controls and exact finite ideal-permutation controls",
        "key_family_conflicting_offsets": key_separation(),
        "trace_path_blocks": TRACE_BLOCKS,
        "shared_key_example": {
            "nominal": Fraction(1, 2),
            "miss_removed": exact_fresh_probability(4, 1, 0, (3,)),
            "hit_removed": exact_fresh_probability(4, 1, 0, (0,)),
            "native_weight": native_weight(4, 1),
        },
        "adaptive_control": {
            "size": 5, "queries": 3, "pre_answer_mark_cap": 2,
            "upper_probability": upper, "win_distribution": distribution,
            "tail_upper": {k: binomial_tail(2, upper, k) for k in (1, 2)},
        },
        "negative_selection_controls": selection_countermodels(),
        "actual_sha_instantiation_proved": False,
        "physical_cost_bound_proved": False,
        "original_O01_O02_closed": False,
    }


def json_exact(value):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator}
    raise TypeError(type(value).__name__)


if __name__ == "__main__":
    print(json.dumps(summary(), default=json_exact, indent=2, sort_keys=True))
