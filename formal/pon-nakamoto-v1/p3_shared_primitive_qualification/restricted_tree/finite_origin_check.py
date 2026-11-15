#!/usr/bin/env python3
"""Finite falsifying controls for the retained-construction proof's invariant.

X is a scalar toy set. One toy leaf symbol represents one complete rate block.
Enumeration is not an asymptotic proof or a test of concrete Poseidon2 security.
"""
from __future__ import annotations
from itertools import combinations, permutations, product

Pair = tuple[int, int]


def has_bad(table: dict[Pair, Pair], order: tuple[Pair, ...], directions: tuple[str, ...]) -> bool:
    forward: list[tuple[Pair, Pair]] = []
    inverse: list[tuple[Pair, Pair]] = []
    for source, direction in zip(order, directions, strict=True):
        target = table[source]
        a, b = source
        u, v = target
        if direction == "F":
            if any(u == old_target[0] or v == old_target[1] for _, old_target in forward):
                return True
            if any(u in old_source or v in old_source for old_source, _ in inverse):
                return True
            forward.append((source, target))
        elif direction == "I":
            if a == 0 or b == 0:
                return True
            if any(a in old_target or b in old_target for _, old_target in forward):
                return True
            inverse.append((source, target))
        else:
            raise ValueError("direction must be F or I")
    return False


def evaluate(table: dict[Pair, Pair], row: tuple[int, ...], siblings: tuple[int, ...], index: int):
    if not row:
        raise ValueError("positive fixed leaf width required")
    calls: list[Pair] = []
    capacity = 0
    digest = 0
    for symbol in row:
        query = (symbol, capacity)
        calls.append(query)
        digest, capacity = table[query]
    for j, sibling in enumerate(siblings):
        query = (sibling, digest) if (index >> j) & 1 else (digest, sibling)
        calls.append(query)
        digest = table[query][0]
    return digest, tuple(calls)


def complete_permutation(n: int, pinned: dict[Pair, Pair]) -> dict[Pair, Pair]:
    universe = tuple(product(range(n), repeat=2))
    if len(set(pinned.values())) != len(pinned):
        raise ValueError("pinned map is not injective")
    unused_inputs = [x for x in universe if x not in pinned]
    unused_outputs = [y for y in universe if y not in pinned.values()]
    return dict(pinned) | dict(zip(unused_inputs, unused_outputs, strict=True))


def exhaustive_check() -> dict[str, int]:
    universe = tuple(product(range(2), repeat=2))
    checked_orders = 0
    conflicting_openings = 0
    distinct_cases = 0
    for outputs in permutations(universe):
        table = dict(zip(universe, outputs, strict=True))
        checked_callsets: set[frozenset[Pair]] = set()
        for blocks in (1, 2, 3):
            rows = tuple(product(range(2), repeat=blocks))
            for height in (0, 1, 2):
                paths = tuple(product(range(2), repeat=height))
                for index in range(1 << height):
                    runs = [
                        (row, path, evaluate(table, row, path, index))
                        for row in rows for path in paths
                    ]
                    for (row0, _, run0), (row1, _, run1) in combinations(runs, 2):
                        if row0 == row1 or run0[0] != run1[0]:
                            continue
                        conflicting_openings += 1
                        callset = frozenset(run0[1] + run1[1])
                        if callset in checked_callsets:
                            continue
                        checked_callsets.add(callset)
                        distinct_cases += 1
                        # Every possible first-exposure order and direction for
                        # required pairs is checked, a superset of reachable
                        # verifier schedules. Extra unrelated pairs can only
                        # add bad equalities once origins are fixed.
                        for order in permutations(callset):
                            for directions in product(("F", "I"), repeat=len(order)):
                                checked_orders += 1
                                if not has_bad(table, order, directions):
                                    raise AssertionError((table, row0, row1, order, directions))
    return {"permutations": 24, "conflicting_opening_pairs": conflicting_openings,
            "distinct_table_callset_cases": distinct_cases,
            "first_exposure_order_direction_cases": checked_orders}


def controls() -> None:
    # Raw inverse collision can remain entirely outside the authenticated
    # no-bad provenance graph. This is intentionally NOT rejected by has_bad.
    table = complete_permutation(3, {(1, 1): (0, 0), (2, 2): (0, 1)})
    order = ((1, 1), (2, 2))
    assert table[order[0]][0] == table[order[1]][0]
    assert not has_bad(table, order, ("I", "I"))

    # A cross-shape alias also exists without any bad event: H(a)=C(a,0),
    # where a=H(m). Fixed context is indispensable for the binding proposition.
    table = complete_permutation(3, {(0, 0): (1, 1), (1, 0): (2, 2)})
    height0 = evaluate(table, (1,), (), 0)
    height1 = evaluate(table, (0,), (0,), 0)
    assert height0[0] == height1[0] == 2
    assert not has_bad(table, ((0, 0), (1, 0)), ("F", "F"))


if __name__ == "__main__":
    import json
    controls()
    result = exhaustive_check()
    result["structural_controls"] = 2
    print(json.dumps(result, sort_keys=True))
