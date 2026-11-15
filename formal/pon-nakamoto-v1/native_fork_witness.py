#!/usr/bin/env python3
"""Exact additive-weight fork algebra for the PoN research continuation.

This is an independent finite tree model, NOT a PoN validator, resource lower
bound, timestamp validator, stochastic mining model, or native risk certificate.
The caller supplies already valid block identities and their positive weights.
The implementation checks local first-removal algebra, inventory decomposition,
the two native confirmation inequalities, and the strict/non-strict tie boundary.
No probability, hardware budget, or production parameter is inferred.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from itertools import product
import json
from pathlib import Path
from typing import Iterable


def natural(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(name)
    return value


@dataclass(frozen=True)
class Block:
    block_id: str
    parent: str | None
    weight: int
    producer: str
    ready_at: int


class Tree:
    """Rooted parent tree; ready_at is a model clock, never a header timestamp."""

    def __init__(self) -> None:
        self.blocks: dict[str, Block] = {"g": Block("g", None, 0, "G", 0)}
        self._score: dict[str, int] = {"g": 0}
        self._path: dict[str, tuple[str, ...]] = {"g": ("g",)}

    def add(self, block_id: str, parent: str, weight: int, producer: str,
            ready_at: int) -> None:
        if not block_id or block_id in self.blocks:
            raise ValueError("DUPLICATE_OR_EMPTY_ID")
        if parent not in self.blocks:
            raise ValueError("UNKNOWN_PARENT")
        natural(weight, "POSITIVE_WEIGHT", positive=True)
        natural(ready_at, "MODEL_TIME")
        if producer not in ("A", "H"):
            raise ValueError("PRODUCER")
        if ready_at < self.blocks[parent].ready_at:
            raise ValueError("NONCAUSAL_READY_TIME")
        self.blocks[block_id] = Block(block_id, parent, weight, producer, ready_at)
        self._score[block_id] = self._score[parent] + weight
        self._path[block_id] = self._path[parent] + (block_id,)

    def score(self, tip: str) -> int:
        return self._score[tip]

    def path(self, tip: str) -> tuple[str, ...]:
        return self._path[tip]

    def contains(self, tip: str, block: str) -> bool:
        return block in self._path[tip]

    def lca(self, left: str, right: str) -> str:
        common = "g"
        for a, b in zip(self.path(left), self.path(right)):
            if a != b:
                break
            common = a
        return common

    def suffix(self, tip: str, ancestor: str) -> tuple[str, ...]:
        path = self.path(tip)
        if ancestor not in path:
            raise ValueError("CUT_NOT_ANCESTOR")
        return path[path.index(ancestor) + 1:]

    def activate(self, incumbent: str, candidate: str, *,
                 fully_valid_available: bool = True) -> str:
        if not fully_valid_available:
            return incumbent
        return candidate if self.score(candidate) > self.score(incumbent) else incumbent


def confirmation(tree: Tree, included: str, tip: str, *, depth_required: int = 6,
                 work_multiplier: int = 6) -> dict:
    natural(depth_required, "DEPTH")
    natural(work_multiplier, "MULTIPLIER")
    if included == "g" or included not in tree.blocks:
        raise ValueError("NON_GENESIS_INCLUDED_BLOCK")
    present = tree.contains(tip, included)
    depth = len(tree.path(tip)) - len(tree.path(included)) if present else None
    work_delta = tree.score(tip) - tree.score(included) if present else None
    threshold = work_multiplier * tree.blocks[included].weight
    return {
        "included": included, "tip": tip, "present": present,
        "depth": depth, "work_delta": work_delta, "threshold": threshold,
        "confirmed": bool(present and depth >= depth_required and work_delta >= threshold),
        "finalized": False, "native_probability_bound": None,
    }


def local_removal_witness(tree: Tree, included: str, confirmed_tip: str,
                          incumbent: str, challenger: str, cutoff: int) -> dict:
    """Check one local first-removal cut, assuming no earlier removal of b.

    Earlier b-preserving reorganizations are allowed: confirmed_tip need not be
    an ancestor of incumbent. A caller must establish that this is the first
    actual removal; the function verifies the necessary local state predicates.
    """
    natural(cutoff, "CUTOFF")
    observation = confirmation(tree, included, confirmed_tip)
    if not observation["confirmed"]:
        raise ValueError("NOT_CONFIRMED_BY_BOTH_GATES")
    if tree.blocks[confirmed_tip].ready_at > cutoff:
        raise ValueError("CONFIRMATION_BEFORE_MODEL_COMPLETION")
    if not tree.contains(incumbent, included):
        raise ValueError("INCUMBENT_ALREADY_REMOVED_INCLUDED")
    if tree.contains(challenger, included):
        raise ValueError("CHALLENGER_PRESERVES_INCLUDED")
    if tree.score(incumbent) < tree.score(confirmed_tip):
        raise ValueError("NONMONOTONE_LOCAL_SCORE")
    if tree.activate(incumbent, challenger) != challenger:
        raise ValueError("NOT_STRICTLY_HEAVIER")
    ancestor = tree.lca(incumbent, challenger)
    if not tree.contains(confirmed_tip, ancestor):
        raise AssertionError("LCA must precede the included block")
    rival_ids = tree.suffix(challenger, ancestor)
    inventory = sum(tree.blocks[x].weight for x in rival_ids
                    if tree.blocks[x].ready_at <= cutoff)
    new_a = sum(tree.blocks[x].weight for x in rival_ids
                if tree.blocks[x].ready_at > cutoff and tree.blocks[x].producer == "A")
    new_h = sum(tree.blocks[x].weight for x in rival_ids
                if tree.blocks[x].ready_at > cutoff and tree.blocks[x].producer == "H")
    rival_cut = tree.score(challenger) - tree.score(ancestor)
    incumbent_cut = tree.score(incumbent) - tree.score(ancestor)
    confirmation_cut = tree.score(confirmed_tip) - tree.score(ancestor)
    growth = tree.score(incumbent) - tree.score(confirmed_tip)
    b_weight = tree.blocks[included].weight
    assert rival_cut == inventory + new_a + new_h
    assert rival_cut > incumbent_cut == confirmation_cut + growth
    assert confirmation_cut >= b_weight + observation["work_delta"] >= 7 * b_weight
    # Integral weights preserve the strict native inequality by adding exactly 1.
    required_new_a = confirmation_cut + growth - inventory - new_h + 1
    assert new_a >= required_new_a
    return {
        "kind": "local_strict_first_removal_necessary_witness",
        "included": included, "confirmed_tip": confirmed_tip,
        "incumbent": incumbent, "challenger": challenger, "ancestor": ancestor,
        "cutoff": cutoff, "competing_suffix_ids": list(rival_ids),
        "competing_suffix_weight": rival_cut, "incumbent_suffix_weight": incumbent_cut,
        "confirmation_cut_weight": confirmation_cut, "native_score_growth": growth,
        "inclusion_weight": b_weight, "six_successor_minimum_cut": 7 * b_weight,
        "inventory_weight": inventory, "new_adversarial_weight": new_a,
        "new_honest_offbranch_weight": new_h,
        "required_new_adversarial_integer_weight": required_new_a,
        "probability_bound": None,
    }


def cross_node_witness(tree: Tree, included: str, earlier_tip: str, later_tip: str,
                       *, earlier_chain_available_to_later: bool) -> dict:
    """Non-strict comparison needs an explicitly established availability premise.

    'Available' includes complete validation and fork-choice eligibility, not
    merely a header arrival. The caller's Boolean is a premise, not its proof.
    """
    if not earlier_chain_available_to_later:
        raise ValueError("CROSS_NODE_AVAILABILITY_NOT_ESTABLISHED")
    if not confirmation(tree, included, earlier_tip)["confirmed"]:
        raise ValueError("NOT_CONFIRMED_BY_BOTH_GATES")
    if tree.contains(later_tip, included):
        raise ValueError("NO_PREFIX_FAILURE")
    if tree.score(later_tip) < tree.score(earlier_tip):
        raise ValueError("NOT_HEAVIEST_AGAINST_KNOWN_EARLIER_CHAIN")
    ancestor = tree.lca(earlier_tip, later_tip)
    left = tree.score(earlier_tip) - tree.score(ancestor)
    right = tree.score(later_tip) - tree.score(ancestor)
    assert right >= left >= 7 * tree.blocks[included].weight
    return {"kind": "cross_node_non_strict_known_chain_witness", "ancestor": ancestor,
            "earlier_cut": left, "later_cut": right, "strict": right > left,
            "availability_is_assumed": True, "probability_bound": None}


def first_local_removal(tree: Tree, included: str, confirmed_tip: str,
                        candidates: Iterable[str], cutoff: int) -> dict | None:
    """Apply already valid, available candidates and report the first removal."""
    if not confirmation(tree, included, confirmed_tip)["confirmed"]:
        raise ValueError("NOT_CONFIRMED_BY_BOTH_GATES")
    incumbent = confirmed_tip
    for candidate in candidates:
        selected = tree.activate(incumbent, candidate)
        if not tree.contains(selected, included):
            return local_removal_witness(tree, included, confirmed_tip,
                                         incumbent, selected, cutoff)
        incumbent = selected
    return None


def paced_honest_events(events: Iterable[tuple[int, int]], *, after: int,
                        spacing: int) -> list[tuple[int, int]]:
    """Greedy strictly spaced model events; no honest-production law is assumed."""
    natural(after, "START")
    natural(spacing, "SPACING")
    rows = list(events)
    for t, w in rows:
        natural(t, "TIME")
        natural(w, "WEIGHT", positive=True)
    if rows != sorted(rows):
        raise ValueError("EVENTS_NOT_ORDERED")
    out: list[tuple[int, int]] = []
    for t, w in rows:
        if t > after and (not out or t > out[-1][0] + spacing):
            out.append((t, w))
    return out


def burst_counterexample() -> dict:
    """All-honest branches can each gain six descendants before a finite delay.

    These are abstract model times and weights. They are deliberately not called
    measured native seconds or a probability for the installed devnet profile.
    """
    tree = Tree()
    for prefix, count, offset in (("a", 7, 0), ("b", 8, 1)):
        parent = "g"
        for i in range(1, count + 1):
            block = f"{prefix}{i}"
            tree.add(block, parent, 1, "H", 2 * i + offset)
            parent = block
    witness = local_removal_witness(tree, "a1", "a7", "a7", "b8", cutoff=14)
    assert witness["new_adversarial_weight"] == 0
    # The entire alternate chain is revealed at model time 17. Every honest
    # block was delivered within the explicitly assumed delay limit 20.
    return {"model_only": True, "delay_limit": 20, "reveal_time": 17,
            "all_producers_honest": True, "confirmation": confirmation(tree, "a1", "a7"),
            "local_removal": witness,
            "conclusion": "Attack-only tail events do not cover honest fork/propagation failures."}


def exhaustive_small_tree_check(max_non_genesis: int = 4) -> dict:
    """Enumerate topology, positive weights, labels, and branch pairs.

    Since four-node trees cannot contain six descendants, add a fixed six-block
    suffix to each candidate inclusion before the checked local removal. This
    suffix is attached only to the incumbent branch and obeys both gates. A
    rival's final adversarial extension is the exact minimal strictly heavier
    weight. The independent cut identity is also checked for all original pairs.
    """
    natural(max_non_genesis, "SIZE", positive=True)
    trees = pairs = local_witnesses = 0
    for n in range(1, max_non_genesis + 1):
        for parents in product(*(range(i) for i in range(1, n + 1))):
            for weights in product((1, 2), repeat=n):
                for producers in product(("A", "H"), repeat=n):
                    tree = Tree()
                    for i in range(1, n + 1):
                        parent = "g" if parents[i-1] == 0 else str(parents[i-1])
                        tree.add(str(i), parent, weights[i-1], producers[i-1], i)
                    trees += 1
                    ids = ["g"] + [str(i) for i in range(1, n + 1)]
                    for left in ids:
                        for right in ids:
                            ancestor = tree.lca(left, right)
                            common = set(tree.path(left)).intersection(tree.path(right))
                            independent_lca = max(common, key=lambda x: len(tree.path(x)))
                            assert ancestor == independent_lca
                            lcut = sum(tree.blocks[x].weight for x in tree.suffix(left, ancestor))
                            rcut = sum(tree.blocks[x].weight for x in tree.suffix(right, ancestor))
                            assert rcut - lcut == tree.score(right) - tree.score(left)
                            assert (tree.activate(left, right) == right if right != left else True) == (
                                tree.score(right) > tree.score(left) if right != left else True)
                            for cutoff in range(n + 1):
                                inv = anew = hnew = 0
                                for block_id in tree.suffix(right, ancestor):
                                    block = tree.blocks[block_id]
                                    if block.ready_at <= cutoff:
                                        inv += block.weight
                                    elif block.producer == "A":
                                        anew += block.weight
                                    else:
                                        hnew += block.weight
                                assert inv + anew + hnew == rcut
                            pairs += 1
                    # One genuine confirmed witness for each original included
                    # block and each original rival excluding that block.
                    for included in ids[1:]:
                        for rival in ids:
                            if tree.contains(rival, included):
                                continue
                            extended = Tree()
                            for block_id in ids[1:]:
                                block = tree.blocks[block_id]
                                extended.add(block_id, block.parent, block.weight,
                                             block.producer, block.ready_at)
                            tip = included
                            for j in range(6):
                                child = f"d{j}"
                                extended.add(child, tip, extended.blocks[included].weight,
                                             "H", n + j + 1)
                                tip = child
                            last_weight = max(1, extended.score(tip) - extended.score(rival) + 1)
                            extended.add("rival_extension", rival, last_weight, "A", n + 7)
                            local_removal_witness(extended, included, tip, tip,
                                                  "rival_extension", cutoff=n + 6)
                            local_witnesses += 1
    return {"enumerated_trees": trees, "ordered_branch_pairs": pairs,
            "confirmed_strict_removal_witnesses": local_witnesses,
            "max_original_non_genesis_blocks": max_non_genesis,
            "weights": [1, 2], "producer_labels": ["A", "H"],
            "probability_calibration": False, "native_validation_test": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = {
        "schema": "pon-native-fork-algebra-v1",
        "scope": "Independent exact finite additive-score model; conditional algebra only",
        "exhaustive": exhaustive_small_tree_check(),
        "all_honest_bounded_delay_counterexample": burst_counterexample(),
        "native_common_prefix_proved": False,
        "native_confirmation_risk_calibrated": False,
        "actual_work_relation_lower_bound_proved": False,
    }
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        with args.out.open("x", encoding="utf-8") as out:
            out.write(body)
    else:
        print(body, end="")


if __name__ == "__main__":
    main()
