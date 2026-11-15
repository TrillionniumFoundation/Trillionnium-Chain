#!/usr/bin/env python3
"""Strict eight-sample V2 readback; V1 records retain their original contract.

Only the frozen record version, eight fresh sample domains and bounded evidence
capacity differ. No mutable module-global switching or acceptance promotion.
"""
import sys

sys.dont_write_bytecode = True
import pon_w1_legal_strategy_reader_v1 as core

PROFILE = core.V2
SCHEMA, SELECTOR, SAMPLES = PROFILE.schema, PROFILE.selector, PROFILE.samples
MAX_LINE, MAX_BYTES = core.MAX_LINE, PROFILE.max_bytes
common = core.common
CLASSES, TARGETS, HORIZONS = core.CLASSES, core.TARGETS, core.HORIZONS
ATTEMPT_BUDGET = core.ATTEMPT_BUDGET
STRATEGIES, PATHS, CASES = core.STRATEGIES, core.PATHS, core.CASES
DISPATCH_ARMS, FALSE_FLAGS = core.DISPATCH_ARMS, core.FALSE_FLAGS
PRODUCER_SCOPE, VERIFY_SCOPE, MUTATION_SCOPE = core.PRODUCER_SCOPE, core.VERIFY_SCOPE, core.MUTATION_SCOPE
dispatch_probes, product_last = core.dispatch_probes, core.product_last


def challenge(task, target, sample, search, nonce):
    return core.challenge(task, target, sample, search, nonce, profile=PROFILE)


def analyze_shard(path):
    return core.analyze_shard(path, profile=PROFILE)


def analyze(paths):
    return core.analyze(paths, profile=PROFILE)


if __name__ == "__main__":
    sys.exit(core.main(profile=PROFILE))
