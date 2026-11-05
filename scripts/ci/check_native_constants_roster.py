#!/usr/bin/env python3
"""Check the complete native-store pretty libtest roster after pipefail/tee.

This is transcript validation, not process/source authentication or a native rerun.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

PREFIX = 'account_archive_prototype::native_store::tests::'
PASSED = (
    'native_account_delta_credit_before_debit_preserves_maximum_aggregate',
    'native_complete_account_root_arithmetic_cache_matches_uncached_growth_and_removal',
    'native_delta_row_decode_matches_complete_parser_without_temporary_state',
    'native_empty_constants_match_wire_and_keep_owned_copy_isolation',
    'native_empty_constants_parallel_callers_keep_independent_values',
    'native_lift_arithmetic_cache_binds_every_input_and_keeps_fixed_capacity',
    'native_lift_cache_collisions_keep_exact_math_and_bounded_replacement',
)
IGNORED = (
    'native_empty_constants_paired_cost_observation',
    'native_lift_cache_complete_graph_cost_observation',
)
EXPECTED = {PREFIX + name: 'ok' for name in PASSED} | {
    PREFIX + name: 'ignored' for name in IGNORED}
SUMMARY = re.compile(
    r'test result: ok\. 7 passed; 0 failed; 2 ignored; 0 measured; '
    r'[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s')


def validate(lines):
    state = 'before'
    seen = set()
    for raw in lines:
        line = raw.rstrip('\r\n')
        if line.startswith('running '):
            if state != 'before' or line != 'running 9 tests':
                raise ValueError('expected exactly one nine-test invocation')
            state = 'running'
        elif line.startswith('test result:'):
            if state != 'running' or seen != set(EXPECTED) or not SUMMARY.fullmatch(line):
                raise ValueError('incomplete roster or unexpected terminal summary')
            state = 'finished'
        elif line.startswith('test '):
            match = re.fullmatch(r'test ([A-Za-z0-9_:]+) \.\.\. (ok|ignored(?:, .+)?)', line)
            if state != 'running' or match is None:
                raise ValueError('unexpected test result')
            name, outcome = match.groups()
            if name in seen or name not in EXPECTED or outcome.split(',')[0] != EXPECTED[name]:
                raise ValueError('duplicate, unknown or changed test outcome')
            seen.add(name)
    if state != 'finished':
        raise ValueError('missing complete terminal invocation')
    return {'result': 'PASS', 'passed': list(PASSED), 'ignored': list(IGNORED),
            'scope': 'complete-native-store-libtest-transcript-only'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.log.read_text(encoding='utf-8').splitlines())
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
