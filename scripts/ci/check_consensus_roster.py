#!/usr/bin/env python3
"""Require the complete frozen consensus pretty-libtest roster.

Run after the original Cargo command with pipefail/tee. This checks the
transcript, not process provenance, source identity, or consensus qualification.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterable
import json
from pathlib import Path
import re
import sys

PREFIX = 'consensus::tests::'
PASSED = (
    'aligned_division_matches_original_for_wide_arbitrary_operands',
    'aligned_division_preserves_all_512_shift_and_limb_boundaries',
    'aligned_required_work_and_retarget_match_original_arithmetic',
    'branch_target_window_uses_checked_child_height_and_exact_parent_period',
    'exact_extreme_work_and_overflow',
    'full_width_division_matches_small_and_high_operands',
    'native_arithmetic_matches_python_integer_vectors',
    'native_arithmetic_matches_versioned_python_domain_vectors',
    'parent_first_median_keeps_short_even_windows_and_error_precedence',
    'retarget_checks_both_time_products_before_adjusting_work',
    'time_deferred_is_not_consensus_invalidity',
)
EXPECTED = frozenset(PREFIX + name for name in PASSED)
SUMMARY = re.compile(
    r'test result: ok\. 11 passed; 0 failed; 0 ignored; 0 measured; '
    r'[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s'
)


def validate(lines: Iterable[str]) -> dict:
    state = 'before'
    seen = set()
    for raw in lines:
        line = raw.rstrip('\r\n')
        if line.startswith('running '):
            if state != 'before' or line != 'running 11 tests':
                raise ValueError('consensus-roster: expected one eleven-test invocation')
            state = 'running'
        elif line.startswith('test result:'):
            if state != 'running' or seen != EXPECTED or SUMMARY.fullmatch(line) is None:
                raise ValueError('consensus-roster: incomplete names or unexpected summary')
            state = 'finished'
        elif line.startswith('test '):
            match = re.fullmatch(r'test ([A-Za-z0-9_:]+) \.\.\. ok', line)
            if state != 'running' or match is None:
                raise ValueError('consensus-roster: unexpected test outcome')
            name = match[1]
            if name not in EXPECTED or name in seen:
                raise ValueError('consensus-roster: unknown or duplicate test identity')
            seen.add(name)
    if state != 'finished':
        raise ValueError('consensus-roster: missing complete terminal invocation')
    return {'result': 'PASS', 'passed': list(PASSED), 'ignored': [],
            'scope': 'complete-consensus-libtest-transcript-only'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        with args.log.open(encoding='utf-8') as stream:
            result = validate(stream)
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
