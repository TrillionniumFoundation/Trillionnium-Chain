#!/usr/bin/env python3
"""Require one named libtest execution, not merely a successful Cargo exit.

Used after the existing pipefail/tee command. This checks the pinned pretty-format
libtest transcript; it does not authenticate test stdout or replace process status,
source identity, the test assertions, or an independent native-state oracle.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterable
import json
from pathlib import Path
import re
import sys

RUNNING = re.compile(r'running ([0-9]+) tests?')
TEST = re.compile(r'test ([A-Za-z0-9_:]+) \.\.\.(?: .*)?')
SUMMARY = re.compile(
    r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
    r'[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s'
)


def validate(lines: Iterable[str], expected_test: str) -> dict:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*', expected_test):
        raise ValueError('required-native-test: invalid exact test name')
    # Nocapture output can share the test-announcement line, and a println-free
    # progress message can share the final "ok" line. The harness summary is
    # authoritative for outcome; requiring a literal standalone "ok" is wrong.
    state = 'before'
    for raw_line in lines:
        line = raw_line.rstrip('\r\n')
        if line.startswith('running '):
            match = RUNNING.fullmatch(line)
            if state != 'before' or match is None or match[1] != '1':
                raise ValueError('required-native-test: expected exactly one test invocation')
            state = 'running'
        elif line.startswith('test result:'):
            if state != 'named' or SUMMARY.fullmatch(line) is None:
                raise ValueError('required-native-test: expected one passed, zero failed/ignored/measured')
            state = 'finished'
        else:
            match = TEST.fullmatch(line)
            if match is not None:
                if state != 'running' or match[1] != expected_test:
                    raise ValueError('required-native-test: missing, duplicate or wrong test identity')
                state = 'named'
    if state != 'finished':
        raise ValueError('required-native-test: incomplete execution transcript')
    return {'result': 'PASS', 'test': expected_test, 'executed_tests': 1,
            'scope': 'named-libtest-execution-only'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--test', required=True)
    args = parser.parse_args()
    try:
        with args.log.open(encoding='utf-8') as stream:
            result = validate(stream, args.test)
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
