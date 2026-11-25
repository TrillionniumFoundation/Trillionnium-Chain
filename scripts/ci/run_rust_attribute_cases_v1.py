#!/usr/bin/env python3
"""Record exact selected owner controls; baseline failures remain failures."""
from __future__ import annotations

import argparse
from collections import Counter
import importlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import time
import traceback
import unittest

NEW = tuple('test_applicability.RustAttributeScanTests.' + name for name in (
    'test_normal_attributes_and_unicode_whitespace_stay_bound',
    'test_attribute_line_and_exact_callable_boundaries_stay_required',
    'test_overlapping_literal_symbols_do_not_bind_another_name',
    'test_source_beyond_parse_cache_limit_keeps_its_final_test',
    'test_ambiguous_attributes_refuse_unattributed_helper_within_deadline',
    'test_ambiguous_attributes_do_not_block_a_later_real_test',
))
RETAINED = tuple('test_applicability.ParserCacheMutationTests.' + name for name in (
    'test_warm_rust_parser_reads_same_size_same_mtime_changes',
    'test_warm_python_parser_reads_same_size_same_mtime_changes',
    'test_warm_rust_parser_refuses_comments_strings_and_unattributed_helpers',
    'test_python_symbol_results_cannot_pollute_later_calls',
    'test_warm_parser_cache_keeps_missing_and_escaped_path_checks',
))
TIMEOUT_MESSAGE = 'current attributed-test binding exceeded the 3-second fixture deadline'


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.success_ids = []
        self.failure_details = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)

    def addFailure(self, test, error):
        failure = error[1]
        context = failure.__context__
        timed_out = isinstance(context, subprocess.TimeoutExpired)
        self.failure_details.append({
            'id': test.id(), 'exception_type': type(failure).__name__,
            'message': str(failure), 'timeout_context': timed_out,
            'timeout_seconds': context.timeout if timed_out else None,
            'child_argv': context.cmd if timed_out else None,
            'timeout_stdout_hex': (context.output.hex() if timed_out
                                   and isinstance(context.output, bytes) else None),
            'timeout_stderr_empty': timed_out and context.stderr in (None, b''),
            'timeout_stderr_hex': (context.stderr.hex() if timed_out
                                   and isinstance(context.stderr, bytes) else None),
        })
        super().addFailure(test, error)


def execute(root: Path, output: Path, kind: str) -> int:
    started = time.monotonic_ns()
    expected = list(NEW[-2:] if kind == 'baseline' else NEW + RETAINED)
    report = {'schema': 'trnm-rust-attribute-named-controls-v1', 'kind': kind,
              'status': 'FAIL', 'complete': False, 'expected_ids': expected,
              'started_ids': [], 'success_ids': [], 'failure_details': [],
              'tests_run': 0, 'loader_errors': [], 'registered_ids': []}
    if output.exists():
        raise ValueError('control report path is already occupied')
    try:
        source = root.resolve(strict=True) / 'scripts/ci'
        sys.path.insert(0, str(source))
        module = importlib.import_module('test_applicability')
        if Path(module.__file__).resolve() != source / 'test_applicability.py':
            raise ValueError('selected control module came from another source')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(expected)
        registered = [test.id() for test in flatten(suite)]
        report.update(registered_ids=registered, loader_errors=list(loader.errors))
        if loader.errors or Counter(registered) != Counter(expected):
            raise ValueError('registered controls differ from the exact roster')
        result = unittest.TextTestRunner(
            stream=sys.stderr, verbosity=2, descriptions=False,
            resultclass=ObservedResult).run(suite)
        report.update(
            complete=True, tests_run=result.testsRun,
            started_ids=result.started_ids, success_ids=result.success_ids,
            failure_details=result.failure_details,
            failures=[(test.id(), text) for test, text in result.failures],
            errors=[(test.id(), text) for test, text in result.errors],
            skipped=[(test.id(), why) for test, why in result.skipped],
            expected_failures=[(test.id(), text) for test, text in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
        )
        passed = (result.wasSuccessful() and not result.skipped
                  and not result.expectedFailures and not result.unexpectedSuccesses
                  and Counter(result.started_ids) == Counter(expected)
                  and Counter(result.success_ids) == Counter(expected))
        report['status'] = 'PASS' if passed else 'FAIL'
        return 0 if passed else 1
    except (Exception, SystemExit) as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error)}
        traceback.print_exc(file=sys.stderr)
        return 2
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - started
        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        report['process_lifetime_cpu'] = {
            'self_user_seconds': own.ru_utime, 'self_system_seconds': own.ru_stime,
            'reaped_children_user_seconds': children.ru_utime,
            'reaped_children_system_seconds': children.ru_stime,
        }
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kind', choices=('baseline', 'fixed'), required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.root, args.output, args.kind))
