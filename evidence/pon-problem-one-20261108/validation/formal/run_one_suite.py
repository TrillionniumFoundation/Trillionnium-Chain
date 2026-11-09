"""Run one existing unittest discovery pattern and retain exact result metadata.

No source edits, test replacements, dependency installation, or skipped-case
promotion. The standard TextTestRunner emits complete raw test diagnostics.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import unittest


root = Path(sys.argv[1]).resolve()
pattern = sys.argv[2]
destination = Path(sys.argv[3])
formal = root / 'formal/pon-nakamoto-v1'
assert pattern.startswith('test_') and pattern.endswith('.py') and '/' not in pattern
assert (formal / pattern).is_file()


def module_snapshot():
    rows = {}
    for name, module in tuple(sys.modules.items()):
        source = getattr(module, '__file__', None)
        if source is None:
            continue
        path = Path(source).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            continue
        raw = path.read_bytes()
        rows[name] = dict(path=str(path.relative_to(root)), bytes=len(raw),
                          sha256=hashlib.sha256(raw).hexdigest())
    return dict(sorted(rows.items()))


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.successful_test_ids = []

    def addSuccess(self, test):
        self.successful_test_ids.append(test.id())
        super().addSuccess(test)


loader = unittest.TestLoader()
suite = loader.discover(str(formal), pattern=pattern)
before = module_snapshot()
start = datetime.now(timezone.utc).isoformat()
timer = time.monotonic_ns()
result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
after = module_snapshot()
unchanged = all(after.get(name) == value for name, value in before.items())
observation = dict(
    schema='pon-existing-formal-suite-observation-v1', pattern=pattern,
    effective_unittest_args=['discover', '-s', str(formal), '-p', pattern, '-v'],
    started_utc=start, finished_utc=datetime.now(timezone.utc).isoformat(),
    duration_ns=time.monotonic_ns() - timer, tests_run=result.testsRun,
    passed=len(result.successful_test_ids), failures=len(result.failures),
    errors=len(result.errors), skipped=len(result.skipped),
    expected_failures=len(result.expectedFailures),
    unexpected_successes=len(result.unexpectedSuccesses),
    successful_test_ids=result.successful_test_ids,
    failed_test_ids=[case.id() for case, _ in result.failures],
    errored_test_ids=[case.id() for case, _ in result.errors],
    skipped_tests=[dict(id=case.id(), reason=reason) for case, reason in result.skipped],
    expected_failure_ids=[case.id() for case, _ in result.expectedFailures],
    unexpected_success_ids=[case.id() for case in result.unexpectedSuccesses],
    discovery_errors=loader.errors, unittest_was_successful=result.wasSuccessful(),
    empty_suite=result.testsRun == 0, imported_repository_modules_before=before,
    imported_repository_modules_after=after, prior_module_bytes_unchanged=unchanged)
with destination.open('x', encoding='utf-8') as handle:
    json.dump(observation, handle, sort_keys=True, indent=2)
    handle.write('\n')
raise SystemExit(0 if result.wasSuccessful() and result.testsRun > 0 and unchanged else 1)
