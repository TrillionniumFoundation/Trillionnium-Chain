from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import traceback
import unittest

out = Path(sys.argv[1])
roster_path = Path('config/pon/w1-qrom-required-tests-v2.json')
expected_digest = 'e0d1cd257e890ecb2173053da898d915cf39d3c0c5f5868379bb36f5d975c286'
required_modules = (
    'test_w1_control_tree_audit',
    'test_w1_qrom_conditional_budget',
    'test_w1_qrom_implementation_audit',
    'test_w1_fri_transcript_audit',
    'test_w1_qrom_workflow_gate',
)
def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result

def refuse_constant(value):
    raise ValueError('nonfinite JSON number: ' + value)

raw = roster_path.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected_digest:
    raise SystemExit('required-test roster differs from its reviewed workflow pin')
manifest = json.loads(raw, object_pairs_hook=strict_object, parse_constant=refuse_constant)
false_fields = (
    'post_quantum_soundness_qualified', 'complete_w1_soundness_qualified',
    'quantum_work_qualified', 'pq_signature_qualification_inferred',
    'production_qualified', 'consensus_admission',
)
if (type(manifest) is not dict
        or manifest.get('schema') != 'TRNM-W1-QROM-REQUIRED-TESTS2'
        or type(manifest.get('suites')) is not list
        or type(manifest.get('expected_tests')) is not int
        or manifest['expected_tests'] <= 0
        or any(manifest.get(key) is not False for key in false_fields)
        or 'unconditional_project_security_bits' not in manifest
        or manifest['unconditional_project_security_bits'] is not None):
    raise SystemExit('required-test roster schema or scope invalid')
if tuple(row.get('module') for row in manifest['suites']) != required_modules:
    raise SystemExit('all fixed module suites must be present in the original order')
total_required = []
for row in manifest['suites']:
    module, count, names = row['module'], row.get('expected_tests'), row.get('tests')
    if (set(row) != {'module', 'expected_tests', 'tests'}
            or type(count) is not int or count <= 0 or type(names) is not list
            or len(names) != count
            or any(type(name) is not str or re.fullmatch(
                re.escape(module) + r'\.[A-Za-z_][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+', name) is None
                for name in names)
            or len(set(names)) != count or sorted(names) != names):
        raise SystemExit('missing, duplicate, unsorted or invalid required names: ' + module)
    total_required.extend(names)
if (len(total_required) != manifest['expected_tests']
        or len(set(total_required)) != len(total_required)):
    raise SystemExit('required-test total or global uniqueness differs')
with (out / 'required-tests.json').open('xb') as stream:
    stream.write(raw)

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

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)

records = []
for row in manifest['suites']:
    module, expected = row['module'], row['tests']
    record = {'module': module, 'expected_ids': expected, 'passed': False}
    try:
        loader = unittest.TestLoader()
        suite = loader.discover('scripts/ci', pattern=module + '.py')
        registered = [test.id() for test in flatten(suite)]
        record['registered_ids'] = registered
        record['loader_errors'] = list(loader.errors)
        if loader.errors or Counter(registered) != Counter(expected):
            raise ValueError('actual complete module registry differs from the required named roster')
        runner = unittest.TextTestRunner(
            stream=sys.stderr, verbosity=2, descriptions=False, resultclass=ObservedResult)
        result = runner.run(suite)
        record.update({
            'tests_run': result.testsRun,
            'started_ids': result.started_ids,
            'success_ids': result.success_ids,
            'skipped': [(test.id(), reason) for test, reason in result.skipped],
            'failures': [(test.id(), reason) for test, reason in result.failures],
            'errors': [(test.id(), reason) for test, reason in result.errors],
            'expected_failures': [(test.id(), reason) for test, reason in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        })
        record['passed'] = (
            result.testsRun == row['expected_tests']
            and Counter(result.started_ids) == Counter(expected)
            and Counter(result.success_ids) == Counter(expected)
            and result.wasSuccessful()
            and not result.skipped and not result.expectedFailures
            and not result.unexpectedSuccesses and not result.failures and not result.errors)
    except (Exception, SystemExit) as error:
        record['exception'] = str(error)
        traceback.print_exc()
    records.append(record)
    with (out / (module + '.json')).open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
report = {
    'schema': 'TRNM-W1-QROM-NAMED-TEST-OBSERVATION1',
    'roster_sha256': expected_digest,
    'required_tests': manifest['expected_tests'],
    'suites': records,
    'all_named_controls_passed': len(records) == len(required_modules)
        and all(row['passed'] is True for row in records),
    'post_quantum_soundness_qualified': False,
    'unconditional_project_security_bits': None,
}
with (out / 'named-tests.json').open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
    stream.write('\n')
if report['all_named_controls_passed'] is not True:
    raise SystemExit('every fixed named test must execute exactly once with success and no skips')
print('All fixed named controls executed exactly once; security qualification remains false.')
