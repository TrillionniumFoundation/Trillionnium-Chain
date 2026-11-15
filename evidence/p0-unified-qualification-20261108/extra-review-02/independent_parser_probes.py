#!/usr/bin/env python3
"""Independent pure parser probes; no Cargo/native workload is executed."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

runner = load('reviewed_extra_runner', ROOT / 'run-extra-native.py')
base = load('reviewed_base_helper', ROOT / 'authority-final-validation-runner.py')
fixtures = load('reviewed_extra_tests', ROOT / 'test_run_extra_native.py')
results = []

def record(name, raw_input, call):
    try:
        value = call()
    except Exception as exc:
        results.append({'probe': name, 'accepted': False, 'error': type(exc).__name__ + ': ' + str(exc), 'input': raw_input})
    else:
        results.append({'probe': name, 'accepted': True, 'result': value, 'input': raw_input})

for name, output in [
    ('python_single_count_failed_then_ok', 'Ran 2 tests in 0.01s\n\nFAILED (failures=1)\nOK\n'),
    ('python_single_count_ok_then_failed', 'Ran 2 tests in 0.01s\n\nOK\nFAILED (failures=1)\n'),
    ('python_single_ok_but_nonzero_failure_counter', 'Ran 2 tests in 0.01s\n\nOK (failures=1)\n'),
]:
    observed = runner.test_observations('unittest', '', output)
    record(name, {'stderr': output, 'observed': observed}, lambda observed=observed, output=output:
           runner.validate_readback(base, {'kind':'unittest'}, '', output, Path('/fixture/repo'), observed, None))

for name, suffix in [
    ('workspace_trailing_unattributed_failed_test', '\nrunning 1 test\ntest late_unreported_failure ... FAILED\n'),
    ('workspace_trailing_unattributed_passed_test', '\nrunning 1 test\ntest late_unreported_pass ... ok\n'),
]:
    stdout, executed, metadata = fixtures.fixture()
    observed = runner.workspace_observations(stdout + suffix, executed, metadata)
    record(name, {'suffix': suffix, 'global_failed_name_count': sum(x['outcome']=='FAILED' for x in observed['tests']),
                  'summary_failed_count': observed['totals']['failed'], 'execution_order_unambiguous': observed['execution_order_unambiguous']},
           lambda observed=observed: runner.validate_readback(base, {'kind':'rust-workspace'}, '', '', Path('/fixture/repo'), observed, None))

for name, changes in [
    ('workspace_extra_dispatch_without_summary', 'extra_dispatch'),
    ('workspace_extra_failure_summary', 'extra_summary'),
]:
    stdout, executed, metadata = fixtures.fixture()
    if changes == 'extra_dispatch':
        executed = [*executed, {'path':'/fixture/target/debug/deps/extra', 'bytes': 1, 'sha256':'f'*64}]
    else:
        stdout += '\nrunning 1 test\ntest extra ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
    observed = runner.workspace_observations(stdout, executed, metadata)
    record(name, {'mutation': changes}, lambda observed=observed:
           runner.validate_readback(base, {'kind':'rust-workspace'}, '', '', Path('/fixture/repo'), observed, None))

document = {'schema':'extra-native-independent-parser-probes-v1', 'native_campaign_executed':False,
            'scope':'synthetic parser inputs only', 'results':results}
(ROOT/'independent-parser-probes.json').write_text(json.dumps(document,indent=2)+'\n')
print(json.dumps(document,indent=2))
