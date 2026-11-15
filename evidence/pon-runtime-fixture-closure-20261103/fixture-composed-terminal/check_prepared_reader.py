#!/usr/bin/env python3
"""Parser-only checks. Never open this candidate's growing native.log/result."""
from pathlib import Path
import datetime
import hashlib
import json

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / 'prepare_terminal.py'
ns = {'__name__': 'terminal_reader_checks', '__file__': str(SCRIPT)}
exec(compile(SCRIPT.read_bytes(), str(SCRIPT), 'exec'), ns)
parse = ns['parse_native_log']
cases = []


def check(name, raw, registered, ignored, exit_code, accepted):
    error = None
    try:
        result = parse(raw, registered, ignored, exit_code)
    except ValueError as caught:
        error = str(caught)
    actual = error is None
    if actual != accepted:
        raise AssertionError((name, accepted, actual, error))
    cases.append({'name': name, 'expected_acceptance': accepted,
                  'actual_acceptance': actual, 'refusal': error})


base = b'''running 3 tests
test mod::ignored ... ignored

successes:
---- nested child output ----
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

successes:
    mod::pass

failures:
---- failure stdout ----
actual failure message

failures:
    mod::fail

test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s

'''
names = ['mod::pass', 'mod::fail', 'mod::ignored']
ignore = ['mod::ignored']
check('final aggregate over nested child success', base, names, ignore, 101, True)
check('missing terminal', base[:base.rfind(b'test result:')], names, ignore, 101, False)
check('trailing nonterminal output', base + b'not a terminal\n', names, ignore, 101, False)
check('duplicate passed selector', base.replace(b'    mod::pass\n', b'    mod::pass\n    mod::pass\n'), names, ignore, 101, False)
check('overlapping result groups', base.replace(b'    mod::fail\n', b'    mod::pass\n'), names, ignore, 101, False)
check('missing original ignored record', base.replace(b'test mod::ignored ... ignored\n', b''), names, ignore, 101, False)
check('changed ignored identity', base.replace(b'test mod::ignored ... ignored', b'test mod::other ... ignored'), names, ignore, 101, False)
check('contradicting native exit', base, names, ignore, 0, False)
check('missing registered selector', base, names + ['mod::missing'], ignore, 101, False)
check('false summary count', base.replace(b'FAILED. 1 passed;', b'FAILED. 2 passed;'), names, ignore, 101, False)
check('truncated successes list', base.replace(b'    mod::pass\n', b''), names, ignore, 101, False)
all_pass = b'''test mod::ignored ... ignored

successes:
    mod::pass

test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s
'''
check('all-pass terminal remains supported', all_pass, ['mod::pass', 'mod::ignored'], ignore, 0, True)

# A frozen previous source verifies the actual libtest output grammar only.
# Its native counts are never input to this fixture candidate's terminal package.
old = Path('/workspace/scratch/b5a148b09b11/next-validation/full-node-b280-j1')
old_plan = json.loads((old / 'plan.json').read_bytes())
old_log = (old / 'native.log').read_bytes()
check('frozen b280 real-format parser control only', old_log,
      old_plan['registered'], old_plan['original_ignored'], 101, True)
result = {
    'schema': 'trnm-fixture-terminal-reader-preparation-v1',
    'prepared_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'reader_sha256': hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
    'passed_checks': len(cases), 'checks': cases,
    'old_format_control_log_sha256': hashlib.sha256(old_log).hexdigest(),
    'old_native_results_inherited': False,
    'candidate_full_native_log_or_result_opened': False,
    'native_or_cargo_executions': 0,
    'status': 'PREPARED_WAITING_FOR_EXPLICIT_ROOT_TERMINAL',
}
output = ROOT / 'reader-preparation-checks.json'
with output.open('x') as file:
    file.write(json.dumps(result, indent=2) + '\n')
print(json.dumps({'checks': len(cases), 'passed': len(cases), 'status': result['status']}))
