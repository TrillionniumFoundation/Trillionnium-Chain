#!/usr/bin/env python3
"""Replay static workflow checks only; no native tests or timing measurements.

Parameterized from workflow_wiring_static.original.py. Source-pin literal hashes
may differ from the comparison base only when current git hash-object verifies
them; the paths and all other guarded command bytes must remain identical.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[4])
parser.add_argument('--comparison-base', default='73ab6e9a83bcc836e261d93f9bb23ceafe556758')
parser.add_argument('--expected-pre-write-count', type=int, default=12)
parser.add_argument('--output-dir', type=Path, required=True)
args = parser.parse_args()
ROOT = args.repository.resolve()
OUT = args.output_dir.resolve()
BASE = args.comparison_base
PRE_WRITE = args.expected_pre_write_count
assert PRE_WRITE >= 12, 'the retained twelve pre-write controls must remain'
POST_WRITE = 23 + PRE_WRITE
AUTHENTICATED = 91 + PRE_WRITE
SELECTED = 61 + PRE_WRITE
OUT.mkdir(parents=True, exist_ok=True)
FILES = [
    '.github/workflows/pon-original-workspace-large-state-cpu.yml',
    '.github/workflows/pon-recent-batch-acceptance.yml',
    '.github/workflows/pon-pq-system-continuation.yml',
]


class UniqueLoader(yaml.BaseLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate YAML mapping key')
        return super().construct_mapping(node, deep=deep)


def load(text):
    return yaml.load(text, Loader=UniqueLoader)


def steps(value):
    assert len(value['jobs']) == 1
    return next(iter(value['jobs'].values()))['steps']


def run(value, name):
    matches = [step['run'] for step in steps(value) if step.get('name') == name]
    assert len(matches) == 1, name
    return matches[0]


def python_blocks(text):
    lines = text.splitlines(keepends=True)
    blocks = {}
    for index, line in enumerate(lines):
        match = re.search(r"<<'(?P<marker>PY[A-Z_0-9]*)'", line)
        if match:
            marker = match['marker']
            end = next(i for i in range(index + 1, len(lines)) if lines[i].strip() == marker)
            blocks[marker] = ''.join(lines[index + 1:end])
    return blocks


def test_names(path, prefix):
    text = (ROOT / path).read_text()
    names = re.findall(r'#\[test\]\s*(?:#\[[^\n]*\]\s*)*fn ([A-Za-z0-9_]+)\(', text)
    assert names and len(names) == len(set(names)), path
    return {prefix + name for name in names}


old = {name: load(subprocess.check_output(['git', 'show', f'{BASE}:{name}'], cwd=ROOT, text=True)) for name in FILES}
raw = {name: (ROOT / name).read_bytes() for name in FILES}
new = {name: load(raw[name].decode()) for name in FILES}
shell_count = 0
python_count = 0
for name, value in new.items():
    for index, step in enumerate(steps(value)):
        if 'run' not in step:
            continue
        script = re.sub(r'\$\{\{.*?\}\}', 'GITHUB_EXPRESSION', step['run'])
        result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
        assert result.returncode == 0, (name, index, result.stderr)
        shell_count += 1
        for marker, block in python_blocks(step['run']).items():
            compile(block, f'{name}:{index}:{marker}', 'exec')
            python_count += 1

allowed_runs = {
    FILES[0]: {'Execute selected arithmetic canonical and reorg semantic controls'},
    FILES[1]: {'Retain authenticated record, ancestry and cold recovery coverage'},
    FILES[2]: {'Observe complete component costs with unchanged native budgets'},
}
added_step = 'Require actual transaction scopes and canonical prefix continuation controls'
verified_source_pins = []
for name in FILES:
    before, after = old[name], new[name]
    old_job = next(iter(before['jobs'].values()))
    new_job = next(iter(after['jobs'].values()))
    assert {k: v for k, v in old_job.items() if k != 'steps'} == {k: v for k, v in new_job.items() if k != 'steps'}, name
    new_steps = [step for step in steps(after) if step.get('name') != added_step]
    assert len(steps(before)) == len(new_steps), name
    for previous, current in zip(steps(before), new_steps):
        if previous.get('name') in allowed_runs[name]:
            assert {k: v for k, v in previous.items() if k != 'run'} == {k: v for k, v in current.items() if k != 'run'}
        elif previous.get('name') == 'Verify exact source, ordered actual main merge and full repository boundary':
            # Final source pins may be refreshed after the original static run.
            # Preserve every command and accept only same-line literal hash changes.
            pattern = r'(?m)^\s*test "\$\(git hash-object ([^)\n]+)\)" = ([0-9a-f]{40})$'
            old_pins = re.findall(pattern, previous['run'])
            current_pins = re.findall(pattern, current['run'])
            old_paths = [path for path, _ in old_pins]
            current_paths = [path for path, _ in current_pins]
            assert current_paths and current_paths == old_paths
            assert len(current_paths) == len(set(current_paths))
            for (path, old_pin), (_, new_pin) in zip(old_pins, current_pins):
                actual = subprocess.check_output(
                    ['git', 'hash-object', '--', path], cwd=ROOT, text=True).strip()
                assert actual == new_pin, (name, path, new_pin, actual)
                verified_source_pins.append({'workflow': name, 'path': path,
                                             'old_literal': old_pin,
                                             'current_literal': new_pin,
                                             'actual_git_hash_object': actual})
            def normalize_pins(step):
                normalized = dict(step)
                normalized['run'] = re.sub(
                    r'(?m)^(\s*test "\$\(git hash-object [^)\n]+\)" = )[0-9a-f]{40}$',
                    r'\1SOURCE_PIN', step['run'])
                return normalized
            assert normalize_pins(previous) == normalize_pins(current), (name, previous.get('name'))
        else:
            assert previous == current, (name, previous.get('name'))
    for key in before:
        if key not in ('jobs', 'on'):
            assert before[key] == after[key], (name, key)
    if name != FILES[1]:
        assert before['on'] == after['on'], name
    else:
        previous = before['on']['pull_request']['paths']
        current = after['on']['pull_request']['paths']
        assert [path for path in current if path in previous] == previous
        assert set(current) - set(previous) == {
            'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs',
            'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/**',
        }


def registry_groups(value):
    code = python_blocks(run(value, 'Execute selected arithmetic canonical and reorg semantic controls'))['PYREGISTRY']
    groups = {}
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('prefix', 'exact'):
            args = tuple(ast.literal_eval(arg) for arg in node.args)
            assert args[1] not in groups
            groups[args[1]] = (node.func.id, args)
    return groups


old_groups = registry_groups(old[FILES[0]])
new_groups = registry_groups(new[FILES[0]])
for key, expected in old_groups.items():
    if key == 'postwrite-readback':
        kind, args = expected
        expected = (kind, args[:-1] + (POST_WRITE,))
    assert new_groups[key] == expected, key
assert set(new_groups) - set(old_groups) == {'canonical-comparison', 'compared-prefix-continuation', 'direct-append-readback'}
assert sum(args[3] if kind == 'prefix' else len(args[2]) for kind, args in new_groups.values()) == SELECTED
canonical = test_names('trillionnium/crates/trnm-mvcc-fee/src/pon_executor/canonical_comparison_tests.rs', 'pon_executor::canonical_comparison_tests::')
prefix = test_names('trillionnium/crates/trnm-mvcc-fee/src/pon_commitment/unchanged_snapshot_tests.rs', 'pon_commitment::unchanged_snapshot_tests::')
prefix = {name for name in prefix if name.split('::')[-1].startswith('compared_')}
append = test_names('trillionnium/crates/trnm-pon-node/src/store/append_readback_tests.rs', 'store::append_readback_tests::')
for group, names, count in [('canonical-comparison', canonical, 3), ('compared-prefix-continuation', prefix, 2), ('direct-append-readback', append, 2)]:
    assert len(names) == count
    assert set(new_groups[group][1][2]) == names

native_prefix = 'store::native_authenticated::post_write_readback::tests::frontier::pre_write::'
pre_write = test_names('trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/pre_write_tests.rs', native_prefix)
assert len(pre_write) == PRE_WRITE
recent_script = run(new[FILES[1]], 'Retain authenticated record, ancestry and cold recovery coverage')
reader = python_blocks(recent_script)['PYLOG']
reader_ast = ast.parse(reader)
expected_pre_write = next(node.value.generators[0].iter for node in reader_ast.body if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'pre_write')
assert {native_prefix + name for name in ast.literal_eval(expected_pre_write)} == pre_write
current_accounts = next(ast.literal_eval(node.value) for node in reader_ast.body if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'current_accounts')
assert len(current_accounts) == 5

pq_new = run(new[FILES[2]], added_step)
scope = test_names('trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope_tests.rs', 'transaction_scope::tests::')
scope |= test_names('trillionnium/crates/trnm-sqlite-io-boundary/src/known_write_scope_tests.rs', 'transaction_scope::known_write_tests::')
observed_scope = re.findall(r'transaction_scope::(?:tests|known_write_tests)::[A-Za-z0-9_]+', pq_new)
assert len(scope) == len(observed_scope) == 22 and set(observed_scope) == scope
observed_m06 = re.findall(r'(?:pon_executor|pon_commitment)::[A-Za-z0-9_:]+', pq_new)
assert len(observed_m06) == 5 and set(observed_m06) == canonical | prefix
assert len(re.findall(r'check_required_native_test.py', pq_new)) == 2
assert len(re.findall(r'--exact --show-output --test-threads=1', pq_new)) == 2
assert all(re.fullmatch(r'[A-Za-z0-9_-]{1,160}', 'scope-' + name.split('::')[-1]) for name in scope)
assert all(re.fullmatch(r'[A-Za-z0-9_-]{1,160}', 'm06-' + name.split('::')[-1]) for name in canonical | prefix)

cost = native_prefix + 'native_publish_continuation_paired_real_sql_cost_observation'
original = run(new[FILES[0]], 'Execute selected arithmetic canonical and reorg semantic controls')
assert original.count('--ignored') == 1
assert f'if [ "$selector" = {cost} ]; then' in original
assert 'TRNM_NATIVE_PUBLISH_CONTINUATION_COST_OUTPUT="$controls/$name.cost.jsonl"' in original
old_command = '/usr/bin/time -v -o "$controls/$name.resources.txt" "$binary" "$selector" --exact --nocapture --test-threads=1 < /dev/null 2>&1 | tee "$log"'
assert old_command in original
assert 'export TRNM_NATIVE_PUBLISH_CONTINUATION_COST_OUTPUT="$OUT/native-publish-continuation-cost.jsonl"' in recent_script
pq_cost = run(new[FILES[2]], 'Observe complete component costs with unchanged native budgets')
assert cost in pq_cost
assert 'export TRNM_NATIVE_PUBLISH_CONTINUATION_COST_OUTPUT="$PQ_OUT/native-publish-continuation-cost.jsonl"' in pq_cost

# Test the embedded acceptance reader, using visibly synthetic lines only.
# These controls assert rejection behavior; they are never native receipts.
synthetic_non_post = sorted(current_accounts) + [f'store::native_authenticated::synthetic_existing_{i}' for i in range(63)]
synthetic_old_post = [f'store::native_authenticated::post_write_readback::tests::synthetic_existing_{i}' for i in range(23)]
synthetic_names = synthetic_non_post + synthetic_old_post + sorted(pre_write)
summary = f'test result: ok. {AUTHENTICATED} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
reader_cases = []
with tempfile.TemporaryDirectory(prefix='workflow-static-reader-') as temp:
    temp = Path(temp)
    program = temp / 'reader.py'
    program.write_text(reader)
    def check_reader(label, names, summaries, should_pass):
        log = temp / f'{label}.log'
        log.write_text('\n'.join([f'test {name} ... ok' for name in names] + summaries) + '\n')
        result = subprocess.run([sys.executable, str(program), str(log)], text=True, capture_output=True)
        assert (result.returncode == 0) == should_pass, (label, result.stdout, result.stderr)
        reader_cases.append({'case': label, 'expected_accept': should_pass, 'exit_code': result.returncode})
    check_reader('synthetic-complete-shape', synthetic_names, [summary], True)
    for index, name in enumerate(sorted(pre_write)):
        replaced = [native_prefix + f'synthetic_wrong_{index}' if value == name else value for value in synthetic_names]
        check_reader(f'replaced-required-prewrite-{index}', replaced, [summary], False)
    check_reader('duplicate-name', synthetic_names[:-1] + [synthetic_names[0]], [summary], False)
    check_reader('missing-old-nonpost', synthetic_names[1:], [summary], False)
    check_reader('duplicate-summary', synthetic_names, [summary, summary], False)
    check_reader('ignored-cost', synthetic_names, [summary.replace(f'{AUTHENTICATED} passed; 0 failed; 0 ignored;', f'{AUTHENTICATED - 1} passed; 0 failed; 1 ignored;')], False)
    wrong_current = [name.replace('current_accounts_tests::', 'synthetic_current::') if name in current_accounts else name for name in synthetic_names]
    check_reader('replaced-current-accounts', wrong_current, [summary], False)

for name, before in raw.items():
    assert (ROOT / name).read_bytes() == before, name + ' changed during static checks'
diff_check = subprocess.run(['git', 'diff', '--check', '--', *FILES], cwd=ROOT, text=True, capture_output=True)
assert diff_check.returncode == 0, diff_check.stderr + diff_check.stdout
report = {
    'result': 'PASS',
    'comparison_base': BASE,
    'expected_pre_write_count': PRE_WRITE,
    'replay_script': 'parameterized derivative; original script and historical outputs are separately retained',
    'scope': 'workflow YAML, shell, embedded Python and source-name static checks only; synthetic reader controls are not native execution',
    'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'workflow_sha256': {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()},
    'yaml_files': len(FILES),
    'bash_scripts_checked': shell_count,
    'embedded_python_blocks_compiled': python_count,
    'old_steps_parameters_and_deadlines_preserved': True,
    'current_source_pins_match_actual_git_blobs': verified_source_pins,
    'old_pq_49_roster_preserved': True,
    'original_workspace_expected_selected_count': SELECTED,
    'expected_registry_counts_awaiting_actual_native_list': {'pre_write': PRE_WRITE, 'post_write': POST_WRITE, 'native_authenticated': AUTHENTICATED},
    'new_scope_controls': len(scope),
    'new_m06_controls': len(canonical | prefix),
    'new_direct_append_controls': len(append),
    'synthetic_reader_cases': reader_cases,
}
path = OUT / 'workflow-wiring-static.json'
with path.open('x') as stream:
    stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
