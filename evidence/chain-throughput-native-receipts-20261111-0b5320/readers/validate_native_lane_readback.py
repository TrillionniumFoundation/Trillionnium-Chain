#!/usr/bin/env python3
"""Read back copied native receipts without replacing their native execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path('/workspace/scratch/0b53202edbbf/chain-throughput')
DRIVER = '11e242dbaaae14a9d16282fe8deaf36827e98395'
READER = ROOT / 'scripts/ci/run_pon_budget_controls.py'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git_bytes(commit, path):
    return subprocess.check_output(['git', 'show', commit + ':' + path], cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt_dir', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = {'schema': 'pon-native-lane-transcript-readback-v1',
              'scope': 'copied original process streams, source receipts, input bytes and recorded binary guards; no local native execution or independent ELF download',
              'result': 'FAIL', 'driver': DRIVER, 'errors': [], 'streams': [],
              'controls': [], 'reader_sha256': sha(READER.read_bytes())}
    try:
        require(READER.read_bytes() == git_bytes(DRIVER, 'scripts/ci/run_pon_budget_controls.py'),
                'frozen reader differs from exact committed driver')
        sys.path.insert(0, str(READER.parent))
        spec = importlib.util.spec_from_file_location('frozen_component_reader', READER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        report_raw = (args.receipt_dir / 'report.json').read_bytes()
        report = json.loads(report_raw)
        result.update(mode=report['mode'], source=report['expected_source'],
                      report_sha256=sha(report_raw), native_report_result=report['result'])
        require(report['expected_driver'] == DRIVER, 'wrong driver')
        mod.validate_source_pair(report['mode'], DRIVER, report['expected_source'])
        require(report['source_before'] == report['source_after'], 'source changed')
        for label, commit in [('driver', DRIVER), ('subject', report['expected_source'])]:
            identity = report['source_before'][label]
            tree = subprocess.check_output(['git', 'rev-parse', commit + '^{tree}'], cwd=ROOT, text=True).strip()
            require(identity['tested_commit'] == commit and identity['tested_tree'] == tree,
                    label + ': source commit/tree mismatch')
            require(identity['kind'] == 'head' and identity['candidate'] == commit
                    and identity['tracked_worktree_verified'] is True,
                    label + ': exact source guard missing')
            for stage in ('before', 'after'):
                require(json.loads((args.receipt_dir / (label + '-source-' + stage + '.json')).read_bytes()) == identity,
                        label + ': separate source receipt differs')
        inputs = report['identical_group_inputs']
        require(set(inputs) == set(mod.same_input_groups(report['mode'])), 'input group mismatch')
        for group, paths in mod.same_input_groups(report['mode']).items():
            require(set(inputs[group]) == set(paths), 'input roster mismatch')
            for path in paths:
                actual = git_bytes(report['expected_source'], path)
                current = git_bytes(DRIVER, path)
                require(actual == current, 'non-identical comparison input: ' + path)
                for side in ('driver', 'subject'):
                    record = inputs[group][path][side]
                    require(record['sha256'] == sha(actual) and record['bytes'] == len(actual),
                            'recorded input mismatch: ' + path)

        def streams(process):
            values = {}
            for stream in ('stdout', 'stderr'):
                record = process[stream]
                local = args.receipt_dir / Path(record['path']).name
                raw = local.read_bytes()
                require(len(raw) == record['bytes'] and sha(raw) == record['sha256'],
                        'raw process stream mismatch: ' + local.name)
                result['streams'].append({'file': local.name, 'bytes': len(raw), 'sha256': sha(raw)})
                values[stream] = raw.decode('utf-8')
            return values

        for command in report['commands']:
            require(mod.successful(command), 'setup/build/list command failed')
            streams(command)
        expected_names = tuple(mod.controls_for_mode(report['mode']))
        require(tuple(case['test'] for case in report['cases']) == expected_names,
                'native control roster/order mismatch')
        for case in report['cases']:
            raw = streams(case['process'])
            actual = mod.validate_control(case['test'], report['mode'], case['process'],
                                          raw['stdout'], raw['stderr'])
            require(case['expected_outcome_observed'] is True
                    and actual['expected_outcome_observed'] is True,
                    'native control outcome not observed')
            result['controls'].append(actual)
        if report['mode'] == 'fixed':
            process = report['pool_integration']['process']
            raw = streams(process)
            require(mod.successful(process), 'pool integration process failed')
            result['pool_integration'] = mod.validate_pool_integration(raw['stdout'])
        for role, entry in report['executables'].items():
            require(entry['built_before'] == entry['built_after']
                    and entry['retained_before'] == entry['retained_after'],
                    'recorded binary guard changed: ' + role)
            require(entry['built_before']['sha256'] == entry['retained_before']['sha256']
                    and entry['built_before']['bytes'] == entry['retained_before']['bytes'],
                    'retained binary identity mismatch: ' + role)
            require(entry['compiler_artifact']['profile'] == (
                    mod.RELEASE_CLI_PROFILE if role == 'cli' else mod.RELEASE_PROFILE),
                    'original native profile mismatch: ' + role)
        result['recorded_binary_guards'] = report['executables']
        require(report['result'] == 'PASS' and report['errors'] == [], 'native lane did not pass')
        require(all(report[flag] is False for flag in mod.FALSE_FLAGS), 'qualification flag changed')
        result.update(result='PASS', actual_control_count=len(result['controls']),
                      native_pass_controls=sum(x['expected'] == 'pass' for x in result['controls']),
                      native_expected_failures=sum(x['expected'] == 'fail' for x in result['controls']))
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.write('\n')
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('streams', 'controls', 'recorded_binary_guards')}))
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
