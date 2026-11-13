#!/usr/bin/env python3
"""Read actual native receipts with the independent v3 observer; never integrate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a')
INPUTS = Path(str(ROOT) + '-inputs')
CONTROLLER = INPUTS / 'integrate_candidate_v3_observer.py'
OLD = INPUTS / 'validation'
FOLLOWUP = INPUTS / 'native-followup-04'
OUT = INPUTS / 'native-observer-audit-03'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
C2_TREE = '7c003a3d183ad33ff4f3349cbcce61564f73a2ba'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def emit(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def main():
    expected = sys.argv[1]
    assert len(expected) == 64 and sha(CONTROLLER.read_bytes()) == expected
    assert not OUT.exists()
    OUT.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')

    def git(*argv):
        return subprocess.check_output(['git', '--no-replace-objects', *argv], cwd=ROOT, env=env)

    def status(phase, code=None):
        emit(OUT / 'status.json', {'stage': 'validate-native-actual-originals', 'phase': phase,
             'last_exit': code, 'recorded_unix_ns': time.time_ns(), 'controller_sha256': expected,
             'code_checkpoint': C2, 'native_full_suite_passed': False, 'security_status': 'HOLD'})

    try:
        assert git('rev-parse', 'HEAD').decode().strip() == C2
        assert git('rev-parse', 'HEAD^{tree}').decode().strip() == C2_TREE
        assert not git('status', '--porcelain')
        source = {'controller_sha256': expected, 'controller_bytes': CONTROLLER.stat().st_size,
                  'recorder_sha256': sha(Path(__file__).read_bytes()), 'code_checkpoint': C2, 'tree': C2_TREE,
                  'original_directory': str(OLD), 'followup_directory': str(FOLLOWUP),
                  'scope': 'read-only actual receipt parser; no Controller construction, project mutation, native test, or C3 commit',
                  'native_full_suite_passed': False, 'production_activation': False}
        emit(OUT / 'source.json', source)
        code = """import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('pon_observer_v3_readonly',Path(sys.argv[1]))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
files,observations=module.validate_native(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]))
print(json.dumps({'observations':observations,'members':{name:item['record'] for name,item in files.items()}},indent=2,sort_keys=True))
"""
        argv = ['python3', '-B', '-c', code, str(CONTROLLER), str(OLD), str(FOLLOWUP), str(ROOT)]
        start = time.time_ns()
        status('running')
        stdout, stderr = OUT / 'validate-native.stdout.log', OUT / 'validate-native.stderr.log'
        with stdout.open('xb') as out, stderr.open('xb') as error:
            result = subprocess.run(argv, cwd=ROOT, env=env, stdout=out, stderr=error)
        record = {'label': 'validate-native-actual-originals', 'argv': argv, 'cwd': str(ROOT),
                  'exit_code': result.returncode, 'start_unix_ns': start, 'end_unix_ns': time.time_ns()}
        for name, path in (('stdout', stdout), ('stderr', stderr)):
            raw = path.read_bytes()
            record[name] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        emit(OUT / 'command.json', record)
        assert sha(CONTROLLER.read_bytes()) == expected
        assert git('rev-parse', 'HEAD').decode().strip() == C2 and not git('status', '--porcelain')
        if result.returncode:
            raise RuntimeError('actual receipt parser refused: exit ' + str(result.returncode))
        report = json.loads(stdout.read_bytes())
        observation = report['observations']
        assert observation['native_observation_complete'] is True
        assert observation['native_full_suite_passed'] is False and observation['draft_only'] is True
        emit(OUT / 'summary.json', dict(source, schema='pon-native-observer-actual-receipts-audit-v1',
             complete=True, parser_exit_code=0, original_commands=observation['original_command_count'],
             followup_commands=observation['followup_command_count'], raw_members=len(report['members']),
             project_mutations_performed=False, native_tests_executed=False, c3_created=False,
             original_node_harness=observation['original_node_harness'], security_status='HOLD'))
        status('finished', 0)
        print(json.dumps({'complete': True, 'parser_exit_code': 0, 'output': str(OUT),
                          'controller_sha256': expected, 'native_full_suite_passed': False}, sort_keys=True))
        return 0
    except BaseException as error:
        emit(OUT / 'failure.json', {'complete': False, 'reason': repr(error), 'controller_sha256': expected,
             'recorded_unix_ns': time.time_ns(), 'native_full_suite_passed': False, 'security_status': 'HOLD'})
        status('failed', 2)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
