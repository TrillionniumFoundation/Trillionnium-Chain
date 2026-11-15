#!/usr/bin/env python3
"""Run the five unchanged native actor selectors on a frozen Hepta candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

SELECTORS = [
    'ordinary_actor_reads_actual_use_and_cold_recovery_without_reexecution',
    'updated_candidate_uses_original_actor_and_recovers_without_another_reset',
    'running_actor_refuses_current_withdrawal_and_revocation',
    'updated_actor_rechecks_current_withdrawal_and_revocation',
    'unpublished_actor_refuses_learning_readback_and_keeps_transport_errors',
]

def record(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())

def source(root, expected):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root).strip()
    head, tree = git('rev-parse', 'HEAD').decode(), git('rev-parse', 'HEAD^{tree}').decode()
    assert head == expected and not git('status', '--porcelain', '--untracked-files=all')
    assert git('write-tree').decode() == tree
    entries = git('ls-files', '--stage', '-z').split(b'\0')
    checked = 0
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, wanted, stage = metadata.split()
        assert stage == b'0' and mode in (b'100644', b'100755', b'120000'), (mode, name)
        path = root / os.fsdecode(name)
        if mode == b'120000':
            raw = os.fsencode(os.readlink(path))
            actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        else:
            info = path.stat()
            assert path.is_file() and not path.is_symlink()
            digest = hashlib.sha1(b'blob ' + str(info.st_size).encode() + b'\0')
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1048576), b''):
                    digest.update(block)
            actual = digest.hexdigest()
        assert actual == wanted.decode(), os.fsdecode(name)
        checked += 1
    return dict(head=head, tree=tree, tracked_entries_verified=checked)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'target', 'output', 'just', 'toolchain', 'tools'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    args.target.mkdir(parents=True, exist_ok=False)
    result = dict(schema='hepta-completed-learning-native-controls-v1',
                  source=args.expected_head, selectors=SELECTORS, engineering_controls_only=True,
                  actual_model_execution_accepted=False, production_activation=False, qualification='HOLD_NO_GO')
    try:
        result['before'] = source(args.source, args.expected_head)
        record(args.output / 'source-before.json', result['before'])
        env = os.environ.copy()
        env.update(CARGO_TARGET_DIR=str(args.target), CARGO_BUILD_JOBS='2',
                   RUSTUP_TOOLCHAIN='1.96.0', RUST_TEST_THREADS='1',
                   HEPTA_GENERATION_LEARNING_READBACK_STDOUT='1',
                   LIBCLANG_PATH='/usr/lib/llvm-21/lib',
                   PATH=str(args.toolchain) + ':' + str(args.tools) + ':' + env.get('PATH', ''),
                   LD_LIBRARY_PATH='/usr/lib/llvm-21/lib' + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else ''))
        expression = ' | '.join('test(' + name + ')' for name in SELECTORS)
        command = [str(args.just), 'test', '-p', 'codex-hepta-agentd', '--lib', '--locked', '--offline',
                   '--no-capture', '-E', expression]
        result.update(command=command, start_unix_ns=time.time_ns(), process_id=os.getpid(),
                      cgroup=Path('/proc/self/cgroup').read_text(), new_empty_target=True)
        record(args.output / 'started.json', result)
        start = time.monotonic()
        with (args.output / 'native.log').open('xb') as stream:
            process = subprocess.run(command, cwd=args.source / 'codex-rs', env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, check=False)
            stream.flush(); os.fsync(stream.fileno())
        result.update(exit_code=process.returncode, elapsed_seconds=time.monotonic() - start,
                      end_unix_ns=time.time_ns())
        result['after'] = source(args.source, args.expected_head)
        record(args.output / 'source-after.json', result['after'])
        raw = (args.output / 'native.log').read_bytes()
        result.update(log_sha256=hashlib.sha256(raw).hexdigest(), log_bytes=len(raw))
        junit = args.target / 'nextest/local/junit.xml'
        assert process.returncode == 0, 'native command failed; preserve original log'
        xml = junit.read_bytes()
        (args.output / 'native.junit.xml').write_bytes(xml)
        cases = list(ET.fromstring(xml).iter('testcase'))
        observed = [case.get('name', '') for case in cases]
        assert len(observed) == len(SELECTORS), observed
        for selector in SELECTORS:
            assert sum(name == selector or name.endswith('::' + selector) for name in observed) == 1, selector
        unacceptable = {'failure', 'error', 'skipped', 'flakyFailure', 'flakyError', 'rerunFailure', 'rerunError'}
        assert all(not any(node.tag in unacceptable for node in case.iter()) for case in cases)
        result.update(native_tests_passed=len(cases), observed_names=observed,
                      native_tests_failed=0, native_tests_skipped=0,
                      junit_sha256=hashlib.sha256(xml).hexdigest(), result='PASS')
    except BaseException as error:
        result.update(result='FAIL', error=repr(error))
        raise
    finally:
        record(args.output / 'result.json', result)
        print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
