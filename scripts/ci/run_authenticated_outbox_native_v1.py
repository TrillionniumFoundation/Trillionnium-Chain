#!/usr/bin/env python3
"""Execute the original authenticated outbox success fixture under its real Host.

The missing-Host refusal is a separate test, never a substitute for this named
positive execution. Source, test ELF, CLI ELF and actual process/Host observations
are retained. This runner cannot provision, widen or replace the fixed parent.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import ci_observation as ci
import public_host_ci_observation as host
from check_required_native_test import validate
from replay_pinned_native import json_load
from run_cross_arch_cost import (build_environment_overrides, cargo_configuration_snapshot,
                                  require_cargo_configuration)
from verify_ci_source import verify as verify_source

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'native_node'
CLI = 'trnm-pon-node'
SOURCE = 'trillionnium/crates/trnm-pon-node/tests/native_node.rs'
SELECTOR = 'test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner'
SCHEMA = 'trnm-authenticated-outbox-native-execution-v1'
FIXTURE_SCHEMA = 'trnm-authenticated-outbox-host-fixture-v1'
BUILD_TIMEOUT_SECONDS = 900
TEST_TIMEOUT_SECONDS = 90
LOG_LIMIT = 8 * 1024 * 1024
SERVICE_CGROUP = re.compile(r'0::/trnmponpublic\.slice/(trnm-from-zero-[A-Za-z0-9_.-]{1,256}\.service)')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def source_identity() -> dict:
    def git(*args):
        return subprocess.check_output(
            ['git', '--no-replace-objects', *args], cwd=ROOT, text=True).strip()
    commit = git('rev-parse', 'HEAD')
    tracked = verify_source('head', commit, root=ROOT)
    return {'commit': commit, 'tree': git('rev-parse', 'HEAD^{tree}'),
            'tracked_source_identity': tracked,
            'test_sha256': ci.digest(ROOT / SOURCE)}


def expected_source(actual: str) -> str:
    expected = os.environ.get('TRNM_EXPECTED_SOURCE_SHA')
    require(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected) is not None,
            'OUTBOX_EXPECTED_SOURCE_REQUIRED')
    require(actual == expected, 'OUTBOX_EXPECTED_SOURCE_MISMATCH')
    return expected


def require_original_build_environment() -> None:
    overrides = build_environment_overrides(dict(os.environ))
    require(not overrides, 'OUTBOX_ORIGINAL_BUILD_REQUIRED:' + ','.join(sorted(overrides)))
    require_cargo_configuration(cargo_configuration_snapshot(ROOT, dict(os.environ)))


def native_build_command() -> list[str]:
    return ['cargo', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', TARGET,
            '--no-run', '--message-format=json']


def regular_elf(path: Path) -> Path:
    require(path.is_absolute() and not path.is_symlink() and path.is_file()
            and path.resolve(strict=True) == path, 'OUTBOX_REGULAR_EXACT_ELF_REQUIRED')
    require(path.stat().st_mode & 0o111, 'OUTBOX_EXECUTABLE_REQUIRED')
    with path.open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'OUTBOX_ELF_REQUIRED')
    return path


def select_binaries(lines: list[str]) -> tuple[Path, Path]:
    tests, clients = [], []
    for line in lines:
        if not line.startswith('{'):
            continue
        row = json_load(line)
        if row.get('reason') != 'compiler-artifact' or not row.get('executable'):
            continue
        target, profile = row.get('target', {}), row.get('profile', {})
        if target.get('name') == TARGET and profile.get('test') is True:
            require(target.get('kind') == ['test'], 'OUTBOX_EXACT_TEST_TARGET_REQUIRED')
            tests.append(regular_elf(Path(row['executable'])))
        elif target.get('name') == CLI and profile.get('test') is False:
            require(target.get('kind') == ['bin'], 'OUTBOX_EXACT_CLI_TARGET_REQUIRED')
            clients.append(regular_elf(Path(row['executable'])))
    require(len(tests) == 1 and len(clients) == 1, 'OUTBOX_EXACT_TEST_AND_CLI_REQUIRED')
    test, client = tests[0], clients[0]
    require(test.parent.name == 'deps' and client == test.parent.parent / CLI,
            'OUTBOX_EMBEDDED_CLI_LOCATION_REQUIRED')
    require(test != client, 'OUTBOX_DISTINCT_BINARIES_REQUIRED')
    return test, client


def native_test_command(binary: Path) -> list[str]:
    return [str(binary), SELECTOR, '--exact', '--ignored', '--nocapture', '--test-threads=1']


def capture_host(phase: str, reference: dict | None = None) -> dict:
    current = Path('/proc/thread-self/cgroup').read_text().strip()
    match = SERVICE_CGROUP.fullmatch(current)
    require(match is not None, 'OUTBOX_FIXED_HOST_MEMBERSHIP_REQUIRED')
    sample = host.capture(phase, match[1])
    errors = host.validate(sample, inside=True, uid=os.getuid(), gid=os.getgid(),
                           cwd=str(ROOT), reference=reference)
    require(not errors, 'OUTBOX_ACTUAL_HOST_REQUIRED:' + ','.join(errors))
    return sample


def fixture_observation(lines: list[str]) -> dict:
    fixtures = []
    for line in lines:
        if FIXTURE_SCHEMA not in line:
            continue
        start = line.find('{')
        require(start >= 0, 'OUTBOX_FIXTURE_JSON_REQUIRED')
        fixture = json_load(line[start:])
        require(type(fixture) is dict and fixture.get('schema') == FIXTURE_SCHEMA,
                'OUTBOX_FIXTURE_SCHEMA')
        fixtures.append(fixture)
    require(len(fixtures) == 1, 'OUTBOX_ONE_COMPLETED_FIXTURE_REQUIRED')
    fixture = fixtures[0]
    fields = {'schema', 'test_pid', 'server_pid', 'push_pids', 'sync_pid', 'perpid_cgroups',
              'sync_success', 'original_server_lifetime_seconds', 'verified_tip',
              'authenticated_requests', 'replayed_responses', 'authenticated_outbox_pending',
              'production_activation', 'public_network_ready'}
    require(set(fixture) == fields, 'OUTBOX_FIXTURE_FIELDS')
    require(fixture['sync_success'] is True and fixture['production_activation'] is False
            and fixture['public_network_ready'] is False, 'OUTBOX_POSITIVE_SUCCESS_REQUIRED')
    for name, expected in [('original_server_lifetime_seconds', 4), ('authenticated_requests', 3),
                           ('replayed_responses', 0), ('authenticated_outbox_pending', 0)]:
        require(type(fixture[name]) is int and fixture[name] == expected,
                'OUTBOX_ORIGINAL_ASSERTIONS_REQUIRED:' + name)
    require(type(fixture['verified_tip']) is str
            and re.fullmatch('[0-9a-f]{64}', fixture['verified_tip']) is not None,
            'OUTBOX_VERIFIED_TIP_REQUIRED')
    require(type(fixture['push_pids']) is list and len(fixture['push_pids']) == 2,
            'OUTBOX_ACTUAL_PUSH_PIDS_REQUIRED')
    pids = [fixture['test_pid'], fixture['server_pid'], *fixture['push_pids'], fixture['sync_pid']]
    require(all(type(pid) is int and 0 < pid <= 0x7fff_ffff for pid in pids)
            and len(set(pids)) == 5, 'OUTBOX_DISTINCT_ACTUAL_PIDS_REQUIRED')
    records = fixture['perpid_cgroups']
    roles = ['test', 'server', 'push-first', 'push-replay', 'sync']
    require(type(records) is list and len(records) == 5, 'OUTBOX_ACTUAL_PROCESS_HOSTS_REQUIRED')
    groups = []
    for record, role, pid in zip(records, roles, pids, strict=True):
        require(type(record) is dict
                and set(record) == {'role', 'pid', 'cgroup', 'cgroup_observation_error'}
                and record['role'] == role and type(record['pid']) is int and record['pid'] == pid,
                'OUTBOX_PROCESS_BINDING')
        group = record['cgroup']
        error = record['cgroup_observation_error']
        if group is None:
            require(role != 'test' and type(error) is str and 0 < len(error) <= 2048,
                    'OUTBOX_UNAVAILABLE_CHILD_OBSERVATION_REQUIRED')
        else:
            require(type(group) is str and SERVICE_CGROUP.fullmatch(group) is not None
                    and error is None, 'OUTBOX_PROCESS_FIXED_HOST_REQUIRED')
            groups.append(group)
    require(len(set(groups)) == 1, 'OUTBOX_SHARED_ACTUAL_HOST_REQUIRED')
    return fixture


def validate_execution(process: dict, log: Path) -> dict:
    require(process.get('executed') is True and process.get('exit_code') == 0
            and process.get('process_exit_code') == 0 and process.get('timed_out') is False
            and process.get('source_verified') is True, 'OUTBOX_NATIVE_PROCESS_REQUIRED')
    require(type(process.get('command')) is list
            and process['command'][1:] == native_test_command(Path('unused'))[1:],
            'OUTBOX_EXACT_NATIVE_COMMAND_REQUIRED')
    require(log.is_file() and not log.is_symlink(), 'OUTBOX_REGULAR_LOG_REQUIRED')
    with log.open('rb') as stream:
        raw = stream.read(LOG_LIMIT + 1)
    require(len(raw) <= LOG_LIMIT, 'OUTBOX_LOG_LIMIT')
    lines = raw.decode('utf-8').splitlines()
    return {'named_execution': validate(lines, SELECTOR),
            'host_fixture': fixture_observation(lines)}


def save_manifest(out: Path, result: dict) -> None:
    temporary = out / 'manifest.json.next'
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, out / 'manifest.json')


def run(out: Path) -> dict:
    require(out.is_absolute() and out.resolve() == out and not out.is_relative_to(ROOT),
            'OUTBOX_OUTPUT_OUTSIDE_CHECKOUT_REQUIRED')
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': SCHEMA, 'source_before': None, 'source_after': None,
              'source_expected': None, 'source_recompiled': False, 'execution_finished': False,
              'all_named_tests_passed': False, 'process': None, 'named_execution': None,
              'host_fixture': None, 'host_before': None, 'host_after': None,
              'test_binary_path': None, 'cli_binary_path': None,
              'test_binary_sha256_before': None, 'test_binary_sha256_after': None,
              'cli_binary_sha256_before': None, 'cli_binary_sha256_after': None,
              'failures': [], 'passed': False, 'production_activation': False,
              'public_network_ready': False, 'physical_power_loss_accepted': False}
    save_manifest(out, result)
    test = client = None
    try:
        result['source_before'] = source_identity()
        expected = expected_source(result['source_before']['commit'])
        result['source_expected'] = expected
        require_original_build_environment()
        result['host_before'] = capture_host('outbox-before-native')
        result['build'] = ci.run(native_build_command(), out / 'build.log',
                                 timeout=BUILD_TIMEOUT_SECONDS, expected_source=expected)
        require(result['build']['exit_code'] == 0 and result['build']['timed_out'] is False
                and result['build']['source_verified'] is True, 'OUTBOX_SOURCE_BUILD_REQUIRED')
        test, client = select_binaries((out / 'build.log').read_text().splitlines())
        for role, binary, name in [('test', test, 'test.elf'), ('cli', client, 'cli.elf')]:
            result[role + '_binary_path'] = str(binary)
            result[role + '_binary_sha256_before'] = ci.digest(binary)
            shutil.copy2(binary, out / name)
        result['source_recompiled'] = True
        log = out / 'native.log'
        result['process'] = ci.run(native_test_command(test), log, timeout=TEST_TIMEOUT_SECONDS,
                                   expected_source=expected)
        result['native_log_sha256'] = ci.digest(log)
        result.update(validate_execution(result['process'], log))
        require(result['host_fixture']['perpid_cgroups'][0]['cgroup']
                == result['host_before']['thread_cgroup'], 'OUTBOX_FIXTURE_RUNNER_HOST_MISMATCH')
        result['execution_finished'] = True
        result['all_named_tests_passed'] = True
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        result['failures'].append(str(error))
    except BaseException as error:
        result['failures'].append(type(error).__name__)
        raise
    finally:
        try:
            result['source_after'] = source_identity()
            require(expected_source(result['source_after']['commit']) == result['source_expected'],
                    'OUTBOX_EXPECTED_SOURCE_CHANGED')
            require(result['source_before'] == result['source_after'], 'OUTBOX_COMPLETE_SOURCE_CHANGED')
            result['host_after'] = capture_host('outbox-after-native', result['host_before'])
            for role, binary, name in [('test', test, 'test.elf'), ('cli', client, 'cli.elf')]:
                if binary is not None:
                    regular_elf(binary)
                    result[role + '_binary_sha256_after'] = ci.digest(binary)
                    require(result[role + '_binary_sha256_after']
                            == result[role + '_binary_sha256_before'] == ci.digest(out / name),
                            'OUTBOX_BINARY_CHANGED:' + role)
            if result.get('native_log_sha256') is not None:
                require(ci.digest(out / 'native.log') == result['native_log_sha256'],
                        'OUTBOX_NATIVE_LOG_CHANGED')
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
            result['failures'].append(str(error))
        result['passed'] = (result['source_before'] is not None
                            and result['source_before'] == result['source_after']
                            and result['host_before'] is not None and result['host_after'] is not None
                            and result['source_recompiled'] and result['execution_finished']
                            and result['all_named_tests_passed'] and not result['failures'])
        result['files'] = {str(path.relative_to(out)): ci.digest(path)
                           for path in sorted(out.rglob('*'))
                           if path.is_file() and path != out / 'manifest.json'}
        save_manifest(out, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    result = run(parser.parse_args().out)
    print(json.dumps({'passed': result['passed'], 'failures': result['failures']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
