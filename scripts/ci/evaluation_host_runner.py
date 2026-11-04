#!/usr/bin/env python3
"""Exact original sync-observation Cargo target in the existing fixed Host parent.

The original two Rust tests, nineteen real CLI calls and twelve listener phases
remain authoritative. This runner only provides the required kernel parent and
retains their unfiltered output, actual child receipts and source identities.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGET = re.compile(r'evaluation_sync_observation-[0-9a-f]{16}')
TESTS = (
    'actual_public_full_sync_query_partial_refusals_reorg_and_retirement',
    'optional_sync_inputs_reject_before_open_without_changing_old_defaults',
)
PHASES = ('full-sync', 'default-query', 'unknown', 'window', 'partial',
          'wrong-context', 'reorganization', 'lighter-branch',
          'retirement-pages-1', 'retirement-pages-2', 'retirement-pages-3', 'retirement')
# The unchanged Rust fixture passes --after equal to --tip in these four
# commands, so they finish locally while their owned listeners accept no client.
LOCAL_PHASES = ('default-query', 'unknown', 'window', 'lighter-branch')
NETWORK_PHASES = tuple(phase for phase in PHASES if phase not in LOCAL_PHASES)


def require(value, message):
    if not value:
        raise ValueError(message)


def selected(command):
    require(bool(command), 'EVALUATION_CARGO_EXECUTABLE_REQUIRED')
    name = Path(command[0]).name
    if not name.startswith('evaluation_sync_observation-'):
        return False
    require(TARGET.fullmatch(name) is not None and len(command) == 1,
            'EVALUATION_ORIGINAL_UNFILTERED_TARGET_REQUIRED')
    return True


def cli_observations(directory):
    """Retain partial actual outcomes too; completeness is a separate decision."""
    rows = []
    if not directory.exists():
        return rows
    for receipt in sorted(directory.glob('cli-*.receipt.json')):
        prefix = receipt.name.removesuffix('.receipt.json')
        require(re.fullmatch(r'cli-[0-9]{3}', prefix) is not None, 'EVALUATION_CLI_ORDINAL')
        value = json.loads(receipt.read_bytes())
        row = {'ordinal': int(prefix[4:]), 'receipt': value, 'files': {}}
        for suffix in ('receipt.json', 'stdout', 'stderr'):
            path = directory / (prefix + '.' + suffix)
            require(path.is_file() and not path.is_symlink(), 'EVALUATION_ACTUAL_CLI_OUTPUT')
            raw = path.read_bytes()
            row['files'][suffix] = {'path': path.name, 'bytes': len(raw),
                                    'sha256': hashlib.sha256(raw).hexdigest()}
            if suffix != 'receipt.json':
                row[suffix] = raw.decode('utf-8')
        rows.append(row)
    return rows


def server_observations(stderr):
    rows = []
    for line in stderr.splitlines():
        if not line.startswith('sync phase='):
            continue
        match = re.fullmatch(
            r'sync phase=(\S+) elapsed=(.*?) command=(.*?) address=(\S+) '
            r'server_exited_before_stop=(true|false) server_result=(.*?) child=(.*)', line)
        require(match is not None, 'EVALUATION_ACTUAL_PHASE_DIAGNOSTIC')
        phase, elapsed, command, address, before_stop, result, child = match.groups()
        counts = re.findall(r'\baccepted_connections: ([0-9]+)', result)
        status = re.match(r'Ok\(\(ExitStatus\(unix_wait_status\(([0-9]+)\)\)', child)
        rows.append({'phase': phase, 'elapsed': elapsed, 'command': command, 'address': address,
                     'server_exited_before_stop': before_stop == 'true',
                     'server_join_succeeded': result.startswith('Ok(Ok('),
                     'accepted_connections': int(counts[0]) if len(counts) == 1 else None,
                     'actual_cli_returncode': os.waitstatus_to_exitcode(int(status.group(1)))
                                             if status is not None else None,
                     'diagnostic_sha256': hashlib.sha256(line.encode('utf-8')).hexdigest()})
    return rows


def validate_observation(stdout, rows, phases, cli_binary):
    """The original Rust assertions retain all state and refusal semantics."""
    names = re.findall(r'^test (\S+) \.\.\. ok$', stdout, re.M)
    require(names == list(TESTS), 'EVALUATION_EXACT_TWO_TESTS')
    summaries = re.findall(
        r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
        r'(\d+) measured; (\d+) filtered out; finished in [0-9.]+s$', stdout, re.M)
    require(summaries == [('ok', '2', '0', '0', '0', '0')],
            'EVALUATION_COMPLETE_UNFILTERED_SUMMARY')
    require([row['ordinal'] for row in rows] == list(range(19)),
            'EVALUATION_ALL_NINETEEN_ACTUAL_CLI_CALLS')
    for index, row in enumerate(rows):
        receipt = row['receipt']
        expected = 0 if index < 2 else 2
        require(type(receipt.get('actual_returncode')) is int
                and receipt['actual_returncode'] == expected
                and receipt.get('actual_child_wait_completed') is True
                and receipt.get('local_loopback_or_input_refusal_test') is True
                and receipt.get('public_ready') is False, 'EVALUATION_ACTUAL_CLI_WAIT_AND_EXIT')
        if expected == 0:
            require(type(json.loads(row['stdout'])) is dict, 'EVALUATION_ACTUAL_CLI_PRODUCT')
        else:
            require(row['stdout'] == '' and row['stderr'] != '', 'EVALUATION_ACTUAL_REFUSAL')
    require([row['phase'] for row in phases] == list(PHASES), 'EVALUATION_ALL_TWELVE_LISTENER_PHASES')
    for index, phase in enumerate(phases):
        require(phase['command'].startswith(json.dumps(str(cli_binary)) + ' "sync" ')
                and phase['server_join_succeeded'] is True
                and type(phase['accepted_connections']) is int
                and phase['actual_cli_returncode'] == rows[index]['receipt']['actual_returncode'],
                'EVALUATION_ACTUAL_LISTENER_AND_CHILD')
        if phase['phase'] in LOCAL_PHASES:
            require(phase['accepted_connections'] == 0, 'EVALUATION_ACTUAL_LOCAL_PHASE')
        else:
            require(phase['accepted_connections'] > 0, 'EVALUATION_ACTUAL_NETWORK_PHASE')
    return {'named_tests': list(TESTS), 'passed': 2, 'failed': 0, 'ignored': 0, 'filtered_out': 0,
            'actual_cli_calls': len(rows), 'actual_cli_exit_counts': dict(Counter(
                row['receipt']['actual_returncode'] for row in rows)),
            'actual_listener_phases': len(phases),
            'actual_network_phases': len(NETWORK_PHASES),
            'actual_local_phases': len(LOCAL_PHASES),
            'network_phase_names': list(NETWORK_PHASES),
            'local_phase_names': list(LOCAL_PHASES),
            'accepted_connections': sum(row['accepted_connections'] for row in phases),
            'original_state_and_refusal_assertions_executed': True,
            'public_readiness': False}


def run_selected(command):
    # -I deliberately excludes caller PYTHONPATH and the script directory.
    os.environ['GIT_NO_LAZY_FETCH'] = '1'
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from from_zero_native_host import EVALUATION_TIMEOUT_SECONDS, run_host_child, sha
    from history_fixed_parent_v2 import owner
    from verify_ci_source import verify

    original_cwd = Path.cwd()
    out_root = os.environ.get('TRNM_CI_RECEIPT_DIR')
    require(out_root is not None, 'EVALUATION_RECEIPT_DIRECTORY_REQUIRED')
    out = Path(out_root) / 'evaluation-native-host'
    require(out.is_absolute() and not out.resolve().is_relative_to(ROOT),
            'EVALUATION_RECEIPT_OUTSIDE_SOURCE')
    out.mkdir(parents=True, exist_ok=False)
    run_owner = os.environ.get('TRNM_FROM_ZERO_HOST_OWNER')
    if run_owner is None:
        run_owner = os.environ.get('GITHUB_RUN_ID', '') + '.' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
    owner(run_owner)
    require(os.environ.get('RUST_TEST_THREADS') == '1', 'EVALUATION_ORIGINAL_SERIAL_HARNESS')
    binary = Path(command[0])
    require(binary.is_absolute() and not binary.is_symlink()
            and binary.resolve(strict=True) == binary, 'EVALUATION_ORIGINAL_BINARY')

    def identity():
        source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        expected = os.environ.get('TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT')
        require(source == expected, 'EVALUATION_COMPILE_AND_RUN_SOURCE')
        return verify('head', source, root=ROOT)

    record = {'schema': 'native-evaluation-host-process-v2', 'original_cargo_command': command,
              'original_cargo_cwd': str(original_cwd), 'native_cwd': str(ROOT),
              'original_test_execution_mapping': {name: 'native/stdout' for name in TESTS},
              'target_selection_changed': False, 'source_before': None, 'source_after': None,
              'source_unchanged': False, 'binary_unchanged': False, 'actual_process': None,
              'observation': None, 'cli_evidence': [], 'server_phases': [], 'complete': False, 'production_qualification': False,
              'errors': []}

    def save():
        (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')

    def parent(action):
        args = ['/usr/bin/sudo', '-n', '--', '/usr/bin/python3', '-I', '-B',
                str(ROOT / 'scripts/ci/history_fixed_parent_v2.py'), action, '--owner', run_owner]
        if action == 'provision':
            args += ['--source', str(ROOT / 'config/systemd/trnmponpublic.slice')]
        observed = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=20, check=False)
        for stream in ('stdout', 'stderr'):
            (out / f'parent-{action}.{stream}').write_bytes(getattr(observed, stream))
        record['parent_' + action] = {'command': args, 'returncode': observed.returncode}
        require(observed.returncode == 0, 'EVALUATION_PARENT_' + action.upper())

    provisioned = False
    save()
    try:
        record['source_before'] = identity()
        record['binary_sha256'] = sha(binary.read_bytes())
        cli_binary = binary.parent.parent / 'trnm-pon-node'
        require(cli_binary.is_file() and not cli_binary.is_symlink()
                and cli_binary.resolve(strict=True) == cli_binary, 'EVALUATION_ORIGINAL_CLI_BINARY')
        record['cli_binary'] = str(cli_binary)
        record['cli_binary_sha256'] = sha(cli_binary.read_bytes())
        record['test_source_sha256'] = sha((ROOT / 'trillionnium/crates/trnm-pon-node/tests/evaluation_sync_observation.rs').read_bytes())
        os.chdir(ROOT)  # The existing root helper binds both actor CWDs to this exact source.
        os.environ['EVALUATION_SYNC_OBSERVATION_EVIDENCE_DIR'] = str(out / 'cli-output')
        # Capture changes only: the unchanged fixture's real joined server and
        # child diagnostics must remain available even when both tests pass.
        os.environ['RUST_TEST_NOCAPTURE'] = '1'
        parent('provision')
        provisioned = True
        save()
        print(json.dumps({'event': 'original evaluation sync target enters fixed Host parent',
                          'source': record['source_before']['tested_commit'],
                          'tests': list(TESTS), 'receipt': str(out)}), flush=True)
        result = run_host_child(command, out / 'native', EVALUATION_TIMEOUT_SECONDS,
                                run_owner=run_owner,
                                source=record['source_before']['tested_commit'],
                                binary_sha256=record['binary_sha256'])
        record['actual_process'] = result
        stdout = (out / 'native/stdout').read_bytes()
        stderr = (out / 'native/stderr').read_bytes()
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
        record['cli_evidence'] = cli_observations(out / 'cli-output')
        record['server_phases'] = server_observations(stderr.decode('utf-8'))
        record['observation'] = validate_observation(
            stdout.decode('utf-8'), record['cli_evidence'], record['server_phases'], cli_binary)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record['errors'].append(str(error))
    finally:
        if provisioned:
            try:
                parent('cleanup')
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                record['errors'].append(str(error))
        try:
            record['source_after'] = identity()
            record['source_unchanged'] = record['source_before'] == record['source_after']
            record['binary_unchanged'] = record.get('binary_sha256') == sha(binary.read_bytes())
            record['cli_binary_unchanged'] = (
                record.get('cli_binary') is not None
                and record.get('cli_binary_sha256') == sha(Path(record['cli_binary']).read_bytes()))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            record['errors'].append(str(error))
        result = record['actual_process']
        record['complete'] = (not record['errors'] and record['source_unchanged']
                              and record['binary_unchanged'] and record.get('cli_binary_unchanged') is True
                              and record['observation'] is not None
                              and result is not None and result['host_scope']['complete']
                              and result['host_scope']['closure'].get('closed') is True
                              and result['host_scope']['closure'].get('forced_cleanup') is False)
        save()
    if record['complete']:
        return 0
    code = (record['actual_process'] or {}).get('exit_code')
    return code if type(code) is int and 0 < code < 256 else 1



def main():
    command = sys.argv[1:]
    require(selected(command), 'EVALUATION_EXACT_TARGET_REQUIRED')
    return run_selected(command)


if __name__ == '__main__':
    raise SystemExit(main())
