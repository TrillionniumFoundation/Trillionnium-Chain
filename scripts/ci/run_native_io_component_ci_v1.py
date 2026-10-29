#!/usr/bin/env python3
"""Run the existing public finite component once, then its original-host reader.

The CI owner does not implement or enable the full identity campaign. Its CLI
deadlines include orchestration and never extend the collector's inner limits.
Nested child owners can create their own process groups; the disposable outer
systemd unit owns cgroup cleanup on any failure. Local hashes/inodes and trusted
executables are observations, not authentication against a malicious host.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'scripts/ci'), str(ROOT/'formal/pon-nakamoto-v1')]
import run_pon_native_io_component as component
import check_pon_native_io_component as reader
from bounded_process import ProcessFailure, run_bounded

SCHEMA = 'pon-native-io-component-ci-v1'
STREAM_BYTES = 16*1024**2
READER_SECONDS = component.RUN_SECONDS
require = component.require


def write_new(fd, name, raw):
    require(type(raw) is bytes and len(raw) <= STREAM_BYTES, 'CI_RETAINED_STREAM_LIMIT')
    require(type(name) is str and '/' not in name and name not in ('', '.', '..'), 'CI_LEAF_REQUIRED')
    member = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(member, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(member)
    finally:
        os.close(member)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def json_new(fd, name, value):
    return write_new(fd, name, (json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False)+'\n').encode())


def document(path, limit=STREAM_BYTES):
    fd = component.held_directory(path.parent)
    try:
        pin, raw = component.checked_member(fd, path.name, retain=True, limit=limit)
    finally:
        os.close(fd)
    return dict(path=str(path), bytes=pin['bytes'], sha256=pin['sha256']), component.strict_json(raw)


def no_full_qualification(value):
    for key in component.FULL_FLAGS:
        require(value.get(key) is False, 'CI_FULL_QUALIFICATION_FORBIDDEN')
    reader.flags(value)


def stage(fd, name, command, seconds):
    value = dict(name=name, command=command, outer_cli_timeout_seconds=seconds,
        started_monotonic_ns=time.monotonic_ns(), exit_code=None,
        process_complete=False, failure=None, stdout_truncated=False, stderr_truncated=False)
    stdout = stderr = b''
    try:
        result = run_bounded(command, b'', timeout=seconds, stdout_limit=STREAM_BYTES,
            stderr_limit=STREAM_BYTES, cwd=str(ROOT), env=component.environment())
        stdout, stderr = result.stdout, result.stderr
        value['exit_code'] = result.returncode
        value['process_complete'] = result.returncode == 0
        if result.returncode: value['failure'] = 'CI_ORIGINAL_COMMAND_NONZERO'
    except ProcessFailure as error:
        stdout, stderr = error.stdout, error.stderr
        value.update(exit_code=error.returncode, failure=str(error),
            stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
    except (OSError, ValueError) as error:
        value['failure'] = str(error)
    finally:
        value['ended_monotonic_ns'] = time.monotonic_ns()
        for label, raw in (('stdout', stdout), ('stderr', stderr)):
            filename = name+'.'+label+'.log'
            value[label] = dict(file=filename, **write_new(fd, filename, raw))
        json_new(fd, name+'.step.json', value)
    return value, stdout


def run(args):
    out, target, cargo = map(component.canonical, (args.out, args.target_dir, args.cargo))
    component.digest(args.expected_head, 40)
    component.digest(args.expected_tree, 40)
    require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT)
        and not out.is_relative_to(target) and not target.is_relative_to(out),
        'CI_DISJOINT_FRESH_PATHS_REQUIRED')
    parent, fd = component.new_directory(out)
    result = dict(schema=SCHEMA, profile=component.PROFILE, component_only=True,
        expected_head=args.expected_head, expected_tree=args.expected_tree,
        original_control_plan=component.PLAN, original_build_seconds=component.BUILD_SECONDS,
        original_collector_seconds=component.RUN_SECONDS, reader_seconds=READER_SECONDS,
        resource_policy=dict(cpu_max='400000 100000', memory_max='17179869184', nice=10),
        stages=[], documents={}, complete_success=False, failure=None,
        finalization_failures=[], full_route_ready=False, physical_authentication=False,
        source_kind='head', runner_sha256=component.sha(__file__),
        scope='one existing finite component on its original host; no full writer, full caller, '
            'full independent-reader, 4097 identity, public fairness, model, merge or production qualification',
        **component.component_flags())
    prepared, execution = out/'prepared', out/'execution'
    common = ['--profile', component.PROFILE, '--expected-head', args.expected_head,
        '--expected-tree', args.expected_tree]
    collector = [sys.executable, '-B', str(ROOT/'scripts/run_pon_native_io_component.py')]
    try:
        source = component.source_snapshot()
        component.validate_source(source, args.expected_head, args.expected_tree)
        json_new(fd, 'source-before.json', source)
        json_new(fd, 'resource-before.json', component.resources())
        row, _ = stage(fd, 'prepare', collector+['prepare', *common, '--out', str(prepared),
            '--target-dir', str(target), '--cargo', str(cargo)], component.BUILD_SECONDS)
        result['stages'].append(row)
        require(row['process_complete'], 'CI_PREPARE_FAILED_NO_EXECUTION')
        pin, value = document(prepared/'prepared.json')
        inventory, _ = document(prepared/'artifact-files.json', component.CAPS['inventory_bytes'])
        result['documents'].update(prepared=pin, prepared_inventory=inventory)
        require(value['schema'] == component.PREPARED and value['profile'] == component.PROFILE
            and value['head'] == args.expected_head and value['tree'] == args.expected_tree
            and value['capture_complete'] is True and value['selector_executed'] is False
            and value['failure'] is None, 'CI_REAL_PUBLIC_PREPARATION_REQUIRED')
        no_full_qualification(value)
        row, _ = stage(fd, 'execute', collector+['execute', *common, '--out', str(execution),
            '--prepared', str(prepared/'prepared.json'), '--prepared-sha256', pin['sha256'],
            '--prepared-inventory-sha256', inventory['sha256']], component.RUN_SECONDS)
        result['stages'].append(row)
        require(row['process_complete'], 'CI_EXECUTION_FAILED_NO_RETRY')
        execution_pin, value = document(execution/'results.json')
        executed_inventory, _ = document(execution/'artifact-files.json', component.CAPS['inventory_bytes'])
        result['documents'].update(execution=execution_pin, execution_inventory=executed_inventory)
        require(value['schema'] == component.EXECUTION and value['complete_success'] is True
            and value['selector_executed'] is True and value['failure'] is None,
            'CI_REAL_PUBLIC_EXECUTION_REQUIRED')
        no_full_qualification(value)
        row, raw = stage(fd, 'readback', [sys.executable, '-B',
            str(ROOT/'scripts/ci/check_pon_native_io_component.py'), '--out', str(execution),
            '--prepared', str(prepared/'prepared.json'), '--inventory-sha256', executed_inventory['sha256'],
            '--prepared-sha256', pin['sha256'], '--prepared-inventory-sha256', inventory['sha256'],
            '--expected-head', args.expected_head, '--expected-tree', args.expected_tree], READER_SECONDS)
        result['stages'].append(row)
        require(row['process_complete'], 'CI_ORIGINAL_HOST_READBACK_FAILED')
        readback = component.strict_json(raw)
        require(readback['schema'] == reader.SCHEMA and readback['profile'] == component.PROFILE
            and readback['mechanism_readback_complete'] is True, 'CI_FINITE_READBACK_REQUIRED')
        component.typed([readback['prefix_paid_unique'], readback['final_paid_unique'],
            readback['actual_used_Node_roles']], [2, 6, [0, 5, 6]])
        no_full_qualification(readback)
        result['complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)[:4096]
    finally:
        for name, observe in (('source', component.source_snapshot), ('resource', component.resources)):
            try:
                value = observe()
                if name == 'source': component.validate_source(value, args.expected_head, args.expected_tree)
                json_new(fd, name+'-after.json', value)
            except (OSError, ValueError, KeyError, TypeError) as error:
                result['finalization_failures'].append(name+': '+str(error)[:4096])
        result['complete_success'] = result['complete_success'] and not result['finalization_failures']
        try:
            json_new(fd, 'results.json', result)
        finally:
            os.close(fd)
            os.close(parent)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'target-dir', 'cargo'): parser.add_argument('--'+name, required=True, type=Path)
    for name in ('expected-head', 'expected-tree'): parser.add_argument('--'+name, required=True)
    result = run(parser.parse_args())
    print(json.dumps(dict(schema=SCHEMA, component_only=True,
        complete_success=result['complete_success'], failure=result['failure'],
        full_route_ready=False, **component.component_flags()), sort_keys=True))
    return 0 if result['complete_success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
