#!/usr/bin/env python3
"""Build and execute exact from-zero tests inside the existing protocol lane.

Keep failed builds, named nonzero test executions, full reports and the actual
binary. No old artifact can satisfy this source build, and no extra CI lane is
introduced. Process CPU encloses the entire test, not a per-actor cost allocation.
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

from check_required_native_test import validate
from replay_pinned_native import digest, json_load, require, run_child

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'public_v3_from_zero'
SOURCE = 'trillionnium/crates/trnm-pon-node/tests/' + TARGET + '.rs'
TESTS = (
    'caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct',
    'from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection',
    'from_zero_service_shares_cpu_with_honest_work_and_reopened_owner',
)


def source_identity() -> dict:
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()
    require(not git('status', '--porcelain'), 'CLEAN_COMMITTED_SOURCE_REQUIRED')
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'test_sha256': digest((ROOT / SOURCE).read_bytes())}


def select_binary(lines: list[str]) -> Path:
    paths = []
    for line in lines:
        if not line.startswith('{'):
            continue
        row = json_load(line)
        if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == TARGET:
            if row.get('profile', {}).get('test') is True and row.get('executable'):
                path = Path(row['executable'])
                require(not path.is_symlink(), 'REGULAR_BINARY_REQUIRED')
                paths.append(path.resolve())
    require(len(paths) == 1, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED')
    return paths[0]


# Bounded report consistency, not a second W1/state oracle or public qualification.
# The native source fixes two phases with eight constructions and eight probes.
REPORT_LIMIT = 32 * 1024 * 1024


def validate_service_report(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), 'NATIVE_SERVICE_REPORT_REQUIRED')
    with path.open('rb') as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    require(len(raw) <= REPORT_LIMIT, 'NATIVE_SERVICE_REPORT_LIMIT')
    doc = json_load(raw)
    require(isinstance(doc, dict) and doc.get('schema') == 'public-v3-local-from-zero-service-v2',
            'NATIVE_SERVICE_REPORT_SCHEMA')
    for key in ('network', 'parameters', 'genesis', 'target', 'policy_id'):
        require(isinstance(doc.get(key), str) and re.fullmatch('[0-9a-f]{64}', doc[key]) is not None,
                'NATIVE_SERVICE_CONTEXT')
    for key in ('reopen_state_equal', 'cpu_domain_retained_across_owner_reopen',
                'all_requested_reads_required_on_time', 'finite_target_met'):
        require(doc.get(key) is True, 'NATIVE_SERVICE_TARGET')
    for key in ('budget_depletion_demonstrated', 'public_network_ready', 'independent_accepted',
                'work_profile_qualified', 'resource_fairness_qualified',
                'physical_power_loss', 'production_activation'):
        require(doc.get(key) is False, 'NATIVE_SERVICE_SCOPE_PROMOTION')
    phases = doc.get('phases')
    require(isinstance(phases, list) and len(phases) == 2, 'NATIVE_SERVICE_PHASES')

    def number(value):
        require(type(value) is int and 0 <= value < 1 << 64, 'NATIVE_SERVICE_NUMBER')
        return value

    for index, phase in enumerate(phases):
        require(isinstance(phase, dict) and type(phase.get('phase')) is int
                and phase['phase'] == index, 'NATIVE_SERVICE_PHASES')
        for key in ('complete_denominators', 'attacker_and_client_cpu_known',
                    'no_attack_accepted', 'cpu_measurements_known',
                    'all_started_work_finished', 'full_native_state_equal', 'finite_target_met'):
            require(phase.get(key) is True, 'NATIVE_SERVICE_PHASE_TARGET')
        attacks, reads = phase.get('from_zero'), phase.get('honest_reads')
        require(isinstance(attacks, list) and isinstance(reads, list)
                and len(attacks) == len(reads) == number(phase.get('construction_count')) == 8,
                'NATIVE_SERVICE_DENOMINATORS')
        hits = exhausted = submitted = late = 0
        for row in attacks:
            require(isinstance(row, dict) and isinstance(row.get('construction'), dict),
                    'NATIVE_SERVICE_CONSTRUCTION')
            status = row['construction'].get('status')
            require(status in ('target_hit_unverified', 'exhausted'), 'NATIVE_SERVICE_CONSTRUCTION')
            number(row['construction'].get('attacker_cpu_ns'))
            require('call' in row, 'NATIVE_SERVICE_CONSTRUCTION')
            call = row['call']
            if status == 'exhausted':
                exhausted += 1
                require(call is None, 'NATIVE_SERVICE_EXHAUSTION_DISPATCH')
            else:
                hits += 1
                require(isinstance(call, dict) and call.get('status') != 'ok',
                        'NATIVE_SERVICE_ATTACK_ACCEPTED')
                number(call.get('client_thread_cpu_ns'))
                submitted += 1
                if call.get('status') == 'refused':
                    response = call.get('response')
                    require(isinstance(response, dict) and isinstance(response.get('value'), dict),
                            'NATIVE_SERVICE_RESPONSE')
                    late += response['value'].get('error') == 'WORK:Transcript'
        require((hits, exhausted, submitted, late) == tuple(number(phase.get(key)) for key in (
            'constructed_hits', 'exhausted_searches', 'submitted_attacks', 'late_transcript_rejections'))
                and late > 0, 'NATIVE_SERVICE_DENOMINATORS')
        for call in [*reads, phase.get('honest_submit')]:
            require(isinstance(call, dict) and call.get('status') == 'ok'
                    and call.get('returned_after_deadline') is False, 'NATIVE_SERVICE_HONEST_GAP')
            number(call.get('client_thread_cpu_ns'))
        require(number(phase.get('honest_read_successes')) == 8
                and phase.get('honest_build_error', 'missing') is None, 'NATIVE_SERVICE_HONEST_GAP')
        preparation = number(phase.get('all_preparation_thread_cpu_ns'))
        worker = number(phase.get('attacker_worker_cpu_ns'))
        require(number(phase.get('attacker_preparation_and_worker_cpu_ns')) == preparation + worker,
                'NATIVE_SERVICE_CPU_SUM')
        require('honest_build_aggregate_cpu_ns' in phase and phase['honest_build_aggregate_cpu_ns'] is None
                and phase.get('honest_worker_cpu_measured_by_this_clock') is False,
                'NATIVE_SERVICE_SCOPE_PROMOTION')
        service = phase.get('service')
        require(isinstance(service, dict) and service.get('error', 'missing') is None
                and isinstance(service.get('metrics'), dict), 'NATIVE_SERVICE_OUTCOME')
        metrics = service['metrics']
        started = number(metrics.get('work_started'))
        require(started > late and number(metrics.get('work_finished')) == started
                and number(metrics.get('work_failed')) >= late, 'NATIVE_SERVICE_UNJOINED_WORK')
        work_cpu = number(metrics.get('mutation_full_work_cpu_ns'))
        require(number(metrics.get('mutation_cpu_clock_failures')) == 0 and work_cpu > 0
                and number(metrics.get('mutation_cpu_charged_ns')) >= work_cpu,
                'NATIVE_SERVICE_CPU_SUM')
    return {'sha256': digest(raw), 'schema': doc['schema'], 'phases': len(phases),
            'scope': 'retained finite native report consistency; no independent work or state oracle'}


def save_manifest(out: Path, result: dict) -> None:
    temporary = out / 'manifest.json.next'
    with temporary.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, out / 'manifest.json')


def run(out: Path) -> dict:
    out = out.resolve()
    require(not out.is_relative_to(ROOT), 'OUTPUT_MUST_BE_OUTSIDE_CHECKOUT')
    identity = source_identity()
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'trnm-from-zero-native-execution-v1', 'source_before': identity,
              'source_after': None, 'source_recompiled': False, 'all_named_tests_passed': False,
              'format_passed': False, 'runs': [], 'failures': [],
              'independent_wan_accepted': False, 'work_hardness_accepted': False,
              'production_activation': False, 'passed': False, 'execution_finished': False,
              'service_report': None}
    previous_output = os.environ.get('TRNM_PUBLIC_V3_FROM_ZERO_DIR')
    previous_cwd = Path.cwd()
    save_manifest(out, result)  # An interrupted launch retains an incomplete, non-passing receipt.
    try:
        os.chdir(ROOT)
        os.environ['TRNM_PUBLIC_V3_FROM_ZERO_DIR'] = str(out / 'native')
        result['rustc'] = subprocess.check_output(['rustc', '-Vv'], text=True, timeout=30)
        result['cargo'] = subprocess.check_output(['cargo', '-V'], text=True, timeout=30).strip()
        result['build_env'] = {key: os.environ.get(key) for key in (
            'CARGO_BUILD_JOBS', 'CARGO_TARGET_DIR', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')}
        # A copy gives a reproducible formatting repair without changing checkout.
        shutil.copyfile(ROOT / SOURCE, out / 'formatted.rs')
        result['format_copy'] = run_child(
            ['rustfmt', '--edition', '2021', str(out / 'formatted.rs')], out / 'format-copy', 60)
        require(result['format_copy']['timed_out'] is False, 'NATIVE_TIMEOUT_STOPS_CAMPAIGN')
        result['format'] = run_child(
            ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'],
            out / 'format-check', 60)
        result['format_passed'] = result['format']['exit_code'] == 0 and not result['format']['timed_out']
        require(result['format']['timed_out'] is False, 'NATIVE_TIMEOUT_STOPS_CAMPAIGN')
        command = ['cargo', 'test', '--locked', '--release', '--manifest-path',
                   'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', TARGET,
                   '--no-run', '--message-format=json']
        result['build'] = run_child(command, out / 'build', 900)
        require(result['build']['exit_code'] == 0 and not result['build']['timed_out'], 'NATIVE_BUILD_FAILED')
        binary = select_binary((out / 'build/stdout').read_text().splitlines())
        require(binary.is_file() and not binary.is_symlink(), 'REGULAR_BINARY_REQUIRED')
        result['source_recompiled'] = True
        result['binary_sha256_before'] = digest(binary.read_bytes())
        shutil.copy2(binary, out / TARGET)
        for name in TESTS:
            folder = out / name
            observed = run_child([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], folder, 90)
            row = {'name': name, 'process': observed, 'passed': False,
                   'stdout_sha256': digest((folder / 'stdout').read_bytes()),
                   'stderr_sha256': digest((folder / 'stderr').read_bytes())}
            result['runs'].append(row)
            try:
                require(observed['exit_code'] == 0 and not observed['timed_out'], 'NATIVE_TEST_FAILED')
                row['named_execution'] = validate((folder / 'stdout').read_text().splitlines(), name)
                row['passed'] = True
            except (ValueError, OSError, UnicodeError) as error:
                row['failure'] = str(error)
                result['failures'].append(name + ': ' + str(error))
            print(json.dumps(row, sort_keys=True), flush=True)
            require(observed['timed_out'] is False, 'NATIVE_TIMEOUT_STOPS_CAMPAIGN')
        result['binary_sha256_after'] = digest(binary.read_bytes())
        require(result['binary_sha256_before'] == result['binary_sha256_after']
                == digest((out / TARGET).read_bytes()), 'NATIVE_BINARY_CHANGED')
        result['all_named_tests_passed'] = len(result['runs']) == len(TESTS) and all(r['passed'] for r in result['runs'])
        result['service_report'] = validate_service_report(out / 'native/report.json')
        result['execution_finished'] = True
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        result['failures'].append(str(error))
    finally:
        if previous_output is None:
            os.environ.pop('TRNM_PUBLIC_V3_FROM_ZERO_DIR', None)
        else:
            os.environ['TRNM_PUBLIC_V3_FROM_ZERO_DIR'] = previous_output
        try:
            result['source_after'] = source_identity()
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            result['failures'].append(str(error))
        try:
            for row in result['runs']:
                for channel in ('stdout', 'stderr'):
                    require(digest((out / row['name'] / channel).read_bytes()) == row[channel + '_sha256'],
                            'NATIVE_LOG_CHANGED')
            if result['service_report'] is not None:
                require(digest((out / 'native/report.json').read_bytes()) == result['service_report']['sha256'],
                        'NATIVE_SERVICE_REPORT_CHANGED')
            result['files'] = {p.relative_to(out).as_posix(): digest(p.read_bytes())
                               for p in sorted(out.rglob('*'))
                               if p.is_file() and p != out / 'manifest.json'}
        except (OSError, ValueError) as error:
            result['failures'].append(str(error))
        finally:
            os.chdir(previous_cwd)
        result['passed'] = (result['source_before'] == result['source_after']
                            and result['source_recompiled'] and result['format_passed']
                            and result['all_named_tests_passed'] and result['execution_finished']
                            and result['service_report'] is not None and not result['failures'])
        save_manifest(out, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    receipt = run(parser.parse_args().out)
    print(json.dumps({'passed': receipt['passed'], 'failures': receipt['failures']}))
    raise SystemExit(0 if receipt['passed'] else 1)
