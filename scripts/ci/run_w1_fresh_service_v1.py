#!/usr/bin/env python3
"""Retain both original and fresh-challenge 4s/16-worker native outcomes.

This explicit successor is run by the same fixed Host owner as the original
runner. A failed original observation never prevents collection of the fresh
one, and neither a zero-test exit nor diagnostic booleans grant acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
import ci_observation as ci
import run_from_zero_native as native
from check_required_native_test import validate

SCHEMA = 'trnm-w1-fresh-service-execution-v1'
FRESH_SCHEMA = 'public-v3-fresh-challenge-confirmation-pressure-v1'
ORIGINAL = native.TESTS[-1]
FRESH = 'fresh_challenge::fresh_challenge_signed_confirmation_keeps_original_pressure_budget'
SELECTORS = (ORIGINAL, FRESH)
TEST_TIMEOUT_SECONDS = 90  # Same outer bound as the original named-test owner.


def require(value, message):
    if not value:
        raise ValueError(message)


def expected_source(actual: str) -> str:
    """Bind hosted execution to the immutable source selected by the workflow."""
    expected = os.environ.get('TRNM_EXPECTED_SOURCE_SHA')
    if os.environ.get('GITHUB_ACTIONS') == 'true' or expected is not None:
        require(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected) is not None,
                'FRESH_EXPECTED_SOURCE_REQUIRED')
        require(actual == expected, 'FRESH_EXPECTED_SOURCE_MISMATCH')
        return expected
    # Local synthetic/control use has no hosted acceptance authority.
    return actual


def load_report(path: Path) -> tuple[dict, bytes]:
    require(path.is_file() and not path.is_symlink(), 'FRESH_REPORT_REQUIRED')
    with path.open('rb') as stream:
        raw = stream.read(native.REPORT_LIMIT + 1)
    require(len(raw) <= native.REPORT_LIMIT, 'FRESH_REPORT_LIMIT')
    doc = native.json_load(raw)
    require(type(doc) is dict, 'FRESH_REPORT_OBJECT')
    return doc, raw


def validate_fresh_report(path: Path) -> dict:
    """Bounded consistency only; native verification owns proof and State truth."""
    doc, raw = load_report(path)

    def number(value):
        require(type(value) is int and 0 <= value < 1 << 64, 'FRESH_NUMBER')
        return value

    def hex_value(value, width):
        require(type(value) is str and len(value) == 2 * width
                and all(c in '0123456789abcdef' for c in value), 'FRESH_HEX')
        return bytes.fromhex(value)

    require(doc.get('schema') == FRESH_SCHEMA, 'FRESH_SCHEMA')
    require(doc.get('requested_window_ns') == 4_000_000_000
            and doc.get('attack_workers') == 16
            and doc.get('per_worker_attempt_cap') == 1024, 'FRESH_ORIGINAL_BUDGET')
    require(doc.get('finite_target_met') is True
            and doc.get('same_signed_business_packets') is True, 'FRESH_BUSINESS_TARGET')
    require(all(doc.get(key) is False for key in (
        'negative_cache_enabled', 'public_network_ready', 'work_profile_qualified',
        'resource_fairness_qualified', 'production_activation')), 'FRESH_SCOPE_PROMOTION')
    context = {key: hex_value(doc.get(key), 32) for key in (
        'network', 'parameters', 'genesis', 'target', 'task', 'policy_id')}
    require(context['target'] != bytes(32), 'FRESH_TARGET')
    packets = doc.get('signed_honest_packets')
    require(type(packets) is list and len(packets) == 7, 'FRESH_SIGNED_BUSINESS')
    metadata = [native.ConfirmationReportChecks.packet_metadata(packet) for packet in packets]
    parent = context['genesis']
    for height, (header, transactions, block_id) in enumerate(metadata, 1):
        require(all(header[key] == context[key] for key in ('network', 'parameters', 'target'))
                and header['parent'] == parent and header['height'] == height
                and header['work_task'] == context['task']
                and len(transactions) == (1 if height == 1 else 0), 'FRESH_BUSINESS_CHAIN')
        parent = block_id
    phases = doc.get('phases')
    require(type(phases) is list and len(phases) == 2
            and all(type(phase) is dict for phase in phases), 'FRESH_PHASES')

    # Rebuild the finite native maintenance task and every false packet. This
    # authenticates neither PoN nor producer CPU; it catches accidental replay,
    # omitted attempts and a report relabelled from the retained-packet stream.
    a = b''.join(struct.pack('<I', i % 31) for i in range(4096))
    b = b''.join(struct.pack('<I', (i * 7) % 37) for i in range(4096))
    task = native.H('task', a, b)
    require(task == context['task'], 'FRESH_MAINTENANCE_TASK')
    workers = phases[1].get('attacks')
    require(type(workers) is list and len(workers) == 16, 'FRESH_WORKERS')
    require(phases[0].get('attacks') == [], 'FRESH_BASELINE_ATTACKS')
    challenges, indices = set(), set()
    nested_cpu = worker_cpu = submitted = exhausted = transcript_rejections = 0
    for worker_index, worker in enumerate(workers):
        require(type(worker) is dict and worker.get('worker') == worker_index, 'FRESH_WORKER_INDEX')
        actual_worker_cpu = number(worker.get('calling_thread_cpu_ns'))
        worker_cpu += actual_worker_cpu
        worker_nested_cpu = 0
        worker_call_cpu = 0
        calls = worker.get('calls')
        require(type(calls) is list and len(calls) < 1024, 'FRESH_CALLS')
        require(worker.get('attempt_cap_reached') is False, 'FRESH_ATTEMPT_CAP')
        for attempt_index, row in enumerate(calls):
            require(type(row) is dict, 'FRESH_CALL')
            index = number(row.get('packet_index'))
            require(index == attempt_index * 16 + worker_index and index not in indices,
                    'FRESH_UNIQUE_INDEX')
            indices.add(index)
            construction = row.get('from_zero_construction')
            require(type(construction) is dict, 'FRESH_CONSTRUCTION')
            header_bytes = hex_value(construction.get('header'), 318)
            header = native.header_decode(header_bytes)
            challenge = native.H('challenge', header_bytes)
            require(challenge not in challenges
                    and hex_value(construction.get('challenge'), 32) == challenge,
                    'FRESH_UNIQUE_CHALLENGE')
            challenges.add(challenge)
            require(all(header[key] == context[key] for key in ('network', 'parameters', 'target'))
                    and header['parent'] == context['genesis'] and header['height'] == 1
                    and header['nonce'] == 200_000 + index and header['work_task'] == task,
                    'FRESH_HEADER_BINDING')
            require(construction.get('attempt_budget') == 4096 and construction.get('setup_calls') == 1,
                    'FRESH_SEARCH_BUDGET')
            disjoint_cpu = sum(number(construction.get(key)) for key in (
                'setup_cpu_ns', 'search_cpu_ns', 'packet_encoding_cpu_ns'))
            construction_cpu = number(construction.get('attacker_cpu_ns'))
            require(disjoint_cpu <= construction_cpu, 'FRESH_CONSTRUCTION_CPU_CONTAINMENT')
            worker_nested_cpu += construction_cpu
            nested_cpu += construction_cpu
            trials = construction.get('attempts')
            require(type(trials) is list and 0 < len(trials) <= 4096, 'FRESH_TRIALS')
            for ordinal, trial in enumerate(trials):
                require(type(trial) is dict, 'FRESH_TRIAL')
                trace = native.H('public-v3-from-zero-v1', challenge, struct.pack('<Q', ordinal))
                ticket = native.H('ticket', challenge, trace)
                hit = ticket <= context['target']
                require(trial.get('nonce') == ordinal
                        and hex_value(trial.get('trace'), 32) == trace
                        and hex_value(trial.get('ticket'), 32) == ticket
                        and trial.get('target_hit') is hit
                        and (not hit or ordinal == len(trials) - 1), 'FRESH_TRIAL_ACCOUNTING')
            if trials[-1]['target_hit']:
                submitted += 1
                worker_call_cpu += number(row.get('client_thread_cpu_ns'))
                require(construction.get('status') == 'target_hit_unverified'
                        and construction.get('winner_nonce') == len(trials) - 1
                        and row.get('status') in ('refused', 'error'), 'FRESH_INVALID_ACCEPTED')
                response = row.get('response')
                if (row['status'] == 'refused' and type(response) is dict
                        and type(response.get('value')) is dict
                        and response['value'].get('error') == 'WORK:Transcript'):
                    transcript_rejections += 1
                packet = header_bytes + bytes(2) + b'PNW1' + a + b + bytes(16384) + trace
                require(hex_value(construction.get('packet_digest'), 32)
                        == native.H('fresh-challenge-attack-packet-v1', packet), 'FRESH_PACKET_DIGEST')
                request = json.dumps({'op': 'submit', 'packet': packet.hex()},
                                     sort_keys=True, separators=(',', ':')).encode()
                require(row.get('recorded_request_bytes') == len(request)
                        and hex_value(row.get('recorded_request_digest'), 32)
                        == native.H('pressure-recorded-request-v1', request), 'FRESH_REQUEST_BINDING')
            else:
                exhausted += 1
                require(len(trials) == 4096 and construction.get('status') == 'exhausted'
                        and construction.get('winner_nonce', 'missing') is None
                        and construction.get('packet_digest', 'missing') is None
                        and row.get('status') == 'not_submitted_exhausted', 'FRESH_EXHAUSTED')
        # Construction finishes before client.call_before starts. These are
        # disjoint intervals in this same joined worker, not two global totals.
        require(worker_nested_cpu + worker_call_cpu <= actual_worker_cpu,
                'FRESH_WORKER_CPU_CONTAINMENT')
    require(submitted > 0 and transcript_rejections > 0
            and len(challenges) == len(indices), 'FRESH_NO_COMPLETE_TRANSCRIPT_REJECTION')
    coverage = doc.get('construction_coverage')
    require(type(coverage) is dict
            and all(coverage.get(key) == len(indices) for key in (
                'constructed', 'unique_challenges', 'unique_packet_indices'))
            and coverage.get('submitted') == submitted and coverage.get('exhausted') == exhausted
            and coverage.get('full_transcript_rejections') == transcript_rejections
            and coverage.get('all_context_bindings_and_challenges_unique') is True
            and coverage.get('all_nested_cpu_measurements_known') is True
            and coverage.get('nested_from_zero_construction_cpu_ns') == nested_cpu,
            'FRESH_COVERAGE')
    require(phases[1].get('attacker_workers_cpu_ns') == worker_cpu
            and nested_cpu <= worker_cpu
            and doc.get('attacker_setup_and_workers_cpu_ns')
            == number(doc.get('shared_material_setup_cpu_ns')) + worker_cpu, 'FRESH_CPU_SUM')

    def resolve_attack(worker_index, attempt_index, row):
        index = number(row.get('packet_index'))
        require(index == attempt_index * 16 + worker_index, 'FRESH_UNIQUE_INDEX')
        construction = row['from_zero_construction']
        resolved = {'status': construction['status']}
        if construction['status'] == 'target_hit_unverified':
            # Reconstruct on demand instead of retaining an expanded packet for
            # every bounded record. No second unbounded packet table is created.
            resolved['packet'] = (
                bytes.fromhex(construction['header']) + bytes(2) + b'PNW1' + a + b
                + bytes(16384) + bytes.fromhex(construction['attempts'][-1]['trace'])
            ).hex()
        return resolved, index

    phase_checks = native.validate_confirmation_phases(doc, context, packets, metadata, resolve_attack)
    return {'schema': FRESH_SCHEMA, 'sha256': native.digest(raw), 'finite_target_met': True,
            'unique_challenges': len(challenges), 'submitted': submitted,
            'phases': phase_checks,
            'scope': 'bounded report consistency, not an independent State/work or fairness proof'}


def validate_execution(process: dict, log: Path, selector: str, report: Path) -> dict:
    require(selector in SELECTORS, 'FRESH_EXACT_SELECTOR_REQUIRED')
    require(process.get('executed') is True and process.get('exit_code') == 0
            and process.get('process_exit_code') == 0 and process.get('timed_out') is False
            and process.get('source_verified') is True, 'FRESH_NATIVE_PROCESS_REQUIRED')
    named = validate(log.read_text().splitlines(), selector)
    read = (native.validate_confirmation_report(report) if selector == ORIGINAL
            else validate_fresh_report(report))
    return {'named_execution': named, 'report': read}


def run(out: Path) -> dict:
    require(out.is_absolute() and out.resolve() == out and not out.is_relative_to(ci.ROOT),
            'OUTPUT_MUST_BE_CANONICAL_OUTSIDE_CHECKOUT')
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': SCHEMA, 'source_before': None, 'source_after': None,
              'source_expected': None,
              'source_recompiled': False, 'all_named_tests_passed': False,
              'runs': [], 'failures': [], 'passed': False, 'execution_finished': False,
              'requested_window_ns': 4_000_000_000, 'attack_workers': 16,
              'independent_wan_accepted': False, 'work_hardness_accepted': False,
              'production_activation': False}
    native.save_manifest(out, result)
    binary = None
    try:
        result['source_before'] = native.source_identity()
        expected = expected_source(result['source_before']['commit'])
        result['source_expected'] = expected
        result['build'] = ci.run(native.native_build_command(), out / 'build.log',
                                 timeout=900, expected_source=expected)
        require(result['build']['exit_code'] == 0 and not result['build']['timed_out']
                and result['build']['source_verified'] is True, 'FRESH_SOURCE_BUILD_FAILED')
        binary = native.select_binary((out / 'build.log').read_text().splitlines())
        result['binary_sha256_before'] = ci.digest(binary)
        shutil.copy2(binary, out / native.TARGET)
        result['source_recompiled'] = True
        for index, selector in enumerate(SELECTORS):
            folder = 'original' if index == 0 else 'fresh'
            log = out / (folder + '.log')
            report = out / folder / 'report.json'
            environment = dict(os.environ)
            environment['TRNM_PUBLIC_V3_CONFIRMATION_DIR' if index == 0
                        else 'TRNM_PUBLIC_V3_FRESH_CONFIRMATION_DIR'] = str(report.parent)
            command = [str(binary), selector, '--exact', '--nocapture', '--test-threads=1']
            if index:
                command.append('--ignored')
            process = ci.run(command, log, timeout=TEST_TIMEOUT_SECONDS,
                             env=environment, expected_source=expected)
            row = {'name': selector, 'process': process, 'passed': False,
                   'log_sha256': ci.digest(log), 'report_path': str(report.relative_to(out))}
            result['runs'].append(row)
            try:
                row.update(validate_execution(process, log, selector, report))
                row['passed'] = True
            except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
                row['failure'] = str(error)
                result['failures'].append(selector + ': ' + str(error))
            native.save_manifest(out, result)
        result['execution_finished'] = True
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        result['failures'].append(str(error))
    finally:
        try:
            result['source_after'] = native.source_identity()
            require(expected_source(result['source_after']['commit']) == result['source_expected'],
                    'FRESH_EXPECTED_SOURCE_CHANGED')
            if binary is not None:
                result['binary_sha256_after'] = ci.digest(binary)
                require(result['binary_sha256_after'] == result['binary_sha256_before']
                        == ci.digest(out / native.TARGET), 'FRESH_BINARY_CHANGED')
            for row in result['runs']:
                log = out / ('original.log' if row['name'] == ORIGINAL else 'fresh.log')
                require(ci.digest(log) == row['log_sha256'], 'FRESH_LOG_CHANGED')
                if row.get('report') is not None:
                    require(ci.digest(out / row['report_path']) == row['report']['sha256'],
                            'FRESH_REPORT_CHANGED')
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            result['failures'].append(str(error))
        result['all_named_tests_passed'] = (
            [row['name'] for row in result['runs']] == list(SELECTORS)
            and all(row['passed'] for row in result['runs']))
        result['passed'] = (result['source_before'] is not None
                            and result['source_before'] == result['source_after']
                            and result['source_recompiled'] and result['execution_finished']
                            and result['all_named_tests_passed'] and not result['failures'])
        result['files'] = {str(path.relative_to(out)): ci.digest(path)
                           for path in sorted(out.rglob('*'))
                           if path.is_file() and path != out / 'manifest.json'}
        native.save_manifest(out, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    receipt = run(parser.parse_args().out)
    print(json.dumps({'passed': receipt['passed'], 'failures': receipt['failures']}))
    raise SystemExit(0 if receipt['passed'] else 1)
