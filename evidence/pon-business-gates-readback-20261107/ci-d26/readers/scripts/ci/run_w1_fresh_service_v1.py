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


def validate_negative_cache_observation(doc: dict, phases: list) -> dict | None:
    """Bind actual cache mode/path facts without calling an attempt fresh replay.

    Historical reports explicitly declared disabled and have no extension.
    Current mode is observed on every started relation attempt in both phases;
    an absent observation is unknown. All existing business gates still run.
    """
    records_by_phase = []
    for phase in phases:
        observed = phase.get('observations')
        require(type(observed) is dict and type(observed.get('records')) is list
                and len(observed['records']) <= 16384, 'FRESH_CACHE_RECORDS')
        require(all(type(row) is dict for row in observed['records']), 'FRESH_CACHE_RECORDS')
        records_by_phase.append(observed['records'])
    enabled = doc.get('negative_cache_enabled')
    if enabled is False:
        require('negative_cache_observation_source' not in doc
                and not any('work_rejection' in row for rows in records_by_phase for row in rows),
                'FRESH_CACHE_DISABLED_CONTRADICTION')
        return None
    require(enabled is True and doc.get('negative_cache_observation_source')
            == 'actual-request-work-rejection-observations-v1', 'FRESH_CACHE_MODE_UNKNOWN')

    boolean_fields = ('key_hashed', 'lookup_contended', 'lookup_poisoned',
                      'exact_fact_found', 'cached_rejection_returned',
                      'native_verifier_started', 'native_verifier_returned', 'full_replay_started')
    configuration = None
    summaries = []
    for phase, rows in zip(phases, records_by_phase):
        summary = {'mode': phase.get('mode'), 'relation_attempts': 0,
                   'completed_cache_observations': 0, 'incomplete_cache_observations': 0,
                   **{key: 0 for key in boolean_fields}}
        for row in rows:
            require(type(row.get('full_work_started')) is bool, 'FRESH_CACHE_ATTEMPT_COVERAGE')
            if not row['full_work_started']:
                require('work_rejection' not in row, 'FRESH_CACHE_WITHOUT_ATTEMPT')
                continue
            summary['relation_attempts'] += 1
            observed = row.get('work_rejection')
            require(type(observed) is dict and observed.get('schema')
                    == 'public-v3-work-rejection-observation-v1', 'FRESH_CACHE_ATTEMPT_COVERAGE')
            keys = ('slots', 'retained_software_bytes', 'lifetime_ms',
                    'lifetime_seconds', 'lifetime_subsec_nanos')
            require(all(type(observed.get(key)) is int for key in keys), 'FRESH_CACHE_CONFIGURATION')
            slots, retained, millis, seconds, nanos = (observed[key] for key in keys)
            require(0 < slots <= 256 and 0 < retained <= 32768
                    and 0 <= seconds <= 30 and 0 <= nanos < 1_000_000_000
                    and 0 < seconds * 1_000_000_000 + nanos <= 30_000_000_000
                    and millis == seconds * 1000 + nanos // 1_000_000,
                    'FRESH_CACHE_CONFIGURATION')
            current = {key: observed[key] for key in keys}
            if configuration is None:
                configuration = current
            require(configuration == current, 'FRESH_CACHE_CONFIGURATION_CHANGED')
            require(type(observed.get('completed')) is bool and 'cache' in observed,
                    'FRESH_CACHE_COMPLETION')
            require('full_work_accepted' in row and (row['full_work_accepted'] is None
                    or type(row['full_work_accepted']) is bool), 'FRESH_CACHE_ATTEMPT_OUTCOME')
            facts = observed['cache']
            if not observed['completed']:
                require(facts is None, 'FRESH_CACHE_COMPLETION')
                summary['incomplete_cache_observations'] += 1
                continue
            require(type(facts) is dict and all(type(facts.get(key)) is bool for key in boolean_fields)
                    and facts.get('publication') in ('none', 'retained', 'contended', 'poisoned'),
                    'FRESH_CACHE_FACTS')
            require(not (facts['lookup_contended'] and facts['lookup_poisoned'])
                    and (facts['key_hashed'] or not any(facts[key] for key in (
                        'lookup_contended', 'lookup_poisoned', 'exact_fact_found', 'cached_rejection_returned')))
                    and (not facts['cached_rejection_returned'] or facts['exact_fact_found'])
                    and (not facts['full_replay_started'] or (
                        facts['key_hashed'] and facts['native_verifier_started']))
                    and (not facts['key_hashed'] or facts['exact_fact_found']
                         or facts['native_verifier_started'])
                    and facts['native_verifier_started'] == facts['native_verifier_returned'],
                    'FRESH_CACHE_PATH_CONTRADICTION')
            if facts['exact_fact_found']:
                require(not any(facts[key] for key in (
                    'lookup_contended', 'lookup_poisoned', 'native_verifier_started',
                    'native_verifier_returned', 'full_replay_started'))
                    and facts['publication'] == 'none', 'FRESH_CACHE_PATH_CONTRADICTION')
            if facts['publication'] != 'none':
                require(facts['key_hashed'] and facts['native_verifier_returned']
                        and facts['full_replay_started'] and not facts['exact_fact_found']
                        and row.get('full_work_accepted') is False, 'FRESH_CACHE_PUBLICATION')
            if row.get('full_work_accepted') is True:
                require(facts['native_verifier_returned'] and facts['full_replay_started']
                        and not facts['exact_fact_found'] and facts['publication'] == 'none',
                        'FRESH_CACHE_ACCEPTANCE')
            # The fresh namespace uses unique complete false statements and an
            # empty receiver owner per phase. A cache hit cannot count as one of
            # its fresh native transcript rejections, even after cancellation.
            require(not facts['exact_fact_found'] and not facts['cached_rejection_returned'],
                    'FRESH_CACHE_REUSED_FACT')
            summary['completed_cache_observations'] += 1
            for key in boolean_fields:
                summary[key] += int(facts[key])
        require(summary['relation_attempts'] > 0, 'FRESH_CACHE_NO_OBSERVED_ATTEMPTS')
        summaries.append(summary)
    return {'schema': 'public-v3-fresh-negative-cache-readback-v1', 'enabled': True,
            'configuration': configuration, 'phases': summaries,
            'scope': 'actual relation-attempt path observations; native verifier entry is not '
                     'full replay, started replay is not completion; path counters cover only '
                     'completed observations, incomplete paths remain unknown; CPU remains nested'}


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
        'public_network_ready', 'work_profile_qualified',
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
    cache = validate_negative_cache_observation(doc, phases)
    result = {'schema': FRESH_SCHEMA, 'sha256': native.digest(raw), 'finite_target_met': True,
              'unique_challenges': len(challenges), 'submitted': submitted,
              'phases': phase_checks,
              'scope': 'bounded report consistency, not an independent State/work or fairness proof'}
    if cache is not None:
        result['negative_cache_observation'] = cache
    return result


def validate_execution(process: dict, log: Path, selector: str, report: Path) -> dict:
    require(selector in SELECTORS, 'FRESH_EXACT_SELECTOR_REQUIRED')
    require(process.get('executed') is True and process.get('exit_code') == 0
            and process.get('process_exit_code') == 0 and process.get('timed_out') is False
            and process.get('source_verified') is True, 'FRESH_NATIVE_PROCESS_REQUIRED')
    named = validate(log.read_text().splitlines(), selector)
    read = (native.validate_confirmation_report(report) if selector == ORIGINAL
            else validate_fresh_report(report))
    return {'named_execution': named, 'report': read}


def failure_diagnostic(process: dict, selector: str, report: Path) -> dict:
    """Bounded, untrusted metadata only; never an alternative acceptance path.

    Preserve the actual child return code, not a wrapper's effective exit code.
    Copy no proof/request fields and do not reconstruct or validate work. The
    final pressure phase owns the last replay; missing pressure observations
    cannot fall back to a successful baseline or an earlier well-shaped row.
    """
    returned = process.get('process_exit_code')
    result = {'schema': 'trnm-w1-fresh-failure-diagnostic-v1',
              'native_returncode': returned if type(returned) is int
              and -(1 << 31) <= returned < 1 << 31 else 'unknown',
              'finite_target_met': 'unknown', 'last_history_replay': 'unknown',
              'acceptance_authority': False}
    expected_schema = ('public-v3-signed-confirmation-pressure-v1' if selector == ORIGINAL
                       else FRESH_SCHEMA if selector == FRESH else None)
    try:
        doc, _ = load_report(report)  # Existing regular-file, byte and JSON bounds.
        if expected_schema is None or doc.get('schema') != expected_schema:
            return result
        finite = doc.get('finite_target_met')
        if type(finite) is bool:
            result['finite_target_met'] = finite
        phases = doc.get('phases')
        if (type(phases) is not list or len(phases) != 2
                or any(type(phase) is not dict for phase in phases)
                or [phase.get('mode') for phase in phases]
                != ['attack-free-baseline', 'from-zero-pressure']):
            return result
        replays = phases[-1].get('independent_history_page_replay')
        if type(replays) is not list or not 1 <= len(replays) <= 16:
            return result
        previous = -1
        last = None
        for row in replays:
            if type(row) is not dict:
                return result
            index, accepted, error = (row.get('history_call_index'),
                                      row.get('replay_accepted'), row.get('replay_error'))
            if (type(index) is not int or not previous < index < 16
                    or type(accepted) is not bool or 'replay_error' not in row):
                return result
            # Only short native error identifiers can enter the manifest. An
            # arbitrary error message might contain an encoded request/proof.
            if (accepted and error is not None) or (not accepted and (
                    type(error) is not str or len(error) > 96
                    or re.fullmatch(r'(?:PUBLIC|HISTORY|HOST|WORK)_[A-Z0-9_]+', error) is None)):
                return result
            previous = index
            last = {'phase': 'from-zero-pressure', 'history_call_index': index,
                    'replay_accepted': accepted, 'replay_error': error}
        result['last_history_replay'] = last
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        # Optional diagnosis cannot replace the failure already recorded by
        # validate_execution, including missing or malformed report bytes.
        pass
    return result


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
                row['failure_diagnostic'] = failure_diagnostic(process, selector, report)
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
