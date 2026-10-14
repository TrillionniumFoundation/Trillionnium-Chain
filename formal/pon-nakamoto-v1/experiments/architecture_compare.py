"""Source-bound native dissemination comparison; no DAG/BFT consensus qualification.

The experiment measures cold native work/application acquisition, actual signed
TCP material and public admission, independent depth/work confirmation and reopen.
The comparison is delivery under the SAME PoN rules, never cross-protocol TPS.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from check_required_native_test import validate as validate_test
from replay_pinned_native import digest, json_load, require, run_child
from verify_ci_source import verify as verify_source
from run_from_zero_native import save_manifest

TARGET = 'architecture_delivery_compare'
SELECTORS = (
    'reference_dag_rejects_withheld_body_equivocation_and_changed_signed_history',
    'signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract',
)
MODES = ('serial-signed-batches', 'concurrent-proposer-batches', 'signed-reference-dag')
REPORT_LIMIT = 32 * 1024 * 1024


def identity():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    return verify_source('head', head, root=ROOT)


def validate_report(path):
    """Bounded observation consistency, not a second consensus/state oracle."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'ARCHITECTURE_REPORT_REQUIRED')
    with path.open('rb') as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    require(len(raw) <= REPORT_LIMIT, 'ARCHITECTURE_REPORT_LIMIT')
    report = json_load(raw)
    require(report.get('schema') == 'native-signed-dag-delivery-comparison-v1', 'ARCHITECTURE_SCHEMA')
    for flag in ('same_signed_packets_across_modes_and_repetitions', 'balanced_cyclic_mode_order',
                 'all_finite_business_targets_met'):
        require(report.get(flag) is True, 'ARCHITECTURE_FINITE_TARGET')
    for flag in ('architecture_winner_declared', 'protocol_switch_qualified',
                 'independent_accepted', 'wan_tested', 'production_activation'):
        require(report.get(flag) is False, 'ARCHITECTURE_SCOPE_PROMOTION')
    require(report.get('samples_per_workload_and_mode') == 3, 'ARCHITECTURE_DENOMINATORS')
    require(len(report.get('workloads', [])) == 2 and len(report.get('samples', [])) == 18,
            'ARCHITECTURE_DENOMINATORS')
    workloads = {row['scenario']: row for row in report['workloads']}
    require(set(workloads) == {'disjoint-recipients', 'hot-recipient'}, 'ARCHITECTURE_WORKLOADS')

    def number(value):
        require(type(value) is int and 0 <= value < 1 << 64, 'ARCHITECTURE_NUMBER')
        return value

    seen = set()
    for row in report['samples']:
        scenario, mode = row.get('scenario'), row.get('mode')
        sample, position = number(row.get('sample')), number(row.get('position'))
        require(scenario in workloads and mode in MODES and sample < 3 and position < 3
                and mode == MODES[(sample + position) % 3], 'ARCHITECTURE_BALANCED_ORDER')
        key = (scenario, sample, position)
        require(key not in seen, 'ARCHITECTURE_DUPLICATE_SAMPLE')
        seen.add(key)
        for flag in ('finite_business_target_met', 'native_state_equal', 'cold_reopen_equal'):
            require(row.get(flag) is True, 'ARCHITECTURE_FINITE_TARGET')
        for flag in ('dag_consensus_implemented', 'committee_bft_implemented', 'ghast_implemented',
                     'quorum_data_availability_qualified', 'wan_tested', 'independent_operators',
                     'work_profile_qualified', 'production_activation'):
            require(row.get(flag) is False, 'ARCHITECTURE_SCOPE_PROMOTION')
        require(row.get('consensus_profile') == 'unchanged-pon-nakamoto-v1'
                and row.get('errors') == [], 'ARCHITECTURE_NATIVE_ERRORS')
        require(number(row.get('signed_transaction_count')) == number(row.get('confirmed_transactions')) == 32,
                'ARCHITECTURE_BUSINESS_DENOMINATOR')
        require(number(row.get('whole_trial_wall_ns_including_cold_reopen')) >= number(row.get('full_business_latency_ns')) > 0,
                'ARCHITECTURE_FULL_COST')
        number(row.get('whole_trial_process_cpu_ns'))
        require(number(row.get('cold_proof_acquisition_wall_ns')) > 0
                and number(row.get('cold_proof_acquisition_process_cpu_ns')) > 0
                and number(row.get('work_attempts_including_target_misses')) >= 7, 'ARCHITECTURE_FULL_COST')
        acquisition = workloads[scenario]
        require(row['work_attempts_including_target_misses'] == acquisition['work_attempts_including_target_misses'],
                'ARCHITECTURE_SAME_WORK')
        material = row.get('dissemination')
        require(isinstance(material, dict) and material.get('signed_cells') == 8
                and material.get('durable_copy_count') == 1
                and material.get('quorum_availability_certified') is False
                and material.get('physical_network_bytes', 'missing') is None,
                'ARCHITECTURE_AVAILABILITY_SCOPE')
        number(material.get('application_frame_bytes'))
        number(material.get('wall_ns'))
        require(len(row.get('pool_calls', [])) == 8 and len(row.get('block_submissions', [])) == 7
                and 1 <= len(row.get('history_calls', [])) <= 16, 'ARCHITECTURE_NATIVE_CALLS')
        for request in row['pool_calls'] + row['block_submissions'] + row['history_calls']:
            require(request.get('ok') is True and request.get('error', 'missing') is None
                    and request.get('reply', {}).get('ok') is True, 'ARCHITECTURE_NATIVE_ERRORS')
            number(request.get('wall_ns'))
        confirmations = row.get('independent_confirmations')
        require(isinstance(confirmations, list) and len(confirmations) == 32, 'ARCHITECTURE_CONFIRMATION')
        for confirmation in confirmations:
            require(confirmation.get('confirmed') is True and confirmation.get('depth') == 6
                    and confirmation.get('included_height') == 1 and confirmation.get('observed_height') == 7
                    and confirmation.get('finalized') is False and confirmation.get('execution_authority') is False
                    and confirmation.get('reorged') is False,
                    'ARCHITECTURE_CONFIRMATION')
        service = row.get('service')
        require(isinstance(service, dict) and number(service.get('work_started')) == number(service.get('work_finished')) == 7
                and number(service.get('work_failed')) == 0
                and number(service.get('mutation_cpu_clock_failures')) == 0,
                'ARCHITECTURE_WORK_CLOSURE')
        require(number(service.get('mutation_cpu_charged_ns')) == number(service.get('mutation_full_work_cpu_ns'))
                + number(service.get('mutation_dispatch_excluding_work_cpu_ns')), 'ARCHITECTURE_CPU_SUM')
    summaries = []
    for scenario in sorted(workloads):
        for mode in MODES:
            selected = [row for row in report['samples'] if row['scenario'] == scenario and row['mode'] == mode]
            latencies = [row['full_business_latency_ns'] for row in selected]
            require(len(selected) == 3, 'ARCHITECTURE_DENOMINATORS')
            summaries.append(dict(scenario=scenario, mode=mode, samples=3,
                latency_median_ns=statistics.median(latencies), latency_max_ns=max(latencies),
                cold_proof_acquisition_wall_median_ns=statistics.median(row['cold_proof_acquisition_wall_ns'] for row in selected),
                dissemination_wall_median_ns=statistics.median(row['dissemination']['wall_ns'] for row in selected),
                whole_trial_wall_including_reopen_median_ns=statistics.median(row['whole_trial_wall_ns_including_cold_reopen'] for row in selected),
                whole_process_cpu_median_ns=statistics.median(row['whole_trial_process_cpu_ns'] for row in selected),
                service_full_work_cpu_median_ns=statistics.median(row['service']['mutation_full_work_cpu_ns'] for row in selected),
                observed_cold_burst_completion_rate_per_second=32_000_000_000/statistics.median(latencies),
                saturated_confirmed_tps=None, cross_protocol_risk_equivalence_qualified=False))
    return dict(sha256=digest(raw), schema=report['schema'], finite_target_met=True, summary=summaries,
        source_identity_qualified=False,
        scope='bounded native report consistency; clean source identity is established only by the complete execution owner, never --report alone; no GHAST/DAG-BFT implementation, saturated WAN TPS or security equivalence')


def run(out):
    out = Path(out).resolve()
    require(not out.is_relative_to(ROOT), 'OUTPUT_MUST_BE_OUTSIDE_CHECKOUT')
    source = identity()
    out.mkdir(parents=True, exist_ok=False)
    result = dict(schema='native-architecture-delivery-execution-v1', source_before=source, source_after=None,
                  runs=[], report=None, failures=[], passed=False, production_activation=False)
    save_manifest(out, result)
    old = os.environ.get('TRNM_ARCHITECTURE_COMPARE_DIR')
    previous = Path.cwd()
    try:
        os.chdir(ROOT)
        os.environ['TRNM_ARCHITECTURE_COMPARE_DIR'] = str(out/'native')
        command = ['cargo', 'test', '--locked', '--release', '--manifest-path', 'trillionnium/Cargo.toml',
                   '-p', 'trnm-pon-node', '--test', TARGET, '--no-run', '--message-format=json']
        result['build'] = run_child(command, out/'build', 900)
        require(result['build']['exit_code'] == 0 and not result['build']['timed_out'], 'ARCHITECTURE_BUILD_FAILED')
        binaries = []
        for line in (out/'build/stdout').read_text().splitlines():
            if line.startswith('{'):
                value = json_load(line)
                if value.get('reason') == 'compiler-artifact' and value.get('target', {}).get('name') == TARGET \
                        and value.get('profile', {}).get('test') is True and value.get('executable'):
                    binaries.append(Path(value['executable']))
        require(len(binaries) == 1 and binaries[0].is_file() and not binaries[0].is_symlink(), 'ARCHITECTURE_NEW_BINARY_REQUIRED')
        binary = binaries[0].resolve()
        result['binary_sha256'] = digest(binary.read_bytes())
        for selector in SELECTORS:
            process = run_child([str(binary), selector, '--exact', '--nocapture', '--test-threads=1'], out/selector, 120)
            result['runs'].append(dict(selector=selector, process=process))
            require(process['exit_code'] == 0 and not process['timed_out'], 'ARCHITECTURE_NATIVE_TEST_FAILED')
            validate_test((out/selector/'stdout').read_text().splitlines(), selector)
        result['report'] = validate_report(out/'native/report.json')
        require(digest(binary.read_bytes()) == result['binary_sha256'], 'ARCHITECTURE_BINARY_CHANGED')
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        result['failures'].append(str(error))
    finally:
        if old is None: os.environ.pop('TRNM_ARCHITECTURE_COMPARE_DIR', None)
        else: os.environ['TRNM_ARCHITECTURE_COMPARE_DIR'] = old
        os.chdir(previous)
        try:
            result['source_after'] = identity()
            if result['report'] is not None:
                require(digest((out/'native/report.json').read_bytes()) == result['report']['sha256'], 'ARCHITECTURE_REPORT_CHANGED')
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            result['failures'].append(str(error))
        result['passed'] = result['report'] is not None and source == result['source_after'] and not result['failures']
        result['source_identity_qualified'] = result['passed']
        result['files'] = {path.relative_to(out).as_posix(): digest(path.read_bytes()) for path in sorted(out.rglob('*'))
                           if path.is_file() and path != out/'manifest.json'}
        save_manifest(out, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.report is not None:
        require(args.out is None, 'EXACTLY_ONE_MODE_REQUIRED')
        receipt = validate_report(args.report)
    else:
        require(args.out is not None, 'EXACTLY_ONE_MODE_REQUIRED')
        receipt = run(args.out)
    print(json.dumps(receipt, indent=2))
    raise SystemExit(0 if receipt.get('passed', receipt.get('finite_target_met', False)) is True else 2)
