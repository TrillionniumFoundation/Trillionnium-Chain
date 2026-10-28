#!/usr/bin/env python3
"""Verify retained actual process artifacts, including the newly closed epoch cut."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    tests = read(HERE / 'tests-receipt.json')
    build = read(HERE / 'build-receipt.json')
    assert build['passed'] and tests['source_stable'] and tests['binary_stable']
    case = HERE / 'native-03/artifacts/settled-epoch'
    result = read(case / 'process-result.json')
    guardian = result['guardian']
    reconciled = result['reconciliation']
    final = result['finished']
    closed = guardian['closed_process']
    barrier = read(case / 'crash-control/crash-ready.json')
    assert result['binary_sha256'] == build['binary_sha256'] == tests['binary_sha256']
    assert guardian['passed'] and guardian['actual_wait4'] and guardian['wait_status'] == 9
    assert closed['actual_wait4'] and closed['signal'] == 9
    assert closed['original_journal'] == barrier['anchor']
    assert closed['epoch'] == barrier['epoch']
    assert closed['intent_sha256'] == barrier['intent_sha256']
    assert barrier['pending_operation'] is None
    original = barrier['original_settlement']
    assert original['operation_closed'] and original['accounting_record_persisted']
    assert original['native_error'] is None
    assert not original['cpu']['accounting_unavailable']
    assert reconciled['original_settlements_preserved']
    assert not reconciled['clean_close_fabricated']
    assert not reconciled['exact_residual_cpu_claimed']
    assert not reconciled['native_effect_repeated']
    assert not reconciled['new_cpu_epoch_created']
    assert reconciled['additional_conservative_debit']['cpu_ns'] == 4_000_000_000
    assert closed['reported_cpu_upper_bound_ns'] <= 4_000_000_000
    assert closed['reported_cpu_upper_bound_ns'] == (closed['user_cpu_microseconds'] + closed['system_cpu_microseconds'] + 2) * 1000
    assert reconciled['prior_journal']['spent']['cpu_ns'] == 12_000_000_000
    assert reconciled['journal']['spent']['cpu_ns'] == 16_000_000_000
    assert reconciled['prior_journal']['known_settlements'] == reconciled['journal']['known_settlements'] == 3
    assert reconciled['journal']['pending'] is None and reconciled['journal']['epoch'] is None
    cold = final['cold_journal']
    assert cold['spent']['cpu_ns'] == 32_000_000_000
    assert cold['used_operations'] == 8 and cold['known_settlements'] == 7
    assert cold['unknown_prepaid_reconciliations'] == 0 and cold['settled_epoch_reconciliations_v1'] == 1
    assert cold['pending'] is None and cold['epoch'] is None
    assert final['frontier']['generation'] == 2 and final['marker_count'] == 4
    startup = read(case / 'resume-control/startup-ready.json')
    assert startup['initial_cpu']['stored_credit_ns'] == 0
    next_task = read(case / 'resume-control/validation-ready.json')['result']
    cpu = next_task['cpu']
    assert cpu['spawned_workers'] == cpu['started_workers'] == cpu['finished_workers'] == cpu['known_workers'] == 2
    assert cpu['scoped_worker_cpu_ns'] > 0
    assert cpu['total_cpu_ns'] == cpu['owner_cpu_ns'] + cpu['scoped_worker_cpu_ns']
    for name, digest in result['original_record_sha256'].items():
        assert sha(case / 'v6-journal' / name) == digest
    frames = [read(p) for p in (case / 'v6-journal').glob('*.json')]
    records = [f for f in frames if f['schema'] == 'restricted-history-settled-epoch-record-v1']
    assert len(records) == 1
    assert records[0]['event']['kind'] == 'settled-epoch-reconciled-v1'
    controls = read(case / 'settled-epoch-refusals.json')
    assert controls['journal_unchanged'] and len(controls['refusals']) >= 11
    summary = {
        'schema': 'history-settled-epoch-native-readback-v1', 'passed': True,
        'scope': 'the direct settled-epoch case only; never a full-suite acceptance',
        'full_native_suite_passed': tests['passed'],
        'binary_sha256': build['binary_sha256'],
        'source_bound_native_crash_cut': 'settled-epoch',
        'actual_sigkill_wait4': True, 'actual_second_process_completed': True,
        'original_settlement_known': True, 'new_record_namespace_verified': True,
        'whole_dead_process_cpu_upper_bound_ns': closed['reported_cpu_upper_bound_ns'],
        'additional_conservative_debit_ns': 4_000_000_000,
        'original_debit_preserved_ns': 12_000_000_000,
        'new_epoch_initial_credit_ns': 0, 'new_epoch_validation_cpu': cpu,
        'cold_journal': cold, 'final_frontier': final['frontier'],
        'refusals': controls['refusals'],
        'process_result_sha256': sha(case / 'process-result.json'),
        'physical_resource_or_performance_qualified': False,
        'arbitrary_subprocess_adoption_qualified': False,
        'whole_history_p0_closed': False, 'production_qualified': False,
    }
    (HERE / 'epoch-summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
