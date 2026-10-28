#!/usr/bin/env python3
"""Read every final epoch recovery window and its retained real process receipts."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def administrative(path, binary):
    guardian = read(path / 'guardian-result.json')
    assert guardian['passed'] and guardian['actual_wait4'] and guardian['wait_status'] == 9
    assert guardian['binary_sha256'] == binary
    assert not guardian['native_operation_started'] and not guardian['new_cpu_epoch_created']
    assert not guardian['v6_closed_process_receipt_created']
    assert not (path / 'closed-process.json').exists()
    return {'path': str(path.relative_to(HERE)), 'actual_sigkill_wait4': True,
            'original_native_receipt_created': False,
            'guardian_sha256': sha(path / 'guardian-result.json'),
            'reported_cpu_upper_bound_ns': guardian['reported_cpu_upper_bound_ns']}


def main():
    build, tests = read(HERE / 'build-receipt.json'), read(HERE / 'tests-receipt.json')
    assert build['passed'] and tests['source_stable'] and tests['binary_stable']
    assert build['binary_sha256'] == tests['binary_sha256']
    names = ['settled-epoch', 'settled-epoch-expired-budget'] + [
        'settled-epoch-record-' + stage for stage in
        ['file-synced', 'linked', 'final-synced', 'unlinked', 'published']]
    rows, admin = [], []
    for name in names:
        case = HERE / 'native-03/artifacts' / name
        result = read(case / 'process-result.json')
        assert result['binary_sha256'] == build['binary_sha256']
        guardian, rec, end = result['guardian'], result['reconciliation'], result['finished']
        closed = guardian['closed_process']
        assert guardian['passed'] and guardian['actual_wait4'] and guardian['wait_status'] == 9
        assert closed['actual_wait4'] and closed['signal'] == 9
        assert closed['reported_cpu_upper_bound_ns'] <= 4_000_000_000
        assert closed['reported_cpu_upper_bound_ns'] == (closed['user_cpu_microseconds'] + closed['system_cpu_microseconds'] + 2) * 1000
        barrier = read(case / 'crash-control/crash-ready.json')
        assert barrier['pending_operation'] is None
        assert closed['original_journal'] == barrier['anchor'] and closed['epoch'] == barrier['epoch']
        assert closed['intent_sha256'] == barrier['intent_sha256']
        assert barrier['original_settlement']['operation_closed']
        assert barrier['original_settlement']['accounting_record_persisted']
        assert rec['prior_journal']['spent']['cpu_ns'] == 12_000_000_000
        assert rec['journal']['spent']['cpu_ns'] == 16_000_000_000
        assert rec['journal']['known_settlements'] == 3
        assert rec['journal']['settled_epoch_reconciliations_v1'] == 1
        assert rec['journal']['epoch'] is None and rec['journal']['pending'] is None
        assert rec['original_settlements_preserved'] and not rec['clean_close_fabricated']
        assert not rec['native_effect_repeated'] and not rec['new_cpu_epoch_created']
        assert rec['additional_conservative_debit']['cpu_ns'] == 4_000_000_000
        cold = end['cold_journal']
        assert cold['spent']['cpu_ns'] == 32_000_000_000
        assert cold['used_operations'] == 8 and cold['known_settlements'] == 7
        assert cold['settled_epoch_reconciliations_v1'] == 1 and cold['unknown_prepaid_reconciliations'] == 0
        assert cold['epoch'] is None and cold['pending'] is None
        assert end['frontier']['generation'] == 2 and end['marker_count'] == 4
        assert result['original_records_unchanged'] and 'ROLLBACK' in result['duplicate_recovery_error']
        for filename, digest in result['original_record_sha256'].items():
            assert sha(case / 'v6-journal' / filename) == digest
        startup = read(case / 'resume-control/startup-ready.json')
        assert startup['initial_cpu']['stored_credit_ns'] == 0
        cpu = read(case / 'resume-control/validation-ready.json')['result']['cpu']
        assert cpu['spawned_workers'] == cpu['started_workers'] == cpu['finished_workers'] == cpu['known_workers'] == 2
        assert cpu['scoped_worker_cpu_ns'] > 0
        assert cpu['total_cpu_ns'] == cpu['owner_cpu_ns'] + cpu['scoped_worker_cpu_ns']
        controls = read(case / 'settled-epoch-refusals.json')
        assert controls['journal_unchanged'] and len(controls['refusals']) >= 14
        assert 'SOURCE_PIN' in controls['refusals']['resigned-wrong-executable-pin']
        row = {'case': name, 'actual_original_sigkill_wait4': True,
               'whole_dead_process_cpu_upper_bound_ns': closed['reported_cpu_upper_bound_ns'],
               'original_debit_preserved_ns': 12_000_000_000,
               'additional_conservative_debit_ns': 4_000_000_000,
               'cold_journal': cold, 'next_epoch_initial_credit_ns': 0,
               'next_validation_cpu': cpu, 'refusals': controls['refusals'],
               'process_result_sha256': sha(case / 'process-result.json')}
        if name == 'settled-epoch':
            relabel = read(case / 'new-epoch-record-namespace-refusal.json')
            assert relabel['legacy_record_schema_relabel_refused'] and 'JOURNAL_CHAIN' in relabel['error']
            row['record_namespace_negative'] = relabel
        if name == 'settled-epoch-expired-budget':
            expired = read(case / 'old-budget-expired.json')
            refused = read(case / 'expired-old-run-authority-refused.json')
            renewed = read(case / 'budget-renewed-after-closure.json')
            assert expired['observed_at_ns'] >= expired['expires_ns']
            assert not refused['old_budget_revived'] and refused['journal_unchanged']
            assert renewed['spent']['cpu_ns'] == 16_000_000_000
            row['actual_old_budget_expiry'] = expired
            row['old_run_authority_refusal'] = refused
            row['separate_renewal_preserved_spend_ns'] = 16_000_000_000
        if name.startswith('settled-epoch-record-'):
            stage = name.removeprefix('settled-epoch-record-')
            pub = read(case / 'epoch-publication-recovery.json')
            repaired, retried = pub['publication_repair'], pub['idempotent_publication_retry']
            assert 'EPOCH_PINS_REQUIRED' in pub['generic_publication_bypass_refused']
            assert repaired['journal'] == retried['journal'] and retried['already_published']
            assert repaired['existing_frame_bytes_preserved'] and not repaired['new_journal_event_created']
            assert not pub['administrative_wait4_used_as_original_receipt']
            pin = repaired['externally_pinned_latest_anchor']
            frame = case / 'v6-journal' / f"{pin['sequence']:020}-{repaired['frame_sha256']}.json"
            assert sha(frame) == repaired['frame_sha256'] and frame.stat().st_size == repaired['frame_bytes']
            assert read(frame)['schema'] == 'restricted-history-settled-epoch-record-v1'
            row['exact_frame_publication'] = {'frame_sha256': sha(frame), 'bytes': frame.stat().st_size,
                                             'idempotent_retry': True, 'generic_bypass_refused': True}
            admin.append(administrative(case / ('epoch-recovery-publish-' + stage), build['binary_sha256']))
            if stage == 'file-synced':
                temporal = read(case / 'expired-event-publication.json')
                assert temporal['original_frame_at_ns'] < temporal['original_event_expires_ns'] <= temporal['publication_observed_at_ns']
                assert temporal['original_pending_bytes_unchanged'] and len(temporal['refusals']) == 3
                assert 'PUBLICATION_AUTHORIZATION' in temporal['refusals']['expired-current-publication']
                row['actual_expired_original_event_fresh_publication'] = temporal
                for cut in ['linked', 'unlinked']:
                    admin.append(administrative(case / ('publication-repair-' + cut), build['binary_sha256']))
        rows.append(row)
    assert len(rows) == 7 and len(admin) == 7
    result = {'schema': 'history-settled-epoch-all-window-readback-v1', 'passed': True,
              'scope': 'the seven new settled-epoch control cases only; not a full-suite acceptance',
              'full_native_suite_passed': tests['passed'],
              'source_commit': build['base_commit'], 'binary_sha256': build['binary_sha256'],
              'real_original_death_cases': len(rows), 'real_administrative_sigkill_cases': len(admin),
              'cases': rows, 'administrative_processes': admin,
              'whole_history_p0_closed': False, 'production_qualified': False,
              'arbitrary_subprocess_adoption_qualified': False, 'physical_power_loss_qualified': False}
    (HERE / 'epoch-window-summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['cases', 'administrative_processes']}))


if __name__ == '__main__':
    main()
