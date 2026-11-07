#!/usr/bin/env python3
"""Read-only integrity and business-predicate audit of this evidence directory."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parent


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load(name: str):
    return json.loads((ROOT / name).read_text())


def main() -> None:
    manifest = load('retention-manifest.json')
    assert manifest['original_four_second_gate_passed'] is False
    assert manifest['original_native_campaign_passed'] is False
    count = 0
    members = 0
    for row in manifest['files']:
        path = ROOT / row['stored_path']
        assert path.parent == ROOT
        raw = path.read_bytes()
        assert len(raw) == row['stored_bytes'] and sha(raw) == row['stored_sha256']
        if 'source_sha256' in row:
            source = gzip.decompress(raw) if row['encoding'].startswith('gzip;') else raw
            assert len(source) == row['source_bytes'] and sha(source) == row['source_sha256']
            if path.name.endswith(('.json', '.json.gz')):
                json.loads(source)
        if 'members' in row:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                assert len(archive.getmembers()) == len(row['members'])
                for member in row['members']:
                    original = archive.extractfile(member['path']).read()
                    assert len(original) == member['bytes'] and sha(original) == member['sha256']
                    members += 1
        count += 1
    summary = load('original-gates-summary.json')
    assert summary['head'] == manifest['tested_commit']
    assert summary['tree'] == manifest['tested_tree']
    assert summary['qualification'] is False and summary['gate_passed'] is False
    pressure = []
    for lane in summary['fresh_service']:
        for phase in lane['phases']:
            if phase['workers'] != 16:
                continue
            assert phase['requested_window_ns'] == 4_000_000_000
            assert phase['submissions']['successful_ack'] == phase['submissions']['total'] == 7
            assert len(phase['history']) == 1
            assert phase['history'][0]['status'] == 'ok'
            assert phase['history'][0]['packet_count'] == 7 and phase['history'][0]['complete'] is True
            assert phase['client_confirmed_transactions'] == 0
            assert phase['finite_business_target_met'] is False
            assert phase['no_attack_accepted'] is True and phase['accounting_closed'] is True
            pressure.append(phase)
    assert len(pressure) == 4
    runs = summary['native']['runs']
    assert len(runs) == 3 and summary['native']['build_complete_success'] is True
    for run in runs:
        assert run['original_criteria_met'] is False
        assert run['phase_startup_errors'] == [] and run['report_validation_failure'] is None
        assert len(run['phases']) == 3
        for phase in run['phases']:
            assert phase['host_controller_passed'] is True and phase['host_errors'] == []
            assert phase['finite_phase_criteria_met'] is False
            assert phase['verifier_errors'] == ['PUBLIC_REQUEST_DEADLINE']
    local = load('local-network-evidence-audit.json')
    assert local['native_confirmed_transactions'] == 24
    assert local['has_end_to_end_six_second_confirmation_gate'] is False
    print(json.dumps({
        'evidence_integrity': 'PASS', 'retained_files_verified': count,
        'archive_members_verified': members, 'four_second_pressure_phases': len(pressure),
        'native_runs': len(runs), 'original_business_gates_passed': False,
        'native_tests_executed_by_this_audit': False,
    }))


if __name__ == '__main__':
    main()
