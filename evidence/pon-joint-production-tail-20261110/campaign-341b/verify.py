"""Read retained receipts; optionally reconcile them against the original ZIP."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parent


def check(raw, size, sha):
    assert len(raw) == size and hashlib.sha256(raw).hexdigest() == sha


def verify(original=None):
    assert __debug__
    for row in json.loads((ROOT / 'MANIFEST.json').read_text())['files']:
        check((ROOT / row['path']).read_bytes(), row['bytes'], row['sha256'])
    rows = json.loads((ROOT / 'retained-members.json').read_text())
    assert len(rows) == 56
    def read(name):
        row = next(r for r in rows if r['archive_member'] == name)
        if row.get('storage_archive'):
            with zipfile.ZipFile(ROOT / row['storage_archive']) as z:
                packed = z.read(row['path'])
        else:
            packed = (ROOT / row['path']).read_bytes()
        check(packed, row['bytes'], row['sha256'])
        assert row['decoded_bytes'] < 64 * 1024 * 1024
        raw = gzip.decompress(packed)
        check(raw, row['decoded_bytes'], row['decoded_sha256'])
        return raw
    for row in rows:
        read(row['archive_member'])
    result = json.loads(read('results.json'))
    assert result['expected_head'] == '341b7b6195a44d3f4a758c98f846457567ac1de3'
    assert result['expected_tree'] == 'eb37d4499ca92121a81ef9c0af1e7b221d5f85b1'
    assert result['complete_success'] is False
    assert result['build']['returncode'] == 0
    assert result['binary']['sha256_before'] == result['binary']['sha256_after'] == 'a1b0c4e61d46e5e59187b3fd2620cdc24f66fb8905d1c43ab81b619055601205'
    derived = []
    for attempt in result['attempts']:
        number = attempt['number']
        assert attempt['complete_success'] is False and attempt['original_criteria_met'] is False
        assert attempt['phase_startup_errors'] == [] and attempt['report_validation_failure'] is None
        assert attempt['step']['returncode'] == 101
        for stream in ['stdout', 'stderr']:
            step = attempt['step']
            check(read(step[stream]), step[stream + '_bytes'], step[stream + '_sha256'])
        raw = read(f'run-{number}-raw/report.json')
        assert hashlib.sha256(raw).hexdigest() == attempt['report_sha256']
        report = json.loads(raw)
        phase_readback = json.loads(read(f'run-{number}-phase-readback.json'))
        phases = []
        for phase, observed in zip(report['phases'], phase_readback['phases']):
            assert all(type(c['confirmed_inside_pressure_window']) is bool for c in phase['confirmations'])
            confirmed = sum(c['confirmed_inside_pressure_window'] for c in phase['confirmations'])
            assert confirmed == observed['confirmed_rounds']
            assert len(phase['confirmations']) == observed['observed_confirmation_rounds']
            assert phase['finite_phase_criteria_met'] is False
            phases.append({'mode': phase['mode'], 'confirmed_rounds': confirmed,
                           'observed_rounds': len(phase['confirmations']),
                           'scheduled_rounds': observed['scheduled_confirmation_rounds'],
                           'criteria': False, 'window_seconds': phase['duration_seconds']})
        assert [p['confirmed_rounds'] for p in phases] == [1, 0, 0]
        assert [p['observed_rounds'] for p in phases] == [2, 1, 1]
        derived.append({'run': number, 'raw_report_sha256': attempt['report_sha256'], 'phases': phases})
    assert derived == json.loads((ROOT / 'SUMMARY.json').read_text())['runs']
    before = json.loads(read('source-before-campaigns.json'))
    assert before == json.loads(read('source-after-native.json'))
    assert before['tested_commit'] == result['expected_head'] and before['tested_tree'] == result['expected_tree']
    if original:
        raw = Path(original).read_bytes()
        check(raw, 71446778, 'b02a44181e54f57c834a37ffd7d6726f98b23c51b81e0b800d12e8c536c2d96f')
        with zipfile.ZipFile(original) as z:
            assert len(z.infolist()) == len(set(z.namelist())) == 1766
            for row in rows:
                assert z.read(row['archive_member']) == read(row['archive_member'])
            b = json.loads((ROOT / 'binary-observation.json').read_text())
            check(z.read(b['archive_member']), b['bytes'], b['sha256'])
    return {'retained_evidence_consistency': 'PASS', 'original_archive_checked': bool(original),
            'original_campaign_passes': '0/3', 'phase_confirmed_rounds_each_run': [1, 0, 0],
            'unique_root_cause': None, 'actual_joint_obligations_closed': 0,
            'native_risk_bounds': None, 'qualification': 'HOLD_NO_GO'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--original-archive')
    print(json.dumps(verify(parser.parse_args().original_archive), sort_keys=True))
