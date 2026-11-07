#!/usr/bin/env python3
"""Read the original retained failures with current readers; execute no native code."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
REPO = Path('/workspace/scratch/ae364bcbabfb/publication-check')
RAW = Path('/workspace/scratch/ae364bcbabfb/acceptance-raw')
sys.path.insert(0, str(REPO / 'scripts/ci'))
import run_from_zero_native as native
import run_w1_fresh_service_v1 as fresh
import run_history_native as history
from check_required_native_test import validate as named


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attempted(call):
    try:
        call()
        return {'accepted': True, 'error': None}
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return {'accepted': False, 'error': type(exc).__name__ + ': ' + str(exc)}


def main():
    rows = []
    for kind, check, selector in [('original', native.validate_confirmation_report, fresh.ORIGINAL),
                                  ('fresh', fresh.validate_fresh_report, fresh.FRESH)]:
        folder = RAW / '13566551605/fresh-service'
        path = folder / kind / 'report.json'
        manifest = json.loads((folder / 'manifest.json').read_text())
        report = json.loads(path.read_text())
        process = manifest['runs'][0 if kind == 'original' else 1]['process']
        rows.append({'kind': kind, 'artifact_id': 13566551605, 'run_id': 42352433680,
                     'source': manifest['source_before']['commit'], 'report_sha256': digest(path),
                     'native_process_exit_code': process['process_exit_code'],
                     'named_native_log': attempted(lambda: named((folder / (kind + '.log')).read_text().splitlines(), selector)),
                     'strict_reader': attempted(lambda: check(path)),
                     'phase_confirmed_transactions': [p['client_confirmed_transactions'] for p in report['phases']],
                     'phase_finite_business_target_met': [p['finite_business_target_met'] for p in report['phases']]})
    for artifact, arch in [('13568123690', 'x64'), ('13568038035', 'arm64')]:
        folder = RAW / artifact / 'history-native'
        path = folder / 'long-history/summary.json'
        summary = json.loads(path.read_text())
        manifest = json.loads((folder / 'manifest.json').read_text())
        rows.append({'kind': 'history-' + arch, 'artifact_id': int(artifact), 'run_id': 42352433738,
                     'source': manifest['source_before']['commit'], 'summary_sha256': digest(path),
                     'native_process_exit_code': manifest['process']['exit_code'],
                     'named_native_log': attempted(lambda: named((folder / 'history.log').read_text().splitlines(), history.SELECTOR)),
                     'strict_reader': attempted(lambda: history.validate_summary(summary)),
                     'retained_summary_passed': summary['passed']})
    assert len(rows) == 4 and all(not row['strict_reader']['accepted'] for row in rows)
    readers = ['scripts/ci/run_from_zero_native.py', 'scripts/ci/run_w1_fresh_service_v1.py',
               'scripts/ci/run_history_native.py', 'scripts/ci/check_required_native_test.py']
    result = {'schema': 'retained-business-failure-reader-check-v1',
              'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
              'scope': 'Four retained failure readbacks using current local reader bytes, not a clean-source or native campaign qualification',
              'readers': {p: digest(REPO / p) for p in readers},
              'retained_failures': rows, 'all_four_remain_refused': True,
              'native_execution': False, 'github_actions_execution': False}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
