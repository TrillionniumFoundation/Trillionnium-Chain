"""Reproduce finite accounting, complete Cell replay and separated service fees.

The whole clean committed source is checked before and after. Output must be a
new directory outside the source tree; no historical observation is overwritten.
A PASS means these declared controls ran successfully, never work qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))

from cell_lottery_cost_audit_v1 import run_audit
from lifecycle_cost_v1 import demo
from service_work_settlement_v1 import run_demo
from verify_ci_source import verify


def write_new(directory, name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with (directory / name).open('xb') as stream:
        stream.write(raw)
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def run(directory):
    directory = directory.resolve()
    if directory.is_relative_to(ROOT):
        raise ValueError('OUTPUT_MUST_BE_OUTSIDE_SOURCE_TREE')
    directory.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                   text=True).strip()
    report = {'schema': 'pon-lifecycle-cost-game-reproduction-v1',
              'source_commit': head, 'driver_status': 'FAIL', 'artifacts': [],
              'qualification': 'HOLD_NO_GO',
              'actual_W1_all_algorithm_lower_bound': None,
              'native_chain_security_probability': None,
              'native_owner_settlement_executed': False}
    try:
        before = verify('head', head, root=ROOT)
        report['artifacts'].append(write_new(directory, 'source-before.json', before))
        for name, execute in [('finite-lifecycle.json', demo),
                              ('cell-conformance.json', run_audit),
                              ('service-separation.json', run_demo)]:
            report['artifacts'].append(write_new(directory, name, execute()))
        after = verify('head', head, root=ROOT)
        report['artifacts'].append(write_new(directory, 'source-after.json', after))
        if before != after:
            raise ValueError('SOURCE_CHANGED_DURING_REPRODUCTION')
        report['driver_status'] = 'PASS'
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
    write_new(directory, 'manifest.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps(result, sort_keys=True, indent=2))
    raise SystemExit(0 if result['driver_status'] == 'PASS' else 1)
