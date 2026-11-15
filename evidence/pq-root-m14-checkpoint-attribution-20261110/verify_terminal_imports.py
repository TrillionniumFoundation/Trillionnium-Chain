#!/usr/bin/env python3
"""Add failed-terminal checkpoint costs to verify_imports.py's exact-source M14 readback."""
import argparse
import json
import zipfile
from verify_imports import analyze, MODES


def terminal_addendum(path):
    original = analyze(path)  # Full ZIP SHA, source, report hashes, phase and budget controls.
    rows = []
    with zipfile.ZipFile(path) as archive:
        for run in (1, 2, 3):
            for mode in MODES:
                phase = json.loads(archive.read(f'run-{run}-raw/{mode}.json'))
                histories = phase['history']
                failed = [(i, h) for i, h in enumerate(histories)
                          if not h['client_import']['succeeded']]
                assert len(failed) == 1 and failed[0][0] == len(histories)-1
                h = failed[0][1]
                assert h['status'] == 'ok'
                assert h['client_import']['error'] == 'PUBLIC_REQUEST_DEADLINE'
                obs = h['client_import']['native_import_observation']
                assert obs['measurement_failures'] == 0
                ck = [x for x in obs['host_checks'] if x['phase'] == 'checkpoint']
                assert len(ck) == 1 and ck[0]['calls_started'] == ck[0]['calls_completed']
                assert ck[0]['calls_rejected'] == ck[0]['cpu_clock_unknown_calls'] == 0
                rows.append({'run': run, 'mode': mode,
                             'failed_calls': ck[0]['calls_completed'],
                             'failed_cpu_ns': ck[0]['thread_cpu_ns']})
    totals = {key: sum(row[key] for row in rows)
              for key in ('failed_calls', 'failed_cpu_ns')}
    assert totals == {'failed_calls': 74646, 'failed_cpu_ns': 3436242779}
    totals['successful_calls'] = sum(v['checkpoint_calls']
                                     for v in original['by_mode'].values())
    totals['successful_cpu_ns'] = sum(v['checkpoint_thread_cpu_ns']
                                      for v in original['by_mode'].values())
    totals['all_calls'] = totals['successful_calls'] + totals['failed_calls']
    totals['all_cpu_ns'] = totals['successful_cpu_ns'] + totals['failed_cpu_ns']
    return {'status': 'HOLD_NO_GO', 'zip_sha256': original['archive_sha256'],
            'source_head': original['source_head'], 'rows': rows, 'totals': totals}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('zip')
    args = parser.parse_args()
    print(json.dumps(terminal_addendum(args.zip), sort_keys=True, indent=2))
