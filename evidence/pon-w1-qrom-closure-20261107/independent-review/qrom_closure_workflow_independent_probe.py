#!/usr/bin/env python3
"""Retain real small-fixture observations of the current closure workflow.

This is an independent review fixture, never a main-repository source or QROM
qualification. Scientific reports/preflight and GitHub step states are outside
this local consumer probe's proof scope.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path('/workspace/scratch/4a83c49617d8/chain_pq')
BASE = Path('/workspace/scratch/4a83c49617d8/qrom-closure-workflow-review')
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from test_w1_qrom_closure_controls import ClosureWorkflowCompletionTests as Probe


def main():
    BASE.mkdir()
    Probe.setUpClass()
    (BASE / 'reviewed-workflow.yml').write_bytes(Probe.workflow_bytes)
    reviewed = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (ROOT / '.github/workflows/pon-w1-qrom-closure.yml',
                     ROOT / 'scripts/ci/w1_qrom_closure_controls.py',
                     ROOT / 'scripts/ci/test_w1_qrom_closure_controls.py',
                     ROOT / 'scripts/ci/verify_ci_source.py')
    }
    report = {
        'scope': 'actual workflow source/named/completion shell blocks on a small Git fixture; not main-repository completion or security qualification',
        'reviewed_sha256': reviewed,
        'cases': [],
        'main_repository_source_integrity_qualified': False,
        'post_quantum_soundness_qualified': False,
        'unconditional_project_security_bits': None,
    }
    for kind in ('head', 'prospective-merge'):
        case = Probe('test_workflow_real_fixture_completion_retains_unqualified_scope')
        case.setUp()
        try:
            fixture = case.fixture(kind)
            positive = case.complete(fixture)
            case.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
            dest = BASE / kind
            dest.mkdir()
            shutil.copytree(fixture[0], dest / 'source')
            shutil.copytree(fixture[1], dest / 'observations')
            (dest / 'positive.stdout.log').write_text(positive.stdout)
            (dest / 'positive.stderr.log').write_text(positive.stderr)
            steps = {name: {'outcome': 'success', 'conclusion': 'success'}
                     for name in case.REQUIRED_STAGES}
            steps['named_controls']['outcome'] = 'failure'
            case.clear_status(fixture)
            negative = case.complete(fixture, steps=steps)
            case.assert_failed_completion(negative, fixture)
            negative_status = json.loads((fixture[1] / 'ci-status.json').read_text())
            (dest / 'negative.stdout.log').write_text(negative.stdout)
            (dest / 'negative.stderr.log').write_text(negative.stderr)
            (dest / 'negative-status.json').write_text(json.dumps(negative_status, indent=2, sort_keys=True) + '\n')
            before = json.loads((dest / 'observations/source-before.json').read_text())
            named = json.loads((dest / 'observations/named-controls.json').read_text())
            report['cases'].append({
                'kind': kind, 'retained_fixture_directory': str(dest),
                'positive_exit': positive.returncode, 'negative_exit': negative.returncode,
                'actual_fixture_commit': before['tested_commit'],
                'tracked_fixture_entries': before['tracked_entries'],
                'actual_tiny_fixture_tests_run': sum(row['tests_run'] for row in named['suites']),
                'matching_named_record_and_softened_failure_refused':
                    negative_status['failed_or_skipped_stages'] == ['named_controls']
                    and negative_status['all_required_observations_passed'] is False,
            })
        finally:
            case.doCleanups()
    path = BASE / 'review.json'
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(path)


if __name__ == '__main__':
    main()
