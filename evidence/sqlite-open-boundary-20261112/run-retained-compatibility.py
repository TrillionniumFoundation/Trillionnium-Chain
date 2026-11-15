import hashlib
import json
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path('/workspace/scratch/3069292387f3/chain-sqlite')
OUT = pathlib.Path('/workspace/scratch/3069292387f3/sqlite-evidence')
HEAD = '9021d15ffe1dfdfb1358a2372b5a472babbf80ac'
TESTS = {
    'trnm-data-availability': [
        'tests::schema_drift_and_sidecar_are_fail_closed_without_migration',
        'tests::row_tamper_is_rejected_on_reopen',
        'tests::open_existing_requires_precreated_regular_nonsymlink_store',
    ],
    'trnm-mvcc-fee': [
        'tests::schema_sidecar_and_self_consistent_row_tamper_fail_closed',
        'tests::open_existing_requires_precreated_regular_nonsymlink_store',
        'tests::crash_outcomes_reopen_to_exact_source_target_or_fence',
    ],
    'trnm-service-settlement': [
        'tests::schema_sidecar_row_and_self_consistent_state_substitution_fail_closed',
        'tests::open_existing_requires_precreated_regular_nonsymlink_store',
        'tests::commit_uncertainty_reopens_to_exact_source_target_or_permanent_fence',
    ],
    'trnm-task-kernel': [
        'tests::schema_sidecar_row_and_journal_tamper_fail_closed_without_migration',
        'tests::open_existing_requires_precreated_regular_nonsymlink_store',
        'tests::crash_outcomes_are_exact_and_third_state_is_permanently_fenced',
        'archive_store::tests::initialization_handles_long_final_names_and_concurrent_publishers',
        'archive_store::tests::archive_delete_moves_rows_and_reopen_preserves_proof',
        'archive_store::tests::schema_and_archive_row_tamper_fail_closed_before_reopen_or_retry',
    ],
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def matches_source(snapshot):
    current_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    return current_head == HEAD == snapshot['head'] and all(
        sha(ROOT / name) == digest for name, digest in snapshot['files_sha256'].items()
    )

subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
results = []
for package, names in TESTS.items():
    build_receipt = json.loads((OUT / f'positive-owners-{package}.json').read_text())
    assert build_receipt['exit_code'] == 0
    assert build_receipt['selected_sources_unchanged']
    assert matches_source(build_receipt['source_after'])
    assert len(build_receipt['binaries_after']) == 1
    binary = build_receipt['binaries_after'][0]
    executable = pathlib.Path(binary['path'])
    assert sha(executable) == binary['sha256']
    for index, name in enumerate(names):
        prefix = OUT / f'retained-{package}-{index + 1}'
        argv = [str(executable), '--exact', name, '--nocapture', '--test-threads=1']
        started = time.time()
        with prefix.with_suffix('.stdout').open('w') as stdout, prefix.with_suffix('.stderr').open('w') as stderr:
            try:
                result = subprocess.run(argv, cwd=ROOT / 'trillionnium', stdout=stdout, stderr=stderr, timeout=180)
                exit_code = result.returncode
            except subprocess.TimeoutExpired:
                exit_code = 124
        output = prefix.with_suffix('.stdout').read_text()
        native_summaries = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
        unchanged = matches_source(build_receipt['source_after']) and sha(executable) == binary['sha256']
        passed = exit_code == 0 and native_summaries == [('ok', '1', '0', '0')] and unchanged
        record = {
            'package': package, 'test': name, 'argv': argv,
            'source_commit': HEAD, 'source_scope': build_receipt['source_after']['scope'],
            'build_receipt': f'positive-owners-{package}.json',
            'binary': binary, 'elapsed_seconds': time.time() - started,
            'exit_code': exit_code, 'native_summaries': native_summaries,
            'selected_source_and_binary_unchanged': unchanged, 'passed': passed,
        }
        for stream in ['stdout', 'stderr']:
            path = prefix.with_suffix('.' + stream)
            record[stream] = {'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path)}
        prefix.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
        results.append(record)
        print(json.dumps({key: record[key] for key in ['package', 'test', 'exit_code', 'native_summaries', 'passed']}), flush=True)
summary = {'source_commit': HEAD, 'tests': results, 'all_passed': len(results) == 15 and all(r['passed'] for r in results)}
(OUT / 'retained-compatibility-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
raise SystemExit(0 if summary['all_passed'] else 1)
