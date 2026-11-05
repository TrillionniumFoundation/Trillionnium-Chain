#!/usr/bin/env python3
"""Run only nine previously uncovered selectors against the supplied final ELF."""
import argparse, datetime, hashlib, json, re, resource, subprocess, time
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--native-records', type=Path, required=True)
    parser.add_argument('--wrapper', type=Path, required=True)
    args = parser.parse_args()
    root = args.repo.resolve()
    evidence = args.native_records.resolve()
    out = Path(__file__).resolve().parent
    expected = json.loads((evidence / 'source-before.json').read_text())
    original = json.loads((evidence / 'result.json').read_text())
    binary = Path(original['binary'])
    reader = root / 'scripts/ci/check_required_native_test.py'
    assert expected['manifest_sha256'] == original['source_manifest_sha256']
    assert original['source_unchanged'] is True
    assert original['binary_sha256'] == original['binary_after_sha256']
    assert expected['head'] == '69d2e06c48bbbd1e22432f9b557727b140aba361'
    assert expected['manifest_sha256'] == 'ccc0b180a702aa012bb24ca0541c9d91592239083c141e3a289f0345acf9df8c'
    assert original['binary_sha256'] == '5349b31b55279a52dd75b679c5c3a12cb0c0d784dc259098409bb376f056045d'
    runtime_before = {'wrapper_sha256': digest(args.wrapper), 'required_reader_sha256': digest(reader)}

    def source():
        paths = {name for name in expected['native_input_files'] if not name.startswith('trillionnium/')}
        paths.update(str(p.relative_to(root)) for p in (root / 'trillionnium').rglob('*')
                     if p.is_file() and not {'target', '__pycache__', '.git'} & set(p.parts))
        files = {name: digest(root / name) for name in sorted(paths)}
        return {'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                'native_input_files': files,
                'manifest_sha256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'scope': expected['scope']}

    def guard():
        observed = source()
        assert observed == expected, 'native inputs or HEAD drifted'
        elf = digest(binary)
        assert elf == original['binary_sha256'], 'ELF drifted'
        assert {'wrapper_sha256': digest(args.wrapper), 'required_reader_sha256': digest(reader)} == runtime_before, 'runtime wrapper or original reader drifted'
        return observed, {'head': observed['head'], 'native_input_files': len(observed['native_input_files']),
                          'native_manifest_sha256': observed['manifest_sha256'], 'elf_sha256': elf,
                          **runtime_before}

    def execute(label, argv, cwd=root):
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tick = time.monotonic_ns()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        stdout, stderr = out / (label + '.stdout'), out / (label + '.stderr')
        with stdout.open('wb') as so, stderr.open('wb') as se:
            result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=so, stderr=se)
        end = resource.getrusage(resource.RUSAGE_CHILDREN)
        record = {'label': label, 'argv': argv, 'cwd': str(cwd), 'started_at': start,
                  'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'wall_ns': time.monotonic_ns() - tick, 'exit_code': result.returncode,
                  'child_user_seconds': end.ru_utime - usage.ru_utime,
                  'child_system_seconds': end.ru_stime - usage.ru_stime,
                  'max_child_rss_kib': end.ru_maxrss,
                  'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}
        write(out / (label + '.json'), record)
        print(json.dumps({'label': label, 'exit_code': result.returncode, 'wall_ns': record['wall_ns']}), flush=True)
        return record

    selectors = [
      'account_archive_prototype::native_root_digest::tests::native_root_digest_matches_record_and_sparse_references_after_exact_input_changes',
      'account_archive_prototype::native_root_digest::tests::native_root_digest_keeps_original_traversal_cancellation_and_collision_order',
      'account_archive_prototype::native_root_digest::tests::native_root_digest_keeps_fork_shape_and_all_lift_input_relations',
      'store::growth::tests::scale_observation::native_growth_scale_retains_rejected_and_cancelled_admission_returns',
      'store::growth::tests::scale_observation::native_growth_scale_retains_admission_when_activation_returns_error',
      'store::detached_admission::tests::large_parent_root_arithmetic_keeps_current_sql_and_original_read_checkpoints',
      'store::historical_commitment_tests::legacy_prepared_history_reads_observe_current_rows_writes_and_rollback',
      'store::historical_commitment_tests::legacy_prepared_history_reads_reprepare_after_schema_and_authorizer_changes',
      'store::historical_commitment_tests::actual_foreign_snapshot_delta_and_root_damage_preserve_original_failures',
    ]
    prior_labels = ['append-reorg','authenticated','archive-store'] + ['tcp-' + str(i) for i in range(1,7)]
    prior_names = []
    prior_logs = {}
    for label in prior_labels:
        path = evidence / (label + '.stdout')
        receipt = json.loads((evidence / (label + '.json')).read_text())
        assert receipt['exit_code'] == 0 and digest(path) == receipt['stdout_sha256']
        prior_names.extend(re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$', path.read_text(), re.M))
        prior_logs[label] = {'stdout_sha256': digest(path), 'receipt_sha256': digest(evidence / (label + '.json'))}
    assert len(prior_names) == len(set(prior_names)) == 118
    assert len(selectors) == len(set(selectors)) == 9
    assert not set(selectors) & set(prior_names), 'would rerun an existing passed selector'
    registered = {line[:-6] for line in (evidence / 'registry-all.stdout').read_text().splitlines() if line.endswith(': test')}
    ignored = {line[:-6] for line in (evidence / 'registry-ignored.stdout').read_text().splitlines() if line.endswith(': test')}
    assert set(selectors) <= registered and not set(selectors) & ignored

    preflight = execute('preflight', ['bash','scripts/project-preflight.sh'])
    assert preflight['exit_code'] == 0
    before, initial_guard = guard()
    write(out / 'source-before.json', before)
    write(out / 'selection.json', {'selectors': selectors, 'previous_unique_passed': 118,
          'overlap_with_previous_passed': [], 'prior_logs': prior_logs,
          'base_native_result_sha256': digest(evidence / 'result.json'),
          'original_reader_runtime': runtime_before})
    records = []
    for index, selector in enumerate(selectors, 1):
        label = 'test-' + str(index)
        _, guard_before = guard()
        native = execute(label, ['bash', str(args.wrapper), str(binary), selector,
                                 '--exact', '--show-output', '--test-threads=1'],
                         cwd=root / 'trillionnium/crates/trnm-pon-node')
        checked = execute(label + '-reader', ['python3', str(reader), str(out / (label + '.stdout')), '--test', selector])
        _, guard_after = guard()
        record = {'selector': selector, 'label': label, 'native': native, 'reader': checked,
                  'guard_before': guard_before, 'guard_after': guard_after,
                  'source_and_elf_unchanged': guard_before == guard_after}
        write(out / (label + '-observation.json'), record)
        records.append(record)
    after, final_guard = guard()
    write(out / 'source-after.json', after)
    result = {'schema': 'final-69d2-uncovered-workspace-controls-v1',
              'scope': 'Only nine previously uncovered exact Node selectors; no build, no Cargo, no performance/service measurement.',
              'head': before['head'], 'source_kind': 'dirty composed source based on 69d2; not clean 69d2',
              'native_input_files': len(before['native_input_files']),
              'native_manifest_sha256': before['manifest_sha256'],
              'binary': str(binary), 'binary_sha256': initial_guard['elf_sha256'],
              'binary_after_sha256': final_guard['elf_sha256'],
              'source_before_after_equal': before == after,
              'previous_unique_passed': 118, 'new_exact_selectors': 9, 'overlap_with_previous_passed': [],
              'records': records,
              'all_native_and_readers_succeeded': all(r['native']['exit_code'] == 0 and r['reader']['exit_code'] == 0 for r in records),
              'full_node_suite_executed': False, 'public_confirmation_measured': False}
    write(out / 'result.json', result)
    print(json.dumps({k: result[k] for k in ('native_manifest_sha256','binary_sha256','source_before_after_equal','all_native_and_readers_succeeded','new_exact_selectors')}), flush=True)
    return 0 if result['all_native_and_readers_succeeded'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
