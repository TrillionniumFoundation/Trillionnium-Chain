from pathlib import Path
import collections, datetime, hashlib, json, os, re, stat
base = Path('/workspace/scratch/a4188f5c86b5')
root = base / 'validation'
z = 'cdd984808a088e6c2e13b1e1ae6630a94d500c89'
y = '90ee47159e32e9014410a1823bed05d84c17b858'
def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()
def load(path):
    return json.loads(path.read_bytes())
patterns = [
    ('child_sigkill_cause_not_established', r'\(signal: 9, SIGKILL: kill\)'),
    ('missing_cargo_deny_0_20_2', r'No such file or directory[^\n]*deny-0\.20\.2/bin/cargo-deny'),
    ('missing_libfuzzer_sparse_entry', r'no matching package named `libfuzzer-sys`'),
    ('cross_device_link', r'OSError: \[Errno 18\] Invalid cross-device link'),
    ('missing_usr_bin_time', r"FileNotFoundError: \[Errno 2\] No such file or directory: '/usr/bin/time'"),
    ('no_space_left_on_device', r'OSError: \[Errno 28\] No space left on device'),
    ('retained_w1_golden_source_mismatch', r'FAIL: test_project_unknowns_do_not_produce_a_target_or_qualification'),
]
records = []
for path in sorted(root.rglob('result.json')):
    result = load(path)
    directory = path.parent
    context = load(directory / 'context.json')
    hashes = {name: sha(directory / name) for name in ['result.json', 'context.json', 'stdout.log', 'stderr.log']}
    source = path.relative_to(root).parts[0]
    logs_match = hashes['stdout.log'] == result['stdout_sha256'] and hashes['stderr.log'] == result['stderr_sha256']
    same_source = result['source_head_before'] == result['source_head_after'] == context['source_commit'] == source
    clean = result['source_status_after'] == ''
    valid_pass = result['returncode'] == 0 and result['launch_error'] is None and same_source and clean and logs_match
    if result['pass']:
        assert valid_pass, (path, 'recorded pass does not independently verify')
    stdout = (directory / 'stdout.log').read_text(errors='replace')
    stderr = (directory / 'stderr.log').read_text(errors='replace')
    combined = stderr + '\n' + stdout
    tags = [name for name, pattern in patterns if re.search(pattern, combined)]
    excerpts = []
    if not result['pass']:
        for line in combined.splitlines():
            if any(re.search(pattern, line) for name, pattern in patterns) or line.startswith(('error:', 'FAIL:', 'ERROR:', 'FAILED (')):
                excerpts.append(line if len(line) <= 700 else line[:180] + ' ... ' + line[-500:])
    records.append({
        'host': 'local-cloud',
        'source_commit': source, 'id': result['id'], 'record_directory': str(directory),
        'classification': 'PASS' if valid_pass and result['pass'] else 'FAIL',
        'recorded_pass': result['pass'], 'computed_pass': valid_pass,
        'source_identity_consistent': same_source, 'source_clean_after': clean,
        'raw_log_hashes_match_receipt': logs_match, 'receipt_hashes': hashes,
        'observed_failure_tags': tags, 'failure_excerpts': excerpts[:12],
        'rust_test_summary_count': len(re.findall(r'^test result:', stdout, re.M)),
        'executed_test_binary_lines': len(re.findall(r'^\s*Running .+ \(/[^\n]+\)$', stderr, re.M)),
        'raw_result': result,
    })
directory = root / z / 'm06-retained-tests'
result = load(directory / 'result.json')
context = load(directory / 'context.json')
stdout = (directory / 'stdout.log').read_text()
stderr = (directory / 'stderr.log').read_text()
summary_pattern = r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([^\n]+)$'
summaries = list(re.finditer(summary_pattern, stdout, re.M))
starts = list(re.finditer(r'^running (\d+) tests?$', stdout, re.M))
binaries = list(re.finditer(r'^\s*Running (.+) \((/[^\n]+)\)$', stderr, re.M))
assert len(summaries) == len(starts) == len(binaries) == 18
finished_ns = int(datetime.datetime.fromisoformat(result['finished_utc']).timestamp() * 1_000_000_000)
totals = collections.Counter()
suites = []
for number, (summary, start, binary) in enumerate(zip(summaries, starts, binaries), 1):
    assert start.end() < summary.start()
    if number < len(starts):
        assert summary.end() < starts[number].start()
    counts = dict(zip(['passed', 'failed', 'ignored', 'measured', 'filtered_out'], map(int, summary.group(2, 3, 4, 5, 6))))
    registered = int(start.group(1))
    assert registered == sum(counts[key] for key in ['passed', 'failed', 'ignored', 'measured'])
    case_text = stdout[start.end():summary.start()]
    cases = [dict(name=match.group(1), status=match.group(2), detail=match.group(3))
             for match in re.finditer(r'^test (.+) \.\.\. (ok|FAILED|ignored)([^\n]*)$', case_text, re.M)]
    case_counts = collections.Counter(case['status'] for case in cases)
    assert case_counts['ok'] == counts['passed']
    assert case_counts['FAILED'] == counts['failed']
    assert case_counts['ignored'] == counts['ignored']
    path = Path(binary.group(2))
    assert path.is_relative_to(Path(context['environment']['CARGO_TARGET_DIR']) / 'debug/deps')
    before = path.stat()
    assert stat.S_ISREG(before.st_mode) and os.access(path, os.X_OK)
    with path.open('rb') as stream:
        assert stream.read(4) == b'\x7fELF'
    digest = sha(path)
    after = path.stat()
    stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    assert stable
    totals.update(counts)
    suites.append({
        'ordinal': number, 'cargo_running_label': binary.group(1), 'registered_test_count': registered,
        'status': summary.group(1), **counts, 'elapsed_reported': summary.group(7),
        'ignored_tests': [case for case in cases if case['status'] == 'ignored'],
        'binary': {'path': str(path), 'canonical_path': str(path.resolve()), 'bytes': before.st_size,
                   'sha256': digest, 'elf': True, 'executable': True, 'device': before.st_dev,
                   'inode': before.st_ino, 'mtime_ns': before.st_mtime_ns, 'stat_stable_during_hash': stable,
                   'mtime_not_after_recorded_run_finish': before.st_mtime_ns <= finished_ns},
    })
    print(json.dumps({'hashed_binary': number, 'label': binary.group(1), 'bytes': before.st_size, 'sha256': digest}), flush=True)
assert totals['passed'] == 272 and totals['failed'] == 0 and totals['ignored'] == 9
by_source = {}
for source in sorted({record['source_commit'] for record in records}):
    selected = [record for record in records if record['source_commit'] == source]
    by_source[source] = {
        'host': 'local-cloud', 'label': 'Z-current' if source == z else 'Y-retained' if source == y else 'other-source',
        'record_count': len(selected), 'status_counts': dict(collections.Counter(record['classification'] for record in selected)),
        'pass_ids': [record['id'] for record in selected if record['classification'] == 'PASS'],
        'fail_ids': [record['id'] for record in selected if record['classification'] != 'PASS'],
    }
incomplete = sorted(str(path.parent) for path in root.rglob('context.json') if not path.with_name('result.json').exists())
report = {
    'schema': 'a418-local-final-validation-inventory-v1',
    'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'scope': 'local-cloud /workspace validation only; desktop evidence is not combined into these statuses',
    'current_source_commit': z, 'retained_prior_source_commit': y,
    'all_result_json_paths_in_scope_included': True, 'result_count': len(records),
    'incomplete_context_directories': incomplete, 'by_host_and_source_commit': {'local-cloud': by_source}, 'records': records,
    'm06_retained_tests': {
        'host': 'local-cloud', 'source_commit': z, 'record_directory': str(directory), 'argv': context['argv'],
        'receipt_hashes': {name: sha(directory / name) for name in ['context.json', 'result.json', 'stdout.log', 'stderr.log']},
        'suite_count': len(suites), 'executed_binary_count': len(binaries), 'totals': dict(totals),
        'total_registered_test_cases': sum(suite['registered_test_count'] for suite in suites),
        'all_rust_suites_ok': all(suite['status'] == 'ok' for suite in suites), 'suites': suites,
        'binary_identity_scope': 'Post-run SHA256 of each present regular ELF at its actual Cargo Running path, with stable stat and mtime recorded; not an at-execution signed attestation.',
        'ignored_tests_count_as_passed': False,
    },
    'interpretation': {'original_failures_reclassified_as_pass': False, 'source_cohorts_combined_for_acceptance': False,
                       'sigkill_diagnosed_as_oom': False, 'missing_tools_counted_as_pass': False,
                       'full_ci_acceptance_granted': False, 'production_or_pq_network_qualification_granted': False},
}
output = base / 'coordination/final-validation-inventory.json'
with output.open('x', encoding='utf-8') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'inventory': str(output), 'sha256': sha(output), 'by_source': by_source,
                  'm06_totals': dict(totals), 'm06_suite_count': len(suites), 'incomplete': incomplete}, indent=2), flush=True)

