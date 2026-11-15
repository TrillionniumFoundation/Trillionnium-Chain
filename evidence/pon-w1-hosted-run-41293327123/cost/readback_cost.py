"""Read retained hosted ZIPs; preserve originals and derive an explicitly timed-field-free stream."""
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path('/workspace/scratch/76b96c45510e/trillionnium-chain')
OUT = Path(__file__).resolve().parent
HEAD = 'c041564b8a6bb0b98ca9c30e7871878427e5d9a4'
sys.path.insert(0, str(ROOT / 'scripts'))
import pon_w1_false_trace_reuse_reader_v1 as reader

SHA = lambda data: hashlib.sha256(data).hexdigest()
PATHS = reader.PATHS
TIMING_FIELDS = {'campaign': ['material_setup'], 'material': [], 'cohort': ['setup', 'total'],
                 'search': ['timing'], 'candidate': [], 'verifier': ['timing'], 'end': []}
EXPECTED_COUNTS = {'campaign': 1, 'material': 9, 'cohort': 72, 'search': 288,
                   'candidate': 288, 'verifier': 1152, 'end': 1}
JOB_IDS = {('x64', 'head'): 124808937574, ('x64', 'prospective-merge'): 124808937565,
           ('arm64', 'head'): 124808937601, ('arm64', 'prospective-merge'): 124808937631}

def write_original(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError('Refusing to overwrite different artifact: ' + str(path))
    else:
        with path.open('xb') as stream:
            stream.write(data)


def dump(path, value):
    write_original(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


source_identities = {}
for name in ['scripts/pon_w1_false_trace_reuse_reader_v1.py', 'scripts/pon_w1_cost_matrix_reader.py']:
    raw = (ROOT / name).read_bytes()
    original = subprocess.check_output(['git', 'show', HEAD + ':' + name], cwd=ROOT)
    if raw != original:
        raise ValueError('Local reader differs from measured head: ' + name)
    source_identities[name] = SHA(raw)

metadata = json.loads((OUT / 'downloads.json').read_text())
results = []
for item in sorted(metadata['artifacts'], key=lambda row: (row['source'], row['arch'])):
    archive_path = Path(item['path'])
    zip_raw = archive_path.read_bytes()
    assert len(zip_raw) == item['size'] and SHA(zip_raw) == item['sha']
    label = item['arch'] + '-' + item['source']
    destination = OUT / label
    prefix = 'w1-false-trace-reuse-v1/'
    with zipfile.ZipFile(io.BytesIO(zip_raw)) as archive:
        mraw = archive.read(prefix + 'manifest.json')
        manifest = json.loads(mraw)
        raw = archive.read(prefix + 'campaign.stdout')
        executable = archive.read(prefix + 'pon_w1_false_trace_reuse_v1')
        assert manifest['result'] == 'PASS'
        assert manifest['expected_source_commit'] == item['tested_sha']
        assert manifest['source_before']['commit'] == item['tested_sha']
        assert manifest['source_before'] == manifest['source_after']
        assert manifest['source_before']['source_state'] == 'committed-clean'
        assert manifest['source_before']['tracked_worktree_verified'] is True
        assert manifest['source_changed'] is False
        assert manifest['build_environment_overrides'] == {}
        assert manifest['cargo_configuration_before'] == manifest['cargo_configuration_after']
        assert manifest['cargo_configuration_changed'] is False
        assert manifest['default_release_configuration_checked'] is True
        assert not manifest['cargo_configuration_before']['violations']
        binary_hash = SHA(executable)
        binary_fields = ['binary_sha256_before', 'binary_sha256_after',
                         'retained_binary_sha256_before', 'retained_binary_sha256_after']
        assert all(manifest[key] == binary_hash for key in binary_fields)
        expected_elf = 62 if item['arch'] == 'x64' else 183
        assert executable[:6] == b'\x7fELF\x02\x01'
        assert int.from_bytes(executable[18:20], 'little') == expected_elf == manifest['binary_elf_machine']
        assert len(manifest['observations']) == 5
        assert all(row['exit_code'] == 0 and row['timed_out'] is False for row in manifest['observations'])
        assert [row['timeout_seconds'] for row in manifest['observations']] == [30, 30, 30, 900, 300]
        assert manifest['observations'][-1]['command'][-1] == reader.SELECTOR
        assert manifest['architecture'] == item['arch']
        assert manifest['execution_context'] == 'github-hosted'
        assert manifest['runner_context']['GITHUB_RUN_ID'] == '41293327123'
        assert manifest['runner_context']['GITHUB_RUN_ATTEMPT'] == '1'
        for flag in reader.FALSE_FLAGS:
            assert manifest[flag] is False
        # Verify every file SHA recorded by the native owner, including the raw
        # output, retained executable, compiler observation and build logs.
        for name, expected_sha in manifest['artifact_sha256'].items():
            assert SHA(archive.read(prefix + name)) == expected_sha, name
        count = lambda text: re.findall(r'^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored;', text, re.M)
        assert count(archive.read('w1-tests.log').decode()) == ['98']
        assert count(archive.read('w1-fuzz-semantics.log').decode()) == ['6']
        saved_names = ['source-before.json', 'source-after.json', 'w1-tests.log',
                       'w1-fuzz-semantics.log', 'w1-clippy.log', 'reader-controls.log', 'runner-controls.log']
        for name in saved_names:
            write_original(destination / name, archive.read(name))
        write_original(destination / 'manifest.json', mraw)
        write_original(destination / 'campaign.jsonl', raw)
        write_original(destination / 'campaign.stderr', archive.read(prefix + 'campaign.stderr'))
        write_original(destination / 'reader-original.json',
                       (json.dumps(manifest['reader'], indent=2, sort_keys=True) + '\n').encode())
        report = reader.analyze(destination / 'campaign.jsonl')
        assert report == manifest['reader'], 'Independent reader differs from retained native-owner reader result'
        assert report['record_counts'] == EXPECTED_COUNTS
        assert report['semantic_alerts'] == []
        assert SHA(raw) == report['input_sha256'] and len(raw) == report['input_bytes']
        canonical = bytearray()
        clock_count, phases, attempt_count = 0, {}, 0
        outcomes = {path: {} for path in PATHS}
        for line in raw.splitlines(keepends=True):
            row = reader.common.decode(line)
            for field in TIMING_FIELDS[row['kind']]:
                stamp = row.pop(field)
                assert set(stamp) == {'cpu_ns', 'wall_ns'}
                assert all(type(stamp[axis]) is int and stamp[axis] > 0 for axis in stamp)
                clock_count += 1
                key = row['kind'] + '.' + field
                phases[key] = phases.get(key, 0) + 1
            if row['kind'] == 'search':
                attempt_count += len(row['attempts'])
            if row['kind'] == 'verifier':
                path = row['path']; outcome = row['outcome']
                outcomes[path][outcome] = outcomes[path].get(outcome, 0) + 1
            canonical.extend(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() + b'\n')
        assert clock_count == 1585
        assert attempt_count == 573
        assert all(value == {'Transcript': 288} for value in outcomes.values())
        canonical_hash = SHA(canonical)
        compressed = lzma.compress(canonical, preset=9)
        write_original(destination / 'canonical-without-timing.jsonl.xz', compressed)
        raw_compressed = lzma.compress(raw, preset=9)
        write_original(destination / 'campaign.jsonl.xz', raw_compressed)
        rows = report['actual_reuse_cohorts']
        total = sum(row['full_attacker_cohort_total']['cpu_ns'] for row in rows)
        verifier_totals = {path: sum(row['verification'][path]['cpu_ns'] for row in rows) for path in PATHS}
        aggregate = {path: verifier_totals[path] / total for path in PATHS}
        minmax = {path: {'minimum': min(row['receiver_rejection_cpu_over_full_attacker_cpu'][path] for row in rows),
                        'maximum': max(row['receiver_rejection_cpu_over_full_attacker_cpu'][path] for row in rows)} for path in PATHS}
        cpuinfo = archive.read(prefix + 'cpuinfo.txt').decode()
        cpu_identity = {}
        for line in cpuinfo.splitlines():
            key, sep, value = line.partition(':')
            if sep and key.strip() in ('model name', 'CPU implementer', 'CPU architecture', 'CPU variant', 'CPU part', 'CPU revision'):
                cpu_identity.setdefault(key.strip(), value.strip())
        result = {'arch': item['arch'], 'source_kind': item['source'], 'tested_source': item['tested_sha'],
            'source_tree': manifest['source_before']['tree'], 'artifact_id': item['id'],
            'job_id': JOB_IDS[item['arch'], item['source']], 'original_zip': archive_path.name,
            'zip_sha256': item['sha'], 'zip_bytes': item['size'], 'zip_github_digest_matched': True,
            'manifest_sha256': SHA(mraw), 'manifest_result': manifest['result'],
            'native_owner_artifact_hashes_checked': len(manifest['artifact_sha256']),
            'source_before_after_expected_match': True, 'source_tracked_worktree_verified': True,
            'executable_retained_copy_before_after_match': True, 'binary_sha256': binary_hash,
            'binary_hash_fields': {key: manifest[key] for key in binary_fields},
            'binary_elf_machine': expected_elf, 'build_environment_overrides': {},
            'cargo_configuration_unchanged_and_accepted': True,
            'native_commands': manifest['observations'], 'cpuinfo_identity': cpu_identity,
            'reader_recomputed_equal_original': True, 'record_counts': report['record_counts'],
            'raw_sha256': SHA(raw), 'raw_bytes': len(raw), 'raw_xz_sha256': SHA(raw_compressed),
            'raw_xz_bytes': len(raw_compressed), 'canonical_sha256': canonical_hash,
            'canonical_bytes': len(canonical), 'canonical_xz_sha256': SHA(compressed),
            'canonical_xz_bytes': len(compressed), 'canonical_records': sum(report['record_counts'].values()),
            'clock_observations_positive_complete': clock_count, 'clock_phases': phases,
            'full_attacker_cohort_cpu_ns': total, 'verifier_cpu_ns': verifier_totals,
            'aggregate_receiver_cpu_over_full_attacker_cpu': aggregate,
            'minmax_class_receiver_cpu_over_full_attacker_cpu': minmax,
            'hash_attempts': attempt_count, 'native_outcomes': outcomes,
            'w1_module_tests_passed': 98, 'fuzz_semantic_tests_passed': 6,
            'semantic_alerts': report['semantic_alerts'], 'false_qualification_flags': {k: False for k in reader.FALSE_FLAGS},
            'actual_reuse_cohorts': rows}
        dump(destination / 'readback.json', result)
        results.append(result)

summary = {'schema': 'trnm-w1-hosted-cost-readback-v1', 'run_id': 41293327123, 'candidate_head': HEAD,
    'reader_source_commit': HEAD, 'reader_source_sha256': source_identities,
    'scope': 'Four hosted exact-source W1 primitive observations, not full-project, public-service, resource-fairness, hardness or release qualification.',
    'canonical_equality': {'all_four_equal': len({r['canonical_sha256'] for r in results}) == 1,
        'sha256': results[0]['canonical_sha256'] if len({r['canonical_sha256'] for r in results}) == 1 else None,
        'removed_timing_objects_by_record_kind': TIMING_FIELDS,
        'encoding': 'Original record order, sorted JSON object keys, compact separators, UTF-8, one LF per record.',
        'included': ['Every campaign parameter and scope flag', 'Every full material A/B byte string and task hash',
            'Every nonce, challenge, trace, ticket, target result and complete winning proof',
            'Verifier path, invocation order and reported native verdict', 'All setup/search/candidate/verifier coverage and final counts'],
        'excluded': ['Only the explicitly listed CPU/wall timing objects', 'Build/runtime environment, binary and host identities are separately retained, not asserted equal'],
        'not_established': ['Equality of CPU cost, performance or hardware', 'Independent W1 transcript replay by Python',
            'Adversarial cost lower bounds', 'Public receiver throughput/fairness or model utility', 'Whole chain acceptance or production readiness']},
    'lanes': results, 'source_or_budget_changes_performed_by_readback': False,
    'native_measurements_relabelled': False, 'independent_hardware_qualified': False,
    'hardness_accepted': False, 'public_service_measured': False, 'production_activation': False}
dump(OUT / 'cost-readback-summary.json', summary)
print(json.dumps({'run_id': summary['run_id'], 'canonical_equality': summary['canonical_equality'],
    'lanes': [{key: row[key] for key in ['arch', 'source_kind', 'tested_source', 'artifact_id', 'record_counts',
        'aggregate_receiver_cpu_over_full_attacker_cpu', 'minmax_class_receiver_cpu_over_full_attacker_cpu',
        'clock_observations_positive_complete', 'raw_sha256', 'canonical_sha256']} for row in results]}, indent=2))
