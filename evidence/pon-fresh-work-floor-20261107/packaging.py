"""Create a byte-checked, research-only evidence package outside the checkout."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import re
import shutil
import statistics
import subprocess
import tarfile

ROOT = Path('/workspace/scratch/10a9f8f2cba0')
REPO = ROOT / 'chain-fairness'
STAGING = ROOT / 'evidence-staging/pon-fresh-work-floor-20261107'
OUT = ROOT / 'fresh-evidence-package'
SOURCE = '1e0eba75f4f4a4e24e17cbd0f263f915c1493ac7'
BASE = '9602cb704f97fb9c87d6fd379809bef468c3c1e8'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write('\n')


def copy(source, relative):
    target = OUT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    assert not target.exists() and source.is_file() and not source.is_symlink()
    shutil.copyfile(source, target)
    assert sha(source.read_bytes()) == sha(target.read_bytes())


def archive(name, roots):
    """Normalize container metadata only; every regular file byte is unchanged."""
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    for prefix, path in roots:
        selected = sorted(path.rglob('*')) if path.is_dir() else [path]
        for item in selected:
            assert not item.is_symlink(), str(item)
            if not item.is_file() or '__pycache__' in item.parts:
                continue
            relative = prefix + '/' + item.relative_to(path).as_posix() if path.is_dir() else prefix
            assert relative not in files
            files[relative] = item
    members = []
    with target.open('xb') as output:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for name, path in sorted(files.items()):
                    raw = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(raw), 0o644, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    tar.addfile(info, io.BytesIO(raw))
                    members.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
    with tarfile.open(target, 'r:gz') as tar:
        actual = tar.getmembers()
        assert len(actual) == len(members)
        for info, expected in zip(actual, members):
            assert info.isfile() and info.name == expected['path']
            raw = tar.extractfile(info).read()
            assert len(raw) == expected['bytes'] and sha(raw) == expected['sha256']
    save(target.with_suffix(target.suffix + '.members.json'), {
        'archive': target.name, 'archive_bytes': target.stat().st_size,
        'archive_sha256': sha(target.read_bytes()),
        'scope': 'Exact regular-file bytes; archive uid/gid/mode/mtime normalized. No source data or failed observations rewritten.',
        'members_verified_by_full_readback': True, 'members': members})


def main():
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip() == SOURCE
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO)
    OUT.mkdir(exist_ok=False)
    val_dir = STAGING / 'validation/final-source-followup'
    fresh_dir = STAGING / 'fresh-work/final-source-run'
    shortcut_dir = STAGING / 'shortcuts/final-source-followup'
    val, fresh, shortcut = map(load, (val_dir / 'summary.json', fresh_dir / 'report.json', shortcut_dir / 'report.json'))
    assert val['status'] == 'PASS' and val['commands_passed'] == val['commands_planned'] == 21
    assert all(r['expected_source_sha'] == SOURCE for r in (val, fresh, shortcut))
    assert fresh['status'] == shortcut['status'] == 'complete_research_hold'
    assert not fresh['failures'] and not shortcut['failures']
    assert fresh['control_accounting_complete'] and fresh['primary_round_accounting_complete']
    assert fresh['verified_primary_attempts'] == fresh['planned_primary_attempts'] == 16
    assert shortcut['verified_attempts'] == shortcut['planned_rounds'] == 208
    assert fresh['exact_committed_source_verified'] and shortcut['exact_committed_source_verified']
    assert fresh['runner_sha256'] == val['fresh_native_runner_sha256']
    audits = {
        'final-native-audit.json': ROOT / 'fresh-native-review/final-native-audit.json',
        'final-theory-followup-audit.json': ROOT / 'fresh-native-review/final-theory-followup-audit.json',
        'final-shortcuts-followup-audit.json': STAGING / 'fresh-native-review/final-shortcuts-followup-audit.json',
        'original-shortcuts-independent-reconstruction.json': STAGING / 'fresh-native-review/final-shortcuts-audit.json',
    }
    for name, path in audits.items():
        assert load(path)['status'].startswith('PASS')
        copy(path, 'reviews/' + name)
    for name in ('summary.json', 'commands.json', 'plan.json', 'environment.json',
                 'source-before.json', 'source-after.json', 'runner-bindings.json'):
        copy(val_dir / name, 'validation/' + name)
    for name in ('report.json', 'plan.json', 'request.json', 'attempts.ndjson', 'controls.ndjson',
                 'hash-transcript.ndjson', 'native-exchanges.ndjson'):
        copy(fresh_dir / name, 'fresh-work/' + name)
    for name in ('report.json', 'plan.json', 'request.json', 'attempts.ndjson'):
        copy(shortcut_dir / name, 'shortcuts/' + name)
    archive('validation/complete-capture.tar.gz', [('final-validation', val_dir)])
    archive('fresh-work/complete-capture.tar.gz', [('final-source-run', fresh_dir)])
    archive('history/complete-history.tar.gz', [
        ('development', STAGING / 'development'),
        ('admission-wire-development', STAGING / 'admission-wire'),
        ('shortcuts-development', STAGING / 'shortcuts/development-run'),
        ('shortcuts-first-source', STAGING / 'shortcuts/final-source-run'),
        ('validation-first-source', STAGING / 'validation/final-source-run'),
        ('fresh-work-first-source', STAGING / 'fresh-work/source-run-01'),
        ('earlier-reviews', ROOT / 'fresh-native-review'),
        ('preparation-and-console', ROOT / 'fresh-work-observations'),
    ])
    # Keep the verified dependency restoration separately discoverable too.
    archive('provenance/offline-fuzz-metadata-repair.tar.gz', [
        ('fuzz-metadata-repair', ROOT / 'fresh-work-observations/fuzz-metadata-repair')])
    for name in ('readiness.json', 'development-failures.json', 'hardware-after-final-campaigns.json'):
        copy(ROOT / 'fresh-work-observations' / name, 'provenance/' + name)
    counts = {}
    for label in ('grouped-python-and-native', 'conditional-query-bound', 'fresh-query-floor',
                  'native-crypto-all-targets', 'native-header-binding', 'native-fresh-admission',
                  'source-integrity-controls', 'ci-contract-controls'):
        raw = (val_dir / (label + '.log')).read_text()
        python_counts = [int(n) for n in re.findall(r'^Ran (\d+) tests?', raw, re.M)]
        rust_counts = [int(n) for n in re.findall(r'^test result: ok\. (\d+) passed;', raw, re.M)]
        counts[label] = {'python_test_counts': python_counts, 'rust_passed_per_target': rust_counts,
                         'test_count': sum(python_counts) + sum(rust_counts),
                         'raw_log_sha256': sha((val_dir / (label + '.log')).read_bytes())}
    save(OUT / 'validation/test-counts.json', counts)
    attempts = fresh['attempts']
    nominal = {row['id']: row for row in shortcut['observations']}
    mac_totals = {key: row['preparation']['cost']['macs'] + sum(a['query_cost']['macs'] for a in row['attempts'])
                  for key, row in nominal.items()}
    native_audit = load(audits['final-native-audit.json'])
    acceptance = {
        'schema': 'pon-grouped-fresh-work-evidence-acceptance-v0',
        'engineering_evidence_status': 'PASS', 'work_profile_qualification': 'HOLD',
        'integration_base_commit': BASE, 'source_commit': SOURCE,
        'implementation_commit': 'b9ccd327b363335ae6c219fd73565ab4ccaa9f17',
        'final_source_followup': 'Only top-level theorem docstring changed; canonical proof hashing alone is not ticket multiplicity.',
        'validation': {'commands_passed': 21, 'commands_failed': 0, 'commands_not_started': 0,
            'strict_workspace_all_targets_all_features_clippy': 'PASS', 'full_workspace_unit_tests_executed': False,
            'original_service_campaign_executed': False, 'hosted_ci_on_this_source_executed': False},
        'shortcut_campaign': {'attempts': 208, 'verified': 208, 'distinct_challenges': 80,
            'real_model_original_inputs_attempts': 112, 'controlled_attempts': 96,
            'preparation_plus_16_round_mac_totals': mac_totals,
            'these_are_not_208_independent_lottery_queries': True},
        'fresh_work_campaign': {'primary_attempts': 16, 'verified': 16, 'hits': fresh['primary_target_hits'],
            'misses': 16 - fresh['primary_target_hits'], 'controls': len(fresh['controls']),
            'packets_and_receipts': fresh['receipt_count'], 'native_exchanges': len(fresh['native_exchanges']),
            'python_primary_crosscheck_step_hashes': 1024, 'python_untrusted_producer_step_hashes': 64,
            'native_producer_step_hashes_primary': 1024, 'cancelled_native_prefix_steps': 17,
            'fresh_neural_contractions_per_primary_nonce_after_prep': 0,
            'verification_reservations': 256, 'verification_spent': 83, 'verification_remaining': 0,
            'independent_audit_checks': len(native_audit['checks']),
            'native_proof_bytes': 134, 'capsule_bytes': 862, 'candidate_bytes': 742,
            'primary_packet_bytes': sorted({a['packet_bytes'] for a in attempts})},
        'observed_costs': {
            'campaign_wall_ns': fresh['whole_campaign_before_report']['wall_ns'],
            'parent_process_cpu_ns': fresh['parent_process_cpu_ns'],
            'all_children_cpu_seconds': fresh['child_user_seconds'] + fresh['child_system_seconds'],
            'native_child_cpu_seconds_subset': fresh['native_exit']['native_child_user_seconds'] + fresh['native_exit']['native_child_system_seconds'],
            'median_native_64_step_producer_wall_ns': statistics.median(a['native_producer']['native_seal_producer']['wall_ns'] for a in attempts),
            'median_independent_full_cell_wall_ns': statistics.median(a['transport_and_full_verification']['response']['stages']['independent_full_cell']['wall_ns'] for a in attempts),
            'median_tcp_full_receiver_roundtrip_wall_ns': statistics.median(a['transport_and_full_verification']['client_round_trip']['wall_ns'] for a in attempts),
            'cpu_or_wall_subtotals_are_not_additive': True,
            'isolation': 'uncontrolled shared host, validation and finite campaigns overlapped; finite observations, no throughput or physical-cost floor'},
        'claim_boundaries': {
            'classical_rom_aggregate_query_argument': 'conditional; includes preprocessing, delegation and verifier queries',
            'coalition_query_argument': 'conditional; real global caps, bounded award, canonical statement and hidden equality feedback are assumptions',
            'coalition_implementation_transfer_established': False,
            'global_verification_cap_enforced': False,
            'hidden_verifier_side_channel_model_verified': False,
            'minimum_fresh_neural_cost_proved': False,
            'physical_resource_lower_bound_proved': False,
            'quantum_security_proved': False,
            'external_demand_authenticated': False,
            'independent_operators': False,
            'production_proof_and_wan_availability_costs_complete': False,
            'proof_system_soundness_implies_work_hardness': False,
        },
        'new_gpu_allocations': 0, 'chainwork_awarded': 0, 'pow_qualified': False,
        'production_activation': False,
        'remote_delivery': {'status': 'BLOCKED', 'observation': 'GitHub connector returned HTTP403: account suspended',
                            'remote_branch_pushed': False, 'new_pull_request_created': False,
                            'alternate_access_path_attempted': False},
    }
    save(OUT / 'acceptance.json', acceptance)
    copy(Path(__file__), 'packaging.py')
    print(json.dumps({'output': str(OUT), 'engineering': 'PASS', 'qualification': 'HOLD',
                      'regular_files_so_far': sum(p.is_file() for p in OUT.rglob('*'))}))


if __name__ == '__main__':
    main()
