#!/usr/bin/env python3
"""Read original 7d campaign samples; never execute or relabel a newer campaign."""
from pathlib import Path
import hashlib
import json
import subprocess
import zipfile

ARCHIVE = Path('/workspace/scratch/0654386882cd/validation/hosted-baseline-readback/artifact-13820807612/payload.zip')
EXPECTED_ARCHIVE = 'f06c618a51693b79fd8d7b7c910b5ce3dad96c1ee73901535688766f57b93b1a'
SOURCE = '7d6567b92575d1d84766afd49d0720b6f197b0e0'
CURRENT = '11e242dbaaae14a9d16282fe8deaf36827e98395'
ROOT = Path('/workspace/scratch/0b53202edbbf/chain-throughput')
OUTPUT = Path('/workspace/scratch/0b53202edbbf/validation/original-7d-depletion-sample-readback.json')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git_bytes(commit, relative):
    return subprocess.check_output(['git', 'show', commit + ':' + relative], cwd=ROOT)

digest = hashlib.sha256()
with ARCHIVE.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
assert digest.hexdigest() == EXPECTED_ARCHIVE
test_path = 'trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs'
test_bytes = git_bytes(SOURCE, test_path)
assert test_bytes == git_bytes(CURRENT, test_path)
result = {
    'schema': 'original-native-campaign-depletion-sample-readback-v1',
    'source': SOURCE, 'reviewed_current_source': CURRENT,
    'scope': 'Existing source-bound receiver budget samples only; no current-source campaign, inter-sample exclusion proof, TPS or qualification',
    'artifact_id': 13820807612, 'artifact_bytes': ARCHIVE.stat().st_size,
    'artifact_sha256': digest.hexdigest(),
    'unchanged_campaign_test': {'path': test_path, 'sha256': sha(test_bytes)},
    'phases': [],
}
with zipfile.ZipFile(ARCHIVE) as archive:
    for run in (1, 2, 3):
        for mode in ('baseline', 'from-zero', 'late-product'):
            member = f'run-{run}-raw/{mode}.json'
            raw = archive.read(member)
            phase = json.loads(raw)
            summary = {'run': run, 'mode': mode, 'member': member, 'raw_bytes': len(raw),
                       'raw_sha256': sha(raw), 'samples': len(phase['budget_samples']),
                       'unknown_meter_samples': 0, 'missing_flow_samples': 0,
                       'observed_depleted_samples': 0, 'computed_depleted_samples': 0,
                       'debit_above_original_threshold_samples': 0,
                       'minimum_paid_credit': None, 'maximum_paid_debit': None,
                       'balance_or_predicate_mismatches': 0}
            for sample in phase['budget_samples']:
                meter_observation = sample['meter'].get('Ok')
                if meter_observation is None:
                    summary['unknown_meter_samples'] += 1
                    continue
                flow = meter_observation.get('actual_flow')
                if flow is None:
                    summary['missing_flow_samples'] += 1
                    continue
                meter = meter_observation['meter']
                assert meter['burst_ns'] == 2_000_000_000
                assert meter['start_reserve_ns'] == 100_000_000
                assert meter['refill_ns_per_second'] == 250_000_000
                paid = flow['remaining_paid_credit_ns']
                debit = flow['paid_cpu_debit_ns']
                computed = (flow['balance_identity_verified'] is True
                            and flow['initial_credit_ns'] == meter['burst_ns']
                            and paid < meter['start_reserve_ns']
                            and debit > meter['burst_ns'] - meter['start_reserve_ns']
                            and meter_observation['clock_failures'] == 0
                            and meter['accounting_unavailable'] is False)
                balanced = (flow['initial_credit_ns'] + flow['credited_refill_ns']
                            - debit - flow['settlement_discard_ns'] == paid)
                summary['observed_depleted_samples'] += meter_observation['depleted'] is True
                summary['computed_depleted_samples'] += computed
                summary['debit_above_original_threshold_samples'] += debit > 1_900_000_000
                summary['balance_or_predicate_mismatches'] += (
                    not balanced or computed != meter_observation['depleted'])
                record = {'sample_at_ns': sample['at_ns'], 'paid_credit_ns': paid,
                          'paid_debit_ns': debit, 'credited_refill_ns': flow['credited_refill_ns'],
                          'settlement_discard_ns': flow['settlement_discard_ns']}
                if summary['minimum_paid_credit'] is None or paid < summary['minimum_paid_credit']['paid_credit_ns']:
                    summary['minimum_paid_credit'] = record
                if summary['maximum_paid_debit'] is None or debit > summary['maximum_paid_debit']['paid_debit_ns']:
                    summary['maximum_paid_debit'] = record
            result['phases'].append(summary)
for key in ('samples', 'unknown_meter_samples', 'missing_flow_samples',
            'observed_depleted_samples', 'computed_depleted_samples',
            'debit_above_original_threshold_samples', 'balance_or_predicate_mismatches'):
    result[key] = sum(phase[key] for phase in result['phases'])
result['minimum_paid_credit_ns'] = min(phase['minimum_paid_credit']['paid_credit_ns'] for phase in result['phases'])
assert result['unknown_meter_samples'] == result['missing_flow_samples'] == 0
assert result['balance_or_predicate_mismatches'] == 0
with OUTPUT.open('x') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
print(json.dumps({key: value for key, value in result.items() if key != 'phases'}))
