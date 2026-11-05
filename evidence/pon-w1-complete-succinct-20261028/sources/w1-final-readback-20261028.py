#!/usr/bin/env python3
"""Read actual saved W1 receipts, costs and frozen identities. No native execution."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path('/workspace/scratch/56818e4fba76/chain-w1-next')
CHECKPOINT = Path('/tmp/w1-staged-full-20261028-r3')
ORIGINAL = Path('/tmp/w1-full-90min-20261028')
CONTINUATION = Path('/tmp/w1-full-continuation-60min-20261028')
RECOVERY = Path('/tmp/w1-continuation-recovery-20261028')
OUT = Path('/tmp/w1-final-readback-20261028.json')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def stats(values):
    v = sorted(values)
    assert v
    return {'n': len(v), 'min_ns': v[0], 'median_ns': statistics.median(v),
            'p95_ns': v[math.ceil(.95 * len(v)) - 1], 'p99_ns': v[math.ceil(.99 * len(v)) - 1],
            'max_ns': v[-1], 'mean_ns': statistics.mean(v),
            'quantile_method': 'nearest rank; fixed-input samples, not population tails'}


def pon_hash(tag, *parts):
    h = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for p in parts:
        h.update(len(p).to_bytes(4, 'little') + p)
    return h.digest()


def main():
    recovery = read(RECOVERY / 'result.json')
    original = read(ORIGINAL / 'result.json')
    continuation = read(CONTINUATION / 'declaration.json')
    prefix = read(CONTINUATION / 'frozen-prefix-before-continuation.json')
    manifest = read(CHECKPOINT / 'manifest.json')
    entries = []
    for row in prefix:
        p = CHECKPOINT / row['path']
        data = p.read_bytes()
        append_only = row['path'] == 'stages.jsonl'
        checked = data[:row['bytes']] if append_only else data
        passed = len(checked) == row['bytes'] and hashlib.sha256(checked).hexdigest() == row['sha256']
        entries.append({**row, 'current_bytes': len(data), 'mode': 'preserved-prefix' if append_only else 'immutable', 'passed': passed})
    originals = []
    for path, expected in recovery['original_records_before'].items():
        originals.append({'path': path, 'expected': expected, 'actual_bytes': Path(path).stat().st_size,
                          'actual_sha256': sha(Path(path)), 'passed': Path(path).stat().st_size == expected['bytes'] and sha(Path(path)) == expected['sha256']})
    binaries = [{'path': path, 'expected_sha256': expected, 'actual_sha256': sha(Path(path)), 'passed': sha(Path(path)) == expected}
                for path, expected in continuation['binaries'].items()]
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=ROOT, text=True).splitlines()
    source_clean = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT) == b''
    header = (CHECKPOINT / 'header.bin').read_bytes()
    data = (CHECKPOINT / 'input.bin').read_bytes()
    journal = (CHECKPOINT / 'expected-journal.bin').read_bytes()
    trace = data[-32:]
    work_id = pon_hash(b'block', header, trace).hex()
    ticket = pon_hash(b'ticket', pon_hash(b'challenge', header), trace)
    offset = len(b'TRNM-W1-ZK-JOURNAL1\0') + 318
    public_checks = {
        'prefix_inventory_bound_to_original_declaration': sha(CONTINUATION / 'frozen-prefix-before-continuation.json') == continuation['prefix_inventory_sha256'],
        'manifest_is_original_prefix_manifest': sha(CHECKPOINT / 'manifest.json') == continuation['checkpoint_manifest_sha256'],
        'header_equals_input_prefix': len(header) == 318 and header == data[:318],
        'input_manifest': len(data) == 49506 and sha(CHECKPOINT / 'input.bin') == manifest['input_sha256'],
        'journal_manifest': len(journal) == 16818 and sha(CHECKPOINT / 'expected-journal.bin') == manifest['journal_sha256'],
        'guest_manifest': sha(CHECKPOINT / 'guest.bin') == manifest['guest_sha256'],
        'journal_domain_header': journal[:offset] == b'TRNM-W1-ZK-JOURNAL1\0' + header,
        'journal_trace': journal[offset:offset + 32] == trace,
        'journal_ticket': journal[offset + 32:offset + 64] == ticket,
        'journal_work_id': journal[offset + 64:offset + 96].hex() == work_id,
        'journal_product_equals_original_witness_product': journal[offset + 96:] == data[318 + 4 + 2 * 4096 * 4:-32],
        'nonzero_target_and_ticket': header[118:150] != bytes(32) and ticket <= header[118:150],
    }
    reports = {}
    for label in recovery['fresh_stage_plan']:
        p = RECOVERY / label / 'stdout.log'
        if p.is_file() and p.read_text().strip():
            reports[label] = read(p)
    hardened = reports['hardened-verifier-100']
    old = reports['original-verifier-100']
    native = reports['native-verifier-1000']
    controls = read(RECOVERY / 'full-negative-control-assets/result.json')
    expected_controls = {'valid', 'trailing', 'truncated', 'declared_seal_length_overflow', 'composite_tag', 'groth16_tag', 'fake_tag', 'wrong_header',
                         'control_id', 'verifier_parameters', 'hash_function', 'claim_digest', 'seal_first', 'seal_body', 'seal_last', 'seal_empty', 'seal_short', 'seal_invalid_field'}
    expected_controls.update(f'journal_byte_{n}' for n in [0, len(b'TRNM-W1-ZK-JOURNAL1\0'), offset, offset + 32, offset + 64, len(journal) - 1])
    control_asset_checks = []
    for row in controls['cases']:
        name = row['name']
        assert name in expected_controls
        for suffix, key in [('receipt', 'receipt_sha256'), ('header', 'header_sha256')]:
            asset = RECOVERY / 'full-negative-control-assets' / f'{name}.{suffix}'
            control_asset_checks.append({'path': str(asset), 'sha256': sha(asset), 'passed': sha(asset) == row[key]})
    exact_controls = len(controls['cases']) == 24 and len({x['name'] for x in controls['cases']}) == 24 and {x['name'] for x in controls['cases']} == expected_controls
    exact_controls = exact_controls and sum(x['expected'] == 'ACCEPT' for x in controls['cases']) == 1 and sum(x['expected'] == 'REJECT' for x in controls['cases']) == 23
    exact_controls = exact_controls and all(x['observed']['outcome'] == x['expected'] for x in controls['cases']) and all(x['passed'] for x in control_asset_checks)
    expected_stages = ['fresh-original-full-gate', 'original-verifier-100', 'native-verifier-1000', 'fresh-hardened-full-gate', 'hardened-verifier-100', 'hardened-controls-1-positive-23-negative']
    exact_stages = [x['stage'] for x in recovery['stages']] == expected_stages and all(x['result']['returncode'] == 0 and x['result']['timed_out'] is False and x['result']['process_group_remaining_after_child_exit'] is False for x in recovery['stages'])
    native_stats = stats(native['native_full_verifier_ns'])
    costs = {'native_full_replay': native_stats,
             'sdk_3_0_3_verify_only': stats(old['verifier_ns']), 'sdk_3_0_3_decode_and_verify': stats(old['decode_verify_ns']),
             'sdk_3_0_6_verify_only': stats(hardened['verifier_ns']), 'sdk_3_0_6_decode_and_verify': stats(hardened['decode_verify_ns'])}
    statement_gates = {
        'original_fresh_work_id': reports['fresh-original-full-gate']['work_id'] == work_id,
        'original_repeated_work_id': old['work_id'] == work_id,
        'hardened_fresh_work_id': reports['fresh-hardened-full-gate']['work_id'] == work_id,
        'hardened_repeated_work_id': hardened['work_id'] == work_id,
        'hardened_original_image': hardened['image_id'] == manifest['image_id'],
        'hardened_journal_hash': hardened['journal_sha256'] == manifest['journal_sha256'],
        'hardened_receipt_hash': hardened['receipt_sha256'] == sha(CHECKPOINT / 'succinct.bin'),
        'native_same_full_input': native['input_sha256'] == manifest['input_sha256'],
        'all_controls_expected': controls['all_passed'] is True and exact_controls and all(x['passed'] for x in controls['cases']),
    }
    original_cost = read(Path('/tmp/w1-original-90min-cost-ledger-20261028.json'))
    assert original_cost['rounds'][0]['record_sha256'] == sha(ORIGINAL / 'result.json')
    reverification = read(CONTINUATION / 'proof-run/reverify-existing-prefix/result.json')
    additional_cpu = sum(x['result']['rusage']['user_seconds'] + x['result']['rusage']['system_seconds'] for x in recovery['stages'])
    prior_proc = {}
    for line in Path('/tmp/w1-proc-observer-continuation-20261028/samples.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row['stage'] != 'complete-recursive-compression':
            continue
        for p in row['processes']:
            key = (p['pid'], p['birth_ticks'])
            prior_proc[key] = max(prior_proc.get(key, 0), p['user_ticks'] + p['system_ticks'])
    old_observer_hz = read(Path('/tmp/w1-proc-observer-continuation-20261028/declaration.json'))['clock_ticks_per_second']
    old_observer_cpu = sum(prior_proc.values()) / old_observer_hz
    compression_cpu = max(old_observer_cpu, recovery['observed_orphan_cpu_lower_bound_seconds'])
    reverification_cpu = reverification['rusage']['user_seconds'] + reverification['rusage']['system_seconds']
    cpu_parts = {'original_90min_pipeline_including_priors': original_cost['paid_cpu_lower_bound_seconds'],
                 'continuation_completed_prefix_reverification': reverification_cpu,
                 'continuation_interrupted_compression_lower_bound': compression_cpu,
                 'fresh_gate_and_control_stages_wait4': additional_cpu,
                 'known_continuation_preflight_process_cpu': continuation['prefix_and_source_preflight_cpu_seconds']}
    events = [json.loads(line) for line in (CHECKPOINT / 'stages.jsonl').read_text().splitlines()]
    final_events = [r for r in events if r['event'].get('stage') == 'FULL_SUCCINCT_STARK_SAVED_VERIFIED']
    all_identity_checks = all(public_checks.values()) and all(statement_gates.values()) and all(x['passed'] for x in entries + originals + binaries) and source == [continuation['source_commit'], continuation['source_tree']] and source_clean
    proof_bytes = (CHECKPOINT / 'succinct.bin').stat().st_size
    native_bytes = len(data) - len(header)
    ratio = costs['sdk_3_0_6_verify_only']['median_ns'] / native_stats['median_ns']
    decode_ratio = costs['sdk_3_0_6_decode_and_verify']['median_ns'] / native_stats['median_ns']
    report = {'schema': 'TRNM-W1-FULL-SUCCINCT-FINAL-READBACK1', 'readback_unix_ns': time.time_ns(),
              'frozen_prover_source': manifest['source_commit'], 'frozen_hardened_verifier_source': 'dd4fb0a65a734bdccac23a061dc0d6c72b69188f',
              'observed_post_gate_source': source, 'post_gate_git_clean': source_clean,
              'source_unchanged': source == [continuation['source_commit'], continuation['source_tree']] and source_clean,
              'original_90min_result': {'outcome': 'TIMEOUT', 'sha256': sha(ORIGINAL / 'result.json'), 'error': original['error'], 'complete_proof_claim': original['complete_proof_claim']},
              'original_continuation_controller_outcome': 'UNKNOWN_INTERRUPTED_NO_TERMINAL_RECORD',
              'original_controller_exit_code': None, 'original_compression_wait4_record': None,
              'recovery_error': recovery['error'], 'recovery_all_declared_fresh_stages_completed': recovery['all_declared_fresh_stages_completed'],
              'recovery_fresh_gates': recovery['fresh_gates'], 'exact_six_fresh_stage_results_passed': exact_stages,
              'recovery_observation_gap_seconds': recovery['observation_gap_seconds'],
              'original_compression_deadline_unix_ns': recovery['original_compression_deadline_unix_ns'],
              'original_total_deadline_unix_ns': recovery['original_total_deadline_unix_ns'],
              'original_total_elapsed_until_fresh_gates_seconds': recovery['new_total_elapsed_from_original_start_seconds'],
              'new_wall_budget_granted_seconds': 0,
              'original_prefix_checks': entries, 'original_record_checks': originals, 'binary_checks': binaries,
              'public_statement_checks': public_checks, 'fresh_cryptographic_statement_checks': statement_gates,
              'all_identity_checks_passed': all_identity_checks,
              'complete_full_succinct_verified': recovery['complete_proof_claim'] and all_identity_checks,
              'full_proof_bytes': proof_bytes, 'full_proof_sha256': sha(CHECKPOINT / 'succinct.bin'),
              'native_witness_bytes': native_bytes, 'header_bytes': len(header), 'journal_bytes': len(journal), 'full_input_bytes': len(data),
              'proof_size_over_native_witness': proof_bytes / native_bytes,
              'work_id': work_id, 'ticket_hex': ticket.hex(), 'proof_randomness_tickets': 0,
              'full_segments': len(manifest['segments']), 'final_complete_events': final_events,
              'fixed_receipt_and_input_costs': costs, 'hardened_verify_median_over_native': ratio,
              'hardened_decode_verify_median_over_native': decode_ratio,
              'cost_comparison_scope': 'Native replay includes native input decoding; the preferred comparison is receipt decode-and-verify. All timings exclude file IO, native excludes additional experimental public-journal construction.',
              'controls': {'total': len(controls['cases']), 'expected_accept': sum(x['expected'] == 'ACCEPT' for x in controls['cases']), 'expected_reject': sum(x['expected'] == 'REJECT' for x in controls['cases']), 'all_passed': controls['all_passed'], 'panics': sum(x['observed']['outcome'] == 'PANIC' for x in controls['cases'])},
              'control_asset_hash_checks': control_asset_checks,
              'cpu_lower_bound_parts_seconds': cpu_parts, 'total_pipeline_cpu_lower_bound_seconds': sum(cpu_parts.values()),
              'continuation_old_observer_compression_lower_bound_seconds': old_observer_cpu,
              'continuation_recovered_root_and_reaped_lower_bound_seconds': recovery['observed_orphan_cpu_lower_bound_seconds'],
              'cpu_observations_combined_by_max_not_addition': True, 'prover_exact_cpu_cost_known': False,
              'maximum_observed_single_process_rss_bytes': original_cost['maximum_single_process_rss_bytes'],
              'staged_controller_and_prior_plus_continuation_wall_seconds': original_cost['controller_and_prior_wall_seconds'] + recovery['new_total_elapsed_from_original_start_seconds'],
              'included_coordinated_pause_seconds': original['coordinated_pause_seconds'],
              'wall_scope': 'Sum of recorded original controller/prior durations and original continuation elapsed; includes declared pause and observation gap, excludes unmeasured gap between rounds. Not isolated prover latency.',
              'resource_scope': 'Shared 8 CPU / 8 GiB cgroup, one original dense maximum-target input; build/control/historical earlier failed experiment costs remain separate, not hidden as a new proof trial.',
              'independent_proof_trials': 1, 'prover_p99_established': False, 'production_verifier_tail_established': False,
              'single_work_benefit_gate_passed': proof_bytes < native_bytes and decode_ratio < 1,
              'full_work_package_2a_accepted': False, 'post_quantum_soundness_qualified': False,
              'consensus_admission': False, 'production_qualification': False}
    with OUT.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ['complete_full_succinct_verified', 'all_identity_checks_passed', 'full_proof_bytes', 'native_witness_bytes', 'proof_size_over_native_witness', 'hardened_verify_median_over_native', 'controls', 'total_pipeline_cpu_lower_bound_seconds', 'single_work_benefit_gate_passed']}))


if __name__ == '__main__':
    main()
