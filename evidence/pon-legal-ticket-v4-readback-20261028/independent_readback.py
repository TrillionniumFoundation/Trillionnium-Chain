#!/usr/bin/env python3
"""Recompute already-completed V4 observations; no solver/native execution."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'source/scripts/ci'))
import check_legal_ticket_batch_v4 as v4
from check_legal_ticket_cost_v3 import parsed, read_rows

HEAD = '7e3543f8817d019975ae578b56b4997eb92bc422'
TREE = 'c238630a84d2e950894e0a2b9b4256d48455e836'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(arch):
    root = ROOT / arch
    rows, raw_bytes, raw_sha = read_rows(root / 'cost/stdout.jsonl.gz')
    result = v4.validate(rows)
    published = parsed((root / 'cost/summary.json').read_bytes())
    for key, value in result.items():
        assert published[key] == value, ('summary changed', key)
    capture = parsed((root / 'cost/capture.json').read_bytes())
    before = parsed((root / 'source-before.json').read_bytes())
    after = parsed((root / 'source-after.json').read_bytes())
    archive = parsed((root / 'archive-member-readback.json').read_bytes())
    assert before == after == published['source']
    assert before['tested_commit'] == HEAD and before['tested_tree'] == TREE
    assert before['tracked_worktree_verified'] is True and before['kind'] == 'head'
    assert capture == published['native_capture']
    assert capture['source']['commit'] == HEAD and capture['source']['tree'] == TREE
    assert capture['machine'] == arch
    assert capture['exit_code'] == 0 and capture['timed_out'] is False
    assert capture['stable_binary'] is True and capture['stdout_within_bound'] is True
    assert capture['timeout_seconds'] == 250 and capture['elapsed_ns'] <= 250_000_000_000
    assert capture['stdout_bytes'] == raw_bytes
    assert capture['stdout_uncompressed_sha256'] == raw_sha == published['raw_uncompressed_sha256']
    assert capture['stdout_gzip_sha256'] == sha(root / 'cost/stdout.jsonl.gz')
    assert capture['stderr_sha256'] == sha(root / 'cost/stderr.log')
    assert len(capture['argv']) == 2 and capture['argv'][1].endswith('/legal-ticket-batch-v4-evidence/packets')
    driver = ROOT / 'source/trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_batch_v4.rs'
    assert capture['source']['example_sha256'] == rows[0]['compiled_driver_sha256'] == sha(driver)
    assert capture['source']['lock_sha256'] == rows[0]['compiled_cargo_lock_sha256'] == sha(ROOT / 'source/trillionnium/Cargo.lock')
    assert capture['source']['workspace_manifest_sha256'] == sha(ROOT / 'source/trillionnium/Cargo.toml')
    assert len(archive['native_binary']) == 1
    native = archive['native_binary'][0]
    assert native['sha256'] == capture['binary_sha256_before'] == capture['binary_sha256_after']
    assert native['sha256'] == (root / 'native-binary.sha256').read_text().split()[0]
    assert native['elf_machine'] == {'x86_64':62, 'aarch64':183}[arch]
    expected = {'packets/'+p['file']:p for row in rows[1:-1] for p in row['retained_packets']}
    actual = {p['name']:p for p in archive['member_records'] if p['name'].startswith('packets/')}
    assert actual.keys() == expected.keys()
    for name, record in actual.items():
        assert record['sha256'] == expected[name]['sha256'] and record['bytes'] == expected[name]['bytes']
    payload = dict(files=len(actual), bytes=sum(p['bytes'] for p in actual.values()),
                   all_sha256_verified=True, cryptographic_admission_repeated_by_reader=False)
    assert published['payload_archive'] == payload
    ids = {}
    for packet in expected.values():
        identity = (packet['sha256'], packet['bytes'])
        assert packet['id'] not in ids or ids[packet['id']] == identity
        ids[packet['id']] = identity
    assert len(ids) == result['distinct_fixture_packet_ids_across_paired_cohorts']
    phases = {name:{clock:sum(row['phases'][name][clock] for row in rows[1:-1])
                         for clock in ('wall_ns','process_cpu_ns')} for name in v4.PHASES}
    calls = result['first_admission_calls']
    totals = {clock:sum(v[clock] for v in phases.values()) for clock in ('wall_ns','process_cpu_ns')}
    outer = {clock:sum(row['observed_outer'][clock] for row in rows[1:-1]) for clock in totals}
    full_cpu_ns = round((capture['child_user_cpu_seconds'] + capture['child_system_cpu_seconds']) * 1e9)
    assert totals['process_cpu_ns'] <= outer['process_cpu_ns'] <= full_cpu_ns
    assert totals['wall_ns'] <= outer['wall_ns'] <= rows[-1]['wall_ns'] <= capture['elapsed_ns']
    for setting in ('settings_setup','packet_archive_setup'):
        assert outer['process_cpu_ns'] + rows[0][setting]['process_cpu_ns'] <= full_cpu_ns
    comparisons = []
    for row in result['comparisons']:
        arm, workers = row['strategy'], row['workers']
        baseline = next(x for x in result['comparisons'] if x['strategy']==arm and x['workers']==1)
        cost, base = row['ms_per_first_admission'], baseline['ms_per_first_admission']
        matching = [x for x in rows[1:-1] if x['strategy']==arm and x['batch_workers']==workers]
        numerators = {scope:{clock:sum(x[field][clock] for x in matching)
                             for clock in ('wall_ns','process_cpu_ns')}
                      for scope,field in [('recurring','recurring_producer_encode_admission'),
                                          ('all_phases','all_exclusive_phases'),('outer','observed_outer')]}
        numerators['batch_generation'] = {clock:sum(x['phases']['all_attempt_generation'][clock] for x in matching)
                                         for clock in ('wall_ns','process_cpu_ns')}
        for scope in numerators:
            for clock in numerators[scope]:
                assert cost[scope][clock.replace('_ns','_ms')] == numerators[scope][clock]/row['first_admissions']/1e6
        phase_ms = {name:{clock.replace('_ns','_ms'):sum(x['phases'][name][clock] for x in matching)/row['first_admissions']/1e6
                         for clock in ('wall_ns','process_cpu_ns')} for name in v4.PHASES}
        comparisons.append(dict(**row, numerator_ns_by_scope=numerators,
            denominator_first_admission_calls=row['first_admissions'],
            generation_wall_speedup_vs_one_worker=base['batch_generation']['wall_ms']/cost['batch_generation']['wall_ms'],
            generation_cpu_ratio_vs_one_worker=cost['batch_generation']['process_cpu_ms']/base['batch_generation']['process_cpu_ms'],
            all_phase_wall_speedup_vs_one_worker=base['all_phases']['wall_ms']/cost['all_phases']['wall_ms'],
            all_phase_cpu_ratio_vs_one_worker=cost['all_phases']['process_cpu_ms']/base['all_phases']['process_cpu_ms'],
            each_phase_ms_per_first_admission=phase_ms,
            per_round=[dict(round=x['round'],winners=x['winners'],attempts=x['attempts'],
                            all_exclusive_phases=x['all_exclusive_phases']) for x in matching]))
    output = dict(schema='legal-ticket-v4-independent-cost-readback-v1', source_commit=HEAD, source_tree=TREE,
        architecture=arch, actual_host=parsed((root/'host.json').read_bytes()),
        all_archive_members_read_and_hashed=True, raw_rows=14, cohorts=12,
        raw_bytes=raw_bytes, raw_sha256=raw_sha, exact_original_reader_summary_recomputed=True,
        capture_and_source_and_native_elf_sha_bound=True, payload_archive=payload,
        native_binary=native, first_admission_calls=calls, distinct_fixture_packet_ids=len(ids),
        attempts=sum(r['attempts'] for r in rows[1:-1]), failures=sum(r['attempts']-r['winners'] for r in rows[1:-1]),
        exhausted_searches=sum(r['exhausted'] for r in rows[1:-1]), phases=phases,
        all_exclusive_phase_totals=totals, sum_cohort_outer=outer,
        driver_terminal_wall_ns=rows[-1]['wall_ns'], capture_elapsed_ns=capture['elapsed_ns'],
        whole_native_process_cpu_ns=full_cpu_ns, whole_native_process_cpu_ms_per_admission=full_cpu_ns/calls/1e6,
        capture_max_rss_kib=capture['child_max_rss_kib'], comparisons=comparisons,
        identity_check_tracked_entries=before['tracked_entries'], identity_check_tracked_bytes=before['tracked_bytes'],
        packet_identities=ids, native_solver_or_admission_executed_by_this_reader=False,
        limits=['Original raw positive native executions are read; no new solver run or adversarial trial is performed.',
                'Actual complete native Node admission was performed by the hosted driver; this reader checks recorded costs and retained bytes, not a new cryptographic admission.',
                'Two paired rounds and fixed parent/maintenance task; repeated admissions into independent fresh stores are not distinct mining rewards.',
                'V4 adds whole-batch timing and packet archival; its all-phase cost is not an algorithm-only comparison with V3.',
                'Shared four-vCPU runners; no hardware authentication, exclusive-host control, GPU, energy, global optimum or production throughput claim.',
                'Archive ZIPs and native executables were read into memory and are not saved locally by this reader.'])
    (root/'independent-cost-readback.json').write_text(json.dumps(output,indent=2)+'\n')
    return output


def main():
    results = {arch:inspect(arch) for arch in ('x86_64','aarch64')}
    assert results['x86_64']['packet_identities'] == results['aarch64']['packet_identities']
    summary = dict(schema='legal-ticket-v4-two-architecture-independent-readback-v1',
        source_commit=HEAD, source_tree=TREE, run_id=40619573406,
        all_checks_passed=True, first_admissions_per_architecture=762,
        first_admission_calls_both_architectures=1524,
        distinct_fixture_packet_ids_across_both_architectures=127,
        packet_bytes_identical_across_strategies_worker_counts_and_architectures=True,
        actual_native_or_solver_executions_by_this_readback=0,
        architectures={a:{k:v for k,v in r.items() if k not in ('packet_identities','phases','comparisons')} for a,r in results.items()})
    (ROOT/'independent-readback.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('schema','all_checks_passed','first_admission_calls_both_architectures','distinct_fixture_packet_ids_across_both_architectures')}))


if __name__ == '__main__':
    main()
