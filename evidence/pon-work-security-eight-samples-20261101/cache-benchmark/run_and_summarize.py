#!/usr/bin/env python3
"""Interleave three fresh-process pairs and retain exact raw observations."""
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

OUT = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def check_sources(entry, common):
    harness = Path(entry['harness'])
    assert digest(entry['elf']) == entry['elf_sha256']
    assert digest(harness / 'Cargo.lock') == entry['lock_sha256']
    assert digest(harness / 'src/main.rs') == common['same_harness_main_sha256']
    assert digest(harness / 'Cargo.toml') == common['same_manifest_sha256']
    for source in entry['sources']:
        assert digest(harness / source['harness_path']) == source['sha256']
    return {'source_files': len(entry['sources']), 'source_verified': True,
            'elf_sha256': entry['elf_sha256'], 'lock_sha256': entry['lock_sha256']}

def main():
    manifest = json.loads((OUT / 'build-manifest.json').read_text())
    runs = []
    all_rows = []
    fixture_identity = {}
    plan = [(1, 'baseline'), (1, 'candidate'), (2, 'candidate'),
            (2, 'baseline'), (3, 'baseline'), (3, 'candidate')]
    for ordinal, (round_number, variant) in enumerate(plan, 1):
        entry = manifest['variants'][variant]
        before = check_sources(entry, manifest)
        command = [entry['elf'], variant, str(round_number)]
        stem = f'run-{ordinal:02d}-{variant}-round-{round_number}'
        started = time.time_ns()
        with (OUT / (stem + '.jsonl')).open('wb') as stdout, (OUT / (stem + '.stderr')).open('wb') as stderr:
            process = subprocess.run(command, cwd=entry['harness'], stdout=stdout, stderr=stderr, timeout=300)
        ended = time.time_ns()
        after = check_sources(entry, manifest)
        receipt = {'ordinal': ordinal, 'round': round_number, 'variant': variant,
                   'command': command, 'cwd': entry['harness'], 'exit_code': process.returncode,
                   'started_unix_ns': started, 'finished_unix_ns': ended,
                   'source_before': before, 'source_after': after,
                   'stdout_sha256': digest(OUT / (stem + '.jsonl')),
                   'stderr_sha256': digest(OUT / (stem + '.stderr'))}
        (OUT / (stem + '.receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
        runs.append(receipt)
        (OUT / 'runs.json').write_text(json.dumps(runs, indent=2) + '\n')
        assert process.returncode == 0, f'{stem}: retained nonzero process result'
        rows = [json.loads(line) for line in (OUT / (stem + '.jsonl')).read_text().splitlines()]
        assert len(rows) == 31
        measurements = [row for row in rows if row['kind'] == 'measurement']
        assert len(measurements) == 24
        assert len({(row['seed'], row['case']) for row in measurements}) == 24
        for row in measurements:
            assert row['variant'] == variant and row['round'] == round_number
            assert row['calls'] == 128 and row['all_results_and_paths_checked'] is True
            assert row['call_cpu_ns'] > 0 and row['call_wall_ns'] > 0
            assert not any(row[k] for k in ['attacker_cost_measurement', 'whole_workspace_qualified',
                                          'host_qualified', 'public_service_qualified'])
        for row in rows:
            if row['kind'] != 'fixture':
                continue
            key = (row['seed'], row['index'])
            identity = {k: row[k] for k in ['challenge', 'task', 'valid_sha256',
                                           'false_trace_sha256', 'last_product_sha256',
                                           'expected_product_sha256']}
            if key in fixture_identity:
                assert fixture_identity[key] == identity
            else:
                fixture_identity[key] = identity
        all_rows.extend(measurements)
        print(stem, 'PASS', sum(row['call_cpu_ns'] for row in measurements), 'call CPU ns', flush=True)
    grouped = {}
    for case in sorted({row['case'] for row in all_rows}):
        pairs = []
        seed_pairs = []
        for round_number in [1, 2, 3]:
            selected = [row for row in all_rows if row['case'] == case and row['round'] == round_number]
            baseline = [row for row in selected if row['variant'] == 'baseline']
            candidate = [row for row in selected if row['variant'] == 'candidate']
            base_cpu = sum(row['call_cpu_ns'] for row in baseline)
            next_cpu = sum(row['call_cpu_ns'] for row in candidate)
            base_wall = sum(row['call_wall_ns'] for row in baseline)
            next_wall = sum(row['call_wall_ns'] for row in candidate)
            pairs.append({'round': round_number, 'calls_per_variant': 384,
                          'baseline_cpu_ns': base_cpu, 'candidate_cpu_ns': next_cpu,
                          'candidate_over_baseline_cpu': next_cpu / base_cpu,
                          'candidate_over_baseline_wall': next_wall / base_wall})
            for seed in [7, 19, 43]:
                b = next(row for row in baseline if row['seed'] == seed)
                c = next(row for row in candidate if row['seed'] == seed)
                seed_pairs.append({'round': round_number, 'seed': seed,
                                   'candidate_over_baseline_cpu': c['call_cpu_ns'] / b['call_cpu_ns']})
        ratios = [row['candidate_over_baseline_cpu'] for row in pairs]
        grouped[case] = {'paired_rounds': pairs, 'paired_seed_rounds': seed_pairs,
                         'minimum_round_cpu_ratio': min(ratios), 'maximum_round_cpu_ratio': max(ratios),
                         'median_round_cpu_ratio': statistics.median(ratios),
                         'total_calls_per_variant': 1152}
    cpu_model = None
    if Path('/proc/cpuinfo').exists():
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                cpu_model = line.split(':', 1)[1].strip()
                break
    summary = {'schema': 'pon-arithmetic-cache-selected-source-diagnostic-summary-v1',
               'run_order': plan, 'runs': len(runs), 'measurement_rows': len(all_rows),
               'complete_calls': sum(row['calls'] for row in all_rows), 'semantic_alerts': 0,
               'actual_transcript_replays': sum(row['transcript_replays'] for row in all_rows),
               'actual_products_completed': sum(row['products_completed'] for row in all_rows),
               'distinct_seed_materials': 3, 'distinct_challenges_per_seed': 2,
               'repeated_rounds_are_not_new_independent_samples': True,
               'platform': platform.uname()._asdict(), 'cpu_model': cpu_model,
               'logical_cpus': os.cpu_count(), 'cases': grouped,
               'qualification': manifest['qualification'],
               'limitations': [
                   'Only selected W1 sources, not the original full workspace or deployed binary.',
                   'Unmodified default Cargo release with exact workspace registry versions; all source and ELF hashes retained.',
                   'One local x86 host; no ARM, physical power, fixed public Host, WAN or full service measurement.',
                   'All-ff diagnostic target, fixture construction/prefill recorded separately; no grinding or cheapest-attacker cost claim.',
                   'Capacity-1 eviction alternates two exact challenges; it is not a growing unique challenge campaign.',
                   'Result vectors are preallocated, complete outputs retained during timing; exact result/path checks run after timing.',
                   'No acceptance threshold or proof-of-work security claim follows from implementation ratios.',
               ]}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({case: {key: value[key] for key in ['minimum_round_cpu_ratio', 'maximum_round_cpu_ratio', 'median_round_cpu_ratio']}
                      for case, value in grouped.items()}, indent=2))

if __name__ == '__main__':
    main()
