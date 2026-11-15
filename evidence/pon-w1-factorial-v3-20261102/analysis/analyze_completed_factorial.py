#!/usr/bin/env python3
"""Read-only analysis of a FINISHED, source-pinned V3 factorial receipt.

Never invoke while the native campaign is running. Manifest absence/incomplete
coverage fails closed. Cost totals below are observations, never qualification.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import importlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys

sys.dont_write_bytecode = True
STRATEGIES = ('eager-transposed', 'lazy-transposed', 'eager-full-limb', 'lazy-full-limb')
FACTORS = ((0, 1, 'lazy_vs_eager_transposed'), (2, 3, 'lazy_vs_eager_full_limb'),
           (0, 2, 'full_limb_vs_transposed_eager'), (1, 3, 'full_limb_vs_transposed_lazy'))
FLAGS = ('hardness_accepted', 'work_profile_qualified', 'resource_fairness_qualified',
         'public_service_measured', 'independent_hardware_qualified',
         'public_network_ready', 'production_activation')
READER_FILES = ('scripts/pon_w1_legal_strategy_reader_v3.py',
                'scripts/pon_w1_cost_matrix_reader.py',
                'config/pon/work-security-acceptance-v1.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def pct(base, candidate):
    return None if not base else 100.0 * (candidate - base) / base


def effects(rows, key):
    values = [r[key] for r in rows]
    result = {}
    for a, b, name in FACTORS:
        result[name] = dict(baseline_ns=values[a], candidate_ns=values[b],
                            delta_ns=values[b]-values[a], percent_change=pct(values[a], values[b]))
    result['interaction_ns'] = (values[3]-values[2])-(values[1]-values[0])
    result['joint_lazy_full_limb_vs_eager_transposed_percent_change'] = pct(values[0], values[3])
    return result


def matched_sample_effects(costs):
    by_strategy = {r['strategy']: {t['sample']: t['cpu_ns'] for t in r['per_sample_cohort_totals']}
                   for r in costs}
    expected_samples = set(range(8))
    require(all(set(m) == expected_samples for m in by_strategy.values()), 'paired eight-sample coverage')
    records = []
    for sample in range(8):
        values = [by_strategy[s][sample] for s in STRATEGIES]
        row = {'sample': sample, 'producer_cpu_ns': dict(zip(STRATEGIES, values))}
        for a, b, name in FACTORS:
            row[name] = {'delta_ns': values[b]-values[a], 'percent_change': pct(values[a], values[b])}
        row['interaction_ns'] = (values[3]-values[2])-(values[1]-values[0])
        records.append(row)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--source-repo', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-scope', default='single local provisioned 8-CPU / 8-GiB environment; not original public Host')
    args = parser.parse_args()
    require(re.fullmatch(r'[0-9a-f]{40}', args.expected_commit) is not None, 'full expected commit required')
    receipt = args.receipt.resolve(strict=True)
    manifest_path = receipt / 'manifest.json'
    require(manifest_path.is_file(), 'WAIT: final manifest is absent; do not read active campaign output')
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    require(manifest.get('schema') == 'trnm-w1-legal-strategy-execution-v3', 'exact V3 execution schema')
    require(len(manifest.get('shards', [])) == 30 and len(manifest.get('planned_shards', [])) == 30,
            'INCOMPLETE: complete thirty-shard final manifest required')
    require(manifest.get('reader', {}).get('complete_fixed_grid') is True, 'INCOMPLETE: final full-grid readback required')
    require(manifest.get('result') == 'PASS', 'FAILED: native campaign failed; comparative full-grid costs withheld')
    require(manifest['source_before'] == manifest['source_after'], 'source changed during campaign')
    require(manifest['source_before']['commit'] == args.expected_commit, 'measured commit differs from requested commit')
    require(manifest['source_before']['source_state'] == 'committed-clean' and
            manifest['source_before']['tracked_worktree_verified'] is True, 'exact tracked source receipt required')
    require(manifest.get('source_changed') is False, 'source-changed flag')
    require(manifest.get('execution_context') == 'local-native-preflight', 'this report scope expects actual local run')
    require(all(manifest.get(flag) is False for flag in FLAGS), 'qualification flags must remain false')
    require(manifest.get('default_release_configuration_checked') is True and
            manifest.get('cargo_configuration_changed') is False, 'release configuration receipt')
    hashes = [manifest[k] for k in ('binary_sha256_before','binary_sha256_after',
              'retained_binary_sha256_before','retained_binary_sha256_after')]
    require(len(set(hashes)) == 1, 'measured and retained binary identities differ')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    frozen = out / 'pinned-reader'
    source_hashes = {}
    for name in READER_FILES:
        raw = subprocess.check_output(['git', '--no-replace-objects', 'show', args.expected_commit + ':' + name], cwd=args.source_repo)
        path = frozen / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        source_hashes[name] = hashlib.sha256(raw).hexdigest()
    sys.path.insert(0, str(frozen / 'scripts'))
    reader = importlib.import_module('pon_w1_legal_strategy_reader_v3')
    require(tuple(reader.STRATEGIES) == STRATEGIES and reader.SAMPLES == 8, 'frozen factorial contract')
    shard_inputs = []
    actual_capture_errors = []
    for index, shard in enumerate(manifest['shards']):
        observation = shard.get('observation')
        require(isinstance(observation, dict), 'missing native shard observation')
        stdout, stderr = receipt / observation['stdout'], receipt / observation['stderr']
        require(stdout.parent == receipt and stderr.parent == receipt, 'unexpected artifact traversal')
        require(observation['timeout_seconds'] == 300, 'original per-shard timeout changed')
        require(sha(stdout) == manifest['artifact_sha256'][stdout.name], 'stdout artifact digest mismatch')
        require(sha(stderr) == manifest['artifact_sha256'][stderr.name], 'stderr artifact digest mismatch')
        if observation['exit_code'] != 0 or observation['timed_out'] or shard.get('result') != 'PASS':
            actual_capture_errors.append({'index':index, 'configuration':shard['configuration'],
                'exit_code':observation['exit_code'], 'timed_out':observation['timed_out'],
                'shard_result':shard.get('result'), 'stderr_bytes':stderr.stat().st_size})
        shard_inputs.append(stdout)
    require(sha(receipt / 'pon_w1_legal_strategy_v3') == hashes[0], 'retained actual ELF mismatch')
    fresh = reader.analyze(shard_inputs)
    require(fresh == manifest['reader'], 'independent exact-source reader differs from retained complete report')
    require(not fresh['semantic_alerts'] and not actual_capture_errors,
            'FAILED: semantic/capture errors retained; comparative cost summary withheld')
    require(manifest_path.read_bytes() == manifest_bytes, 'final manifest changed during analysis')
    save_json(out / 'independent-reader-readback.json', fresh)
    rows, cohorts, comparisons, timing_flags = [], [], [], []
    counts = Counter()
    verifier_outcomes = {case:Counter() for case in reader.CASES}
    unique_searches = {}
    common_material_cpu = common_material_wall = 0
    for shard in fresh['shards']:
        selection = shard['selection']
        key = (selection['class'], selection['target_index'], selection['reuse_winners'])
        counts.update(shard['record_counts'])
        common_material_cpu += shard['material_setup']['cpu_ns']
        common_material_wall += shard['material_setup']['wall_ns']
        require([c['strategy'] for c in shard['strategy_costs']] == list(STRATEGIES), 'fixed strategy order')
        shard_rows = []
        for costs in shard['strategy_costs']:
            row = dict(selection, strategy=costs['strategy'], arithmetic=costs['arithmetic'],
                materialization=costs['materialization'],
                setup_calls=costs['actual_setup_calls'], searches=costs['actual_searches'],
                target_hits=costs['target_hits'], exhausted_searches=costs['exhausted_searches'],
                attempts=costs['attempts'], proof_materializations=costs['proof_materializations'],
                serialized_proof_bytes=costs['serialized_proof_bytes'],
                producer_cpu_ns=costs['inclusive_cohort_total']['cpu_ns'],
                producer_wall_ns=costs['inclusive_cohort_total']['wall_ns'],
                setup_cpu_ns=costs['setup_total']['cpu_ns'],
                evidence_cpu_ns=costs['separate_attempt_evidence_total']['cpu_ns'],
                evidence_wall_ns=costs['separate_attempt_evidence_total']['wall_ns'],
                mutation_cpu_ns=costs['separate_product_mutation_total']['cpu_ns'],
                mutation_wall_ns=costs['separate_product_mutation_total']['wall_ns'])
            row['producer_plus_measured_evidence_cpu_ns'] = row['producer_cpu_ns'] + row['evidence_cpu_ns']
            row['producer_plus_measured_evidence_wall_ns'] = row['producer_wall_ns'] + row['evidence_wall_ns']
            row['evidence_over_producer_percent'] = 100.0 * row['evidence_cpu_ns'] / row['producer_cpu_ns']
            row['producer_wall_over_cpu'] = row['producer_wall_ns'] / row['producer_cpu_ns']
            rows.append(row); shard_rows.append(row)
            for case, actual in costs['native_outcome_counts'].items():
                verifier_outcomes[case].update(actual)
            for sample in costs['per_sample_cohort_totals']:
                cohorts.append(dict(selection, strategy=costs['strategy'], **sample))
            sample_cpus = [s['cpu_ns'] for s in costs['per_sample_cohort_totals']]
            med = statistics.median(sample_cpus)
            # A timing flag retains the observation; it is not an invalidation.
            if row['producer_wall_over_cpu'] > 2.0 or max(sample_cpus) > 2.0 * med:
                timing_flags.append(dict(selection, strategy=costs['strategy'],
                    wall_over_cpu=row['producer_wall_over_cpu'],
                    max_sample_cpu_over_median=max(sample_cpus)/med,
                    warning='descriptive variation includes different paid attempt counts across samples; not an outlier rejection; no samples removed'))
        comparisons.append(dict(selection,
            producer=effects(shard_rows,'producer_cpu_ns'),
            producer_plus_measured_evidence=effects(shard_rows,'producer_plus_measured_evidence_cpu_ns'),
            matched_samples=matched_sample_effects(shard['strategy_costs'])))
        for fingerprint in shard['search_fingerprints']:
            indexed = key[:2] + (fingerprint['sample'], fingerprint['search_index'])
            require(indexed not in unique_searches or unique_searches[indexed] == fingerprint, 'cross-horizon identity changed')
            unique_searches[indexed] = fingerprint
    aggregates = []
    sum_keys = ('setup_calls','searches','target_hits','exhausted_searches','attempts','proof_materializations',
        'serialized_proof_bytes','producer_cpu_ns','producer_wall_ns','setup_cpu_ns','evidence_cpu_ns','evidence_wall_ns',
        'mutation_cpu_ns','mutation_wall_ns','producer_plus_measured_evidence_cpu_ns','producer_plus_measured_evidence_wall_ns')
    for strategy in STRATEGIES:
        selected = [row for row in rows if row['strategy'] == strategy]
        aggregates.append(dict(strategy=strategy, **{key:sum(row[key] for row in selected) for key in sum_keys}))
    effect_ranges = {}
    for scope in ('producer','producer_plus_measured_evidence'):
        effect_ranges[scope] = {}
        for _,_,name in FACTORS:
            changes = [r[scope][name]['percent_change'] for r in comparisons]
            effect_ranges[scope][name] = dict(min_percent_change=min(changes),max_percent_change=max(changes),
                lower_cost_shards=sum(v<0 for v in changes),higher_cost_shards=sum(v>0 for v in changes),
                equal_cost_shards=sum(v==0 for v in changes),shards=len(changes))
    summary = dict(schema='pon-factorial-completed-local-analysis-v1', qualification_status='HOLD',
        **dict.fromkeys(FLAGS,False), source=manifest['source_before'],
        execution_result=manifest['result'], execution_context=manifest['execution_context'],
        host_scope=args.host_scope, host_scope_is_independent_attestation=False,
        binary_sha256=hashes[0],manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        exact_reader_source_sha256=source_hashes,independent_reader_matches_manifest=True,
        original_public_host_acceptance=False, economic_lower_bound=False,
        complete_shards=len(fresh['shards']),samples_per_shard=fresh['observed_samples_per_class'],
        policy_sample_count_satisfied=fresh['policy_sample_count_satisfied'],
        record_counts=dict(counts),
        actual_paid_setup_calls=sum(r['setup_calls'] for r in rows),
        actual_paid_searches=sum(r['searches'] for r in rows),
        actual_paid_complete_attempts=sum(r['attempts'] for r in rows),
        actual_target_hits=sum(r['target_hits'] for r in rows),
        actual_exhausted_searches=sum(r['exhausted_searches'] for r in rows),
        unique_indexed_searches=len(unique_searches),
        deduplicated_indexed_attempts=sum(r['attempts'] for r in unique_searches.values()),
        actual_verifier_outcomes={k:dict(v) for k,v in verifier_outcomes.items()},
        semantic_alerts=fresh['semantic_alerts'], capture_errors=actual_capture_errors,
        common_material_generation=dict(cpu_ns=common_material_cpu,wall_ns=common_material_wall,
            allocation='actual common material costs retained once per shard, never imputed per strategy winner'),
        aggregates=aggregates,
        aggregate_producer_effects=effects(aggregates,'producer_cpu_ns'),
        aggregate_producer_plus_measured_evidence_effects=effects(aggregates,'producer_plus_measured_evidence_cpu_ns'),
        effects_by_shard=comparisons,effect_ranges=effect_ranges,descriptive_timing_flags=timing_flags,
        limitations=[
            'This is one local native source/binary run; provisioning is not independent physical hardware attestation.',
            'Inclusive producer cohort CPU includes one actual setup, all complete attempts/tickets, successful proof serialization, eager losing-proof destruction, binary-trial retention and timer/container overhead up to cohort completion.',
            'Producer-plus-measured-evidence adds a separate non-overlapping interval for complete attempt digests and attempt-record JSON Value construction only; it is a measured subtotal, not total mining cost.',
            'Outer search/candidate/mutation/verifier record construction, additional proof hashes, JSON serialization/write, later retained-object destruction, verification, transfer and business settlement remain outside that subtotal.',
            'The separately recorded common material cost is not silently added once per winner or duplicated across cells.',
            'Repeated strategy and horizon observations are not independent challenges or credited chainwork.',
            'Negative native calls here are Product-last, not a new measurement of false-trace rejection economics.',
            'No claim about the cheapest legal algorithm, physical energy, quantum cost, original public Host service or production qualification follows.',
            'Timing flags are descriptive; no observation or failure denominator is removed.'])
    save_json(out/'analysis.json',summary)
    for name, table in [('shard-costs.csv', rows),('sample-cohort-costs.csv',cohorts)]:
        with (out/name).open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)
    md=['# V3 local factorial cost observations','',
        f"Measured source: `{args.expected_commit}`. Native execution result: **{manifest['result']}**. Qualification: **HOLD**.",
        '',f"Scope: {args.host_scope}. This does not certify original public-Host budgets or independent hardware.",'',
        f"Actual retained grid: {len(fresh['shards'])}/30 shards, {fresh['observed_samples_per_class']} sample IDs per shard.",
        f"Actual paid setups/searches/attempts: {summary['actual_paid_setup_calls']:,} / {summary['actual_paid_searches']:,} / {summary['actual_paid_complete_attempts']:,}.",
        f"Exhausted searches: {summary['actual_exhausted_searches']:,}; indexed searches after horizon/cell deduplication: {len(unique_searches):,}.",
        f"Native verifier outcomes: `{summary['actual_verifier_outcomes']}`. Semantic alerts: {len(fresh['semantic_alerts'])}; capture errors: {len(actual_capture_errors)}.",'',
        '## Aggregate measured CPU','',
        '| Fixed cell | Producer CPU (s) | Setup within producer (s) | Separate evidence CPU (s) | Producer + measured evidence (s) | Paid attempts | PNW1 bytes materialized |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for r in aggregates:
        md.append(f"| {r['strategy']} | {r['producer_cpu_ns']/1e9:.9f} | {r['setup_cpu_ns']/1e9:.9f} | {r['evidence_cpu_ns']/1e9:.9f} | {r['producer_plus_measured_evidence_cpu_ns']/1e9:.9f} | {r['attempts']:,} | {r['serialized_proof_bytes']:,} |")
    md+=['',f"Common material generation, paid once in each actual shard: {common_material_cpu/1e9:.9f} CPU seconds, separately retained.",
        '', 'Adding measured evidence is not an end-to-end service or mining cost; the unmeasured/excluded stages remain explicit.','',
        '## Matched per-shard effects','',
        'Percent change is candidate minus baseline, divided by baseline; negative is lower measured CPU. No values are confidence or security guarantees.']
    for scope,title in [('producer','Producer only'),('producer_plus_measured_evidence','Producer plus measured evidence')]:
        md+=['',f'### {title}','',
            '| Material | Target index | Reuse | Lazy vs eager: Transposed | Lazy vs eager: FullLimb | FullLimb vs Transposed: eager | FullLimb vs Transposed: lazy | Interaction (CPU ms) |',
            '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
        for r in comparisons:
            values=[r[scope][name]['percent_change'] for _,_,name in FACTORS]
            md.append(f"| {r['class']} | {r['target_index']} | {r['reuse_winners']} | "+' | '.join(f'{v:+.4f}%' for v in values)+f" | {r[scope]['interaction_ns']/1e6:+.6f} |")
    md+=['','## Limitations and timing variation','']+['- '+s for s in summary['limitations']]
    md+=['',f"Descriptive timing flags: {len(timing_flags)} cell/shard observations; see analysis.json. They do not invalidate or remove samples.",
         '', 'All exact totals, eight-sample paired producer effects, original record counts and reader identities are retained in analysis.json and the accompanying CSVs.']
    (out/'REPORT.md').write_text('\n'.join(md)+'\n')
    print(json.dumps({key:summary[key] for key in ('source','execution_result','qualification_status','complete_shards','actual_paid_searches','actual_paid_complete_attempts','actual_verifier_outcomes','semantic_alerts','capture_errors','effect_ranges')},indent=2))

if __name__ == '__main__':
    main()
