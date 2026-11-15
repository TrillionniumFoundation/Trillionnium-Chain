#!/usr/bin/env python3
"""Read retained analysis only; never run producer or edit native receipts."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path('/tmp/pon-factorial-2b250859-analysis/completed')
selection = {'class': 'zero', 'target_index': 0, 'reuse_winners': 64}
inputs = {name: (ROOT / name).read_bytes() for name in ('analysis.json', 'independent-reader-readback.json')}
a = json.loads(inputs['analysis.json'])
r = json.loads(inputs['independent-reader-readback.json'])
assert a['source']['commit'] == '2b250859e7c07088e6c3c01f75006372c684de61', a['source']
assert a['complete_shards'] == 30 and not a['capture_errors'] and not a['semantic_alerts']
e = next(v for v in a['effects_by_shard'] if all(v[k] == x for k, x in selection.items()))
s = next(v for v in r['shards'] if v['selection'] == selection)
assert s['matched_full_search_streams'] and not s['semantic_alerts']
rows = []
for matched in e['matched_samples']:
    sample = matched['sample']
    streams = [v for v in s['search_fingerprints'] if v['sample'] == sample]
    assert len(streams) == 64
    assert sorted(v['search_index'] for v in streams) == list(range(64))
    assert all(v['winner'] is not None for v in streams)
    rows.append({
        'sample': sample,
        'searches_per_arm': len(streams),
        'paid_complete_attempts_per_arm': sum(v['attempts'] for v in streams),
        'target_hits_per_arm': len(streams),
        'producer_cpu_ns': matched['producer_cpu_ns'],
        'producer_wall_ns': {
            arm['strategy']: next(v['wall_ns'] for v in arm['per_sample_cohort_totals'] if v['sample'] == sample)
            for arm in s['strategy_costs']
        },
        'lazy_vs_eager_full_limb': matched['lazy_vs_eager_full_limb'],
        'full_limb_vs_transposed_lazy': matched['full_limb_vs_transposed_lazy'],
    })
rows.sort(key=lambda v: v['sample'])
assert [v['sample'] for v in rows] == list(range(8))
for arm in s['strategy_costs']:
    name = arm['strategy']
    assert sum(v['producer_cpu_ns'][name] for v in rows) == arm['inclusive_cohort_total']['cpu_ns']
    assert sum(v['paid_complete_attempts_per_arm'] for v in rows) == arm['attempts']
    assert arm['actual_searches'] == arm['target_hits'] == 512
    assert arm['actual_setup_calls'] == 8 and arm['exhausted_searches'] == 0
focus = rows[5]
lf_ef = e['producer']['lazy_vs_eager_full_limb']
lf_lt = e['producer']['full_limb_vs_transposed_lazy']
concentration = {
    'sample': 5,
    'lazy_full_limb_share_of_its_arm_shard_cpu_percent': 100 * focus['producer_cpu_ns']['lazy-full-limb'] / lf_ef['candidate_ns'],
    'sample_lazy_full_limb_minus_eager_full_limb_cpu_ns': focus['lazy_vs_eager_full_limb']['delta_ns'],
    'all_samples_lazy_full_limb_minus_eager_full_limb_cpu_ns': lf_ef['delta_ns'],
    'other_seven_signed_differences_sum_lf_minus_ef_cpu_ns': lf_ef['delta_ns'] - focus['lazy_vs_eager_full_limb']['delta_ns'],
    'sample_lazy_full_limb_minus_lazy_transposed_cpu_ns': focus['full_limb_vs_transposed_lazy']['delta_ns'],
    'all_samples_lazy_full_limb_minus_lazy_transposed_cpu_ns': lf_lt['delta_ns'],
    'other_seven_signed_differences_sum_lf_minus_lt_cpu_ns': lf_lt['delta_ns'] - focus['full_limb_vs_transposed_lazy']['delta_ns'],
}
result = {
    'schema': 'pon-w1-legal-strategy-v3-retained-sample-diagnostic-v1',
    'selection': selection,
    'source': a['source'],
    'input_sha256': {name: sha256(blob).hexdigest() for name, blob in inputs.items()},
    'scope': 'One retained local 8 CPU / 8 GiB campaign at exact commit 2b250859; all eight samples and all thirty shards retained.',
    'native_reexecution': False,
    'receipt_mutations': False,
    'filtered_performance_estimate': False,
    'timing_cause_attributed': False,
    'matched_full_search_streams': True,
    'semantic_alerts': [],
    'per_sample': rows,
    'all_eight_sample_producer_effects': e['producer'],
    'all_eight_sample_producer_plus_measured_evidence_effects': e['producer_plus_measured_evidence'],
    'concentration': concentration,
    'qualification_status': 'HOLD',
    'economic_lower_bound': False,
    'original_public_host_acceptance': False,
    'limitations': [
        'Descriptive concentration of retained timing observations only; it does not identify a mechanism or establish stability.',
        'The producer CPU interval includes actual task setup, all complete relation attempts, tickets, target-hit PNW1 serialization, and eager losing-proof materialization/destruction.',
        'Separately measured attempt evidence CPU is excluded from the producer column; neither subtotal is total system or mining cost.',
        'All samples remain in the published thirty-shard totals; no trimmed, replacement, or fastest-sample estimate is reported.',
        'Matching nonce streams and attempt counts do not make this one local timing campaign a hardware-independent cost bound.',
    ],
}
json_path = ROOT / 'zero-target0-reuse64-sample-diagnostic.json'
json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
lines = [
    '# Retained sample diagnostic: zero / target 0 / reuse 64',
    '',
    'Measured source: `2b250859e7c07088e6c3c01f75006372c684de61`. This is a read-only analysis of the completed local 8 CPU / 8 GiB V3 campaign. It does not rerun the producer, change native receipts, remove samples, or replace the original thirty-shard totals.',
    '',
    '## Observation',
    '',
    f"Across all eight samples, lazy FullLimb used {lf_ef['candidate_ns']/1e6:.6f} ms producer CPU versus eager FullLimb {lf_ef['baseline_ns']/1e6:.6f} ms: **+{lf_ef['percent_change']:.6f}%**. The same lazy FullLimb arm exceeded lazy transposed by **+{lf_lt['percent_change']:.6f}%**.",
    '',
    f"The large positive contribution is concentrated in sample 5. Its lazy FullLimb producer CPU is {focus['producer_cpu_ns']['lazy-full-limb']/1e6:.6f} ms, or {concentration['lazy_full_limb_share_of_its_arm_shard_cpu_percent']:.6f}% of that arm's eight-sample total. Its difference versus eager FullLimb is +{focus['lazy_vs_eager_full_limb']['delta_ns']/1e6:.6f} ms, exceeding the whole-shard net difference of +{lf_ef['delta_ns']/1e6:.6f} ms. The other seven signed differences sum to {concentration['other_seven_signed_differences_sum_lf_minus_ef_cpu_ns']/1e6:.6f} ms.",
    '',
    f"Against lazy transposed, sample 5 contributes +{focus['full_limb_vs_transposed_lazy']['delta_ns']/1e6:.6f} ms, while the full eight-sample net difference is +{lf_lt['delta_ns']/1e6:.6f} ms. All seven other sample differences have the opposite sign and sum to {concentration['other_seven_signed_differences_sum_lf_minus_lt_cpu_ns']/1e6:.6f} ms. These signed sums locate the concentration; they are not a filtered performance estimate.",
    '',
    '**Cause remains unassigned.** Matching streams and equal paid-attempt counts establish comparable work records. They do not identify why this timing observation is larger. No inference is made about scheduler behavior, clocks, allocation, thermal state, kernel stability, or a durable regression/speedup.',
    '',
    '## Eight matched samples',
    '',
    'CPU values are milliseconds of the complete producer interval, including setup and all winning/losing attempts. All four arms share the recorded nonce stream within each row. Each row has 64 successful searches per arm and no exhaustion. Paid attempts include all misses. The strict pinned reader confirms full-stream matching and no semantic alerts.',
    '',
    '| Sample | Paid attempts / arm | Eager transposed CPU ms | Lazy transposed CPU ms | Eager FullLimb CPU ms | Lazy FullLimb CPU ms | Lazy vs eager FullLimb | FullLimb vs transposed, lazy |',
    '|---:|---:|---:|---:|---:|---:|---:|---:|',
]
for v in rows:
    cpu = v['producer_cpu_ns']
    lines.append('| ' + ' | '.join([
        str(v['sample']), str(v['paid_complete_attempts_per_arm']),
        *(f'{cpu[name]/1e6:.6f}' for name in ['eager-transposed','lazy-transposed','eager-full-limb','lazy-full-limb']),
        f"{v['lazy_vs_eager_full_limb']['percent_change']:+.4f}%",
        f"{v['full_limb_vs_transposed_lazy']['percent_change']:+.4f}%",
    ]) + ' |')
lines += [
    '',
    'Totals per arm: 8 actual setups, 512 searches, 997 complete attempts, 512 target hits, 485 misses, 0 exhausted searches. Four verifier paths yield 2,048 Accepted legal verifications and 2,048 Product rejections per arm.',
    '',
    '## Interpretation retained in the full report',
    '',
    '- All eight samples and all thirty configurations remain in the results. This diagnostic neither censors sample 5 nor supplies a replacement/trimmed estimate.',
    '- Separately measured attempt-evidence CPU does not remove the exceptional direction: this shard remains +100.470330% lazy versus eager FullLimb and +20.468152% FullLimb versus transposed for lazy, on the producer-plus-measured-evidence subtotal.',
    '- In the original full campaign, eager FullLimb producer CPU is lower than eager transposed in all 30 configurations. This statement describes that retained campaign only; it does not establish a universal speedup.',
    '- The full-campaign aggregate lazy FullLimb change must not be described as a stable 1.44% regression. The retained per-configuration and per-sample dispersion remains material.',
    '- Qualification remains HOLD. No fastest-adversary lower bound, independent hardware qualification, or original public Host acceptance follows.',
    '',
    'Inputs: `analysis.json` and `independent-reader-readback.json` in this directory; their SHA-256 values, exact nanosecond CPU/wall values, and the complete paired arithmetic are retained in `zero-target0-reuse64-sample-diagnostic.json`.',
]
md_path = ROOT / 'zero-target0-reuse64-sample-diagnostic.md'
md_path.write_text('\n'.join(lines) + '\n')
print(json.dumps({'outputs': [str(json_path), str(md_path)], 'concentration': concentration}, indent=2))
