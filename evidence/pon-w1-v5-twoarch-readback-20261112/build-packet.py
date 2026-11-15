#!/usr/bin/env python3
"""Create an external, create-only readback packet from actual retained originals."""
import base64
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import zipfile

BASE = Path('/home/qian-qi/work/w1-v5-readback-20261112-b34d')
OUT = Path('/home/qian-qi/work/w1-v5-packet-20261112-b34d')
HEAD = '229b14c2d366a257f51f287d502a550df2332338'
TREE = 'b386c32458589f81944ddd69c04a56c28c55e284'
PART_BYTES = 4194304
SPECS = {
    'arm64': (13917333858, 45024075, 'da553653d88eced182fa698e2c4d099cc7bb5c64d29083a87bf6791c2cbde6fd'),
    'x64': (13917828728, 45074329, '0442f1fc392367d83803944e46bd1c803dfe55a9ec0f2bcb6bb32d37ede152c2'),
}
PINS = {
    'review_artifact.py': '0fe35a029d0c226849503a75d9e5169b438f19fdcee5526027048eea946dfb30',
    'pon_w1_cost_matrix_reader.py': '6a967274b93394494a2606c08173d4c755f255742bdca6cecd9665ce9f3686fa',
    'pon_w1_preparation_strategy_reader_v4.py': 'b4314bcf354dc24a7a2a4c8381ead3811010db4470bedaeaf4c8b75e7ab2682d',
    'pon_w1_rank_batch_reader_v5.py': '03b34de9bd63616d8a243cae0c9e226c21102aca4bef7c52904cf7d20f364f26',
}


def need(test, message):
    if not test:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1048576), b''):
            h.update(raw)
    return h.hexdigest()


def identity(path):
    return {'bytes': path.stat().st_size, 'sha256': digest(path)}


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def write_json(path, value):
    write(path, (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())


def load(path):
    return json.loads(path.read_text())


def copy(source, target):
    raw = source.read_bytes()
    write(target, raw)
    need(identity(source) == identity(target), 'copy changed: ' + str(source))


def rate(arm, axis):
    wins = arm['accepted_winners']
    numerator = arm['producer_total'][axis]
    return None if wins == 0 or numerator is None else Fraction(numerator, wins)


def ms(value):
    return 'null' if value is None else f'{float(value) / 1000000:.6f}'


def best(arms, axis):
    eligible = [a for a in arms if a['supported'] is True and rate(a, axis) is not None]
    return min(eligible, key=lambda a: rate(a, axis)) if eligible else None


def validate_inputs():
    for name, pin in PINS.items():
        need(digest(BASE / name) == pin, 'actual executed helper/reader changed: ' + name)
    values = {}
    for arch, (artifact_id, size, sha) in SPECS.items():
        root = BASE / arch
        original = root / 'original.zip'
        need(original.stat().st_size == size and digest(original) == sha, 'original ZIP changed')
        exit_receipt = load(root / 'readback-exit.json')
        need(type(exit_receipt['exit_code']) is int and exit_receipt['exit_code'] == 0, 'readback did not exit zero')
        need(exit_receipt['command'] == ['python3', str(BASE / 'review_artifact.py'), str(root / 'extracted'),
             '--zip', str(original), '--arch', arch], 'actual readback command changed')
        need(exit_receipt['archive_bytes'] == size and exit_receipt['archive_sha256'] == sha, 'exit archive binding')
        need((root / 'readback.stderr').read_bytes() == b'', 'readback stderr nonempty')
        p = load(root / 'readback.json')
        need(p['status'] == 'COMPLETE_COMPONENT_EVIDENCE_READBACK' and p['architecture'] == arch
             and p['commit'] == HEAD and p['tree'] == TREE and p['artifact_id'] == artifact_id, 'readback identity incomplete')
        need(p['archive']['checked'] is True and p['archive']['all_crc_and_extracted_member_hashes_match'] is True
             and p['archive']['files'] == 220 and p['archive']['bytes'] == size and p['archive']['sha256'] == sha,
             'archive readback incomplete')
        need(p['all_66_original_reader_summaries_reproduced'] is True
             and p['all_fixed_arm_producer_sums_recomputed_from_raw_rows'] is True, 'readback incomplete')
        need(p['cost_cell_count'] == 44 and p['control_cell_count'] == 22 and len(p['cells']) == 66, 'partial grid')
        need(p['production_activation'] is False and p['security_or_cost_lower_bound'] is False
             and p['independent_w1_math_replay'] is False, 'qualification boundary changed')
        for name, expected in p['input_identities'].items():
            need(identity(root / 'extracted' / name) == expected, 'readback original input changed')
        expected_keys = {(name, t, h) for name in ('zero','rank-one','rank-two-left','rank-four-left','rank-eight-left',
             'rank-four-right','rank-nine-left','full-rank-field','sparse-diagonal','one-zero-rank-one','continuity-maintenance-v1')
             for t in range(4) for h in ((1,8) if t < 2 else (1,))}
        observed_keys = {(c['class'], c['target_index'], c['horizon']) for c in p['cells']}
        need(observed_keys == expected_keys, 'changed complete cell roster')
        need(all(len(c['arms']) == 17 and len({a['strategy'] for a in c['arms']}) == 17 for c in p['cells']), 'missing fixed arms')
        values[arch] = p
    need(values['arm64']['total_counts'] == values['x64']['total_counts'], 'matched mathematical counters differ')
    return values


def main():
    values = validate_inputs()
    need(not OUT.exists(), 'create-only packet destination already exists')
    OUT.mkdir()
    for name in PINS:
        copy(BASE / name, OUT / 'helpers' / name)
    copy(Path(__file__).resolve(), OUT / 'build-packet.py')
    full_grid = {'schema': 'pon-w1-v5-complete-fixed-arm-cost-grid-v1', 'source_commit': HEAD, 'source_tree': TREE,
                 'aggregation': 'ratio-of-sums per architecture/class/target/horizon/fixed arm; no per-sample selection; no horizon pooling',
                 'architectures': {}}
    summary = {'schema': 'pon-w1-v5-readback-numeric-summary-v1', 'source_commit': HEAD, 'source_tree': TREE,
               'new_native_execution': False, 'security_or_minimum_cost_lower_bound': False, 'architectures': {}}
    archive_parts, table_sections = {}, []
    chosen = ('full-limb-dense-lazy','full-limb-sparse-lazy','full-limb-rank8-lazy','full-limb-rank8-batch4-lazy')
    for arch, p in values.items():
        root, target = BASE / arch, OUT / arch
        for name in ('readback.json', 'readback-exit.json', 'readback.stderr'):
            copy(root / name, target / name)
        for name in p['input_identities']:
            copy(root / 'extracted' / name, target / 'metadata' / name)
        for c in p['cells']:
            if c['target_index'] < 2:
                need(c['purpose'] == 'search-cost', 'control misclassified as cost')
                for axis in ('cpu_ns','wall_ns'):
                    expected = best(c['arms'], axis)
                    need(c['lowest_observed_fixed_arm_' + axis] == (expected['strategy'] if expected else None), 'recomputed fixed-arm min differs')
        costs = [c for c in p['cells'] if c['purpose'] == 'search-cost']
        need(len(costs) == 44, 'cost count mismatch')
        full_grid['architectures'][arch] = costs
        compact = []
        table_sections.extend([f'## {arch}: T1 / H8', '',
            '| Material | Dense CPU / wall | Sparse CPU / wall | Rank8 CPU / wall | Batch4 CPU / wall | Lowest observed CPU fixed arm | Lowest observed wall fixed arm |',
            '| --- | ---: | ---: | ---: | ---: | --- | --- |'])
        for c in costs:
            if (c['target_index'], c['horizon']) != (1, 8):
                continue
            by_name = {a['strategy']:a for a in c['arms']}
            cpu, wall = best(c['arms'],'cpu_ns'), best(c['arms'],'wall_ns')
            pairs = [ms(rate(by_name[name],'cpu_ns')) + ' / ' + ms(rate(by_name[name],'wall_ns')) for name in chosen]
            cpu_label = 'null' if cpu is None else cpu['strategy'] + ' ' + ms(rate(cpu,'cpu_ns'))
            wall_label = 'null' if wall is None else wall['strategy'] + ' ' + ms(rate(wall,'wall_ns'))
            table_sections.append('| ' + ' | '.join([c['class'], *pairs, cpu_label, wall_label]) + ' |')
            compact.append({'class':c['class'], 'target_index':1, 'horizon':8,
                 'lowest_observed_fixed_arm_cpu':None if cpu is None else {'strategy':cpu['strategy'], 'milliseconds':float(rate(cpu,'cpu_ns'))/1e6},
                 'lowest_observed_fixed_arm_wall':None if wall is None else {'strategy':wall['strategy'], 'milliseconds':float(rate(wall,'wall_ns'))/1e6},
                 'primary_arms':[{k:a[k] for k in ('strategy','accepted_winners','searches','setups','physical_attempts','speculative_attempts',
                     'producer_total','paid_setup','cpu_per_accepted_winner','wall_per_accepted_winner')} for a in c['arms'] if a['strategy'] in chosen]})
        table_sections.append('')
        summary['architectures'][arch] = {'total_counts':p['total_counts'],'manifest_identity':p['input_identities']['campaign/manifest.json'],
             'readback_identity':identity(root/'readback.json'),'outer_execution':p['outer_execution'], 't1_h8':compact,
             'cost_cells':44,'control_cells':22,'fixed_arm_rows_in_cost_cells':44*17}
        original = root / 'original.zip'
        members = []
        with zipfile.ZipFile(original) as zipped:
            need(zipped.testzip() is None, 'current ZIP CRC failure')
            names = zipped.namelist()
            need(len(names) == len(set(names)), 'duplicate ZIP member')
            for item in zipped.infolist():
                if item.is_dir():
                    continue
                path = PurePosixPath(item.filename)
                need(not path.is_absolute() and '..' not in path.parts and not stat.S_ISLNK(item.external_attr >> 16), 'unsafe ZIP member')
                raw = zipped.read(item)
                members.append({'name':item.filename,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                     'crc32':f'{item.CRC:08x}','compressed_bytes':item.compress_size,'compression':item.compress_type})
        need(len(members) == 220, 'member count changed')
        write_json(target / 'original-zip-members.json', {'schema':'original-zip-member-identities-v1','original_zip':identity(original),'members':members})
        parts, reconstructed = [], hashlib.sha256()
        with original.open('rb') as stream:
            for number, raw in enumerate(iter(lambda:stream.read(PART_BYTES),b'')):
                part = target / f'original.zip.part-{number:03d}'
                write(part,raw)
                reconstructed.update(part.read_bytes())
                parts.append({'path':part.relative_to(OUT).as_posix(),'bytes':len(raw),'sha256':digest(part)})
        need(reconstructed.hexdigest() == SPECS[arch][2] and sum(x['bytes'] for x in parts) == SPECS[arch][1], 'partition does not reproduce original')
        part_record = {'schema':'ordered-original-zip-parts-v1','artifact_id':SPECS[arch][0], 'original_zip':identity(original),
             'maximum_part_bytes':PART_BYTES,'ordered_parts':parts,'reassembly':'concatenate ordered_parts in this exact order; verify original_zip bytes and SHA256 before unzip'}
        write_json(target / 'original-zip-parts.json',part_record)
        archive_parts[arch] = part_record
    write_json(OUT/'full-cost-grid.json',full_grid)
    write_json(OUT/'numerical-summary.json',summary)
    write(OUT/'t1-h8-tables.md', ('# V5 fixed-arm T1/H8 observations\n\nAll values are milliseconds per accepted winner, computed as complete producer sums divided by accepted winners. The four named columns are preregistered implementations; lowest columns select one aggregate fixed arm after all eight cohorts and are descriptive observations. All 17 arms in every cost cell are retained in full-cost-grid.json. Controls are excluded.\n\n'+'\n'.join(table_sections)).encode())
    readme = '''# W1 V5 original Actions artifact readback

This packet preserves evidence reading and arithmetic verification of existing native executions. It records no new native W1 execution, rerun, source change or production activation.

Both head jobs in run 43147686753 completed all 66 declared V5 shards on source 229b14c2d366a257f51f287d502a550df2332338, tree b386c32458589f81944ddd69c04a56c28c55e284. The ARM64 job is 130949245425 / artifact 13917333858; the x64 job is 130949245331 / artifact 13917828728. Each original ZIP contains 220 files: all 440 file CRCs and complete byte hashes were checked. The independent readers exited zero; their original command/exit receipts, output and stderr are retained unchanged.

Each architecture has 11 material classes, 17 preregistered arms and eight cohorts. There are 44 cost cells (class × two targets × H1/H8) and 22 controls. Each original campaign counts 8,976 preparations, including 3,696 unsupported probes, 17,600 searches, 274,647 physical attempts, 17,845 physical hits, 256,802 misses, 880 exhausted searches, 3,204 speculative attempts, 170,344 materialized proof buffers and 73,288 verifier calls. Counts repeat matched strategy streams and are not independent lottery samples or unique business effects. Physical postwinner hits do not create additional accepted winners.

The complete per-cell tables retain every fixed arm and its support state, preparation selection, full producer CPU/wall totals, setup, misses, speculation, cleanup and teardown. Cost comparisons use ratio of sums within one architecture/class/target/horizon/arm, without per-sample fastest selection, controls or H1/H8 pooling. The per-cell minimum among measured aggregate arms is descriptive, selected after the samples: it is an achievable-cost observation, never a global cheapest-strategy proof or an attacker cost lower bound. Zero-winner and unsupported comparison rates stay null. Eight cohorts do not establish confidence bounds or hardware independence.

Fixture/material and scalar-reference construction, observation/hashing, full-verifier work, inclusive cohort intervals and outer wait4/observer costs remain separately visible. Inclusive clocks are not added to their components. Separate clocks do not eliminate cache and allocator effects in the shared process. The reader reconstructs declared commitments, checks records and recalculates arithmetic; it does not independently execute all W1 mathematics or authenticate physical clocks. Production security and whole-chain qualification remain HOLD.

V5 emits setup and search journal records only after that work completes. These successful complete-grid readbacks therefore do not qualify interruption or cancellation accounting for work interrupted before emission. Exhaustion-control misses are not replayed by both full verifiers in V5; do not inherit that different coverage from newer zero-paired V1. Winner, mutant and declared postwinner verifier checks retain their exact original scope. `independent_w1_math_replay=false`; no repeated native executions or all-algorithm closure is claimed.

## Contents and reproduction

- `arm64/` and `x64/` retain successful readbacks, actual exit receipts, zero-byte stderr and original metadata bytes. `original-zip-members.json` identifies every original file. Each original ZIP is preserved once as ordered parts of at most 4,194,304 bytes; `original-zip-parts.json` binds each part and the full original. Concatenating the listed parts reproduces the byte-identical ZIP; verify full length and hash before extraction.
- `helpers/review_artifact.py` is the actual executed helper copied byte-for-byte, together with its three actual pinned imports. The original exit receipts retain their earlier absolute command paths. After reassembly/extraction, run `python3 helpers/review_artifact.py EXTRACTED_ROOT --zip ORIGINAL_ZIP --arch arm64` (or `x64`) to repeat the evidence readback. This command runs Python readers, not the retained native ELF.
- `full-cost-grid.json` contains all 17 arms in all 44 cost cells per architecture. `t1-h8-tables.md` is a compact 11-material view per architecture; `numerical-summary.json` retains exact input identities and outer observation costs. Both complete original readbacks retain all controls as well.
- `packet-manifest.json` identifies every packet file except itself. Its integrity is separate from native execution or security qualification. `build-packet.py` records this new packaging/arithmetic operation; it does not replace or reconstruct an original execution receipt.

## User-requested strategy coverage

| Strategy class | Evidence in these V5 artifacts | Remaining boundary |
| --- | --- | --- |
| Zero, sparse, low-rank, diagonal, short-column padding | Synthetic zero; rank1/2/4/8 left; rank4 right; rank9 explicit fallback; full rank; sparse diagonal; one-zero rank1. Original winner/mutant and declared postwinner production/reference checks retain their exact scope. | Exhaustion-control misses have no dual full replay; real short-column task provenance and general nonfixture demand are not established. |
| Preparation across nonce, miners and epochs | Actual paid preparation reused across H1/H8 searches on fixed A/B; full challenge-dependent transcript work retained. | No cross-miner or cross-epoch ownership/cost qualification; correlated horizons are not pooled. |
| GPU/ASIC, shared cache and early screening | Native x64 and ARM64 CPU implementations; batch4 charges worker spawn/join and all completed speculation. | No GPU/ASIC measurement, shared-cache campaign or general early-screening bound. |
| Omit failing proofs | Lazy arms retain complete losing attempts while constructing proof buffers under the declared policy. | No proof that these arms are globally cheapest legal strategies. |
| Cheap fake transcripts and expensive receiver rejection | Original verifier/control observations remain in the ZIPs; this V5 cost grid measures the declared legal producers. | No production public-inbound rejection-service/liveness qualification. |
| Attacker-chosen tasks, sponsor self-traffic and repeated reward | Synthetic task choice is explicit and all task/challenge/stream identities are retained. | No independent authorization, real demand, sponsor anti-self-traffic or unique settlement/reward qualification. |
| Maintenance without real tasks | `continuity-maintenance-v1` is an explicit measured synthetic material class. | It does not establish real useful demand or complete maintenance economics. |

Under independent uniform inclusive 256-bit tickets, p=(T+1)/2^256. The empirical grids do not prove this assumption. Shared preparation, failing attempts and winner-only costs must be charged at their actual reuse/ownership scope. The ESA 2026 asymptotic conjecture does not supply a finite-parameter lower bound for this concrete 64×64 profile.
'''
    write(OUT/'README.md',readme.encode())
    files = {p.relative_to(OUT).as_posix():identity(p) for p in sorted(OUT.rglob('*')) if p.is_file()}
    manifest = {'schema':'pon-w1-v5-external-readback-packet-v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'source_commit':HEAD,'source_tree':TREE,'native_executions_started_by_packaging':0,'original_zip_count':2,
        'original_member_count':440,'file_count_without_manifest':len(files),'files':files}
    write_json(OUT/'packet-manifest.json',manifest)
    for name, expected in files.items():
        need(identity(OUT/name) == expected,'packet changed after manifest')
    complete_files = [p for p in OUT.rglob('*') if p.is_file()]
    result = {'status':'PACKET_CREATED_FROM_ACTUAL_ORIGINALS','path':str(OUT), 'bytes':sum(p.stat().st_size for p in complete_files),
              'files':len(complete_files),'manifest':identity(OUT/'packet-manifest.json'),
              'parts_per_architecture':{arch:len(record['ordered_parts']) for arch,record in archive_parts.items()},
              'summary':identity(OUT/'numerical-summary.json'),'tables':identity(OUT/'t1-h8-tables.md'),
              'manifest_original_inputs':{arch:p['input_identities']['campaign/manifest.json'] for arch,p in values.items()},
              't1_h8_observed_cpu_fixed_arm_roster':{arch:dict(Counter(r['lowest_observed_fixed_arm_cpu']['strategy'] for r in summary['architectures'][arch]['t1_h8'])) for arch in values}}
    print(json.dumps(result,sort_keys=True,indent=2))
    for arch in values:
        for row in summary['architectures'][arch]['t1_h8']:
            print(json.dumps({'architecture':arch,**row},sort_keys=True))


if __name__ == '__main__':
    main()
