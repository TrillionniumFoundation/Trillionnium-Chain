#!/usr/bin/env python3
"""Check returned fixed-run records; do not claim a second large native run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path('/workspace/scratch/4a83c49617d8/chain_pq')
BASE = ROOT / 'evidence/pon-w1-qrom-semantics-20261107'
SPEC = importlib.util.spec_from_file_location('native_audit', ROOT / 'scripts/w1_zkr_control_id_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate native JSON field')
        result[key] = value
    return result


def main():
    path = BASE / 'control-ids-all27.json'
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == '48be4b4f4016e90adab07505e27f511232ec4164049c333073ded39a2f462aad',
            'returned all27 report hash')
    report = json.loads(blob, object_pairs_hook=unique)
    execution = json.loads((BASE / 'control-id-execution.json').read_bytes(), object_pairs_hook=unique)
    shapes = json.loads((BASE / 'zkr-programs.json').read_bytes(), object_pairs_hook=unique)
    by_name = {row['program']: row for row in shapes['programs']}
    shape, helper, engine, catalog, allowed, c_source, header, provenance = AUDIT.load_context(ROOT)
    require(report['requested_programs'] == sorted(allowed), 'requested exact default roster')
    require([row['program'] for row in report['programs']] == sorted(allowed), 'completed exact roster')
    require(type(report['completed_programs']) is int and report['completed_programs'] == 27, 'completed count')
    require(report['source_provenance'] == provenance, 'source provenance equals current pinned inputs')
    require(report['official_zip'] == {'sha256': shape.ZIP_SHA256, 'bytes': shape.ZIP_BYTES}, 'ZIP pin')
    for label in ('source_template', 'source_driver'):
        row = execution[label]
        require(hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256'], label)
    require(execution['generated_header_sha256'] == hashlib.sha256(header).hexdigest(), 'header execution identity')
    require(execution['native_binary_sha256'] == report['native_build']['binary_sha256'], 'binary record identity')
    computed = []
    for row in report['programs']:
        name = row['program']
        raw = row['native_run']['stdout'].encode()
        run = row['native_run']
        require(type(run['exit_code']) is int and run['exit_code'] == 0 and run['timed_out'] is False, name + ' completion')
        require(len(raw) == run['stdout_bytes'] and hashlib.sha256(raw).hexdigest() == run['stdout_sha256'], name + ' stdout binding')
        require(run['stderr'] == '' and run['stderr_bytes'] == 0
                and run['stderr_sha256'] == hashlib.sha256(b'').hexdigest(), name + ' stderr binding')
        result = json.loads(raw, object_pairs_hook=unique)
        require(row['bytecode_sha256'] == row['geometry']['sha256'] == by_name[name]['sha256'], name + ' shape byte identity')
        require(row['geometry']['code_rows'] == by_name[name]['code_rows'], name + ' row count')
        AUDIT.validate_native_result(result, row['geometry']['code_rows'], catalog[name], 4)
        require(row['matches_fixed_catalog'] is True and row['computed_control_id'] == result['control_id']
                and row['declared_control_id'] == catalog[name], name + ' catalog identity')
        normal = result['root_normal_words']
        require(struct.pack('<8I', *(x * ((1 << 32) % AUDIT.P) % AUDIT.P for x in normal)).hex()
                == catalog[name], name + ' independent Mont-LE encoding')
        computed.append(result['control_id'])
    root = helper.build_tree(computed, engine)[-1][0]
    require(root == helper.EXPECTED_ROOT == report['control_root_from_computed_ids'], 'recomputed allowlist root')
    require(report['qualification'] == {
        'requested_bytecode_to_fri_control_ids_recomputed': True,
        'all_27_default_named_control_ids_recomputed': True,
        'default_control_root_recomputed_from_bytecode': True,
        'recursion_source_to_bytecode_compilation_reproduced': False,
        'intended_recursive_program_semantics_proved': False,
        'every_reachable_trace_certified': False,
        'valid_code_zero_control_digest_excluded': False,
        'fresh_receipt_cryptographically_verified': False,
        'end_to_end_qrom_bound_established': False,
        'quantum_work_to_chain_weight_correspondence_proved': False,
    }, 'qualification scope')
    result = {'scope': 'independent source/record/encoding/root consistency review; no second 27-program native run',
              'report_sha256': hashlib.sha256(blob).hexdigest(),
              'all_native_results_and_shape_byte_identities_checked': 27,
              'root_from_computed_native_results': root, 'unresolved_qualification_flags_preserved': True,
              'post_quantum_soundness_qualified': False, 'all_27_recomputed_independently_here': False}
    out = Path('/workspace/scratch/4a83c49617d8/zkr-control-id-independent-review-final/all27-record-check.json')
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
