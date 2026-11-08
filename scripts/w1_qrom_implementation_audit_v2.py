#!/usr/bin/env python3
"""Versioned selected-source mapping after the reviewed bb026697 transition.

The immutable v1 contract, engine and historical report remain historical inputs.
This v2 entry point accepts exactly two reviewed source changes. It recomputes
the mapping and checks historical semantic fields without changing v1 globals.
Neither source projection nor this offline audit verifies a new native route,
the complete build, a fresh proof, QROM soundness, or consensus admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tomllib
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'config/pon/w1-qrom-implementation-v2.json'
CONTRACT_SHA256 = 'bed7e925b5c02f896ea0f6ada378a346080d044a8c7c3879f7d47c034fb86280'
ENGINE = 'scripts/w1_qrom_implementation_audit.py'
ENGINE_SHA256 = 'c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354'
HISTORICAL_REPORT = 'evidence/pon-w1-qrom-implementation-20261107/implementation-map.json'
SOURCE_REVIEW = 'evidence/pon-w1-qrom-source-convergence-20261108/source-review.json'
SELECTED_SOURCE_COMMIT = 'bb026697a972521009bc133ae6ed2b653e18e931'
CHANGED_PATHS = frozenset({
    'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs',
    'trillionnium/crates/trnm-protocol/src/pon_wire.rs',
})


def _checked_legacy_engine() -> ModuleType:
    # This is trusted repository audit code, not an interpreter for upstream
    # code. Compile these exact pinned bytes; ignore imports and sys.modules.
    path = ROOT / ENGINE
    if path.is_symlink():
        raise ValueError('symlink implementation engine')
    with path.open('rb') as stream:
        data = stream.read(21679)
    if len(data) != 21678 or hashlib.sha256(data).hexdigest() != ENGINE_SHA256:
        raise ValueError('pinned implementation engine drift')
    module = ModuleType('_w1_qrom_immutable_v1_engine')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_engine = _checked_legacy_engine()
AuditError = _engine.AuditError
require = _engine.require
sha = _engine.sha
strict_json = _engine.strict_json
bounded_file = _engine.bounded_file
load_pinned_files = _engine.load_pinned_files
checked_helper = _engine.checked_helper
load_snapshot = _engine.load_snapshot
inspect_v2 = _engine.inspect_v2
fri_schedule = _engine.fri_schedule
parameter_digest = _engine.parameter_digest
UPSTREAM, PROFILE = _engine.UPSTREAM, _engine.PROFILE
CONTROL_ROOT, PARAMETERS, JOIN = _engine.CONTROL_ROOT, _engine.PARAMETERS, _engine.JOIN
IMAGE, P, Q, FIXTURE = _engine.IMAGE, _engine.P, _engine.Q, _engine.FIXTURE
QUALIFICATION = dict(_engine.QUALIFICATION)


def load_contract(root: Path) -> tuple[dict, bytes]:
    data = bounded_file(root, CONTRACT, 65536)
    require(sha(data) == CONTRACT_SHA256, 'unsupported implementation contract')
    contract = strict_json(data)
    historical, _ = _engine.load_contract(root)
    require(contract['schema'] == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2', 'contract schema')
    require(contract['source_base_commit'] == SELECTED_SOURCE_COMMIT, 'selected source identity')
    require(set(contract) == set(historical) | {'historical_inputs', 'source_review'},
            'v2 contract fields')
    require(contract['source_review'] == SOURCE_REVIEW, 'source review identity')
    require([row['path'] for row in contract['historical_inputs']] == [
        _engine.CONTRACT, ENGINE, HISTORICAL_REPORT, SOURCE_REVIEW], 'historical input roster')
    inputs = load_pinned_files(root, contract['historical_inputs'])
    require(sha(inputs[ENGINE]) == ENGINE_SHA256, 'historical engine identity')
    review = strict_json(inputs[SOURCE_REVIEW])
    require(review['schema'] == 'TRNM-W1-QROM-SOURCE-TRANSITION1'
            and review['historical_source_commit'] == historical['source_base_commit']
            and review['selected_source_commit'] == SELECTED_SOURCE_COMMIT,
            'source transition identity')
    changes = review['source_changes']
    require(len(changes) == 2 and {row['after']['path'] for row in changes} == CHANGED_PATHS,
            'reviewed source transition roster')
    before = {row['path']: row for row in historical['project_files']}
    replacements = {}
    for change in changes:
        path = change['after']['path']
        require(change['before'] == before[path] and len(change['reverse_edits']) == 2,
                'historical transition anchor')
        replacements[path] = change['after']
    require(contract['project_files'] == [replacements.get(row['path'], row)
                                         for row in historical['project_files']],
            'selected source roster is not the reviewed transition')
    for key, value in historical.items():
        if key not in {'schema', 'source_base_commit', 'project_files'}:
            require(contract[key] == value, f'historical mapping field changed: {key}')
    return contract, data


def verify_reviewed_source_projection(project: dict[str, bytes], review: dict) -> None:
    """Check bounded byte projection only, not semantic equivalence of new code."""
    for change in review['source_changes']:
        path = change['after']['path']
        projected = project[path]
        for edit in change['reverse_edits']:
            current = edit['current'].encode('utf-8')
            historical = edit['historical'].encode('utf-8')
            require(current and projected.count(current) == 1, 'reviewed source edit not unique')
            projected = projected.replace(current, historical, 1)
        require(len(projected) == change['before']['bytes']
                and sha(projected) == change['before']['sha256'],
                f'historical source projection differs: {path}')


def build_report(root: Path) -> dict:
    contract, contract_bytes = load_contract(root)
    historical_inputs = load_pinned_files(root, contract['historical_inputs'])
    review = strict_json(historical_inputs[SOURCE_REVIEW])
    helpers = load_pinned_files(root, contract['audit_helpers'])
    project = load_pinned_files(root, contract['project_files'])
    verify_reviewed_source_projection(project, review)
    assets = load_pinned_files(root, contract['saved_v2_files'])
    snapshot_record = contract['upstream_snapshot']
    snapshot = load_pinned_files(root, [snapshot_record])[snapshot_record['path']]
    sources, upstream_records = load_snapshot(snapshot, contract['upstream_commit'])
    control_path = 'scripts/w1_control_tree_audit.py'
    control = checked_helper(root, control_path, helpers[control_path])
    control_tree = control.audit_sources(sources)
    # audit_sources recomputes the root and each inclusion branch independently.
    require(control_tree['root'] == CONTROL_ROOT and control_tree['matches_fixed_root'] is True,
            'independently reconstructed control root')
    join_branch = control_tree['final_join']['merkle_path']
    v2 = inspect_v2(assets, join_branch)
    image_text = project['formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'].decode()
    matches = re.findall(r'IMAGE_ID: \[u32; 8\] = \[([^]]+)\]', image_text)
    require(len(matches) == 1 and tuple(int(x.strip()) for x in matches[0].split(',') if x.strip()) == IMAGE,
            'compiled v2 image pin')
    profile_text = project['formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs'].decode()
    require(f'PARAMETERS: &str = "{PARAMETERS}"' in profile_text
            and f'CONTROL_ID: &str = "{JOIN}"' in profile_text, 'compiled receipt profile')
    profile_path = 'scripts/w1_profile_source_map.py'
    profile = checked_helper(root, profile_path, helpers[profile_path])
    stark = profile.extract_stark_parameters(sources['risc0/zkp/src/lib.rs'])
    transcript_path = 'scripts/w1_fri_transcript_audit.py'
    transcript = checked_helper(root, transcript_path, helpers[transcript_path])
    transcript_report = transcript.audit_sources(sources, assets[FIXTURE + 'succinct.bin'])
    def protocol(path, name):
        values = re.findall(name + r': ProtocolInfo = ProtocolInfo\(\*b"([^\"]+)"\)', sources[path])
        require(len(values) == 1, f'unique protocol declaration: {name}')
        return values[0]
    proof_info = protocol('risc0/zkp/src/adapter.rs', 'PROOF_SYSTEM_INFO')
    circuit_info = protocol('risc0/circuit/recursion/src/info.rs', 'CIRCUIT_INFO')
    require(parameter_digest(CONTROL_ROOT, proof_info, circuit_info) == PARAMETERS, 'parameter recomputation')
    locks = {}
    for path, data in project.items():
        if path.endswith('Cargo.lock'):
            selected = [{'name': p['name'], 'version': p['version'], 'source': p.get('source'),
                         'checksum': p.get('checksum')} for p in tomllib.loads(data.decode())['package']
                        if p['name'].startswith('risc0-') or p['name'] == 'sha2']
            locks[path] = {'sha256': sha(data), 'selected_packages': selected}
    report = {
        'schema': 'TRNM-W1-QROM-IMPLEMENTATION-AUDIT2', 'result': 'MAPPING_REPRODUCED_SECURITY_HOLD',
        'profile_id': PROFILE, 'contract_sha256': sha(contract_bytes),
        'source_base_commit': contract['source_base_commit'],
        'generator_sha256': sha(Path(__file__).read_bytes()),
        'helper_execution': {'mode': 'compile_exact_pinned_repository_audit_bytes',
                             'sources': contract['audit_helpers'],
                             'upstream_source_executed': False},
        'qualification': dict(QUALIFICATION),
        'project_files': contract['project_files'], 'saved_fixture_files': contract['saved_v2_files'],
        'upstream_commit': UPSTREAM, 'upstream_snapshot': snapshot_record,
        'upstream_selected_sources': upstream_records, 'locked_package_mapping': locks,
        'field': {'work_modulus': Q, 'proof_base_modulus': P,
                  'extension_degree': 4, 'extension_polynomial': 'X^4 + 11',
                  'digest_support_size': str(P ** 8), 'digest_storage_bits': 256,
                  'uniform_bit_oracle_sigma_justified': None},
        'stark_parameters': stark, 'control_tree': control_tree,
        'parameter_digest_independently_recomputed': PARAMETERS,
        'control_scope': {
            'fixed_final_program': 'join.zkr', 'named_default_inner_programs': 27,
            'padding_leaf_count': 229, 'padding_leaf_digest': '0' * 64,
            'padding_digest_has_no_accepting_code_proved': False,
            'allowed_lift_po2_min': 14, 'allowed_lift_po2_max': 22,
            'generic_outer_verifier_explicit_po2_max': 24,
            'generic_outer_verifier_explicit_po2_min': None,
            'all_recursive_trace_sizes_reachable': None,
            'warning': 'The default lift-name limit 22 is not a standalone upper bound for every recursion seal. The succinct check_code closure ignores its po2 argument; code-root constraints may restrict feasibility, which is not proved here.',
            'all_program_bytecode_to_control_ids_recomputed': False,
            'all_program_relations_and_rbr_proved': False,
        },
        'fri_schedules': [fri_schedule(po2) for po2 in range(0, 25)],
        'fri_schedule_scope': 'Public arithmetic for each explicit parser po2 value, not a claim that every value admits a valid seal. No FRI folding-round count is substituted for the full IOR round count.',
        'saved_v2': v2, 'fri_transcript_audit': transcript_report,
        'lifetime_budget': contract['lifetime_budget'],
        'open_obligations': [{'id': item, 'state': 'UNRESOLVED'} for item in contract['proof_obligations']],
        'independent_conclusions': {
            'pq_signature_authorization': 'Not assessed or certified by this proof map.',
            'complete_computation_proof': 'Selected construction and historical v2 bindings reproduced; QROM qualification remains open.',
            'quantum_work_and_chainweight': 'Not implied by proof or signature validation; remains a separate analysis.',
        },
    }

    # Only these provenance fields differ from the immutable historical map.
    # All reconstructed parameters, receipt observations and unknowns must match.
    historical_report = strict_json(historical_inputs[HISTORICAL_REPORT])
    provenance = {'schema', 'contract_sha256', 'source_base_commit',
                  'generator_sha256', 'project_files'}
    def semantic_json(value):
        # JSON bytes distinguish false/0, true/1 and integer/float producer
        # regressions that Python container equality would silently equate.
        return json.dumps({k: v for k, v in value.items() if k not in provenance},
                          sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(semantic_json(report) == semantic_json(historical_report),
            'historical semantic mapping fields changed')
    report['source_review'] = {
        'schema': 'TRNM-W1-QROM-SOURCE-TRANSITION1',
        'review_sha256': sha(historical_inputs[SOURCE_REVIEW]),
        'historical_contract_sha256': _engine.CONTRACT_SHA256,
        'historical_engine_sha256': ENGINE_SHA256,
        'historical_report_sha256': sha(historical_inputs[HISTORICAL_REPORT]),
        'selected_project_file_count': 16,
        'unchanged_project_file_count': 14,
        'changed_paths': sorted(CHANGED_PATHS),
        'historical_route_byte_projection_reproduced': True,
        'historical_semantic_report_fields_reproduced': True,
        'new_native_once_route_qualified': False,
        'funded_service_decoder_qualified': False,
        'whole_source_and_build_equivalence_proved': False,
    }
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = build_report(args.repo_root)
        data = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output:
            with args.output.open('x') as stream:
                stream.write(data)
        else:
            sys.stdout.write(data)
        return 0
    except (ValueError, OSError, KeyError, TypeError, struct.error, EOFError) as error:
        print(json.dumps({'result': 'INPUT_REJECTED', 'reason': str(error),
                          'qualification': QUALIFICATION}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
