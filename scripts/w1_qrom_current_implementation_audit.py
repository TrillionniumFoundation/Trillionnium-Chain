#!/usr/bin/env python3
"""Explicit current-source W1 mapping, retaining the historical v1 refusal.

This separate entry pins the reviewed local path crates and literal includes.
It neither changes v1 inputs nor supplies a native run, complete build identity,
third-party source review, cryptographic theorem or consensus qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tomllib
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'config/pon/w1-qrom-implementation-current-v2.json'
CONTRACT_SHA256 = 'c57cfc453aae93ecc650cc401de054a13a0eb325ebef308cc286c622539496b7'
SOURCE = '15e4050ab7604990caf57bd5ca4472552f42dad1'
LEGACY_READER = 'scripts/w1_qrom_implementation_audit.py'
LEGACY_READER_SHA256 = 'c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354'
MAX_BYTES = 2 * 1024 * 1024
CHANGED = frozenset({
    'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock',
    'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs',
    'trillionnium/crates/trnm-protocol/src/pon_wire.rs',
})


class AuditError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise AuditError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(root, name, limit=MAX_BYTES):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and str(relative) == name
            and all(part not in ('', '.', '..') for part in relative.parts),
            'noncanonical current source path')
    current = root
    for part in relative.parts[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), 'nonregular source ancestor: ' + name)
    path = root / name
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                'nonregular or oversized current source: ' + name)
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        visible = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) == identity(visible)
                and len(raw) == before.st_size, 'current source changed during read: ' + name)
        return raw
    finally:
        os.close(descriptor)


def pinned(root, rows):
    result = {}
    for row in rows:
        name = row['path']
        require(name not in result and type(row['bytes']) is int
                and 0 < row['bytes'] <= MAX_BYTES, 'duplicate path or invalid bound')
        raw = read_regular(root, name, row['bytes'])
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
                'current source pin differs: ' + name)
        result[name] = raw
    return result


def load_current(root):
    root = Path(root)
    require(root.absolute() == root.resolve(strict=True), 'source root/ancestor is an alias')
    original = read_regular(root, LEGACY_READER)
    require(sha(original) == LEGACY_READER_SHA256, 'historical reader differs')
    audit = ModuleType('_trnm_retained_qrom_implementation_v1')
    audit.__file__ = str(root / LEGACY_READER)
    exec(compile(original, audit.__file__, 'exec'), audit.__dict__)
    historical, historical_raw = audit.load_contract(root)
    raw = read_regular(root, CONTRACT, 128 * 1024)
    require(sha(raw) == CONTRACT_SHA256, 'unreviewed current implementation contract')
    current = audit.strict_json(raw)
    require(current['schema'] == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2'
            and current['source_base_commit'] == SOURCE, 'current source namespace differs')
    # Historical fixtures, helpers, proof obligations, parameters and unknown
    # budget remain exactly the old contract. Only explicitly reviewed project
    # source pins acquire new values under this separate profile.
    additions = {'historical_contract', 'historical_reader', 'local_path_closure',
                 'reviewed_changes'}
    require(set(current) == set(historical) | additions, 'current contract fields differ')
    for key in set(historical) - {'schema', 'source_base_commit', 'project_files'}:
        require(current[key] == historical[key], 'historical contract section differs: ' + key)
    old_rows = {row['path']: row for row in historical['project_files']}
    new_rows = {row['path']: row for row in current['project_files']}
    require(list(new_rows) == list(old_rows), 'historical selected project roster differs')
    require({path for path in old_rows if old_rows[path] != new_rows[path]} == CHANGED,
            'unreviewed project source difference')
    require(current['historical_contract']['sha256'] == sha(historical_raw)
            and current['historical_reader']['sha256'] == sha(original),
            'retained historical input identity differs')
    return audit, current, raw


def local_closure(root, contract):
    closure = contract['local_path_closure']
    inputs = pinned(root, closure['files'])
    roots = closure['crate_roots']
    manifests = {name + '/Cargo.toml' for name in roots}
    require(manifests <= set(inputs), 'local manifest missing from reviewed source')
    seen, pending, edges = set(), list(closure['entry_manifests']), []
    while pending:
        manifest = pending.pop()
        if manifest in seen:
            continue
        require(manifest in manifests, 'local path dependency outside reviewed closure')
        seen.add(manifest)
        data = tomllib.loads(inputs[manifest].decode())
        tables = [data.get(key, {}) for key in ('dependencies', 'dev-dependencies', 'build-dependencies')]
        for target in data.get('target', {}).values():
            tables.extend(target.get(key, {}) for key in ('dependencies', 'dev-dependencies', 'build-dependencies'))
        for table in tables:
            for name, dependency in table.items():
                if not isinstance(dependency, dict) or 'path' not in dependency:
                    continue
                location = (root / manifest).parent / dependency['path'] / 'Cargo.toml'
                target = str(location.resolve(strict=True).relative_to(root.resolve(strict=True)))
                require(target in manifests, 'unreviewed local path dependency: ' + target)
                edges.append({'manifest': manifest, 'dependency': name, 'target': target})
                pending.append(target)
    require(seen == manifests, 'reviewed local crate is disconnected from entry manifests')
    actual_rust = set()
    for name in roots:
        for kind in ('src', 'tests', 'examples', 'benches'):
            directory = root / name / kind
            if not directory.exists():
                continue
            require(not directory.is_symlink(), 'symlinked local source directory')
            for parent, dirs, files in os.walk(directory, followlinks=False):
                for child in dirs:
                    require(not (Path(parent) / child).is_symlink(), 'symlinked local source directory')
                actual_rust.update(str((Path(parent) / child).relative_to(root))
                                   for child in files if child.endswith('.rs'))
    require(actual_rust == {name for name in inputs if name.endswith('.rs')},
            'local Rust source inventory differs')
    included = set()
    for name in sorted(actual_rust):
        source = inputs[name].decode()
        require(re.search(r'\binclude!\s*\(', source) is None,
                'unreviewed Rust token include')
        matches = re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"\s*\)', source)
        require(len(matches) == len(re.findall(r'include_(?:str|bytes)!\s*\(', source)),
                'nonliteral Rust data include')
        for relative in matches:
            target = ((root / name).parent / relative).resolve(strict=True)
            included.add(str(target.relative_to(root.resolve(strict=True))))
    require(included == set(closure['literal_include_files']) and included <= set(inputs),
            'literal include source inventory differs')
    for name in closure['absent_build_inputs']:
        require(not (root / name).exists() and not (root / name).is_symlink(),
                'new unreviewed build input: ' + name)
    require(set(closure['workspace_inputs']) <= set(inputs), 'workspace source input missing')
    return inputs, sorted(edges, key=lambda value: (value['manifest'], value['dependency'], value['target']))


def map_current(audit, root, contract, contract_raw):
    """Apply the retained pure mapping checks to the explicit reviewed inputs."""
    helpers = pinned(root, contract['audit_helpers'])
    project = pinned(root, contract['project_files'])
    assets = pinned(root, contract['saved_v2_files'])
    snapshot_record = contract['upstream_snapshot']
    snapshot = pinned(root, [snapshot_record])[snapshot_record['path']]
    sources, upstream_records = audit.load_snapshot(snapshot, contract['upstream_commit'])
    control_path = 'scripts/w1_control_tree_audit.py'
    control = audit.checked_helper(root, control_path, helpers[control_path])
    control_tree = control.audit_sources(sources)
    require(control_tree['root'] == audit.CONTROL_ROOT and control_tree['matches_fixed_root'] is True,
            'independently reconstructed control root')
    v2 = audit.inspect_v2(assets, control_tree['final_join']['merkle_path'])
    image_text = project['formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'].decode()
    matches = re.findall(r'IMAGE_ID: \[u32; 8\] = \[([^]]+)\]', image_text)
    require(len(matches) == 1 and tuple(int(x.strip()) for x in matches[0].split(',') if x.strip()) == audit.IMAGE,
            'compiled v2 image pin')
    profile_text = project['formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs'].decode()
    require(f'PARAMETERS: &str = "{audit.PARAMETERS}"' in profile_text
            and f'CONTROL_ID: &str = "{audit.JOIN}"' in profile_text, 'compiled receipt profile')
    profile_path = 'scripts/w1_profile_source_map.py'
    profile = audit.checked_helper(root, profile_path, helpers[profile_path])
    stark = profile.extract_stark_parameters(sources['risc0/zkp/src/lib.rs'])
    transcript_path = 'scripts/w1_fri_transcript_audit.py'
    transcript = audit.checked_helper(root, transcript_path, helpers[transcript_path])
    transcript_report = transcript.audit_sources(sources, assets[audit.FIXTURE + 'succinct.bin'])

    def protocol(path, name):
        values = re.findall(name + r': ProtocolInfo = ProtocolInfo\(\*b"([^\"]+)"\)', sources[path])
        require(len(values) == 1, 'unique protocol declaration: ' + name)
        return values[0]

    proof_info = protocol('risc0/zkp/src/adapter.rs', 'PROOF_SYSTEM_INFO')
    circuit_info = protocol('risc0/circuit/recursion/src/info.rs', 'CIRCUIT_INFO')
    require(audit.parameter_digest(audit.CONTROL_ROOT, proof_info, circuit_info) == audit.PARAMETERS,
            'parameter recomputation')
    locks = {}
    for path, data in project.items():
        if path.endswith('Cargo.lock'):
            selected = [{'name': p['name'], 'version': p['version'], 'source': p.get('source'),
                         'checksum': p.get('checksum')} for p in tomllib.loads(data.decode())['package']
                        if p['name'].startswith('risc0-') or p['name'] == 'sha2']
            locks[path] = {'sha256': sha(data), 'selected_packages': selected}
    return {
        'schema': 'TRNM-W1-QROM-CURRENT-IMPLEMENTATION-AUDIT2',
        'result': 'CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD',
        'profile_id': audit.PROFILE, 'contract_sha256': sha(contract_raw),
        'source_base_commit': SOURCE, 'qualification': dict(audit.QUALIFICATION),
        'project_files': contract['project_files'], 'saved_fixture_files': contract['saved_v2_files'],
        'helper_execution': {'mode': 'compile_exact_pinned_repository_audit_bytes',
                             'sources': contract['audit_helpers'], 'upstream_source_executed': False},
        'upstream_commit': audit.UPSTREAM, 'upstream_snapshot': snapshot_record,
        'upstream_selected_sources': upstream_records, 'locked_package_mapping': locks,
        'field': {'work_modulus': audit.Q, 'proof_base_modulus': audit.P,
                  'extension_degree': 4, 'extension_polynomial': 'X^4 + 11',
                  'digest_support_size': str(audit.P ** 8), 'digest_storage_bits': 256,
                  'uniform_bit_oracle_sigma_justified': None},
        'stark_parameters': stark, 'control_tree': control_tree,
        'parameter_digest_independently_recomputed': audit.PARAMETERS,
        'control_scope': {
            'fixed_final_program': 'join.zkr', 'named_default_inner_programs': 27,
            'padding_leaf_count': 229, 'padding_leaf_digest': '0' * 64,
            'padding_digest_has_no_accepting_code_proved': False,
            'allowed_lift_po2_min': 14, 'allowed_lift_po2_max': 22,
            'generic_outer_verifier_explicit_po2_max': 24,
            'generic_outer_verifier_explicit_po2_min': None,
            'all_recursive_trace_sizes_reachable': None,
            'all_program_bytecode_to_control_ids_recomputed': False,
            'all_program_relations_and_rbr_proved': False,
            'warning': 'Parser po2 and lift-name limits do not prove reachable recursion trace bounds.',
        },
        'fri_schedules': [audit.fri_schedule(po2) for po2 in range(25)],
        'fri_schedule_scope': 'Public parser arithmetic; reachable seals and full IOR rounds are unproved.',
        'saved_v2': v2, 'fri_transcript_audit': transcript_report,
        'lifetime_budget': contract['lifetime_budget'],
        'open_obligations': [{'id': item, 'state': 'UNRESOLVED'} for item in contract['proof_obligations']],
    }


def build_report(root):
    root = Path(root)
    audit, contract, raw = load_current(root)
    before, graph = local_closure(root, contract)
    try:
        audit.build_report(root)
    except audit.AuditError as error:
        historical_reason = str(error)
        require(historical_reason == 'input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs',
                'unexpected historical mapping refusal')
    else:
        raise AuditError('historical source contract unexpectedly accepted current sources')
    report = map_current(audit, root, contract, raw)
    after, after_graph = local_closure(root, contract)
    require(before == after and graph == after_graph, 'local closure changed during mapping')
    require(read_regular(root, CONTRACT, 128 * 1024) == raw
            and sha(read_regular(root, LEGACY_READER)) == LEGACY_READER_SHA256,
            'reader or contract changed during mapping')
    report.update({
        'generator_sha256': sha(Path(__file__).read_bytes()),
        'local_path_closure': {'scope': contract['local_path_closure']['scope'],
            'files': contract['local_path_closure']['files'], 'path_edges': graph,
            'literal_include_files': contract['local_path_closure']['literal_include_files'],
            'source_files_checked': len(before), 'source_before_after_equal': True},
        'historical_v1': {'reader_sha256': LEGACY_READER_SHA256,
            'contract_sha256': contract['historical_contract']['sha256'],
            'result': 'INPUT_REJECTED', 'reason': historical_reason,
            'named_roster_completed': False, 'workflow_passed': False},
        'reviewed_changes': contract['reviewed_changes'],
        'fresh_cryptographic_verification': False, 'native_binary_executed': False,
        'whole_repository_source_verified': False, 'third_party_source_closure_verified': False,
        'provider_build_identity_verified': False, 'git_commit_ancestry_verified': False,
        'source_binding_scope': 'reviewed-local-path-crate-files-and-selected-mapping-inputs',
    })
    return report


def main():
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
    except (ValueError, OSError, KeyError, TypeError, EOFError) as error:
        print(json.dumps({'schema': 'TRNM-W1-QROM-CURRENT-IMPLEMENTATION-AUDIT2',
                          'result': 'INPUT_REJECTED', 'reason': str(error),
                          'production_qualified': False, 'security_bits_quantum': None}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
