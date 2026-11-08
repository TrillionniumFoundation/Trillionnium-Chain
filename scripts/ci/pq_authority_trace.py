#!/usr/bin/env python3
"""Check exact-source bindings for incomplete authorization trace observations.

This checker verifies inventory, file and anchor identities. It does not infer
Rust reachability, execute the named regressions, or validate the prose claims.
No record format accepted here can qualify an authorization path or the chain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

from pq_authority_surface_scan import AuditError, MAX_SOURCE_BYTES, inspect
from pq_source_reader import SourceReadError, read_regular

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = 'config/pon/pq-authority-traces-v1.json'
SCHEMA = 'trnm-pq-authority-source-traces-v1'
BUILD_INPUT_SCHEMA = 'trnm-pq-authority-build-inputs-v1'
# Removing an entry from the JSON must not silently shrink the reviewed scope.
# These are required starting observations, not an exhaustive authority map.
REQUIRED_TRACES = {
    'classical-network-profile': (
        'trillionnium/crates/trnm-pon-node/src/ingress.rs', 'profile-boundary'),
    'legacy-transfer': (
        'trillionnium/crates/trnm-types/src/transfer.rs', 'classical-validator'),
    'legacy-settlement': (
        'trillionnium/crates/trnm-service-settlement/src/engine.rs', 'classical-effect-owner'),
    'legacy-research-command': (
        'trillionnium/crates/trnm-research-protocol/src/command.rs', 'classical-validator'),
    'legacy-hepta-v1': (
        'trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs', 'classical-validator'),
    'legacy-provider-discovery': (
        'trillionnium/crates/trnm-data-availability/src/cell/discovery.rs', 'classical-validator'),
}
SOURCE_ROLES = {
    'entrypoint', 'profile-check', 'verifier', 'caller', 'effect-boundary',
    'return-boundary', 'regression-source',
}
HASH = re.compile(r'[0-9a-f]{64}\Z')


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AuditError(reason)


def require_keys(value: object, keys: set[str], label: str) -> None:
    require(type(value) is dict and set(value) == keys, label + ' fields')


def text_value(value: object, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value) <= maximum
            and value.strip() == value and '\0' not in value, label)
    return value


def digest_value(value: object, label: str) -> str:
    require(type(value) is str and HASH.fullmatch(value) is not None, label)
    return value


def relative_path(value: object) -> str:
    path = text_value(value, 'source path', 1024)
    parts = PurePosixPath(path).parts
    require(not path.startswith('/') and str(PurePosixPath(path)) == path
            and '..' not in parts and '\\' not in path
            and not any(char in path for char in '*?[]'), 'noncanonical source path')
    return path


def read_rooted(root: Path, name: str) -> bytes:
    try:
        return read_regular(root, relative_path(name), MAX_SOURCE_BYTES)
    except SourceReadError as exc:
        raise AuditError(str(exc)) from exc


def build_inputs(root: Path) -> list[dict]:
    """Bind checked-in Cargo/toolchain configuration, not an actual build.

    The runtime environment, target, compiler binary and selected feature flags
    are not certified by this list. Missing fixed inputs fail closed.
    """
    names = {'rust-toolchain.toml', 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock'}

    def walk_error(error: OSError) -> None:
        raise AuditError('unreadable Cargo input directory') from error

    for current, dirs, files in os.walk(root / 'trillionnium' / 'crates',
                                       followlinks=False, onerror=walk_error):
        for directory in dirs:
            require(not (Path(current) / directory).is_symlink(),
                    'symlink Cargo input directory')
        for filename in files:
            if filename in {'Cargo.toml', 'Cargo.lock'}:
                names.add((Path(current) / filename).relative_to(root).as_posix())
    for name in ('rust-toolchain', 'trillionnium/rust-toolchain',
                 'trillionnium/rust-toolchain.toml', '.cargo/config',
                 '.cargo/config.toml', 'trillionnium/.cargo/config',
                 'trillionnium/.cargo/config.toml'):
        path = root / name
        if path.exists() or path.is_symlink():
            names.add(name)
    return [{'path': name, 'sha256': hashlib.sha256(read_rooted(root, name)).hexdigest()}
            for name in sorted(names)]


def build_inputs_sha256(entries: list[dict]) -> str:
    wire = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('ascii')
    return hashlib.sha256(BUILD_INPUT_SCHEMA.encode('ascii') + b'\0' + wire).hexdigest()


def no_duplicate_keys(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_manifest(path: Path) -> dict:
    def refuse_constant(_):
        raise AuditError('nonfinite JSON constant')

    try:
        raw = read_rooted(path.parent, path.name).decode('utf-8')
        return json.loads(raw, object_pairs_hook=no_duplicate_keys,
                          parse_constant=refuse_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError('invalid trace manifest JSON') from exc


def validate(root: Path, manifest: dict) -> dict:
    require_keys(manifest, {'schema', 'source_inventory_sha256', 'build_inputs_sha256',
                            'whole_chain_pq_qualified', 'records', 'untraced_scope'},
                 'manifest')
    require(manifest['schema'] == SCHEMA, 'trace manifest schema')
    require(manifest['whole_chain_pq_qualified'] is False,
            'trace inventory cannot qualify whole-chain PQ')
    report = inspect(root)
    require(digest_value(manifest['source_inventory_sha256'], 'source inventory digest')
            == report['source_inventory_sha256'], 'stale full Rust source inventory')
    inputs = build_inputs(root)
    configuration_digest = build_inputs_sha256(inputs)
    require(digest_value(manifest['build_inputs_sha256'], 'build input digest')
            == configuration_digest, 'stale Cargo/toolchain input inventory')
    scope = manifest['untraced_scope']
    require(type(scope) is list and 1 <= len(scope) <= 32, 'untraced scope required')
    for item in scope:
        text_value(item, 'untraced scope statement')

    identities = {entry['path']: entry['sha256'] for entry in report['source_inventory']}
    records = manifest['records']
    require(type(records) is list and len(records) == len(REQUIRED_TRACES),
            'all selected high-risk trace records required')
    seen = set()
    observed_sources = {}
    for record in records:
        require_keys(record, {'id', 'classification', 'selected_profile', 'observation',
                              'authority_effect', 'status', 'runtime_validation',
                              'sources', 'unresolved_obligations'}, 'trace record')
        record_id = text_value(record['id'], 'trace record id', 96)
        require(record_id in REQUIRED_TRACES and record_id not in seen,
                'unknown or duplicate selected trace record')
        seen.add(record_id)
        entrypoint_path, classification = REQUIRED_TRACES[record_id]
        require(record['classification'] == classification,
                'selected trace cannot be reclassified as test-only')
        require(record['status'] == 'INCOMPLETE', 'source trace cannot close authority review')
        require(record['runtime_validation'] == 'NOT_RECORDED',
                'source trace cannot certify runtime validation')
        for key in ('selected_profile', 'observation', 'authority_effect'):
            text_value(record[key], key)
        obligations = record['unresolved_obligations']
        require(type(obligations) is list and 1 <= len(obligations) <= 32,
                'unresolved obligations required')
        for obligation in obligations:
            text_value(obligation, 'unresolved obligation')
        require(len(set(obligations)) == len(obligations), 'duplicate unresolved obligation')
        sources = record['sources']
        require(type(sources) is list and 2 <= len(sources) <= 16,
                'bounded source anchors required')
        entrypoints = []
        roles = set()
        seen_anchors = set()
        for source in sources:
            require_keys(source, {'role', 'path', 'sha256', 'anchor'}, 'source anchor')
            role = text_value(source['role'], 'source role', 48)
            require(role in SOURCE_ROLES, 'unknown source role')
            roles.add(role)
            name = relative_path(source['path'])
            require(name in identities, 'source anchor outside full Rust inventory')
            expected_sha = digest_value(source['sha256'], 'source anchor digest')
            require(expected_sha == identities[name], 'stale source anchor digest: ' + name)
            anchor = text_value(source['anchor'], 'source anchor', 8192)
            require((name, anchor) not in seen_anchors, 'duplicate source anchor')
            seen_anchors.add((name, anchor))
            if name not in observed_sources:
                data = read_rooted(root, name)
                require(hashlib.sha256(data).hexdigest() == expected_sha,
                        'source changed after inventory: ' + name)
                observed_sources[name] = data.decode('utf-8')
            require(observed_sources[name].count(anchor) == 1,
                    'missing or nonunique source anchor: ' + name)
            if role == 'entrypoint':
                entrypoints.append(name)
        require(entrypoints == [entrypoint_path], 'exact selected entrypoint required')
        require(bool(roles & {'profile-check', 'verifier'}),
                'verification or profile observation required')

    # Detect ordinary concurrent edits across the scan/anchor read. This still
    # is not an atomic filesystem snapshot against a cooperating same-UID writer.
    require(inspect(root)['source_inventory_sha256'] == report['source_inventory_sha256'],
            'Rust inventory changed during trace validation')
    require(build_inputs_sha256(build_inputs(root)) == configuration_digest,
            'Cargo/toolchain inputs changed during trace validation')
    return {
        'schema': 'trnm-pq-authority-source-trace-result-v1',
        'status': 'HOLD_INCOMPLETE_AUTHORITY_TRACING',
        'source_trace_integrity_passed': True,
        'whole_chain_pq_qualified': False,
        'all_authority_paths_traced': False,
        'source_files_read': report['source_files_read'],
        'source_inventory_sha256': report['source_inventory_sha256'],
        'build_input_files_read': len(inputs),
        'build_inputs_sha256': configuration_digest,
        'mapped_role_hints': report['mapped_role_hints'],
        'unreviewed_indicator_files': report['unreviewed_indicator_files'],
        'selected_source_trace_records': len(records),
        'completed_authority_traces': 0,
        'runtime_tests_executed': 0,
        'records': records,
        'untraced_scope': scope,
        'build_inputs': inputs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--summary-only', action='store_true')
    args = parser.parse_args()
    try:
        path = args.manifest if args.manifest is not None else args.root / DEFAULT_MANIFEST
        report = validate(args.root, load_manifest(path))
    except AuditError as error:
        print(json.dumps({'status': 'REFUSE', 'whole_chain_pq_qualified': False,
                          'reason': str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    if args.summary_only:
        for key in ('records', 'untraced_scope', 'build_inputs'):
            report.pop(key)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
